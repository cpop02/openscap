//
// Created by Cristian Pop on 19/10/2020.
//

#include <stdlib.h>

#include <probe-api.h>
#include <debug_priv.h>
#include <probe-common.h>
#include <probe-table.h>
#include <util.h>
#include <sexp-manip.h>

#include "executor.h"
#include "probe.h"

#define MAX_EVAL_DEPTH 8

extern bool OSCAP_GSYM(varref_handling);

static int probe_executor_exec_nocache(probe_executor_t *exec, probe_request_t *req);
static int probe_executor_eval_obj_ref(probe_executor_t *exec, SEXP_t *obj_ref, SEXP_t **out);
static int probe_executor_eval_obj_ref_nocache(probe_executor_t *exec, SEXP_t *oid, SEXP_t **out);
static int probe_executor_eval_set(probe_executor_t *exec, SEXP_t *set, SEXP_t **out, size_t depth);

probe_executor_t* probe_executor_new(probe_executor_ctx_t *ctx) {
    probe_executor_t *exec;

    __attribute__nonnull__(ctx);

    dD("probe_executor: Creating new probe_executor");

    exec = (probe_executor_t*)malloc(sizeof(probe_executor_t));
    if(exec == NULL) {
        goto fail;
    }
    exec->ctx = *ctx;
    exec->rcache = probe_rcache_new();
    if(exec->rcache == NULL) {
        goto fail;
    }
    exec->icache = probe_icache_new();
    if(exec->icache == NULL) {
        goto fail;
    }
    if(probe_icache_wait(exec->icache) != 0) {
        goto fail;
    }

    goto cleanup;

fail:
    probe_executor_free(exec);
    exec = NULL;

cleanup:
    return exec;
}

void probe_executor_free(probe_executor_t *exec) {
    dD("probe_executor: Freeing probe_executor");

    if(exec != NULL) {
        if(exec->rcache != NULL) {
            probe_rcache_free(exec->rcache);
        }
        if(exec->icache != NULL) {
            probe_icache_free(exec->icache);
        }
    }
    free(exec);
}

int probe_executor_reset(probe_executor_t *exec) {
    // TODO: Clear caches
    return 0;
}

int probe_executor_exec(probe_executor_t *exec, probe_request_t *req) {
    int ret = 0, cache_ret;
    SEXP_t *oid = NULL, *out;

    dD("probe_executor: Executing probe request");
    dO(OSCAP_DEBUGOBJ_SEXP, req->probe_in);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(req);
    __attribute__nonnull__(req->probe_in);
    __attribute__nonnull__(req->probe_out);

    oid = probe_obj_getattrval(req->probe_in, "id");
    if(oid == NULL) {
        dE("probe_executor: Failed to get OVAL object ID");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    out = probe_rcache_sexp_get(exec->rcache, oid);
    if(out != NULL) {
        dD("probe_executor: Serving request from cache");
        *req->probe_out = out;
        goto cleanup;
    }
    ret = probe_executor_exec_nocache(exec, req);
    if(ret != 0) {
        dE("probe_executor: Failed to execute request");
        goto fail;
    }
    cache_ret = probe_rcache_sexp_add(exec->rcache, oid, *req->probe_out);
    if(cache_ret != 0) {
        // Don't fail the request
        dE("probe_executor: Failed to add result to cache");
    }

fail:
cleanup:
    SEXP_free(oid);

    return ret;
}

static int probe_executor_exec_nocache(probe_executor_t *exec, probe_request_t *req) {
    int ret;
    probe_ctx probe_ctx;
    SEXP_t *set = NULL, *cobj, *aux;
    SEXP_t *mask = NULL, *varrefs = NULL;
    SEXP_t *probe_in = NULL, *probe_out = NULL;
    probe_main_function_t probe_func;
    struct probe_varref_ctx *varref_ctx = NULL;

    __attribute__nonnull__(exec);
    __attribute__nonnull__(req);
    __attribute__nonnull__(req->probe_in);
    __attribute__nonnull__(req->probe_out);

    probe_ctx.filters = NULL;

    probe_in = SEXP_ref(req->probe_in);
    set = probe_obj_getent(probe_in, "set", 1);
    if(set != NULL) {
        dD("probe_executor: Handling set in object");

        ret = probe_executor_eval_set(exec, set, &probe_out, 0);
        if(ret != 0) {
            goto fail;
        }
    } else {
        probe_ctx.probe_data = exec->ctx.probe_data;
        probe_ctx.probe_type = req->probe_type;

        probe_ctx.offline_mode = PROBE_OFFLINE_NONE;
        probe_ctx.icache = exec->icache;
        probe_ctx.filters = NULL;
        // TODO: Add filters

        mask = probe_obj_getmask(probe_in);
        if(OSCAP_GSYM(varref_handling)) {
            varrefs = probe_obj_getent(probe_in, "varrefs", 1);
        }

        probe_func = probe_table_get_main_function(req->probe_type);
        if(probe_func == NULL) {
            dW("probe_executor: No probe available for type %d", req->probe_type);
            ret = PROBE_EOPNOTSUPP;
            goto fail;
        }
        if(varrefs == NULL || !OSCAP_GSYM(varref_handling)) {
            dD("probe_executor: Handling object");

            probe_out = probe_cobj_new(SYSCHAR_FLAG_UNKNOWN, NULL, NULL, mask);
            if(probe_out == NULL) {
                ret = PROBE_ENOMEM;
                goto fail;
            }

            probe_ctx.probe_in = probe_in;
            probe_ctx.probe_out = probe_out;

            ret = probe_func(&probe_ctx, NULL);
            if(ret != 0) {
                goto fail;
            }

            probe_icache_nop(exec->icache);
            probe_cobj_compute_flag(probe_out);
        } else {
            dD("probe_executor: Handling varrefs in object");

            ret = probe_varref_create_ctx(probe_in, varrefs, &varref_ctx);
            if(ret != 0) {
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
            do {
                cobj = probe_cobj_new(SYSCHAR_FLAG_UNKNOWN, NULL, NULL, mask);
                if(cobj == NULL) {
                    ret = PROBE_EUNKNOWN;
                    goto fail;
                }

                probe_ctx.probe_in  = varref_ctx->pi2;
                probe_ctx.probe_out = cobj;

                ret = probe_func(&probe_ctx, NULL);

                probe_icache_nop(exec->icache);
                probe_cobj_compute_flag(cobj);

                aux = probe_out;
                probe_out = probe_set_combine(aux, cobj, OVAL_SET_OPERATION_UNION);
                SEXP_free(cobj);
                SEXP_free(aux);
            } while(ret == 0 && probe_varref_iterate_ctx(varref_ctx));
            if(ret != 0) {
                goto fail;
            }
        }
    }

    SEXP_VALIDATE(probe_out);
    *req->probe_out = probe_out;

    goto cleanup;

fail:
    SEXP_free(probe_out);

cleanup:
    if(varref_ctx != NULL) {
        probe_varref_destroy_ctx(varref_ctx);
    }
    SEXP_free(varrefs);
    SEXP_free(mask);
    SEXP_free(probe_ctx.filters);
    SEXP_free(set);
    SEXP_free(probe_in);

    return ret;
}


static int probe_executor_eval_obj_ref(probe_executor_t *exec, SEXP_t *obj_ref, SEXP_t **out) {
    int ret = 0;
    SEXP_t *oid = NULL, *obj;

    dD("probe_executor: Evaluating object reference");
    dO(OSCAP_DEBUGOBJ_SEXP, obj_ref);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(obj_ref);
    __attribute__nonnull__(out);

    oid = probe_ent_getval(obj_ref);
    if(oid == NULL) {
        dE("probe_executor: Failed to get object reference entity value");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    obj = probe_rcache_sexp_get(exec->rcache, oid);
    if(obj != NULL) {
        dD("probe_executor: Serving object reference from cache");
        *out = obj;
        goto cleanup;
    }
    ret = probe_executor_eval_obj_ref_nocache(exec, oid, out);
    if(ret != 0) {
        dE("probe_executor: Failed to evaluate object reference");
    }

fail:
cleanup:
    SEXP_free(oid);

    return ret;
}

static int probe_executor_eval_obj_ref_nocache(probe_executor_t *exec, SEXP_t *oid, SEXP_t **out) {
    int ret = 0;
    SEXP_t *res = NULL, *roid = NULL, *obj;

    __attribute__nonnull__(exec);
    __attribute__nonnull__(oid);
    __attribute__nonnull__(out);

    if(exec->ctx.probe_cmd_handlers.obj_eval == NULL) {
        dE("probe_executor: No object reference evaluation handler provided");
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    res = exec->ctx.probe_cmd_handlers.obj_eval(oid, exec->ctx.probe_cmd_handler_arg);
    if(res == NULL) {
        dE("probe_executor: Object reference evaluation handler failed");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    roid = SEXP_list_first(res);
    if(roid == NULL) {
        dE("probe_executor: Failed to get OID from object reference evaluation result");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    if(SEXP_string_cmp(oid, roid) != 0) {
        dE("probe_executor: Unexpected OID in object reference evaluation result");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    obj = probe_rcache_sexp_get(exec->rcache, oid);
    if(obj == NULL) {
        dE("probe_executor: Object reference evaluation result not found in cache");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }

    *out = obj;

fail:
    SEXP_free(roid);
    SEXP_free(res);

    return ret;
}

static int probe_executor_eval_set(probe_executor_t *exec, SEXP_t *set, SEXP_t **resp, size_t depth) {
    size_t n, i;
    int ret, op_num;
    char elem_name[24];
    SEXP_t *op_val = NULL, *elem = NULL, *out;

    dD("probe_executor: Evaluating set");
    dO(OSCAP_DEBUGOBJ_SEXP, set);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(set);
    __attribute__nonnull__(resp);

    if(depth > MAX_EVAL_DEPTH) {
        dE("probe_executor: Max set evaluation recursion depth reached");
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }

    // TODO: Filters

    op_num = OVAL_SET_OPERATION_UNION;
    op_val = probe_ent_getattrval(set, "operation");
    if (op_val != NULL) {
        op_num = SEXP_number_geti_32(op_val);
    }

    n = SEXP_list_length(set);
    for(i = 2; i <= n; i++) {
        elem = SEXP_list_nth(set, i);
        dO(OSCAP_DEBUGOBJ_SEXP, elem);
        if(elem == NULL) {
            dE("probe_executor: Unexpected end of set");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        if(probe_ent_getname_r(elem, elem_name, sizeof(elem_name)) == 0) {
            dE("probe_executor: Failed to get set element name");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        if(strcmp("set", elem_name) == 0) {

        } else if(strcmp("obj_ref", elem_name) == 0) {
            ret = probe_executor_eval_obj_ref(exec, elem, &out);
            if(ret != 0) {
                goto fail;
            }
        } else if(strcmp("filter", elem_name) == 0) {

        } else {

        }

        SEXP_free(elem);
        elem = NULL;
    }

    ret = PROBE_EOPNOTSUPP;

fail:
    SEXP_free(elem);
    SEXP_free(op_val);

    return ret;
}
