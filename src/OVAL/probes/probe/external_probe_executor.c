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

#include "external_probe.h"
#include "external_probe_executor_impl.h"
#include "probe.h"

#define MAX_EVAL_DEPTH 8

extern bool OSCAP_GSYM(varref_handling);

static int external_probe_executor_eval_set(external_probe_executor_t *exec, external_probe_request_t *req, SEXP_t *set,
                                            SEXP_t **resp, size_t depth);
static probe_main_function_t external_probe_executor_exec_func(external_probe_executor_t *exec, external_probe_request_t *req);

external_probe_executor_t* external_probe_executor_new(oval_evaluation_t *eval) {
    external_probe_executor_t *exec;

    __attribute__nonnull__(eval);

    dD("external_probe_executor: Creating new executor");

    exec = (external_probe_executor_t*)malloc(sizeof(external_probe_executor_t));
    if(exec == NULL) {
        goto fail;
    }
    exec->eval = eval;
    exec->icache = probe_icache_new();
    if(exec->icache == NULL) {
        goto fail;
    }
    if(probe_icache_wait(exec->icache) != 0) {
        goto fail;
    }
    exec->ext_probe_main_func = external_probe_main;

    goto cleanup;

fail:
    external_probe_executor_free(exec);
    exec = NULL;

cleanup:
    return exec;
}

void external_probe_executor_free(external_probe_executor_t *exec) {
    dD("external_probe_executor: Freeing executor");

    if(exec != NULL) {
        if(exec->icache != NULL) {
            probe_icache_free(exec->icache);
        }
    }
    free(exec);
}

int external_probe_executor_exec(external_probe_executor_t *exec, external_probe_request_t *req, SEXP_t **resp) {
    int ret;
    probe_ctx probe_ctx;
    SEXP_t *set = NULL, *cobj, *aux;
    SEXP_t *mask = NULL, *varrefs = NULL;
    SEXP_t *probe_in = NULL, *probe_out = NULL;
    probe_main_function_t probe_func;
    struct probe_varref_ctx *varref_ctx = NULL;

    dD("external_probe_executor: Executing request");

    __attribute__nonnull__(exec);
    __attribute__nonnull__(req);
    __attribute__nonnull__(req->probe_in);
    __attribute__nonnull__(resp);

    probe_ctx.filters = NULL;

    probe_in = SEXP_ref(req->probe_in);
    set = probe_obj_getent(probe_in, "set", 1);
    if(set != NULL) {
        dD("external_probe_executor: Handling set in object");

        /*ret = external_probe_executor_eval_set(exec, req, set, &probe_out);
        if(ret != 0) {
            goto fail;
        }*/
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    } else {
        probe_ctx.offline_mode = PROBE_OFFLINE_NONE;
        probe_ctx.icache = exec->icache;
        probe_ctx.eval = exec->eval;
        probe_ctx.req = req;
        probe_ctx.filters = NULL;
        // TODO: Add filters

        mask = probe_obj_getmask(probe_in);
        if(OSCAP_GSYM(varref_handling)) {
            varrefs = probe_obj_getent(probe_in, "varrefs", 1);
        }

        probe_func = external_probe_executor_exec_func(exec, req);
        if(probe_func == NULL) {
            dW("external_probe_executor: No probe available for type %d", req->probe_type);
            ret = PROBE_EOPNOTSUPP;
            goto fail;
        }
        if(varrefs == NULL || !OSCAP_GSYM(varref_handling)) {
            dD("external_probe_executor: Handling object");

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
            dD("external_probe_executor: Handling varrefs in object");

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
    *resp = probe_out;

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

static int external_probe_executor_eval_set(external_probe_executor_t *exec, external_probe_request_t *req, SEXP_t *set,
                                            SEXP_t **resp, size_t depth) {
    size_t n, i;
    int ret, op_num;
    char elem_name[24];
    SEXP_t *op_val = NULL, *elem = NULL;

    if(depth > MAX_EVAL_DEPTH) {
        dE("external_probe_executor: Max set evaluation recursion depth reached");
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
    for(i = 2; i < n && ret == 0; i++) {
        elem = SEXP_list_nth(set, i);
        if(elem == NULL) {
            dE("external_probe_executor: Unexpected end of set");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        ret = probe_ent_getname_r(elem, elem_name, sizeof(elem_name));
        if(ret != 0) {
            dE("external_probe_executor: Failed to get set element name");
            goto fail;
        }
        if(strcmp("set", elem_name) == 0) {

        } else if(strcmp("obj_ref", elem_name) == 0) {

        } else if(strcmp("filter", elem_name) == 0) {

        } else {

        }

        SEXP_free(elem);
        elem = NULL;
    }

fail:
    SEXP_free(elem);
    SEXP_free(op_val);

    return ret;
}

static inline probe_main_function_t external_probe_executor_exec_func(external_probe_executor_t *exec, external_probe_request_t *req) {
    probe_main_function_t probe_func;

    __attribute__nonnull__(exec);
    __attribute__nonnull__(req);

    probe_func = probe_table_get_main_function(req->probe_type);
    if(probe_func == NULL && exec->ext_probe_main_func != NULL) {
        dD("external_probe_executor: Defaulting to external probe for type %d", req->probe_type);
        probe_func = exec->ext_probe_main_func;
    }

    return probe_func;
}
