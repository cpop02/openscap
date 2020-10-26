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

#define _SEXP_free(var) SEXP_free(var), var = NULL

#define MAX_SET_EVAL_DEPTH 8

extern bool OSCAP_GSYM(varref_handling);

static int probe_executor_exec_nocache(probe_executor_t *exec, SEXP_t *oid, probe_request_t *req);
static int probe_executor_prepare_filters(probe_executor_t *exec, SEXP_t *obj, SEXP_t **out);
static int probe_executor_eval_set(probe_executor_t *exec, SEXP_t *set, SEXP_t **out, size_t depth);
static int probe_executor_eval_obj_ref(probe_executor_t *exec, SEXP_t *obj_ref, SEXP_t **out);
static int probe_executor_eval_obj_ref_nocache(probe_executor_t *exec, SEXP_t *oid, SEXP_t **out);
static int probe_executor_fetch_filters(probe_executor_t *exec, SEXP_t *filters, SEXP_t **out);
static int probe_executor_fetch_ste(probe_executor_t *exec, SEXP_t *sids, SEXP_t **out);
static int probe_executor_fetch_ste_nocache(probe_executor_t *exec, SEXP_t *sids, SEXP_t **out);

probe_executor_t* probe_executor_new(probe_executor_ctx_t *ctx) {
    probe_executor_t *exec;

    __attribute__nonnull__(ctx);

    dD("probe_executor_new: Creating new probe_executor");

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
#ifdef OVAL_ICACHE_THREAD_ENABLED
    if(probe_icache_wait(exec->icache) != 0) {
        goto fail;
    }
#endif

    goto cleanup;

fail:
    probe_executor_free(exec);
    exec = NULL;

cleanup:
    return exec;
}

void probe_executor_free(probe_executor_t *exec) {
    dD("probe_executor_free: Freeing probe_executor");

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
    int ret = 0;
    SEXP_t *oid = NULL, *out;

    dD("probe_executor_exec: Executing probe request");
    dO(OSCAP_DEBUGOBJ_SEXP, req->probe_in);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(req);
    __attribute__nonnull__(req->probe_in);
    __attribute__nonnull__(req->probe_out);

    oid = probe_obj_getattrval(req->probe_in, "id");
    if(oid == NULL) {
        dE("probe_executor_exec: Failed to get OVAL object ID");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    out = probe_rcache_sexp_get(exec->rcache, oid);
    if(out != NULL) {
        dD("probe_executor_exec: Serving request from cache");
        *req->probe_out = out;
        goto cleanup;
    }
    ret = probe_executor_exec_nocache(exec, oid, req);
    if(ret != 0) {
        dE("probe_executor_exec: Failed to execute request");
    }

fail:
cleanup:
    SEXP_free(oid);

    return ret;
}

static int probe_executor_exec_nocache(probe_executor_t *exec, SEXP_t *oid, probe_request_t *req) {
    int ret;
    probe_ctx probe_ctx;
    SEXP_t *set = NULL, *cobj, *aux;
    SEXP_t *mask = NULL, *varrefs = NULL;
    SEXP_t *probe_in = NULL, *probe_out = NULL;
    probe_main_function_t probe_handler;
    struct probe_varref_ctx *varref_ctx = NULL;
#ifdef OVAL_ICACHE_THREAD_ENABLED
    int err;
#endif

    __attribute__nonnull__(exec);
    __attribute__nonnull__(oid);
    __attribute__nonnull__(req);

    memset(&probe_ctx, 0, sizeof(probe_ctx));

    probe_in = SEXP_ref(req->probe_in);
    set = probe_obj_getent(probe_in, "set", 1);
    if(set != NULL) {
        ret = probe_executor_eval_set(exec, set, &probe_out, 0);
        if(ret != 0) {
            goto fail;
        }
    } else {
        probe_ctx.probe_data = exec->ctx.probe_data;
        probe_ctx.probe_type = req->probe_type;

        probe_ctx.offline_mode = PROBE_OFFLINE_NONE;
        probe_ctx.icache = exec->icache;
        ret = probe_executor_prepare_filters(exec, probe_in, &probe_ctx.filters);
        if(ret != 0) {
            dE("probe_executor_exec_nocache: Failed to prepare filters");
            goto fail;
        }

        mask = probe_obj_getmask(probe_in);
        if(OSCAP_GSYM(varref_handling)) {
            varrefs = probe_obj_getent(probe_in, "varrefs", 1);
        }

        probe_handler = probe_table_get_main_function(req->probe_type);
        if(probe_handler == NULL) {
            dW("probe_executor_exec_nocache: No probe available for type %d", req->probe_type);
            ret = PROBE_EOPNOTSUPP;
            goto fail;
        }
        if(varrefs == NULL || !OSCAP_GSYM(varref_handling)) {
            dD("probe_executor_exec_nocache: Handling object");

            probe_out = probe_cobj_new(SYSCHAR_FLAG_UNKNOWN, NULL, NULL, mask);
            if(probe_out == NULL) {
                ret = PROBE_ENOMEM;
                goto fail;
            }

            probe_ctx.probe_in = probe_in;
            probe_ctx.probe_out = probe_out;

            ret = probe_handler(&probe_ctx, NULL);
            if(ret != 0) {
                dE("probe_executor_exec_nocache: Failed to run probe handler for object");
            }

#ifdef OVAL_ICACHE_THREAD_ENABLED
            if((err = probe_icache_nop(exec->icache)) != 0) {
                dE("probe_executor_exec_nocache: Failed to sync with icache");
                if(ret == 0) {
                    ret = err;
                }
            }
#endif
            probe_cobj_compute_flag(probe_out);

            if(ret != 0) {
                goto fail;
            }
        } else {
            dD("probe_executor_exec_nocache: Handling varrefs in object");

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

                ret = probe_handler(&probe_ctx, NULL);
                if(ret != 0) {
                    dE("probe_executor_exec_nocache: Failed to run probe handler for variable reference");
                }

#ifdef OVAL_ICACHE_THREAD_ENABLED
                if((err = probe_icache_nop(exec->icache)) != 0) {
                    dE("probe_executor_exec_nocache: Failed to sync with icache");
                    if(ret == 0) {
                        ret = err;
                    }
                }
#endif
                probe_cobj_compute_flag(cobj);

                aux = probe_out;
                probe_out = probe_set_combine(aux, cobj, OVAL_SET_OPERATION_UNION);
                if(probe_out == NULL) {
                    dE("probe_executor_exec_nocache: Failed to combine sets for variable reference");
                    ret = PROBE_EUNKNOWN;
                }
                SEXP_free(cobj);
                SEXP_free(aux);
            } while(ret == 0 && probe_varref_iterate_ctx(varref_ctx));
            if(ret != 0) {
                goto fail;
            }
        }
    }
    SEXP_VALIDATE(probe_out);

    ret = probe_rcache_sexp_add(exec->rcache, oid, probe_out);
    if(ret != 0) {
        dE("probe_executor_exec_nocache: Failed to add probe result to cache");
        goto fail;
    }

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

static int probe_executor_prepare_filters(probe_executor_t *exec, SEXP_t *obj, SEXP_t **out) {
    int ret, i;
    SEXP_t *filters = NULL, *rfilters = NULL;
    SEXP_t *ent = NULL, *action = NULL, *sid = NULL, *filter = NULL;

    __attribute__nonnull__(exec);
    __attribute__nonnull__(exec);
    __attribute__nonnull__(out);

    filters = SEXP_list_new(NULL);
    if(filters == NULL) {
        dE("probe_executor_prepare_filters: Failed to create filter list");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    for(i = 1;; i++) {
        ent = probe_obj_getent(obj, "filter", i);
        if(ent == NULL) {
            break;
        }
        action = probe_ent_getattrval(ent, "action");
        if(action == NULL) {
            dE("probe_executor_prepare_filters: Invalid filter provided; could not extract action");
            ret = PROBE_EINVAL;
            goto fail;
        }
        sid = probe_ent_getval(ent);
        if(sid == NULL) {
            dE("probe_executor_prepare_filters: Invalid filter provided; could not extract state ID");
            ret = PROBE_EINVAL;
            goto fail;
        }
        filter = SEXP_list_new(action, sid);
        if(filter == NULL) {
            dE("probe_executor_prepare_filters: Failed to create filter");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        if(SEXP_list_add(filters, filter) == NULL) {
            dE("probe_executor_prepare_filters: Failed to add filter to filter list");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        _SEXP_free(filter);
        _SEXP_free(sid);
        _SEXP_free(action);
        _SEXP_free(ent);
    }
    ret = probe_executor_fetch_filters(exec, filters, &rfilters);
    if(ret != 0) {
        dE("probe_executor_prepare_filters: Failed to fetch filters");
        goto fail;
    }

    *out = rfilters;

    goto cleanup;

    fail:
    SEXP_free(filter);
    SEXP_free(sid);
    SEXP_free(action);
    SEXP_free(ent);

    cleanup:
    SEXP_free(filters);

    return ret;
}

static int probe_executor_eval_set(probe_executor_t *exec, SEXP_t *set, SEXP_t **out, size_t depth) {
    int ret, op_num;
    char elem_name[24];
    SEXP_t *objs[2], *sets[2];
    size_t n, i, obj_i = 0, set_i = 0;
    SEXP_t *op_val = NULL, *elem = NULL, *res;
    SEXP_t *action = NULL, *sid = NULL, *filter = NULL, *filters = NULL, *rfilters = NULL;

    dD("probe_executor_eval_set: Evaluating set");
    dO(OSCAP_DEBUGOBJ_SEXP, set);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(set);
    __attribute__nonnull__(out);

    if(depth > MAX_SET_EVAL_DEPTH) {
        dE("probe_executor_eval_set: Max set evaluation recursion depth reached");
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }

    op_num = OVAL_SET_OPERATION_UNION;
    op_val = probe_ent_getattrval(set, "operation");
    if (op_val != NULL) {
        op_num = SEXP_number_geti_32(op_val);
    }
    if(op_num != OVAL_SET_OPERATION_UNION && op_num != OVAL_SET_OPERATION_COMPLEMENT && op_num != OVAL_SET_OPERATION_INTERSECTION) {
        dE("probe_executor_eval_set: Invalid set operation provided");
        ret = PROBE_EINVAL;
        goto fail;
    }

    memset(objs, 0, sizeof(objs));
    memset(sets, 0, sizeof(sets));

    // Evaluate objects and sets and extract filters
    filters = SEXP_list_new(NULL);
    if(filters == NULL) {
        dE("probe_executor_eval_set: Failed to create filters list");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    n = SEXP_list_length(set);
    SEXP_sublist_foreach(elem, set, 2, n) {
        dO(OSCAP_DEBUGOBJ_SEXP, elem);
        if(elem == NULL) {
            dE("probe_executor_eval_set: Unexpected end of set");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        if(probe_ent_getname_r(elem, elem_name, sizeof(elem_name)) == 0) {
            dE("probe_executor_eval_set: Failed to get set element name");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        if(strcmp("set", elem_name) == 0) {
            if(set_i >= 2) {
                dE("probe_executor_eval_set: Max number of nested sets surpassed");
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
            ret = probe_executor_eval_set(exec, elem, &sets[set_i], depth + 1);
            if(ret != 0) {
                dE("probe_executor_eval_set: Failed to evaluate nested set");
                goto fail;
            }
            ++set_i;
        } else if(strcmp("obj_ref", elem_name) == 0) {
            if(obj_i >= 2) {
                dE("probe_executor_eval_set: Max number of nested objects surpassed");
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
            ret = probe_executor_eval_obj_ref(exec, elem, &objs[obj_i]);
            if(ret != 0) {
                goto fail;
            }
            ++obj_i;
        } else if(strcmp("filter", elem_name) == 0) {
            action = probe_ent_getattrval(elem, "action");
            if(action == NULL) {
                dE("probe_executor_eval_set: Invalid filter provided; could not extract action");
                ret = PROBE_EINVAL;
                goto fail;
            }
            sid = probe_ent_getval(elem);
            if(sid == NULL) {
                dE("probe_executor_eval_set: Invalid filter provided; could not extract state ID");
                ret = PROBE_EINVAL;
                goto fail;
            }
            filter = SEXP_list_new(action, sid);
            if(filter == NULL) {
                dE("probe_executor_eval_set: Failed to create filter list");
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
            if(SEXP_list_add(filter, filters) == NULL) {
                dE("probe_executor_eval_set: Failed to add filter state ID to filter state ID list");
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
            _SEXP_free(filter);
            _SEXP_free(sid);
            _SEXP_free(action);
        } else {
            dE("probe_executor_eval_set: Invalid set element");
            ret = PROBE_EINVAL;
            goto fail;
        }
    }
    if(obj_i > 0 && set_i > 0) {
        dE("probe_executor_eval_set: A set cannot contain nested sets and objects at the same time");
        ret = PROBE_EINVAL;
        goto fail;
    }

    ret = probe_executor_fetch_filters(exec, filters, &rfilters);
    if(ret != 0) {
        dE("probe_executor_eval_set: Failed to fetch filter states");
        goto fail;
    }
    if(obj_i > 0) {
        for(set_i = 0; set_i < obj_i; set_i++) {
            sets[set_i] = probe_set_apply_filters(objs[set_i], rfilters);
            if(sets[set_i] == NULL) {
                dE("probe_executor_eval_set: Failed to apply filters to collected object");
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
        }
    }
    res = probe_set_combine(sets[0], sets[1], op_num);
    if(res == NULL) {
        dE("probe_executor_eval_set: Failed to combine collected object sets");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }

    *out = res;

    goto cleanup;

    fail:
    SEXP_free(filter);
    SEXP_free(sid);
    SEXP_free(action);
    SEXP_free(elem);

    cleanup:
    for(i = 0; i < obj_i; i++) {
        SEXP_free(objs[i]);
    }
    for(i = 0; i < set_i; i++) {
        SEXP_free(sets[i]);
    }
    SEXP_free(rfilters);
    SEXP_free(filters);
    SEXP_free(op_val);

    return ret;
}

static int probe_executor_eval_obj_ref(probe_executor_t *exec, SEXP_t *obj_ref, SEXP_t **out) {
    int ret = 0;
    SEXP_t *oid = NULL, *obj;

    dD("probe_executor_eval_obj_ref: Evaluating object reference");
    dO(OSCAP_DEBUGOBJ_SEXP, obj_ref);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(obj_ref);
    __attribute__nonnull__(out);

    oid = probe_ent_getval(obj_ref);
    if(oid == NULL) {
        dE("probe_executor_eval_obj_ref: Failed to get object reference entity value");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    obj = probe_rcache_sexp_get(exec->rcache, oid);
    if(obj != NULL) {
        dD("probe_executor_eval_obj_ref: Serving object reference from cache");
        *out = obj;
        goto cleanup;
    }
    ret = probe_executor_eval_obj_ref_nocache(exec, oid, out);
    if(ret != 0) {
        dE("probe_executor_eval_obj_ref: Failed to evaluate object reference");
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
        dE("probe_executor_eval_obj_ref_nocache: No object evaluation handler provided");
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    res = exec->ctx.probe_cmd_handlers.obj_eval(oid, exec->ctx.probe_cmd_handler_arg);
    if(res == NULL) {
        dE("probe_executor_eval_obj_ref_nocache: Object evaluation handler failed");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    roid = SEXP_list_first(res);
    if(roid == NULL) {
        dE("probe_executor_eval_obj_ref_nocache: Failed to get OID from object evaluation result");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    if(SEXP_string_cmp(oid, roid) != 0) {
        dE("probe_executor_eval_obj_ref_nocache: Unexpected OID in object evaluation result");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    obj = probe_rcache_sexp_get(exec->rcache, oid);
    if(obj == NULL) {
        dE("probe_executor_eval_obj_ref_nocache: Object evaluation result not found in cache");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }

    *out = obj;

    fail:
    SEXP_free(roid);
    SEXP_free(res);

    return ret;
}

static int probe_executor_fetch_filters(probe_executor_t *exec, SEXP_t *filters, SEXP_t **out) {
    int ret;
    SEXP_t *sid = NULL, *sids = NULL;
    SEXP_t *action = NULL, *state = NULL;
    SEXP_t *filter = NULL, *rfilter = NULL, *rfilters = NULL;

    dD("probe_executor_fetch_filters: Fetching filters");
    dO(OSCAP_DEBUGOBJ_SEXP, filters);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(filters);
    __attribute__nonnull__(out);

    sids = SEXP_list_new(NULL);
    if(sids == NULL) {
        dE("probe_executor_fetch_filters: Failed to create filter state ID list");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    SEXP_list_foreach(filter, filters) {
        sid = SEXP_list_nth(filter, 2);
        if(sid == NULL) {
            dE("probe_executor_fetch_filters: Invalid filter provided; could not extract state ID");
            ret = PROBE_EINVAL;
            goto fail;
        }
        if(SEXP_list_add(sids, sid) == NULL) {
            dE("probe_executor_fetch_filters: Failed to add filter state ID to filter state ID list");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        _SEXP_free(sid);
    }
    // Hydrate the cache with all required filters
    ret = probe_executor_fetch_ste(exec, sids, NULL);
    if(ret != 0) {
        dE("probe_executor_fetch_filters: Failed to fetch filter states");
        goto fail;
    }
    rfilters = SEXP_list_new(NULL);
    if(rfilters == NULL) {
        dE("probe_executor_fetch_filters: Failed to create response filters list");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    SEXP_list_foreach(filter, filters) {
        action = SEXP_list_nth(filter, 1);
        if(action == NULL) {
            dE("probe_executor_fetch_filters: Invalid filter provided; could not extract action");
            ret = PROBE_EINVAL;
            goto fail;
        }
        sid = SEXP_list_nth(filter, 2);
        if(sid == NULL) {
            dE("probe_executor_fetch_filters: Invalid filter provided; could not extract state ID");
            ret = PROBE_EINVAL;
            goto fail;
        }
        state = probe_rcache_sexp_get(exec->rcache, sid);
        if(state == NULL) {
            dE("probe_executor_fetch_filters: Filter state not found in cache after hydration");
            ret = PROBE_ENOENT;
            goto fail;
        }
        rfilter = SEXP_list_new(action, state);
        if(rfilter == NULL) {
            dE("probe_executor_fetch_filters: Failed to create response filter");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        if(SEXP_list_add(rfilters, rfilter) == NULL) {
            dE("probe_executor_fetch_filters: Failed to add response filter to response filters list");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        _SEXP_free(rfilter);
        _SEXP_free(state);
        _SEXP_free(sid);
        _SEXP_free(action);
    }

    *out = rfilters;

    goto cleanup;

    fail:
    SEXP_free(rfilter);
    SEXP_free(state);
    SEXP_free(sid);
    SEXP_free(action);
    SEXP_free(filter);

    cleanup:
    SEXP_free(sids);

    return ret;
}

static int probe_executor_fetch_ste(probe_executor_t *exec, SEXP_t *sids, SEXP_t **out) {
    int ret = 0;
    bool return_states;
    SEXP_t *sid = NULL, *rsids = NULL;
    SEXP_t *state = NULL, *states = NULL,  *rstates = NULL, **prstates;

    dD("probe_executor_fetch_ste: Fetching states");
    dO(OSCAP_DEBUGOBJ_SEXP, sids);

    __attribute__nonnull__(exec);
    __attribute__nonnull__(sids);

    return_states = out != NULL ? true : false;
    prstates = return_states ? &rstates : NULL;

    if(return_states) {
        states = SEXP_list_new(NULL);
        if (states == NULL) {
            dE("probe_executor_fetch_ste: Failed to create state list");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
    }
    rsids = SEXP_list_new(NULL);
    if(rsids == NULL) {
        dE("probe_executor_fetch_ste: Failed to create requested state ID list");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    SEXP_list_foreach(sid, sids) {
        state = probe_rcache_sexp_get(exec->rcache, sid);
        if(state != NULL) {
            dD("probe_executor_fetch_ste: Serving state from cache");
            if(return_states && SEXP_list_add(states, state) == NULL) {
                dE("probe_executor_fetch_ste: Failed to add cached state to state list");
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
            _SEXP_free(state);
            continue;
        }
        if(SEXP_list_add(rsids, sid) == NULL) {
            dE("probe_executor_fetch_ste: Failed to add state ID to requested state ID list");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
    };
    if(SEXP_list_length(rsids) == 0) {
        goto cleanup;
    }
    ret = probe_executor_fetch_ste_nocache(exec, rsids, prstates);
    if(ret != 0) {
        dE("probe_executor_fetch_ste: Failed to fetch states");
        goto fail;
    }
    if(return_states) {
        SEXP_list_foreach(state, rstates) {
            if (SEXP_list_add(states, state) == NULL) {
                dE("probe_executor_fetch_ste: Failed to add requested state to state list");
                ret = PROBE_EUNKNOWN;
                goto fail;
            }
        }
        *out = states;
    }

    goto cleanup;

fail:
    SEXP_free(sid);
    SEXP_free(state);
    SEXP_free(states);

cleanup:
    SEXP_free(rstates);
    SEXP_free(rsids);

    return ret;
}

static int probe_executor_fetch_ste_nocache(probe_executor_t *exec, SEXP_t *sids, SEXP_t **out) {
    int ret = 0;
    size_t n, i;
    SEXP_t *sid = NULL, *state = NULL, *states = NULL;

    __attribute__nonnull__(exec);
    __attribute__nonnull__(sids);
    __attribute__nonnull__(out);


    if(exec->ctx.probe_cmd_handlers.ste_fetch == NULL) {
        dE("probe_executor_fetch_ste_nocache: No state fetch handler provided");
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    states = exec->ctx.probe_cmd_handlers.ste_fetch(sids, exec->ctx.probe_cmd_handler_arg);
    if(states == NULL) {
        dE("probe_executor_fetch_ste_nocache: State fetch handler failed");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    n = SEXP_list_length(states);
    if(n != SEXP_list_length(sids)) {
        dE("probe_executor_fetch_ste_nocache: State fetch handler failed");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }

    for(i = 1; i <= n; i++) {
        sid = SEXP_list_nth(sids, i);
        if(sid == NULL) {
            dE("probe_executor_fetch_ste_nocache: Failed to fetch state ID from requested state ID list");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        state = SEXP_list_nth(states, i);
        if(state == NULL) {
            dE("probe_executor_fetch_ste_nocache: Failed to fetch state from requested state list");
            ret = PROBE_EUNKNOWN;
            goto fail;
        }
        ret = probe_rcache_sexp_add(exec->rcache, sid, state);
        if(ret != 0) {
            dE("probe_executor_fetch_ste_nocache: Failed to add state to cache");
            goto fail;
        }
        _SEXP_free(sid);
        _SEXP_free(state);
    }

    *out = states;

    goto cleanup;

fail:
    SEXP_free(state);
    SEXP_free(sid);
    SEXP_free(states);

cleanup:
    return ret;
}
