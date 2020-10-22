//
// Created by Cristian Pop on 19/10/2020.
//

#include <sexp.h>
#include <debug_priv.h>
#include <oval_external_probe.h>
#include <oval_evaluation.h>
#include <probe-api.h>

#include "default_probe.h"
#include "OVAL/probes/probe/probe.h"

static int probe_collect_external_probe_items(probe_ctx *ctx, oval_subtype_t type, oval_syschar_status_t status, oval_external_probe_item_list_t *ext_items);
static int probe_collect_external_probe_item(probe_ctx *ctx, oval_subtype_t type, oval_syschar_status_t status, oval_external_probe_item_t *ext_item);

int default_probe_main(probe_ctx *ctx, void *arg) {
    int ret;
    char *str_id = NULL;
    void *ext_probe_data;
    SEXP_t *in, *id = NULL;
    oval_evaluation_t *eval;
    oval_syschar_status_t status;
    oval_external_probe_result_t *ext_res = NULL;
    oval_external_probe_item_list_t *ext_items;
    oval_external_probe_handler_t ext_probe_handler;

    dD("default_probe: Handling external probe");

    __attribute__nonnull__(ctx);

    if(ctx->probe_data == NULL) {
        dW("default_probe: No probe data provided");
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    eval = (oval_evaluation_t*)ctx->probe_data;


    in = probe_ctx_getobject(ctx);
    id = probe_obj_getattrval(in, "id");
    if(id == NULL) {
        ret = PROBE_ENOVAL;
        goto fail;
    }
    str_id = SEXP_string_cstr(id);
    if(str_id == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ext_probe_data = oval_evaluation_get_probe_data(eval);
    ext_probe_handler = oval_evaluation_get_probe_handler(eval);
    if(ext_probe_handler == NULL) {
        dW("default_probe: No external probe handler provided");
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    ext_res = ext_probe_handler(ext_probe_data, ctx->probe_type, str_id);
    if(ext_res == NULL) {
        dE("default_probe: External probe handler failed");
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    status = oval_external_probe_result_get_status(ext_res);
    ext_items = oval_external_probe_result_get_items(ext_res);
    ret = probe_collect_external_probe_items(ctx, ctx->probe_type, status, ext_items);

fail:
    oval_external_probe_result_free(ext_res);
    free(str_id);
    SEXP_free(id);

    return ret;
}

static int probe_collect_external_probe_items(probe_ctx *ctx, oval_subtype_t type, oval_syschar_status_t status, oval_external_probe_item_list_t *ext_items) {
    int ret = 0;
    oval_external_probe_item_t *ext_item;

    dD("external_probe: Collecting items for probe of type %d with status %d", type, status);

    __attribute__nonnull__(ctx);

    if(ext_items != NULL) {
        OVAL_EXTERNAL_PROBE_ITEM_LIST_FOREACH(ext_items, ext_item, {
            ret = probe_collect_external_probe_item(ctx, type, status, ext_item);
            if (ret != 0) {
                dE("Failed to collect item for probe of type %d with status %d", type, status);
                break;
            }
        })
    }

    return ret;
}

static int probe_collect_external_probe_item(probe_ctx *ctx, oval_subtype_t type, oval_syschar_status_t status, oval_external_probe_item_t *ext_item) {
    int ret = 0;
    bool b_val;
    double f_val;
    long long i_val;
    const char *str_val, *ext_item_name;
    void *ptr_val;
    SEXP_t *probe_item;
    oval_datatype_t ext_item_value_type;
    oval_external_probe_item_value_t *ext_item_val;

    dD("external_probe: Collecting item for probe of type %d with status %d", type, status);

    __attribute__nonnull__(ctx);
    __attribute__nonnull__(ext_item);

    probe_item = probe_item_create(type, NULL, NULL);
    OVAL_EXTERNAL_PROBE_ITEM_FOREACH(ext_item, ext_item_name, ext_item_val, {
        ext_item_value_type = oval_external_probe_item_value_get_datatype(ext_item_val);
        switch(ext_item_value_type) {
            case OVAL_DATATYPE_BOOLEAN:
                b_val = oval_external_probe_item_value_get_boolean(ext_item_val);
                ptr_val = &b_val;
                break;
            case OVAL_DATATYPE_FLOAT:
                f_val = oval_external_probe_item_value_get_float(ext_item_val);
                ptr_val = &f_val;
                break;
            case OVAL_DATATYPE_INTEGER:
                i_val = oval_external_probe_item_value_get_integer(ext_item_val);
                ptr_val = &i_val;
                break;
            case OVAL_DATATYPE_STRING:
                str_val = oval_external_probe_item_value_get_string(ext_item_val);
                ptr_val = &str_val;
                break;
            default:
                dW("external_probe: Unsupported external probe item value data type %d", ext_item_value_type);
                ret = PROBE_EINVAL;
        }
        if(ret != 0) {
            break;
        }
        ret = probe_item_add_value(probe_item, ext_item_name, ext_item_value_type, ptr_val);
        if(ret != 0) {
            dE("external_probe: Failed to add probe item value of type %d with name %s", ext_item_value_type, ext_item_name);
            break;
        }
    })
    if(ret != 0) {
        goto fail;
    }
    ret = probe_ent_setstatus(probe_item, status);
    if(ret != 0) {
        goto fail;
    }
    ret = probe_item_collect(ctx, probe_item);
    if(ret != 0) {
        goto fail;
    }

    goto cleanup;

fail:
    SEXP_free(probe_item);

cleanup:
    return ret;
}
