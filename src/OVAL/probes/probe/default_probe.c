//
// Created by Sorin Otescu on 30/09/2020.
//

#include <OVAL/probes/SEAP/public/sexp.h>
#include <common/debug_priv.h>
#include <oval_external_probe.h>
#include "default_probe.h"

#ifdef EXTERNAL_PROBE_COLLECT

static int create_query(SEXP_t *in, oval_external_probe_item_t** out_ext_query) {
    int ret = 0;
    char *str_val, *item_val_name;
    oval_external_probe_item_t *ext_query;
    oval_external_probe_item_value_t *item_val;
    SEXP_t *ents = NULL, *ent, *ent_name, *ent_val, *aux;

    __attribute__nonnull__(in);
    __attribute__nonnull__(out_ext_query);

    ext_query = oval_external_probe_item_new(NULL, NULL);
    if(ext_query == NULL) {
        ret = PROBE_ENOMEM;
        goto fail;
    }

    ents = SEXP_list_rest(in);
    SEXP_list_foreach(ent, ents) {
        item_val = NULL;

        ent_name = SEXP_list_first(ent);
        if(SEXP_listp(ent_name)) {
            aux = SEXP_list_first(ent_name);
            SEXP_free(ent_name);
            ent_name = aux;
        }

        if(SEXP_stringp(ent_name)) {
            ent_val = probe_ent_getval(ent);
            if(SEXP_stringp(ent_val)) {
                str_val = SEXP_string_cstr(ent_val);
                item_val = oval_external_probe_item_value_new_string(str_val);
                free(str_val);
            } else if(SEXP_numberp(ent_val)) {
                switch(SEXP_number_type(ent_val)) {
                    case SEXP_NUM_BOOL:
                        item_val = oval_external_probe_item_value_new_boolean(SEXP_number_getb(ent_val));
                        break;
                    case SEXP_NUM_INT8:
                    case SEXP_NUM_UINT8:
                    case SEXP_NUM_INT16:
                    case SEXP_NUM_UINT16:
                    case SEXP_NUM_INT32:
                    case SEXP_NUM_UINT32:
                    case SEXP_NUM_INT64:
                    case SEXP_NUM_UINT64:
                        item_val = oval_external_probe_item_value_new_integer(SEXP_number_geti_64(ent_val));
                        break;
                    case SEXP_NUM_DOUBLE:
                        item_val = oval_external_probe_item_value_new_float(SEXP_number_getf(ent_val));
                        break;
                    default:
                        dW("Skipping unsupported SEXP number type %d", SEXP_number_type(ent_val));
                }
            } else {
                dW("Skipping unsupported SEXP type %s", SEXP_datatype(ent_val));
            }
            SEXP_free(ent_val);

            if(item_val != NULL) {
                item_val_name = SEXP_string_cstr(ent_name);
                oval_external_probe_item_set_value(ext_query, item_val_name, item_val);
                free(item_val_name);
            }
        }
        SEXP_free(ent_name);
    }

    *out_ext_query = ext_query;

    goto cleanup;

fail:
    oval_external_probe_item_free(ext_query);

cleanup:
    SEXP_free(ents);

    return ret;
}

static int collect_item(probe_ctx *ctx, oval_subtype_t type, oval_syschar_status_t status, oval_external_probe_item_t *ext_item) {
    int ret = 0;
    bool b_val;
    double f_val;
    long long i_val;
    const char *str_val, *ext_item_name;
    void *ptr_val;
    SEXP_t *probe_item;
    oval_datatype_t ext_item_value_type;
    oval_external_probe_item_value_t *ext_item_val;

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
                dW("Unsupported external probe item value data type %d", ext_item_value_type);
                ret = PROBE_EINVAL;
        }
        if(ret != 0) {
            break;
        }
        ret = probe_item_add_value(probe_item, ext_item_name, ext_item_value_type, ptr_val);
        if(ret != 0) {
            dW("Failed to add probe item value of type %d with name %s", ext_item_value_type, ext_item_name);
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

static int collect_items(probe_ctx *ctx, oval_subtype_t type, oval_syschar_status_t status, oval_external_probe_item_list_t *ext_items) {
    int ret = 0;
    oval_external_probe_item_t *ext_item;

    __attribute__nonnull__(ctx);
    __attribute__nonnull__(ext_items);

    OVAL_EXTERNAL_PROBE_ITEM_LIST_FOREACH(ext_items, ext_item, {
        ret = collect_item(ctx, type, status, ext_item);
        if(ret != 0) {
            dW("Failed to collect item for probe type %d", type);
            break;
        }
    })

    return ret;
}

int default_probe_main(probe_ctx *ctx, oval_subtype_t type) {
    int ret;
    char *str_id = NULL;
    SEXP_t *in, *id = NULL;
    oval_syschar_status_t status;
    oval_external_probe_eval_funcs_t *eval;
    oval_external_probe_item_t *ext_query = NULL;
    oval_external_probe_result_t *ext_res = NULL;
    oval_external_probe_item_list_t *ext_items;

    __attribute__nonnull__(ctx);

    eval = probe_get_external_probe_eval(ctx);
    if(eval == NULL || eval->default_probe == NULL) {
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
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
    ret = create_query(in, &ext_query);
    if(ret != 0) {
        goto fail;
    }
    ext_res = eval->default_probe(eval->probe_ctx, type, str_id, ext_query);
    if(ext_res == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    status = oval_external_probe_result_get_status(ext_res);
    if(status == SYSCHAR_STATUS_ERROR) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ext_items = oval_external_probe_result_get_items(ext_res);
    if(ext_items == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ret = collect_items(ctx, type, status, ext_items);

fail:
    oval_external_probe_result_free(ext_res);
    oval_external_probe_item_free(ext_query);
    free(str_id);
    SEXP_free(id);

    return ret;
}

#endif
