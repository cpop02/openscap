//
// Created by Sorin Otescu on 30/09/2020.
//

#include <OVAL/probes/SEAP/public/sexp.h>
#include <common/debug_priv.h>
#include "default_probe.h"

#ifdef EXTERNAL_PROBE_COLLECT

static oval_external_probe_value_map_t *convert_probe_ents(SEXP_t *probe_in) {
    SEXP_t *objents, *ent, *ent_name;

    ent = NULL;
    objents = SEXP_list_rest(probe_in);

    oval_external_probe_value_map_t *values = oval_external_probe_value_map_new(NULL, NULL);

    SEXP_list_foreach(ent, objents) {
        ent_name = SEXP_list_first(ent);

        if (SEXP_listp(ent_name)) {
            SEXP_t *nr;

            nr = SEXP_list_first(ent_name);
            SEXP_free(ent_name);
            ent_name = nr;
        }

        if (SEXP_stringp(ent_name)) {
            SEXP_t *sval = probe_ent_getval(ent);
            oval_external_probe_value_t *val = NULL;

            if (SEXP_numberp(sval)) {
                switch (SEXP_number_type(sval)) {
                    case SEXP_NUM_BOOL:
                        val = oval_external_probe_value_new_boolean(SEXP_number_getb(sval));
                        break;
                    case SEXP_NUM_INT8:
                    case SEXP_NUM_UINT8:
                    case SEXP_NUM_INT16:
                    case SEXP_NUM_UINT16:
                    case SEXP_NUM_INT32:
                    case SEXP_NUM_UINT32:
                    case SEXP_NUM_INT64:
                    case SEXP_NUM_UINT64:
                        val = oval_external_probe_value_new_integer(SEXP_number_geti_64(sval));
                        break;
                    case SEXP_NUM_DOUBLE:
                        val = oval_external_probe_value_new_float(SEXP_number_getf(sval));
                        break;
                    default:
                        dW("Skipping SEXP number type %d", SEXP_number_type(sval));
                }
            } else if (SEXP_stringp(sval)) {
                char *str = SEXP_string_cstr(sval);
                val = oval_external_probe_value_new_string(str);
                free(str);
            } else {
                dW("Skipping unknown/unsupported SEXP type %s", SEXP_datatype(sval));
            }

            if (val != NULL) {
                char name[1024];
                SEXP_string_cstr_r(ent_name, name, sizeof(name));

                oval_external_probe_value_map_set(values, name, val);
            }
        }

        SEXP_free(ent_name);
    }

    return values;
}

int default_probe_main(probe_ctx *ctx, oval_subtype_t probe_type) {
    oval_external_probe_eval_funcs_t *eval = probe_get_external_probe_eval(ctx);
    if (eval == NULL || eval->default_probe == NULL)
        return PROBE_EOPNOTSUPP;

    SEXP_t *probe_in = probe_ctx_getobject(ctx);

    SEXP_t *oid = NULL;
    oval_external_probe_result_t *res = NULL;

    oid = probe_obj_getattrval(probe_in, "id");
    if (oid == NULL)
        return PROBE_ENOVAL;

    int err = PROBE_ENOVAL;

    char *id = SEXP_string_cstr(oid);
    res = eval->default_probe(eval->probe_ctx, probe_type, id, convert_probe_ents(probe_in));
    free(id);

    if (res == NULL) {
        goto cleanup;
    }

    err = oval_external_probe_result_get_status(res);
    if (err != 0)
        goto cleanup;

    SEXP_t *item = probe_item_create(probe_type, NULL, NULL);

    const char *value_str;
    int64_t value_int;
    double value_flt;
    bool value_bool;

    const char *name;
    oval_external_probe_value_t *val;
    oval_external_probe_value_map_t *res_fields = oval_external_probe_result_get_fields(res);
    OVAL_EXTERNAL_PROBE_VALUE_MAP_FOREACH(res_fields, name, val, {
        oval_datatype_t value_type = oval_external_probe_value_get_datatype(val);
        void *pvalue = NULL;
        err = 0;

        switch (value_type) {
            case OVAL_DATATYPE_BOOLEAN:
                value_bool = oval_external_probe_value_get_boolean(val);
                pvalue = &value_bool;
                break;
            case OVAL_DATATYPE_FLOAT:
                value_flt = oval_external_probe_value_get_float(val);
                pvalue = &value_flt;
                break;
            case OVAL_DATATYPE_INTEGER:
                value_int = oval_external_probe_value_get_integer(val);
                pvalue = &value_int;
                break;
            case OVAL_DATATYPE_STRING:
                value_str = oval_external_probe_value_get_string(val);
                pvalue = &value_str;
                break;
            default:
                err = PROBE_EINVAL;
        }

        if (err == 0)
            err = probe_item_add_value(item, name, value_type, pvalue);
        if (err != 0)
            break;
    })

    if (err == 0)
        probe_item_collect(ctx, item);
    else
        SEXP_free(item);

    cleanup:
    oval_external_probe_result_free(res);
    SEXP_free(oid);

    return err;
}

#endif
