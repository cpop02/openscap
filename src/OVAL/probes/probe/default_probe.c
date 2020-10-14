//
// Created by Sorin Otescu on 30/09/2020.
//

#include <OVAL/probes/SEAP/public/sexp.h>
#include <common/debug_priv.h>
#include <oval_external_probe.h>
#include "default_probe.h"

#ifdef EXTERNAL_PROBE_COLLECT

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
    ret = probe_create_external_probe_query(in, &ext_query);
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
    ret = probe_collect_external_probe_items(ctx, type, status, ext_items);

fail:
    oval_external_probe_result_free(ext_res);
    oval_external_probe_item_free(ext_query);
    free(str_id);
    SEXP_free(id);

    return ret;
}

#endif
