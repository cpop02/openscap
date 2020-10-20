/**
 * @file oval_external_probe_result.c
 * \brief Open Vulnerability and Assessment Language
 *
 * See more details at http://oval.mitre.org/
 */

#include "oval_external_probe.h"
#include "probe-api.h"
#include "adt/oval_collection_impl.h"

struct oval_external_probe_result {
    char* name;
    oval_syschar_status_t status;
    oval_external_probe_item_list_t* items;
};

oval_external_probe_result_t* oval_external_probe_result_new(char* name) {
    oval_external_probe_result_t* res;

    __attribute__nonnull__(name);

    res = (oval_external_probe_result_t*)malloc(sizeof(oval_external_probe_result_t));
    if(res == NULL) {
        goto fail;
    }
    res->name = oscap_strdup(name);
    if(res->name == NULL) {
        goto fail;
    }
    res->status = PROBE_EINIT;
    res->items = NULL;

    goto cleanup;

    fail:
    oval_external_probe_result_free(res);
    res = NULL;

    cleanup:
    return res;
}

void oval_external_probe_result_free(oval_external_probe_result_t* res) {
    if(res != NULL) {
        oval_external_probe_item_list_free(res->items);
        res->items = NULL;
        free(res->name);
        res->name = NULL;
    }
    free(res);
}

void oval_external_probe_result_set_status(oval_external_probe_result_t* res, oval_syschar_status_t status) {
    __attribute__nonnull__(res);
    res->status = status;
}

void oval_external_probe_result_set_items(oval_external_probe_result_t* res, oval_external_probe_item_list_t* items) {
    __attribute__nonnull__(res);
    if(res->items != items) {
        oval_external_probe_item_list_free(res->items);
        res->items = items;
    }
}

const char* oval_external_probe_result_get_name(oval_external_probe_result_t* res) {
    __attribute__nonnull__(res);
    return res->name;
}

oval_syschar_status_t oval_external_probe_result_get_status(oval_external_probe_result_t* res) {
    __attribute__nonnull__(res);
    return res->status;
}

oval_external_probe_item_list_t* oval_external_probe_result_get_items(oval_external_probe_result_t* res) {
    __attribute__nonnull__(res);
    return res->items;
}