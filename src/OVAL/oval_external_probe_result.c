/**
 * @file oval_external_probe_result.c
 * \brief Open Vulnerability and Assessment Language
 *
 * See more details at http://oval.mitre.org/
 */

#include "oval_types.h"
#include "oval_external_probe.h"
#include "probe-api.h"
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "adt/oval_collection_impl.h"

struct oval_external_probe_result {
    char* name;
    oval_external_probe_value_map_t* fields;
    oval_syschar_status_t status;
};

oval_external_probe_result_t* oval_external_probe_result_new(char* name) {
    oval_external_probe_result_t* ext_res = (oval_external_probe_result_t*)malloc(sizeof(oval_external_probe_result_t));
    if (ext_res == NULL)
        return NULL;

    ext_res->name = oscap_strdup(name);
    ext_res->fields = NULL;
	ext_res->status = PROBE_EINIT;
    return ext_res;
}

void oval_external_probe_result_free(oval_external_probe_result_t* ext_res) {
    if (ext_res == NULL)
        return;

    free(ext_res->name);
    oval_external_probe_value_map_free(ext_res->fields);

    ext_res->name = NULL;   // paranoia
    ext_res->fields = NULL;

    free(ext_res);
}

void oval_external_probe_result_set_status(oval_external_probe_result_t* ext_res, oval_syschar_status_t status) {
    __attribute__nonnull__(ext_res);
	ext_res->status = status;
}

void oval_external_probe_result_set_fields(oval_external_probe_result_t* ext_res, oval_external_probe_value_map_t* fields) {
    __attribute__nonnull__(ext_res);
    oval_external_probe_value_map_free(ext_res->fields);
    ext_res->fields = fields;
}

const char* oval_external_probe_result_get_name(oval_external_probe_result_t* ext_res) {
    __attribute__nonnull__(ext_res);
    return ext_res->name;
}

oval_syschar_status_t oval_external_probe_result_get_status(oval_external_probe_result_t* ext_res) {
    __attribute__nonnull__(ext_res);
    return ext_res->status;
}

oval_external_probe_value_map_t* oval_external_probe_result_get_fields(oval_external_probe_result_t* ext_res) {
    __attribute__nonnull__(ext_res);
    return ext_res->fields;
}

const char* oval_external_probe_result_get_field_string(oval_external_probe_result_t* ext_res, const char* name) {
    __attribute__nonnull__(ext_res);
    __attribute__nonnull__(name);
    if (ext_res->fields == NULL)
        return NULL;
    oval_external_probe_value_t* value = oval_external_probe_value_map_get(ext_res->fields, name);
    if (value == NULL)
        return NULL;
    return oval_external_probe_value_get_string(value);
}
