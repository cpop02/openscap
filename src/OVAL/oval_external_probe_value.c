/**
 * @file oval_external_probe_value.c
 * \brief Open Vulnerability and Assessment Language
 *
 * See more details at http://oval.mitre.org/
 */

#include "list.h"
#include "oval_definitions.h"
#include "oval_external_probe.h"
#include "oval_types.h"
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "adt/oval_collection_impl.h"

struct oval_external_probe_value {
    oval_datatype_t datatype;
    union {
        char* str_val;
        float float_val;
        bool bool_val;
        long long int_val;
    };
};

struct oval_external_probe_value_map {
    struct oscap_htable* htbl;
};

oval_external_probe_value_map_t* oval_external_probe_value_map_new(char* name, oval_external_probe_value_t* value, ...) {
    oval_external_probe_value_map_t* map = (oval_external_probe_value_map_t*)malloc(sizeof(oval_external_probe_value_map_t));
    if (map == NULL)
        return NULL;

    va_list ap;
    va_start(ap, value);

    map->htbl = oscap_htable_new();

    while (name != NULL) {
        oscap_htable_add(map->htbl, name, value);

        name = va_arg(ap, char*);
        if (name == NULL)
            break;

        value = va_arg(ap, oval_external_probe_value_t*);
    }
	va_end(ap);

    return map;
}

void oval_external_probe_value_map_free(oval_external_probe_value_map_t* map) {
    if (map == NULL)
        return;

    oscap_htable_free(map->htbl, (oscap_destruct_func)oval_external_probe_value_free);   
    map->htbl = NULL;   // paranoia
    
    free(map);
}

void oval_external_probe_value_map_set(oval_external_probe_value_map_t* map, char* name, oval_external_probe_value_t* value) {
    __attribute__nonnull__(map);
    __attribute__nonnull__(name);
    oscap_htable_add(map->htbl, name, value);
}

oval_external_probe_value_t* oval_external_probe_value_map_get(oval_external_probe_value_map_t* map, const char* name) {
    __attribute__nonnull__(map);
    __attribute__nonnull__(name);
    return (oval_external_probe_value_t*)oscap_htable_get(map->htbl, name);
}

struct oval_external_probe_value_map_iterator* oval_external_probe_value_map_iterator_new(oval_external_probe_value_map_t* map) {
    __attribute__nonnull__(map);
    return (struct oval_external_probe_value_map_iterator*)oscap_htable_iterator_new(map->htbl);
}

bool oval_external_probe_value_map_iterator_has_more(struct oval_external_probe_value_map_iterator* it) {
    __attribute__nonnull__(it);
    return oscap_htable_iterator_has_more((struct oscap_htable_iterator *)it);
}

const char* oval_external_probe_value_map_iterator_next_key(struct oval_external_probe_value_map_iterator* it) {
    __attribute__nonnull__(it);
    return oscap_htable_iterator_next_key((struct oscap_htable_iterator *)it);
}

void oval_external_probe_value_map_iterator_free(struct oval_external_probe_value_map_iterator* it) {
    if (it == NULL)
        return;
    oscap_htable_iterator_free((struct oscap_htable_iterator *)it);
}

int oval_external_probe_value_iterator_remaining(struct oval_external_probe_value_map_iterator* iterator) {
    return oval_collection_iterator_remaining((struct oval_iterator*)iterator);
}

oval_datatype_t oval_external_probe_value_get_datatype(oval_external_probe_value_t* value) {
    __attribute__nonnull__(value);
    return value->datatype;
}

const char* oval_external_probe_value_get_string(oval_external_probe_value_t* value) {
    __attribute__nonnull__(value);
    __attribute__nonnull__(value->str_val);
    if (value->datatype != OVAL_DATATYPE_STRING)
        return NULL;
    return value->str_val;
}

bool oval_external_probe_value_get_boolean(oval_external_probe_value_t* value) {
    __attribute__nonnull__(value);
    if (value->datatype != OVAL_DATATYPE_BOOLEAN)
        return false;
    return value->bool_val;
}

float oval_external_probe_value_get_float(oval_external_probe_value_t* value) {
    __attribute__nonnull__(value);
    if (value->datatype != OVAL_DATATYPE_FLOAT)
        return 0;
    return value->float_val;
}

long long oval_external_probe_value_get_integer(oval_external_probe_value_t* value) {
    __attribute__nonnull__(value);
    if (value->datatype != OVAL_DATATYPE_INTEGER)
        return 0;
    return value->int_val;
}

oval_external_probe_value_t* oval_external_probe_value_new_string(char* val) {
    oval_external_probe_value_t* value = (oval_external_probe_value_t*)malloc(sizeof(oval_external_probe_value_t));
    if (value == NULL)
        return NULL;
    value->datatype = OVAL_DATATYPE_STRING;
    value->str_val = oscap_strdup(val);
    return value;
}

oval_external_probe_value_t* oval_external_probe_value_new_stringf(char* fmt, ...) {
    va_list ap, copy;
    char *v_string = NULL;
    int v_strlen = 0;

    va_start(ap, fmt);
    va_copy(copy, ap);
    v_strlen = vsnprintf(v_string, v_strlen, fmt, copy);
    va_end(copy);
    if (v_strlen < 0) {
        return NULL;
    }
    v_strlen++; /* For '\0' */
    v_string = malloc(v_strlen);
    v_strlen = vsnprintf(v_string, v_strlen, fmt, ap);
    if (v_strlen < 0) {
        free(v_string);
        return NULL;
    }
    va_end(ap);

    oval_external_probe_value_t* value = (oval_external_probe_value_t*)malloc(sizeof(oval_external_probe_value_t));
    if (value == NULL) {
        free(v_string);
        return NULL;
    }

    value->datatype = OVAL_DATATYPE_STRING;
    value->str_val = v_string;
    return value;
}

oval_external_probe_value_t* oval_external_probe_value_new_boolean(bool val) {
    oval_external_probe_value_t* value = (oval_external_probe_value_t*)malloc(sizeof(oval_external_probe_value_t));
    if (value == NULL)
        return NULL;
    value->datatype = OVAL_DATATYPE_BOOLEAN;
    value->bool_val = val;
    return value;
}

oval_external_probe_value_t* oval_external_probe_value_new_float(float val) {
    oval_external_probe_value_t* value = (oval_external_probe_value_t*)malloc(sizeof(oval_external_probe_value_t));
    if (value == NULL)
        return NULL;
    value->datatype = OVAL_DATATYPE_FLOAT;
    value->float_val = val;
    return value;
}

oval_external_probe_value_t* oval_external_probe_value_new_integer(long long val) {
    oval_external_probe_value_t* value = (oval_external_probe_value_t*)malloc(sizeof(oval_external_probe_value_t));
    if (value == NULL)
        return NULL;
    value->datatype = OVAL_DATATYPE_INTEGER;
    value->int_val = val;
    return value;
}

oval_external_probe_value_t* oval_external_probe_value_clone(oval_external_probe_value_t* old_value) {
    __attribute__nonnull__(old_value);

    oval_external_probe_value_t* new_value = (oval_external_probe_value_t*)malloc(sizeof(oval_external_probe_value_t));

    *new_value = *old_value;
    if (old_value->datatype == OVAL_DATATYPE_STRING)
        new_value->str_val = oscap_strdup(old_value->str_val);

    return new_value;
}

void oval_external_probe_value_free(oval_external_probe_value_t* value) {
    if (value == NULL)
        return;

    if (value->datatype == OVAL_DATATYPE_STRING)
        free(value->str_val);
    free(value);
}
