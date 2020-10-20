/**
 * @file oval_external_probe_item.c
 * \brief Open Vulnerability and Assessment Language
 *
 * See more details at http://oval.mitre.org/
 */

#include "list.h"
#include "oval_definitions.h"
#include "oval_external_probe.h"
#include "oval_types.h"

struct oval_external_probe_item_value {
    oval_datatype_t datatype;
    union {
        char* str_val;
        double float_val;
        bool bool_val;
        long long int_val;
    };
};

struct oval_external_probe_item {
    struct oscap_htable* values;
};

oval_external_probe_item_value_t* oval_external_probe_item_value_new_string(char* val) {
    oval_external_probe_item_value_t* value;

    __attribute__nonnull__(val);

    value = (oval_external_probe_item_value_t*)malloc(sizeof(oval_external_probe_item_value_t));
    if(value == NULL) {
        goto fail;
    }
    value->datatype = OVAL_DATATYPE_STRING;
    value->str_val = oscap_strdup(val);
    if(value->str_val == NULL) {
        goto fail;
    }

    goto cleanup;

    fail:
    oval_external_probe_item_value_free(value);
    value = NULL;

    cleanup:
    return value;
}

oval_external_probe_item_value_t* oval_external_probe_item_value_new_stringf(char* fmt, ...) {
    va_list ap, copy;
    char *v_string = NULL;
    int v_strlen = 0;
    oval_external_probe_item_value_t* value = NULL;

    __attribute__nonnull__(fmt);

    va_start(ap, fmt);

    va_copy(copy, ap);
    v_strlen = vsnprintf(v_string, v_strlen, fmt, copy);
    va_end(copy);
    if(v_strlen < 0) {
        goto fail;
    }
    v_strlen++; // For '\0'

    value = (oval_external_probe_item_value_t*)malloc(sizeof(oval_external_probe_item_value_t));
    if(value == NULL) {
        goto fail;
    }
    value->datatype = OVAL_DATATYPE_STRING;
    value->str_val = (char*)malloc(v_strlen);
    if(value->str_val == NULL) {
        goto fail;
    }
    v_strlen = vsnprintf(value->str_val, v_strlen, fmt, ap);
    if(v_strlen < 0) {
        goto fail;
    }

    goto cleanup;

    fail:
    oval_external_probe_item_value_free(value);
    value = NULL;

    cleanup:
    va_end(ap);

    return value;
}

oval_external_probe_item_value_t* oval_external_probe_item_value_new_boolean(bool val) {
    oval_external_probe_item_value_t* value;

    value = (oval_external_probe_item_value_t*)malloc(sizeof(oval_external_probe_item_value_t));
    if(value == NULL) {
        goto fail;
    }
    value->datatype = OVAL_DATATYPE_BOOLEAN;
    value->bool_val = val;

    fail:
    return value;
}

oval_external_probe_item_value_t* oval_external_probe_item_value_new_float(double val) {
    oval_external_probe_item_value_t* value;

    value = (oval_external_probe_item_value_t*)malloc(sizeof(oval_external_probe_item_value_t));
    if(value == NULL) {
        goto fail;
    }
    value->datatype = OVAL_DATATYPE_FLOAT;
    value->float_val = val;

    fail:
    return value;
}

oval_external_probe_item_value_t* oval_external_probe_item_value_new_integer(long long val) {
    oval_external_probe_item_value_t* value;

    value = (oval_external_probe_item_value_t*)malloc(sizeof(oval_external_probe_item_value_t));
    if(value == NULL) {
        goto fail;
    }
    value->datatype = OVAL_DATATYPE_INTEGER;
    value->int_val = val;

    fail:
    return value;
}

oval_external_probe_item_value_t* oval_external_probe_item_value_clone(oval_external_probe_item_value_t* old_value) {
    oval_external_probe_item_value_t* new_value;

    __attribute__nonnull__(old_value);

    new_value = (oval_external_probe_item_value_t*)malloc(sizeof(oval_external_probe_item_value_t));
    if(new_value == NULL) {
        goto fail;
    }

    *new_value = *old_value;
    if(old_value->datatype == OVAL_DATATYPE_STRING) {
        __attribute__nonnull__(old_value->str_val);
        new_value->str_val = oscap_strdup(old_value->str_val);
        if(new_value->str_val == NULL) {
            goto fail;
        }
    }

    goto cleanup;

    fail:
    oval_external_probe_item_value_free(new_value);
    new_value = NULL;

    cleanup:
    return new_value;
}

void oval_external_probe_item_value_free(oval_external_probe_item_value_t* value) {
    if(value != NULL) {
        if(value->datatype == OVAL_DATATYPE_STRING) {
            free(value->str_val);
            value->str_val = NULL;
        }
    }
    free(value);
}

oval_datatype_t oval_external_probe_item_value_get_datatype(oval_external_probe_item_value_t* value) {
    __attribute__nonnull__(value);
    return value->datatype;
}

const char* oval_external_probe_item_value_get_string(oval_external_probe_item_value_t* value) {
    __attribute__nonnull__(value);
    assert(value->datatype == OVAL_DATATYPE_STRING);
    __attribute__nonnull__(value->str_val);
    return value->str_val;
}

bool oval_external_probe_item_value_get_boolean(oval_external_probe_item_value_t* value) {
    __attribute__nonnull__(value);
    assert(value->datatype == OVAL_DATATYPE_BOOLEAN);
    return value->bool_val;
}

double oval_external_probe_item_value_get_float(oval_external_probe_item_value_t* value) {
    __attribute__nonnull__(value);
    assert(value->datatype == OVAL_DATATYPE_FLOAT);
    return value->float_val;
}

long long oval_external_probe_item_value_get_integer(oval_external_probe_item_value_t* value) {
    __attribute__nonnull__(value);
    assert(value->datatype == OVAL_DATATYPE_INTEGER);
    return value->int_val;
}

oval_external_probe_item_t* oval_external_probe_item_new(char* name, oval_external_probe_item_value_t* value, ...) {
    va_list ap;
    oval_external_probe_item_t* item;

    va_start(ap, value);

    item = (oval_external_probe_item_t*)malloc(sizeof(oval_external_probe_item_t));
    if(item == NULL) {
        goto fail;
    }
    item->values = oscap_htable_new();
    if(item->values == NULL) {
        goto fail;
    }
    while(name != NULL) {
        __attribute__nonnull__(value);
        oscap_htable_add(item->values, name, value);
        name = va_arg(ap, char*);
        if(name == NULL) {
            break;
        }
        value = va_arg(ap, oval_external_probe_item_value_t*);
    }

    goto cleanup;

    fail:
    oval_external_probe_item_free(item);
    item = NULL;

    cleanup:
    va_end(ap);

    return item;
}

void oval_external_probe_item_free(oval_external_probe_item_t* item) {
    if(item != NULL) {
        oscap_htable_free(item->values, (oscap_destruct_func)oval_external_probe_item_value_free);
        item->values = NULL;
    }
    free(item);
}

void oval_external_probe_item_set_value(oval_external_probe_item_t* item, char* name, oval_external_probe_item_value_t* value) {
    __attribute__nonnull__(item);
    __attribute__nonnull__(item->values);
    __attribute__nonnull__(name);
    oscap_htable_add(item->values, name, value);
}

oval_external_probe_item_value_t* oval_external_probe_item_get_value(oval_external_probe_item_t* item, const char* name) {
    __attribute__nonnull__(item);
    __attribute__nonnull__(item->values);
    __attribute__nonnull__(name);
    return (oval_external_probe_item_value_t*)oscap_htable_get(item->values, name);
}

struct oval_external_probe_item_iterator* oval_external_probe_item_iterator_new(oval_external_probe_item_t* item) {
    __attribute__nonnull__(item);
    __attribute__nonnull__(item->values);
    return (struct oval_external_probe_item_iterator*)oscap_htable_iterator_new(item->values);
}

bool oval_external_probe_item_iterator_has_more_values(struct oval_external_probe_item_iterator* it) {
    __attribute__nonnull__(it);
    return oscap_htable_iterator_has_more((struct oscap_htable_iterator*)it);
}

const char* oval_external_probe_item_iterator_next_value_name(struct oval_external_probe_item_iterator* it) {
    __attribute__nonnull__(it);
    return oscap_htable_iterator_next_key((struct oscap_htable_iterator*)it);
}

void oval_external_probe_item_iterator_free(struct oval_external_probe_item_iterator* it) {
    oscap_htable_iterator_free((struct oscap_htable_iterator*)it);
}