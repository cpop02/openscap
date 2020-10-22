//
// Created by Cristian Pop on 19/10/2020.
//

#ifndef OVAL_EXTERNAL_PROBE_H_
#define OVAL_EXTERNAL_PROBE_H_

#include "oscap_export.h"
#include "oval_definitions.h"
#include "oval_types.h"
#include "oval_system_characteristics.h"

typedef struct oval_external_probe_item_value oval_external_probe_item_value_t;
typedef struct oval_external_probe_item oval_external_probe_item_t;
typedef struct oval_external_probe_item_list oval_external_probe_item_list_t;
typedef struct oval_external_probe_result oval_external_probe_result_t;

struct oval_external_probe_item_iterator;
struct oval_external_probe_item_list_iterator;

typedef oval_external_probe_result_t* (*oval_external_probe_handler_t)(void *eval_ctx, oval_subtype_t probe_type, char *oval_id);

OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_string(char* val);
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_stringf(char* fmt, ...);
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_boolean(bool val);
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_float(double val);
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_integer(long long val);
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_clone(oval_external_probe_item_value_t* old_value);
OSCAP_API void oval_external_probe_item_value_free(oval_external_probe_item_value_t* value);
OSCAP_API oval_datatype_t oval_external_probe_item_value_get_datatype(oval_external_probe_item_value_t* value);
OSCAP_API const char* oval_external_probe_item_value_get_string(oval_external_probe_item_value_t* value);
OSCAP_API bool oval_external_probe_item_value_get_boolean(oval_external_probe_item_value_t* value);
OSCAP_API double oval_external_probe_item_value_get_float(oval_external_probe_item_value_t* value);
OSCAP_API long long oval_external_probe_item_value_get_integer(oval_external_probe_item_value_t* value);

OSCAP_API oval_external_probe_item_t* oval_external_probe_item_new(char* name, oval_external_probe_item_value_t* value, ...);
OSCAP_API void oval_external_probe_item_free(oval_external_probe_item_t* item);
OSCAP_API void oval_external_probe_item_set_value(oval_external_probe_item_t* item, char* name, oval_external_probe_item_value_t* value);
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_get_value(oval_external_probe_item_t* item, const char* name);

OSCAP_API oval_external_probe_item_list_t* oval_external_probe_item_list_new(oval_external_probe_item_t* item, ...);
OSCAP_API void oval_external_probe_item_list_free(oval_external_probe_item_list_t* list);
OSCAP_API void oval_external_probe_item_list_push(oval_external_probe_item_list_t* list, oval_external_probe_item_t* item);

OSCAP_API oval_external_probe_result_t* oval_external_probe_result_new(char* name);
OSCAP_API void oval_external_probe_result_free(oval_external_probe_result_t* res);

OSCAP_API void oval_external_probe_result_set_status(oval_external_probe_result_t* res, oval_syschar_status_t status);
OSCAP_API void oval_external_probe_result_set_items(oval_external_probe_result_t* res, oval_external_probe_item_list_t* list);
OSCAP_API const char* oval_external_probe_result_get_name(oval_external_probe_result_t* res);
OSCAP_API oval_syschar_status_t oval_external_probe_result_get_status(oval_external_probe_result_t* res);
OSCAP_API oval_external_probe_item_list_t* oval_external_probe_result_get_items(oval_external_probe_result_t* res);

OSCAP_API struct oval_external_probe_item_iterator* oval_external_probe_item_iterator_new(oval_external_probe_item_t* item);
OSCAP_API void oval_external_probe_item_iterator_free(struct oval_external_probe_item_iterator* it);
OSCAP_API bool oval_external_probe_item_iterator_has_more_values(struct oval_external_probe_item_iterator* it);
OSCAP_API const char* oval_external_probe_item_iterator_next_value_name(struct oval_external_probe_item_iterator* it);

// Do not return from 'code' or use 'goto' to a label outside 'code' ! Otherwise the iterator will not be freed.
#define OVAL_EXTERNAL_PROBE_ITEM_FOREACH(item, name_var, val_var, code) {                                               \
        struct oval_external_probe_item_iterator *item##_iter = oval_external_probe_item_iterator_new(item);            \
        while(oval_external_probe_item_iterator_has_more_values(item##_iter)) {                                         \
            (name_var) = oval_external_probe_item_iterator_next_value_name(item##_iter);                                \
            (val_var) = oval_external_probe_item_get_value(item, name_var);                                             \
            code                                                                                                        \
        }                                                                                                               \
        oval_external_probe_item_iterator_free(item##_iter);                                                            \
    }

OSCAP_API struct oval_external_probe_item_list_iterator* oval_external_probe_item_list_iterator_new(oval_external_probe_item_list_t* list);
OSCAP_API void oval_external_probe_item_list_iterator_free(struct oval_external_probe_item_list_iterator* it);
OSCAP_API bool oval_external_probe_item_list_iterator_has_more_items(struct oval_external_probe_item_list_iterator* it);
OSCAP_API oval_external_probe_item_t* oval_external_probe_item_list_iterator_next_item(struct oval_external_probe_item_list_iterator* it);

// Do not return from 'code' or use 'goto' to a label outside 'code' ! Otherwise the iterator will not be freed.
#define OVAL_EXTERNAL_PROBE_ITEM_LIST_FOREACH(list, item_var, code) {                                                   \
        struct oval_external_probe_item_list_iterator *list##_iter = oval_external_probe_item_list_iterator_new(list);  \
        while(oval_external_probe_item_list_iterator_has_more_items(list##_iter)) {                                     \
            (item_var) = oval_external_probe_item_list_iterator_next_item(list##_iter);                                 \
            code                                                                                                        \
        }                                                                                                               \
        oval_external_probe_item_list_iterator_free(list##_iter);                                                       \
    }

#endif  // OVAL_EXTERNAL_PROBE_H_
