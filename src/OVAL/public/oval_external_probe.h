/**
 * @addtogroup OVAL
 * @{
 * @addtogroup OVALEXTPROBE
 * Interface for external probes.
 * @{
 *
 * @file
 *
 * @author "Sorin Otescu" <sorin.otescu@crowdstrike.com>
 */

#ifndef OVAL_EXTERNAL_PROBE_H_
#define OVAL_EXTERNAL_PROBE_H_

#include "oscap_export.h"
#include "oval_definitions.h"
#include "oval_types.h"
#include "oval_system_characteristics.h"

/**
 * @struct oval_external_probe_item_value
 * @memberof oval_external_probe
 * Value of an external probe query result item (only if EXTERNAL_PROBE_COLLECT is defined).
 */
typedef struct oval_external_probe_item_value oval_external_probe_item_value_t;
/**
 * @struct oval_external_probe_result
 * @memberof oval_external_probe
 * Item of an external probe query result (only if EXTERNAL_PROBE_COLLECT is defined).
 */
typedef struct oval_external_probe_item oval_external_probe_item_t;
/**
 * @struct oval_external_probe_item_list
 * @memberof oval_external_probe
 * Items of an external probe query result (only if EXTERNAL_PROBE_COLLECT is defined).
 */
typedef struct oval_external_probe_item_list oval_external_probe_item_list_t;
/**
 * @struct oval_external_probe_result
 * @memberof oval_external_probe
 * Result of an external probe query (only if EXTERNAL_PROBE_COLLECT is defined).
 */
typedef struct oval_external_probe_result oval_external_probe_result_t;

/**
 * @struct oval_external_probe_result
 * @memberof oval_external_probe
 * Iterator over the values of an external probe query result item (only if EXTERNAL_PROBE_COLLECT is defined).
 */
struct oval_external_probe_item_iterator;
/**
 * @struct oval_external_probe_result
 * @memberof oval_external_probe
 * Iterator over the items of an external probe query result (only if EXTERNAL_PROBE_COLLECT is defined).
 */
struct oval_external_probe_item_list_iterator;

/**
 * @struct oval_external_probe_eval_funcs
 * @memberof oval_external_probe
 * Handler functions for external probe queries (only if EXTERNAL_PROBE_COLLECT is defined)
 */
typedef struct oval_external_probe_eval_funcs {
    void* probe_ctx;
    // Set to true to always use the default probe
    bool default_probe_only;
    oval_external_probe_result_t* (*default_probe)(void *ctx, oval_subtype_t type, char *id, oval_external_probe_item_t* query);
} oval_external_probe_eval_funcs_t;

/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_string(char* val);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_stringf(char* fmt, ...);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_boolean(bool val);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_float(double val);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_new_integer(long long val);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_value_clone(oval_external_probe_item_value_t* old_value);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API void oval_external_probe_item_value_free(oval_external_probe_item_value_t* value);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API oval_datatype_t oval_external_probe_item_value_get_datatype(oval_external_probe_item_value_t* value);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API const char* oval_external_probe_item_value_get_string(oval_external_probe_item_value_t* value);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API bool oval_external_probe_item_value_get_boolean(oval_external_probe_item_value_t* value);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API double oval_external_probe_item_value_get_float(oval_external_probe_item_value_t* value);
/**
 * @memberof oval_external_probe_item_value
 */
OSCAP_API long long oval_external_probe_item_value_get_integer(oval_external_probe_item_value_t* value);

/**
 * @memberof oval_external_probe_item
 */
OSCAP_API oval_external_probe_item_t* oval_external_probe_item_new(char* name, oval_external_probe_item_value_t* value, ...);
/**
 * @memberof oval_external_probe_item
 */
OSCAP_API void oval_external_probe_item_free(oval_external_probe_item_t* item);
/**
 * @memberof oval_external_probe_item
 */
OSCAP_API void oval_external_probe_item_set_value(oval_external_probe_item_t* item, char* name, oval_external_probe_item_value_t* value);
/**
 * @memberof oval_external_probe_item
 */
OSCAP_API oval_external_probe_item_value_t* oval_external_probe_item_get_value(oval_external_probe_item_t* item, const char* name);

/**
 * @memberof oval_external_probe_item_list
 */
OSCAP_API oval_external_probe_item_list_t* oval_external_probe_item_list_new(oval_external_probe_item_t* item, ...);
/**
 * @memberof oval_external_probe_item_list
 */
OSCAP_API void oval_external_probe_item_list_free(oval_external_probe_item_list_t* list);
/**
 * @memberof oval_external_probe_item_list
 */
OSCAP_API void oval_external_probe_item_list_push(oval_external_probe_item_list_t* list, oval_external_probe_item_t* item);

/**
 * @memberof oval_external_probe_result
 */
OSCAP_API oval_external_probe_result_t* oval_external_probe_result_new(char* name);
/**
 * @memberof oval_external_probe_result
 */
OSCAP_API void oval_external_probe_result_free(oval_external_probe_result_t* res);

/**
 * @memberof oval_external_probe_result
 * @param status one of the SYSCHAR_STATUS_ constants defined in @ref OVALSYS
 */
OSCAP_API void oval_external_probe_result_set_status(oval_external_probe_result_t* res, oval_syschar_status_t status);
/**
 * @memberof oval_external_probe_result
 */
OSCAP_API void oval_external_probe_result_set_items(oval_external_probe_result_t* res, oval_external_probe_item_list_t* list);
/**
 * Get OVAL external probe result name.
 * @return A pointer to the name attribute of the specified @ref oval_external_probe_result.
 * @memberof oval_external_probe_result
 */
OSCAP_API const char* oval_external_probe_result_get_name(oval_external_probe_result_t* res);
/**
 * @memberof oval_external_probe_result
 * @return one of the SYSCHAR_STATUS_ constants defined in @ref OVALSYS
 */
OSCAP_API oval_syschar_status_t oval_external_probe_result_get_status(oval_external_probe_result_t* res);
/**
 * @memberof oval_external_probe_result
 */
OSCAP_API oval_external_probe_item_list_t* oval_external_probe_result_get_items(oval_external_probe_result_t* res);

/**
 * @memberof oval_external_probe_item_iterator
 */
OSCAP_API struct oval_external_probe_item_iterator* oval_external_probe_item_iterator_new(oval_external_probe_item_t* item);
/**
 * @memberof oval_external_probe_item_iterator
 */
OSCAP_API void oval_external_probe_item_iterator_free(struct oval_external_probe_item_iterator* it);
/**
 * @memberof oval_external_probe_item_iterator
 */
OSCAP_API bool oval_external_probe_item_iterator_has_more_values(struct oval_external_probe_item_iterator* it);
/**
 * @memberof oval_external_probe_item_iterator
 */
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

/**
 * @memberof oval_external_probe_item_list_iterator
 */
OSCAP_API struct oval_external_probe_item_list_iterator* oval_external_probe_item_list_iterator_new(oval_external_probe_item_list_t* list);
/**
 * @memberof oval_external_probe_item_list_iterator
 */
OSCAP_API void oval_external_probe_item_list_iterator_free(struct oval_external_probe_item_list_iterator* it);
/**
 * @memberof oval_external_probe_item_list_iterator
 */
OSCAP_API bool oval_external_probe_item_list_iterator_has_more_items(struct oval_external_probe_item_list_iterator* it);
/**
 * @memberof oval_external_probe_item_list_iterator
 */
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

/**
 * @}END OVALEXTPROBE
 * @}END OVAL
 */

#endif  // OVAL_EXTERNAL_PROBE_H_
