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

/**
 * @struct oval_external_probe_result
 * @memberof oval_external_probe
 * Result of an external probe query (only if EXTERNAL_PROBE_COLLECT is defined).
 */
typedef struct oval_external_probe_result oval_external_probe_result_t;

typedef struct oval_external_probe_value oval_external_probe_value_t;
typedef struct oval_external_probe_value_map oval_external_probe_value_map_t;

struct oval_external_probe_value_map_iterator;

/**
 * @struct oval_external_probe_eval_funcs
 * @memberof oval_external_probe
 * @param probe_ctx The context value provided by the caller during registration of the callbacks @see oval_external_probe_eval_funcs_t
 * @param id The OVAL id of the probe item
 * @param family The OVAL family (Unix, Windows etc)
 * @param probe_type The probe type
 * @param fields The probe type-specific fields required for evaluation
 * @return A @ref oval_external_probe_result containing the evaluation result and record of result fields. The caller must free the result.
 */
typedef struct oval_external_probe_eval_funcs {
    void* probe_ctx;
    bool default_probe_only;    // If true, only call the default probe and ignore specialised probe implementations
    oval_external_probe_result_t* (*default_probe)(void* ctx, oval_subtype_t probe_type, char* id, oval_external_probe_value_map_t* values);
    oval_external_probe_result_t* (*environmentvariable_probe)(void* ctx, char* id);
    oval_external_probe_result_t* (*system_info_probe)(void* ctx, char* id);
} oval_external_probe_eval_funcs_t;

/**
 * @memberof oval_external_probe_result
 */
OSCAP_API oval_external_probe_result_t* oval_external_probe_result_new(char*);
/**
 * @memberof oval_external_probe_result
 */
OSCAP_API void oval_external_probe_result_free(oval_external_probe_result_t*);

/**
 * @name Setters
 * @{
 */
/**
 * @memberof oval_external_probe_result
 * @param status 0 for success or one of the PROBE_ constants defined in @ref PROBEAPI
 */
OSCAP_API void oval_external_probe_result_set_status(oval_external_probe_result_t*, int status);
/**
 * @memberof oval_external_probe_result
 */
OSCAP_API void oval_external_probe_result_set_fields(oval_external_probe_result_t*, oval_external_probe_value_map_t*);
/** @} */

/**
 * @name Getters
 * @{
 */
/**
 * Get OVAL external probe result name.
 * @return A pointer to the name attribute of the specified @ref oval_external_probe_result.
 * @memberof oval_external_probe_result
 */
OSCAP_API const char* oval_external_probe_result_get_name(oval_external_probe_result_t*);
/**
 * @memberof oval_external_probe_result
 * @return 0 for success or one of the PROBE_ constants defined in @ref PROBEAPI
 */
OSCAP_API int oval_external_probe_result_get_status(oval_external_probe_result_t*);
/**
 * @memberof oval_external_probe_result
 */
OSCAP_API oval_external_probe_value_map_t* oval_external_probe_result_get_fields(oval_external_probe_result_t*);
/**
 * @memberof oval_external_probe_result
 */
OSCAP_API const char* oval_external_probe_result_get_field_string(oval_external_probe_result_t* ext_res, const char* name);
/** @} */

OSCAP_API oval_external_probe_value_map_t* oval_external_probe_value_map_new(char* name, oval_external_probe_value_t* value, ...);
OSCAP_API void oval_external_probe_value_map_free(oval_external_probe_value_map_t* map);
OSCAP_API void oval_external_probe_value_map_set(oval_external_probe_value_map_t* map, char* name, oval_external_probe_value_t* value);
OSCAP_API oval_external_probe_value_t* oval_external_probe_value_map_get(oval_external_probe_value_map_t* map, const char* name);

OSCAP_API struct oval_external_probe_value_map_iterator* oval_external_probe_value_map_iterator_new(oval_external_probe_value_map_t* map);
OSCAP_API void oval_external_probe_value_map_iterator_free(struct oval_external_probe_value_map_iterator* it);
OSCAP_API bool oval_external_probe_value_map_iterator_has_more(struct oval_external_probe_value_map_iterator* it);
OSCAP_API const char* oval_external_probe_value_map_iterator_next_key(struct oval_external_probe_value_map_iterator* it);

// Do not return from 'code' or use 'goto' to a label outside 'code' ! Otherwise the iterator will not be freed.
#define OVAL_EXTERNAL_PROBE_VALUE_MAP_FOREACH(map, key_var, val_var, code)                                              \
    {                                                                                                                   \
        struct oval_external_probe_value_map_iterator *map##_iter = oval_external_probe_value_map_iterator_new(map);    \
        while (oval_external_probe_value_map_iterator_has_more(map##_iter)) {                                           \
            key_var = oval_external_probe_value_map_iterator_next_key(map##_iter);                                      \
            val_var = oval_external_probe_value_map_get(map, key_var);                                                  \
            code                                                                                                        \
        }                                                                                                               \
        oval_external_probe_value_map_iterator_free(map##_iter);                                                        \
    }

OSCAP_API oval_external_probe_value_t* oval_external_probe_value_new_string(char* val);
OSCAP_API oval_external_probe_value_t* oval_external_probe_value_new_stringf(char* fmt, ...);

OSCAP_API oval_external_probe_value_t* oval_external_probe_value_new_boolean(bool val);

OSCAP_API oval_external_probe_value_t* oval_external_probe_value_new_float(float val);

OSCAP_API oval_external_probe_value_t* oval_external_probe_value_new_integer(long long val);

OSCAP_API oval_external_probe_value_t* oval_external_probe_value_clone(oval_external_probe_value_t* old_value);

OSCAP_API void oval_external_probe_value_free(oval_external_probe_value_t* value);

OSCAP_API void oval_external_probe_value_iterator_free(struct oval_external_probe_value_map_iterator* oc_value);

OSCAP_API int oval_external_probe_value_iterator_remaining(struct oval_external_probe_value_map_iterator* iterator);

OSCAP_API oval_datatype_t oval_external_probe_value_get_datatype(oval_external_probe_value_t* value);

OSCAP_API const char* oval_external_probe_value_get_string(oval_external_probe_value_t* value);

OSCAP_API bool oval_external_probe_value_get_boolean(oval_external_probe_value_t* value);

OSCAP_API float oval_external_probe_value_get_float(oval_external_probe_value_t* value);

OSCAP_API long long oval_external_probe_value_get_integer(oval_external_probe_value_t* value);

/**
 * @}END OVALEXTPROBE
 * @}END OVAL
 */
#endif  // OVAL_EXTERNAL_PROBE_H_
