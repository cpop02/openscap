//
// Created by Cristian Pop on 19/10/2020.
//

#ifndef OVAL_EVALUATION_H
#define OVAL_EVALUATION_H

#include <oscap_export.h>

#include "oval_external_probe.h"

typedef struct oval_evaluation oval_evaluation_t;

OSCAP_API oval_evaluation_t* oval_evaluation_new(void *probe_data, oval_external_probe_handler_t probe_handler);
OSCAP_API void oval_evaluation_free(oval_evaluation_t *eval);

OSCAP_API void* oval_evaluation_get_probe_data(oval_evaluation_t *eval);
OSCAP_API oval_external_probe_handler_t oval_evaluation_get_probe_handler(oval_evaluation_t *eval);

typedef struct oval_evaluator oval_evaluator_t;

OSCAP_API oval_evaluator_t* oval_evaluator_new(const char *filename);
OSCAP_API void oval_evaluator_free(oval_evaluator_t *evaluator);

OSCAP_API int oval_evaluator_eval(oval_evaluator_t *evaluator, oval_evaluation_t *eval);

#endif //OVAL_EVALUATION_H
