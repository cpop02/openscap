//
// Created by Cristian Pop on 19/10/2020.
//

#ifndef EXTERNAL_PROBE_EXECUTOR_H
#define EXTERNAL_PROBE_EXECUTOR_H

#include <oval_evaluation.h>
#include <oval_types.h>
#include <sexp.h>
#include <probe-table.h>

typedef struct {
    oval_subtype_t probe_type;
    SEXP_t *probe_in;
} external_probe_request_t;

typedef struct external_probe_executor external_probe_executor_t;

external_probe_executor_t* external_probe_executor_new(oval_evaluation_t *eval);
void external_probe_executor_free(external_probe_executor_t *exec);

int external_probe_executor_exec(external_probe_executor_t *exec, external_probe_request_t *req, SEXP_t **out);

#endif //EXTERNAL_PROBE_EXECUTOR_H
