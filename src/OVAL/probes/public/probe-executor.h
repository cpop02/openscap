//
// Created by Cristian Pop on 19/10/2020.
//

#ifndef PROBE_EXECUTOR_H
#define PROBE_EXECUTOR_H

#include <oval_types.h>
#include <sexp.h>

typedef struct probe_executor probe_executor_t;

typedef SEXP_t* (*oval_probe_cmd_handler_t)(SEXP_t *sexp, void *arg);

typedef struct {
    oval_probe_cmd_handler_t obj_eval;
    oval_probe_cmd_handler_t ste_fetch;
} probe_cmd_handler_table_t;

typedef struct {
    void *probe_data;
    void *probe_cmd_handler_arg;
    probe_cmd_handler_table_t probe_cmd_handlers;
} probe_executor_ctx_t;

typedef struct {
    oval_subtype_t probe_type;
    SEXP_t *probe_in;
    SEXP_t **probe_out;
} probe_request_t;

probe_executor_t* probe_executor_new(probe_executor_ctx_t *desc);
void probe_executor_free(probe_executor_t *exec);
int probe_executor_reset(probe_executor_t *exec);

int probe_executor_exec(probe_executor_t *exec, probe_request_t *req);

#endif //PROBE_EXECUTOR_H
