//
// Created by Cristian Pop on 20/10/2020.
//

#ifndef _EXTERNAL_PROBE_EXECUTOR_IMPL_H
#define _EXTERNAL_PROBE_EXECUTOR_IMPL_H

#include <oval_evaluation.h>
#include <external_probe_executor.h>

#include "icache.h"

struct external_probe_executor {
    oval_evaluation_t *eval;
    probe_main_function_t ext_probe_main_func;
    // TODO: Add request cache
    probe_icache_t *icache;
};


#endif //_EXTERNAL_PROBE_EXECUTOR_IMPL_H
