//
// Created by Cristian Pop on 20/10/2020.
//

#ifndef _EXECUTOR_H
#define _EXECUTOR_H

#include <probe-executor.h>

#include "icache.h"

struct probe_executor {
    probe_executor_ctx_t ctx;

    // TODO: Add request cache
    probe_icache_t *icache;
};


#endif //_EXECUTOR_H
