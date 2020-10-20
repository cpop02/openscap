/*
 * Copyright 2011 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software 
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors:
 *      Daniel Kopecek <dkopecek@redhat.com>
 */
#ifndef PROBE_H
#define PROBE_H

#include "oscap_platforms.h"

#include <sys/types.h>
#ifdef OS_WINDOWS
#include <io.h>
#else
#include <unistd.h>
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <pthread.h>
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
#include <oval_evaluation.h>
#include "external_probe_executor.h"
#endif
#include "_seap.h"
#include "ncache.h"
#include "rcache.h"
#include "icache.h"
#include "probe-common.h"
#include "option.h"
#include "common/util.h"
#include "common/compat_pthread_barrier.h"

typedef struct {
	pthread_rwlock_t rwlock;
	uint32_t         flags;

	pid_t       pid;

        void       *probe_arg;
        int         probe_exitcode;

	SEAP_CTX_t *SEAP_ctx; /**< SEAP context */
	int         sd;       /**< SEAP descriptor */

	pthread_t th_input;
	pthread_t th_signal;

        rbt_t    *workers;
        uint32_t  max_threads;
        uint32_t  max_chdepth;

	probe_rcache_t *rcache; /**< probe result cache */
	probe_ncache_t *ncache; /**< probe name cache */
        probe_icache_t *icache; /**< probe item cache */

	probe_option_t *option; /**< probe option handlers */
	size_t          optcnt; /**< number of defined options */
	bool offline_mode;
	int supported_offline_mode;
	int selected_offline_mode;
	oval_subtype_t subtype;

	int real_root_fd;
	int real_cwd_fd;
} probe_t;

struct probe_ctx {
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    oval_evaluation_t *eval;
    external_probe_request_t *req;
#endif
    SEXP_t         *probe_in;  /**< S-exp representation of the input object */
    SEXP_t         *probe_out; /**< collected object */
    SEXP_t         *filters;   /**< object filters (OVAL 5.8 and higher) */
    probe_icache_t *icache;    /**< item cache */
	int offline_mode;
};

struct probe_varref_ctx {
    SEXP_t *pi2;
    unsigned int ent_cnt;
    struct probe_varref_ctx_ent *ent_lst;
};

struct probe_varref_ctx_ent {
    SEXP_t *ent_name_sref;
    unsigned int val_cnt;
    unsigned int next_val_idx;
};

typedef enum {
	PROBE_OFFLINE_NONE = 0x00,
	PROBE_OFFLINE_CHROOT = 0x01,
	PROBE_OFFLINE_OWN = 0x04,
	PROBE_OFFLINE_ALL = 0x0f
} probe_offline_flags;

extern pthread_barrier_t OSCAP_GSYM(th_barrier);

int probe_varref_create_ctx(const SEXP_t *probe_in, SEXP_t *varrefs, struct probe_varref_ctx **octx);
void probe_varref_destroy_ctx(struct probe_varref_ctx *ctx);
int probe_varref_iterate_ctx(struct probe_varref_ctx *ctx);

SEXP_t *probe_set_combine(SEXP_t *cobj0, SEXP_t *cobj1, oval_setobject_operation_t op);

#endif /* PROBE_H */
