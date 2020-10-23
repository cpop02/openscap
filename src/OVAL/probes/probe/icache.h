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
#ifndef ICACHE_H
#define ICACHE_H

#include <stddef.h>
#include <sexp.h>
#include <compat_pthread_barrier.h>
#include "../SEAP/generic/rbt/rbt.h"

#ifndef PROBE_IQUEUE_CAPACITY
#define PROBE_IQUEUE_CAPACITY 1024
#endif

typedef struct {
        SEXP_t *cobj;
        union {
                SEXP_t         *item;
                pthread_cond_t *cond;
        } p;
} probe_iqpair_t;

typedef struct {
        rbt_t    *tree; /* XXX: rewrite to extensible or linear hashing */
        pthread_t thid;

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
        pthread_barrier_t queue_barrier;
#endif
        pthread_mutex_t queue_mutex;
        pthread_cond_t  queue_notempty;
        pthread_cond_t  queue_notfull;

        probe_iqpair_t  queue[PROBE_IQUEUE_CAPACITY];
        uint16_t        queue_beg;
        uint16_t        queue_end;
        uint16_t        queue_cnt;
        uint16_t        queue_max;

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
#ifndef HAVE_ATOMIC_BUILTINS
        pthread_mutex_t queue_mutex_next_id;
#endif
        volatile uint32_t next_id;
#endif
} probe_icache_t;

typedef struct {
        SEXP_t  **item;
        uint16_t  count;
} probe_citem_t;

probe_icache_t *probe_icache_new(void);
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
int probe_icache_wait(probe_icache_t *cache);
#endif
int probe_icache_add(probe_icache_t *cache, SEXP_t *cobj, SEXP_t *item);
int probe_icache_nop(probe_icache_t *cache);
void probe_icache_free(probe_icache_t *cache);

#endif /* ICACHE_H */
