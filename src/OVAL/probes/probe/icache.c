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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pthread.h>
#include <stddef.h>
#include <sexp.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(OS_FREEBSD)
#include <pthread_np.h>
#endif

#include "../SEAP/generic/rbt/rbt.h"
#include "probe-api.h"
#include "common/debug_priv.h"
#include "common/memusage.h"

#include "probe.h"
#include "icache.h"
#include "_sexp-ID.h"

#define PROBE_RESULT_MEMCHECK_CTRESHOLD  32768  /* item count */
#define PROBE_RESULT_MEMCHECK_MINFREEMEM 512    /* MiB */
#define PROBE_RESULT_MEMCHECK_MAXRATIO   0.8   /* max. memory usage ratio - used/total */

#ifndef OVAL_EXTERNAL_PROBES_ENABLED
static volatile uint32_t next_ID = 0;

#if !defined(HAVE_ATOMIC_BUILTINS)
pthread_mutex_t next_ID_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
#endif


#ifdef OVAL_ICACHE_THREAD_ENABLED
static void *probe_icache_worker(void *arg);
#endif
static void probe_icache_free_node(struct rbt_i64_node *n);
static void probe_icache_item_setID(probe_icache_t *cache, SEXP_t *item);
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
static int icache_lookup(probe_icache_t *cache, int64_t item_id, probe_iqpair_t *pair);
#else
static int icache_lookup(rbt_t *tree, int64_t item_id, probe_iqpair_t *pair);
#endif
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
static void icache_add_to_tree(probe_icache_t *cache, int64_t item_id, probe_iqpair_t *pair);
#else
static void icache_add_to_tree(rbt_t *tree, int64_t item_id, probe_iqpair_t *pair);
#endif
#ifdef OVAL_ICACHE_THREAD_ENABLED
static int __probe_icache_add_nolock(probe_icache_t *cache, SEXP_t *cobj, SEXP_t *item, pthread_cond_t *cond) {
#endif
static int probe_cobj_memcheck(size_t item_cnt);

#ifdef OVAL_ICACHE_THREAD_ENABLED
probe_icache_t *probe_icache_new(void) {
    probe_icache_t *cache = malloc(sizeof(probe_icache_t));
    if(cache == NULL) {
        goto fail;
    }
    cache->tree = rbt_i64_new();
    if(cache->tree == NULL) {
        goto fail;
    }

    cache->queue_beg = 0;
    cache->queue_end = 0;
    cache->queue_cnt = 0;
    cache->queue_max = PROBE_IQUEUE_CAPACITY;
    cache->next_id = 0;

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    if(pthread_barrier_init(&cache->queue_barrier, NULL, 2) != 0) {
        dE("Can't initialize icache barrier: %u, %s", errno, strerror(errno));
        goto fail_barrier;
    }
#endif
    if(pthread_mutex_init(&cache->queue_mutex, NULL) != 0) {
        dE("Can't initialize icache mutex: %u, %s", errno, strerror(errno));
        goto fail_mutex;
    }

    if(pthread_cond_init(&cache->queue_notempty, NULL) != 0) {
        dE("Can't initialize icache queue condition variable (notempty): %u, %s", errno, strerror(errno));
        goto fail_cond_notempty;
    }
    if(pthread_cond_init(&cache->queue_notfull, NULL) != 0) {
        dE("Can't initialize icache queue condition variable (notfull): %u, %s", errno, strerror(errno));
        goto fail_cond_notfull;
    }
#if defined(OVAL_EXTERNAL_PROBES_ENABLED) && !defined(HAVE_ATOMIC_BUILTINS)
    if(pthread_mutex_init(&cache->queue_mutex_next_id) != 0) {
        dE("Can't initialize icache mutex: %u, %s", errno, strerror(errno));
        goto fail_mutex_next_id;
    }
#endif
    if(pthread_create(&cache->thid, NULL, probe_icache_worker, (void *)cache) != 0) {
        dE("Can't start the icache worker: %u, %s", errno, strerror(errno));
        goto fail_thread;
    }

    return (cache);

fail_thread:
#if defined(OVAL_EXTERNAL_PROBES_ENABLED) && !defined(HAVE_ATOMIC_BUILTINS)
    pthread_mutex_destroy(&cache->queue_mutex_next_id);
fail_mutex_next_id:
#endif
    pthread_cond_destroy(&cache->queue_notfull);
fail_cond_notfull:
    pthread_cond_destroy(&cache->queue_notempty);
fail_cond_notempty:
    pthread_mutex_destroy(&cache->queue_mutex);
fail_mutex:
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    pthread_barrier_destroy(&cache->queue_barrier);
fail_barrier:
#endif
fail:
    if(cache != NULL && cache->tree != NULL) {
        rbt_i64_free(cache->tree);
    }

    return (NULL);
}
#else
probe_icache_t *probe_icache_new(void) {
    probe_icache_t *cache;

    cache = (probe_icache_t*)calloc(1, sizeof(probe_icache_t));
    if(cache == NULL) {
        goto fail;
    }
    cache->tree = rbt_i64_new();
    if(cache->tree != NULL) {
        goto cleanup;
    }

fail:
    probe_icache_free(cache);
    if(cache != NULL && cache->tree != NULL) {
        rbt_i64_free(cache->tree);
    }
cleanup:
    return cache;
}
#endif

#ifdef OVAL_ICACHE_THREAD_ENABLED
void probe_icache_free(probe_icache_t *cache) {
    if(cache != NULL) {
        if (pthread_cancel(cache->thid) != 0) {
            dE("An error occurred while canceling the icache worker thread: %u %s", errno, strerror(errno));
        }
        if (pthread_join(cache->thid, NULL) != 0) {
            dE("An error occurred while joining the icache worker thread: %u %s", errno, strerror(errno));
        }

#if defined(OVAL_EXTERNAL_PROBES_ENABLED) && !defined(HAVE_ATOMIC_BUILTINS)
        pthread_mutex_destroy(&cache->queue_mutex_next_id);
#endif
        pthread_cond_destroy(&cache->queue_notfull);
        pthread_cond_destroy(&cache->queue_notempty);
        pthread_mutex_destroy(&cache->queue_mutex);
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
        pthread_barrier_destroy(&cache->queue_barrier);
#endif
        rbt_i64_free_cb(cache->tree, &probe_icache_free_node);
    }
    free(cache);
}
#else
void probe_icache_free(probe_icache_t *cache) {
    if(cache != NULL) {
        rbt_i64_free_cb(cache->tree, &probe_icache_free_node);
    }
    free(cache);
}
#endif

#ifdef OVAL_ICACHE_THREAD_ENABLED
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
int probe_icache_wait(probe_icache_t *cache) {
    int ret;

    switch(ret = pthread_barrier_wait(&cache->queue_barrier)) {
        case 0:
        case PTHREAD_BARRIER_SERIAL_THREAD:
            ret = 0;
            break;
        default:
            dE("Failed to sync with icache worker: %u, %s.", errno, strerror(errno));
    }

    return ret;
}
#endif
#endif

#ifdef OVAL_ICACHE_THREAD_ENABLED
int probe_icache_add(probe_icache_t *cache, SEXP_t *cobj, SEXP_t *item) {
    int ret;

    if(cache == NULL || cobj == NULL || item == NULL) {
        return (-1); /* XXX: EFAULT */
    }

    if(pthread_mutex_lock(&cache->queue_mutex) != 0) {
        dE("An error occurred while locking the queue mutex: %u, %s", errno, strerror(errno));
        return (-1);
    }
    ret = __probe_icache_add_nolock(cache, cobj, item, NULL);
    if(pthread_cond_signal(&cache->queue_notempty) != 0 && ret == 0) {
        dE("An error occurred while signaling the `notempty' condition: %u, %s", errno, strerror(errno));
        ret = -1;
    }
    if(pthread_mutex_unlock(&cache->queue_mutex) != 0) {
        dE("An error occurred while unlocking the queue mutex: %u, %s", errno, strerror(errno));
        abort();
    }
    if(ret != 0) {
        return (-1);
    }

    return (0);
}
#else
int probe_icache_add(probe_icache_t *cache, SEXP_t *cobj, SEXP_t *item) {
    int ret;
    SEXP_ID_t item_id;
    probe_iqpair_t pair;

    item_id = SEXP_ID_v(item);

    dD("Adding item to cache: ID="PRIu64" address=%"PRIu64, item_id, item);

    __attribute__nonnull__(cache);
    __attribute__nonnull__(cobj);
    __attribute__nonnull__(item);

    pair.cobj = cobj;
    pair.p.item = item;

    if(icache_lookup(cache, item_id, &pair) != 0) {
        dD("Adding missing item to cache");
        icache_add_to_tree(cache, item_id, &pair);
    }
    ret = probe_cobj_add_item(cobj, pair.p.item);
    if(ret != 0) {
        dW("An error occurred while adding the item to the collected object");
    }

    return ret;
}
#endif

#ifdef OVAL_ICACHE_THREAD_ENABLED
int probe_icache_nop(probe_icache_t *cache) {
    pthread_cond_t cond;

    memset(&cond, 0, sizeof(pthread_cond_t));

    dD("NOP");

    if(pthread_mutex_lock(&cache->queue_mutex) != 0) {
        dE("An error occurred while locking the queue mutex: %u, %s", errno, strerror(errno));
        return (-1);
    }
    if(pthread_cond_init(&cond, NULL) != 0) {
        dE("Can't initialize icache queue condition variable (NOP): %u, %s", errno, strerror(errno));
        return (-1);
    }
    if(__probe_icache_add_nolock(cache, NULL, NULL, &cond) != 0) {
        if(pthread_mutex_unlock(&cache->queue_mutex) != 0) {
            dE("An error occurred while unlocking the queue mutex: %u, %s", errno, strerror(errno));
            abort();
        }
        pthread_cond_destroy(&cond);
        return (-1);
    }

    dD("Signaling `notempty'");

    if(pthread_cond_signal(&cache->queue_notempty) != 0) {
        dE("An error occurred while signaling the `notempty' condition: %u, %s", errno, strerror(errno));
        pthread_cond_destroy(&cond);
        return (-1);
    }

    dD("Waiting for icache worker to handle the NOP");

    if(pthread_cond_wait(&cond, &cache->queue_mutex) != 0) {
        dE("An error occurred while waiting for the `NOP' queue condition: %u, %s", errno, strerror(errno));
        return (-1);
    }

    dD("Sync");

    if(pthread_mutex_unlock(&cache->queue_mutex) != 0) {
        dE("An error occurred while unlocking the queue mutex: %u, %s", errno, strerror(errno));
        abort();
    }

    pthread_cond_destroy(&cond);

    return (0);
}
#endif

/**
 * Collect an item
 * This function adds an item the collected object assosiated
 * with the given probe context.
 *
 * Returns:
 * 0 ... the item was succesfully added to the collected object
 * 1 ... the item was filtered out
 * 2 ... the item was not added because of memory constraints
 *       and the collected object was flagged as incomplete
 *-1 ... unexpected/internal error
 *
 * The caller must not free the item, it's freed automatically
 * by this function or by the icache worker thread.
 */
int probe_item_collect(struct probe_ctx *ctx, SEXP_t *item) {
    size_t  cobj_itemcnt;
    SEXP_t *cobj_content, *msg;

    if(ctx == NULL || ctx->probe_out == NULL || item == NULL) {
        return -1;
    }

    cobj_content = SEXP_listref_nth(ctx->probe_out, 3);
    cobj_itemcnt = SEXP_list_length(cobj_content);
    SEXP_free(cobj_content);

    if(probe_cobj_memcheck(cobj_itemcnt) != 0) {
        /*
         * Don't set the message again if the collected object is
         * already flagged as incomplete.
         */
        if(probe_cobj_get_flag(ctx->probe_out) != SYSCHAR_FLAG_INCOMPLETE) {
#ifdef OVAL_ICACHE_THREAD_ENABLED
            /*
             * Sync with the icache thread before modifying the
             * collected object.
             */
            if(probe_icache_nop(ctx->icache) != 0) {
                return -1;
            }
#endif
            msg = probe_msg_creat(OVAL_MESSAGE_LEVEL_WARNING,
                                  "Object is incomplete due to memory constraints.");
            probe_cobj_add_msg(ctx->probe_out, msg);
            probe_cobj_set_flag(ctx->probe_out, SYSCHAR_FLAG_INCOMPLETE);
            SEXP_free(msg);
        }
        return 2;
    }
    if(ctx->filters != NULL && probe_item_filtered(item, ctx->filters)) {
        SEXP_free(item);
        return (1);
    }
    if(probe_icache_add(ctx->icache, ctx->probe_out, item) != 0) {
        dE("Can't add item (%p) to the item cache (%p)", item, ctx->icache);
        SEXP_free(item);
        return (-1);
    }

    return (0);
}

#ifdef OVAL_ICACHE_THREAD_ENABLED
static void *probe_icache_worker(void *arg) {
    probe_icache_t *cache = (probe_icache_t *)(arg);
    probe_iqpair_t *pair, pair_mem;
    SEXP_ID_t       item_ID;

	if(cache == NULL) {
		return NULL;
	}

#if defined(HAVE_PTHREAD_SETNAME_NP)
    const char* thread_name = "icache_worker";
# if defined(OS_APPLE)
	pthread_setname_np(thread_name);
# else
	pthread_setname_np(pthread_self(), thread_name);
# endif
#endif

    if(pthread_mutex_lock(&cache->queue_mutex) != 0) {
        dE("An error occurred while locking the queue mutex: %u, %s", errno, strerror(errno));
        return (NULL);
    }

	pair = &pair_mem;
    dD("icache worker ready");

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    switch(pthread_barrier_wait(&cache->queue_barrier))
#else
    switch(pthread_barrier_wait(&OSCAP_GSYM(th_barrier)))
#endif
    {
        case 0:
        case PTHREAD_BARRIER_SERIAL_THREAD:
	        break;
        default:
	        dE("Failed to wait for icache barrier: %u, %s.", errno, strerror(errno));
	        pthread_mutex_unlock(&cache->queue_mutex);
	        return (NULL);
    }

    while(pthread_cond_wait(&cache->queue_notempty, &cache->queue_mutex) == 0) {
        if(cache->queue_cnt <= 0) {
            return NULL;
        }
        do {
            dD("Extracting item from the cache queue: cnt=%"PRIu16", beg=%"PRIu16"", cache->queue_cnt, cache->queue_beg);
            /*
             * Extract an item from the queue and update queue beg, end & cnt
             */
            pair_mem = cache->queue[cache->queue_beg];
#ifndef NDEBUG
		    memset(cache->queue + cache->queue_beg, 0, sizeof(probe_iqpair_t));
#endif
            --cache->queue_cnt;
		    ++cache->queue_beg;

		    if(cache->queue_beg == cache->queue_max) {
                cache->queue_beg = 0;
            }

		    if(cache->queue_cnt == 0 ?
		    	cache->queue_end != cache->queue_beg :
	    		cache->queue_end == cache->queue_beg) {
	    		return NULL;
	    	}

            dD("Signaling `notfull'");

            if(pthread_cond_signal(&cache->queue_notfull) != 0) {
                dE("An error occurred while signaling the `notfull' condition: %u, %s", errno, strerror(errno));
                abort();
            }
            /*
             * Release the mutex
             */
            if(pthread_mutex_unlock(&cache->queue_mutex) != 0) {
                dE("An error occurred while unlocking the queue mutex: %u, %s", errno, strerror(errno));
                abort();
            }

            if(pair->cobj == NULL) {
                /*
                * Handle NOP case (synchronization)
                */
                if(pair->p.cond == NULL) {
                   return NULL;
                }

                dD("Handling NOP");

                int ret;
                if((ret = pthread_cond_signal(pair->p.cond)) != 0) {
                    dE("An error occurred while signaling NOP condition: %u, %s", ret, strerror(ret));
                    abort();
                }
            } else {
                dD("Handling cache request");

                /*
                 * Compute item ID
                 */
                dD("pair address: %"PRIu64, (uint64_t) pair);
                dD("item address: %"PRIu64, (uint64_t) pair->p.item);
                item_ID = SEXP_ID_v(pair->p.item);
                dD("item ID=%"PRIu64"", item_ID);

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
                if(icache_lookup(cache, item_ID, pair) != 0) {
#else
                if(icache_lookup(cache->tree, item_ID, pair) != 0) {
#endif
                    /*
                     * Cache MISS
                     */
                    dD("cache MISS");
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
                    icache_add_to_tree(cache, item_ID, pair);
#else
                    icache_add_to_tree(cache->tree, item_ID, pair);
#endif
                }

                if(probe_cobj_add_item(pair->cobj, pair->p.item) != 0) {
                    dW("An error occurred while adding the item to the collected object");
                }
            }

            if(pthread_mutex_lock(&cache->queue_mutex) != 0) {
                dE("An error occurred while re-locking the queue mutex: %u, %s", errno, strerror(errno));
                abort();
            }
        } while(cache->queue_cnt > 0);
    }

    return (NULL);
}
#endif

static void probe_icache_free_node(struct rbt_i64_node *n) {
    probe_citem_t *ci;

    ci = (probe_citem_t *)n->data;
    for( ; ci->count > 0 ; --ci->count ) {
        SEXP_free(ci->item[ci->count - 1]);
    }

    free(ci->item);
    free(ci);
}

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
static void probe_icache_item_setID(probe_icache_t *cache, SEXP_t *item) {
#else
static void probe_icache_item_setID(SEXP_t *item) {
#endif
    SEXP_t  *name_ref, *prev_id;
    SEXP_t   uniq_id;
    uint32_t local_id;

    /* ((foo_item :id "<int>") ... ) */

	if (item == NULL) {
		return;
	}
	if (!SEXP_listp(item)) {
		return;
	}

#if defined(HAVE_ATOMIC_BUILTINS)
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    local_id = __sync_fetch_and_add(&cache->next_id, 1);
#else
    local_id = __sync_fetch_and_add(&next_ID, 1);
#endif
#else
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    if(pthread_mutex_lock(&cache->queue_mutex_next_id) != 0) {
            dE("Can't lock the next_ID_mutex: %u, %s", errno, strerror(errno));
            abort();
    }
    local_id = ++cache->next_id;
    if(pthread_mutex_unlock(&cache->queue_mutex_next_id) != 0) {
            dE("Can't unlock the next_ID_mutex: %u, %s", errno, strerror(errno));
            abort();
    }
#else
    if(pthread_mutex_lock(&next_ID_mutex) != 0) {
            dE("Can't lock the next_ID_mutex: %u, %s", errno, strerror(errno));
            abort();
    }
    local_id = ++next_ID;
    if(pthread_mutex_unlock(&next_ID_mutex) != 0) {
            dE("Can't unlock the next_ID_mutex: %u, %s", errno, strerror(errno));
            abort();
    }
#endif
#endif

    SEXP_string_newf_r(&uniq_id, "1%05u%u", getpid(), local_id);

    name_ref = SEXP_listref_first(item);
    prev_id  = SEXP_list_replace(name_ref, 3, &uniq_id);

    SEXP_free(prev_id);
    SEXP_free_r(&uniq_id);
    SEXP_free(name_ref);
}

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
static int icache_lookup(probe_icache_t *cache, int64_t item_id, probe_iqpair_t *pair) {
#else
static int icache_lookup(rbt_t *tree, int64_t item_id, probe_iqpair_t *pair) {
#endif
	probe_citem_t *cached = NULL;
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
	rbt_t *tree = cache->tree;
#endif

	if(rbt_i64_get(tree, item_id, (void**)&cached) != 0) {
		return -1;
	}

	/*
	* Maybe a cache HIT
	*/
	dD("cache HIT #1");

	register uint16_t i;
	for(i = 0; i < cached->count; ++i) {
		SEXP_t rest1;
		SEXP_t* rest_r1 = SEXP_list_rest_r(&rest1, pair->p.item);

		SEXP_t rest2;
		SEXP_t* rest_r2 = SEXP_list_rest_r(&rest2, cached->item[i]);

		if (SEXP_deepcmp(rest_r1, rest_r2)) {
			SEXP_free_r(&rest1);
			SEXP_free_r(&rest2);
			break;
		}

		SEXP_free_r(&rest1);
		SEXP_free_r(&rest2);
	}

	if(i == cached->count) {
		/*
		* Cache MISS
		*/
		dD("cache MISS");

		cached->item = realloc(cached->item, sizeof(SEXP_t *) * ++cached->count);
		cached->item[cached->count - 1] = pair->p.item;

		/* Assign an unique item ID */
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
		probe_icache_item_setID(cache, pair->p.item);
#else
        probe_icache_item_setID(pair->p.item);
#endif
	} else {
		/*
		* Cache HIT
		*/
		dD("cache HIT #2 -> real HIT");
		SEXP_free(pair->p.item);
		pair->p.item = cached->item[i];
	}
	return 0;
}

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
static void icache_add_to_tree(probe_icache_t *cache, int64_t item_id, probe_iqpair_t *pair) {
#else
static void icache_add_to_tree(rbt_t *tree, int64_t item_id, probe_iqpair_t *pair) {
#endif
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    rbt_t *tree = cache->tree;
#endif

	probe_citem_t *cached = malloc(sizeof(probe_citem_t));
	cached->item = malloc(sizeof(SEXP_t *));
	cached->item[0] = pair->p.item;
	cached->count = 1;

	/* Assign an unique item ID */
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    probe_icache_item_setID(cache, pair->p.item);
#else
	probe_icache_item_setID(pair->p.item);
#endif

	if(rbt_i64_add(tree, (int64_t)item_id, (void **)cached, NULL) != 0) {
		dE("Can't add item (k=%"PRIi64" to the cache (%p)", item_id, tree);

		free(cached->item);
		free(cached);

		/* now what? */
		abort();
	}
}

#ifdef OVAL_ICACHE_THREAD_ENABLED
static int __probe_icache_add_nolock(probe_icache_t *cache, SEXP_t *cobj, SEXP_t *item, pthread_cond_t *cond) {
	if (!((cond == NULL) ^ (item == NULL))) {
		return -1;
	}
retry:
    if(cache->queue_cnt < cache->queue_max) {
        if(item != NULL) {
            if(cobj == NULL) {
                return -1;
            }
            cache->queue[cache->queue_end].p.item = item;
        } else {
            if(item != NULL || cobj != NULL) {
                return -1;
            }
            cache->queue[cache->queue_end].p.cond = cond;
		}
        cache->queue[cache->queue_end].cobj = cobj;

        ++cache->queue_cnt;
		++cache->queue_end;

        if(cache->queue_end == cache->queue_max) {
            cache->queue_end = 0;
        }
    } else {
        /*
         * The queue is full, we have to wait
         */
        if(pthread_cond_wait(&cache->queue_notfull, &cache->queue_mutex) == 0) {
            goto retry;
        } else {
            dE("An error occurred while waiting for the `notfull' queue condition: %u, %s", errno, strerror(errno));
            return (-1);
        }
    }

    return (0);
}
#endif

/**
 * Returns 0 if the memory constraints are not reached. Otherwise, 1 is returned.
 * In case of an error, -1 is returned.
 */
static int probe_cobj_memcheck(size_t item_cnt) {
	if (item_cnt > PROBE_RESULT_MEMCHECK_CTRESHOLD) {
		struct proc_memusage mu_proc;
		struct sys_memusage  mu_sys;
		double c_ratio;

		if (oscap_proc_memusage (&mu_proc) != 0)
			return (-1);

		if (oscap_sys_memusage (&mu_sys) != 0)
			return (-1);

		c_ratio = (double)mu_proc.mu_rss/(double)(mu_sys.mu_total);

		if (c_ratio > PROBE_RESULT_MEMCHECK_MAXRATIO) {
			dW("Memory usage ratio limit reached! limit=%f, current=%f",
			   PROBE_RESULT_MEMCHECK_MAXRATIO, c_ratio);
			errno = ENOMEM;
			return (1);
		}

		if ((mu_sys.mu_realfree / 1024) < PROBE_RESULT_MEMCHECK_MINFREEMEM) {
			dW("Minimum free memory limit reached! limit=%zu, current=%zu",
			   PROBE_RESULT_MEMCHECK_MINFREEMEM, mu_sys.mu_realfree / 1024);
			errno = ENOMEM;
			return (1);
		}
	}

	return (0);
}
