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

#include "_seap.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#if defined(OS_FREEBSD)
#include <pthread_np.h>
#endif

#include "probe-api.h"
#include "common/debug_priv.h"
#include "entcmp.h"

#include "worker.h"
#include "probe-table.h"
#include "probe.h"

extern bool  OSCAP_GSYM(varref_handling);
extern void *OSCAP_GSYM(probe_arg);

// Dummy pthread routine
static void *dummy_routine(void *dummy_param)
{
	return NULL;
}

static void preload_libraries_before_chroot()
{
	// Force to load dynamic libraries used by pthread_cancel
	pthread_t t;
	if (pthread_create(&t, NULL, dummy_routine, NULL)) {
		dE("pthread_create failed: %s", strerror(errno));
	}
	pthread_cancel(t);
	pthread_join(t, NULL);
}

void *probe_worker_runfn(void *arg)
{
	dD("probe_worker_runfn has started");
	probe_pwpair_t *pair = (probe_pwpair_t *)arg;

	SEXP_t *probe_res, *obj, *oid;
	int     probe_ret;

#if defined(HAVE_PTHREAD_SETNAME_NP)
# if defined(OS_APPLE)
	pthread_setname_np("probe_worker");
# else
	pthread_setname_np(pthread_self(), "probe_worker");
# endif
#endif
	dD("handling SEAP message ID %u", pair->pth->sid);
	//
	probe_ret = -1;
	probe_res = pair->pth->msg_handler(pair->probe, pair->pth->msg, &probe_ret);
	//
	dD("handler result = %p, return code = %d", probe_res, probe_ret);

	/* Assuming that the red-black tree API is doing locking for us... */
	if (rbt_i32_del(pair->probe->workers, pair->pth->sid, NULL) != 0) {
		dW("thread not found in the probe thread tree, probably canceled by an external signal");
		/*
		 * XXX: this is a possible deadlock; we can't send anything from
		 * here because the signal handler replied to the message
		 */
		arg = NULL;

                SEAP_msg_free(pair->pth->msg);
                SEXP_free(probe_res);
                free(pair);

		dD("probe_worker_runfn has finished");
                return (NULL);
	} else {
                SEXP_t *items;

		dD("probe thread deleted");

		obj = SEAP_msg_get(pair->pth->msg);
		oid = probe_obj_getattrval(obj, "id");
                items = probe_cobj_get_items(probe_res);

                if (items != NULL) {
                        SEXP_list_sort(items, SEXP_refcmp);
                        SEXP_free(items);
                }

		if (probe_rcache_sexp_add(pair->probe->rcache, oid, probe_res) != 0) {
			/* TODO */
			abort();
		}
		SEXP_free(obj);
		SEXP_free(oid);
	}

	if (probe_ret != 0) {
		/*
		 * Something bad happened. A hint of the cause is stored as a error code in
		 * probe_ret (should be). We'll send it to the library using a SEAP error packet.
		 */
		if (SEAP_replyerr(pair->probe->SEAP_ctx, pair->probe->sd, pair->pth->msg, probe_ret) == -1) {
			int ret = errno;

			dE("An error ocured while sending error status. errno=%u, %s.", errno, strerror(errno));
			SEXP_free(probe_res);

			/* FIXME */
			exit(ret);
		}
		SEXP_free(probe_res);
	} else {
		SEAP_msg_t *seap_reply;
		/*
		 * OK, the probe actually returned something, let's send it to the library.
		 */
		seap_reply = SEAP_msg_new();
		SEAP_msg_set(seap_reply, probe_res);

		if (SEAP_reply(pair->probe->SEAP_ctx, pair->probe->sd, seap_reply, pair->pth->msg) == -1) {
			int ret = errno;

			SEAP_msg_free(seap_reply);
			SEXP_free(probe_res);

			exit(ret);
		}

		SEAP_msg_free(seap_reply);
                SEXP_free(probe_res);
	}

        SEAP_msg_free(pair->pth->msg);
        free(pair->pth);
	free(pair);
	pthread_detach(pthread_self());

	dD("probe_worker_runfn has finished");
	return (NULL);
}

probe_worker_t *probe_worker_new(void)
{
	probe_worker_t *pth = malloc(sizeof(probe_worker_t));

	pth->sid = 0;
#ifndef OS_WINDOWS
	pth->tid = 0;
#endif
	pth->msg_handler = NULL;
	pth->msg = NULL;

	return (pth);
}



#define MAX_EVAL_DEPTH 8 /**< maximum recursion depth for set evaluation */

/**
 * Fetch states from the library. This function performs the state fetch operation
 * that is used by the set evaluation function to fetch states that aren't available
 * in the probe cache. The operation is implemented using a remote synchronous SEAP
 * command. The fetched states are added to the probe cache by this function.
 *
 * @param id_list list of requested state ids
 * @retval list list of fetched states, the possition in the list corresponds to the
 *              possition in the id_list
 * @retval NULL on failure or when some of the ids do not refer to existing states in
 *              the associated OVAL document
 */
static SEXP_t *probe_ste_fetch(probe_t *probe, SEXP_t *id_list)
{
	SEXP_t *res, *ste, *id;
	uint32_t i_len, r_len;

	i_len = SEXP_list_length(id_list);

	if (i_len == 0)
		return SEXP_list_new(NULL);

	res = SEAP_cmd_exec(probe->SEAP_ctx, probe->sd, 0, PROBECMD_STE_FETCH, id_list, SEAP_CMDTYPE_SYNC, NULL, NULL);

	r_len = SEXP_list_length(res);

	if (i_len != r_len) {
		SEXP_free(res);
		return (NULL);
	}

	for (; i_len > 0; --i_len) {
		ste = SEXP_list_nth(res, i_len);
		id  = SEXP_list_nth(id_list, i_len);

		_A(id != NULL);
		_A(ste != NULL);

		if (probe_rcache_sexp_add(probe->rcache, id, ste) != 0) {

			SEXP_free(res);
			SEXP_free(ste);
			SEXP_free(id);

			return (NULL);
		}

		SEXP_free(ste);
		SEXP_free(id);
	}

	return (res);
}

/**
 * Evaluate an OVAL object identified by its id. Using a remote
 * synchronous SEAP command, this function executes evaluation of an
 * OVAL object which results weren't found in the probe cache. This
 * indirectly spawns a new thread in the probe process which evaluates
 * the object and stores the result in the probe cache. That result is
 * not send to the library because it doesn't know how to handle
 * it. Instead, the result is fetched by this function from the cache
 * and returned to the caller.
 * @param id the id of the OVAL object to be evaluated
 * @return the result of the evaluation of the object or NULL on failure
 */
static SEXP_t *probe_obj_eval(probe_t *probe, SEXP_t *id)
{
	SEXP_t *res, *rid;

	res = SEAP_cmd_exec(probe->SEAP_ctx, probe->sd, 0, PROBECMD_OBJ_EVAL, id, SEAP_CMDTYPE_SYNC, NULL, NULL);

	rid = SEXP_list_first(res);
	if (SEXP_string_cmp(id, rid) != 0) {
		SEXP_free(res);
		SEXP_free(rid);
		return NULL;
	}
	SEXP_free(res);
	SEXP_free(rid);

	return probe_rcache_sexp_get(probe->rcache, id);
}

static SEXP_t *probe_prepare_filters(probe_t *probe, SEXP_t *obj)
{
	SEXP_t *filters;
	int i;

	filters = SEXP_list_new(NULL);

	for (i = 1; ; ++i) {
		SEXP_t *of, *f, *ste, *ste_id, *act;

		of = probe_obj_getent(obj, "filter", i);

		if (of == NULL)
			break;

		act = probe_ent_getattrval(of, "action");
		ste_id = probe_ent_getval(of);
		ste = probe_rcache_sexp_get(probe->rcache, ste_id);

		if (ste == NULL) {
			SEXP_t *r0, *r1;

			r0  = SEXP_list_new(ste_id, NULL);
			r1  = probe_ste_fetch(probe, r0);
			ste = SEXP_list_first(r1);

			SEXP_free(r0);
			SEXP_free(r1);
		}
		SEXP_free(of);
		SEXP_free(ste_id);

		f = SEXP_list_new(act, ste, NULL);
		SEXP_list_add(filters, f);

		SEXP_free(act);
		SEXP_free(ste);
		SEXP_free(f);
	}

	return filters;
}

/**
 * Evaluate a set. This function takes care of evaluating a set of either two other sets
 * or an object and 0..n filters. Objects are evaluated using the probe_obj_eval function
 * and filters are fetched using the probe_ste_fetch function.
 * @param set the set to be evaluated
 * @param depth maximum recursion depth
 * @return the result of the evaluation or NULL on failure
 */
static SEXP_t *probe_set_eval(probe_t *probe, SEXP_t *set, size_t depth)
{
	SEXP_t *filters_u, *filters_a, *filters_req;

	SEXP_t *s_subset[2];
	size_t s_subset_i;
	SEXP_t *o_subset[2];
	size_t o_subset_i;

	SEXP_t *member;
	char member_name[24];

	SEXP_t *op_val;
	int op_num;

	SEXP_t *r0, *r1, *result, *Omsg = NULL;

	if (depth > MAX_EVAL_DEPTH) {
		char *fmt = "probe_set_eval: Too many levels: max=%zu.";
#ifndef NDEBUG
                dD(fmt, (size_t) MAX_EVAL_DEPTH);
		abort();
#endif
		r0 = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR, fmt, (size_t) MAX_EVAL_DEPTH);
		r1 = SEXP_list_new(r0, NULL);
		result = probe_cobj_new(SYSCHAR_FLAG_ERROR, r1, NULL, NULL);
		SEXP_free(r0);
		SEXP_free(r1);
		return result;
	}

	filters_u = SEXP_list_new(NULL);	/* unavailable filters */
	filters_a = SEXP_list_new(NULL);	/* available filters (cached) */
	filters_req = SEXP_list_new(NULL);	/* request list for probe_ste_fetch() */

	s_subset[0] = NULL;
	s_subset[1] = NULL;
	s_subset_i = 0;

	o_subset[0] = NULL;
	o_subset[1] = NULL;
	o_subset_i = 0;

	result = NULL;

	op_val = probe_ent_getattrval(set, "operation");

	if (op_val != NULL)
		op_num = SEXP_number_geti_32(op_val);
	else
		op_num = OVAL_SET_OPERATION_UNION;

	SEXP_free(op_val);

	_A(op_num == OVAL_SET_OPERATION_UNION ||
	   op_num == OVAL_SET_OPERATION_COMPLEMENT || op_num == OVAL_SET_OPERATION_INTERSECTION);

#define probe_set_foreach(elm_var, set_list) SEXP_sublist_foreach (elm_var, set_list, 2, 1000)
#define CASE(__c1, __rest) case (__c1): if (strcmp (__rest, member_name + 1) == 0)

	probe_set_foreach(member, set) {
		if (probe_ent_getname_r(member, member_name, sizeof member_name) == 0) {
                        Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
						"probe_set_eval: Invalid set element: ptr=%p, type=%s.", member, SEXP_strtype(member));
			goto eval_fail;
		}

		if (strcmp("set", member_name) == 0) {
			/*
			 * Handle a (sub)set entity
			 */
			if (s_subset_i < 2) {
				s_subset[s_subset_i] = probe_set_eval(probe, member, depth + 1);

				if (s_subset[s_subset_i] == NULL) {
					Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
								"probe_set_eval: Recursive set evaluation failed: m=%p, d=%zu.",
								member, depth + 1);
					goto eval_fail;
				}

				++s_subset_i;
			} else {
				Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
							"probe_set_eval: More than 2 \"set\".");
				goto eval_fail;
			}
		} else if (strcmp("obj_ref", member_name) == 0) {
			/*
			 * Handle an object reference
			 */
			SEXP_t *OID; /**< OVAL object ID */
			SEXP_t *objres; /**< Result of the evaluation */
			char    OID_cstr[128];

			dD("Handling object_reference");

			if ((OID = probe_ent_getval(member)) == NULL) {
				Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
							"%s: missing object_reference entity value!", __FUNCTION__);
				goto eval_fail;
			}
#ifndef NDEBUG
			SEXP_string_cstr_r(OID, OID_cstr, sizeof OID_cstr);
			dD("Looking for the result in cache: OID=%s", OID_cstr);
#endif
			if ((objres = probe_rcache_sexp_get(probe->rcache, OID)) == NULL) {
				dD("MISS => requesting object evaluation from the library");

				objres = probe_obj_eval(probe, OID);

				dD("EVAL: result=%p", objres);
				if (objres != NULL) {
					dO(OSCAP_DEBUGOBJ_SEXP, objres);
				} else {
					SEXP_string_cstr_r(OID, OID_cstr, sizeof OID_cstr);
					Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
								"%s: evaluation failed: OID=%s", __FUNCTION__, OID_cstr);
					SEXP_free(OID);
					goto eval_fail;
				}
			}

			SEXP_free(OID);

			if (o_subset_i < 2) {
				o_subset[o_subset_i] = objres;
				++o_subset_i;
			} else {
				Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
							"%s: more than 2 obj_refs.", __FUNCTION__);
				SEXP_free(objres);
				goto eval_fail;
			}
		} else if (strcmp("filter", member_name) == 0) {
			/*
			 * Retrieve cached filters (states), remember unavailable ones so that
			 * we can fetch them all in one request.
			 */
			SEXP_t *SID, *action, *state;

			if ((SID = probe_ent_getval(member)) == NULL) {
				Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
							"%s: missing filter entity value.", __FUNCTION__);
				goto eval_fail;
			}

			if ((action = probe_ent_getattrval(member, "action")) == NULL) {
				Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
							"%s: missing filter action.", __FUNCTION__);
				SEXP_free(SID);
				goto eval_fail;
			}

			if ((state = probe_rcache_sexp_get(probe->rcache, SID)) == NULL) {
				/* MISS - remember the ID */
				SEXP_list_add(filters_req, SID);
				r0 = SEXP_list_new(action, SID, NULL);
				SEXP_list_add(filters_u, r0);
			} else {
				/* HIT */
				r0 = SEXP_list_new(action, state, NULL);
				SEXP_list_add(filters_a, r0);
				SEXP_free(state);
			}

			SEXP_free(SID);
			SEXP_free(action);
			SEXP_free(r0);
		} else {
			/*
			 * Unexpected entity
			 */
			abort();
		}
	}

	member = NULL;

	/* request filters */
	result = probe_ste_fetch(probe, filters_req);

	if (result == NULL) {
                Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
					"%s: Can't get unavailable filters.", __FUNCTION__);
		goto eval_fail;
	}
	SEXP_free(filters_req);
	SEXP_free(result);

	SEXP_list_foreach(member, filters_u) {
		SEXP_t *id, *act, *ste;

		act = SEXP_list_first(member);
		id = SEXP_list_nth(member, 2);
		ste = probe_rcache_sexp_get(probe->rcache, id);
		r0 = SEXP_list_new(act, ste, NULL);
		SEXP_list_add(filters_a, r0);

		SEXP_free(act);
		SEXP_free(id);
		SEXP_free(ste);
		SEXP_free(r0);
	}

	SEXP_free(filters_u);

	_A((s_subset_i > 0 && o_subset_i == 0) || (s_subset_i == 0 && o_subset_i > 0));

	if (o_subset_i > 0) {
		for (s_subset_i = 0; s_subset_i < o_subset_i; ++s_subset_i) {
			s_subset[s_subset_i] = probe_set_apply_filters(o_subset[s_subset_i], filters_a);

#ifndef NDEBUG
			if (s_subset[s_subset_i] == NULL) {
                                Omsg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
							"%s: apply_filters returned NULL: set=%p, filters=%p.",
							__FUNCTION__, o_subset[s_subset_i], filters_a);
				goto eval_fail;
			}
#endif
			SEXP_free(o_subset[s_subset_i]);
                        o_subset[s_subset_i] = NULL;
		}
	}

#ifndef NDEBUG
        {
                unsigned int i;

                for (i = 0; i < s_subset_i; ++i) {
                        if (s_subset[i] != NULL) {
                                dD("=== s_subset[%d] ===", i);
                                dO(OSCAP_DEBUGOBJ_SEXP, s_subset[i]);
                        }
                }

                for (i = 0; i < o_subset_i; ++i) {
                        if (o_subset[i] != NULL) {
                                dD("=== o_subset[%d] ===", i);
                                dO(OSCAP_DEBUGOBJ_SEXP, o_subset[i]);
                        }
                }
        }

        dD("OP= %d", op_num);
#endif

	SEXP_free(filters_a);
	result = probe_set_combine(s_subset[0], s_subset[1], op_num);

	_A(result != NULL);

	SEXP_free(s_subset[0]);
	SEXP_free(s_subset[1]);

        dD("=== RESULT ===");
        dO(OSCAP_DEBUGOBJ_SEXP, result);

	return (result);
 eval_fail:
	SEXP_free(member);

	for (; s_subset_i > 0; --s_subset_i)
		SEXP_free(s_subset[s_subset_i - 1]);

	for (; o_subset_i > 0; --o_subset_i)
		SEXP_free(o_subset[o_subset_i - 1]);

	SEXP_free(filters_u);
	SEXP_free(filters_a);
	SEXP_free(filters_req);
	SEXP_free(result);

        r1 = SEXP_list_new(Omsg, NULL);
	result = probe_cobj_new(SYSCHAR_FLAG_ERROR, r1, NULL, NULL);
	SEXP_free(Omsg);
	SEXP_free(r1);
	return result;
}

/**
 * Worker thread function. This functions handles the evalution of objects and sets.
 * @param msg_in SEAP message with the request which contains the object to be evaluated
 * @param ret pointer to the return code storage
 */
SEXP_t *probe_worker(probe_t *probe, SEAP_msg_t *msg_in, int *ret)
{
#ifndef OS_WINDOWS
	char *rootdir = NULL;
	probe_offline_mode_function_t offline_mode_function = probe_table_get_offline_mode_function(probe->subtype);
	if (offline_mode_function != NULL) {
		probe->supported_offline_mode = offline_mode_function();
	} else {
		probe->supported_offline_mode = PROBE_OFFLINE_NONE;
	}

	/*
	 * Setup offline mode(s)
	 */
	rootdir = getenv("OSCAP_PROBE_ROOT");
	if ((rootdir != NULL) && (strlen(rootdir) > 0)) {
		preload_libraries_before_chroot(); // todo - maybe useless for own mode

		if (probe->supported_offline_mode == PROBE_OFFLINE_NONE) {
			dW("Requested offline mode is not supported by %s probe.", oval_subtype_get_text(probe->subtype));
			*ret = 0;
			return probe_cobj_new(SYSCHAR_FLAG_NOT_APPLICABLE, NULL, NULL, NULL);

		} else if (probe->supported_offline_mode & PROBE_OFFLINE_OWN) {
			dI("Switching probe to PROBE_OFFLINE_OWN mode.");
			probe->offline_mode = true;
			probe->selected_offline_mode = PROBE_OFFLINE_OWN;

		} else if (probe->supported_offline_mode & PROBE_OFFLINE_CHROOT) {
			probe->real_root_fd = open("/", O_RDONLY);
			if (probe->real_root_fd == -1) {
				dE("open(\"/\") failed: %s", strerror(errno));
				return NULL;
			}
			probe->real_cwd_fd = open(".", O_RDONLY);
			if (probe->real_cwd_fd == -1) {
				close(probe->real_root_fd);
				dE("open(\".\") failed: %s", strerror(errno));
				return NULL;
			}
			if (chdir(rootdir) != 0) {
				dE("chdir failed: %s", strerror(errno));
			}

			if (chroot(rootdir) != 0) {
				dE("chroot failed: %s", strerror(errno));
			}
			/* NOTE: We're running in a different root directory.
			 * Unless /proc, /sys are somehow emulated for the new
			 * environment, they are not relevant and so are other
			 * runtime only things (e.g. getenv, uname, ...).
			 * Switch to offline mode. We may add a separate
			 * mechanism to control this behaviour in the future.
			 */
			dI("Switching probe to PROBE_OFFLINE_CHROOT mode.");
			probe->offline_mode = true;
			probe->selected_offline_mode = PROBE_OFFLINE_CHROOT;
		}
	}
#endif

	SEXP_t *probe_in, *probe_out, *set;

	if (msg_in == NULL) {
		*ret = PROBE_EINVAL;
		return (NULL);
	}

	probe_in  = SEAP_msg_get(msg_in);
	probe_out = NULL;

	if (probe_in == NULL) {
		*ret = PROBE_ENOOBJ;
		return (NULL);
	}

	set = probe_obj_getent(probe_in, "set", 1);

	if (set != NULL) {
		/* set object */
		probe_out = probe_set_eval(probe, set, 0);
		SEXP_free(set);
		// todo: in case of an internal error set probe_ret accordingly
		*ret = 0;
	} else {
                struct probe_ctx pctx;
		SEXP_t *varrefs, *mask;

		pctx.offline_mode = probe->selected_offline_mode;

		/* simple object */
                pctx.icache  = probe->icache;
		pctx.filters = probe_prepare_filters(probe, probe_in);
                mask = probe_obj_getmask(probe_in);

		if (OSCAP_GSYM(varref_handling))
			varrefs = probe_obj_getent(probe_in, "varrefs", 1);
                else
                        varrefs = NULL;

		oval_subtype_t subtype = probe->subtype;
		probe_main_function_t probe_main_function = probe_table_get_main_function(subtype);
		const char *subtype_str = oval_subtype_get_text(subtype);

		if (varrefs == NULL || !OSCAP_GSYM(varref_handling)) {
                        /*
                         * Prepare the collected object
                         */
			probe_out = probe_cobj_new(SYSCHAR_FLAG_UNKNOWN, NULL, NULL, mask);
			SEXP_free(mask);
			
                        pctx.probe_in  = probe_in;
                        pctx.probe_out = probe_out;

                        /*
                         * Run the main function of the probe implementation. Set thread
			 * cancelation type to ASYNC to prevent the code in probe_main to
			 * defer the cancelation for too long.
                         */
			int __unused_oldstate;
			pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &__unused_oldstate);



			dI("I will run %s_probe_main:", subtype_str);
			*ret = probe_main_function(&pctx, probe->probe_arg);

			pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &__unused_oldstate);

#ifdef OVAL_ICACHE_THREAD_ENABLED
                        /*
                         * Synchronize
                         */
                        probe_icache_nop(probe->icache);
#endif

			probe_cobj_compute_flag(probe_out);
		} else {
			/*
			 * there are variable references in the object.
			 * create ctx, iterate through all variable combinations
			 */
			struct probe_varref_ctx *ctx;

			dD("handling varrefs in object");

			if (probe_varref_create_ctx(probe_in, varrefs, &ctx) != 0) {
				SEXP_free(varrefs);
				SEXP_free(pctx.filters);
				SEXP_free(probe_in);
				SEXP_free(mask);
				*ret = PROBE_EUNKNOWN;
				return (NULL);
			}

			SEXP_free(varrefs);

			do {
				SEXP_t *cobj, *r0;
                                /*
                                 * Prepare the collected object
                                 */
				cobj = probe_cobj_new(SYSCHAR_FLAG_UNKNOWN, NULL, NULL, mask);

                                pctx.probe_in  = ctx->pi2;
                                pctx.probe_out = cobj;
                                /*
                                 * Run the main function of the probe implementation
                                 */
			dI("I will run %s_probe_main:", subtype_str);
			*ret = probe_main_function(&pctx, probe->probe_arg);

#ifdef OVAL_ICACHE_THREAD_ENABLED
                                /*
                                 * Synchronize
                                 */
                                probe_icache_nop(probe->icache);
#endif

				probe_cobj_compute_flag(cobj);
				r0 = probe_out;
				probe_out = probe_set_combine(r0, cobj, OVAL_SET_OPERATION_UNION);
				SEXP_free(cobj);
				SEXP_free(r0);
			} while (*ret == 0
				 && probe_varref_iterate_ctx(ctx));

			SEXP_free(mask);
			probe_varref_destroy_ctx(ctx);
		}

                SEXP_free(pctx.filters);
	}

	SEXP_free(probe_in);

#ifndef OS_WINDOWS
	/* Revert chroot */
	if (probe->real_root_fd != -1) {
		if (fchdir(probe->real_root_fd) != 0) {
			dE("fchdir failed: %s", strerror(errno));
			close(probe->real_root_fd);
			close(probe->real_cwd_fd);
			probe->real_root_fd = -1;
			probe->real_cwd_fd = -1;
			SEXP_free(probe_out);
			return NULL;
		}
		close(probe->real_root_fd);
		probe->real_root_fd = -1;
		dI("Leaving chroot mode");
		if (chroot(".") == -1) {
			dE("chroot(\".\") failed: %s", strerror(errno));
			close(probe->real_cwd_fd);
			probe->real_cwd_fd = -1;
			SEXP_free(probe_out);
			return NULL;
		}
		if (fchdir(probe->real_cwd_fd) != 0) {
			dE("fchdir failed: %s", strerror(errno));
			close(probe->real_cwd_fd);
			probe->real_cwd_fd = -1;
			SEXP_free(probe_out);
			return NULL;
		}
		close(probe->real_cwd_fd);
		probe->real_cwd_fd = -1;
	}
#endif

	SEXP_VALIDATE(probe_out);

	return (probe_out);
}
