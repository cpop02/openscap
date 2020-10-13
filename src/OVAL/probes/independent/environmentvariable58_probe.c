/**
 * @file   environmentvariable58_probe.c
 * @brief  environmentvariable58 probe
 * @author "Petr Lautrbach" <plautrba@redhat.com>
 *
 *  This probe is able to process a environmentvariable58_object as defined in OVAL 5.8.
 *
 */

/*
 * Copyright 2009-2011 Red Hat Inc., Durham, North Carolina.
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
 *   Petr Lautrbach <plautrba@redhat.com>
 */

/*
 * environmentvariable58 probe:
 *
 * pid
 * name
 * value
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "probe-common.h"
#include "probes/probe/probe.h"

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#include <probe/probe.h>
#include "_seap.h"
#include "probe-api.h"
#include "probe/entcmp.h"
#include "common/debug_priv.h"
#include "environmentvariable58_probe.h"

#ifndef EXTERNAL_PROBE_COLLECT

#if defined(OS_FREEBSD)
#include <limits.h>
#include <sys/user.h>
#include <kvm.h>
#include <sys/param.h>
#include <paths.h>
#include <libprocstat.h>
#include <sys/sysctl.h>

static int read_environment(SEXP_t *pid_ent, SEXP_t *name_ent, probe_ctx *ctx)
{
	struct kinfo_proc *proclist, *proc;
	int i, j, count, pid;
	char *name, *value;
	const char *SEP = "=";
	struct procstat *stat = NULL;
	char buf[LINE_MAX];
	SEXP_t *pid_sexp;
	char **env = NULL;
	kvm_t *kd;

	const char *extra_vars = getenv("OSCAP_CONTAINER_VARS");
	if (extra_vars && *extra_vars) {
		char *vars = strdup(extra_vars);
		char *tok, *eq_chr, *str, *strp;

		for (str = vars; ; str = NULL) {
			tok = strtok_r(str, "\n", &strp);
			if (tok == NULL)
				break;
			eq_chr = strchr(tok, '=');
			if (eq_chr == NULL)
				continue;
			PROBE_ENT_I32VAL(pid_ent, pid, pid = -1;, pid = 0;);

			size_t extra_env_name_size = eq_chr - tok;
			SEXP_t *extra_env_name = SEXP_string_new(tok, extra_env_name_size);
			SEXP_t *extra_env_value = SEXP_string_newf("%s", tok + extra_env_name_size + 1);

			if (probe_entobj_cmp(name_ent, extra_env_name) == OVAL_RESULT_TRUE) {
				SEXP_t *extra_item = probe_item_create(
					OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE58, NULL,
					"pid", OVAL_DATATYPE_INTEGER, (int64_t)pid,
					"name",  OVAL_DATATYPE_SEXP, extra_env_name,
					"value", OVAL_DATATYPE_SEXP, extra_env_value,
					NULL);

				if (!extra_item) {
					dE("Failed to create new probem item");
					SEXP_free(extra_env_name);
					SEXP_free(extra_env_value);
					free(vars);
					return (PROBE_EFAULT);
				}

				probe_item_collect(ctx, extra_item);
			} else {
				SEXP_free(extra_env_name);
				SEXP_free(extra_env_value);
			}
		}

		free(vars);
		return 0;
	}

	kd = kvm_openfiles(NULL, _PATH_DEVNULL, NULL, O_RDONLY, buf);

	if (!kd)
		return (PROBE_EFAULT);

	proclist = kvm_getprocs(kd, KERN_PROC_PROC, 0, &count);

	if (!proclist) {
		dE("Failed to obtain process list handle");
		kvm_close(kd);
		return (PROBE_EFAULT);
	}

	proc = proclist;

	/* Loop until we find a matching PID */
	for (i = 0; i < count; i++, proc++) {
		pid = proc->ki_pid;
		pid_sexp = SEXP_number_newi_32(pid);

		if (!pid_sexp) {
			dE("Failed to allocate pid_sexp");
			kvm_close(kd);
			return (PROBE_EFATAL);
		}

		/* PID doesn't match */
		if (probe_entobj_cmp(pid_ent, pid_sexp) != OVAL_RESULT_TRUE) {
			SEXP_free(pid_sexp);
			continue;
		}

		/* PID matches */
		stat = procstat_open_sysctl();

		if (!stat) {
			dE("NULL procstat handle returned");
			SEXP_free(pid_sexp);
			kvm_close(kd);
			return (PROBE_EFAULT);
		}

		env = procstat_getenvv(stat, proc, ARG_MAX);

		/* Found matching process, so stop searching */
		SEXP_free(pid_sexp);
		break;
	}

	if (!env) {
		dE("NULL env returned");
		procstat_freeenvv(stat);
		kvm_close(kd);
		return (PROBE_EFATAL);
	}

	for (j = 0; env[j] != NULL; j++) {
		char *strp;
		name = strtok_r(env[j], SEP, &strp);

		if (!name) {
			dE("Error parsing environment string");
			procstat_freeenvv(stat);
			kvm_close(kd);
			return (PROBE_EFAULT);
		}

		value = strtok_r(NULL, SEP, &strp);

		if (value != NULL) {
			SEXP_t *env_name = SEXP_string_new(name, strlen(name) + 1);
			SEXP_t *env_value = SEXP_string_new(value, strlen(value) + 1);

			if (probe_entobj_cmp(name_ent, env_name) == OVAL_RESULT_TRUE) {

				SEXP_t *item = probe_item_create(
					OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE58, NULL,
					"pid", OVAL_DATATYPE_INTEGER, (int64_t)pid,
					"name",  OVAL_DATATYPE_SEXP, env_name,
					"value", OVAL_DATATYPE_SEXP, env_value,
					NULL);

				if (!item) {
					dE("Failed to create new probe item");
					SEXP_free(env_name);
					SEXP_free(env_value);
					procstat_freeenvv(stat);
					kvm_close(kd);
					return (PROBE_EFAULT);
				}

				probe_item_collect(ctx, item);
			} else {
				SEXP_free(env_name);
				SEXP_free(env_value);
			}
		}
	}

	procstat_freeenvv(stat);
	kvm_close(kd);
	return 0;
}

#else
#define BUFFER_SIZE 256

extern char **environ;

static int collect_variable(char *buffer, size_t env_name_size, int pid, SEXP_t *name_ent, probe_ctx *ctx)
{
	int res = 1;

	SEXP_t *env_name = SEXP_string_new(buffer, env_name_size);
	SEXP_t *env_value = SEXP_string_newf("%s", buffer + env_name_size + 1);

	if (probe_entobj_cmp(name_ent, env_name) == OVAL_RESULT_TRUE) {
		SEXP_t *item = probe_item_create(
			OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE58, NULL,
			"pid", OVAL_DATATYPE_INTEGER, (int64_t)pid,
			"name",  OVAL_DATATYPE_SEXP, env_name,
			"value", OVAL_DATATYPE_SEXP, env_value,
			NULL);
		probe_item_collect(ctx, item);
		res = 0;
	}
	SEXP_free(env_name);
	SEXP_free(env_value);

	return res;
}

static int read_environment(SEXP_t *pid_ent, SEXP_t *name_ent, probe_ctx *ctx)
{
	int err = 1, pid, fd;
	bool empty;
	SEXP_t *item, *pid_sexp;
	DIR *d;
	struct dirent *d_entry;
	char *buffer, *null_char, path[PATH_MAX] = {0};
	ssize_t buffer_used;
	size_t buffer_size;

	const char *extra_vars = getenv("OSCAP_CONTAINER_VARS");
	if (extra_vars && *extra_vars) {
		char *vars = strdup(extra_vars);
		char *tok, *eq_chr, *str, *strp;

		for (str = vars; ; str = NULL) {
			tok = strtok_r(str, "\n", &strp);
			if (tok == NULL)
				break;
			eq_chr = strchr(tok, '=');
			if (eq_chr == NULL)
				continue;
			PROBE_ENT_I32VAL(pid_ent, pid, pid = -1;, pid = 0;);
			collect_variable(tok, eq_chr - tok, pid, name_ent, ctx);
		}

		free(vars);
		return 0;
	}

	const char *prefix = getenv("OSCAP_PROBE_ROOT");
	snprintf(path, PATH_MAX, "%s/proc", prefix ? prefix : "");
	d = opendir(path);
	if (d == NULL) {
		dE("Can't read %s/proc: errno=%d, %s.", prefix ? prefix : "", errno, strerror(errno));
		return PROBE_EACCESS;
	}

	if ((buffer = realloc(NULL, BUFFER_SIZE)) == NULL) {
		dE("Can't allocate memory");
		closedir(d);
		return PROBE_EFAULT;
	}
	buffer_size = BUFFER_SIZE;

	while ((d_entry = readdir(d))) {
		if (strspn(d_entry->d_name, "0123456789") != strlen(d_entry->d_name))
			continue;

		pid = atoi(d_entry->d_name);
		pid_sexp = SEXP_number_newi_32(pid);

		if (probe_entobj_cmp(pid_ent, pid_sexp) != OVAL_RESULT_TRUE) {
			SEXP_free(pid_sexp);
			continue;
		}
		SEXP_free(pid_sexp);

		snprintf(path, PATH_MAX, "%s/proc/%d/environ", prefix ? prefix : "", pid);
		if ((fd = open(path, O_RDONLY)) == -1) {
			dE("Can't open \"%s\": errno=%d, %s.", path, errno, strerror (errno));
			item = probe_item_create(
					OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE58, NULL,
					"pid", OVAL_DATATYPE_INTEGER, (int64_t)pid,
					NULL
			);

			probe_item_setstatus(item, SYSCHAR_STATUS_ERROR);
			probe_item_add_msg(item, OVAL_MESSAGE_LEVEL_ERROR,
					   "Can't open \"%s\": errno=%d, %s.", path, errno, strerror (errno));
			probe_item_collect(ctx, item);
			continue;
		}

		empty = true;

		if ((buffer_used = read(fd, buffer, buffer_size - 1)) > 0) {
			empty = false;
		}

		while (! empty) {
			while (! (null_char = memchr(buffer, 0, buffer_used))) {
				ssize_t s;
				if ((size_t)buffer_used >= buffer_size) {
					buffer_size += BUFFER_SIZE;
					buffer = realloc(buffer, buffer_size);
					if (buffer == NULL) {
						dE("Can't allocate memory");
						exit(ENOMEM);
					}

				}
				s = read(fd, buffer + buffer_used, buffer_size - buffer_used);
				if (s <= 0) {
					empty = true;
					buffer[buffer_used++] = 0;
				}
				else {
					buffer_used += s;
				}
			}

			do {
				char *eq_char = strchr(buffer, '=');
				if (eq_char == NULL) {
					/* strange but possible:
					 * $ strings /proc/1218/environ
 					/dev/input/event0 /dev/input/event1 /dev/input/event4 /dev/input/event3
					*/
					buffer_used -= null_char + 1 - buffer;
					memmove(buffer, null_char + 1, buffer_used);
					continue;
				}

				collect_variable(buffer, eq_char - buffer, pid, name_ent, ctx);

				buffer_used -= null_char + 1 - buffer;
				memmove(buffer, null_char + 1, buffer_used);
			} while ((null_char = memchr(buffer, 0, buffer_used)));
		}

		close(fd);
	}
	closedir(d);
	free(buffer);
	if (err) {
		SEXP_t *msg = probe_msg_creatf(OVAL_MESSAGE_LEVEL_ERROR,
				"Can't find process with requested PID.");
		probe_cobj_add_msg(probe_ctx_getresult(ctx), msg);
		SEXP_free(msg);
		err = 0;
	}

	return err;
}

#endif

#else // EXTERNAL_PROBE_COLLECT

static inline int collect_variable(SEXP_t *un_ent, probe_ctx *ctx, const char *ext_value_name, oval_external_probe_item_value_t *ext_value_val) {
    int ret = 0;
    const char *ext_value_val_cstr;
    oval_datatype_t ext_value_datatype;
    SEXP_t *var_name = NULL, *var_val = NULL, *var;

    ext_value_datatype = oval_external_probe_item_value_get_datatype(ext_value_val);
    if(ext_value_datatype != OVAL_DATATYPE_STRING) {
        ret = PROBE_EINVAL;
        goto fail;
    }
    ext_value_val_cstr = oval_external_probe_item_value_get_string(ext_value_val);
    if(ext_value_val_cstr == NULL) {
        ret = PROBE_EINVAL;
        goto fail;
    }
    var_name = SEXP_string_newf("%s", ext_value_name);
    if(probe_entobj_cmp(un_ent, var_name) != OVAL_RESULT_TRUE) {
        goto cleanup;
    }
    var_val = SEXP_string_newf("%s", ext_value_val_cstr);
    var = probe_item_create(
            OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE58, NULL,
            "name", OVAL_DATATYPE_SEXP, var_name,
            "value", OVAL_DATATYPE_SEXP, var_val,
            NULL);
    if(var == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    // no need to free the item because probe_item_collect frees it in almost all cases
    ret = probe_item_collect(ctx, var);

    fail:
    cleanup:
    SEXP_free(var_val);
    SEXP_free(var_name);

    return ret;
}

static int collect_variables(SEXP_t *un_ent, probe_ctx *ctx, oval_external_probe_item_list_t *ext_items) {
    int ret = 0;
    oval_external_probe_item_t *ext_item;
    const char *ext_item_value_name;
    oval_external_probe_item_value_t *ext_item_value_val;

    __attribute__nonnull__(ctx);
    __attribute__nonnull__(ext_items);

    OVAL_EXTERNAL_PROBE_ITEM_LIST_FOREACH(ext_items, ext_item, {
        OVAL_EXTERNAL_PROBE_ITEM_FOREACH(ext_item, ext_item_value_name, ext_item_value_val, {
                ret = collect_variable(un_ent, ctx, ext_item_value_name, ext_item_value_val);
                if(ret != 0) {
                    break;
                }
        })
        if(ret != 0) {
            break;
        }
    })

    return ret;
}

static int read_environment(SEXP_t *un_ent, probe_ctx *ctx) {
    int ret;
    char *str_id = NULL;
    SEXP_t *in, *id = NULL;
    oval_syschar_status_t status;
    oval_external_probe_eval_funcs_t *eval;
    oval_external_probe_item_t *ext_query = NULL;
    oval_external_probe_result_t *ext_res = NULL;
    oval_external_probe_item_list_t *ext_items;

    __attribute__nonnull__(ctx);

    eval = probe_get_external_probe_eval(ctx);
    if(eval == NULL || eval->environmentvariable_probe == NULL) {
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    in = probe_ctx_getobject(ctx);
    id = probe_obj_getattrval(in, "id");
    if(id == NULL) {
        ret = PROBE_ENOVAL;
        goto fail;
    }
    str_id = SEXP_string_cstr(id);
    if(str_id == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ret = probe_create_external_probe_query(in, &ext_query);
    if(ret != 0) {
        goto fail;
    }
    ext_res = eval->environmentvariable_probe(eval->probe_ctx, str_id, ext_query);
    if(ext_res == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    status = oval_external_probe_result_get_status(ext_res);
    if(status == SYSCHAR_STATUS_ERROR) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ext_items = oval_external_probe_result_get_items(ext_res);
    if(ext_items == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ret = collect_variables(un_ent, ctx, ext_items);

fail:
    oval_external_probe_result_free(ext_res);
    oval_external_probe_item_free(ext_query);
    free(str_id);
    SEXP_free(id);

    return ret;
}

#endif //EXTERNAL_PROBE_COLLECT

int environmentvariable58_probe_offline_mode_supported(void) {
#ifdef EXTERNAL_PROBE_COLLECT
	return PROBE_OFFLINE_NONE;
#else
	return PROBE_OFFLINE_OWN;
#endif
}

int environmentvariable58_probe_main(probe_ctx *ctx, void *arg) {
	int pid, ret = 0;
    SEXP_t *probe_in, *name_ent = NULL, *pid_ent = NULL;

	probe_in  = probe_ctx_getobject(ctx);
	name_ent = probe_obj_getent(probe_in, "name", 1);
	if(name_ent == NULL) {
	    ret = PROBE_ENOENT;
	    goto fail;
	}
	pid_ent = probe_obj_getent(probe_in, "pid", 1);
	if(pid_ent == NULL) {
	    ret = PROBE_ENOENT;
	    goto fail;
	}
	PROBE_ENT_I32VAL(pid_ent, pid, pid = -1;, pid = 0;);
	if(pid == -1) {
	    ret = PROBE_ERANGE;
	    goto fail;
	}
#ifdef EXTERNAL_PROBE_COLLECT
	if(pid != 0) {
		// External probe can't collect env vars from other processes
		ret = PROBE_EOPNOTSUPP;
		goto fail;
	} else {
		ret = read_environment(name_ent, ctx);
	}
#else
	if(pid == 0) {
		/* overwrite pid value with actual pid */
		SEXP_t *nref, *nval, *new_pid_ent;

		nref = SEXP_list_first(probe_in);
		nval = SEXP_number_newu_32(getpid());
		new_pid_ent = SEXP_list_new(nref, nval, NULL);
		SEXP_free(pid_ent);
		SEXP_free(nref);
		SEXP_free(nval);
		pid_ent = new_pid_ent;
	}
	ret = read_environment(pid_ent, name_ent, ctx);
#endif

fail:
    SEXP_free(pid_ent);
	SEXP_free(name_ent);

	return ret;
}
