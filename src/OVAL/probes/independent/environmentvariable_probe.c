/**
 * @file   environment_probe.c
 * @brief  environmentvariable probe
 * @author "Petr Lautrbach" <plautrba@redhat.com>
 *
 *  This probe is able to process a environmentvariable_object as defined in OVAL 5.8.
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
 * environmentvariable probe:
 *
 * name
 * value
 */

#include "probe-common.h"
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "common/debug_priv.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "_seap.h"
#include "probe-api.h"
#include "probe/entcmp.h"
#include "environmentvariable_probe.h"

#ifndef EXTERNAL_PROBE_COLLECT

extern char **environ;

static int read_environment(SEXP_t *un_ent, probe_ctx *ctx) {
	int err = PROBE_ENOVAL;
	char **env;
	size_t env_name_size;
	SEXP_t *env_name, *env_value, *item;

	for(env = environ; *env != 0; env++) {
		env_name_size = strchr(*env, '=') - *env; 
		env_name = SEXP_string_new(*env, env_name_size);
		env_value = SEXP_string_newf("%s", *env + env_name_size + 1);
		if(probe_entobj_cmp(un_ent, env_name) == OVAL_RESULT_TRUE) {
			item = probe_item_create(
				OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE, NULL,
				"name",  OVAL_DATATYPE_SEXP, env_name,
				"value", OVAL_DATATYPE_SEXP, env_value,
			      NULL);
			probe_item_collect(ctx, item);
			err = 0;
		}
		SEXP_free(env_name);
		SEXP_free(env_value);
	}

	return err;
}

#else // EXTERNAL_PROBE_COLLECT

static inline int collect_environment_variable(SEXP_t *un_ent, probe_ctx *ctx, const char *ext_var_name, oval_external_probe_item_value_t *ext_var_val) {
    int ret = 0;
    const char *ext_var_val_cstr;
    oval_datatype_t ext_var_datatype;
    SEXP_t *var_name = NULL, *var_val = NULL, *item;

    ext_var_datatype = oval_external_probe_item_value_get_datatype(ext_var_val);
    if(ext_var_datatype != OVAL_DATATYPE_STRING) {
        ret = PROBE_EINVAL;
        goto fail;
    }
    ext_var_val_cstr = oval_external_probe_item_value_get_string(ext_var_val);
    if(ext_var_val_cstr == NULL) {
        ret = PROBE_EINVAL;
        goto fail;
    }
    var_name = SEXP_string_newf("%s", ext_var_name);
    if(probe_entobj_cmp(un_ent, var_name) != OVAL_RESULT_TRUE) {
        goto cleanup;
    }
    var_val = SEXP_string_newf("%s", ext_var_val_cstr);
    item = probe_item_create(
            OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE, NULL,
            "name", OVAL_DATATYPE_SEXP, var_name,
            "value", OVAL_DATATYPE_SEXP, var_val,
            NULL);
    if(item == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    // no need to free the item because probe_item_collect frees it (in almost all cases)
    ret = probe_item_collect(ctx, item);

fail:
cleanup:
    SEXP_free(var_val);
    SEXP_free(var_name);

    return ret;
}

static int collect_environment_variables(SEXP_t *un_ent, probe_ctx *ctx, oval_external_probe_item_t *ext_env) {
    int ret = 0;
    const char *ext_env_var_name;
    oval_external_probe_item_value_t *ext_env_var_val;

    __attribute__nonnull__(ctx);
    __attribute__nonnull__(ext_env);

    OVAL_EXTERNAL_PROBE_ITEM_FOREACH(ext_env, ext_env_var_name, ext_env_var_val, {
        ret = collect_environment_variable(un_ent, ctx, ext_env_var_name, ext_env_var_val);
        if(ret != 0) {
            break;
        }
    })

    return ret;
}

static int read_environment(SEXP_t *un_ent, probe_ctx *ctx) {
    int ret;
    oval_external_probe_eval_funcs_t *eval;
    oval_external_probe_item_t *ext_env = NULL;

    __attribute__nonnull__(ctx);

    eval = probe_get_external_probe_eval(ctx);
    if(eval == NULL || eval->environment_probe == NULL) {
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    ext_env = eval->environment_probe(eval->probe_ctx);
    if(ext_env == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ret = collect_environment_variables(un_ent, ctx, ext_env);

fail:
    oval_external_probe_item_free(ext_env);

    return ret;
}

#endif // EXTERNAL_PROBE_COLLECT

int environmentvariable_probe_main(probe_ctx *ctx, void *arg) {
	int ret;
    SEXP_t *probe_in, *un_ent = NULL;

	probe_in  = probe_ctx_getobject(ctx);
    un_ent = probe_obj_getent(probe_in, "name", 1);
	if(un_ent == NULL) {
	    ret = PROBE_ENOVAL;
	    goto fail;
	}
	ret = read_environment(un_ent, ctx);

fail:
    SEXP_free(un_ent);

	return ret;
}
