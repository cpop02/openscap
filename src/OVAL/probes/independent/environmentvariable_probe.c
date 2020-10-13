/**
 * @file   environmentvariable_probe.c
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
            OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE, NULL,
            "name", OVAL_DATATYPE_SEXP, var_name,
            "value", OVAL_DATATYPE_SEXP, var_val,
            NULL);
    if(var == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    // no need to free the item because probe_item_collect frees it (in almost all cases)
    ret = probe_item_collect(ctx, var);

fail:
cleanup:
    SEXP_free(var_val);
    SEXP_free(var_name);

    return ret;
}

static int collect_variables(SEXP_t *un_ent, probe_ctx *ctx, oval_external_probe_item_list_t *ext_items) {
    int ret = 0, ext_items_len;
    oval_external_probe_item_t *ext_item;
    const char *ext_item_value_name;
    oval_external_probe_item_value_t *ext_item_value_val;

    __attribute__nonnull__(ctx);
    __attribute__nonnull__(ext_items);

    ext_items_len = oval_external_probe_item_list_get_length(ext_items);
    if(ext_items_len != 1) {
        ret = ext_items_len < 1 ? PROBE_ERANGE : PROBE_EINVAL;
        goto fail;
    }
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

fail:
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
