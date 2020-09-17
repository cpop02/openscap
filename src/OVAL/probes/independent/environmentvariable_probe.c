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

static int read_environment(SEXP_t *un_ent, probe_ctx *ctx)
{
	int err = PROBE_ENOVAL;
	char **env;
	size_t env_name_size;
	SEXP_t *env_name, *env_value, *item;

	for (env = environ; *env != 0; env++) {
		env_name_size = strchr(*env, '=') - *env; 
		env_name = SEXP_string_new(*env, env_name_size);
		env_value = SEXP_string_newf("%s", *env + env_name_size + 1);
		if (probe_entobj_cmp(un_ent, env_name) == OVAL_RESULT_TRUE) {
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

static int extract_matching_env_keys(SEXP_t* un_ent, probe_ctx* ctx, oval_external_probe_value_map_t* env_vals) {
    int err = 0;
    SEXP_t *env_name, *env_value, *item;

    if (env_vals == NULL)
        return 0;

    const char* name;
    oval_external_probe_value_t* val;
    OVAL_EXTERNAL_PROBE_VALUE_MAP_FOREACH(env_vals, name, val, {
        if (oval_external_probe_value_get_datatype(val) != OVAL_DATATYPE_STRING) {
            err = PROBE_EINVAL;
            break;
        }

        env_name = SEXP_string_newf("%s", name);
        env_value = SEXP_string_newf("%s", oval_external_probe_value_get_string(val));
        if (probe_entobj_cmp(un_ent, env_name) == OVAL_RESULT_TRUE) {
            dI("EXTPROBE: environmentvariable: matched env_name=%s, value=%s", name, val);
            item = probe_item_create(OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE, NULL, "name", OVAL_DATATYPE_SEXP, env_name, "value", OVAL_DATATYPE_SEXP,
                                     env_value, NULL);
            probe_item_collect(ctx, item);
        }
        SEXP_free(env_name);
        SEXP_free(env_value);
    })

    return err;
}

static int read_environment(SEXP_t *un_ent, probe_ctx *ctx)
{
    oval_external_probe_eval_funcs_t* eval = probe_get_external_probe_eval(ctx);
    if (eval == NULL || eval->environmentvariable_probe == NULL)
		return PROBE_EOPNOTSUPP;

	SEXP_t *probe_in = probe_ctx_getobject(ctx);
    SEXP_t* oid = NULL;
    oval_external_probe_result_t* res = NULL;
	int err = PROBE_ENOVAL;

    oid = probe_obj_getattrval(probe_in, "id");
	if (oid == NULL)
		goto cleanup;

	char *id = SEXP_string_cstr(oid);
	res = eval->environmentvariable_probe(eval->probe_ctx, id);
	free(id);

	if (res == NULL) {
		goto cleanup;
	}

	err = oval_external_probe_result_get_status(res);
	if (err != 0)
		goto cleanup;

	err = extract_matching_env_keys(un_ent, ctx, oval_external_probe_result_get_fields(res));

cleanup:
	oval_external_probe_result_free(res);
	SEXP_free(oid);

	return err;
}

#endif // EXTERNAL_PROBE_COLLECT

int environmentvariable_probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t *probe_in, *ent;
	int res;

	probe_in  = probe_ctx_getobject(ctx);
	ent = probe_obj_getent(probe_in, "name", 1);

	if (ent == NULL) {
		return PROBE_ENOVAL;
	}

	res = read_environment(ent, ctx);
	SEXP_free(ent);

	return res;
}
