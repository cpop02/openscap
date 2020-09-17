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

#include "oval_definitions.h"
#include "oval_external_probe.h"
#include "oval_types.h"
#include "sexp-manip.h"
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "common/debug_priv.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "_seap.h"
#include "environmentvariable_probe.h"
#include "probe-api.h"
#include "probe/entcmp.h"

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
            dI("SORIN: ext_environmentvariable_probe: matched env_name=%s, value=%s", name, val);
            item = probe_item_create(OVAL_INDEPENDENT_ENVIRONMENT_VARIABLE, NULL, "name", OVAL_DATATYPE_SEXP, env_name, "value", OVAL_DATATYPE_SEXP,
                                     env_value, NULL);
            probe_item_collect(ctx, item);
        }
        SEXP_free(env_name);
        SEXP_free(env_value);
    })

    return err;
}

int ext_environmentvariable_probe_main(probe_ctx* ctx, void* arg) {
    SEXP_t* probe_in;
    SEXP_t* ent = NULL;
    // SEXP_t *entval = NULL;
    SEXP_t* oid = NULL;
    oval_external_probe_result_t* res = NULL;
    int err = PROBE_ENOVAL;
    oval_external_probe_eval_funcs_t* eval;

    probe_in = probe_ctx_getobject(ctx);
    ent = probe_obj_getent(probe_in, "name", 1);
    oid = probe_obj_getattrval(probe_in, "id");

    if (oid == NULL || ent == NULL) {
        goto cleanup;
    }

    // entval = probe_ent_getval(ent);
    // if (entval == NULL || !SEXP_stringp(entval)) {
    //     SEXP_free(oid);
    //     SEXP_free(ent);
    //     return PROBE_ENOVAL;
    // }

    eval = probe_get_external_probe_eval(ctx);
    if (eval != NULL) {
        char* id = SEXP_string_cstr(oid);
        res = eval->environmentvariable_probe(eval->probe_ctx, id);
        free(id);

        if (res == NULL) {
            goto cleanup;
        }

        err = oval_external_probe_result_get_status(res);
        if (err != 0)
            goto cleanup;

        err = extract_matching_env_keys(ent, ctx, oval_external_probe_result_get_fields(res));
    } else {
        err = PROBE_ENOVAL;
    }

cleanup:
    if (res != NULL)
        oval_external_probe_result_free(res);
    // if (entval != NULL)
    //     SEXP_free(entval);
    if (oid != NULL)
        SEXP_free(oid);
    if (ent != NULL)
        SEXP_free(ent);

    return err;
}
