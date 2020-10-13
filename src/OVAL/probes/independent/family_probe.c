/**
 * @file   family_probe.c
 * @brief  family probe
 * @author "Tomas Heinrich" <theinric@redhat.com>
 * @author "Daniel Kopecek" <dkopecek@redhat.com>
 *
 * 2010/06/13 dkopecek@redhat.com
 *  This probe is able to process a family_object as defined in OVAL 5.4 and 5.5.
 *
 */

/*
 * Copyright 2009 Red Hat Inc., Durham, North Carolina.
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
 *      "Tomas Heinrich" <theinric@redhat.com>
 *      "Daniel Kopecek" <dkopecek@redhat.com>
 */

/*
 * family probe:
 *
 *  family_object
 *
 *  family_item
 *    attrs
 *      id
 *      status_enum status
 *    [0..1] string family
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "_seap.h"
#include <string.h>
#include <probe-api.h>
#include <probe/probe.h>
#include <probe/option.h>
#include "oval_external_probe.h"
#include "family_probe.h"
#include "probes/probe/probe.h"

#ifndef EXTERNAL_PROBE_COLLECT

int family_probe_offline_mode_supported() {
	/* We say that the probe supports all offline modes, but in fact
	   it always returns the same hardocoded string. */
	return PROBE_OFFLINE_ALL;
}

int family_probe_main(probe_ctx *ctx, void *arg) {
	SEXP_t *item;

        (void)arg;

	const char *family =
#if defined(OS_WINDOWS)
        "windows";
#elif defined(OS_OSX)
        "macos";
#elif defined(OSCAP_UNIX)
        "unix";
#elif defined(CISCO_IOS) /* XXX: how to detect IOS? */
        "ios";
#else
        "error";
#endif

        item = probe_item_create(OVAL_INDEPENDENT_FAMILY, NULL,
                                 "family", OVAL_DATATYPE_STRING, family,
                                 NULL);

        probe_item_collect(ctx, item);

	return (0);
}

#else

static int collect_family(probe_ctx *ctx, char *ext_family) {
    int ret;
    SEXP_t *item;

    __attribute__nonnull__(ctx);
    __attribute__nonnull__(ext_family);

    item = probe_item_create(
            OVAL_INDEPENDENT_FAMILY, NULL,
            "family", OVAL_DATATYPE_STRING, ext_family,
            NULL);
    if(item == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    // no need to free the item because probe_item_collect frees it (in almost all cases)
    ret = probe_item_collect(ctx, item);

fail:
    return ret;
}

int family_probe_offline_mode_supported() {
    return PROBE_OFFLINE_NONE;
}

int family_probe_main(probe_ctx *ctx, void *arg) {
    int ret;
    char *ext_family = NULL;
    oval_external_probe_eval_funcs_t *eval;

    __attribute__nonnull__(ctx);

    eval = probe_get_external_probe_eval(ctx);
    if(eval == NULL || eval->family_probe == NULL) {
        ret = PROBE_EOPNOTSUPP;
        goto fail;
    }
    ext_family = eval->family_probe(eval->probe_ctx);
    if(ext_family == NULL) {
        ret = PROBE_EUNKNOWN;
        goto fail;
    }
    ret = collect_family(ctx, ext_family);

fail:
    free(ext_family);

    return ret;
}

#endif
