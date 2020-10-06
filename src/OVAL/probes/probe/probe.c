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

#include <sexp.h>
#include "probe-api.h"
#include "probe.h"

SEXP_t *probe_ctx_getobject(probe_ctx *ctx)
{
        return (ctx->probe_in);
}

SEXP_t *probe_ctx_getresult(probe_ctx *ctx)
{
        return (ctx->probe_out);
}

#ifdef EXTERNAL_PROBE_COLLECT
oval_external_probe_eval_funcs_t *probe_get_external_probe_eval(probe_ctx *ctx) {
        return ctx->ext_probe_eval;
}
#endif
