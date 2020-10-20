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
#include <debug_priv.h>
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

int probe_varref_create_ctx(const SEXP_t *probe_in, SEXP_t *varrefs, struct probe_varref_ctx **octx)
{
    unsigned int i, ent_cnt, val_cnt;
    SEXP_t *ent_name, *ent, *varref, *val_lst;
    SEXP_t *r0, *r1, *r2, *r3;
    SEXP_t *vid, *vidx_name, *vidx_val;

    /* varref_cnt = SEXP_number_getu_32(r0 = SEXP_list_nth(varrefs, 2)); */
    ent_cnt = SEXP_number_getu_32(r1 = SEXP_list_nth(varrefs, 3));
    SEXP_free(r1);

    struct probe_varref_ctx *ctx = malloc(sizeof(struct probe_varref_ctx));
    ctx->pi2 = SEXP_softref((SEXP_t *)probe_in);
    ctx->ent_cnt = ent_cnt;
    ctx->ent_lst = malloc(ent_cnt * sizeof (ctx->ent_lst[0]));

    vidx_name = SEXP_string_new(":val_idx", 8);
    vidx_val = SEXP_number_newu(0);

    /* entities that use var_refs are stored at the begining of an object */
    for (i = 0; i < ent_cnt; ++i) {
        /*
         * add variable values to entities and insert
         * them into the new probe_in object
         */
        r0 = SEXP_list_nth(ctx->pi2, i + 2);
        vid = probe_ent_getattrval(r0, "var_ref");
        r1 = SEXP_list_first(r0);
        r2 = SEXP_list_first(r1);

        r3 = SEXP_list_new(r2, vidx_name, vidx_val, NULL);
        SEXP_free(r0);
        r0 = SEXP_list_rest(r1);
        ent_name = SEXP_list_join(r3, r0);
        SEXP_free(r0);
        SEXP_free(r1);
        SEXP_free(r2);
        SEXP_free(r3);

        SEXP_sublist_foreach(varref, varrefs, 4, SEXP_LIST_END) {
            r0 = SEXP_list_first(varref);
            if (!SEXP_string_cmp(vid, r0)) {
                SEXP_free(r0);
                break;
            }
            SEXP_free(r0);
        }

        if (varref == NULL) {
            char *var_id = SEXP_string_cstr(vid);
            dE("Unexpected error: variable id \"%s\" not found in varrefs.", var_id);
            free(var_id);
            SEXP_free(vid);
            SEXP_free(ent_name);
            SEXP_free(vidx_name);
            SEXP_free(vidx_val);
            probe_varref_destroy_ctx(ctx);
            return -1;
        }

        SEXP_free(vid);

        r0 = SEXP_list_nth(varref, 2);
        val_cnt = SEXP_number_getu_32(r0);
        val_lst = SEXP_list_nth(varref, 3);
        SEXP_free(varref);
        SEXP_free(r0);

        ent = SEXP_list_new(ent_name, val_lst, NULL);
        SEXP_free(ent_name);
        SEXP_free(val_lst);

        r0 = SEXP_list_replace(ctx->pi2, i + 2, ent);
        SEXP_free(r0);
        SEXP_free(ent);

        r0 = SEXP_listref_nth(ctx->pi2, i + 2);
        ctx->ent_lst[i].ent_name_sref = SEXP_listref_first(r0);
        SEXP_free(r0);
        ctx->ent_lst[i].val_cnt = val_cnt;
        ctx->ent_lst[i].next_val_idx = 0;
    }

    SEXP_free(vidx_name);
    SEXP_free(vidx_val);

    *octx = ctx;

    return 0;
}

void probe_varref_destroy_ctx(struct probe_varref_ctx *ctx)
{
    struct probe_varref_ctx_ent *ent, *ent_end;

    SEXP_free(ctx->pi2);

    ent = ctx->ent_lst;
    ent_end = ent + ctx->ent_cnt;

    while (ent != ent_end) {
        SEXP_free(ent->ent_name_sref);
        ++ent;
    }

    free(ctx->ent_lst);
    free(ctx);
}

int probe_varref_iterate_ctx(struct probe_varref_ctx *ctx)
{
    unsigned int val_cnt, *next_val_idx;
    SEXP_t *ent_name_sref;
    SEXP_t *r0, *r1, *r2;
    struct probe_varref_ctx_ent *ent, *ent_end;

    ent = ctx->ent_lst;
    ent_end = ent + ctx->ent_cnt;
    val_cnt = ent->val_cnt;
    next_val_idx = &ent->next_val_idx;
    ent_name_sref = ent->ent_name_sref;

    r0 = SEXP_number_newu(0);

    while (++(*next_val_idx) >= val_cnt) {
        if (++ent == ent_end) {
            SEXP_free(r0);
            return 0;
        }

        *next_val_idx = 0;
        r1 = SEXP_list_replace(ent_name_sref, 3, r0);
        SEXP_free(r1);

        val_cnt = ent->val_cnt;
        next_val_idx = &ent->next_val_idx;
        ent_name_sref = ent->ent_name_sref;
    }
    r1 = SEXP_list_replace(ent_name_sref, 3, r2 = SEXP_number_newu(*next_val_idx));

    SEXP_free(r0);
    SEXP_free(r1);
    SEXP_free(r2);

    return 1;
}

SEXP_t *probe_set_combine(SEXP_t *cobj0, SEXP_t *cobj1, oval_setobject_operation_t op)
{
    SEXP_t *set0, *set1, *res_cobj, *cobj0_mask, *cobj1_mask, *res_mask;
    register int cmp;
    register SEXP_t *item0, *item1, *res;
    register SEXP_list_it *sit0, *sit1;
    oval_syschar_collection_flag_t res_flag;

    if (cobj0 == NULL)
        return SEXP_ref(cobj1);
    if (cobj1 == NULL)
        return SEXP_ref(cobj0);

    set0 = probe_cobj_get_items(cobj0);
    set1 = probe_cobj_get_items(cobj1);
    cobj0_mask = probe_cobj_get_mask(cobj0);
    cobj1_mask = probe_cobj_get_mask(cobj1);

    /* prepare storage for results */
    res = SEXP_list_new(NULL);
    res_flag = probe_cobj_combine_flags(probe_cobj_get_flag(cobj0),
                                        probe_cobj_get_flag(cobj1), op);
    res_mask = SEXP_list_join(cobj0_mask, cobj1_mask);

    /* prepare iterators & first items */
    sit0  = SEXP_list_it_new(set0);
    sit1  = SEXP_list_it_new(set1);
    item0 = SEXP_list_it_next(sit0);
    item1 = SEXP_list_it_next(sit1);

    /* perform the set operation */
    switch(op) {
        case OVAL_SET_OPERATION_UNION:
            while (item0 != NULL && item1 != NULL) {
                cmp = SEXP_refcmp(item0, item1);

                if (cmp < 0) {
                    SEXP_list_add(res, item0);
                    item0 = SEXP_list_it_next(sit0);
                } else if (cmp > 0) {
                    SEXP_list_add(res, item1);
                    item1 = SEXP_list_it_next(sit1);
                } else {
                    SEXP_list_add(res, item0);
                    item0 = SEXP_list_it_next(sit0);
                    item1 = SEXP_list_it_next(sit1);
                }
            }

            if (item0 != NULL) {
                do {
                    SEXP_list_add(res, item0);
                } while((item0 = SEXP_list_it_next(sit0)) != NULL);
            } else if (item1 != NULL) {
                do {
                    SEXP_list_add(res, item1);
                } while((item1 = SEXP_list_it_next(sit1)) != NULL);
            }

            break;
        case OVAL_SET_OPERATION_INTERSECTION:
            while (item0 != NULL && item1 != NULL) {
                cmp = SEXP_refcmp(item0, item1);

                if (cmp < 0)
                    item0 = SEXP_list_it_next(sit0);
                else if (cmp > 0)
                    item1 = SEXP_list_it_next(sit1);
                else {
                    SEXP_list_add(res, item0);
                    item0 = SEXP_list_it_next(sit0);
                    item1 = SEXP_list_it_next(sit1);
                }
            }

            break;
        case OVAL_SET_OPERATION_COMPLEMENT:
            while (item0 != NULL && item1 != NULL) {
                cmp = SEXP_refcmp(item0, item1);

                if (cmp < 0) {
                    SEXP_list_add(res, item0);
                    item0 = SEXP_list_it_next(sit0);
                } else if (cmp > 0) {
                    item1 = SEXP_list_it_next(sit1);
                } else {
                    item0 = SEXP_list_it_next(sit0);
                    item1 = SEXP_list_it_next(sit1);
                }
            }

            if (item0 != NULL) {
                do {
                    SEXP_list_add(res, item0);
                } while((item0 = SEXP_list_it_next(sit0)) != NULL);
            }

            break;
        default:
            dE("Unknown set operation: %d", op);
            abort();
    }

    SEXP_list_it_free(sit0);
    SEXP_list_it_free(sit1);

    /*
     * If the collected information is complete but all the items are
     * removed, the flag is set to SYSCHAR_FLAG_DOES_NOT_EXIST
     */
    if (res_flag == SYSCHAR_FLAG_COMPLETE && SEXP_list_length(res) == 0)
        res_flag = SYSCHAR_FLAG_DOES_NOT_EXIST;

    res_cobj = probe_cobj_new(res_flag, NULL, res, res_mask);

    SEXP_free(set0);
    SEXP_free(set1);
    SEXP_free(res);
    SEXP_free(res_mask);
    SEXP_free(cobj0_mask);
    SEXP_free(cobj1_mask);

    // todo: variables

    return (res_cobj);
}
