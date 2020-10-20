//
// Created by Cristian Pop on 20/10/2020.
//

#include <oval_sexp.h>
#include <debug_priv.h>

#include "oval_probe_exec.h"
#include "_oval_probe_session.h"

static SEXP_t* oval_probe_sys_query_create();
static int oval_probe_sexp_to_sysinfo(SEXP_t *sdata, struct oval_syschar_model *model, struct oval_sysinfo **out);

int oval_probe_exec_sys_handler(oval_probe_session_t *sess, oval_subtype_t type, struct oval_sysinfo **object) {
    int ret;
    SEXP_t *query, *out = NULL;
    external_probe_request_t req;

    query = oval_probe_sys_query_create();
    if(query == NULL) {
        ret = 1;
        goto fail;
    }

    req.probe_in = query;
    req.probe_type = type;

    ret = external_probe_executor_exec(sess->exec, &req, &out);
    if(ret != 0) {
        goto fail;
    }
    ret = oval_probe_sexp_to_sysinfo(out, sess->sys_model, object);

fail:
    SEXP_free(out);
    SEXP_free(query);

    return ret;
}

int oval_probe_exec_ext_handler(oval_probe_session_t *sess, oval_subtype_t type, struct oval_syschar *syschar) {
    int ret;
    struct oval_object *object;
    external_probe_request_t req;
    SEXP_t *query = NULL, *out = NULL;

    object = oval_syschar_get_object(syschar);
    ret = oval_object_to_sexp(sess, oval_subtype_to_str(oval_object_get_subtype(object)), syschar, &query);
    if(ret != 0) {
        goto fail;
    }

    req.probe_in = query;
    req.probe_type = type;

    ret = external_probe_executor_exec(sess->exec, &req, &out);
    if(ret != 0) {
        goto fail;
    }
    ret = oval_sexp_to_sysch(out, syschar);

fail:
    SEXP_free(out);
    SEXP_free(query);

    return ret;
}

static SEXP_t* oval_probe_sys_query_create() {
    SEXP_t *r0, *r1, *r2, *r3, *query;

    r0 = SEXP_list_new (r1 = SEXP_string_newf ("%s", "sysinfo_object"),
                        r2 = SEXP_string_newf (":%s", "id"),
                        r3 = SEXP_string_newf ("sysinfo:0"),
                        NULL);
    SEXP_free(r1);
    SEXP_free(r2);
    SEXP_free(r3);
    query = SEXP_list_new (r0, NULL);
    SEXP_free (r0);

    return query;
}

static int oval_probe_sexp_to_sysinfo(SEXP_t *sdata, struct oval_syschar_model *model, struct oval_sysinfo **out) {
    struct oval_sysinfo *sysinf;
    struct oval_sysint *ife;
    SEXP_t *s_sinf, *ent, *r1;

    r1 = probe_cobj_get_items(sdata);
    s_sinf = SEXP_list_first(r1);
    SEXP_free(r1);

    if (s_sinf == NULL)
        return (-1);

    sysinf = oval_sysinfo_new(model);

#define SYSINF_EXT(obj, name, sysinf, fail)                             \
        do {                                                            \
                SEXP_t *val;                                            \
                char    buf[128+1];                                     \
                                                                        \
                val = probe_obj_getentval (obj, #name, 1);     \
                                                                        \
                if (val == NULL) {                                      \
                        dD("No entity or value: %s", #name); \
                        goto fail;                                      \
                }                                                       \
                                                                        \
                if (SEXP_string_cstr_r (val, buf, sizeof buf) >= sizeof buf) { \
                        dD("Value too large: %s", #name);    \
                        SEXP_free (val);                                \
                        goto fail;                                      \
                }                                                       \
                                                                        \
                oval_sysinfo_set_##name (sysinf, buf);                  \
                SEXP_free (val);                                        \
        } while (0)

    SYSINF_EXT(s_sinf, os_name, sysinf, fail_gen);
    SYSINF_EXT(s_sinf, os_version, sysinf, fail_gen);
    SYSINF_EXT(s_sinf, os_architecture, sysinf, fail_gen);
    SYSINF_EXT(s_sinf, primary_host_name, sysinf, fail_gen);

    {
        uint32_t n;

        for (n = 1; (ent = probe_obj_getent(s_sinf, "interface", n)) != NULL; ++n) {
            ife = oval_sysint_new(model);

#define SYSINF_IEXT(ent, name, sysint, fail)                            \
                        do {                                            \
                                SEXP_t *val;                            \
                                char    buf[128+1];                     \
                                                                        \
                                val = probe_ent_getattrval (ent, #name); \
                                                                        \
                                if (val == NULL) {                      \
                                        dD("No value: %s", #name); \
                                        goto fail;                      \
                                }                                       \
                                                                        \
                                if (SEXP_string_cstr_r (val, buf, sizeof buf) >= sizeof buf) { \
                                        dD("Value too large: %s", #name); \
                                        SEXP_free (val);                \
                                        goto fail;                      \
                                }                                       \
                                                                        \
                                oval_sysint_set_##name (sysint, buf);   \
                                SEXP_free (val);                        \
                                                                        \
                        } while (0)

            SYSINF_IEXT(ent, ip_address, ife, fail_int);
            SYSINF_IEXT(ent, mac_address, ife, fail_int);
            SYSINF_IEXT(ent, name, ife, fail_int);

            oval_sysinfo_add_interface(sysinf, ife);
            oval_sysint_free(ife);
            SEXP_free(ent);
        }
    }

    SEXP_free(s_sinf);

    *out = sysinf;

    return (0);

fail_int:
    SEXP_free(ent);
    oval_sysint_free(ife);
fail_gen:
    SEXP_free(s_sinf);
    oval_sysinfo_free(sysinf);

    return (-1);
}

