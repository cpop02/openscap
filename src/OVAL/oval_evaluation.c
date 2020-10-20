//
// Created by Cristian Pop on 19/10/2020.
//

#include <stdlib.h>

#include <oval_agent_api.h>
#include <oval_definitions.h>
#include <oval_evaluation.h>
#include <oscap_helpers.h>
#include <oscap_source.h>
#include <debug_priv.h>

static const char *oscap_productname = "cpe:/a:open-scap:oscap";

struct oval_evaluation {
    void *ext_probe_ctx;
    oval_external_probe_function_t ext_probe_func;
};

struct oval_evaluator {
    struct oscap_source *source;
    struct {
        struct oscap_source *definitions;
    } oval;
    struct oval_definition_model *def_model;
};

static int oval_evaluator_load(oval_evaluator_t *evaluator);
static int oval_evaluator_load_definitions(oval_evaluator_t *evaluator);

static oval_agent_session_t *oval_evaluator_new_agent_session(oval_evaluator_t *evaluator, oval_evaluation_t *eval);

oval_evaluation_t* oval_evaluation_new(void *ext_probe_ctx, oval_external_probe_function_t ext_probe_func) {
    oval_evaluation_t *eval;

    eval = (oval_evaluation_t*)malloc(sizeof(oval_evaluation_t));
    if(eval == NULL) {
        goto fail;
    }
    eval->ext_probe_ctx = ext_probe_ctx;
    eval->ext_probe_func = ext_probe_func;

    goto cleanup;

fail:
    oval_evaluation_free(eval);
    eval = NULL;

cleanup:
    return eval;
}

void oval_evaluation_free(oval_evaluation_t *eval) {
    free(eval);
}

void* oval_evaluation_get_external_probe_ctx(oval_evaluation_t *eval) {
    __attribute__nonnull__(eval);

    return eval->ext_probe_ctx;
}

oval_external_probe_function_t oval_evaluation_get_external_probe_func(oval_evaluation_t *eval) {
    __attribute__nonnull__(eval);

    return eval->ext_probe_func;
}

oval_evaluator_t* oval_evaluator_new(const char *filename) {
    int ret;
    oval_evaluator_t *evaluator;

    __attribute__nonnull__(filename);

    evaluator = (oval_evaluator_t*)malloc(sizeof(oval_evaluator_t));
    if(evaluator == NULL) {
        goto fail;
    }
    evaluator->source = oscap_source_new_from_file(filename);
    ret = oval_evaluator_load(evaluator);
    if(ret != 0) {
        goto fail;
    }

    goto cleanup;

fail:
    oval_evaluator_free(evaluator);
    evaluator = NULL;

cleanup:
    return evaluator;
}

void oval_evaluator_free(oval_evaluator_t *evaluator) {
    if(evaluator != NULL) {
        oscap_source_free(evaluator->source);
    }
    free(evaluator);
}


int oval_evaluator_do(oval_evaluator_t *evaluator, oval_evaluation_t *eval) {
    int ret;
    oval_agent_session_t *session;

    __attribute__nonnull__(evaluator);
    __attribute__nonnull__(eval);

    session = oval_evaluator_new_agent_session(evaluator, eval);
    if(session == NULL) {
        ret = 1;
        goto fail;
    }
    ret = oval_agent_eval_system(session, NULL, NULL);
    if(ret != 0) {
        goto fail;
    }
    // TODO: Collect results from results model

fail:
    oval_agent_destroy_session(session);

    return ret;
}

static int oval_evaluator_load(oval_evaluator_t *evaluator) {
    __attribute__nonnull__(evaluator);

    return oval_evaluator_load_definitions(evaluator);
}

static int oval_evaluator_load_definitions(oval_evaluator_t *evaluator) {
    int ret = 0;
    oscap_document_type_t type;

    __attribute__nonnull__(evaluator);
    __attribute__nonnull__(evaluator->source);

    type = oscap_source_get_scap_type(evaluator->source);
    if(type != OSCAP_DOCUMENT_OVAL_DEFINITIONS) {
        ret = 1;
        goto fail;
    }
    evaluator->oval.definitions = evaluator->source;
    evaluator->def_model = oval_definition_model_import_source(evaluator->oval.definitions);
    if(evaluator->def_model == NULL) {
        ret = 1;
    }

fail:
    return ret;
}

static oval_agent_session_t *oval_evaluator_new_agent_session(oval_evaluator_t *evaluator, oval_evaluation_t *eval) {
    char *path = NULL, *base_name = NULL;
    oval_agent_session_t *session = NULL;

    path = oscap_strdup(oscap_source_readable_origin(evaluator->oval.definitions));
    if(path == NULL) {
        goto fail;
    }
    base_name = oscap_basename(path);
    if(base_name == NULL) {
        goto fail;
    }
    session = oval_agent_new_session(evaluator->def_model, base_name, eval);
    if(session == NULL) {
        goto fail;
    }
    oval_agent_set_product_name(session, (char *)oscap_productname);

fail:
    free(base_name);
    free(path);

    return session;
}



