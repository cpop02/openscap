/**
 * @file oval_external_probe_item_list.c
 * \brief Open Vulnerability and Assessment Language
 *
 * See more details at http://oval.mitre.org/
 */

#include "list.h"
#include "oval_definitions.h"
#include "oval_external_probe.h"
#include "oval_types.h"

struct oval_external_probe_item_list {
    struct oscap_list* items;
};

oval_external_probe_item_list_t* oval_external_probe_item_list_new(oval_external_probe_item_t* item, ...) {
    va_list ap;
    oval_external_probe_item_list_t* list;

    va_start(ap, item);

    list = (oval_external_probe_item_list_t*)malloc(sizeof(oval_external_probe_item_list_t));
    if(list == NULL) {
        goto fail;
    }
    list->items = oscap_list_new();
    if(list->items == NULL) {
        goto fail;
    }
    while(item != NULL) {
        oscap_list_push(list->items, item);
        item = va_arg(ap, oval_external_probe_item_t*);
    }

    goto cleanup;

fail:
    oval_external_probe_item_list_free(list);
    list = NULL;

cleanup:
    va_end(ap);

    return list;
}

void oval_external_probe_item_list_free(oval_external_probe_item_list_t* list) {
    if(list != NULL) {
        oscap_list_free(list->items, (oscap_destruct_func)oval_external_probe_item_free);
        list->items = NULL;
    }
    free(list);
}

void oval_external_probe_item_list_push(oval_external_probe_item_list_t* list, oval_external_probe_item_t* item) {
    __attribute__nonnull__(list);
    __attribute__nonnull__(list->items);
    __attribute__nonnull__(item);
    oscap_list_push(list->items, item);
}

struct oval_external_probe_item_list_iterator* oval_external_probe_item_list_iterator_new(oval_external_probe_item_list_t* list) {
    __attribute__nonnull__(list);
    __attribute__nonnull__(list->items);
    return (struct oval_external_probe_item_list_iterator*)oscap_iterator_new(list->items);
}

bool oval_external_probe_item_list_iterator_has_more_items(struct oval_external_probe_item_list_iterator* it) {
    __attribute__nonnull__(it);
    return oscap_iterator_has_more((struct oscap_iterator*)it);
}

oval_external_probe_item_t* oval_external_probe_item_list_iterator_next_item(struct oval_external_probe_item_list_iterator* it) {
    __attribute__nonnull__(it);
    return (oval_external_probe_item_t*)oscap_iterator_next((struct oscap_iterator*)it);
}

void oval_external_probe_item_list_iterator_free(struct oval_external_probe_item_list_iterator* it) {
    oscap_iterator_free((struct oscap_iterator*)it);
}
