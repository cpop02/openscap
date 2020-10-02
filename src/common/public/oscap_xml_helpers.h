/*
 * Copyright 2015 Red Hat Inc., Durham, North Carolina.
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
 *       Jan Černý <jcerny@redhat.com>
 */

#ifndef OSCAP_XML_HELPERS_H_
#define OSCAP_XML_HELPERS_H_

#include <libxml/tree.h>
#include "oscap_export.h"

/**
 * Save XML Document to the file of the given filename.
 * @param filename path to the file
 * @param doc the XML document content
 * @return 1 on success, -1 on failure (oscap_seterr is set appropriatly).
 */
OSCAP_API int oscap_xml_save_filename(const char *filename, xmlDocPtr doc);

/**
 * Save XML Document to the file of the given filename and dispose the document afterwards.
 * @param filename path to the file
 * @param doc the XML document content
 * @return 1 on success, -1 on failure (oscap_seterr is set appropriatly).
 */
OSCAP_API int oscap_xml_save_filename_free(const char *filename, xmlDocPtr doc);

#endif
