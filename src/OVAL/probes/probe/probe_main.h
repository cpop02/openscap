/*
 * Copyright 2018 Red Hat Inc., Durham, North Carolina.
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
 *      "Jan Černý" <jcerny@redhat.com>
 */

#ifndef OPENSCAP_PROBE_MAIN_H
#define OPENSCAP_PROBE_MAIN_H

struct probe_common_main_argument {
	oval_subtype_t subtype;
	sch_queuedata_t *queuedata;
#ifdef EXTERNAL_PROBE_COLLECT
    oval_external_probe_eval_funcs_t *ext_probe_eval;
#endif
};
void *probe_common_main(void *);

#endif /* OPENSCAP_PROBE_MAIN_H */
