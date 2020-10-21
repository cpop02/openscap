/**
 * @file oval_probe_session.h
 * @brief OVAL probe session API private header
 * @author "Daniel Kopecek" <dkopecek@redhat.com>
 *
 * @addtogroup PROBESESSION
 * @{
 */
/*
 * Copyright 2010 Red Hat Inc., Durham, North Carolina.
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
 *      "Daniel Kopecek" <dkopecek@redhat.com>
 */
#ifndef _OVAL_PROBE_SESSION
#define _OVAL_PROBE_SESSION

#ifdef OVAL_EXTERNAL_PROBES_ENABLED
#include <external_probe_executor.h>
#endif
#include "public/oval_probe_session.h"
#include "_oval_probe_handler.h"
#include "oval_probe_ext.h"

/** OVAL probe session structure.
 * This structure holds all the library side state information associated with
 * a probe session. A probe session is bound to a system characteristics model
 * during the initialization and all evaluations are done relative to this model.
 */
struct oval_probe_session {
#ifdef OVAL_EXTERNAL_PROBES_ENABLED
    oval_evaluation_t *eval;
    external_probe_executor_t *exec;
#endif
        oval_phtbl_t *ph;   /**< probe handler table */
        oval_pext_t  *pext; /**< state information associated with external probes */
        struct oval_syschar_model *sys_model; /**< system characteristics model */
        char         *dir;  /**< probe session directory */
        uint32_t      flg;  /**< probe session flags */
};

#endif /* _OVAL_PROBE_SESSION */

/// @}
