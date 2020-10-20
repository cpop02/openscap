//
// Created by Cristian Pop on 20/10/2020.
//

#ifndef OVAL_PROBE_EXEC_H
#define OVAL_PROBE_EXEC_H

#include <oval_types.h>
#include <oval_probe_session.h>
#include <external_probe_executor.h>

#include "oval_definitions_impl.h"

int oval_probe_exec_sys_handler(oval_probe_session_t *sess, oval_subtype_t type, struct oval_sysinfo **object);
int oval_probe_exec_ext_handler(oval_probe_session_t *sess, oval_subtype_t type, struct oval_syschar *object);

#endif //OVAL_PROBE_EXEC_H
