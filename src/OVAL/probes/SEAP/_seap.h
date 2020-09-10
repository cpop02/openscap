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
 *      "Daniel Kopecek" <dkopecek@redhat.com>
 */

#pragma once
#ifndef _SEAP_H
#define _SEAP_H

#include "_seap-message.h"
#include "sch_queue.h"
#include "../../../common/util.h"
#include "_seap-types.h"

#ifndef EOPNOTSUPP
# define EOPNOTSUPP 1001
#endif

#ifndef ECANCELED
# define ECANCELED  1002
#endif

SEAP_CTX_t *SEAP_CTX_new(void);
void SEAP_CTX_init(SEAP_CTX_t *ctx);
void SEAP_CTX_free(SEAP_CTX_t *ctx);

int SEAP_connect(SEAP_CTX_t *ctx);
int SEAP_listen(SEAP_CTX_t *ctx, int sd, uint32_t maxcli);
int SEAP_accept(SEAP_CTX_t *ctx, int sd);

int SEAP_open(SEAP_CTX_t *ctx, const char *path, uint32_t flags);
SEXP_t *SEAP_read(SEAP_CTX_t *ctx, int sd);
int SEAP_write(SEAP_CTX_t *ctx, int sd, SEXP_t *sexp);
int SEAP_close(SEAP_CTX_t *ctx, int sd);

int SEAP_openfd(SEAP_CTX_t *ctx, int fd, uint32_t flags);
int SEAP_openfd2(SEAP_CTX_t *ctx, int ifd, int ofd, uint32_t flags);
int SEAP_add_probe(SEAP_CTX_t *ctx, sch_queuedata_t *data);

int SEAP_recvsexp(SEAP_CTX_t *ctx, int sd, SEXP_t **sexp);
int SEAP_recvmsg(SEAP_CTX_t *ctx, int sd, SEAP_msg_t **seap_msg);

int SEAP_sendsexp(SEAP_CTX_t *ctx, int sd, SEXP_t *sexp);
int SEAP_sendmsg(SEAP_CTX_t *ctx, int sd, SEAP_msg_t *seap_msg);

int SEAP_reply(SEAP_CTX_t *ctx, int sd, SEAP_msg_t *rep_msg, SEAP_msg_t *req_msg);

int SEAP_senderr(SEAP_CTX_t *ctx, int sd, SEAP_err_t *err);
int SEAP_recverr(SEAP_CTX_t *ctx, int sd, SEAP_err_t **err);
int SEAP_recverr_byid(SEAP_CTX_t *ctx, int sd, SEAP_err_t **err, SEAP_msgid_t id);

int SEAP_replyerr(SEAP_CTX_t *ctx, int sd, SEAP_msg_t *rep_msg, uint32_t e);

int __SEAP_recvmsg_process_cmd (SEAP_CTX_t *ctx, int sd, SEAP_cmd_t *cmd);

#ifdef EXTERNAL_PROBE_COLLECT
void SEAP_CTX_set_external_probe_eval_fn(SEAP_CTX_t *ctx, oval_external_probe_eval_fn ext_probe_eval_fn);
#endif

#endif /* _SEAP_H */
