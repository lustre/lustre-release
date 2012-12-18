/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

/* Intramodule declarations for ptlrpc. */

#ifndef PTLRPC_INTERNAL_H
#define PTLRPC_INTERNAL_H

#include "../ldlm/ldlm_internal.h"

struct ldlm_namespace;
struct obd_import;
struct ldlm_res_id;
struct ptlrpc_request_set;
extern int test_req_buffer_pressure;

/* client.c */
void ptlrpc_init_xid(void);

/* events.c */
int ptlrpc_init_portals(void);
void ptlrpc_exit_portals(void);

void ptlrpc_request_handle_notconn(struct ptlrpc_request *);
void lustre_assert_wire_constants(void);
int ptlrpc_import_in_recovery(struct obd_import *imp);
int ptlrpc_set_import_discon(struct obd_import *imp, __u32 conn_cnt);
void ptlrpc_handle_failed_import(struct obd_import *imp);
int ptlrpc_replay_next(struct obd_import *imp, int *inflight);
void ptlrpc_initiate_recovery(struct obd_import *imp);

int lustre_unpack_req_ptlrpc_body(struct ptlrpc_request *req, int offset);
int lustre_unpack_rep_ptlrpc_body(struct ptlrpc_request *req, int offset);

#ifdef LPROCFS
void ptlrpc_lprocfs_register_service(struct proc_dir_entry *proc_entry,
                                     struct ptlrpc_service *svc);
void ptlrpc_lprocfs_unregister_service(struct ptlrpc_service *svc);
void ptlrpc_lprocfs_rpc_sent(struct ptlrpc_request *req, long amount);
void ptlrpc_lprocfs_do_request_stat (struct ptlrpc_request *req,
                                     long q_usec, long work_usec);
#else
#define ptlrpc_lprocfs_register_service(params...) do{}while(0)
#define ptlrpc_lprocfs_unregister_service(params...) do{}while(0)
#define ptlrpc_lprocfs_rpc_sent(params...) do{}while(0)
#define ptlrpc_lprocfs_do_request_stat(params...) do{}while(0)
#endif /* LPROCFS */

/* recovd_thread.c */

int ptlrpc_expire_one_request(struct ptlrpc_request *req, int async_unlink);

/* pers.c */
void ptlrpc_fill_bulk_md(lnet_md_t *md, struct ptlrpc_bulk_desc *desc);
void ptlrpc_add_bulk_page(struct ptlrpc_bulk_desc *desc, cfs_page_t *page,
                          int pageoffset, int len);

/* pack_generic.c */
struct ptlrpc_reply_state *lustre_get_emerg_rs(struct ptlrpc_service *svc);
void lustre_put_emerg_rs(struct ptlrpc_reply_state *rs);

/* pinger.c */
int ptlrpc_start_pinger(void);
int ptlrpc_stop_pinger(void);
void ptlrpc_pinger_sending_on_import(struct obd_import *imp);
void ptlrpc_pinger_commit_expected(struct obd_import *imp);
void ptlrpc_pinger_wake_up(void);
void ptlrpc_ping_import_soon(struct obd_import *imp);
#ifdef __KERNEL__
int ping_evictor_wake(struct obd_export *exp);
#else
#define ping_evictor_wake(exp)     1
#endif

/* sec_null.c */
int  sptlrpc_null_init(void);
void sptlrpc_null_fini(void);

/* sec_plain.c */
int  sptlrpc_plain_init(void);
void sptlrpc_plain_fini(void);

/* sec_bulk.c */
int  sptlrpc_enc_pool_init(void);
void sptlrpc_enc_pool_fini(void);
int sptlrpc_proc_read_enc_pool(char *page, char **start, off_t off, int count,
                               int *eof, void *data);

/* sec_lproc.c */
int  sptlrpc_lproc_init(void);
void sptlrpc_lproc_fini(void);

/* sec_gc.c */
int sptlrpc_gc_init(void);
void sptlrpc_gc_fini(void);

/* sec_config.c */
void sptlrpc_conf_choose_flavor(enum lustre_sec_part from,
                                enum lustre_sec_part to,
                                struct obd_uuid *target,
                                lnet_nid_t nid,
                                struct sptlrpc_flavor *sf);
int  sptlrpc_conf_init(void);
void sptlrpc_conf_fini(void);

/* sec.c */
int  __init sptlrpc_init(void);
void sptlrpc_fini(void);

/* recov_thread.c */
int llog_recov_init(void);
void llog_recov_fini(void);

static inline int ll_rpc_recoverable_error(int rc)
{
        return (rc == -ENOTCONN || rc == -ENODEV);
}
#endif /* PTLRPC_INTERNAL_H */
