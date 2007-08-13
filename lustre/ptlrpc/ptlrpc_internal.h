/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
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
void ptlrpc_lprocfs_rpc_sent(struct ptlrpc_request *req);
void ptlrpc_lprocfs_do_request_stat (struct ptlrpc_request *req,
                                     long q_usec, long work_usec);
#else
#define ptlrpc_lprocfs_register_service(params...) do{}while(0)
#define ptlrpc_lprocfs_unregister_service(params...) do{}while(0)
#define ptlrpc_lprocfs_rpc_sent(params...) do{}while(0)
#define ptlrpc_lprocfs_do_request_stat(params...) do{}while(0)
#endif /* LPROCFS */

/* recovd_thread.c */

static inline int opcode_offset(__u32 opc) {
        if (opc < OST_LAST_OPC) {
                 /* OST opcode */
                return (opc - OST_FIRST_OPC);
        } else if (opc < MDS_LAST_OPC) {
                /* MDS opcode */
                return (opc - MDS_FIRST_OPC +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < LDLM_LAST_OPC) {
                /* LDLM Opcode */
                return (opc - LDLM_FIRST_OPC +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < MGS_LAST_OPC) {
                /* MGS Opcode */
                return (opc - MGS_FIRST_OPC +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < OBD_LAST_OPC) {
                /* OBD Ping */
                return (opc - OBD_FIRST_OPC +
                        (MGS_LAST_OPC - MGS_FIRST_OPC) +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < LLOG_LAST_OPC) {
                /* LLOG Opcode */
                return (opc - LLOG_FIRST_OPC +
                        (OBD_LAST_OPC - OBD_FIRST_OPC) +
                        (MGS_LAST_OPC - MGS_FIRST_OPC) +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else {
                /* Unknown Opcode */
                return -1;
        }
}

#define LUSTRE_MAX_OPCODES ((OST_LAST_OPC - OST_FIRST_OPC)     + \
                            (MDS_LAST_OPC - MDS_FIRST_OPC)     + \
                            (LDLM_LAST_OPC - LDLM_FIRST_OPC)   + \
                            (MGS_LAST_OPC - MGS_FIRST_OPC)     + \
                            (OBD_LAST_OPC - OBD_FIRST_OPC)     + \
                            (LLOG_LAST_OPC - LLOG_FIRST_OPC))

enum {
        PTLRPC_REQWAIT_CNTR = 0,
        PTLRPC_REQQDEPTH_CNTR,
        PTLRPC_REQACTIVE_CNTR,
        PTLRPC_REQBUF_AVAIL_CNTR,
        PTLRPC_LAST_CNTR
};

int ptlrpc_expire_one_request(struct ptlrpc_request *req);

/* pers.c */
void ptlrpc_fill_bulk_md(lnet_md_t *md, struct ptlrpc_bulk_desc *desc);
void ptlrpc_add_bulk_page(struct ptlrpc_bulk_desc *desc, cfs_page_t *page, 
                          int pageoffset, int len);
void ptl_rpc_wipe_bulk_pages(struct ptlrpc_bulk_desc *desc);

/* pinger.c */
int ptlrpc_start_pinger(void);
int ptlrpc_stop_pinger(void);
void ptlrpc_pinger_sending_on_import(struct obd_import *imp);
void ptlrpc_pinger_wake_up(void);
void ptlrpc_ping_import_soon(struct obd_import *imp);
#ifdef __KERNEL__
int ping_evictor_wake(struct obd_export *exp);
#else
#define ping_evictor_wake(exp)     1
#endif

#endif /* PTLRPC_INTERNAL_H */
