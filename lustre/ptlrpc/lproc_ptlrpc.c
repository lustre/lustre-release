/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>
#include <linux/obd.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_net.h>
#include "ptlrpc_internal.h"


struct ll_rpc_opcode {
     __u32       opcode;
     const char *opname;
} ll_rpc_opcode_table[LUSTRE_MAX_OPCODES] = {
        { OST_REPLY,        "ost_reply" },
        { OST_GETATTR,      "ost_getattr" },
        { OST_SETATTR,      "ost_setattr" },
        { OST_READ,         "ost_read" },
        { OST_WRITE,        "ost_write" },
        { OST_CREATE ,      "ost_create" },
        { OST_DESTROY,      "ost_destroy" },
        { OST_GET_INFO,     "ost_get_info" },
        { OST_CONNECT,      "ost_connect" },
        { OST_DISCONNECT,   "ost_disconnect" },
        { OST_PUNCH,        "ost_punch" },
        { OST_OPEN,         "ost_open" },
        { OST_CLOSE,        "ost_close" },
        { OST_STATFS,       "ost_statfs" },
        { OST_SAN_READ,     "ost_san_read" },
        { OST_SAN_WRITE,    "ost_san_write" },
        { OST_SYNC,         "ost_sync" },
        { OST_SET_INFO,     "ost_set_info" },
        { MDS_GETATTR,      "mds_getattr" },
        { MDS_GETATTR_NAME, "mds_getattr_name" },
        { MDS_CLOSE,        "mds_close" },
        { MDS_REINT,        "mds_reint" },
        { MDS_READPAGE,     "mds_readpage" },
        { MDS_CONNECT,      "mds_connect" },
        { MDS_DISCONNECT,   "mds_disconnect" },
        { MDS_GETSTATUS,    "mds_getstatus" },
        { MDS_STATFS,       "mds_statfs" },
        { MDS_GETLOVINFO,   "mds_getlovinfo" },
        { MDS_PIN,          "mds_pin" },
        { MDS_UNPIN,        "mds_unpin" },
        { MDS_SYNC,         "mds_sync" },
        { LDLM_ENQUEUE,     "ldlm_enqueue" },
        { LDLM_CONVERT,     "ldlm_convert" },
        { LDLM_CANCEL,      "ldlm_cancel" },
        { LDLM_BL_CALLBACK, "ldlm_bl_callback" },
        { LDLM_CP_CALLBACK, "ldlm_cp_callback" },
        { PTLBD_QUERY,      "ptlbd_query" },
        { PTLBD_READ,       "ptlbd_read" },
        { PTLBD_WRITE,      "ptlbd_write" },
        { PTLBD_FLUSH,      "ptlbd_flush" },
        { PTLBD_CONNECT,    "ptlbd_connect" },
        { PTLBD_DISCONNECT, "ptlbd_disconnect" },
        { OBD_PING,         "obd_ping" },
        { OBD_LOG_CANCEL,   "llog_origin_handle_cancel"},
};

const char* ll_opcode2str(__u32 opcode)
{
        /* When one of the assertions below fail, chances are that:
         *     1) A new opcode was added in lustre_idl.h, but was
         *        is missing from the table above.
         * or  2) The opcode space was renumbered or rearranged,
         *        and the opcode_offset() function in
         *        ptlrpc_internals.h needs to be modified.
         */
        __u32 offset = opcode_offset(opcode);
        LASSERT(offset < LUSTRE_MAX_OPCODES);
        LASSERT(ll_rpc_opcode_table[offset].opcode == opcode);
        return ll_rpc_opcode_table[offset].opname;
}

#ifndef LPROCFS
void ptlrpc_lprocfs_register_service(struct obd_device *obddev,
                                     struct ptlrpc_service *svc) { return ; }
void ptlrpc_lprocfs_unregister_service(struct ptlrpc_service *svc) { return; }
#else

void ptlrpc_lprocfs_register(struct proc_dir_entry *root, char *dir,
                             char *name, struct proc_dir_entry **procroot_ret,
                             struct lprocfs_stats **stats_ret)
{
        struct proc_dir_entry *svc_procroot;
        struct lprocfs_stats *svc_stats;
        int i, rc;
        unsigned int svc_counter_config = LPROCFS_CNTR_AVGMINMAX | 
                                          LPROCFS_CNTR_STDDEV;

        LASSERT(*procroot_ret == NULL);
        LASSERT(*stats_ret == NULL);

        svc_stats = lprocfs_alloc_stats(PTLRPC_LAST_CNTR + LUSTRE_MAX_OPCODES);
        if (svc_stats == NULL)
                return;

        if (dir) {
                svc_procroot = lprocfs_register(dir, root, NULL, NULL);
                if (IS_ERR(svc_procroot)) {
                        lprocfs_free_stats(svc_stats);
                        return;
                }
        } else 
                svc_procroot = root;

        lprocfs_counter_init(svc_stats, PTLRPC_REQWAIT_CNTR,
                             svc_counter_config, "req_waittime", "usec");
        lprocfs_counter_init(svc_stats, PTLRPC_REQQDEPTH_CNTR,
                             svc_counter_config, "req_qdepth", "reqs");
        for (i = 0; i < LUSTRE_MAX_OPCODES; i++) {
                __u32 opcode = ll_rpc_opcode_table[i].opcode;
                lprocfs_counter_init(svc_stats, PTLRPC_LAST_CNTR + i,
                                     svc_counter_config, ll_opcode2str(opcode),
                                     "usec");
        }

        rc = lprocfs_register_stats(svc_procroot, name, svc_stats);
        if (rc < 0) {
                if (dir)
                        lprocfs_remove(svc_procroot);
                lprocfs_free_stats(svc_stats);
        } else {
                if (dir)
                        *procroot_ret = svc_procroot;
                *stats_ret = svc_stats;
        }
}

void ptlrpc_lprocfs_register_service(struct obd_device *obddev,
                                     struct ptlrpc_service *svc)
{
        ptlrpc_lprocfs_register(obddev->obd_proc_entry, svc->srv_name,
                                "stats", &svc->srv_procroot, 
                                &svc->srv_stats);
}

void ptlrpc_lprocfs_register_obd(struct obd_device *obddev)
{
        ptlrpc_lprocfs_register(obddev->obd_proc_entry, NULL, "stats", 
                                &obddev->obd_svc_procroot, 
                                &obddev->obd_svc_stats);
}

void ptlrpc_lprocfs_rpc_sent(struct ptlrpc_request *req)
{
        struct lprocfs_stats *svc_stats;
        int opc =  opcode_offset(req->rq_reqmsg->opc);

        svc_stats = req->rq_import->imp_obd->obd_svc_stats;
        if (svc_stats == NULL || opc <= 0)
                return;
        LASSERT(opc < LUSTRE_MAX_OPCODES);
        lprocfs_counter_add(svc_stats, opc + PTLRPC_LAST_CNTR, 0);
}

void ptlrpc_lprocfs_unregister_service(struct ptlrpc_service *svc)
{
        if (svc->srv_procroot != NULL) {
                lprocfs_remove(svc->srv_procroot);
                svc->srv_procroot = NULL;
        }
        if (svc->srv_stats) {
                lprocfs_free_stats(svc->srv_stats);
                svc->srv_stats = NULL;
        }
}
void ptlrpc_lprocfs_unregister_obd(struct obd_device *obd)
{
        if (obd->obd_svc_procroot) {
                lprocfs_remove(obd->obd_svc_procroot);
                obd->obd_svc_procroot = NULL;
        }
        if (obd->obd_svc_stats) {
                lprocfs_free_stats(obd->obd_svc_stats);
                obd->obd_svc_stats = NULL;
        }
}
#endif /* LPROCFS */
