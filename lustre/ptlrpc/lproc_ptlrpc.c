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
        { OST_SYNCFS,       "ost_syncfs" },
        { OST_LOG_CANCEL,   "ost_log_cancel" },
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
        { LDLM_ENQUEUE,     "ldlm_enqueue" },
        { LDLM_CONVERT,     "ldlm_convert" },
        { LDLM_CANCEL,      "ldlm_cancel" },
        { LDLM_BL_CALLBACK, "ldlm_bl_callback" },
        { LDLM_CP_CALLBACK, "ldlm_cp_callback" },
        { PTLBD_QUERY,      "ptlbd_query" },
        { PTLBD_READ,       "ptlbd_read" },
        { PTLBD_WRITE,      "ptlbd_write" },
        { PTLBD_FLUSH,      "ptlbd_flush" },
        { OBD_PING,         "obd_ping" }
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

void ptlrpc_lprocfs_register_service(struct obd_device *obddev,
                                     struct ptlrpc_service *svc)
{
        struct proc_dir_entry   *svc_procroot;
        struct lprocfs_counters *svc_cntrs;
        int i, rc;
        unsigned int svc_counter_config = LPROCFS_CNTR_EXTERNALLOCK | 
                LPROCFS_CNTR_AVGMINMAX | LPROCFS_CNTR_STDDEV;

        LASSERT(svc->svc_procroot == NULL);
        LASSERT(svc->svc_counters == NULL);

        svc_procroot = lprocfs_register(svc->srv_name, obddev->obd_proc_entry,
                                        NULL, NULL);
        if (svc_procroot == NULL) 
                return;
        
        svc_cntrs = 
                lprocfs_alloc_counters(PTLRPC_LAST_CNTR+LUSTRE_MAX_OPCODES);
        if (svc_cntrs == NULL) {
                lprocfs_remove(svc_procroot);
                return;
        }
 
        LPROCFS_COUNTER_INIT(&svc_cntrs->cntr[PTLRPC_REQWAIT_CNTR], 
                             svc_counter_config, &svc->srv_lock, 
                             "req_waittime", "cycles");
        LPROCFS_COUNTER_INIT(&svc_cntrs->cntr[PTLRPC_SVCEQDEPTH_CNTR], 
                             svc_counter_config, &svc->srv_lock, 
                             "svc_eqdepth", "reqs");
        /* no stddev on idletime */
        LPROCFS_COUNTER_INIT(&svc_cntrs->cntr[PTLRPC_SVCIDLETIME_CNTR],
                             (LPROCFS_CNTR_EXTERNALLOCK | LPROCFS_CNTR_AVGMINMAX),
                             &svc->srv_lock, "svc_idletime", "cycles");
        for (i=0; i < LUSTRE_MAX_OPCODES; i++) {
                __u32 opcode = ll_rpc_opcode_table[i].opcode;
                LPROCFS_COUNTER_INIT(&svc_cntrs->cntr[PTLRPC_LAST_CNTR+i], 
                                     svc_counter_config, &svc->srv_lock,
                                     ll_opcode2str(opcode), "cycles");
        }
        rc = lprocfs_register_counters(svc_procroot, "service_stats", 
                                       svc_cntrs);
        if (rc < 0) {
                lprocfs_remove(svc_procroot);
                lprocfs_free_counters(svc_cntrs);
        } else {
                svc->svc_procroot = svc_procroot;
                svc->svc_counters = svc_cntrs;
        }
}

void ptlrpc_lprocfs_unregister_service(struct ptlrpc_service *svc)
{
        if (svc->svc_procroot) {
                lprocfs_remove(svc->svc_procroot);
                svc->svc_procroot = NULL;
        }
        if (svc->svc_counters) {
                lprocfs_free_counters(svc->svc_counters);
                svc->svc_counters = NULL;
        }
}
#endif /* LPROCFS */
