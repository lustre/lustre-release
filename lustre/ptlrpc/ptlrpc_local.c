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

#define DEBUG_SUBSYSTEM S_RPC

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#ifndef __KERNEL__
#include <liblustre.h>
#include <linux/kp30.h>
#endif
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <portals/types.h>
#include "ptlrpc_internal.h"

static int local_handle(struct ptlrpc_request *req, svc_handler_t handler)
{
        int rc = 0;
        ENTRY;

        req->rq_export = class_conn2export(&req->rq_reqmsg->handle);
        if (req->rq_export) {
                req->rq_connection = req->rq_export->exp_connection;
                ptlrpc_connection_addref(req->rq_connection);
                if (req->rq_reqmsg->conn_cnt < 
                    req->rq_export->exp_conn_cnt) {
                        DEBUG_REQ(D_ERROR, req,
                                  "DROPPING req from old connection %d < %d",
                                  req->rq_reqmsg->conn_cnt,
                                  req->rq_export->exp_conn_cnt);
                        rc = -EINVAL;
                        goto out_putconn;
                }

                req->rq_export->exp_last_request_time =
                        LTIME_S(CURRENT_TIME);
        } else {
                /* connection must has been established */
                LBUG();
                /* create a (hopefully temporary) connection that will be used
                 * to send the reply if this call doesn't create an export.
                 * XXX revisit this when we revamp ptlrpc */
                req->rq_connection =
                        ptlrpc_get_connection(&req->rq_peer, NULL);
        }

        rc = handler(req);

        memset(req->rq_ack_locks, 0, sizeof(req->rq_ack_locks));
        if (req->rq_bulk)
                req->rq_bulk->bd_complete = 1;
        req->rq_repmsg->type = (req->rq_type == PTL_LOCAL_MSG_ERR) ?
                PTL_RPC_MSG_ERR : PTL_RPC_MSG_REPLY;
        req->rq_repmsg->status = req->rq_status;
        req->rq_repmsg->opc = req->rq_reqmsg->opc;
        req->rq_receiving_reply = 0;
        req->rq_replied = 1;

out_putconn:
        ptlrpc_put_connection(req->rq_connection);
        if (req->rq_export != NULL) {
                class_export_put(req->rq_export);
                req->rq_export = NULL;
        }
        
        RETURN(rc);

}

int local_svc_available(struct ptlrpc_request *req)
{
        int req_portal = req->rq_request_portal;
        int av_portal = 0;

        av_portal =  (req_portal == MDS_REQUEST_PORTAL ||
                      req_portal == MDS_SETATTR_PORTAL ||
                      req_portal == MDS_READPAGE_PORTAL ||
                      req_portal == OST_REQUEST_PORTAL ||
                      req_portal == OST_CREATE_PORTAL) ? 1 : 0;
        
        return av_portal;

}

int local_send_rpc(struct ptlrpc_request *req)
{
        int rc;
        struct obd_ucred ucred;
        void *journal_info;
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
        ENTRY;
        
        LASSERT (req->rq_replen != 0);
        req->rq_reqmsg->handle = req->rq_import->imp_remote_handle;
        req->rq_reqmsg->conn_cnt = req->rq_import->imp_conn_cnt;
                
        req->rq_receiving_reply = 1;
        req->rq_replied = 0;
        req->rq_err = 0;
        req->rq_timedout = 0;
        req->rq_resend = 0;
        req->rq_restart = 0;
                
        req->rq_sent = LTIME_S(CURRENT_TIME);
        ptlrpc_pinger_sending_on_import(req->rq_import);
        req->rq_type = PTL_LOCAL_MSG_REQUEST;
        
        ucred.ouc_fsuid = current->fsuid;
        ucred.ouc_fsgid = current->fsgid;
        ucred.ouc_cap = current->cap_effective;
        current->fsuid = current->fsgid = 0;
        current->cap_effective = -1;
        
        /* for nesting journal on MDS and OST*/
        journal_info = current->journal_info;
        current->journal_info = NULL;
        
        rc = local_handle(req, cli->srv_handler);
        
        current->journal_info = journal_info;
                
        current->fsuid = ucred.ouc_fsuid;
        current->fsgid = ucred.ouc_fsgid;
        current->cap_effective = ucred.ouc_cap;
                
        ptlrpc_lprocfs_rpc_sent(req);
        RETURN(rc);
}

int local_reply(struct ptlrpc_request *req)
{
        ENTRY;
        
        switch (req->rq_type) {
        case PTL_LOCAL_MSG_REQUEST:
                req->rq_type = PTL_LOCAL_MSG_REPLY;
        case PTL_LOCAL_MSG_REPLY:
        case PTL_LOCAL_MSG_ERR:
                req->rq_want_ack = 0;
                break;
        default:
                LBUG();
                break;
        }
        RETURN(0);
}

int local_error(struct ptlrpc_request *req)
{
        ENTRY;

        switch (req->rq_type) {
        case PTL_LOCAL_MSG_REQUEST:
        case PTL_LOCAL_MSG_REPLY:
                req->rq_type = PTL_LOCAL_MSG_ERR;
        case PTL_LOCAL_MSG_ERR:
                break;
        default:
                LBUG();
                break;
        }
        EXIT;

        return local_reply(req);
}

int local_bulk_move(struct ptlrpc_bulk_desc *desc)
{        
        struct ptlrpc_bulk_desc *source, *dest;
        struct ptlrpc_bulk_page *src_pg, *dst_pg;
        struct list_head *src, *dst;
        char *src_addr, *dst_addr;
        int len, i;
        ENTRY;

        if (desc->bd_type == BULK_GET_SINK) {
                source = desc->bd_req->rq_bulk;
                dest = desc;
        } else if (desc->bd_type == BULK_PUT_SOURCE) {
                source = desc;
                dest = desc->bd_req->rq_bulk;
        } else {
                LBUG();
        }

        LASSERT(source);
        LASSERT(dest);
        /* XXX need more investigation for sparse file case ? */
        if (source->bd_page_count != dest->bd_page_count)
                goto done;

        src = source->bd_page_list.next;
        dst = dest->bd_page_list.next;
        for (i = 0; i < dest->bd_page_count; i++) {
                src_pg = list_entry(src, struct ptlrpc_bulk_page, bp_link);
                dst_pg = list_entry(dst, struct ptlrpc_bulk_page, bp_link);

                len = MIN(src_pg->bp_buflen, dst_pg->bp_buflen);
                src_addr = kmap(src_pg->bp_page) + src_pg->bp_pageoffset;
                dst_addr = kmap(dst_pg->bp_page) + dst_pg->bp_pageoffset;
                memcpy(dst_addr, src_addr, len);
                kunmap(dst_pg->bp_page);
                kunmap(src_pg->bp_page);

                src = src->next;
                dst = dst->next;
        }
done:
        desc->bd_network_rw = 0;
        desc->bd_complete = 1;

        RETURN(0);
        
}


