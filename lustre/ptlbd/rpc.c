/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@clusterfs.com>
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
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>

#define DEBUG_SUBSYSTEM S_PTLBD

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_debug.h>
#include <linux/lprocfs_status.h>
#include <linux/obd_ptlbd.h>

int ptlbd_send_req(struct ptlbd_obd *ptlbd, ptlbd_cmd_t cmd, 
                struct buffer_head *first_bh)
{
        struct obd_import *imp = &ptlbd->bd_import;
        struct ptlbd_op *op;
        struct ptlbd_niob *niob, *niobs;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_request *req;
        struct ptlrpc_bulk_desc *desc;
        struct buffer_head *bh;
        unsigned long flags;
        unsigned int page_count;
        int rc, rep_size, size[2];
        __u32 xid;
        ENTRY;

        LASSERT(cmd == PTLBD_READ || cmd == PTLBD_WRITE);

        for ( page_count = 0, bh = first_bh ; bh ; bh = bh->b_next )
                page_count++;

        size[0] = sizeof(struct ptlbd_op);
        size[1] = page_count * sizeof(struct ptlbd_niob);

        req = ptlrpc_prep_req(imp, cmd, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        op = lustre_msg_buf(req->rq_reqmsg, 0);
        niobs = lustre_msg_buf(req->rq_reqmsg, 1);

        /* XXX pack */
        op->op_cmd = cmd;
        op->op_lun = 0;
        op->op_niob_cnt = page_count;
        op->op__padding = 0;
        op->op_block_cnt = page_count;

        desc = ptlrpc_prep_bulk(imp->imp_connection);
        if ( desc == NULL )
                GOTO(out_req, rc = -ENOMEM);
        desc->bd_portal = PTLBD_BULK_PORTAL;
        desc->bd_ptl_ev_hdlr = NULL;

        spin_lock_irqsave(&imp->imp_lock, flags);
        xid = ++imp->imp_last_xid;
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        for ( niob = niobs, bh = first_bh ; bh ; bh = bh->b_next, niob++ ) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_req, rc = -ENOMEM);

                niob->n_xid = xid;
                niob->n_block_nr = bh->b_blocknr;
                niob->n_offset = bh_offset(bh);
                niob->n_length = bh->b_size;

                bulk->bp_xid = xid;
                bulk->bp_buf = bh->b_data;
                bulk->bp_page = bh->b_page;
                bulk->bp_buflen = bh->b_size;
        }

        if ( cmd == PTLBD_READ )
                rc = ptlrpc_register_bulk_put(desc);
        else
                rc = ptlrpc_register_bulk_get(desc);

        if (rc)
                GOTO(out_desc, rc);

        rep_size = sizeof(struct ptlbd_rsp);
        req->rq_replen = lustre_msg_size(1, &rep_size);

        /* XXX find out how we're really supposed to manage levels */
        req->rq_level = imp->imp_level;
        rc = ptlrpc_queue_wait(req);

        if ( rc == 0 ) {
                rsp = lustre_msg_buf(req->rq_repmsg, 0);
                /* XXX do stuff */
        }

out_desc:
        ptlrpc_bulk_decref(desc);
out_req:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

static int ptlbd_bulk_timeout(void *data)
{
/*        struct ptlrpc_bulk_desc *desc = data;*/
        ENTRY;

        CERROR("ugh, timed out\n");

        RETURN(1);
}

void ptlbd_do_filp(struct file *filp, int op, struct ptlbd_niob *niobs, 
                int page_count, struct list_head *page_list)
{
        mm_segment_t old_fs;
        struct list_head *pos;
        ENTRY;

        old_fs = get_fs();
        set_fs(KERNEL_DS);

        list_for_each(pos, page_list) {
                ssize_t ret;
                struct page *page = list_entry(pos, struct page, list);
                loff_t offset = (niobs->n_block_nr << PAGE_SHIFT) + 
                        niobs->n_offset;

                if ( op == PTLBD_READ )
                        ret = filp->f_op->read(filp, page_address(page), 
                                        niobs->n_length, &offset);
                else
                        ret = filp->f_op->write(filp, page_address(page), 
                                        niobs->n_length, &offset);

                niobs++;
        }

        set_fs(old_fs);
        EXIT;
}

int ptlbd_parse_req(struct ptlrpc_request *req)
{
        struct ptlbd_op *op;
        struct ptlbd_niob *niob, *niobs;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_bulk_desc *desc;
        struct file *filp = req->rq_obd->u.ptlbd.filp;
        struct l_wait_info lwi;
        int size[1], wait_flag, i, page_count, rc;
        struct list_head *pos, *n;
        LIST_HEAD(tmp_pages);
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if ( rc )
                RETURN(rc);

        op = lustre_msg_buf(req->rq_reqmsg, 0);
        LASSERT(op->op_cmd == PTLBD_READ || op->op_cmd == PTLBD_WRITE);

        niobs = lustre_msg_buf(req->rq_reqmsg, 1);
        page_count = req->rq_reqmsg->buflens[1] / sizeof(struct ptlbd_niob);

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        desc->bd_ptl_ev_hdlr = NULL;
        desc->bd_portal = PTLBD_BULK_PORTAL;

        for ( i = 0, niob = niobs ; i < page_count; niob++, i++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_bulk, rc = -ENOMEM);

                bulk->bp_page = alloc_page(GFP_KERNEL);
                if (bulk->bp_page == NULL)
                        GOTO(out_bulk, rc = -ENOMEM);
                list_add(&bulk->bp_page->list, &tmp_pages);

                /* 
                 * XXX what about the block number? 
                 */
                bulk->bp_xid = niob->n_xid;
                bulk->bp_buf = page_address(bulk->bp_page);
                bulk->bp_buflen = niob->n_length;
        }

        if ( op->op_cmd == PTLBD_READ ) {
                ptlbd_do_filp(filp, PTLBD_READ, niobs, page_count, &tmp_pages);
                rc = ptlrpc_bulk_put(desc);
                wait_flag = PTL_BULK_FL_SENT;
        } else {
                rc = ptlrpc_bulk_get(desc);
                wait_flag = PTL_BULK_FL_RCVD;
        }

        if ( rc )
                GOTO(out_bulk, rc);

        /* this synchronization probably isn't good enough */
        lwi = LWI_TIMEOUT(obd_timeout * HZ, ptlbd_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, desc->bd_flags & wait_flag, &lwi);

        size[0] = sizeof(struct ptlbd_rsp);
        rc = lustre_pack_msg(1, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if ( rc )
                GOTO(out, rc);

        rsp = lustre_msg_buf(req->rq_repmsg, 0);
        if ( rsp == NULL )
                GOTO(out, rc = -EINVAL);
        
        ptlbd_do_filp(filp, PTLBD_WRITE, niobs, page_count, &tmp_pages);

        rsp->r_error_cnt = 42;
        rsp->r_status = 69;

        req->rq_status = 0; /* XXX */
        ptlrpc_reply(req->rq_svc, req);

out_bulk:
        list_for_each_safe(pos, n, &tmp_pages) {
                struct page *page = list_entry(pos, struct page, list);
                list_del(&page->list);
                __free_page(page);
        }
        ptlrpc_bulk_decref(desc);
out:
        RETURN(rc);
}
