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

int ptlbd_send_rw_req(struct ptlbd_obd *ptlbd, ptlbd_cmd_t cmd, 
                   struct buffer_head *first_bh)
{
        struct obd_import *imp = ptlbd->bd_import;
        struct ptlbd_op *op;
        struct ptlbd_niob *niob, *niobs;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_request *req;
        struct ptlrpc_bulk_desc *desc;
        struct buffer_head *bh;
        unsigned int page_count;
        int rc, rep_size, size[2];
        ENTRY;

        LASSERT(cmd == PTLBD_READ || cmd == PTLBD_WRITE);

        for ( page_count = 0, bh = first_bh ; bh ; bh = bh->b_reqnext )
                page_count++;

        size[0] = sizeof(struct ptlbd_op);
        size[1] = page_count * sizeof(struct ptlbd_niob);

        req = ptlrpc_prep_req(imp, cmd, 2, size, NULL);
        if (!req)
                RETURN(rc = 1);                  /* need to return error cnt */

        op = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*op));
        niobs = lustre_msg_buf(req->rq_reqmsg, 1, size[1]);

        /* XXX pack */
        op->op_cmd = cmd;
        op->op_lun = 0;
        op->op_niob_cnt = page_count;
        op->op__padding = 0;
        op->op_block_cnt = page_count;

        if (cmd == PTLBD_READ) 
                desc = ptlrpc_prep_bulk_imp (req, BULK_PUT_SINK, PTLBD_BULK_PORTAL);
        else
                desc = ptlrpc_prep_bulk_imp (req, BULK_GET_SOURCE, PTLBD_BULK_PORTAL);
        if ( desc == NULL )
                GOTO(out, rc = 1);              /* need to return error cnt */
        /* NB req now owns desc, and frees it when she frees herself */
        
        for ( niob = niobs, bh = first_bh ; bh ; bh = bh->b_reqnext, niob++ ) {
                rc = ptlrpc_prep_bulk_page(desc, bh->b_page,
                                           bh_offset (bh) & (PAGE_SIZE - 1),
                                           bh->b_size);
                if (rc != 0)
                        GOTO(out, rc = 1);      /* need to return error cnt */

                niob->n_block_nr = bh->b_blocknr;
                niob->n_offset = bh_offset(bh);
                niob->n_length = bh->b_size;
        }

        rep_size = sizeof(struct ptlbd_rsp);
        req->rq_replen = lustre_msg_size(1, &rep_size);

        /* XXX find out how we're really supposed to manage levels */
        req->rq_send_state = imp->imp_state;
        rc = ptlrpc_queue_wait(req);

        if ( rc != 0 )
                GOTO(out, rc = 1);              /* need to return error count */

        rsp = lustre_swab_repbuf(req, 0, sizeof (*rsp),
                                 lustre_swab_ptlbd_rsp);
        if (rsp == NULL) {
                CERROR ("can't unpack response\n");
                GOTO (out, rc = 1);             /* need to return error count */
        }
        else if (rsp->r_status != 0) {
                rc = rsp->r_error_cnt;
        }

out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}


int ptlbd_send_flush_req(struct ptlbd_obd *ptlbd, ptlbd_cmd_t cmd)
{
        struct obd_import *imp = ptlbd->bd_import;
        struct ptlbd_op *op;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_request *req;
        int rc, rep_size, size[1];
        ENTRY;

        LASSERT(cmd == PTLBD_FLUSH);

        size[0] = sizeof(struct ptlbd_op);

        req = ptlrpc_prep_req(imp, cmd, 1, size, NULL);
        if (!req)
                RETURN(-ENOMEM); 

        op = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*op));

        /* XXX pack */
        op->op_cmd = cmd;
        op->op_lun = 0;
        op->op_niob_cnt = 0;
        op->op__padding = 0;
        op->op_block_cnt = 0;

        rep_size = sizeof(struct ptlbd_rsp);
        req->rq_replen = lustre_msg_size(1, &rep_size);

        /* XXX find out how we're really supposed to manage levels */
        req->rq_send_state = imp->imp_state;

        rc = ptlrpc_queue_wait(req);
        if ( rc != 0 )
                GOTO(out_req, rc = 1);
        rsp = lustre_swab_repbuf(req, 0, sizeof (*rsp),
                                 lustre_swab_ptlbd_rsp);
        if (rsp->r_status != 0)
                rc = rsp->r_status;

out_req:
        ptlrpc_req_finished(req);
        RETURN(rc);
}


int ptlbd_do_filp(struct file *filp, int op, struct ptlbd_niob *niobs, 
                int page_count, struct list_head *page_list)
{
        mm_segment_t old_fs;
        struct list_head *pos;
        int status = 0;
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
                if (ret != niobs->n_length) {
                        status = ret;
                        break;
                }
                niobs++;
        }
        set_fs(old_fs);
        RETURN(status);
}


int ptlbd_srv_rw_req(ptlbd_cmd_t cmd, __u16 index, 
                     struct ptlrpc_request *req, int swab)
{
        struct ptlbd_niob *niob, *niobs;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct file *filp = req->rq_export->exp_obd->u.ptlbd.filp;
        struct l_wait_info lwi;
        int size[1], i, page_count, rc = 0, error_cnt = 0;
        struct list_head *pos, *n;
        struct page *page;
        LIST_HEAD(tmp_pages);
        ENTRY;

        niobs = lustre_swab_reqbuf (req, 1, sizeof (*niobs),
                                    lustre_swab_ptlbd_niob);
        if (niobs == NULL)
                GOTO (out, rc = -EFAULT);

        size[0] = sizeof(struct ptlbd_rsp);
        rc = lustre_pack_reply(req, 1, size, NULL);
        if ( rc )
                GOTO(out, rc);

        rsp = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rsp));
        if ( rsp == NULL )
                GOTO (out, rc = -EFAULT);

        page_count = req->rq_reqmsg->buflens[1] / sizeof(struct ptlbd_niob);
        if (swab) {                             /* swab remaining niobs */
                for (i = 1; i < page_count; i++)
                        lustre_swab_ptlbd_niob(&niobs[i]);
        }
        if (req->rq_export == NULL) {
                error_cnt++;
                GOTO(out_reply, rc = -EFAULT);
        }
        
        if (cmd == PTLBD_READ)
                desc = ptlrpc_prep_bulk_exp (req, BULK_PUT_SOURCE, PTLBD_BULK_PORTAL);
        else
                desc = ptlrpc_prep_bulk_exp (req, BULK_GET_SINK, PTLBD_BULK_PORTAL);
        if (desc == NULL) {
                error_cnt++;
                GOTO(out_reply, rc = -ENOMEM);
        }
        desc->bd_portal = PTLBD_BULK_PORTAL;
        LASSERT (page_count > 0);

        for ( i = 0, niob = niobs ; i < page_count; niob++, i++) {
                page = alloc_page(GFP_KERNEL);
                if (page == NULL) {
                        error_cnt++;
                        GOTO(out_reply, rc = -ENOMEM);
                }
                list_add_tail(&page->list, &tmp_pages);

                rc = ptlrpc_prep_bulk_page(desc, page,
                                           niob->n_offset & (PAGE_SIZE - 1),
                                           niob->n_length);
                if (rc != 0) {
                        error_cnt++;
                        GOTO(out_reply, rc);
                }
        }

        if ( cmd == PTLBD_READ ) {
                if ((rc = ptlbd_do_filp(filp, PTLBD_READ, niobs, 
                                        page_count, &tmp_pages)) < 0) {
                        error_cnt++;
                        GOTO(out_reply, rc);
                }
                rc = ptlrpc_bulk_put(desc);
        } else {
                rc = ptlrpc_bulk_get(desc);
        }

        if ( rc ) {
                error_cnt++;
                GOTO(out_reply, rc);
        }

        lwi = LWI_TIMEOUT(obd_timeout * HZ / 4, NULL, desc);
        rc = l_wait_event(desc->bd_waitq, ptlrpc_bulk_complete(desc), &lwi);
        if (rc != 0) {
                LASSERT(rc == -ETIMEDOUT);
                ptlrpc_abort_bulk(desc);
                error_cnt++;
                GOTO(out_reply, rc);
        }
        
        if ( cmd == PTLBD_WRITE ) {
                if ((rc = ptlbd_do_filp(filp, PTLBD_WRITE, niobs, 
                                           page_count, &tmp_pages)) < 0) {
                        error_cnt++;
                }
        }

out_reply:
        rsp->r_error_cnt = error_cnt;
        rsp->r_status = rc;  
        req->rq_status = rc; 

        ptlrpc_reply(req);

        list_for_each_safe(pos, n, &tmp_pages) {
                struct page *page = list_entry(pos, struct page, list);
                list_del(&page->list);
                __free_page(page);
        }
        if (desc)
                ptlrpc_free_bulk(desc);
out:
        RETURN(rc);
}


int ptlbd_srv_flush_req(ptlbd_cmd_t cmd, __u16 index, 
                        struct ptlrpc_request *req)
{
        struct ptlbd_rsp *rsp;
        struct file *filp = req->rq_export->exp_obd->u.ptlbd.filp;
        int size[1], rc, status;
        ENTRY;

        size[0] = sizeof(struct ptlbd_rsp);
        rc = lustre_pack_reply(req, 1, size, NULL);
        if ( rc )
                RETURN(rc);

        rsp = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rsp));
        if ( rsp == NULL )
                RETURN(-EINVAL);

        if (! (filp) && (filp->f_op) && (filp->f_op->fsync) &&
              (filp->f_dentry))
                GOTO(out_reply, status = -EINVAL);

        status = filp->f_op->fsync(filp, filp->f_dentry, 1);

out_reply:
        rsp->r_error_cnt = 0;
        rsp->r_status = status;
        req->rq_status = 0;

        ptlrpc_reply(req);
        RETURN(0);
}


int ptlbd_handle(struct ptlrpc_request *req)
{
        struct ptlbd_op *op;
        int swab;
        int rc;
        ENTRY;

        swab = lustre_msg_swabbed (req->rq_reqmsg);

        if (req->rq_reqmsg->opc == PTLBD_CONNECT) {
                rc = target_handle_connect(req, ptlbd_handle);
                target_send_reply(req, rc, OBD_FAIL_PTLRPC);
                RETURN(0);
        }
        if (req->rq_reqmsg->opc == PTLBD_DISCONNECT) {
                rc = target_handle_disconnect(req);
                target_send_reply(req, rc, OBD_FAIL_PTLRPC);
                RETURN(0);
        }
        op = lustre_swab_reqbuf (req, 0, sizeof (*op),
                                 lustre_swab_ptlbd_op);
        if (op == NULL)
                RETURN(-EFAULT);

        switch (op->op_cmd) {
                case PTLBD_READ:
                case PTLBD_WRITE:
                        rc = ptlbd_srv_rw_req(op->op_cmd, op->op_lun, req, 
                                              swab);
                        break;

                case PTLBD_FLUSH:
                        rc = ptlbd_srv_flush_req(op->op_cmd, op->op_lun, req);
                        break;
                default:
                        rc = -EINVAL;
        }

        RETURN(rc);
}
