/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc.
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

static __u32 get_next_xid(struct obd_import *imp)
{
        unsigned long flags;
        __u32 xid;
        spin_lock_irqsave(&imp->imp_lock, flags);
        xid = ++imp->imp_last_xid;
        spin_unlock_irqrestore(&imp->imp_lock, flags);
        return xid;
}

static int ptlbd_brw_callback(struct obd_brw_set *set, int phase)
{
        ENTRY;
        RETURN(0);
}

static void decref_bulk_desc(void *data)
{
        struct ptlrpc_bulk_desc *desc = data;
        ENTRY;

        ptlrpc_bulk_decref(desc);
        EXIT;
}

/*  this is the callback function which is invoked by the Portals
 *  event handler associated with the bulk_sink queue and bulk_source queue. 
 */
static void ptlbd_ptl_ev_hdlr(struct ptlrpc_bulk_desc *desc)
{
        ENTRY;

        LASSERT(desc->bd_brw_set != NULL);
        LASSERT(desc->bd_brw_set->brw_callback != NULL);

        desc->bd_brw_set->brw_callback(desc->bd_brw_set, CB_PHASE_FINISH);

        prepare_work(&desc->bd_queue, decref_bulk_desc, desc);
        schedule_work(&desc->bd_queue);

        EXIT;
}


int ptlbd_write_put_req(struct ptlbd_obd *ptlbd, ptlbd_cmd_t cmd, 
                struct buffer_head *first_bh, unsigned int page_count)
{
        struct obd_import *imp = &ptlbd->bd_import;
        struct ptlbd_op *op;
        struct ptlbd_niob *niob, *niobs;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_request *req;
        struct ptlrpc_bulk_desc *desc;
        struct buffer_head *bh;
        int rc, size[2];
        struct obd_brw_set *set;
        ENTRY;

        size[0] = sizeof(struct ptlbd_op);
        size[1] = page_count * sizeof(struct ptlbd_niob);

        req = ptlrpc_prep_req(imp, cmd, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        /* XXX might not need these */
        req->rq_request_portal = PTLBD_REQUEST_PORTAL;
        req->rq_reply_portal = PTLBD_REPLY_PORTAL;

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
        desc->bd_ptl_ev_hdlr = ptlbd_ptl_ev_hdlr;

        /* XXX someone needs to free this */
        set = obd_brw_set_new();
        if (set == NULL)
                GOTO(out_desc, rc = -ENOMEM);

        set->brw_callback = ptlbd_brw_callback;
 
#if 0
        xid = get_next_xid(imp);
#endif

        for ( niob = niobs, bh = first_bh ; bh ; bh = bh->b_next, niob++ ) {
#if 0
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_set, rc = -ENOMEM);
#endif

#if 0
                niob->n_xid = xid;
#endif
                niob->n_block_nr = bh->b_blocknr;
                niob->n_offset = bh_offset(bh);
                niob->n_length = bh->b_size;


#if 0
                bulk->bp_xid = xid;
                bulk->bp_buf = bh->b_data;
                bulk->bp_page = bh->b_page;
                bulk->bp_buflen = bh->b_size;
#endif
        }


        size[0] = sizeof(struct ptlbd_rsp);
        size[1] = sizeof(struct ptlbd_niob) * page_count;
        req->rq_replen = lustre_msg_size(2, size);

        /* XXX find out how we're really supposed to manage levels */
        req->rq_level = imp->imp_level;
        rc = ptlrpc_queue_wait(req);

        rsp = lustre_msg_buf(req->rq_repmsg, 0);

        niob = lustre_msg_buf(req->rq_repmsg, 1);
        /* XXX check that op->num matches ours */
        for ( bh = first_bh ; bh ; bh = bh->b_next, niob++ ) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                bulk->bp_xid = niob->n_xid;
                bulk->bp_page = bh->b_page;
                bulk->bp_buf = bh->b_data;
                bulk->bp_buflen = bh->b_size;
        }

        obd_brw_set_add(set, desc);
        rc = ptlrpc_send_bulk(desc);

        /* if there's an error, no brw_finish called, just like
         * osc_brw_read */

        GOTO(out_req, rc);

out_set:
        obd_brw_set_free(set);
out_desc:
        ptlrpc_bulk_decref(desc);
out_req:
        ptlrpc_req_finished(req);
out:
        RETURN(rc);
}

int ptlbd_read_put_req(struct ptlbd_obd *ptlbd, ptlbd_cmd_t cmd, 
                struct buffer_head *first_bh, unsigned int page_count)
{
        struct obd_import *imp = &ptlbd->bd_import;
        struct ptlbd_op *op;
        struct ptlbd_niob *niob, *niobs;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_request *req;
        struct ptlrpc_bulk_desc *desc;
        struct buffer_head *bh;
        int rc, rep_size, size[2];
        struct obd_brw_set *set;
        __u32 xid;
        ENTRY;

        size[0] = sizeof(struct ptlbd_op);
        size[1] = page_count * sizeof(struct ptlbd_niob);

        req = ptlrpc_prep_req(imp, cmd, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        /* XXX might not need these? */
        req->rq_request_portal = PTLBD_REQUEST_PORTAL;
        req->rq_reply_portal = PTLBD_REPLY_PORTAL;

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
        desc->bd_ptl_ev_hdlr = ptlbd_ptl_ev_hdlr;

        /* XXX someone needs to free this */
        set = obd_brw_set_new();
        if (set == NULL)
                GOTO(out_desc, rc = -ENOMEM);

        set->brw_callback = ptlbd_brw_callback;

        xid = get_next_xid(imp);

        for ( niob = niobs, bh = first_bh ; bh ; bh = bh->b_next, niob++ ) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                niob->n_xid = xid;
                niob->n_block_nr = bh->b_blocknr;
                niob->n_offset = bh_offset(bh);
                niob->n_length = bh->b_size;

                bulk->bp_xid = xid;
                bulk->bp_buf = bh->b_data;
                bulk->bp_page = bh->b_page;
                bulk->bp_buflen = bh->b_size;
        }

        /* XXX put in OBD_FAIL_CHECK for ptlbd? */
        rc = ptlrpc_register_bulk(desc);
        if (rc)
                GOTO(out_set, rc);

        obd_brw_set_add(set, desc);

        rep_size = sizeof(struct ptlbd_rsp);
        req->rq_replen = lustre_msg_size(1, &rep_size);

        /* XXX find out how we're really supposed to manage levels */
        req->rq_level = imp->imp_level;
        rc = ptlrpc_queue_wait(req);

        rsp = lustre_msg_buf(req->rq_repmsg, 0);

        /* if there's an error, no brw_finish called, just like
         * osc_brw_read */

        GOTO(out_req, rc);

out_set:
        obd_brw_set_free(set);
out_desc:
        ptlrpc_bulk_decref(desc);
out_req:
        ptlrpc_req_finished(req);
out:
        RETURN(rc);
}

int ptlbd_send_req(struct ptlbd_obd *ptlbd, ptlbd_cmd_t cmd, 
                struct buffer_head *first_bh)
{
        unsigned int page_count = 0;
        struct buffer_head *bh;
        int rc;
        ENTRY;

        for ( page_count = 0, bh = first_bh ; bh ; bh = bh->b_next )
                page_count++;

        switch (cmd) {
                case PTLBD_READ:
                        rc = ptlbd_read_put_req(ptlbd, cmd, 
                                        first_bh, page_count);
                        break;
                case PTLBD_WRITE:
                        rc = ptlbd_write_put_req(ptlbd, cmd, 
                                        first_bh, page_count);
                        break;
                default:
                        rc = -EINVAL;
                        break;
        };

        RETURN(rc);
}

static int ptlbd_bulk_timeout(void *data)
{
/*        struct ptlrpc_bulk_desc *desc = data;*/
        ENTRY;

        CERROR("ugh, timed out\n");

        RETURN(1);
}

#define SILLY_MAX 2048
static struct page *pages[SILLY_MAX] = {NULL,};

static struct page * fake_page(int block_nr)
{
        if ( block_nr >= SILLY_MAX )
                return NULL;

        if (pages[block_nr] == NULL) {
                void *vaddr = (void *)get_free_page(GFP_KERNEL);
                pages[block_nr] = virt_to_page(vaddr);
        } 
        return pages[block_nr];
}

static int ptlbd_put_write(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ptlbd_op *op;
        struct ptlbd_niob *reply_niob, *request_niob;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_bulk_desc *desc;
        struct ptlrpc_service *srv;
        struct l_wait_info lwi;
        int size[2];
        int i, page_count, rc;
        __u32 xid;

        op = lustre_msg_buf(req->rq_reqmsg, 0);
        request_niob = lustre_msg_buf(req->rq_reqmsg, 1);
        page_count = req->rq_reqmsg->buflens[1] / sizeof(struct ptlbd_niob);

        size[0] = sizeof(struct ptlbd_rsp);
        size[1] = sizeof(struct ptlbd_niob) * page_count;
        rc = lustre_pack_msg(2, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                GOTO(out, rc);
        reply_niob = lustre_msg_buf(req->rq_repmsg, 1);

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        desc->bd_ptl_ev_hdlr = NULL;
        desc->bd_portal = PTLBD_BULK_PORTAL;
        memcpy(&(desc->bd_conn), &conn, sizeof(conn)); /* XXX what? */

        srv = req->rq_obd->u.ptlbd.ptlbd_service;
        spin_lock(&srv->srv_lock);
        xid = srv->srv_xid++;                   /* single xid for all pages */
        spin_unlock(&srv->srv_lock);

        for ( i = 0; i < page_count; i++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_desc, rc = -ENOMEM);
                        
                reply_niob[i] = request_niob[i];
                reply_niob[i].n_xid = xid;

                bulk->bp_xid = xid;
                bulk->bp_page = fake_page(request_niob[i].n_block_nr);
                bulk->bp_buf = page_address(bulk->bp_page);
                bulk->bp_buflen = request_niob[i].n_length;
        }

        rc = ptlrpc_register_bulk(desc);
        if ( rc )
                GOTO(out_desc, rc);

        rsp = lustre_msg_buf(req->rq_reqmsg, 0);
        rsp->r_status = 42;
        rsp->r_error_cnt = 13;
        ptlrpc_reply(req->rq_svc, req);

        /* this synchronization probably isn't good enough */
        lwi = LWI_TIMEOUT(obd_timeout * HZ, ptlbd_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, desc->bd_flags &PTL_BULK_FL_RCVD, 
                        &lwi);

out_desc:
        ptlrpc_free_bulk(desc);
out:
        RETURN(rc);
}

static int ptlbd_put_read(struct ptlrpc_request *req)
{
        struct ptlbd_op *op;
        struct ptlbd_niob *niob, *niobs;
        struct ptlbd_rsp *rsp;
        struct ptlrpc_bulk_desc *desc;
        struct l_wait_info lwi;
        int size[1];
        int i, page_count, rc;

        op = lustre_msg_buf(req->rq_reqmsg, 0);
        niobs = lustre_msg_buf(req->rq_reqmsg, 1);
        page_count = req->rq_reqmsg->buflens[1] / sizeof(struct ptlbd_niob);

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        desc->bd_portal = PTLBD_BULK_PORTAL;

        for ( i = 0, niob = niobs ; i < page_count; niob++, i++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_bulk, rc = -ENOMEM);

                /* 
                 * XXX what about the block number? 
                 */
                bulk->bp_xid = niob->n_xid;
                bulk->bp_page = fake_page(niob->n_block_nr);
                bulk->bp_buf = page_address(bulk->bp_page);
                bulk->bp_buflen = niob->n_length;
        }

        rc = ptlrpc_send_bulk(desc);
        if ( rc )
                GOTO(out_bulk, rc);

        /* this synchronization probably isn't good enough */
        lwi = LWI_TIMEOUT(obd_timeout * HZ, ptlbd_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, desc->bd_flags &PTL_BULK_FL_SENT, 
                        &lwi);

        size[0] = sizeof(struct ptlbd_rsp);
        rc = lustre_pack_msg(1, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if ( rc )
                GOTO(out, rc);

        rsp = lustre_msg_buf(req->rq_repmsg, 0);
        if ( rsp == NULL )
                GOTO(out, rc = -EINVAL);

        rsp->r_error_cnt = 42;
        rsp->r_status = 69;

        req->rq_status = 0; /* XXX */
        ptlrpc_reply(req->rq_svc, req);

out_bulk:
        ptlrpc_free_bulk(desc);
out:
        RETURN(rc);
}


int ptlbd_parse_req(struct ptlrpc_request *req)
{
        struct ptlbd_op *op;
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if ( rc )
                RETURN(rc);

        op = lustre_msg_buf(req->rq_reqmsg, 0);

        switch(op->op_cmd) {
                case PTLBD_READ:
                        ptlbd_put_read(req);
                        break;
                case PTLBD_WRITE:
                        ptlbd_put_write(req);
                        break;
                default:
                        CERROR("fix this %d\n", op->op_cmd);
                        break;
        }

        RETURN(0);
}


#if 0
int ptlbd_bh_req(int cmd, struct ptlbd_state *st, struct buffer_head *first_bh)
{
        struct obd_brw_set *set = NULL;
        struct brw_page *pg = NULL;
        struct buffer_head *bh;
        int rc, i, pg_bytes = 0;
        ENTRY;

        for ( bh = first_bh ; bh ; bh = bh->b_reqnext ) 
                pg_bytes += sizeof(struct brw_page);

        OBD_ALLOC(pg, pg_bytes);
        if ( pg == NULL )
                GOTO(out, rc = -ENOMEM);

        set = obd_brw_set_new();
        if (set == NULL)
                GOTO(out, rc = -ENOMEM);

        for ( i = 0, bh = first_bh ; bh ; bh = bh->b_reqnext, i++) {
                pg[i].pg = bh->b_page;
                pg[i].off = bh_offset(bh);
                pg[i].count = bh->b_size;
                pg[i].flag = 0;
        }

        set->brw_callback = ll_brw_sync_wait;
        rc = obd_brw(cmd, /* lsm */NULL, num_pages, pg, set);
        if ( rc )
                GOTO(out, rc);

        rc = ll_brw_sync_wait(set, CB_PHASE_START);
        if (rc)
                CERROR("error from callback: rc = %d\n", rc);

out:
        if ( pg != NULL )
                OBD_FREE(pg, pg_bytes);
        if ( set != NULL )
                obd_brw_set_free(set);

        RETURN(rc); 
}
#endif
