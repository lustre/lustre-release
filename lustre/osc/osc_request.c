/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author Peter Braam <braam@clusterfs.com>
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
 *  For testing and management it is treated as an obd_device,
 *  although * it does not export a full OBD method table (the
 *  requests are coming * in over the wire, so object target modules
 *  do not have a full * method table.)
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/lustre_dlm.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/workqueue.h>
#include <linux/smp_lock.h>
#else
#include <linux/locks.h>
#endif
#else
#include <liblustre.h>
#endif

#include <linux/kp30.h>
#include <linux/lustre_mds.h> /* for mds_objid */
#include <linux/obd_ost.h>
#include <linux/obd_lov.h> /* for IOC_LOV_SET_OSC_ACTIVE */
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/lustre_ha.h>
#include <linux/obd_support.h> /* for OBD_FAIL_CHECK */
#include <linux/lustre_lite.h> /* for ll_i2info */
#include <portals/lib-types.h> /* for PTL_MD_MAX_IOV */
#include <linux/lprocfs_status.h>

/* It is important that ood_fh remain the first item in this structure: that
 * way, we don't have to re-pack the obdo's inline data before we send it to
 * the server, we can just send the whole struct unaltered. */
#define OSC_OBDO_DATA_MAGIC 0xD15EA5ED
struct osc_obdo_data {
        struct lustre_handle ood_fh;
        struct ptlrpc_request *ood_request;
        __u32 ood_magic;
};
#include <linux/obd_lov.h> /* just for the startup assertion; is that wrong? */

static int send_sync(struct obd_import *imp, struct ll_fid *rootfid,
                          int level, int msg_flags)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        req = ptlrpc_prep_req(imp, OST_SYNCFS, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        req->rq_level = level;
        req->rq_replen = lustre_msg_size(1, &size);

        req->rq_reqmsg->flags |= msg_flags;
        rc = ptlrpc_queue_wait(req);

        if (!rc) {
                CDEBUG(D_NET, "last_committed="LPU64
                       ", last_xid="LPU64"\n",
                       req->rq_repmsg->last_committed,
                       req->rq_repmsg->last_xid);
        }

        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

static int signal_completed_replay(struct obd_import *imp)
{
        struct ll_fid fid;

        return send_sync(imp, &fid, LUSTRE_CONN_RECOVD, MSG_LAST_REPLAY);
}

static int osc_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(&lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

static int osc_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

/* Pack OSC object metadata for shipment to the MDS. */
static int osc_packmd(struct lustre_handle *conn, struct lov_mds_md **lmmp,
                      struct lov_stripe_md *lsm)
{
        int lmm_size;
        ENTRY;

        lmm_size = sizeof(**lmmp);
        if (!lmmp)
                RETURN(lmm_size);

        if (*lmmp && !lsm) {
                OBD_FREE(*lmmp, lmm_size);
                *lmmp = NULL;
                RETURN(0);
        }

        if (!*lmmp) {
                OBD_ALLOC(*lmmp, lmm_size);
                if (!*lmmp)
                        RETURN(-ENOMEM);
        }
        if (lsm) {
                LASSERT(lsm->lsm_object_id);
                (*lmmp)->lmm_object_id = (lsm->lsm_object_id);
        }

        RETURN(lmm_size);
}

static int osc_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsmp,
                        struct lov_mds_md *lmm)
{
        int lsm_size;
        ENTRY;

        lsm_size = sizeof(**lsmp);
        if (!lsmp)
                RETURN(lsm_size);

        if (*lsmp && !lmm) {
                OBD_FREE(*lsmp, lsm_size);
                *lsmp = NULL;
                RETURN(0);
        }

        if (!*lsmp) {
                OBD_ALLOC(*lsmp, lsm_size);
                if (!*lsmp)
                        RETURN(-ENOMEM);
        }

        /* XXX endianness */
        if (lmm) {
                (*lsmp)->lsm_object_id = (lmm->lmm_object_id);
                LASSERT((*lsmp)->lsm_object_id);
        }

        RETURN(lsm_size);
}

inline void oti_from_request(struct obd_trans_info *oti,
                             struct ptlrpc_request *req)
{
        if (oti && req->rq_repmsg)
                oti->oti_transno = NTOH__u64(req->rq_repmsg->transno);
        EXIT;
}

static int osc_getattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *md)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_GETATTR, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
#warning FIXME: pack only valid fields instead of memcpy, endianness
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        body = lustre_msg_buf(request->rq_repmsg, 0);
        CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_open(struct lustre_handle *conn, struct obdo *oa,
                    struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_OPEN, 1, &size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_flags |= PTL_RPC_FL_REPLAY;
        body = lustre_msg_buf(request->rq_reqmsg, 0);
#warning FIXME: pack only valid fields instead of memcpy, endianness
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        if (oa) {
                struct osc_obdo_data ood;
                body = lustre_msg_buf(request->rq_repmsg, 0);
                memcpy(oa, &body->oa, sizeof(*oa));

                /* If the open succeeded, we better have a handle */
                /* BlueArc OSTs don't send back (o_valid | FLHANDLE).  sigh.
                 * Temporary workaround until fixed. -phil 24 Feb 03 */
                //LASSERT(oa->o_valid & OBD_MD_FLHANDLE);
                oa->o_valid |= OBD_MD_FLHANDLE;

                memcpy(&ood.ood_fh, obdo_handle(oa), sizeof(ood.ood_fh));
                ood.ood_request = ptlrpc_request_addref(request);
                ood.ood_magic = OSC_OBDO_DATA_MAGIC;

                /* Save this data in the request; it will be passed back to us
                 * in future obdos.  This memcpy is guaranteed to be safe,
                 * because we check at compile-time that sizeof(ood) is smaller
                 * than oa->o_inline. */
                memcpy(&oa->o_inline, &ood, sizeof(ood));
        }

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_close(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct obd_import *import = class_conn2cliimp(conn);
        struct ptlrpc_request *request;
        struct ost_body *body;
        struct osc_obdo_data *ood;
        unsigned long flags;
        int rc, size = sizeof(*body);
        ENTRY;

        LASSERT(oa != NULL);
        ood = (struct osc_obdo_data *)&oa->o_inline;
        LASSERT(ood->ood_magic == OSC_OBDO_DATA_MAGIC);

        request = ptlrpc_prep_req(import, OST_CLOSE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
#warning FIXME: pack only valid fields instead of memcpy, endianness
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc) {
                /* FIXME: Does this mean that the file is still open locally?
                 * If not, and I somehow suspect not, we need to cleanup
                 * below */
                GOTO(out, rc);
        }

        spin_lock_irqsave(&import->imp_lock, flags);
        ood->ood_request->rq_flags &= ~PTL_RPC_FL_REPLAY;
        /* see comments in llite/file.c:ll_mdc_close() */
        if (ood->ood_request->rq_transno) {
                LBUG(); /* this can't happen yet */
                if (!request->rq_transno) {
                        request->rq_transno = ood->ood_request->rq_transno;
                        ptlrpc_retain_replayable_request(request, import);
                }
                spin_unlock_irqrestore(&import->imp_lock, flags);
        } else {
                spin_unlock_irqrestore(&import->imp_lock, flags);
                ptlrpc_req_finished(ood->ood_request);
        }

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_setattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_SETATTR, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);

        ptlrpc_req_finished(request);
        return rc;
}

static int osc_create(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti_in)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        struct lov_stripe_md *lsm;
        struct obd_trans_info *oti, trans_info;
        int rc, size = sizeof(*body);
        ENTRY;

        LASSERT(oa);
        LASSERT(ea);

        lsm = *ea;
        if (!lsm) {
                rc = obd_alloc_memmd(conn, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

        if (oti_in)
                oti = oti_in;
        else
                oti = &trans_info;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_CREATE, 1, &size,
                                  NULL);
        if (!request)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        lsm->lsm_object_id = oa->o_id;
        lsm->lsm_stripe_count = 0;
        *ea = lsm;

        oti_from_request(oti, request);
        CDEBUG(D_HA, "transno: "LPD64"\n", oti->oti_transno);
        EXIT;
out_req:
        ptlrpc_req_finished(request);
out:
        if (rc && !*ea)
                obd_free_memmd(conn, &lsm);
        return rc;
}

static int osc_punch(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md, obd_size start,
                     obd_size end, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_PUNCH, 1, &size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
#warning FIXME: pack only valid fields instead of memcpy, endianness, valid
        memcpy(&body->oa, oa, sizeof(*oa));

        /* overload the size and blocks fields in the oa with start/end */
        body->oa.o_size = HTON__u64(start);
        body->oa.o_blocks = HTON__u64(end);
        body->oa.o_valid |= HTON__u32(OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_destroy(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_DESTROY, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
#warning FIXME: pack only valid fields instead of memcpy, endianness
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

/* Our bulk-unmapping bottom half. */
static void unmap_and_decref_bulk_desc(void *data)
{
        struct ptlrpc_bulk_desc *desc = data;
        struct list_head *tmp;
        ENTRY;

        list_for_each(tmp, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                kunmap(bulk->bp_page);
                obd_kmap_put(1);
        }

        ptlrpc_bulk_decref(desc);
        EXIT;
}


/*  this is the callback function which is invoked by the Portals
 *  event handler associated with the bulk_sink queue and bulk_source queue.
 */
static void osc_ptl_ev_hdlr(struct ptlrpc_bulk_desc *desc)
{
        ENTRY;

        LASSERT(desc->bd_brw_set != NULL);
        LASSERT(desc->bd_brw_set->brw_callback != NULL);

        desc->bd_brw_set->brw_callback(desc->bd_brw_set, CB_PHASE_FINISH);

        /* We can't kunmap the desc from interrupt context, so we do it from
         * the bottom half above. */
        prepare_work(&desc->bd_queue, unmap_and_decref_bulk_desc, desc);
        schedule_work(&desc->bd_queue);

        EXIT;
}

/*
 * This is called when there was a bulk error return.  However, we don't know
 * whether the bulk completed or not.  We cancel the portals bulk descriptors,
 * so that if the OST decides to send them later we don't double free.  Then
 * remove this descriptor from the set so that the set callback doesn't wait
 * forever for the last CB_PHASE_FINISH to be called, and finally dump all of
 * the bulk descriptor references.
 */
static void osc_ptl_ev_abort(struct ptlrpc_bulk_desc *desc)
{
        ENTRY;

        LASSERT(desc->bd_brw_set != NULL);

        ptlrpc_abort_bulk(desc);
        obd_brw_set_del(desc);
        unmap_and_decref_bulk_desc(desc);

        EXIT;
}

static int osc_brw_read(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                        obd_count page_count, struct brw_page *pga,
                        struct obd_brw_set *set)
{
        struct obd_import *imp = class_conn2cliimp(conn);
        struct ptlrpc_connection *connection = imp->imp_connection;
        struct ptlrpc_request *request = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ost_body *body;
        int rc, size[3] = {sizeof(*body)}, mapped = 0;
        struct obd_ioobj *iooptr;
        void *nioptr;
        __u32 xid;
        ENTRY;

restart_bulk:
        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(struct niobuf_remote);

        request = ptlrpc_prep_req(imp, OST_READ, 3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->oa.o_valid = HTON__u32(OBD_MD_FLCKSUM * CHECKSUM_BULK);

        desc = ptlrpc_prep_bulk(connection);
        if (!desc)
                GOTO(out_req, rc = -ENOMEM);
        desc->bd_portal = OST_BULK_PORTAL;
        desc->bd_ptl_ev_hdlr = osc_ptl_ev_hdlr;
        CDEBUG(D_PAGE, "desc = %p\n", desc);

        iooptr = lustre_msg_buf(request->rq_reqmsg, 1);
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2);
        ost_pack_ioo(&iooptr, lsm, page_count);
        /* end almost identical to brw_write case */

        xid = ptlrpc_next_xid();       /* single xid for all pages */

        obd_kmap_get(page_count, 0);

        for (mapped = 0; mapped < page_count; mapped++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL) {
                        unmap_and_decref_bulk_desc(desc);
                        GOTO(out_req, rc = -ENOMEM);
                }

                bulk->bp_xid = xid;           /* single xid for all pages */

                bulk->bp_buf = kmap(pga[mapped].pg);
                bulk->bp_page = pga[mapped].pg;
                bulk->bp_buflen = PAGE_SIZE;
                ost_pack_niobuf(&nioptr, pga[mapped].off, pga[mapped].count,
                                pga[mapped].flag, bulk->bp_xid);
        }

        /*
         * Register the bulk first, because the reply could arrive out of order,
         * and we want to be ready for the bulk data.
         *
         * One reference is released when osc_ptl_ev_hdlr() is called by
         * portals, the other when the caller removes us from the "set" list.
         *
         * On error, we never do the brw_finish, so we handle all decrefs.
         */
        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_BRW_READ_BULK)) {
                CERROR("obd_fail_loc=%x, skipping register_bulk\n",
                       OBD_FAIL_OSC_BRW_READ_BULK);
        } else {
                rc = ptlrpc_register_bulk_put(desc);
                if (rc) {
                        unmap_and_decref_bulk_desc(desc);
                        GOTO(out_req, rc);
                }
                obd_brw_set_add(set, desc);
        }

        request->rq_flags |= PTL_RPC_FL_NO_RESEND;
        request->rq_replen = lustre_msg_size(1, size);
        rc = ptlrpc_queue_wait(request);

        /* XXX bug 937 here */
        if (rc == -ETIMEDOUT && (request->rq_flags & PTL_RPC_FL_RESEND)) {
                DEBUG_REQ(D_HA, request,  "BULK TIMEOUT");
                ptlrpc_req_finished(request);
                goto restart_bulk;
        }

        if (rc) {
                osc_ptl_ev_abort(desc);
                GOTO(out_req, rc);
        }

#if CHECKSUM_BULK
        body = lustre_msg_buf(request->rq_repmsg, 0);
        if (body->oa.o_valid & NTOH__u32(OBD_MD_FLCKSUM)) {
                static int cksum_counter;
                __u64 server_cksum = NTOH__u64(body->oa.o_rdev);
                __u64 cksum = 0;

                for (mapped = 0; mapped < page_count; mapped++) {
                        char *ptr = kmap(pga[mapped].pg);
                        int   off = pga[mapped].off & (PAGE_SIZE - 1);
                        int   len = pga[mapped].count;

                        LASSERT(off + len <= PAGE_SIZE);
                        ost_checksum(&cksum, ptr + off, len);
                        kunmap(pga[mapped].pg);
                }

                cksum_counter++;
                if (server_cksum != cksum) {
                        CERROR("Bad checksum: server "LPX64", client "LPX64
                               ", server NID "LPX64"\n", server_cksum, cksum,
                               imp->imp_connection->c_peer.peer_nid);
                        cksum_counter = 0;
                } else if ((cksum_counter & (-cksum_counter)) == cksum_counter)
                        CERROR("Checksum %u from "LPX64" OK: "LPX64"\n",
                               cksum_counter,
                               imp->imp_connection->c_peer.peer_nid, cksum);
        } else {
                static int cksum_missed;
                cksum_missed++;
                if ((cksum_missed & (-cksum_missed)) == cksum_missed)
                        CERROR("Request checksum %u from "LPX64", no reply\n",
                               cksum_missed,
                               imp->imp_connection->c_peer.peer_nid);
        }
#endif

        EXIT;
 out_req:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_brw_write(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                         obd_count page_count, struct brw_page *pga,
                         struct obd_brw_set *set, struct obd_trans_info *oti)
{
        struct obd_import *imp = class_conn2cliimp(conn);
        struct ptlrpc_connection *connection = imp->imp_connection;
        struct ptlrpc_request *request = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ost_body *body;
        int rc, size[3] = {sizeof(*body)}, mapped = 0;
        struct obd_ioobj *iooptr;
        void *nioptr;
        __u32 xid;
#if CHECKSUM_BULK
        __u64 cksum = 0;
#endif
        ENTRY;

restart_bulk:
        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(struct niobuf_remote);

        request = ptlrpc_prep_req(imp, OST_WRITE, 3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);

        desc = ptlrpc_prep_bulk(connection);
        if (!desc)
                GOTO(out_req, rc = -ENOMEM);
        desc->bd_portal = OSC_BULK_PORTAL;
        desc->bd_ptl_ev_hdlr = osc_ptl_ev_hdlr;
        CDEBUG(D_PAGE, "desc = %p\n", desc);

        iooptr = lustre_msg_buf(request->rq_reqmsg, 1);
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2);
        ost_pack_ioo(&iooptr, lsm, page_count);
        /* end almost identical to brw_read case */

        xid = ptlrpc_next_xid();       /* single xid for all pages */

        obd_kmap_get(page_count, 0);

        for (mapped = 0; mapped < page_count; mapped++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL) {
                        unmap_and_decref_bulk_desc(desc);
                        GOTO(out_req, rc = -ENOMEM);
                }

                bulk->bp_xid = xid;           /* single xid for all pages */

                bulk->bp_buf = kmap(pga[mapped].pg);
                bulk->bp_page = pga[mapped].pg;
                bulk->bp_buflen = pga[mapped].count;
                ost_pack_niobuf(&nioptr, pga[mapped].off, pga[mapped].count,
                                pga[mapped].flag, bulk->bp_xid);
                ost_checksum(&cksum, bulk->bp_buf, bulk->bp_buflen);
        }

#if CHECKSUM_BULK
        body->oa.o_rdev = HTON__u64(cksum);
        body->oa.o_valid |= HTON__u32(OBD_MD_FLCKSUM);
#endif
        /*
         * Register the bulk first, because the reply could arrive out of
         * order, and we want to be ready for the bulk data.
         *
         * One reference is released when brw_finish is complete, the other
         * when the caller removes us from the "set" list.
         *
         * On error, we never do the brw_finish, so we handle all decrefs.
         */
        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_BRW_WRITE_BULK)) {
                CERROR("obd_fail_loc=%x, skipping register_bulk\n",
                       OBD_FAIL_OSC_BRW_WRITE_BULK);
        } else {
                rc = ptlrpc_register_bulk_get(desc);
                if (rc) {
                        unmap_and_decref_bulk_desc(desc);
                        GOTO(out_req, rc);
                }
                obd_brw_set_add(set, desc);
        }

        request->rq_flags |= PTL_RPC_FL_NO_RESEND;
        request->rq_replen = lustre_msg_size(1, size);
        rc = ptlrpc_queue_wait(request);

        /* XXX bug 937 here */
        if (rc == -ETIMEDOUT && (request->rq_flags & PTL_RPC_FL_RESEND)) {
                DEBUG_REQ(D_HA, request,  "BULK TIMEOUT");
                ptlrpc_req_finished(request);
                goto restart_bulk;
        }

        if (rc) {
                osc_ptl_ev_abort(desc);
                GOTO(out_req, rc);
        }

        EXIT;
 out_req:
        ptlrpc_req_finished(request);
        return rc;
}

#ifndef min_t
#define min_t(a,b,c) ( b<c ) ? b : c
#endif

#warning "FIXME: make values dynamic based on get_info at setup (bug 665)"
#define OSC_BRW_MAX_SIZE 65536
#define OSC_BRW_MAX_IOV min_t(int, PTL_MD_MAX_IOV, OSC_BRW_MAX_SIZE/PAGE_SIZE)

static int osc_brw(int cmd, struct lustre_handle *conn,
                   struct lov_stripe_md *md, obd_count page_count,
                   struct brw_page *pga, struct obd_brw_set *set,
                   struct obd_trans_info *oti)
{
        ENTRY;

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > OSC_BRW_MAX_IOV)
                        pages_per_brw = OSC_BRW_MAX_IOV;
                else
                        pages_per_brw = page_count;

                if (cmd & OBD_BRW_WRITE)
                        rc = osc_brw_write(conn, md, pages_per_brw, pga,
                                           set, oti);
                else
                        rc = osc_brw_read(conn, md, pages_per_brw, pga, set);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}

#ifdef __KERNEL__
/* Note: caller will lock/unlock, and set uptodate on the pages */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int sanosc_brw_read(struct lustre_handle *conn,
                           struct lov_stripe_md *md,
                           obd_count page_count,
                           struct brw_page *pga,
                           struct obd_brw_set *set)
{
        struct ptlrpc_request *request = NULL;
        struct ost_body *body;
        struct niobuf_remote *remote, *nio_rep;
        int rc, j, size[3] = {sizeof(*body)}, mapped = 0;
        struct obd_ioobj *iooptr;
        void *nioptr;
        ENTRY;

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(*remote);

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_SAN_READ, 3,
                                  size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        iooptr = lustre_msg_buf(request->rq_reqmsg, 1);
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2);
        ost_pack_ioo(&iooptr, md, page_count);

        obd_kmap_get(page_count, 0);

        for (mapped = 0; mapped < page_count; mapped++) {
                LASSERT(PageLocked(pga[mapped].pg));

                kmap(pga[mapped].pg);
                ost_pack_niobuf(&nioptr, pga[mapped].off, pga[mapped].count,
                                pga[mapped].flag, 0);
        }

        size[1] = page_count * sizeof(*remote);
        request->rq_replen = lustre_msg_size(2, size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_unmap, rc);

        nioptr = lustre_msg_buf(request->rq_repmsg, 1);
        if (!nioptr)
                GOTO(out_unmap, rc = -EINVAL);

        if (request->rq_repmsg->buflens[1] != size[1]) {
                CERROR("buffer length wrong (%d vs. %d)\n",
                       request->rq_repmsg->buflens[1], size[1]);
                GOTO(out_unmap, rc = -EINVAL);
        }

        for (j = 0; j < page_count; j++) {
                ost_unpack_niobuf(&nioptr, &remote);
        }

        nioptr = lustre_msg_buf(request->rq_repmsg, 1);
        nio_rep = (struct niobuf_remote*)nioptr;

        /* actual read */
        for (j = 0; j < page_count; j++) {
                struct page *page = pga[j].pg;
                struct buffer_head *bh;
                kdev_t dev;

                /* got san device associated */
                LASSERT(class_conn2obd(conn));
                dev = class_conn2obd(conn)->u.cli.cl_sandev;

                /* hole */
                if (!nio_rep[j].offset) {
                        CDEBUG(D_PAGE, "hole at ino %lu; index %ld\n",
                                        page->mapping->host->i_ino,
                                        page->index);
                        memset(page_address(page), 0, PAGE_SIZE);
                        continue;
                }

                if (!page->buffers) {
                        create_empty_buffers(page, dev, PAGE_SIZE);
                        bh = page->buffers;

                        clear_bit(BH_New, &bh->b_state);
                        set_bit(BH_Mapped, &bh->b_state);
                        bh->b_blocknr = (unsigned long)nio_rep[j].offset;

                        clear_bit(BH_Uptodate, &bh->b_state);

                        ll_rw_block(READ, 1, &bh);
                } else {
                        bh = page->buffers;

                        /* if buffer already existed, it must be the
                         * one we mapped before, check it */
                        LASSERT(!test_bit(BH_New, &bh->b_state));
                        LASSERT(test_bit(BH_Mapped, &bh->b_state));
                        LASSERT(bh->b_blocknr ==
                                (unsigned long)nio_rep[j].offset);

                        /* wait it's io completion */
                        if (test_bit(BH_Lock, &bh->b_state))
                                wait_on_buffer(bh);

                        if (!test_bit(BH_Uptodate, &bh->b_state))
                                ll_rw_block(READ, 1, &bh);
                }


                /* must do syncronous write here */
                wait_on_buffer(bh);
                if (!buffer_uptodate(bh)) {
                        /* I/O error */
                        rc = -EIO;
                        goto out_unmap;
                }
        }

out_req:
        ptlrpc_req_finished(request);
        RETURN(rc);

out_unmap:
        /* Clean up on error. */
        while (mapped-- > 0)
                kunmap(pga[mapped].pg);

        obd_kmap_put(page_count);

        goto out_req;
}

static int sanosc_brw_write(struct lustre_handle *conn,
                            struct lov_stripe_md *md,
                            obd_count page_count,
                            struct brw_page *pga,
                            struct obd_brw_set *set)
{
        struct ptlrpc_request *request = NULL;
        struct ost_body *body;
        struct niobuf_remote *remote, *nio_rep;
        int rc, j, size[3] = {sizeof(*body)}, mapped = 0;
        struct obd_ioobj *iooptr;
        void *nioptr;
        ENTRY;

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(*remote);

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_SAN_WRITE,
                                  3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        iooptr = lustre_msg_buf(request->rq_reqmsg, 1);
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2);
        ost_pack_ioo(&iooptr, md, page_count);

        /* map pages, and pack request */
        obd_kmap_get(page_count, 0);
        for (mapped = 0; mapped < page_count; mapped++) {
                LASSERT(PageLocked(pga[mapped].pg));

                kmap(pga[mapped].pg);
                ost_pack_niobuf(&nioptr, pga[mapped].off, pga[mapped].count,
                                pga[mapped].flag, 0);
        }

        size[1] = page_count * sizeof(*remote);
        request->rq_replen = lustre_msg_size(2, size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_unmap, rc);

        nioptr = lustre_msg_buf(request->rq_repmsg, 1);
        if (!nioptr)
                GOTO(out_unmap, rc = -EINVAL);

        if (request->rq_repmsg->buflens[1] != size[1]) {
                CERROR("buffer length wrong (%d vs. %d)\n",
                       request->rq_repmsg->buflens[1], size[1]);
                GOTO(out_unmap, rc = -EINVAL);
        }

        for (j = 0; j < page_count; j++) {
                ost_unpack_niobuf(&nioptr, &remote);
        }

        nioptr = lustre_msg_buf(request->rq_repmsg, 1);
        nio_rep = (struct niobuf_remote*)nioptr;

        /* actual write */
        for (j = 0; j < page_count; j++) {
                struct page *page = pga[j].pg;
                struct buffer_head *bh;
                kdev_t dev;

                /* got san device associated */
                LASSERT(class_conn2obd(conn));
                dev = class_conn2obd(conn)->u.cli.cl_sandev;

                if (!page->buffers) {
                        create_empty_buffers(page, dev, PAGE_SIZE);
                } else {
                        /* checking */
                        LASSERT(!test_bit(BH_New, &page->buffers->b_state));
                        LASSERT(test_bit(BH_Mapped, &page->buffers->b_state));
                        LASSERT(page->buffers->b_blocknr ==
                                (unsigned long)nio_rep[j].offset);
                }
                bh = page->buffers;

                LASSERT(bh);

                /* if buffer locked, wait it's io completion */
                if (test_bit(BH_Lock, &bh->b_state))
                        wait_on_buffer(bh);

                clear_bit(BH_New, &bh->b_state);
                set_bit(BH_Mapped, &bh->b_state);

                /* override the block nr */
                bh->b_blocknr = (unsigned long)nio_rep[j].offset;

                /* we are about to write it, so set it
                 * uptodate/dirty
                 * page lock should garentee no race condition here */
                set_bit(BH_Uptodate, &bh->b_state);
                set_bit(BH_Dirty, &bh->b_state);

                ll_rw_block(WRITE, 1, &bh);

                /* must do syncronous write here */
                wait_on_buffer(bh);
                if (!buffer_uptodate(bh) || test_bit(BH_Dirty, &bh->b_state)) {
                        /* I/O error */
                        rc = -EIO;
                        goto out_unmap;
                }
        }

out_req:
        ptlrpc_req_finished(request);
        RETURN(rc);

out_unmap:
        /* Clean up on error. */
        while (mapped-- > 0)
                kunmap(pga[mapped].pg);

        obd_kmap_put(page_count);

        goto out_req;
}
#else
static int sanosc_brw_read(struct lustre_handle *conn,
                           struct lov_stripe_md *md,
                           obd_count page_count,
                           struct brw_page *pga,
                           struct obd_brw_set *set)
{
        LBUG();
        return 0;
}

static int sanosc_brw_write(struct lustre_handle *conn,
                            struct lov_stripe_md *md,
                            obd_count page_count,
                            struct brw_page *pga,
                            struct obd_brw_set *set)
{
        LBUG();
        return 0;
}
#endif

static int sanosc_brw(int cmd, struct lustre_handle *conn,
                      struct lov_stripe_md *md, obd_count page_count,
                      struct brw_page *pga, struct obd_brw_set *set,
                      struct obd_trans_info *oti)
{
        ENTRY;

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > OSC_BRW_MAX_IOV)
                        pages_per_brw = OSC_BRW_MAX_IOV;
                else
                        pages_per_brw = page_count;

                if (cmd & OBD_BRW_WRITE)
                        rc = sanosc_brw_write(conn, md, pages_per_brw,
                                              pga, set);
                else
                        rc = sanosc_brw_read(conn, md, pages_per_brw, pga, set);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}
#endif

static int osc_enqueue(struct lustre_handle *connh, struct lov_stripe_md *lsm,
                       struct lustre_handle *parent_lock,
                       __u32 type, void *extentp, int extent_len, __u32 mode,
                       int *flags, void *callback, void *data, int datalen,
                       struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };
        struct obd_device *obddev = class_conn2obd(connh);
        struct ldlm_extent *extent = extentp;
        int rc;
        ENTRY;

        /* Filesystem locks are given a bit of special treatment: if
         * this is not a file size lock (which has end == -1), we
         * fixup the lock to start and end on page boundaries. */
        if (extent->end != OBD_OBJECT_EOF) {
                extent->start &= PAGE_MASK;
                extent->end = (extent->end & PAGE_MASK) + PAGE_SIZE - 1;
        }

        /* Next, search for already existing extent locks that will cover us */
        rc = ldlm_lock_match(obddev->obd_namespace, 0, &res_id, type, extent,
                             sizeof(extent), mode, lockh);
        if (rc == 1)
                /* We already have a lock, and it's referenced */
                RETURN(ELDLM_OK);

        /* If we're trying to read, we also search for an existing PW lock.  The
         * VFS and page cache already protect us locally, so lots of readers/
         * writers can share a single PW lock.
         *
         * There are problems with conversion deadlocks, so instead of
         * converting a read lock to a write lock, we'll just enqueue a new
         * one.
         *
         * At some point we should cancel the read lock instead of making them
         * send us a blocking callback, but there are problems with canceling
         * locks out from other users right now, too. */

        if (mode == LCK_PR) {
                rc = ldlm_lock_match(obddev->obd_namespace, 0, &res_id, type,
                                     extent, sizeof(extent), LCK_PW, lockh);
                if (rc == 1) {
                        /* FIXME: This is not incredibly elegant, but it might
                         * be more elegant than adding another parameter to
                         * lock_match.  I want a second opinion. */
                        ldlm_lock_addref(lockh, LCK_PR);
                        ldlm_lock_decref(lockh, LCK_PW);

                        RETURN(ELDLM_OK);
                }
        }

        rc = ldlm_cli_enqueue(connh, NULL, obddev->obd_namespace, parent_lock,
                              res_id, type, extent, sizeof(extent), mode, flags,
                              ldlm_completion_ast, callback, data, NULL,
                              lockh);
        RETURN(rc);
}

static int osc_cancel(struct lustre_handle *oconn, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static int osc_cancel_unused(struct lustre_handle *connh,
                             struct lov_stripe_md *lsm, int flags)
{
        struct obd_device *obddev = class_conn2obd(connh);
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };

        return ldlm_cli_cancel_unused(obddev->obd_namespace, &res_id, flags);
}

static int osc_statfs(struct lustre_handle *conn, struct obd_statfs *osfs)
{
        struct ptlrpc_request *request;
        int rc, size = sizeof(*osfs);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_STATFS, 0, NULL,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        obd_statfs_unpack(osfs, lustre_msg_buf(request->rq_repmsg, 0));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

/* Retrieve object striping information.
 *
 * @lmmu is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_MAGIC (we only use 1 slot here).
 */
static int osc_getstripe(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                         struct lov_mds_md *lmmu)
{
        struct lov_mds_md lmm, *lmmk;
        int rc, lmm_size;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        rc = copy_from_user(&lmm, lmmu, sizeof(lmm));
        if (rc)
                RETURN(-EFAULT);

        if (lmm.lmm_magic != LOV_MAGIC)
                RETURN(-EINVAL);

        if (lmm.lmm_ost_count < 1)
                RETURN(-EOVERFLOW);

        lmm_size = sizeof(lmm) + sizeof(lmm.lmm_objects[0]);
        OBD_ALLOC(lmmk, lmm_size);
        if (rc < 0)
                RETURN(rc);

        lmmk->lmm_stripe_count = 1;
        lmmk->lmm_ost_count = 1;
        lmmk->lmm_object_id = lsm->lsm_object_id;
        lmmk->lmm_objects[0].l_object_id = lsm->lsm_object_id;

        if (copy_to_user(lmmu, lmmk, lmm_size))
                rc = -EFAULT;

        OBD_FREE(lmmk, lmm_size);

        RETURN(rc);
}

static int osc_iocontrol(unsigned int cmd, struct lustre_handle *conn, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        int err = 0;
        ENTRY;

        switch (cmd) {
#if 0
        case IOC_LDLM_TEST: {
                err = ldlm_test(obddev, conn);
                CERROR("-- done err %d\n", err);
                GOTO(out, err);
        }
        case IOC_LDLM_REGRESS_START: {
                unsigned int numthreads = 1;
                unsigned int numheld = 10;
                unsigned int numres = 10;
                unsigned int numext = 10;
                char *parse;

                if (data->ioc_inllen1) {
                        parse = data->ioc_inlbuf1;
                        if (*parse != '\0') {
                                while(isspace(*parse)) parse++;
                                numthreads = simple_strtoul(parse, &parse, 0);
                                while(isspace(*parse)) parse++;
                        }
                        if (*parse != '\0') {
                                while(isspace(*parse)) parse++;
                                numheld = simple_strtoul(parse, &parse, 0);
                                while(isspace(*parse)) parse++;
                        }
                        if (*parse != '\0') {
                                while(isspace(*parse)) parse++;
                                numres = simple_strtoul(parse, &parse, 0);
                                while(isspace(*parse)) parse++;
                        }
                        if (*parse != '\0') {
                                while(isspace(*parse)) parse++;
                                numext = simple_strtoul(parse, &parse, 0);
                                while(isspace(*parse)) parse++;
                        }
                }

                err = ldlm_regression_start(obddev, conn, numthreads,
                                numheld, numres, numext);

                CERROR("-- done err %d\n", err);
                GOTO(out, err);
        }
        case IOC_LDLM_REGRESS_STOP: {
                err = ldlm_regression_stop();
                CERROR("-- done err %d\n", err);
                GOTO(out, err);
        }
#endif
        case IOC_OSC_REGISTER_LOV: {
                if (obddev->u.cli.cl_containing_lov)
                        GOTO(out, err = -EALREADY);
                obddev->u.cli.cl_containing_lov = (struct obd_device *)karg;
                GOTO(out, err);
        }
        case OBD_IOC_LOV_GET_CONFIG: {
                char *buf;
                struct lov_desc *desc;
                struct obd_uuid uuid;

                buf = NULL;
                len = 0;
                if (obd_ioctl_getdata(&buf, &len, (void *)uarg))
                        GOTO(out, err = -EINVAL);

                data = (struct obd_ioctl_data *)buf;

                if (sizeof(*desc) > data->ioc_inllen1) {
                        OBD_FREE(buf, len);
                        GOTO(out, err = -EINVAL);
                }

                if (data->ioc_inllen2 < sizeof(uuid)) {
                        OBD_FREE(buf, len);
                        GOTO(out, err = -EINVAL);
                }

                desc = (struct lov_desc *)data->ioc_inlbuf1;
                desc->ld_tgt_count = 1;
                desc->ld_active_tgt_count = 1;
                desc->ld_default_stripe_count = 1;
                desc->ld_default_stripe_size = 0;
                desc->ld_default_stripe_offset = 0;
                desc->ld_pattern = 0;
                memcpy(&desc->ld_uuid, &obddev->obd_uuid, sizeof(uuid));

                memcpy(data->ioc_inlbuf2, &obddev->obd_uuid, sizeof(uuid));

                err = copy_to_user((void *)uarg, buf, len);
                if (err)
                        err = -EFAULT;
                OBD_FREE(buf, len);
                GOTO(out, err);
        }
        case LL_IOC_LOV_SETSTRIPE:
                err = obd_alloc_memmd(conn, karg);
                if (err > 0)
                        err = 0;
                GOTO(out, err);
        case LL_IOC_LOV_GETSTRIPE:
                err = osc_getstripe(conn, karg, uarg);
                GOTO(out, err);
        default:
                CERROR ("osc_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO(out, err = -ENOTTY);
        }
out:
        return err;
}

static void set_osc_active(struct obd_import *imp, int active)
{
        struct obd_device *notify_obd;

        LASSERT(imp->imp_obd);

        notify_obd = imp->imp_obd->u.cli.cl_containing_lov;

        if (notify_obd == NULL)
                return;

        /* How gross is _this_? */
        if (!list_empty(&notify_obd->obd_exports)) {
                int rc;
                struct lustre_handle fakeconn;
                struct obd_ioctl_data ioc_data = { 0 };
                struct obd_export *exp =
                        list_entry(notify_obd->obd_exports.next,
                                   struct obd_export, exp_obd_chain);

                fakeconn.addr = (__u64)(unsigned long)exp;
                fakeconn.cookie = exp->exp_cookie;
                ioc_data.ioc_inlbuf1 =
                        (char *)&imp->imp_obd->u.cli.cl_target_uuid;
                ioc_data.ioc_offset = active;
                rc = obd_iocontrol(IOC_LOV_SET_OSC_ACTIVE, &fakeconn,
                                   sizeof ioc_data, &ioc_data, NULL);
                if (rc)
                        CERROR("error disabling %s on LOV %p/%s: %d\n",
                               imp->imp_obd->u.cli.cl_target_uuid.uuid,
                               notify_obd, notify_obd->obd_uuid.uuid, rc);
        } else {
                CDEBUG(D_HA, "No exports for obd %p/%s, can't notify about "
                       "%p\n", notify_obd, notify_obd->obd_uuid.uuid,
                       imp->imp_obd->obd_uuid.uuid);
        }
}

static int osc_recover(struct obd_import *imp, int phase)
{
        int rc;
        unsigned long flags;
        int msg_flags;
        struct ptlrpc_request *req;
        struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
        ENTRY;

        CDEBUG(D_HA, "%s: entering phase: %d\n",
               imp->imp_obd->obd_name, phase);
        switch(phase) {

            case PTLRPC_RECOVD_PHASE_PREPARE: {
                if (imp->imp_flags & IMP_REPLAYABLE) {
                        CDEBUG(D_HA, "failover OST\n");
                        /* If we're a failover OSC/OST, just cancel unused
                         * locks to simplify lock replay.
                         */
                        ldlm_cli_cancel_unused(ns, NULL, LDLM_FL_LOCAL_ONLY);
                } else {
                        CDEBUG(D_HA, "non-failover OST\n");
                        /* Non-failover OSTs (LLNL scenario) disable the OSC
                         * and invalidate local state.
                         */
                        ldlm_namespace_cleanup(ns, 1 /* no network ops */);
                        ptlrpc_abort_inflight(imp, 0);
                        set_osc_active(imp, 0 /* inactive */);
                }
                RETURN(0);
            }

        case PTLRPC_RECOVD_PHASE_RECOVER: {
        reconnect:
                imp->imp_flags &= ~IMP_INVALID;
                rc = ptlrpc_reconnect_import(imp, OST_CONNECT, &req);

                msg_flags = req->rq_repmsg
                        ? lustre_msg_get_op_flags(req->rq_repmsg)
                        : 0;

                if (rc == -EBUSY && (msg_flags & MSG_CONNECT_RECOVERING))
                        CERROR("reconnect denied by recovery; should retry\n");

                if (rc) {
                        if (phase != PTLRPC_RECOVD_PHASE_NOTCONN) {
                                CERROR("can't reconnect, invalidating\n");
                                ldlm_namespace_cleanup(ns, 1);
                                ptlrpc_abort_inflight(imp, 0);
                        }
                        imp->imp_flags |= IMP_INVALID;
                        ptlrpc_req_finished(req);
                        RETURN(rc);
                }

                if (msg_flags & MSG_CONNECT_RECOVERING) {
                        /* Replay if they want it. */
                        DEBUG_REQ(D_HA, req, "OST wants replay");
                        rc = ptlrpc_replay(imp);
                        if (rc)
                                GOTO(check_rc, rc);

                        rc = ldlm_replay_locks(imp);
                        if (rc)
                                GOTO(check_rc, rc);

                        rc = signal_completed_replay(imp);
                        if (rc)
                                GOTO(check_rc, rc);
                } else if (msg_flags & MSG_CONNECT_RECONNECT) {
                        DEBUG_REQ(D_HA, req, "reconnecting to MDS\n");
                        /* Nothing else to do here. */
                } else {
                        DEBUG_REQ(D_HA, req, "evicted: invalidating\n");
                        /* Otherwise, clean everything up. */
                        ldlm_namespace_cleanup(ns, 1);
                        ptlrpc_abort_inflight(imp, 0);
                }

                ptlrpc_req_finished(req);

                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_level = LUSTRE_CONN_FULL;
                imp->imp_flags &= ~IMP_INVALID;
                spin_unlock_irqrestore(&imp->imp_lock, flags);

                /* Is this the right place?  Should we do this in _PREPARE
                 * as well?  What about raising the level right away?
                 */
                ptlrpc_wake_delayed(imp);

                rc = ptlrpc_resend(imp);
                if (rc)
                        GOTO(check_rc, rc);

                set_osc_active(imp, 1 /* active */);
                RETURN(0);

        check_rc:
                /* If we get disconnected in the middle, recovery has probably
                 * failed.  Reconnect and find out.
                 */
                if (rc == -ENOTCONN)
                        goto reconnect;
                RETURN(rc);
        }
            case PTLRPC_RECOVD_PHASE_NOTCONN:
                osc_recover(imp, PTLRPC_RECOVD_PHASE_PREPARE);
                RETURN(osc_recover(imp, PTLRPC_RECOVD_PHASE_RECOVER));

            default:
                RETURN(-EINVAL);
        }
}

static int osc_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct obd_import *imp = &obd->u.cli.cl_import;
        imp->imp_recover = osc_recover;
        return client_obd_connect(conn, obd, cluuid, recovd, recover);
}

struct obd_ops osc_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       osc_attach,
        o_detach:       osc_detach,
        o_setup:        client_obd_setup,
        o_cleanup:      client_obd_cleanup,
        o_connect:      osc_connect,
        o_disconnect:   client_obd_disconnect,
        o_statfs:       osc_statfs,
        o_packmd:       osc_packmd,
        o_unpackmd:     osc_unpackmd,
        o_create:       osc_create,
        o_destroy:      osc_destroy,
        o_getattr:      osc_getattr,
        o_setattr:      osc_setattr,
        o_open:         osc_open,
        o_close:        osc_close,
        o_brw:          osc_brw,
        o_punch:        osc_punch,
        o_enqueue:      osc_enqueue,
        o_cancel:       osc_cancel,
        o_cancel_unused: osc_cancel_unused,
        o_iocontrol:    osc_iocontrol
};

struct obd_ops sanosc_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       osc_attach,
        o_detach:       osc_detach,
        o_cleanup:      client_obd_cleanup,
        o_connect:      osc_connect,
        o_disconnect:   client_obd_disconnect,
        o_statfs:       osc_statfs,
        o_packmd:       osc_packmd,
        o_unpackmd:     osc_unpackmd,
        o_create:       osc_create,
        o_destroy:      osc_destroy,
        o_getattr:      osc_getattr,
        o_setattr:      osc_setattr,
        o_open:         osc_open,
        o_close:        osc_close,
#ifdef __KERNEL__
        o_setup:        client_sanobd_setup,
        o_brw:          sanosc_brw,
#endif
        o_punch:        osc_punch,
        o_enqueue:      osc_enqueue,
        o_cancel:       osc_cancel,
        o_cancel_unused: osc_cancel_unused,
        o_iocontrol:    osc_iocontrol,
};

int __init osc_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        LASSERT(sizeof(struct osc_obdo_data) <= FD_OSTDATA_SIZE);

        lprocfs_init_vars(&lvars);

        rc = class_register_type(&osc_obd_ops, lvars.module_vars,
                                 LUSTRE_OSC_NAME);
        if (rc)
                RETURN(rc);

        rc = class_register_type(&sanosc_obd_ops, lvars.module_vars,
                                 LUSTRE_SANOSC_NAME);
        if (rc)
                class_unregister_type(LUSTRE_OSC_NAME);

        RETURN(rc);
}

static void __exit osc_exit(void)
{
        class_unregister_type(LUSTRE_SANOSC_NAME);
        class_unregister_type(LUSTRE_OSC_NAME);
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC)");
MODULE_LICENSE("GPL");

module_init(osc_init);
module_exit(osc_exit);
#endif
