/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/lustre_dlm.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/workqueue.h>
#endif
#include <linux/kp30.h>
#include <linux/lustre_mds.h> /* for mds_objid */
#include <linux/obd_ost.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/lustre_ha.h>
#include <linux/obd_support.h> /* for OBD_FAIL_CHECK */
#include <linux/lustre_lite.h> /* for ll_i2info */
#include <portals/lib-types.h> /* for PTL_MD_MAX_IOV */
#include <linux/lprocfs_status.h>

extern struct lprocfs_vars status_var_nm_1[];
extern struct lprocfs_vars status_class_var[];

int osc_attach(struct obd_device *dev, obd_count len, void *data)
{
        return lprocfs_reg_obd(dev, status_var_nm_1, dev);
}

int osc_detach(struct obd_device *dev)
{
        return lprocfs_dereg_obd(dev);
}

/* Pack OSC object metadata for shipment to the MDS. */
static int osc_packmd(struct lustre_handle *conn, struct lov_mds_md **lmmp,
                      struct lov_stripe_md *lsm)
{
        int lmm_size;

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
        if (lsm)
                (*lmmp)->lmm_object_id = (lsm->lsm_object_id);

        return lmm_size;
}

static int osc_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsmp,
                        struct lov_mds_md *lmm)
{
        int lsm_size;

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
        if (lmm)
                (*lsmp)->lsm_object_id = (lmm->lmm_object_id);

        return lsm_size;
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
        rc = ptlrpc_check_status(request, rc);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        body = lustre_msg_buf(request->rq_repmsg, 0);
        CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
        if (oa)
                memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_open(struct lustre_handle *conn, struct obdo *oa,
                    struct lov_stripe_md *md)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_OPEN, 1, &size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
#warning FIXME: pack only valid fields instead of memcpy, endianness
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
        if (oa)
                memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_close(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_CLOSE, 1, &size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
#warning FIXME: pack only valid fields instead of memcpy, endianness
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
        if (oa)
                memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_setattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *md)
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
        rc = ptlrpc_check_status(request, rc);

        ptlrpc_req_finished(request);
        return rc;
}

static int osc_create(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md **ea)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        struct lov_stripe_md *lsm;
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

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_CREATE, 1, &size,
                                  NULL);
        if (!request)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out_req, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        lsm->lsm_object_id = oa->o_id;
        lsm->lsm_stripe_count = 0;
        *ea = lsm;
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
                     obd_size end)
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
        rc = ptlrpc_check_status(request, rc);
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
                       struct lov_stripe_md *ea)
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
        rc = ptlrpc_check_status(request, rc);
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

        /* This feels wrong to me. */
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

static int osc_brw_read(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                        obd_count page_count, struct brw_page *pga,
                        struct obd_brw_set *set)
{
        struct ptlrpc_connection *connection =
                client_conn2cli(conn)->cl_import.imp_connection;
        struct ptlrpc_request *request = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ost_body *body;
        int rc, size[3] = {sizeof(*body)}, mapped = 0;
        void *iooptr, *nioptr;
        __u32 xid;
        ENTRY;

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(struct niobuf_remote);

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_READ, 3, size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);

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

        spin_lock(&connection->c_lock);
        xid = ++connection->c_xid_out;       /* single xid for all pages */
        spin_unlock(&connection->c_lock);

        obd_kmap_get(page_count, 0);

        for (mapped = 0; mapped < page_count; mapped++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_unmap, rc = -ENOMEM);

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
         * One reference is released when brw_finish is complete, the other when
         * the caller removes us from the "set" list.
         *
         * On error, we never do the brw_finish, so we handle all decrefs.
         */
        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_BRW_READ_BULK)) {
                CERROR("obd_fail_loc=%x, skipping register_bulk\n",
                       OBD_FAIL_OSC_BRW_READ_BULK);
        } else {
                rc = ptlrpc_register_bulk(desc);
                if (rc)
                        GOTO(out_unmap, rc);
                obd_brw_set_add(set, desc);
        }

        request->rq_replen = lustre_msg_size(1, size);
        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);

        /*
         * XXX: If there is an error during the processing of the callback,
         *      such as a timeout in a sleep that it performs, brw_finish
         *      will never get called, and we'll leak the desc, fail to kunmap
         *      things, cats will live with dogs.  One solution would be to
         *      export brw_finish as osc_brw_finish, so that the timeout case
         *      and its kin could call it for proper cleanup.  An alternative
         *      would be for an error return from the callback to cause us to
         *      clean up, but that doesn't help the truly async cases (like
         *      LOV), which will immediately return from their PHASE_START
         *      callback, before any such cleanup-requiring error condition can
         *      be detected.
         */
 out_req:
        ptlrpc_req_finished(request);
        RETURN(rc);

        /* Clean up on error. */
out_unmap:
        while (mapped-- > 0)
                kunmap(pga[mapped].pg);
        obd_kmap_put(page_count);
        ptlrpc_bulk_decref(desc);
        goto out_req;
}

static int osc_brw_write(struct lustre_handle *conn, struct lov_stripe_md *md,
                         obd_count page_count, struct brw_page *pga,
                         struct obd_brw_set *set)
{
        struct ptlrpc_connection *connection =
                client_conn2cli(conn)->cl_import.imp_connection;
        struct ptlrpc_request *request = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ost_body *body;
        struct niobuf_local *local = NULL;
        struct niobuf_remote *remote;
        int rc, j, size[3] = {sizeof(*body)}, mapped = 0;
        void *iooptr, *nioptr;
        ENTRY;

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(*remote);

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_WRITE, 3, size,
                                  NULL);
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
        ost_pack_ioo(&iooptr, md, page_count);
        /* end almost identical to brw_read case */

        OBD_ALLOC(local, page_count * sizeof(*local));
        if (!local)
                GOTO(out_desc, rc = -ENOMEM);

        obd_kmap_get(page_count, 0);

        for (mapped = 0; mapped < page_count; mapped++) {
                local[mapped].addr = kmap(pga[mapped].pg);

                CDEBUG(D_INFO, "kmap(pg) = %p ; pg->flags = %lx ; pg->count = "
                       "%d ; page %d of %d\n",
                       local[mapped].addr, pga[mapped].pg->flags,
                       page_count(pga[mapped].pg),
                       mapped, page_count - 1);

                local[mapped].offset = pga[mapped].off;
                local[mapped].len = pga[mapped].count;
                ost_pack_niobuf(&nioptr, pga[mapped].off, pga[mapped].count,
                                pga[mapped].flag, 0);
        }

        size[1] = page_count * sizeof(*remote);
        request->rq_replen = lustre_msg_size(2, size);
        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
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
                struct ptlrpc_bulk_page *bulk;

                ost_unpack_niobuf(&nioptr, &remote);

                bulk = ptlrpc_prep_bulk_page(desc);
                if (!bulk)
                        GOTO(out_unmap, rc = -ENOMEM);

                bulk->bp_buf = (void *)(unsigned long)local[j].addr;
                bulk->bp_buflen = local[j].len;
                bulk->bp_xid = remote->xid;
                bulk->bp_page = pga[j].pg;
        }

        if (desc->bd_page_count != page_count)
                LBUG();

        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_BRW_WRITE_BULK))
                GOTO(out_unmap, rc = 0);

        OBD_FREE(local, page_count * sizeof(*local));

        /* One reference is released when brw_finish is complete, the other
         * when the caller removes it from the "set" list. */
        obd_brw_set_add(set, desc);
        rc = ptlrpc_send_bulk(desc);

        /* XXX: Mike, same question as in osc_brw_read. */
out_req:
        ptlrpc_req_finished(request);
        RETURN(rc);

        /* Clean up on error. */
out_unmap:
        while (mapped-- > 0)
                kunmap(pga[mapped].pg);

        obd_kmap_put(page_count);

        OBD_FREE(local, page_count * sizeof(*local));
out_desc:
        ptlrpc_bulk_decref(desc);
        goto out_req;
}

static int osc_brw(int cmd, struct lustre_handle *conn,
                   struct lov_stripe_md *md, obd_count page_count,
                   struct brw_page *pga, struct obd_brw_set *set)
{
        ENTRY;

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > PTL_MD_MAX_IOV)
                        pages_per_brw = PTL_MD_MAX_IOV;
                else
                        pages_per_brw = page_count;

                if (cmd & OBD_BRW_WRITE)
                        rc = osc_brw_write(conn, md, pages_per_brw, pga, set);
                else
                        rc = osc_brw_read(conn, md, pages_per_brw, pga, set);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}

static int osc_enqueue(struct lustre_handle *connh, struct lov_stripe_md *lsm,
                       struct lustre_handle *parent_lock,
                       __u32 type, void *extentp, int extent_len, __u32 mode,
                       int *flags, void *callback, void *data, int datalen,
                       struct lustre_handle *lockh)
{
        __u64 res_id[RES_NAME_SIZE] = { lsm->lsm_object_id };
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
        rc = ldlm_lock_match(obddev->obd_namespace, res_id, type, extent,
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
                rc = ldlm_lock_match(obddev->obd_namespace, res_id, type,
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
                              ldlm_completion_ast, callback, data, datalen,
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
        __u64 res_id[RES_NAME_SIZE] = { lsm->lsm_object_id };

        return ldlm_cli_cancel_unused(obddev->obd_namespace, res_id, flags);
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
        rc = ptlrpc_check_status(request, rc);
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

static int osc_iocontrol(long cmd, struct lustre_handle *conn, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        int err = 0;
        ENTRY;

        switch (cmd) {
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
        case IOC_OSC_REGISTER_LOV: {
                if (obddev->u.cli.cl_containing_lov)
                        GOTO(out, err = -EALREADY);
                obddev->u.cli.cl_containing_lov = (struct obd_device *)karg;
                GOTO(out, err);
        }
        case OBD_IOC_LOV_GET_CONFIG: {
                char *buf;
                struct lov_desc *desc;
                obd_uuid_t *uuidp;

                buf = NULL;
                len = 0;
                if (obd_ioctl_getdata(&buf, &len, (void *)uarg))
                        GOTO(out, err = -EINVAL);

                data = (struct obd_ioctl_data *)buf;

                if (sizeof(*desc) > data->ioc_inllen1) {
                        OBD_FREE(buf, len);
                        GOTO(out, err = -EINVAL);
                }

                if (data->ioc_inllen2 < sizeof(*uuidp)) {
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
                memcpy(desc->ld_uuid,  obddev->obd_uuid, sizeof(*uuidp));

                uuidp = (obd_uuid_t *)data->ioc_inlbuf2;
                memcpy(uuidp,  obddev->obd_uuid, sizeof(*uuidp));

                err = copy_to_user((void *)uarg, buf, len);
                if (err)
                        err = -EFAULT;
                OBD_FREE(buf, len);
                GOTO(out, err);
        }
        default:
                GOTO(out, err = -ENOTTY);
        }
out:
        return err;
}

struct obd_ops osc_obd_ops = {
        o_attach:       osc_attach,
        o_detach:       osc_detach,
        o_setup:        client_obd_setup,
        o_cleanup:      client_obd_cleanup,
        o_connect:      client_obd_connect,
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

static int __init osc_init(void)
{
        RETURN(class_register_type(&osc_obd_ops, status_class_var,
                                   LUSTRE_OSC_NAME));
}

static void __exit osc_exit(void)
{
        class_unregister_type(LUSTRE_OSC_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC) v1.0");
MODULE_LICENSE("GPL");

module_init(osc_init);
module_exit(osc_exit);
