/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  Author Peter Braam <braam@clusterfs.com>
 *
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OSC

#include <linux/module.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h> /* for mds_objid */
#include <linux/obd_ost.h>
#include <linux/obd_lov.h>

static void osc_con2cl(struct lustre_handle *conn, struct ptlrpc_client **cl,
                       struct ptlrpc_connection **connection,
                       struct lustre_handle **rconn)
{
        struct obd_export *export = class_conn2export(conn);
        struct osc_obd *osc = &export->exp_obd->u.osc;

        *cl = osc->osc_client;
        *connection = osc->osc_conn;
        *rconn = &export->exp_rconnh;
}

static void osc_con2dlmcl(struct lustre_handle *conn, struct ptlrpc_client **cl,
                          struct ptlrpc_connection **connection,
                          struct lustre_handle **rconn)
{
        struct obd_export *export = class_conn2export(conn);
        struct osc_obd *osc = &export->exp_obd->u.osc;

        *cl = osc->osc_ldlm_client;
        *connection = osc->osc_conn;
        *rconn = &export->exp_rconnh;
}

static int osc_connect(struct lustre_handle *conn, struct obd_device *obd)
{
        struct osc_obd *osc = &obd->u.osc;
        //struct obd_import *import;
        struct ptlrpc_request *request;
        char *tmp = osc->osc_target_uuid;
        int rc, size = sizeof(osc->osc_target_uuid);
        ENTRY;

        /* not used yet
        OBD_ALLOC(import, sizeof(*import));
        if (!import)
                RETURN(-ENOMEM);
         */

        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd);
        if (rc)
                RETURN(rc);

        request = ptlrpc_prep_req(osc->osc_client, osc->osc_conn,
                                  OST_CONNECT, 1, &size, &tmp);
        if (!request)
                GOTO(out_disco, rc = -ENOMEM);

        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);
        request->rq_reqmsg->addr = -1;
        /* Sending our local connection info breaks for local connections
        request->rq_reqmsg->addr = conn->addr;
        request->rq_reqmsg->cookie = conn->cookie;
         */

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        /* XXX eventually maybe more refinement */
        osc->osc_conn->c_level = LUSTRE_CONN_FULL;

        class_rconn2export(conn, (struct lustre_handle *)request->rq_repmsg);

        EXIT;
 out:
        ptlrpc_free_req(request);
 out_disco:
        if (rc) {
                class_disconnect(conn);
                MOD_DEC_USE_COUNT;
        }
        return rc;
}

static int osc_disconnect(struct lustre_handle *conn)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        int rc;
        ENTRY;

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_DISCONNECT, 0, NULL, NULL);
        if (!request)
                RETURN(-ENOMEM);
        request->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);
        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

 out:
        ptlrpc_free_req(request);
        return rc;
}

static int osc_getattr(struct lustre_handle *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_GETATTR, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->oa.o_valid = ~0;

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
        ptlrpc_free_req(request);
        return rc;
}

static int osc_open(struct lustre_handle *conn, struct obdo *oa,
                    struct lov_stripe_md *md)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_OPEN, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->oa.o_valid = (OBD_MD_FLMODE | OBD_MD_FLID);

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
        ptlrpc_free_req(request);
        return rc;
}

static int osc_close(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_CLOSE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        oa->o_id = md->lmd_object_id;
        oa->o_mode = S_IFREG;
        oa->o_valid = (OBD_MD_FLMODE | OBD_MD_FLID);
        body = lustre_msg_buf(request->rq_reqmsg, 0);
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
        ptlrpc_free_req(request);
        return rc;
}

static int osc_setattr(struct lustre_handle *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                  OST_SETATTR, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        GOTO(out, rc);

 out:
        ptlrpc_free_req(request);
        return rc;
}

static int osc_create(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md **ea)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        if (!ea) {
                LBUG();
        }

        if (!*ea) {
                OBD_ALLOC(*ea, oa->o_easize);
                if (!*ea)
                        RETURN(-ENOMEM);
                (*ea)->lmd_size = oa->o_easize;
        }

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                  OST_CREATE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        (*ea)->lmd_object_id = oa->o_id;
        (*ea)->lmd_stripe_count = 1;
        EXIT;
 out:
        ptlrpc_free_req(request);
        return rc;
}

static int osc_punch(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md, obd_size count,
                     obd_off offset)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_PUNCH, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->oa.o_blocks = count;
        body->oa.o_valid |= OBD_MD_FLBLOCKS;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_free_req(request);
        return rc;
}

static int osc_destroy(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_DESTROY, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->oa.o_valid = ~0;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_free_req(request);
        return rc;
}

struct osc_brw_cb_data {
        brw_callback_t callback;
        void *cb_data;
        void *obd_data;
        size_t obd_size;
};

/* Our bulk-unmapping bottom half. */
static void unmap_and_decref_bulk_desc(void *data)
{
        struct ptlrpc_bulk_desc *desc = data;
        struct list_head *tmp;
        ENTRY;

        /* This feels wrong to me. */
        list_for_each(tmp, &desc->b_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, b_link);

                kunmap(bulk->b_page);
        }

        ptlrpc_bulk_decref(desc);
        EXIT;
}

static void brw_finish(struct ptlrpc_bulk_desc *desc, void *data)
{
        struct osc_brw_cb_data *cb_data = data;
        ENTRY;

        if (desc->b_flags & PTL_RPC_FL_INTR)
                CERROR("got signal\n");

        if (cb_data->callback)
                cb_data->callback(cb_data->cb_data);

        OBD_FREE(cb_data->obd_data, cb_data->obd_size);
        OBD_FREE(cb_data, sizeof(*cb_data));

        /* We can't kunmap the desc from interrupt context, so we do it from
         * the bottom half above. */
        INIT_TQUEUE(&desc->b_queue, 0, 0);
        PREPARE_TQUEUE(&desc->b_queue, unmap_and_decref_bulk_desc, desc);
        schedule_task(&desc->b_queue);

        EXIT;
}

static int osc_brw_read(struct lustre_handle *conn, struct lov_stripe_md *md,
                        obd_count page_count, struct page **page_array,
                        obd_size *count, obd_off *offset, obd_flag *flags,
                        brw_callback_t callback, void *data)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ptlrpc_request *request = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ost_body *body;
        struct osc_brw_cb_data *cb_data = NULL;
        int rc, size[3] = {sizeof(*body)};
        void *iooptr, *nioptr;
        int mapped = 0;
        ENTRY;

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(struct niobuf_remote);

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_BRW, 3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->data = OBD_BRW_READ;

        desc = ptlrpc_prep_bulk(connection);
        if (!desc)
                GOTO(out_free, rc = -ENOMEM);
        desc->b_portal = OST_BULK_PORTAL;
        desc->b_cb = brw_finish;
        OBD_ALLOC(cb_data, sizeof(*cb_data));
        if (!cb_data)
                GOTO(out_free, rc = -ENOMEM);
        cb_data->callback = callback;
        cb_data->cb_data = data;
        desc->b_cb_data = cb_data;
        /* end almost identical to brw_write case */

        iooptr = lustre_msg_buf(request->rq_reqmsg, 1);
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2);
        ost_pack_ioo(&iooptr, md, page_count);
        for (mapped = 0; mapped < page_count; mapped++) {
                struct ptlrpc_bulk_page *bulk;
                bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_unmap, rc = -ENOMEM);

                spin_lock(&connection->c_lock);
                bulk->b_xid = ++connection->c_xid_out;
                spin_unlock(&connection->c_lock);

                bulk->b_buf = kmap(page_array[mapped]);
                bulk->b_page = page_array[mapped];
                bulk->b_buflen = PAGE_SIZE;
                ost_pack_niobuf(&nioptr, offset[mapped], count[mapped],
                                flags[mapped], bulk->b_xid);
        }

        /*
         * Register the bulk first, because the reply could arrive out of order,
         * and we want to be ready for the bulk data.
         *
         * One reference is released by the bulk callback, the other when
         * we finish sleeping on it (if we don't have a callback).
         */
        atomic_set(&desc->b_refcount, callback ? 1 : 2);
        rc = ptlrpc_register_bulk(desc);
        if (rc)
                GOTO(out_unmap, rc);

        request->rq_replen = lustre_msg_size(1, size);
        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc) {
                ptlrpc_bulk_decref(desc);
                GOTO(out_unmap, rc);
        }

        /* Callbacks cause asynchronous handling. */
        if (callback)
                RETURN(0);

        l_wait_event_killable(desc->b_waitq, ptlrpc_check_bulk_received(desc));
        rc = desc->b_flags & PTL_RPC_FL_INTR ? -EINTR : 0;
        ptlrpc_bulk_decref(desc);
        RETURN(rc);

        /* Clean up on error. */
 out_unmap:
        while (mapped-- > 0)
                kunmap(page_array[mapped]);
 out_free:
        if (cb_data)
                OBD_FREE(cb_data, sizeof(*cb_data));
        ptlrpc_free_bulk(desc);
        ptlrpc_free_req(request);
        return rc;
}

static int osc_brw_write(struct lustre_handle *conn,
                         struct lov_stripe_md *md, obd_count page_count,
                         struct page **pagearray, obd_size *count,
                         obd_off *offset, obd_flag *flags,
                         brw_callback_t callback, void *data)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct ptlrpc_request *request = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ost_body *body;
        struct niobuf_local *local = NULL;
        struct niobuf_remote *remote;
        struct osc_brw_cb_data *cb_data = NULL;
        int rc, j, size[3] = {sizeof(*body)};
        void *iooptr, *nioptr;
        int mapped = 0;
        ENTRY;

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(*remote);

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_BRW, 3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->data = OBD_BRW_WRITE;

        OBD_ALLOC(local, page_count * sizeof(*local));
        if (!local)
                GOTO(out_free, rc = -ENOMEM);

        desc = ptlrpc_prep_bulk(connection);
        if (!desc)
                GOTO(out_free, rc = -ENOMEM);
        desc->b_portal = OSC_BULK_PORTAL;
        desc->b_cb = brw_finish;
        OBD_ALLOC(cb_data, sizeof(*cb_data));
        if (!cb_data)
                GOTO(out_free, rc = -ENOMEM);
        cb_data->callback = callback;
        cb_data->cb_data = data;
        desc->b_cb_data = cb_data;

        iooptr = lustre_msg_buf(request->rq_reqmsg, 1);
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2);
        ost_pack_ioo(&iooptr, md, page_count);
        /* end almost identical to brw_read case */

        cb_data->obd_data = local;
        cb_data->obd_size = page_count * sizeof(*local);

        for (mapped = 0; mapped < page_count; mapped++) {
                local[mapped].addr = kmap(pagearray[mapped]);
                local[mapped].offset = offset[mapped];
                local[mapped].len = count[mapped];
                ost_pack_niobuf(&nioptr, offset[mapped], count[mapped],
                                flags[mapped], 0);
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

                bulk->b_buf = (void *)(unsigned long)local[j].addr;
                bulk->b_buflen = local[j].len;
                bulk->b_xid = remote->xid;
        }

        if (desc->b_page_count != page_count)
                LBUG();

        /*
         * One is released when the bulk is complete, the other when we finish
         * waiting on it.  (Callback cases don't sleep, so only one ref for
         * them.)
         */
        atomic_set(&desc->b_refcount, callback ? 1 : 2);
        CDEBUG(D_PAGE, "Set refcount of %p to %d\n", desc,
               atomic_read(&desc->b_refcount));
        rc = ptlrpc_send_bulk(desc);
        if (rc)
                GOTO(out_unmap, rc);

        /* Callbacks cause asynchronous handling. */
        if (callback)
                RETURN(0);

        /* If there's no callback function, sleep here until complete. */
        l_wait_event_killable(desc->b_waitq, ptlrpc_check_bulk_sent(desc));
        ptlrpc_bulk_decref(desc);
        if (desc->b_flags & PTL_RPC_FL_INTR)
                RETURN(-EINTR);
        RETURN(0);

        /* Clean up on error. */
 out_unmap:
        while (mapped-- > 0)
                kunmap(pagearray[mapped]);

 out_free:
        OBD_FREE(cb_data, sizeof(*cb_data));
        OBD_FREE(local, page_count * sizeof(*local));
        ptlrpc_free_bulk(desc);
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_brw(int cmd, struct lustre_handle *conn,
                   struct lov_stripe_md *md, obd_count page_count,
                   struct page **page_array, obd_size *count, obd_off *offset,
                   obd_flag *flags, brw_callback_t callback, void *data)
{
        if (cmd & OBD_BRW_WRITE)
                return osc_brw_write(conn, md, page_count, page_array, count,
                                     offset, flags, callback, data);
        else
                return osc_brw_read(conn, md, page_count, page_array, count,
                                    offset, flags, callback, data);
}

static int osc_enqueue(struct lustre_handle *conn,
                       struct lustre_handle *parent_lock, __u64 *res_id,
                       __u32 type, void *extentp, int extent_len, __u32 mode,
                       int *flags, void *callback, void *data, int datalen,
                       struct lustre_handle *lockh)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct ptlrpc_connection *connection;
        struct ptlrpc_client *cl;
        struct lustre_handle *rconn;
        struct ldlm_extent *extent = extentp;
        int rc;
        __u32 mode2;

        /* Filesystem locks are given a bit of special treatment: first we
         * fixup the lock to start and end on page boundaries. */
        extent->start &= PAGE_MASK;
        extent->end = (extent->end + PAGE_SIZE - 1) & PAGE_MASK;

        /* Next, search for already existing extent locks that will cover us */
        osc_con2dlmcl(conn, &cl, &connection, &rconn);
        rc = ldlm_lock_match(obddev->obd_namespace, res_id, type, extent,
                             sizeof(extent), mode, lockh);
        if (rc == 1) {
                /* We already have a lock, and it's referenced */
                return 0;
        }

        /* Next, search for locks that we can upgrade (if we're trying to write)
         * or are more than we need (if we're trying to read).  Because the VFS
         * and page cache already protect us locally, lots of readers/writers
         * can share a single PW lock. */
        if (mode == LCK_PW)
                mode2 = LCK_PR;
        else
                mode2 = LCK_PW;

        rc = ldlm_lock_match(obddev->obd_namespace, res_id, type, extent,
                             sizeof(extent), mode2, lockh);
        if (rc == 1) {
                int flags;
                /* FIXME: This is not incredibly elegant, but it might
                 * be more elegant than adding another parameter to
                 * lock_match.  I want a second opinion. */
                ldlm_lock_addref(lockh, mode);
                ldlm_lock_decref(lockh, mode2);

                if (mode == LCK_PR)
                        return 0;

                rc = ldlm_cli_convert(cl, lockh, rconn, mode, &flags);
                if (rc)
                        LBUG();

                return rc;
        }

        rc = ldlm_cli_enqueue(cl, connection, rconn, NULL,obddev->obd_namespace,
                              parent_lock, res_id, type, extent, sizeof(extent),
                              mode, flags, callback, data, datalen, lockh);
        return rc;
}

static int osc_cancel(struct lustre_handle *oconn, __u32 mode,
                      struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static int osc_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct osc_obd *osc = &obddev->u.osc;
        char server_uuid[37];
        int rc;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("osc setup requires a TARGET UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("osc TARGET UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen2 < 1) {
                CERROR("osc setup requires a SERVER UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen2 > 37) {
                CERROR("osc SERVER UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        memcpy(osc->osc_target_uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        memcpy(server_uuid, data->ioc_inlbuf2, MIN(data->ioc_inllen2,
                                                   sizeof(server_uuid)));

        osc->osc_conn = ptlrpc_uuid_to_connection(server_uuid);
        if (!osc->osc_conn)
                RETURN(-ENOENT);

        obddev->obd_namespace =
                ldlm_namespace_new("osc", LDLM_NAMESPACE_CLIENT);
        if (obddev->obd_namespace == NULL)
                GOTO(out_conn, rc = -ENOMEM);

        OBD_ALLOC(osc->osc_client, sizeof(*osc->osc_client));
        if (osc->osc_client == NULL)
                GOTO(out_ns, rc = -ENOMEM);

        OBD_ALLOC(osc->osc_ldlm_client, sizeof(*osc->osc_ldlm_client));
        if (osc->osc_ldlm_client == NULL)
                GOTO(out_client, rc = -ENOMEM);

        ptlrpc_init_client(NULL, NULL, OST_REQUEST_PORTAL, OSC_REPLY_PORTAL,
                           osc->osc_client);
        ptlrpc_init_client(NULL, NULL, LDLM_REQUEST_PORTAL, LDLM_REPLY_PORTAL,
                           osc->osc_ldlm_client);
        osc->osc_client->cli_name = "osc";
        osc->osc_ldlm_client->cli_name = "ldlm";

        MOD_INC_USE_COUNT;
        RETURN(0);

 out_client:
        OBD_FREE(osc->osc_client, sizeof(*osc->osc_client));
 out_ns:
        ldlm_namespace_free(obddev->obd_namespace);
 out_conn:
        ptlrpc_put_connection(osc->osc_conn);
        return rc;
}

static int osc_cleanup(struct obd_device * obddev)
{
        struct osc_obd *osc = &obddev->u.osc;

        ldlm_namespace_free(obddev->obd_namespace);

        ptlrpc_cleanup_client(osc->osc_client);
        OBD_FREE(osc->osc_client, sizeof(*osc->osc_client));
        ptlrpc_cleanup_client(osc->osc_ldlm_client);
        OBD_FREE(osc->osc_ldlm_client, sizeof(*osc->osc_ldlm_client));
        ptlrpc_put_connection(osc->osc_conn);

        MOD_DEC_USE_COUNT;
        return 0;
}

static int osc_statfs(struct lustre_handle *conn, struct statfs *sfs)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct lustre_handle *rconn;
        struct obd_statfs *osfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        osc_con2cl(conn, &cl, &connection, &rconn);
        request = ptlrpc_prep_req2(cl, connection, rconn,
                                   OST_STATFS, 0, NULL, NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        osfs = lustre_msg_buf(request->rq_repmsg, 0);
        obd_statfs_unpack(osfs, sfs);

        EXIT;
 out:
        ptlrpc_free_req(request);
        return rc;
}

struct obd_ops osc_obd_ops = {
        o_setup:        osc_setup,
        o_cleanup:      osc_cleanup,
        o_statfs:       osc_statfs,
        o_create:       osc_create,
        o_destroy:      osc_destroy,
        o_getattr:      osc_getattr,
        o_setattr:      osc_setattr,
        o_open:         osc_open,
        o_close:        osc_close,
        o_connect:      osc_connect,
        o_disconnect:   osc_disconnect,
        o_brw:          osc_brw,
        o_punch:        osc_punch,
        o_enqueue:      osc_enqueue,
        o_cancel:       osc_cancel
};

static int __init osc_init(void)
{
        return class_register_type(&osc_obd_ops, LUSTRE_OSC_NAME);
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
