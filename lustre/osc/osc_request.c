/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copryright (C) 2001, 2002 Cluster File Systems, Inc.
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

static void osc_obd2cl(struct obd_device *obd, struct ptlrpc_client **cl,
                       struct ptlrpc_connection **connection)
{
        struct osc_obd *osc = &obd->u.osc;
        *cl = osc->osc_client;
        *connection = osc->osc_conn;
}

static void osc_con2cl(struct obd_conn *conn, struct ptlrpc_client **cl,
                       struct ptlrpc_connection **connection)
{
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        *cl = osc->osc_client;
        *connection = osc->osc_conn;
}

static void osc_con2dlmcl(struct obd_conn *conn, struct ptlrpc_client **cl,
                          struct ptlrpc_connection **connection)
{
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        *cl = osc->osc_ldlm_client;
        *connection = osc->osc_conn;
}

static int osc_connect(struct obd_conn *conn, struct obd_device *obd)
{
        struct osc_obd *osc = &obd->u.osc;
        struct obd_import *import;
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        char *tmp = osc->osc_target_uuid;
        int rc, size = sizeof(osc->osc_target_uuid);
        ENTRY;

        OBD_ALLOC(import, sizeof(*import)); 
        if (!import)
                RETURN(-ENOMEM);
                  
        MOD_INC_USE_COUNT;
        rc = gen_connect(conn, obd);
        if (rc) 
                GOTO(out, rc);

        osc_obd2cl(obd, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_CONNECT, 1, &size, &tmp);
        if (!request)
                RETURN(-ENOMEM);

        size = sizeof(*body);
        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        body = lustre_msg_buf(request->rq_repmsg, 0);
        CDEBUG(D_INODE, "received connid %d\n", body->connid);


        /* XXX: Make this a handle */
        osc->osc_connh.addr = request->rq_repmsg->addr;
        osc->osc_connh.cookie = request->rq_repmsg->cookie;
        /* This might be redundant. */
        cl->cli_target_devno = request->rq_repmsg->target_id;
        osc->osc_ldlm_client->cli_target_devno = cl->cli_target_devno;
        conn->oc_id = body->connid;
        EXIT;
 out:
        ptlrpc_free_req(request);
        if (rc)
                MOD_DEC_USE_COUNT;
        return rc;
}

static int osc_disconnect(struct obd_conn *conn)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh,
                                  OST_DISCONNECT, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->connid = conn->oc_id;

        request->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(request);
        if (rc) 
                GOTO(out, rc);
        rc = gen_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

 out:
        ptlrpc_free_req(request);
        return rc;
}

static int osc_getattr(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                   OST_GETATTR, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
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
        return 0;
}

static int osc_open(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                   OST_OPEN, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
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
        return 0;
}

static int osc_close(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                   OST_CLOSE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;

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
        return 0;
}

static int osc_setattr(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                  OST_SETATTR, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        GOTO(out, rc);

 out:
        ptlrpc_free_req(request);
        return 0;
}

static int osc_create(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ost_body *body;
        struct mds_objid *objid;
        struct lov_object_id *lov_id;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                  OST_CREATE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        memset(oa->o_inline, 0, sizeof(oa->o_inline));
        objid = (struct mds_objid *)oa->o_inline;
        objid->mo_lov_md.lmd_object_id = oa->o_id;
        objid->mo_lov_md.lmd_stripe_count = 1;
        lov_id = (struct lov_object_id *)(oa->o_inline + sizeof(*objid));
        lov_id->l_device_id = 0;
        lov_id->l_object_id = oa->o_id;

        EXIT;
 out:
        ptlrpc_free_req(request);
        return 0;
}

static int osc_punch(struct obd_conn *conn, struct obdo *oa, obd_size count,
                     obd_off offset)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                   OST_PUNCH, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
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
        return 0;
}

static int osc_destroy(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                   OST_DESTROY, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
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
        return 0;
}

struct osc_brw_cb_data {
        struct page **buf;
        struct ptlrpc_request *req;
        bulk_callback_t callback;
        void *cb_data;
};

static void brw_read_finish(struct ptlrpc_bulk_desc *desc, void *data)
{
        struct osc_brw_cb_data *cb_data = data;

        if (desc->b_flags & PTL_RPC_FL_INTR)
                CERROR("got signal\n");

        (cb_data->callback)(desc, cb_data->cb_data);

        ptlrpc_free_bulk(desc);
        ptlrpc_free_req(cb_data->req);

        OBD_FREE(cb_data, sizeof(*cb_data));
}

static int osc_brw_read(struct obd_conn *conn, obd_count num_oa,
                        struct obdo **oa, obd_count *oa_bufs, struct page **buf,
                        obd_size *count, obd_off *offset, obd_flag *flags,
                        bulk_callback_t callback)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct ptlrpc_request *request;
        struct ost_body *body;
        struct list_head *tmp;
        int pages, rc, i, j, size[3] = {sizeof(*body)};
        void *ptr1, *ptr2;
        struct ptlrpc_bulk_desc *desc;
        ENTRY;

        size[1] = num_oa * sizeof(struct obd_ioobj);
        pages = 0;
        for (i = 0; i < num_oa; i++)
                pages += oa_bufs[i];
        size[2] = pages * sizeof(struct niobuf_remote);

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                  OST_BRW, 3, size, NULL);
        if (!request)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->data = OBD_BRW_READ;

        desc = ptlrpc_prep_bulk(connection);
        if (!desc)
                GOTO(out2, rc = -ENOMEM);
        desc->b_portal = OST_BULK_PORTAL;

        ptr1 = lustre_msg_buf(request->rq_reqmsg, 1);
        ptr2 = lustre_msg_buf(request->rq_reqmsg, 2);
        for (pages = 0, i = 0; i < num_oa; i++) {
                ost_pack_ioo(&ptr1, oa[i], oa_bufs[i]);
                /* FIXME: this inner loop is wrong for multiple OAs */
                for (j = 0; j < oa_bufs[i]; j++, pages++) {
                        struct ptlrpc_bulk_page *bulk;
                        bulk = ptlrpc_prep_bulk_page(desc);
                        if (bulk == NULL)
                                GOTO(out3, rc = -ENOMEM);

                        spin_lock(&connection->c_lock);
                        bulk->b_xid = ++connection->c_xid_out;
                        spin_unlock(&connection->c_lock);

                        bulk->b_buf = kmap(buf[pages]);
                        bulk->b_page = buf[pages];
                        bulk->b_buflen = PAGE_SIZE;
                        ost_pack_niobuf(&ptr2, offset[pages], count[pages],
                                        flags[pages], bulk->b_xid);
                }
        }

        rc = ptlrpc_register_bulk(desc);
        if (rc)
                GOTO(out3, rc);

        request->rq_replen = lustre_msg_size(1, size);
        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                ptlrpc_abort_bulk(desc);
        GOTO(out3, rc);

 out3:
        list_for_each(tmp, &desc->b_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, b_link);
                if (bulk->b_page != NULL)
                        kunmap(bulk->b_page);
        }
        ptlrpc_free_bulk(desc);
 out2:
        ptlrpc_free_req(request);
 out:
        return rc;
}

static void brw_write_finish(struct ptlrpc_bulk_desc *desc, void *data)
{
        struct osc_brw_cb_data *cb_data = data;
        int i;
        ENTRY;

        if (desc->b_flags & PTL_RPC_FL_INTR)
                CERROR("got signal\n");

        for (i = 0; i < desc->b_page_count; i++)
                kunmap(cb_data->buf[i]);

        (cb_data->callback)(desc, cb_data->cb_data);

        ptlrpc_free_bulk(desc);
        ptlrpc_free_req(cb_data->req);

        OBD_FREE(cb_data, sizeof(*cb_data));
        EXIT;
}

static int osc_brw_write(struct obd_conn *conn, obd_count num_oa,
                         struct obdo **oa, obd_count *oa_bufs,
                         struct page **pagearray, obd_size *count,
                         obd_off *offset, obd_flag *flags,
                         bulk_callback_t callback)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ptlrpc_request *request;
        struct ptlrpc_bulk_desc *desc;
        struct osc_obd *osc = &gen_conn2obd(conn)->u.osc;
        struct obd_ioobj ioo;
        struct ost_body *body;
        struct niobuf_local *local;
        struct niobuf_remote *remote;
        struct osc_brw_cb_data *cb_data;
        long pages;
        int rc, i, j, size[3] = {sizeof(*body)};
        void *ptr1, *ptr2;
        ENTRY;

        size[1] = num_oa * sizeof(ioo);
        pages = 0;
        for (i = 0; i < num_oa; i++)
                pages += oa_bufs[i];
        size[2] = pages * sizeof(*remote);

        OBD_ALLOC(local, pages * sizeof(*local));
        if (local == NULL)
                RETURN(-ENOMEM);

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req2(cl, connection, &osc->osc_connh, 
                                  OST_BRW, 3, size, NULL);
        if (!request)
                GOTO(out, rc = -ENOMEM);
        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->data = OBD_BRW_WRITE;

        ptr1 = lustre_msg_buf(request->rq_reqmsg, 1);
        ptr2 = lustre_msg_buf(request->rq_reqmsg, 2);
        for (pages = 0, i = 0; i < num_oa; i++) {
                ost_pack_ioo(&ptr1, oa[i], oa_bufs[i]);
                for (j = 0; j < oa_bufs[i]; j++, pages++) {
                        local[pages].addr = kmap(pagearray[pages]);
                        local[pages].offset = offset[pages];
                        local[pages].len = count[pages];
                        ost_pack_niobuf(&ptr2, offset[pages], count[pages],
                                        flags[pages], 0);
                }
        }

        size[1] = pages * sizeof(struct niobuf_remote);
        request->rq_replen = lustre_msg_size(2, size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out2, rc);

        ptr2 = lustre_msg_buf(request->rq_repmsg, 1);
        if (ptr2 == NULL)
                GOTO(out2, rc = -EINVAL);

        if (request->rq_repmsg->buflens[1] !=
            pages * sizeof(struct niobuf_remote)) {
                CERROR("buffer length wrong (%d vs. %ld)\n",
                       request->rq_repmsg->buflens[1],
                       pages * sizeof(struct niobuf_remote));
                GOTO(out2, rc = -EINVAL);
        }

        desc = ptlrpc_prep_bulk(connection);
        desc->b_portal = OSC_BULK_PORTAL;
        if (callback) {
                desc->b_cb = brw_write_finish;
                OBD_ALLOC(cb_data, sizeof(*cb_data));
                cb_data->buf = pagearray;
                cb_data->callback = callback;
                desc->b_cb_data = cb_data;
        }

        for (pages = 0, i = 0; i < num_oa; i++) {
                for (j = 0; j < oa_bufs[i]; j++, pages++) {
                        struct ptlrpc_bulk_page *page;

                        ost_unpack_niobuf(&ptr2, &remote);

                        page = ptlrpc_prep_bulk_page(desc);
                        if (page == NULL)
                                GOTO(out3, rc = -ENOMEM);

                        page->b_buf = (void *)(unsigned long)local[pages].addr;
                        page->b_buflen = local[pages].len;
                        page->b_xid = remote->xid;
                }
        }

        if (desc->b_page_count != pages)
                LBUG();

        rc = ptlrpc_send_bulk(desc);
        if (rc)
                GOTO(out3, rc);
        if (callback)
                GOTO(out, rc);

        /* If there's no callback function, sleep here until complete. */
        wait_event_interruptible(desc->b_waitq, ptlrpc_check_bulk_sent(desc));
        if (desc->b_flags & PTL_RPC_FL_INTR)
                rc = -EINTR;

        GOTO(out3, rc);

 out3:
        ptlrpc_free_bulk(desc);
 out2:
        ptlrpc_free_req(request);
        for (pages = 0, i = 0; i < num_oa; i++)
                for (j = 0; j < oa_bufs[i]; j++, pages++)
                        kunmap(pagearray[pages]);
 out:
        OBD_FREE(local, pages * sizeof(*local));

        return rc;
}

static int osc_brw(int cmd, struct obd_conn *conn, obd_count num_oa,
                   struct obdo **oa, obd_count *oa_bufs, struct page **buf,
                   obd_size *count, obd_off *offset, obd_flag *flags,
                   void *callback)
{
        if (num_oa != 1)
                LBUG();

        if (cmd & OBD_BRW_WRITE)
                return osc_brw_write(conn, num_oa, oa, oa_bufs, buf, count,
                                     offset, flags, (bulk_callback_t)callback);
        else
                return osc_brw_read(conn, num_oa, oa, oa_bufs, buf, count,
                                    offset, flags, (bulk_callback_t)callback);
}

static int osc_enqueue(struct obd_conn *oconn,
                       struct lustre_handle *parent_lock, __u64 *res_id,
                       __u32 type, void *extentp, int extent_len, __u32 mode,
                       int *flags, void *callback, void *data, int datalen,
                       struct lustre_handle *lockh)
{
        struct obd_device *obddev = gen_conn2obd(oconn);
        struct ptlrpc_connection *conn;
        struct osc_obd *osc = &gen_conn2obd(oconn)->u.osc;
        struct ptlrpc_client *cl;
        struct ldlm_extent *extent = extentp;
        int rc;
        __u32 mode2;

        /* Filesystem locks are given a bit of special treatment: first we
         * fixup the lock to start and end on page boundaries. */
        extent->start &= PAGE_MASK;
        extent->end = (extent->end + PAGE_SIZE - 1) & PAGE_MASK;

        /* Next, search for already existing extent locks that will cover us */
        osc_con2dlmcl(oconn, &cl, &conn);
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

                rc = ldlm_cli_convert(cl, lockh, mode, &flags);
                if (rc)
                        LBUG();

                return rc;
        }

        rc = ldlm_cli_enqueue(cl, conn, NULL, obddev->obd_namespace,
                              parent_lock, res_id, type, extent, sizeof(extent),
                              mode, flags, callback, data, datalen, lockh);
        return rc;
}

static int osc_cancel(struct obd_conn *oconn, __u32 mode,
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

#if 0
static int osc_statfs(struct obd_conn *conn, struct statfs *sfs);
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct obd_statfs *osfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_STATFS, 0, NULL, NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        osfs = lustre_msg_buf(request->rq_repmsg, 0);
        obd_statfs_unpack(sfs, osfs);

        EXIT;
 out:
        ptlrpc_free_req(request);
        return 0;
}
#endif

struct obd_ops osc_obd_ops = {
        o_setup:   osc_setup,
        o_cleanup: osc_cleanup,
        o_create: osc_create,
        o_destroy: osc_destroy,
        o_getattr: osc_getattr,
        o_setattr: osc_setattr,
        o_open: osc_open,
        o_close: osc_close,
        o_connect: osc_connect,
        o_disconnect: osc_disconnect,
        o_brw: osc_brw,
        o_punch: osc_punch,
        o_enqueue: osc_enqueue,
        o_cancel: osc_cancel
};

static int __init osc_init(void)
{
        return obd_register_type(&osc_obd_ops, LUSTRE_OSC_NAME);
}

static void __exit osc_exit(void)
{
        obd_unregister_type(LUSTRE_OSC_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC) v1.0");
MODULE_LICENSE("GPL");

module_init(osc_init);
module_exit(osc_exit);
