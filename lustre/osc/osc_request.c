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
#include <linux/obd_ost.h>

static void osc_con2cl(struct obd_conn *conn, struct ptlrpc_client **cl,
                       struct ptlrpc_connection **connection)
{
        struct osc_obd *osc = &conn->oc_dev->u.osc;
        *cl = osc->osc_client;
        *connection = osc->osc_conn;
}

static void osc_con2dlmcl(struct obd_conn *conn, struct ptlrpc_client **cl,
                          struct ptlrpc_connection **connection)
{
        struct osc_obd *osc = &conn->oc_dev->u.osc;
        *cl = osc->osc_ldlm_client;
        *connection = osc->osc_conn;
}

static int osc_connect(struct obd_conn *conn)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_CONNECT, 0, NULL, NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        CDEBUG(D_INODE, "received connid %d\n", body->connid);

        conn->oc_id = body->connid;
        EXIT;
 out:
        ptlrpc_free_req(request);
        return rc;
}

static int osc_disconnect(struct obd_conn *conn)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_DISCONNECT, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->connid = conn->oc_id;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        GOTO(out, rc);
 out:
        ptlrpc_free_req(request);
        return rc;
}

static int osc_getattr(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_GETATTR, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
        body->oa.o_valid = ~0;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
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

static int osc_open(struct obd_conn *conn, struct obdo *oa)
{
        struct ptlrpc_request *request;
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_OPEN, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
        if (body->oa.o_valid != (OBD_MD_FLMODE | OBD_MD_FLID))
                LBUG();

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
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
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_CLOSE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
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
        struct ptlrpc_connection *connection;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_SETATTR, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
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
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_CREATE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->oa.o_valid = ~0;
        body->connid = conn->oc_id;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

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
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_PUNCH, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
        body->oa.o_valid = ~0;
        body->oa.o_size = offset;
        body->oa.o_blocks = count;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
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
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }
        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_DESTROY, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        memcpy(&body->oa, oa, sizeof(*oa));
        body->connid = conn->oc_id;
        body->oa.o_valid = ~0;

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(request->rq_repmsg, 0);
        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_free_req(request);
        return 0;
}

int osc_sendpage(struct obd_conn *conn, struct ptlrpc_request *req,
                 struct niobuf *dst, struct niobuf *src)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ptlrpc_bulk_desc *bulk;
        int rc;
        ENTRY;

        osc_con2cl(conn, &cl, &connection);

        bulk = ptlrpc_prep_bulk(connection);
        if (bulk == NULL)
                RETURN(-ENOMEM);

        bulk->b_buf = (void *)(unsigned long)src->addr;
        bulk->b_buflen = src->len;
        bulk->b_xid = dst->xid;
        rc = ptlrpc_send_bulk(bulk, OSC_BULK_PORTAL);
        if (rc != 0) {
                CERROR("send_bulk failed: %d\n", rc);
                ptlrpc_free_bulk(bulk);
                LBUG();
                RETURN(rc);
        }
        wait_event_interruptible(bulk->b_waitq, ptlrpc_check_bulk_sent(bulk));

        if (bulk->b_flags & PTL_RPC_FL_INTR) {
                ptlrpc_free_bulk(bulk);
                RETURN(-EINTR);
        }

        ptlrpc_free_bulk(bulk);
        RETURN(0);
}

int osc_brw_read(struct obd_conn *conn, obd_count num_oa, struct obdo **oa,
                 obd_count *oa_bufs, struct page **buf, obd_size *count,
                 obd_off *offset, obd_flag *flags)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ptlrpc_request *request;
        struct ost_body *body;
        int pages, rc, i, j, size[3] = {sizeof(*body)};
        void *ptr1, *ptr2;
        struct ptlrpc_bulk_desc **bulk;
        ENTRY;

        size[1] = num_oa * sizeof(struct obd_ioobj);
        pages = 0;
        for (i = 0; i < num_oa; i++)
                pages += oa_bufs[i];
        size[2] = pages * sizeof(struct niobuf);

        OBD_ALLOC(bulk, pages * sizeof(*bulk));
        if (bulk == NULL)
                RETURN(-ENOMEM);

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_BRW, 3, size, NULL);
        if (!request)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->data = OBD_BRW_READ;

        ptr1 = lustre_msg_buf(request->rq_reqmsg, 1);
        ptr2 = lustre_msg_buf(request->rq_reqmsg, 2);
        for (pages = 0, i = 0; i < num_oa; i++) {
                ost_pack_ioo(&ptr1, oa[i], oa_bufs[i]);
                for (j = 0; j < oa_bufs[i]; j++, pages++) {
                        bulk[pages] = ptlrpc_prep_bulk(connection);
                        if (bulk[pages] == NULL)
                                GOTO(out, rc = -ENOMEM);

                        spin_lock(&connection->c_lock);
                        bulk[pages]->b_xid = ++connection->c_xid_out;
                        spin_unlock(&connection->c_lock);

                        bulk[pages]->b_buf = kmap(buf[pages]);
                        bulk[pages]->b_buflen = PAGE_SIZE;
                        bulk[pages]->b_portal = OST_BULK_PORTAL;
                        ost_pack_niobuf(&ptr2, bulk[pages]->b_buf,
                                        offset[pages], count[pages],
                                        flags[pages], bulk[pages]->b_xid);

                        rc = ptlrpc_register_bulk(bulk[pages]);
                        if (rc)
                                GOTO(out, rc);
                }
        }

        request->rq_replen = lustre_msg_size(1, size);
        rc = ptlrpc_queue_wait(request);
        GOTO(out, rc);

 out:
        /* FIXME: if we've called ptlrpc_wait_bulk but rc != 0, we need to
         * abort those bulk listeners. */

        for (pages = 0, i = 0; i < num_oa; i++) {
                for (j = 0; j < oa_bufs[i]; j++, pages++) {
                        if (bulk[pages] == NULL)
                                continue;
                        kunmap(buf[pages]);
                        ptlrpc_free_bulk(bulk[pages]);
                }
        }

        OBD_FREE(bulk, pages * sizeof(*bulk));
        ptlrpc_free_req(request);
        return rc;
}

int osc_brw_write(struct obd_conn *conn, obd_count num_oa, struct obdo **oa,
                  obd_count *oa_bufs, struct page **buf, obd_size *count,
                  obd_off *offset, obd_flag *flags)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ptlrpc_request *request;
        struct obd_ioobj ioo;
        struct ost_body *body;
        struct niobuf *src;
        long pages;
        int rc, i, j, size[3] = {sizeof(*body)};
        void *ptr1, *ptr2;
        ENTRY;

        size[1] = num_oa * sizeof(ioo);
        pages = 0;
        for (i = 0; i < num_oa; i++)
                pages += oa_bufs[i];
        size[2] = pages * sizeof(*src);

        OBD_ALLOC(src, size[2]);
        if (!src)
                RETURN(-ENOMEM);

        osc_con2cl(conn, &cl, &connection);
        request = ptlrpc_prep_req(cl, connection, OST_BRW, 3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);
        body = lustre_msg_buf(request->rq_reqmsg, 0);
        body->data = OBD_BRW_WRITE;

        ptr1 = lustre_msg_buf(request->rq_reqmsg, 1);
        ptr2 = lustre_msg_buf(request->rq_reqmsg, 2);
        for (pages = 0, i = 0; i < num_oa; i++) {
                ost_pack_ioo(&ptr1, oa[i], oa_bufs[i]);
                for (j = 0; j < oa_bufs[i]; j++, pages++) {
                        ost_pack_niobuf(&ptr2, kmap(buf[pages]), offset[pages],
                                        count[pages], flags[pages], 0);
                }
        }
        memcpy(src, lustre_msg_buf(request->rq_reqmsg, 2), size[2]);

        size[1] = pages * sizeof(struct niobuf);
        request->rq_replen = lustre_msg_size(2, size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        ptr2 = lustre_msg_buf(request->rq_repmsg, 1);
        if (ptr2 == NULL)
                GOTO(out, rc = -EINVAL);

        if (request->rq_repmsg->buflens[1] != pages * sizeof(struct niobuf)) {
                CERROR("buffer length wrong (%d vs. %ld)\n",
                       request->rq_repmsg->buflens[1],
                       pages * sizeof(struct niobuf));
                GOTO(out, rc = -EINVAL);
        }

        for (pages = 0, i = 0; i < num_oa; i++) {
                for (j = 0; j < oa_bufs[i]; j++, pages++) {
                        struct niobuf *dst;
                        ost_unpack_niobuf(&ptr2, &dst);
                        osc_sendpage(conn, request, dst, &src[pages]);
                }
        }
        OBD_FREE(src, size[2]);
 out:
        for (pages = 0, i = 0; i < num_oa; i++)
                for (j = 0; j < oa_bufs[i]; j++, pages++)
                        kunmap(buf[pages]);

        ptlrpc_free_req(request);
        return 0;
}

int osc_brw(int rw, struct obd_conn *conn, obd_count num_oa,
              struct obdo **oa, obd_count *oa_bufs, struct page **buf,
              obd_size *count, obd_off *offset, obd_flag *flags)
{
        if (rw == OBD_BRW_READ)
                return osc_brw_read(conn, num_oa, oa, oa_bufs, buf, count,
                                    offset, flags);
        else
                return osc_brw_write(conn, num_oa, oa, oa_bufs, buf, count,
                                     offset, flags);
}

int osc_enqueue(struct obd_conn *oconn, struct ldlm_namespace *ns,
                struct ldlm_handle *parent_lock, __u64 *res_id, __u32 type,
                struct ldlm_extent *extent, __u32 mode, int *flags, void *data,
                int datalen, struct ldlm_handle *lockh)
{
        struct ptlrpc_connection *conn;
        struct ptlrpc_client *cl;
        int rc;
        __u32 mode2;

        /* Filesystem locks are given a bit of special treatment: first we
         * fixup the lock to start and end on page boundaries. */
        extent->start &= PAGE_MASK;
        extent->end = (extent->end + PAGE_SIZE - 1) & PAGE_MASK;

        /* Next, search for already existing extent locks that will cover us */
        osc_con2dlmcl(oconn, &cl, &conn);
        rc = ldlm_local_lock_match(ns, res_id, type, extent, mode, lockh);
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

        rc = ldlm_local_lock_match(ns, res_id, type, extent, mode2, lockh);
        if (rc == 1) {
                int flags;
                struct ldlm_lock *lock = ldlm_handle2object(lockh);
                /* FIXME: This is not incredibly elegant, but it might
                 * be more elegant than adding another parameter to
                 * lock_match.  I want a second opinion. */
                ldlm_lock_addref(lock, mode);
                ldlm_lock_decref(lock, mode2);

                if (mode == LCK_PR)
                        return 0;

                rc = ldlm_cli_convert(cl, lockh, type, &flags);
                if (rc)
                        LBUG();

                return rc;
        }

        rc = ldlm_cli_enqueue(cl, conn, ns, parent_lock, res_id, type,
                              extent, mode, flags, data, datalen, lockh);
        return rc;
}

int osc_cancel(struct obd_conn *oconn, __u32 mode, struct ldlm_handle *lockh)
{
        struct ldlm_lock *lock;
        ENTRY;

        lock = ldlm_handle2object(lockh);
        ldlm_lock_decref(lock, mode);

        RETURN(0);
}

static int osc_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct osc_obd *osc = &obddev->u.osc;
        int rc;
        ENTRY;

        osc->osc_conn = ptlrpc_uuid_to_connection("ost");
        if (!osc->osc_conn)
                RETURN(-EINVAL);

        OBD_ALLOC(osc->osc_client, sizeof(*osc->osc_client));
        if (osc->osc_client == NULL)
                GOTO(out_conn, rc = -ENOMEM);

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
 out_conn:
        ptlrpc_put_connection(osc->osc_conn);
        return rc;
}

static int osc_cleanup(struct obd_device * obddev)
{
        struct osc_obd *osc = &obddev->u.osc;

        ptlrpc_cleanup_client(osc->osc_client);
        OBD_FREE(osc->osc_client, sizeof(*osc->osc_client));
        ptlrpc_cleanup_client(osc->osc_ldlm_client);
        OBD_FREE(osc->osc_ldlm_client, sizeof(*osc->osc_ldlm_client));
        ptlrpc_put_connection(osc->osc_conn);

        MOD_DEC_USE_COUNT;
        return 0;
}

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
        obd_register_type(&osc_obd_ops, LUSTRE_OSC_NAME);
        return 0;
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
