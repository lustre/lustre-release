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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_OSC

#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/obd_ost.h>

static void osc_con2cl(struct obd_conn *conn, struct ptlrpc_client **cl,
                       struct ptlrpc_connection **connection)
{
        struct osc_obd *osc = &conn->oc_dev->u.osc;
        *cl = osc->osc_client;
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

        osc_con2cl(conn, &cl, &connection);

        if (cl->cli_obd) {
                /* local sendpage */
                memcpy((char *)(unsigned long)dst->addr,
                       (char *)(unsigned long)src->addr, src->len);
        } else {
                struct ptlrpc_bulk_desc *bulk;
                int rc;

                bulk = ptlrpc_prep_bulk(connection);
                if (bulk == NULL)
                        return -ENOMEM;

                bulk->b_buf = (void *)(unsigned long)src->addr;
                bulk->b_buflen = src->len;
                bulk->b_xid = dst->xid;
                rc = ptlrpc_send_bulk(bulk, OSC_BULK_PORTAL);
                if (rc != 0) {
                        CERROR("send_bulk failed: %d\n", rc);
                        LBUG();
                        return rc;
                }
                wait_event_interruptible(bulk->b_waitq,
                                         ptlrpc_check_bulk_sent(bulk));

                if (bulk->b_flags == PTL_RPC_INTR) {
                        EXIT;
                        /* FIXME: hey hey, we leak here. */
                        return -EINTR;
                }

                OBD_FREE(bulk, sizeof(*bulk));
        }

        return 0;
}

int osc_brw_read(struct obd_conn *conn, obd_count num_oa, struct obdo **oa,
                 obd_count *oa_bufs, struct page **buf, obd_size *count,
                 obd_off *offset, obd_flag *flags)
{
        struct ptlrpc_client *cl;
        struct ptlrpc_connection *connection;
        struct ptlrpc_request *request;
        struct ost_body *body;
        struct obd_ioobj ioo;
        struct niobuf src;
        int pages, rc, i, j, size[3] = {sizeof(*body)};
        void *ptr1, *ptr2;
        struct ptlrpc_bulk_desc **bulk;
        ENTRY;

        size[1] = num_oa * sizeof(ioo);
        pages = 0;
        for (i = 0; i < num_oa; i++)
                pages += oa_bufs[i];
        size[2] = pages * sizeof(src);

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
                        OBD_FREE(bulk[pages], sizeof(**bulk));
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
        int pages, rc, i, j, size[3] = {sizeof(*body)};
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
                CERROR("buffer length wrong (%d vs. %d)\n",
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

/* mount the file system (secretly) */
static int osc_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct osc_obd *osc = &obddev->u.osc;
        ENTRY;

        OBD_ALLOC(osc->osc_client, sizeof(*osc->osc_client));
        if (osc->osc_client == NULL)
                RETURN(-ENOMEM);

        ptlrpc_init_client(NULL, OST_REQUEST_PORTAL, OSC_REPLY_PORTAL,
                           osc->osc_client);

        osc->osc_conn = ptlrpc_uuid_to_connection("ost");
        if (!osc->osc_conn)
                RETURN(-EINVAL);

        MOD_INC_USE_COUNT;
        RETURN(0);
}

static int osc_cleanup(struct obd_device * obddev)
{
        struct osc_obd *osc = &obddev->u.osc;

        OBD_FREE(osc->osc_client, sizeof(*osc->osc_client));
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
        o_punch: osc_punch
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
