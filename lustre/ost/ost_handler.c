/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
 *  Storage Target Handling functions
 *  Lustre Object Server Module (OST)
 *
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OST

#include <linux/module.h>
#include <linux/obd_ost.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_export.h>
#include <linux/init.h>
#include <linux/lprocfs_status.h>

inline void oti_to_request(struct obd_trans_info *oti, struct ptlrpc_request *req)
{
        if (oti && req->rq_repmsg)
                req->rq_repmsg->transno = HTON__u64(oti->oti_transno);
        EXIT;
}

static int ost_destroy(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_destroy(conn, &body->oa, NULL, oti);
        RETURN(0);
}

static int ost_getattr(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        /* FIXME: unpack only valid fields instead of memcpy, endianness */
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_getattr(conn, &repbody->oa, NULL);
        RETURN(0);
}

static int ost_statfs(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct obd_statfs *osfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        osfs = lustre_msg_buf(req->rq_repmsg, 0);
        memset(osfs, 0, size);

        rc = obd_statfs(conn, osfs);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                req->rq_status = rc;
                RETURN(rc);
        }
        obd_statfs_pack(osfs, osfs);

        RETURN(0);
}

static int ost_syncfs(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct obd_statfs *osfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        rc = lustre_pack_msg(0, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        rc = obd_syncfs(conn);
        if (rc) {
                CERROR("ost: syncfs failed: rc %d\n", rc);
                req->rq_status = rc;
                RETURN(rc);
        }

        RETURN(0);
}

static int ost_open(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        /* FIXME: unpack only valid fields instead of memcpy, endianness */
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_open(conn, &repbody->oa, NULL, oti);
        RETURN(0);
}

static int ost_close(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        /* FIXME: unpack only valid fields instead of memcpy, endianness */
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_close(conn, &repbody->oa, NULL, oti);
        RETURN(0);
}

static int ost_create(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        /* FIXME: unpack only valid fields instead of memcpy, endianness */
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_create(conn, &repbody->oa, NULL, oti);
        RETURN(0);
}

static int ost_punch(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        if ((NTOH__u32(body->oa.o_valid) & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))!=
            (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
                RETURN(-EINVAL);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        /* FIXME: unpack only valid fields instead of memcpy, endianness */
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_punch(conn, &repbody->oa, NULL,
                                   repbody->oa.o_size, repbody->oa.o_blocks, oti);
        RETURN(0);
}

static int ost_setattr(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        /* FIXME: unpack only valid fields instead of memcpy, endianness */
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_setattr(conn, &repbody->oa, NULL, oti);
        RETURN(0);
}

static int ost_bulk_timeout(void *data)
{
        ENTRY;
        /* We don't fail the connection here, because having the export
         * killed makes the (vital) call to commitrw very sad.
         */
        RETURN(1);
}

static int ost_brw_read(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ptlrpc_bulk_desc *desc;
        struct obd_ioobj *tmp1;
        void *tmp2, *end2;
        struct niobuf_remote *remote_nb;
        struct niobuf_local *local_nb = NULL;
        struct obd_ioobj *ioo;
        struct ost_body *body;
        struct l_wait_info lwi;
        void *desc_priv = NULL;
        int cmd, i, j, objcount, niocount, size = sizeof(*body);
        int rc = 0;
#if CHECKSUM_BULK
        __u64 cksum = 0;
#endif
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        end2 = (char *)tmp2 + req->rq_reqmsg->buflens[2];
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        niocount = req->rq_reqmsg->buflens[2] / sizeof(*remote_nb);
        cmd = OBD_BRW_READ;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_READ_BULK))
                GOTO(out, req->rq_status = -EIO);

        /* Hmm, we don't return anything in this reply buffer?
         * We should be returning per-page status codes and also
         * per-object size, blocks count, mtime, ctime.  (bug 593) */
        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                GOTO(out, req->rq_status = rc);

        for (i = 0; i < objcount; i++) {
                ost_unpack_ioo(&tmp1, &ioo);
                if (tmp2 + ioo->ioo_bufcnt > end2) {
                        LBUG();
                        GOTO(out, rc = -EFAULT);
                }
                for (j = 0; j < ioo->ioo_bufcnt; j++) {
                        /* XXX verify niobuf[j].offset > niobuf[j-1].offset */
                        ost_unpack_niobuf(&tmp2, &remote_nb);
                }
        }

        OBD_ALLOC(local_nb, sizeof(*local_nb) * niocount);
        if (local_nb == NULL)
                GOTO(out, rc = -ENOMEM);

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        ioo = lustre_msg_buf(req->rq_reqmsg, 1);
        remote_nb = lustre_msg_buf(req->rq_reqmsg, 2);
        req->rq_status = obd_preprw(cmd, conn, objcount, ioo, niocount,
                                    remote_nb, local_nb, &desc_priv, NULL);

        if (req->rq_status)
                GOTO(out, req->rq_status);

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out_local, rc = -ENOMEM);
        desc->bd_ptl_ev_hdlr = NULL;
        desc->bd_portal = OST_BULK_PORTAL;

        for (i = 0; i < niocount; i++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);

                if (bulk == NULL)
                        GOTO(out_bulk, rc = -ENOMEM);
                bulk->bp_xid = remote_nb[i].xid;
                bulk->bp_buf = local_nb[i].addr;
                bulk->bp_buflen = remote_nb[i].len;
                if (body->oa.o_valid & NTOH__u32(OBD_MD_FLCKSUM))
                        ost_checksum(&cksum, bulk->bp_buf, bulk->bp_buflen);
        }

        rc = ptlrpc_bulk_put(desc);
        if (rc)
                GOTO(out_bulk, rc);

        lwi = LWI_TIMEOUT(obd_timeout * HZ, ost_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, desc->bd_flags & PTL_BULK_FL_SENT,
                          &lwi);
        if (rc) {
                LASSERT(rc == -ETIMEDOUT);
                GOTO(out_bulk, rc);
        }

        req->rq_status = obd_commitrw(cmd, conn, objcount, ioo, niocount,
                                      local_nb, desc_priv, NULL);

out_bulk:
        ptlrpc_bulk_decref(desc);
out_local:
        OBD_FREE(local_nb, sizeof(*local_nb) * niocount);
out:
        if (rc)
                ptlrpc_error(req->rq_svc, req);
        else {
#if CHECKSUM_BULK
                body = lustre_msg_buf(req->rq_repmsg, 0);
                body->oa.o_rdev = HTON__u64(cksum);
                body->oa.o_valid |= HTON__u32(OBD_MD_FLCKSUM);
#endif
                ptlrpc_reply(req->rq_svc, req);
        }

        RETURN(rc);
}

static int ost_brw_write(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ptlrpc_bulk_desc *desc;
        struct obd_ioobj *tmp1;
        void *tmp2, *end2;
        struct niobuf_remote *remote_nb;
        struct niobuf_local *local_nb = NULL;
        struct obd_ioobj *ioo;
        struct ost_body *body;
        struct l_wait_info lwi;
        void *desc_priv = NULL;
        int cmd, i, j, objcount, niocount, size = sizeof(*body);
        int rc = 0;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        end2 = (char *)tmp2 + req->rq_reqmsg->buflens[2];
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        niocount = req->rq_reqmsg->buflens[2] / sizeof(*remote_nb);
        cmd = OBD_BRW_WRITE;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK))
                GOTO(out, req->rq_status = -EIO);

        for (i = 0; i < objcount; i++) {
                ost_unpack_ioo(&tmp1, &ioo);
                if (tmp2 + ioo->ioo_bufcnt > end2) {
                        LBUG();
                        GOTO(out, rc = -EFAULT);
                }
                for (j = 0; j < ioo->ioo_bufcnt; j++) {
                        /* XXX verify niobuf[j].offset > niobuf[j-1].offset */
                        ost_unpack_niobuf(&tmp2, &remote_nb);
                }
        }

        OBD_ALLOC(local_nb, sizeof(*local_nb) * niocount);
        if (local_nb == NULL)
                GOTO(out, rc = -ENOMEM);

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        ioo = lustre_msg_buf(req->rq_reqmsg, 1);
        remote_nb = lustre_msg_buf(req->rq_reqmsg, 2);
        req->rq_status = obd_preprw(cmd, conn, objcount, ioo, niocount,
                                    remote_nb, local_nb, &desc_priv, oti);

        if (req->rq_status)
                GOTO(out_local, rc = 0);

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out_local, rc = -ENOMEM);
        desc->bd_ptl_ev_hdlr = NULL;
        desc->bd_portal = OSC_BULK_PORTAL;

        for (i = 0; i < niocount; i++) {
                struct ptlrpc_bulk_page *bulk = ptlrpc_prep_bulk_page(desc);

                if (bulk == NULL)
                        GOTO(out_bulk, rc = -ENOMEM);
                bulk->bp_xid = remote_nb[i].xid;
                bulk->bp_buf = local_nb[i].addr;
                bulk->bp_buflen = remote_nb[i].len;
        }

        rc = ptlrpc_bulk_get(desc);
        if (rc)
                GOTO(out_bulk, rc);

        lwi = LWI_TIMEOUT(obd_timeout * HZ, ost_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, desc->bd_flags & PTL_BULK_FL_RCVD,
                          &lwi);
        if (rc) {
                LASSERT(rc == -ETIMEDOUT);
                ptlrpc_abort_bulk(desc);
                recovd_conn_fail(desc->bd_connection);
                obd_commitrw(cmd, conn, objcount, ioo, niocount, local_nb,
                             desc_priv, oti);
                GOTO(out_bulk, rc);
        }

#if CHECKSUM_BULK
        if ((body->oa.o_valid & NTOH__u32(OBD_MD_FLCKSUM))) {
                static int cksum_counter;
                __u64 client_cksum = NTOH__u64(body->oa.o_rdev);
                __u64 cksum = 0;

                for (i = 0; i < niocount; i++) {
                        char *ptr = kmap(local_nb[i].page);
                        int   off = local_nb[i].offset & (PAGE_SIZE - 1);
                        int   len = local_nb[i].len;

                        LASSERT(off + len <= PAGE_SIZE);
                        ost_checksum(&cksum, ptr + off, len);
                        kunmap(local_nb[i].page);
                }

                if (client_cksum != cksum) {
                        CERROR("Bad checksum: client "LPX64", server "LPX64
                               ", client NID "LPX64"\n", client_cksum, cksum,
                               req->rq_connection->c_peer.peer_nid);
                        cksum_counter = 1;
                } else {
                        cksum_counter++;
                        if ((cksum_counter & (-cksum_counter)) == cksum_counter)
                                CERROR("Checksum %d from "LPX64": "LPX64" OK\n",
                                        cksum_counter,
                                        req->rq_connection->c_peer.peer_nid,
                                        cksum);
                }
        }
#endif

        req->rq_status = obd_commitrw(cmd, conn, objcount, ioo, niocount,
                                      local_nb, desc_priv, oti);

 out_bulk:
        ptlrpc_bulk_decref(desc);
 out_local:
        OBD_FREE(local_nb, sizeof(*local_nb) * niocount);
 out:
        if (!rc)
                /* Hmm, we don't return anything in this reply buffer?
                 * We should be returning per-page status codes and also
                 * per-object size, blocks count, mtime, ctime.  (bug 593) */
                rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
        if (rc)
                ptlrpc_error(req->rq_svc, req);
        else {
                oti_to_request(oti, req);
                rc = ptlrpc_reply(req->rq_svc, req);
        }
        RETURN(rc);
}

static int ost_san_brw(struct ptlrpc_request *req, int alloc)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct niobuf_remote *remote_nb, *res_nb;
        struct obd_ioobj *ioo;
        struct ost_body *body;
        int cmd, rc, i, j, objcount, niocount, size[2] = {sizeof(*body)};
        void *tmp1, *tmp2, *end2;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        end2 = (char *)tmp2 + req->rq_reqmsg->buflens[2];
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        niocount = req->rq_reqmsg->buflens[2] / sizeof(*remote_nb);
        
        cmd = alloc ? OBD_BRW_WRITE : OBD_BRW_READ;

        for (i = 0; i < objcount; i++) {
                ost_unpack_ioo((void *)&tmp1, &ioo);
                if (tmp2 + ioo->ioo_bufcnt > end2) {
                        rc = -EFAULT;
                        break;
                }
                for (j = 0; j < ioo->ioo_bufcnt; j++)
                        ost_unpack_niobuf((void *)&tmp2, &remote_nb);
        }

        size[1] = niocount * sizeof(*remote_nb);
        rc = lustre_pack_msg(2, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                GOTO(out, rc);

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);

        req->rq_status = obd_san_preprw(cmd, conn, objcount, tmp1,
                                        niocount, tmp2);

        if (req->rq_status) {
                rc = 0;
                goto out;
        }

        remote_nb = lustre_msg_buf(req->rq_repmsg, 1);
        res_nb = lustre_msg_buf(req->rq_reqmsg, 2);
        for (i = 0; i < niocount; i++) {
                /* this advances remote_nb */
                ost_pack_niobuf((void **)&remote_nb,
                                res_nb[i].offset,
                                res_nb[i].len, /* 0 */
                                res_nb[i].flags, /* 0 */
                                res_nb[i].xid
                                );
        }

        rc = 0;

out:
        if (rc) {
                OBD_FREE(req->rq_repmsg, req->rq_replen);
                req->rq_repmsg = NULL;
                ptlrpc_error(req->rq_svc, req);
        } else
                ptlrpc_reply(req->rq_svc, req);

        return rc;
}

static int filter_recovery_request(struct ptlrpc_request *req,
                                   struct obd_device *obd, int *process)
{
        switch (req->rq_reqmsg->opc) {
        case OST_CONNECT: /* This will never get here, but for completeness. */
        case OST_DISCONNECT:
               *process = 1;
               RETURN(0);

        case OST_CLOSE:
        case OST_CREATE:
        case OST_DESTROY:
        case OST_OPEN:
        case OST_PUNCH:
        case OST_SETATTR: 
        case OST_SYNCFS:
        case OST_WRITE:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
                *process = 0;
                /* XXX what should we set rq_status to here? */
                RETURN(ptlrpc_error(req->rq_svc, req));
        }
}

static int ost_handle(struct ptlrpc_request *req)
{
        struct obd_trans_info trans_info = { 0, }, *oti = &trans_info;
        int should_process, rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_OST_HANDLE_UNPACK)) {
                CERROR("lustre_ost: Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->opc != OST_CONNECT) {
                struct obd_device *obd;

                if (req->rq_export == NULL) {
                        CERROR("lustre_ost: operation %d on unconnected OST\n",
                               req->rq_reqmsg->opc);
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                obd = req->rq_export->exp_obd;

                spin_lock_bh(&obd->obd_processing_task_lock);
                if (obd->obd_flags & OBD_ABORT_RECOVERY)
                        target_abort_recovery(obd);
                spin_unlock_bh(&obd->obd_processing_task_lock);

                if (obd->obd_flags & OBD_RECOVERING) {
                        rc = filter_recovery_request(req, obd, &should_process);
                        if (rc || !should_process)
                                RETURN(rc);
                } else if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
#if 0
/* need to store this reply somewhere... */
                        if (req->rq_xid == med->med_last_xid) {
                                DEBUG_REQ(D_HA, req, "resending reply");
                                OBD_ALLOC(req->rq_repmsg, med->med_last_replen);
                                req->rq_replen = med->med_last_replen;
                                memcpy(req->rq_repmsg, med->med_last_reply,
                                       req->rq_replen);
                                ptlrpc_reply(req->rq_svc, req);
                                return 0;
                        }
                        DEBUG_REQ(D_HA, req, "no reply for resend, continuing");
#endif
                }

        } 

        if (strcmp(req->rq_obd->obd_type->typ_name, "ost") != 0)
                GOTO(out, rc = -EINVAL);

        switch (req->rq_reqmsg->opc) {
        case OST_CONNECT:
                CDEBUG(D_INODE, "connect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CONNECT_NET, 0);
                rc = target_handle_connect(req, ost_handle);
                break;
        case OST_DISCONNECT:
                CDEBUG(D_INODE, "disconnect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                break;
        case OST_CREATE:
                CDEBUG(D_INODE, "create\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CREATE_NET, 0);
                rc = ost_create(req, oti);
                break;
        case OST_DESTROY:
                CDEBUG(D_INODE, "destroy\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DESTROY_NET, 0);
                rc = ost_destroy(req, oti);
                break;
        case OST_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_GETATTR_NET, 0);
                rc = ost_getattr(req);
                break;
        case OST_SETATTR:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_SETATTR_NET, 0);
                rc = ost_setattr(req, oti);
                break;
        case OST_OPEN:
                CDEBUG(D_INODE, "open\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_OPEN_NET, 0);
                rc = ost_open(req, oti);
                break;
        case OST_CLOSE:
                CDEBUG(D_INODE, "close\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CLOSE_NET, 0);
                rc = ost_close(req, oti);
                break;
        case OST_WRITE:
                CDEBUG(D_INODE, "write\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw_write(req, oti);
                /* ost_brw sends its own replies */
                RETURN(rc);
        case OST_READ:
                CDEBUG(D_INODE, "read\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw_read(req);
                /* ost_brw sends its own replies */
                RETURN(rc);
        case OST_SAN_READ:
                CDEBUG(D_INODE, "san read\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_san_brw(req, 0);
                /* ost_san_brw sends its own replies */
                RETURN(rc);
        case OST_SAN_WRITE:
                CDEBUG(D_INODE, "san write\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_san_brw(req, 1);
                /* ost_san_brw sends its own replies */
                RETURN(rc);
        case OST_PUNCH:
                CDEBUG(D_INODE, "punch\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_PUNCH_NET, 0);
                rc = ost_punch(req, oti);
                break;
        case OST_STATFS:
                CDEBUG(D_INODE, "statfs\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_STATFS_NET, 0);
                rc = ost_statfs(req);
                break;
        case OST_SYNCFS:
                CDEBUG(D_INODE, "sync\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_SYNCFS_NET, 0);
                rc = ost_syncfs(req);
                break;
        case LDLM_ENQUEUE:
                CDEBUG(D_INODE, "enqueue\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ldlm_server_blocking_ast);
                break;
        case LDLM_CONVERT:
                CDEBUG(D_INODE, "convert\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CONVERT, 0);
                rc = ldlm_handle_convert(req);
                break;
        case LDLM_CANCEL:
                CDEBUG(D_INODE, "cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CANCEL, 0);
                rc = ldlm_handle_cancel(req);
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "callback\n");
                CERROR("callbacks should not happen on OST\n");
                LBUG();
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req->rq_svc, req);
                RETURN(rc);
        }

        EXIT;
        /* If we're DISCONNECTing, the export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != OST_DISCONNECT) {
                struct obd_device *obd  = req->rq_export->exp_obd;
                if ((obd->obd_flags & OBD_NO_TRANSNO) == 0) {
                        req->rq_repmsg->last_committed =
                                HTON__u64(obd->obd_last_committed);
                } else {
                        DEBUG_REQ(D_IOCTL, req,
                                  "not sending last_committed update");
                }
                CDEBUG(D_INFO, "last_committed "LPU64", xid "LPX64"\n",
                       obd->obd_last_committed, HTON__u64(req->rq_xid));
        }

out:
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                struct obd_device *obd = req->rq_export->exp_obd;

                if (obd && (obd->obd_flags & OBD_RECOVERING)) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        return target_queue_final_reply(req, rc);
                }
                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }

        if (rc) {
                CERROR("ost: processing error (opcode=%d): %d\n",
                       req->rq_reqmsg->opc, rc);
                ptlrpc_error(req->rq_svc, req);
        } else {
                CDEBUG(D_INODE, "sending reply\n");
                if (req->rq_repmsg == NULL)
                        CERROR("handler for opcode %d returned rc=0 without "
                               "creating rq_repmsg; needs to return rc != 0!\n",
                               req->rq_reqmsg->opc);
                else
                        oti_to_request(oti, req);
                ptlrpc_reply(req->rq_svc, req);
        }

        return 0;
}

static int ost_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct ost_obd *ost = &obddev->u.ost;
        int err;
        int i;
        ENTRY;

        ost->ost_service = ptlrpc_init_svc(OST_NEVENTS, OST_NBUFS,
                                           OST_BUFSIZE, OST_MAXREQSIZE,
                                           OST_REQUEST_PORTAL, OSC_REPLY_PORTAL,
                                           ost_handle, "ost");
        if (!ost->ost_service) {
                CERROR("failed to start service\n");
                GOTO(error_disc, err = -ENOMEM);
        }

        for (i = 0; i < OST_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "ll_ost_%02d", i);
                err = ptlrpc_start_thread(obddev, ost->ost_service, name);
                if (err) {
                        CERROR("error starting thread #%d: rc %d\n", i, err);
                        GOTO(error_disc, err = -EINVAL);
                }
        }

        RETURN(0);

error_disc:
        RETURN(err);
}

static int ost_cleanup(struct obd_device * obddev)
{
        struct ost_obd *ost = &obddev->u.ost;
        int err = 0;

        ENTRY;

        ptlrpc_stop_all_threads(ost->ost_service);
        ptlrpc_unregister_service(ost->ost_service);

        RETURN(err);
}

int ost_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(&lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

int ost_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

/* I don't think this function is ever used, since nothing 
 * connects directly to this module.
 */
static int ost_connect(struct lustre_handle *conn,
                       struct obd_device *obd, struct obd_uuid *cluuid,
                       struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp);

        RETURN(0);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops ost_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       ost_attach,
        o_detach:       ost_detach,
        o_setup:        ost_setup,
        o_cleanup:      ost_cleanup,
        o_connect:      ost_connect,
};

static int __init ost_init(void)
{
        struct lprocfs_static_vars lvars;
        ENTRY;

        lprocfs_init_vars(&lvars);
        RETURN(class_register_type(&ost_obd_ops, lvars.module_vars,
                                   LUSTRE_OST_NAME));
}

static void __exit ost_exit(void)
{
        class_unregister_type(LUSTRE_OST_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
