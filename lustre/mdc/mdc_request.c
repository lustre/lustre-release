/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
# include <linux/obd_class.h>
#endif

#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>
#include <linux/lprocfs_status.h>
#include "mdc_internal.h"

#define REQUEST_MINOR 244

extern int mds_queue_req(struct ptlrpc_request *);
struct mdc_rpc_lock mdc_rpc_lock;
struct mdc_rpc_lock mdc_setattr_lock;
EXPORT_SYMBOL(mdc_rpc_lock);

/* Helper that implements most of mdc_getstatus and signal_completed_replay. */
static int send_getstatus(struct obd_import *imp, struct ll_fid *rootfid,
                          int level, int msg_flags)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        req = ptlrpc_prep_req(imp, MDS_GETSTATUS, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        req->rq_level = level;
        req->rq_replen = lustre_msg_size(1, &size);

        mds_pack_req_body(req);
        req->rq_reqmsg->flags |= msg_flags;
        rc = ptlrpc_queue_wait(req);

        if (!rc) {
                body = lustre_swab_repbuf (req, 0, sizeof (*body),
                                           lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't extract mds_body\n");
                        GOTO (out, rc = -EPROTO);
                }

                memcpy(rootfid, &body->fid1, sizeof(*rootfid));

                CDEBUG(D_NET, "root ino="LPU64", last_committed="LPU64
                       ", last_xid="LPU64"\n",
                       rootfid->id, req->rq_repmsg->last_committed,
                       req->rq_repmsg->last_xid);
        }

        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

/* should become mdc_getinfo() */
int mdc_getstatus(struct lustre_handle *conn, struct ll_fid *rootfid)
{
        return send_getstatus(class_conn2cliimp(conn), rootfid, LUSTRE_CONN_CON,
                              0);
}

int mdc_getlovinfo(struct obd_device *obd, struct lustre_handle *mdc_connh,
                   struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_status_req *streq;
        struct lov_desc       *desc;
        struct obd_uuid       *uuids;
        int rc, size[2] = {sizeof(*streq)};
        int i;
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(mdc_connh), MDS_GETLOVINFO, 1,
                              size, NULL);
        if (!req)
                RETURN (-ENOMEM);

        *request = req;
        streq = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*streq));
        streq->flags = MDS_STATUS_LOV;
        streq->repbuf = LOV_MAX_UUID_BUFFER_SIZE;

        /* prepare for reply */
        req->rq_level = LUSTRE_CONN_CON;
        size[0] = sizeof (*desc);
        size[1] = LOV_MAX_UUID_BUFFER_SIZE;
        req->rq_replen = lustre_msg_size(2, size);

        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);

        if (rc != 0) {
                CERROR ("rcp failed\n");
                GOTO (failed, rc);
        }

        desc = lustre_swab_repbuf (req, 0, sizeof (*desc),
                                   lustre_swab_lov_desc);
        if (desc == NULL) {
                CERROR ("Can't unpack lov_desc\n");
                GOTO (failed, rc = -EPROTO);
        }

        LASSERT_REPSWAB (req, 1);
        /* array of uuids byte-sex insensitive; just verify they are all
         * there and terminated */
        uuids = lustre_msg_buf (req->rq_repmsg, 1,
                                desc->ld_tgt_count * sizeof (*uuids));
        if (uuids == NULL) {
                CERROR ("Can't unpack %d uuids\n", desc->ld_tgt_count);
                GOTO (failed, rc = -EPROTO);
        }

        for (i = 0; i < desc->ld_tgt_count; i++) {
                int uid_len = strnlen (uuids[i].uuid, sizeof (uuids[i].uuid));

                if (uid_len == sizeof (uuids[i].uuid)) {
                        CERROR ("Unterminated uuid %d:%*s\n",
                                i, (int)sizeof (uuids[i].uuid), uuids[i].uuid);
                        GOTO (failed, rc = -EPROTO);
                }
        }
        RETURN(0);

 failed:
        ptlrpc_req_finished (req);
        RETURN (rc);
}

int mdc_getattr_common (struct lustre_handle *conn,
                        unsigned int ea_size, struct ptlrpc_request *req)
{
        struct mds_body *body;
        void            *eadata;
        int              rc;
        int              size[2] = {sizeof(*body), 0};
        int              bufcount = 1;
        ENTRY;

        /* request message already built */

        if (ea_size != 0) {
                size[bufcount++] = ea_size;
                CDEBUG(D_INODE, "reserved %u bytes for MD/symlink in packet\n",
                       ea_size);
        }
        req->rq_replen = lustre_msg_size(bufcount, size);

        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);
        if (rc != 0)
                RETURN (rc);

        body = lustre_swab_repbuf (req, 0, sizeof (*body),
                                   lustre_swab_mds_body);
        if (body == NULL) {
                CERROR ("Can't unpack mds_body\n");
                RETURN (-EPROTO);
        }

        CDEBUG(D_NET, "mode: %o\n", body->mode);

        LASSERT_REPSWAB (req, 1);
        if (body->eadatasize != 0) {
                /* reply indicates presence of eadata; check it's there... */
                eadata = lustre_msg_buf (req->rq_repmsg, 1, body->eadatasize);
                if (eadata == NULL) {
                        CERROR ("Missing/short eadata\n");
                        RETURN (-EPROTO);
                }
        }

        RETURN (0);
}

int mdc_getattr(struct lustre_handle *conn, struct ll_fid *fid,
                unsigned long valid, unsigned int ea_size,
                struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int size = sizeof(*body);
        int rc;
        ENTRY;

        /* XXX do we need to make another request here?  We just did a getattr
         *     to do the lookup in the first place.
         */
        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_GETATTR, 1, &size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->fid1, fid, sizeof(*fid));
        body->valid = valid;
        body->eadatasize = ea_size;
        mds_pack_req_body(req);

        rc = mdc_getattr_common (conn, ea_size, req);
        if (rc != 0) {
                ptlrpc_req_finished (req);
                req = NULL;
        }
 out:
        *request = req;
        RETURN (rc);
}

int mdc_getattr_name(struct lustre_handle *conn, struct ll_fid *fid,
                     char *filename, int namelen, unsigned long valid,
                     unsigned int ea_size, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size[2] = {sizeof(*body), namelen};
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_GETATTR_NAME, 2,
                              size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->fid1, fid, sizeof(*fid));
        body->valid = valid;
        body->eadatasize = ea_size;
        mds_pack_req_body(req);

        LASSERT (strnlen (filename, namelen) == namelen - 1);
        memcpy(lustre_msg_buf(req->rq_reqmsg, 1, namelen), filename, namelen);

        rc = mdc_getattr_common (conn, ea_size, req);
        if (rc != 0) {
                ptlrpc_req_finished (req);
                req = NULL;
        }
 out:
        *request = req;
        return rc;
}

/* This should be called with both the request and the reply still packed. */
void mdc_store_inode_generation(struct ptlrpc_request *req, int reqoff,
                                int repoff)
{
        struct mds_rec_create *rec =
                lustre_msg_buf(req->rq_reqmsg, reqoff, sizeof (*rec));
        struct mds_body *body =
                lustre_msg_buf(req->rq_repmsg, repoff, sizeof (*body));

        LASSERT (rec != NULL);
        LASSERT (body != NULL);

        memcpy(&rec->cr_replayfid, &body->fid1, sizeof rec->cr_replayfid);
        DEBUG_REQ(D_HA, req, "storing generation %x for ino "LPD64,
                  rec->cr_replayfid.generation, rec->cr_replayfid.id);
}

/* We always reserve enough space in the reply packet for a stripe MD, because
 * we don't know in advance the file type.
 *
 * XXX we could get that from ext2_dir_entry_2 file_type
 */
int mdc_enqueue(struct lustre_handle *conn,
                int lock_type,
                struct lookup_intent *it,
                int lock_mode,
                struct mdc_op_data *data,
                struct lustre_handle *lockh,
                char *tgt,
                int tgtlen,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data)
{
        struct ptlrpc_request *req;
        struct obd_device *obddev = class_conn2obd(conn);
        struct ldlm_res_id res_id =
                { .name = {data->ino1, data->gen1} };
        int size[6] = {sizeof(struct ldlm_request), sizeof(struct ldlm_intent)};
        int rc, flags = LDLM_FL_HAS_INTENT;
        int repsize[3] = {sizeof(struct ldlm_reply),
                          sizeof(struct mds_body),
                          obddev->u.cli.cl_max_mds_easize};
        struct ldlm_reply *dlm_rep;
        struct ldlm_intent *lit;
        struct ldlm_request *lockreq;
        void *eadata;
        unsigned long irqflags;
        int   reply_buffers = 0;
        ENTRY;

//        LDLM_DEBUG_NOLOCK("mdsintent=%s,name=%s,dir=%lu",
//                          ldlm_it2str(it->it_op), it_name, it_inode->i_ino);

        if (it->it_op & IT_OPEN) {
                it->it_mode |= S_IFREG;
                it->it_mode &= ~current->fs->umask;

                size[2] = sizeof(struct mds_rec_create);
                size[3] = data->namelen + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                spin_lock_irqsave (&req->rq_lock, irqflags);
                req->rq_replay = 1;
                spin_unlock_irqrestore (&req->rq_lock, irqflags);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1, sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mds_open_pack(req, 2, data, it->it_mode, 0,
                              current->fsuid, current->fsgid,
                              LTIME_S(CURRENT_TIME), it->it_flags,
                              tgt, tgtlen);
                /* get ready for the reply */
                reply_buffers = 3;
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op & IT_UNLINK) {
                size[2] = sizeof(struct mds_rec_unlink);
                size[3] = data->namelen + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1, sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mds_unlink_pack(req, 2, data);
                /* get ready for the reply */
                reply_buffers = 3;
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op & (IT_GETATTR | IT_LOOKUP)) {
                int valid = OBD_MD_FLNOTOBD | OBD_MD_FLEASIZE;
                size[2] = sizeof(struct mds_body);
                size[3] = data->namelen + 1;

                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1, sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mds_getattr_pack(req, valid, 2, it->it_flags, data);
                /* get ready for the reply */
                reply_buffers = 3;
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op == IT_READDIR) {
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 1,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* get ready for the reply */
                reply_buffers = 1;
                req->rq_replen = lustre_msg_size(1, repsize);
        }  else {
                LBUG();
                RETURN(-EINVAL);
        }

        mdc_get_rpc_lock(&mdc_rpc_lock, it);
        rc = ldlm_cli_enqueue(conn, req, obddev->obd_namespace, NULL, res_id,
                              lock_type, NULL, 0, lock_mode, &flags,
                              cb_completion, cb_blocking, cb_data, lockh);
        mdc_put_rpc_lock(&mdc_rpc_lock, it);

        /* Similarly, if we're going to replay this request, we don't want to
         * actually get a lock, just perform the intent. */
        if (req->rq_transno || req->rq_replay) {
                lockreq = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*lockreq));
                lockreq->lock_flags |= LDLM_FL_INTENT_ONLY;
        }

        /* This can go when we're sure that this can never happen */
        LASSERT(rc != -ENOENT);
        if (rc == ELDLM_LOCK_ABORTED) {
                lock_mode = 0;
                memset(lockh, 0, sizeof(*lockh));
        } else if (rc != 0) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                LASSERT (rc < 0);
                ptlrpc_req_finished(req);
                RETURN(rc);
        } else { /* rc = 0 */
                struct ldlm_lock *lock = ldlm_handle2lock(lockh);
                struct lustre_handle lockh2;
                LASSERT(lock);

                /* If the server gave us back a different lock mode, we should
                 * fix up our variables. */
                if (lock->l_req_mode != lock_mode) {
                        ldlm_lock_addref(lockh, lock->l_req_mode);
                        ldlm_lock_decref(lockh, lock_mode);
                        lock_mode = lock->l_req_mode;
                }

                /* The server almost certainly gave us a lock other than the
                 * one that we asked for.  If we already have a matching lock,
                 * then cancel this one--we don't need two. */
                LDLM_DEBUG(lock, "matching against this");

                memcpy(&lockh2, lockh, sizeof(lockh2));
                if (ldlm_lock_match(NULL,
                                    LDLM_FL_BLOCK_GRANTED | LDLM_FL_MATCH_DATA,
                                    NULL, LDLM_PLAIN, NULL, 0, LCK_NL, cb_data,
                                    &lockh2)) {
                        /* We already have a lock; cancel the new one */
                        ldlm_lock_decref_and_cancel(lockh, lock_mode);
                        memcpy(lockh, &lockh2, sizeof(lockh2));
                }
                LDLM_LOCK_PUT(lock);
        }

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*dlm_rep));
        LASSERT (dlm_rep != NULL);           /* checked by ldlm_cli_enqueue() */
        LASSERT_REPSWABBED (req, 0);         /* swabbed by ldlm_cli_enqueue() */

        it->it_disposition = (int) dlm_rep->lock_policy_res1;
        it->it_status = (int) dlm_rep->lock_policy_res2;
        it->it_lock_mode = lock_mode;
        it->it_data = req;

        /* We know what to expect, so we do any byte flipping required here */
        LASSERT (reply_buffers == 3 || reply_buffers == 1);
        if (reply_buffers == 3) {
                struct mds_body *body;

                body = lustre_swab_repbuf (req, 1, sizeof (*body),
                                           lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't swab mds_body\n");
                        RETURN (-EPROTO);
                }

                if ((body->valid & OBD_MD_FLEASIZE) != 0) {
                        /* The eadata is opaque; just check that it is
                         * there.  Eventually, obd_unpackmd() will check
                         * the contents */
                        eadata = lustre_swab_repbuf (req, 2, body->eadatasize,
                                                     NULL);
                        if (eadata == NULL) {
                                CERROR ("Missing/short eadata\n");
                                RETURN (-EPROTO);
                        }
                }
        }

        RETURN(rc);
}

static void mdc_replay_open(struct ptlrpc_request *req)
{
        struct obd_client_handle *och = req->rq_replay_data;
        struct lustre_handle old, *file_fh = &och->och_fh;
        struct list_head *tmp;
        struct mds_body *body;

        body = lustre_swab_repbuf (req, 1, sizeof (*body),
                                   lustre_swab_mds_body);
        LASSERT (body != NULL);

        memcpy(&old, file_fh, sizeof(old));
        CDEBUG(D_HA, "updating handle from "LPD64" to "LPD64"\n",
               file_fh->cookie, body->handle.cookie);
        memcpy(file_fh, &body->handle, sizeof(body->handle));

        /* A few frames up, ptlrpc_replay holds the lock, so this is safe. */
        list_for_each(tmp, &req->rq_import->imp_sending_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                if (req->rq_reqmsg->opc != MDS_CLOSE)
                        continue;
                body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
                if (memcmp(&body->handle, &old, sizeof(old)))
                        continue;

                DEBUG_REQ(D_HA, req, "updating close body with new fh");
                memcpy(&body->handle, file_fh, sizeof(*file_fh));
        }
}

void mdc_set_open_replay_data(struct obd_client_handle *och)
{
        struct ptlrpc_request *req = och->och_req;
        struct mds_rec_create *rec =
                lustre_msg_buf(req->rq_reqmsg, 2, sizeof (*rec));
        struct mds_body *body =
                lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));

        LASSERT (rec != NULL);
        /* outgoing messages always in my byte order */
        LASSERT (body != NULL);
        /* incoming message in my byte order (it's been swabbed) */
        LASSERT_REPSWABBED (req, 1);

        memcpy(&rec->cr_replayfid, &body->fid1, sizeof rec->cr_replayfid);
        req->rq_replay_cb = mdc_replay_open;
        req->rq_replay_data = och;
}

int mdc_close(struct lustre_handle *conn, obd_id ino, int type,
              struct lustre_handle *fh, struct ptlrpc_request **request)
{
        struct mds_body *body;
        int rc, size = sizeof(*body);
        struct ptlrpc_request *req;
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_CLOSE, 1, &size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        ll_ino2fid(&body->fid1, ino, 0, type);
        memcpy(&body->handle, fh, sizeof(body->handle));

        req->rq_replen = lustre_msg_size(0, NULL);

        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);

        EXIT;
 out:
        *request = req;
        return rc;
}

int mdc_readpage(struct lustre_handle *conn, obd_id ino, int type, __u64 offset,
                 struct page *page, struct ptlrpc_request **request)
{
        struct obd_import *imp = class_conn2cliimp(conn);
        struct ptlrpc_request *req = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        CDEBUG(D_INODE, "inode: %ld\n", (long)ino);

        req = ptlrpc_prep_req(imp, MDS_READPAGE, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        /* XXX FIXME bug 249 */
        req->rq_request_portal = MDS_READPAGE_PORTAL;

        desc = ptlrpc_prep_bulk_imp (req, BULK_PUT_SINK, MDS_BULK_PORTAL);
        if (desc == NULL) {
                GOTO(out, rc = -ENOMEM);
        }
        /* NB req now owns desc and will free it when it gets freed */

        rc = ptlrpc_prep_bulk_page(desc, page, 0, PAGE_CACHE_SIZE);
        if (rc != 0)
                GOTO(out, rc);

        mds_readdir_pack(req, offset, PAGE_CACHE_SIZE, ino, type);

        req->rq_replen = lustre_msg_size(1, &size);
        rc = ptlrpc_queue_wait(req);

        if (rc == 0) {
                LASSERT (desc->bd_page_count == 1);
                body = lustre_swab_repbuf (req, 0, sizeof (*body),
                                           lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't unpack mds_body\n");
                        GOTO (out, rc = -EPROTO);
                }
        }

        EXIT;
 out:
        *request = req;
        return rc;
}

static int mdc_iocontrol(unsigned int cmd, struct lustre_handle *conn, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        struct obd_import *imp = obddev->u.cli.cl_import;
        ENTRY;

        switch (cmd) {
        case OBD_IOC_CLIENT_RECOVER:
                RETURN(ptlrpc_recover_import(imp, data->ioc_inlbuf1));
        case IOC_OSC_SET_ACTIVE:
                if (data->ioc_offset) {
                        CERROR("%s: can't reactivate MDC\n",
                               obddev->obd_uuid.uuid);
                        RETURN(-ENOTTY);
                }
                RETURN(ptlrpc_set_import_active(imp, 0));
        default:
                CERROR("osc_ioctl(): unrecognised ioctl %#x\n", cmd);
                RETURN(-ENOTTY);
        }
}

static int mdc_statfs(struct lustre_handle *conn, struct obd_statfs *osfs)
{
        struct ptlrpc_request *req;
        struct obd_statfs *msfs;
        int rc, size = sizeof(*msfs);
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_STATFS, 0, NULL,
                              NULL);
        if (!req)
                RETURN(-ENOMEM);

        req->rq_replen = lustre_msg_size(1, &size);

        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);

        if (rc)
                GOTO(out, rc);

        msfs = lustre_swab_repbuf (req, 0, sizeof (*msfs),
                                   lustre_swab_obd_statfs);
        if (msfs == NULL) {
                CERROR ("Can't unpack obd_statfs\n");
                GOTO (out, rc = -EPROTO);
        }

        memcpy (osfs, msfs, sizeof (*msfs));
        EXIT;
out:
        ptlrpc_req_finished(req);

        return rc;
}

static int mdc_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(&lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

static int mdc_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

struct obd_ops mdc_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      mdc_attach,
        o_detach:      mdc_detach,
        o_setup:       client_obd_setup,
        o_cleanup:     client_obd_cleanup,
        o_connect:     client_import_connect,
        o_disconnect:  client_import_disconnect,
        o_iocontrol:   mdc_iocontrol,
        o_statfs:      mdc_statfs
};

int __init mdc_init(void)
{
        struct lprocfs_static_vars lvars;
        mdc_init_rpc_lock(&mdc_rpc_lock);
        mdc_init_rpc_lock(&mdc_setattr_lock);
        lprocfs_init_vars(&lvars);
        return class_register_type(&mdc_obd_ops, lvars.module_vars,
                                   LUSTRE_MDC_NAME);
}

static void __exit mdc_exit(void)
{
        class_unregister_type(LUSTRE_MDC_NAME);
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Client");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mdc_getstatus);
EXPORT_SYMBOL(mdc_getlovinfo);
EXPORT_SYMBOL(mdc_enqueue);
EXPORT_SYMBOL(mdc_getattr);
EXPORT_SYMBOL(mdc_getattr_name);
EXPORT_SYMBOL(mdc_create);
EXPORT_SYMBOL(mdc_unlink);
EXPORT_SYMBOL(mdc_rename);
EXPORT_SYMBOL(mdc_link);
EXPORT_SYMBOL(mdc_readpage);
EXPORT_SYMBOL(mdc_setattr);
EXPORT_SYMBOL(mdc_close);
EXPORT_SYMBOL(mdc_set_open_replay_data);

EXPORT_SYMBOL(mdc_store_inode_generation);

module_init(mdc_init);
module_exit(mdc_exit);
#endif
