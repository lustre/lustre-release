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

#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/miscdevice.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/lprocfs_status.h>

#define REQUEST_MINOR 244

extern int mds_queue_req(struct ptlrpc_request *);
struct mdc_rpc_lock mdc_rpc_lock;
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

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        req->rq_level = level;
        req->rq_replen = lustre_msg_size(1, &size);

        mds_pack_req_body(req);
        req->rq_reqmsg->flags |= msg_flags;
        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);

        if (!rc) {
                body = lustre_msg_buf(req->rq_repmsg, 0);
                mds_unpack_body(body);
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
        int rc, size[2] = {sizeof(*streq)};
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(mdc_connh), MDS_GETLOVINFO, 1,
                              size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        *request = req;
        streq = lustre_msg_buf(req->rq_reqmsg, 0);
        streq->flags = HTON__u32(MDS_STATUS_LOV);
        streq->repbuf = HTON__u32(8192);

        /* prepare for reply */
        req->rq_level = LUSTRE_CONN_CON;
        size[0] = 512;
        size[1] = 8192;
        req->rq_replen = lustre_msg_size(2, size);
        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);

 out:
        RETURN(rc);
}

int mdc_getattr(struct lustre_handle *conn,
                obd_id ino, int type, unsigned long valid, unsigned int ea_size,
                struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size[2] = {sizeof(*body), 0}, bufcount = 1;
        ENTRY;

        /* XXX do we need to make another request here?  We just did a getattr
         *     to do the lookup in the first place.
         */
        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_GETATTR, 1, size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        /* XXX FIXME bug 249 */
        req->rq_request_portal = MDS_GETATTR_PORTAL;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_ino2fid(&body->fid1, ino, 0, type);
        body->valid = valid;

        if (ea_size) {
                size[bufcount] = ea_size;
                bufcount++;
                body->size = ea_size;
                CDEBUG(D_INODE, "reserved %u bytes for MD/symlink in packet\n",
                       ea_size);
        }
        req->rq_replen = lustre_msg_size(bufcount, size);
        mds_pack_req_body(req);

        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);
        if (!rc) {
                body = lustre_msg_buf(req->rq_repmsg, 0);
                mds_unpack_body(body);
                CDEBUG(D_NET, "mode: %o\n", body->mode);
        }

        GOTO(out, rc);
 out:
        *request = req;
        return rc;
}

int mdc_getattr_name(struct lustre_handle *conn, struct inode *parent,
                     char *filename, int namelen, unsigned long valid,
                     unsigned int ea_size, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size[2] = {sizeof(*body), namelen}, bufcount = 1;
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_GETATTR_NAME, 2,
                              size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_inode2fid(&body->fid1, parent);
        body->valid = valid;
        memcpy(lustre_msg_buf(req->rq_reqmsg, 1), filename, namelen);

        if (ea_size) {
                size[1] = ea_size;
                bufcount++;
                body->size = ea_size;
                CDEBUG(D_INODE, "reserved %u bytes for MD/symlink in packet\n",
                       ea_size);
                valid |= OBD_MD_FLEASIZE;
        }

        req->rq_replen = lustre_msg_size(bufcount, size);
        mds_pack_req_body(req);

        mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(&mdc_rpc_lock, NULL);
        if (!rc) {
                body = lustre_msg_buf(req->rq_repmsg, 0);
                mds_unpack_body(body);
        }

        EXIT;
 out:
        *request = req;
        return rc;
}

/* This should be called with both the request and the reply still packed. */
void mdc_store_inode_generation(struct ptlrpc_request *req, int reqoff,
                                int repoff)
{
        struct mds_rec_create *rec = lustre_msg_buf(req->rq_reqmsg, reqoff);
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, repoff);

        memcpy(&rec->cr_replayfid, &body->fid1, sizeof rec->cr_replayfid);
        DEBUG_REQ(D_HA, req, "storing generation %x for ino "LPD64,
                  rec->cr_replayfid.generation, rec->cr_replayfid.id);
}

static int mdc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                            void *data, int flag)
{
        int rc;
        struct lustre_handle lockh;
        ENTRY;


        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0) {
                        CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
                        RETURN(rc);
                }
                break;
        case LDLM_CB_CANCELING: {
                /* Invalidate all dentries associated with this inode */
                struct inode *inode = lock->l_data;

                LASSERT(data != NULL);

                /* XXX what tells us that 'data' is a valid inode at all?
                 *     we should probably validate the lock handle first?
                 */

                inode = igrab(inode);

                if (inode == NULL)      /* inode->i_state & I_FREEING */
                        break;

                if (S_ISDIR(inode->i_mode)) {
                        CDEBUG(D_INODE, "invalidating inode %lu\n",
                               inode->i_ino);

                        ll_invalidate_inode_pages(inode);
                }

                if (inode != inode->i_sb->s_root->d_inode)
                        d_unhash_aliases(inode);

                iput(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

/* We always reserve enough space in the reply packet for a stripe MD, because
 * we don't know in advance the file type.
 *
 * XXX we could get that from ext2_dir_entry_2 file_type
 */
int mdc_enqueue(struct lustre_handle *conn, int lock_type,
                struct lookup_intent *it, int lock_mode, struct inode *dir,
                struct dentry *de, struct lustre_handle *lockh,
                char *tgt, int tgtlen, void *data, int datalen)
{
        struct ptlrpc_request *req;
        struct obd_device *obddev = class_conn2obd(conn);
        struct ldlm_res_id res_id =
                { .name = {dir->i_ino, dir->i_generation} };
        int size[6] = {sizeof(struct ldlm_request), sizeof(struct ldlm_intent)};
        int rc, flags = LDLM_FL_HAS_INTENT;
        int repsize[3] = {sizeof(struct ldlm_reply),
                          sizeof(struct mds_body),
                          obddev->u.cli.cl_max_mds_easize};
        struct mdc_unlink_data *d = data;
        struct ldlm_reply *dlm_rep;
        struct ldlm_intent *lit;
        struct ldlm_request *lockreq;
        ENTRY;

        LDLM_DEBUG_NOLOCK("mdsintent %s parent dir %lu",
                          ldlm_it2str(it->it_op), dir->i_ino);

        if (it->it_op & IT_OPEN) {
                it->it_mode |= S_IFREG;
                it->it_mode &= ~current->fs->umask;

                size[2] = sizeof(struct mds_rec_create);
                size[3] = de->d_name.len + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                req->rq_flags |= PTL_RPC_FL_REPLAY;

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1);
                lit->opc = NTOH__u64((__u64)it->it_op);

                /* pack the intended request */
                mds_open_pack(req, 2, dir, it->it_mode, 0, current->fsuid,
                              current->fsgid, CURRENT_TIME, it->it_flags,
                              de->d_name.name, de->d_name.len, tgt, tgtlen);
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op & IT_UNLINK) {
                size[2] = sizeof(struct mds_rec_unlink);
                size[3] = d->unl_len + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1);
                lit->opc = NTOH__u64((__u64)it->it_op);

                /* pack the intended request */
                mds_unlink_pack(req, 2, d->unl_dir, 
                                d->unl_de, d->unl_mode,
                                d->unl_name, d->unl_len);
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op & (IT_GETATTR| IT_SETATTR | IT_LOOKUP)) {
                int valid = OBD_MD_FLNOTOBD | OBD_MD_FLEASIZE;
                size[2] = sizeof(struct mds_body);
                size[3] = de->d_name.len + 1;

                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1);
                lit->opc = NTOH__u64((__u64)it->it_op);

                /* pack the intended request */
                mds_getattr_pack(req, valid, 2, it->it_flags,  dir,
                                 de->d_name.name, de->d_name.len);
                /* get ready for the reply */
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op == IT_READDIR) {
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 1,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* get ready for the reply */
                req->rq_replen = lustre_msg_size(1, repsize);
        }  else {
                LBUG();
                RETURN(-EINVAL);
        }

        mdc_get_rpc_lock(&mdc_rpc_lock, it);
        rc = ldlm_cli_enqueue(conn, req, obddev->obd_namespace, NULL, res_id,
                              lock_type, NULL, 0, lock_mode, &flags,
                              ldlm_completion_ast, mdc_blocking_ast, dir, NULL,
                              lockh);

        /* If we successfully created, mark the request so that replay will
         * do the right thing */
        if (req->rq_transno) {
                struct mds_rec_create *rec = lustre_msg_buf(req->rq_reqmsg, 2);
                rec->cr_opcode |= REINT_REPLAYING;
        }
        /* Similarly, if we're going to replay this request, we don't want to
         * actually get a lock, just perform the intent. */
        if (req->rq_transno || (req->rq_flags & PTL_RPC_FL_REPLAY)) {
                lockreq = lustre_msg_buf(req->rq_reqmsg, 0);
                lockreq->lock_flags |= LDLM_FL_INTENT_ONLY;
        }

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0);

        /* This can go when we're sure that this can never happen */
        LASSERT(rc != -ENOENT);
        if (rc == ELDLM_LOCK_ABORTED) {
                lock_mode = 0;
                memset(lockh, 0, sizeof(*lockh));
        } else if (rc != 0) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
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
                LDLM_DEBUG0(lock, "matching against this");

                memcpy(&lockh2, lockh, sizeof(lockh2));
                if (ldlm_lock_match(NULL, LDLM_FL_BLOCK_GRANTED, NULL,
                                    LDLM_PLAIN, NULL, 0, LCK_NL, &lockh2)) {
                        /* We already have a lock; cancel the new one */
                        ldlm_lock_decref_and_cancel(lockh, lock_mode);
                        memcpy(lockh, &lockh2, sizeof(lockh2));
                }
                LDLM_LOCK_PUT(lock);
        }

        it->it_disposition = (int) dlm_rep->lock_policy_res1;
        it->it_status = (int) dlm_rep->lock_policy_res2;
        it->it_lock_mode = lock_mode;
        it->it_data = req;

        RETURN(rc);
}

void mdc_lock_set_inode(struct lustre_handle *lockh, struct inode *inode)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        ENTRY;

        LASSERT(lock != NULL);
        lock->l_data = inode;
        LDLM_LOCK_PUT(lock);
        EXIT;
}

int mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                      int flags)
{
        struct ldlm_res_id res_id =
                { .name = {inode->i_ino, inode->i_generation} };
        struct obd_device *obddev = class_conn2obd(conn);
        ENTRY;
        RETURN(ldlm_cli_cancel_unused(obddev->obd_namespace, &res_id, flags));
}

static void mdc_replay_open(struct ptlrpc_request *req)
{
        struct lustre_handle old, *file_fh = req->rq_replay_data;
        struct list_head *tmp;
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 0);

        mds_unpack_body(body);
        memcpy(&old, file_fh, sizeof(old));
        CDEBUG(D_HA, "updating from "LPD64"/"LPD64" to "LPD64"/"LPD64"\n",
               file_fh->addr, file_fh->cookie, body->handle.addr,
               body->handle.cookie);
        memcpy(file_fh, &body->handle, sizeof(body->handle));

        /* A few frames up, ptlrpc_replay holds the lock, so this is safe. */
        list_for_each(tmp, &req->rq_import->imp_sending_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                if (req->rq_reqmsg->opc != MDS_CLOSE)
                        continue;
                body = lustre_msg_buf(req->rq_reqmsg, 0);
                if (memcmp(&body->handle, &old, sizeof(old)))
                        continue;

                DEBUG_REQ(D_HA, req, "updating close body with new fh");
                memcpy(&body->handle, file_fh, sizeof(*file_fh));
        }
}

void mdc_set_open_replay_data(struct ll_file_data *fd)
{
        fd->fd_req->rq_replay_cb = mdc_replay_open;
        fd->fd_req->rq_replay_data = &fd->fd_mdshandle;
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

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_ino2fid(&body->fid1, ino, 0, type);
        memcpy(&body->handle, fh, sizeof(body->handle));

        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);

        EXIT;
 out:
        *request = req;
        return rc;
}

int mdc_readpage(struct lustre_handle *conn, obd_id ino, int type, __u64 offset,
                 char *addr, struct ptlrpc_request **request)
{
        struct obd_import *imp = class_conn2cliimp(conn);
        struct ptlrpc_connection *connection =
                client_conn2cli(conn)->cl_import.imp_connection;
        struct ptlrpc_request *req = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ptlrpc_bulk_page *bulk = NULL;
        struct mds_body *body;
        unsigned long flags;
        int rc, size = sizeof(*body);
        ENTRY;

        CDEBUG(D_INODE, "inode: %ld\n", (long)ino);

        desc = ptlrpc_prep_bulk(connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        req = ptlrpc_prep_req(imp, MDS_READPAGE, 1, &size, NULL);
        if (!req)
                GOTO(out2, rc = -ENOMEM);

        bulk = ptlrpc_prep_bulk_page(desc);
        if (bulk == NULL)
                GOTO(out2, rc = -ENOMEM);

        spin_lock_irqsave(&imp->imp_lock, flags);
        bulk->bp_xid = ++imp->imp_last_bulk_xid;
        spin_unlock_irqrestore(&imp->imp_lock, flags);
        bulk->bp_buflen = PAGE_CACHE_SIZE;
        bulk->bp_buf = addr;

        desc->bd_ptl_ev_hdlr = NULL;
        desc->bd_portal = MDS_BULK_PORTAL;

        rc = ptlrpc_register_bulk_put(desc);
        if (rc) {
                CERROR("couldn't setup bulk sink: error %d.\n", rc);
                GOTO(out2, rc);
        }

        mds_readdir_pack(req, offset, ino, type, bulk->bp_xid);

        req->rq_replen = lustre_msg_size(1, &size);
        rc = ptlrpc_queue_wait(req);
        if (rc) {
                ptlrpc_abort_bulk(desc);
                GOTO(out2, rc);
        } else {
                body = lustre_msg_buf(req->rq_repmsg, 0);
                mds_unpack_body(body);
        }

        EXIT;
 out2:
        ptlrpc_bulk_decref(desc);
 out:
        *request = req;
        return rc;
}

static int mdc_statfs(struct lustre_handle *conn, struct obd_statfs *osfs)
{
        struct ptlrpc_request *req;
        int rc, size = sizeof(*osfs);
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

        obd_statfs_unpack(osfs, lustre_msg_buf(req->rq_repmsg, 0));

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

/* Send a mostly-dummy GETSTATUS request and indicate that we're done replay. */
static int signal_completed_replay(struct obd_import *imp)
{
        struct ll_fid fid;

        return send_getstatus(imp, &fid, LUSTRE_CONN_RECOVD, MSG_LAST_REPLAY);
}

static int mdc_recover(struct obd_import *imp, int phase)
{
        int rc;
        unsigned long flags;
        struct ptlrpc_request *req;
        struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
        ENTRY;

        switch(phase) {
            case PTLRPC_RECOVD_PHASE_PREPARE:
                ldlm_cli_cancel_unused(ns, NULL, LDLM_FL_LOCAL_ONLY);
                RETURN(0);

            case PTLRPC_RECOVD_PHASE_NOTCONN:
                ldlm_namespace_cleanup(ns, 1);
                ptlrpc_abort_inflight(imp, 0);
                /* FALL THROUGH */
            case PTLRPC_RECOVD_PHASE_RECOVER:
        reconnect:
                rc = ptlrpc_reconnect_import(imp, MDS_CONNECT, &req);

                flags = req->rq_repmsg
                        ? lustre_msg_get_op_flags(req->rq_repmsg)
                        : 0;

                if (rc == -EBUSY && (flags & MSG_CONNECT_RECOVERING))
                        CERROR("reconnect denied by recovery; should retry\n");

                if (rc) {
                        if (phase != PTLRPC_RECOVD_PHASE_NOTCONN) {
                                CERROR("can't reconnect, invalidating\n");
                                ldlm_namespace_cleanup(ns, 1);
                                ptlrpc_abort_inflight(imp, 0);
                        }
                        ptlrpc_req_finished(req);
                        RETURN(rc);
                }

                if (flags & MSG_CONNECT_RECOVERING) {
                        /* Replay if they want it. */
                        DEBUG_REQ(D_HA, req, "MDS wants replay");
                        rc = ptlrpc_replay(imp);
                        if (rc)
                                GOTO(check_rc, rc);

                        rc = ldlm_replay_locks(imp);
                        if (rc)
                                GOTO(check_rc, rc);

                        rc = signal_completed_replay(imp);
                        if (rc)
                                GOTO(check_rc, rc);
                } else if (flags & MSG_CONNECT_RECONNECT) {
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

                ptlrpc_wake_delayed(imp);

                rc = ptlrpc_resend(imp);
                if (rc)
                        GOTO(check_rc, rc);

                RETURN(0);
        check_rc:
                /* If we get disconnected in the middle, recovery has probably
                 * failed.  Reconnect and find out.
                 */
                if (rc == -ENOTCONN)
                        goto reconnect;
                RETURN(rc);

            default:
                RETURN(-EINVAL);
        }
}

static int mdc_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct obd_import *imp = &obd->u.cli.cl_import;
        imp->imp_recover = mdc_recover;
        return client_obd_connect(conn, obd, cluuid, recovd, recover);
}

struct obd_ops mdc_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      mdc_attach,
        o_detach:      mdc_detach,
        o_setup:       client_obd_setup,
        o_cleanup:     client_obd_cleanup,
        o_connect:     mdc_connect,
        o_disconnect:  client_obd_disconnect,
        o_statfs:      mdc_statfs
};

static int __init ptlrpc_request_init(void)
{
        struct lprocfs_static_vars lvars;
        mdc_init_rpc_lock(&mdc_rpc_lock);
        lprocfs_init_vars(&lvars);
        return class_register_type(&mdc_obd_ops, lvars.module_vars,
                                   LUSTRE_MDC_NAME);
}

static void __exit ptlrpc_request_exit(void)
{
        class_unregister_type(LUSTRE_MDC_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Client");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mdc_getstatus);
EXPORT_SYMBOL(mdc_getlovinfo);
EXPORT_SYMBOL(mdc_enqueue);
EXPORT_SYMBOL(mdc_cancel_unused);
EXPORT_SYMBOL(mdc_getattr);
EXPORT_SYMBOL(mdc_getattr_name);
EXPORT_SYMBOL(mdc_create);
EXPORT_SYMBOL(mdc_unlink);
EXPORT_SYMBOL(mdc_rename);
EXPORT_SYMBOL(mdc_link);
EXPORT_SYMBOL(mdc_readpage);
EXPORT_SYMBOL(mdc_setattr);
EXPORT_SYMBOL(mdc_close);
EXPORT_SYMBOL(mdc_lock_set_inode);
EXPORT_SYMBOL(mdc_set_open_replay_data);

EXPORT_SYMBOL(mdc_store_inode_generation);

module_init(ptlrpc_request_init);
module_exit(ptlrpc_request_exit);
