/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDC

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/obd_lov.h>
#include <linux/lprocfs_status.h>

#define REQUEST_MINOR 244

extern int mds_queue_req(struct ptlrpc_request *);
extern struct lprocfs_vars status_var_nm_1[];
extern struct lprocfs_vars status_class_var[];

/* should become mdc_getinfo() */
int mdc_getstatus(struct lustre_handle *conn, struct ll_fid *rootfid)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_GETSTATUS, 1, &size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        req->rq_level = LUSTRE_CONN_CON;
        req->rq_replen = lustre_msg_size(1, &size);

        mds_pack_req_body(req);
        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

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

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

 out:
        RETURN(rc);
}


int mdc_getattr(struct lustre_handle *conn,
                obd_id ino, int type, unsigned long valid, size_t ea_size,
                struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size[2] = {sizeof(*body), 0}, bufcount = 1;
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_GETATTR, 1, size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_ino2fid(&body->fid1, ino, 0, type);
        body->valid = valid;

        if (S_ISREG(type)) {
                struct client_obd *mdc = &class_conn2obd(conn)->u.cli;
                bufcount = 2;
                size[1] = mdc->cl_max_mds_easize;
        } else if (valid & OBD_MD_LINKNAME) {
                bufcount = 2;
                size[1] = ea_size;
                body->size = ea_size;
                CDEBUG(D_INODE, "allocating %d bytes for symlink in packet\n",
                       ea_size);
        }
        req->rq_replen = lustre_msg_size(bufcount, size);
        mds_pack_req_body(req);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        if (!rc) {
                body = lustre_msg_buf(req->rq_repmsg, 0);
                mds_unpack_body(body);
                CDEBUG(D_NET, "mode: %o\n", body->mode);
        }

        EXIT;
 out:
        *request = req;
        return rc;
}

void d_delete_aliases(struct inode *inode)
{
        struct dentry *dentry = NULL;
	struct list_head *tmp;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ENTRY;

	spin_lock(&dcache_lock);
        list_for_each(tmp, &inode->i_dentry) {
                dentry = list_entry(tmp, struct dentry, d_alias);

                //                if (atomic_read(&dentry->d_count))
                //      continue;
                //if (!list_empty(&dentry->d_lru))
                //        continue;

                list_del_init(&dentry->d_hash);
                list_add(&dentry->d_hash, &sbi->ll_orphan_dentry_list);
        }

        spin_unlock(&dcache_lock);
        EXIT;
}

static int mdc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                            void *data, __u32 data_len, int flag)
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
                struct inode *inode = data;

                LASSERT(inode != NULL);
                LASSERT(data_len == sizeof(*inode));

                if (S_ISDIR(inode->i_mode)) {
                        CDEBUG(D_INODE, "invalidating inode %ld\n",
                               inode->i_ino);

                        ll_invalidate_inode_pages(inode);
                }

                if ( inode != inode->i_sb->s_root->d_inode ) { 
                        LASSERT(igrab(inode) == inode);
                        d_delete_aliases(inode);
                        iput(inode);
                }
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

/* This should be called with both the request and the reply still packed. */
void mdc_store_inode_generation(struct ptlrpc_request *req, int reqoff,
                                int repoff)
{
        struct mds_rec_create *rec = lustre_msg_buf(req->rq_reqmsg, reqoff);
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, repoff);

        memcpy(&rec->cr_replayfid, &body->fid1, sizeof rec->cr_replayfid);
}

int mdc_enqueue(struct lustre_handle *conn, int lock_type,
                struct lookup_intent *it, int lock_mode, struct inode *dir,
                struct dentry *de, struct lustre_handle *lockh,
                char *tgt, int tgtlen, void *data, int datalen)
{
        struct ptlrpc_request *req;
        struct obd_device *obddev = class_conn2obd(conn);
        __u64 res_id[RES_NAME_SIZE] = {dir->i_ino, (__u64)dir->i_generation};
        int size[6] = {sizeof(struct ldlm_request), sizeof(struct ldlm_intent)};
        int rc, flags = LDLM_FL_HAS_INTENT;
        int repsize[3] = {sizeof(struct ldlm_reply),
                          sizeof(struct mds_body),
                          obddev->u.cli.cl_max_mds_easize};
        struct ldlm_reply *dlm_rep;
        struct ldlm_intent *lit;
        struct ldlm_request *lockreq;
        ENTRY;

        LDLM_DEBUG_NOLOCK("mdsintent %s dir %ld", ldlm_it2str(it->it_op),
                          dir->i_ino);

        if (it->it_op & (IT_MKDIR | IT_CREAT | IT_SYMLINK | IT_MKNOD)) {
                switch (it->it_op) {
                case IT_MKDIR:
                        it->it_mode |= S_IFDIR;
                        break;
                case (IT_CREAT|IT_OPEN):
                case IT_CREAT:
                        it->it_mode |= S_IFREG;
                        break;
                case IT_SYMLINK:
                        it->it_mode |= S_IFLNK;
                        break;
                }
                it->it_mode &= ~current->fs->umask;

                size[2] = sizeof(struct mds_rec_create);
                size[3] = de->d_name.len + 1;
                size[4] = tgtlen + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 5,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1);
                lit->opc = NTOH__u64((__u64)it->it_op);

                /* pack the intended request */
                mds_create_pack(req, 2, dir, it->it_mode, 0, current->fsuid,
                                current->fsgid, CURRENT_TIME, de->d_name.name,
                                de->d_name.len, tgt, tgtlen);
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op == IT_RENAME2) {
                struct dentry *old_de = it->it_data;

                size[2] = sizeof(struct mds_rec_rename);
                size[3] = old_de->d_name.len + 1;
                size[4] = de->d_name.len + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 5,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1);
                lit->opc = NTOH__u64((__u64)it->it_op);

                /* pack the intended request */
                mds_rename_pack(req, 2, old_de->d_parent->d_inode, dir,
                                old_de->d_name.name, old_de->d_name.len,
                                de->d_name.name, de->d_name.len);
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op == IT_LINK2) {
                struct dentry *old_de = it->it_data;

                size[2] = sizeof(struct mds_rec_link);
                size[3] = de->d_name.len + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1);
                lit->opc = NTOH__u64((__u64)it->it_op);

                /* pack the intended request */
                mds_link_pack(req, 2, old_de->d_inode, dir,
                              de->d_name.name, de->d_name.len);
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op == IT_UNLINK || it->it_op == IT_RMDIR) {
                size[2] = sizeof(struct mds_rec_unlink);
                size[3] = de->d_name.len + 1;
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1);
                lit->opc = NTOH__u64((__u64)it->it_op);

                /* pack the intended request */
                mds_unlink_pack(req, 2, dir, NULL,
                                it->it_op == IT_UNLINK ? S_IFREG : S_IFDIR,
                                de->d_name.name, de->d_name.len);

                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op  & (IT_GETATTR | IT_RENAME | IT_LINK | 
                   IT_OPEN |  IT_SETATTR | IT_LOOKUP | IT_READLINK)) {
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
                mds_getattr_pack(req, 2, dir, de->d_name.name, de->d_name.len);

                /* get ready for the reply */
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op == IT_READDIR) {
                req = ptlrpc_prep_req(class_conn2cliimp(conn), LDLM_ENQUEUE, 1,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* get ready for the reply */
                req->rq_replen = lustre_msg_size(1, repsize);
        } else {
                LBUG();
                RETURN(-EINVAL);
        }

        rc = ldlm_cli_enqueue(conn, req, obddev->obd_namespace, NULL, res_id,
                              lock_type, NULL, 0, lock_mode, &flags,
                              ldlm_completion_ast, mdc_blocking_ast, data,
                              datalen, lockh);

        if (it->it_op != IT_READDIR) {
                /* XXX This should become a lustre_msg flag, but for now... */
                __u32 *opp = lustre_msg_buf(req->rq_reqmsg, 2);
                *opp |= REINT_REPLAYING;
        }

        if (rc == -ENOENT) {
                /* This can go when we're sure that this can never happen */
                LBUG();
        }
        if (rc == ELDLM_LOCK_ABORTED) {
                lock_mode = 0;
                memset(lockh, 0, sizeof(*lockh));
                /* rc = 0 */
        } else if (rc != 0) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                RETURN(rc);
        } else {
                /* The server almost certainly gave us a lock other than the one
                 * that we asked for.  If we already have a matching lock, then
                 * cancel this one--we don't need two. */
                struct ldlm_lock *lock = ldlm_handle2lock(lockh);
                struct lustre_handle lockh2;
                LASSERT(lock);

                LDLM_DEBUG(lock, "matching against this");

                memcpy(&lockh2, lockh, sizeof(lockh2));
                if (ldlm_lock_match(NULL, NULL, LDLM_PLAIN, NULL, 0, LCK_NL,
                                    &lockh2)) {
                        /* We already have a lock; cancel the old one */
                        ldlm_lock_decref(lockh, lock_mode);
                        ldlm_cli_cancel(lockh);
                        memcpy(lockh, &lockh2, sizeof(lockh2));
                }
                LDLM_LOCK_PUT(lock);
        }

        /* On replay, we don't want the lock granted. */
        lockreq = lustre_msg_buf(req->rq_reqmsg, 0);
        lockreq->lock_flags |= LDLM_FL_INTENT_ONLY;

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0);
        it->it_disposition = (int) dlm_rep->lock_policy_res1;
        it->it_status = (int) dlm_rep->lock_policy_res2;
        it->it_lock_mode = lock_mode;
        it->it_data = req;

        RETURN(0);
}

int mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                      int flags)
{
        __u64 res_id[RES_NAME_SIZE] = {inode->i_ino, inode->i_generation};
        struct obd_device *obddev = class_conn2obd(conn);
        ENTRY;
        RETURN(ldlm_cli_cancel_unused(obddev->obd_namespace, res_id, flags));
}

struct replay_open_data {
        struct lustre_handle *fh;
};

static void mdc_replay_open(struct ptlrpc_request *req)
{
        int offset;
        struct replay_open_data *saved;
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 0);

        if (lustre_msg_get_op_flags(req->rq_reqmsg) & MDS_OPEN_HAS_EA)
                offset = 2;
        else
                offset = 1;

        saved = lustre_msg_buf(req->rq_reqmsg, offset);
        mds_unpack_body(body);
        CDEBUG(D_HA, "updating from "LPD64"/"LPD64" to "LPD64"/"LPD64"\n",
               saved->fh->addr, saved->fh->cookie,
               body->handle.addr, body->handle.cookie);
        memcpy(saved->fh, &body->handle, sizeof(body->handle));
}

int mdc_open(struct lustre_handle *conn, obd_id ino, int type, int flags,
             struct lov_stripe_md *lsm, struct lustre_handle *fh,
             struct ptlrpc_request **request)
{
        struct mds_body *body;
        struct replay_open_data *replay_data;
        int rc, size[3] = {sizeof(*body), sizeof(*replay_data)}, bufcount = 2;
        struct ptlrpc_request *req;
        ENTRY;

        if (lsm) {
                bufcount = 3;
                size[2] = size[1]; /* shuffle the spare data along */

                size[1] = lsm->lsm_mds_easize;
        }

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_OPEN, bufcount, size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        if (lsm)
                lustre_msg_set_op_flags(req->rq_reqmsg, MDS_OPEN_HAS_EA);


        req->rq_flags |= PTL_RPC_FL_REPLAY;
        body = lustre_msg_buf(req->rq_reqmsg, 0);

        ll_ino2fid(&body->fid1, ino, 0, type);
        body->flags = HTON__u32(flags);
        memcpy(&body->handle, fh, sizeof(body->handle));

        if (lsm)
                lov_packmd(lustre_msg_buf(req->rq_reqmsg, 1), lsm);

        req->rq_replen = lustre_msg_size(1, size);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        if (!rc) {
                body = lustre_msg_buf(req->rq_repmsg, 0);
                mds_unpack_body(body);
                memcpy(fh, &body->handle, sizeof(*fh));
        }

        /* If open is replayed, we need to fix up the fh. */
        req->rq_replay_cb = mdc_replay_open;
        replay_data = lustre_msg_buf(req->rq_reqmsg, lsm ? 2 : 1);
        replay_data->fh = fh;
        
        EXIT;
 out:
        *request = req;
        return rc;
}

int mdc_close(struct lustre_handle *conn, obd_id ino, int type,
              struct lustre_handle *fh, struct ptlrpc_request **request)
{
        struct mds_body *body;
        int rc, size = sizeof(*body);
        struct ptlrpc_request *req;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_CLOSE, 1, &size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_ino2fid(&body->fid1, ino, 0, type);
        memcpy(&body->handle, fh, sizeof(body->handle));

        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        EXIT;
 out:
        *request = req;
        return rc;
}

int mdc_readpage(struct lustre_handle *conn, obd_id ino, int type, __u64 offset,
                 char *addr, struct ptlrpc_request **request)
{
        struct ptlrpc_connection *connection = 
                client_conn2cli(conn)->cl_import.imp_connection;
        struct ptlrpc_request *req = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct ptlrpc_bulk_page *bulk = NULL;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        CDEBUG(D_INODE, "inode: %ld\n", (long)ino);

        desc = ptlrpc_prep_bulk(connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_READPAGE, 1, &size,
                              NULL);
        if (!req)
                GOTO(out2, rc = -ENOMEM);

        bulk = ptlrpc_prep_bulk_page(desc);
        bulk->bp_buflen = PAGE_SIZE;
        bulk->bp_buf = addr;
        bulk->bp_xid = req->rq_xid;
        desc->bd_portal = MDS_BULK_PORTAL;

        rc = ptlrpc_register_bulk(desc);
        if (rc) {
                CERROR("couldn't setup bulk sink: error %d.\n", rc);
                GOTO(out2, rc);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->fid1.id = ino;
        body->fid1.f_type = type;
        body->size = offset;

        req->rq_replen = lustre_msg_size(1, &size);
        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        if (rc) {
                ptlrpc_abort_bulk(desc);
                GOTO(out2, rc);
        } else {
                body = lustre_msg_buf(req->rq_repmsg, 0);
                mds_unpack_body(body);
        }

        EXIT;
 out2:
        ptlrpc_free_bulk(desc);
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

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        if (rc)
                GOTO(out, rc);

        obd_statfs_unpack(osfs, lustre_msg_buf(req->rq_repmsg, 0));

        EXIT;
out:
        ptlrpc_req_finished(req);

        return rc;
}
int mdc_attach(struct obd_device *dev, 
                   obd_count len, void *data)
{
        int rc;
        rc = lprocfs_reg_obd(dev, (struct lprocfs_vars*)status_var_nm_1, 
			     (void*)dev);
        return rc; 
}

int mdc_detach(struct obd_device *dev)
{
        int rc;
        rc = lprocfs_dereg_obd(dev);
        return rc;

}
struct obd_ops mdc_obd_ops = {
        o_attach: mdc_attach,
        o_detach: mdc_detach,
        o_setup:   client_obd_setup,
        o_cleanup: client_obd_cleanup,
        o_connect: client_obd_connect,
        o_disconnect: client_obd_disconnect,
        o_statfs: mdc_statfs,
};

static int __init ptlrpc_request_init(void)
{
        int rc;
        rc = class_register_type(&mdc_obd_ops, 
                                 (struct lprocfs_vars*)status_class_var, 
                                 LUSTRE_MDC_NAME);
        if(rc)
                RETURN(rc);
        return 0;
        
}

static void __exit ptlrpc_request_exit(void)
{
        
        class_unregister_type(LUSTRE_MDC_NAME);
        
}

MODULE_AUTHOR("Cluster File Systems <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Client v1.0");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(d_delete_aliases);
EXPORT_SYMBOL(mdc_getstatus);
EXPORT_SYMBOL(mdc_getlovinfo);
EXPORT_SYMBOL(mdc_enqueue);
EXPORT_SYMBOL(mdc_cancel_unused);
EXPORT_SYMBOL(mdc_getattr);
EXPORT_SYMBOL(mdc_create);
EXPORT_SYMBOL(mdc_unlink);
EXPORT_SYMBOL(mdc_rename);
EXPORT_SYMBOL(mdc_link);
EXPORT_SYMBOL(mdc_readpage);
EXPORT_SYMBOL(mdc_setattr);
EXPORT_SYMBOL(mdc_close);
EXPORT_SYMBOL(mdc_open);

EXPORT_SYMBOL(mdc_store_inode_generation);

module_init(ptlrpc_request_init);
module_exit(ptlrpc_request_exit);
