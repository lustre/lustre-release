/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
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
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
#else
# include <linux/locks.h>
#endif
#include <linux/obd_lov.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>

#include "mds_internal.h"

struct mds_file_data *mds_dentry_open(struct dentry *dentry,
                                      struct vfsmount *mnt,
                                      int flags,
                                      struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct inode *inode;
        struct mds_file_data *mfd;
        int mode, error;

        mfd = mds_mfd_new();
        if (mfd == NULL) {
                CERROR("mds: out of memory\n");
                GOTO(cleanup_dentry, error = -ENOMEM);
        }

        mode = (flags + 1) & O_ACCMODE;
        inode = dentry->d_inode;

        if (mode & FMODE_WRITE) {
                error = get_write_access(inode);
                if (error)
                        goto cleanup_mfd;
        }

        mfd->mfd_mode = mode;
        mfd->mfd_dentry = dentry;
        mfd->mfd_xid = req->rq_xid;

        spin_lock(&med->med_open_lock);
        list_add(&mfd->mfd_list, &med->med_open_head);
        spin_unlock(&med->med_open_lock);
        mds_mfd_put(mfd);
        return mfd;

cleanup_mfd:
        mds_mfd_put(mfd);
        mds_mfd_destroy(mfd);
cleanup_dentry:
        dput(dentry);
        mntput(mnt);
        return ERR_PTR(error);
}

void reconstruct_open(struct mds_update_record *rec, int offset,
                      struct ptlrpc_request *req,
                      struct lustre_handle *child_lockh)
{
        struct ptlrpc_request *oldreq = req->rq_export->exp_outstanding_reply;
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_file_data *mfd;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *parent, *child;
        struct ldlm_reply *rep;
        struct mds_body *body;
        int rc;
        struct list_head *t;
        int put_child = 1;
        ENTRY;

        LASSERT(offset == 2);                  /* only called via intent */
        rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));

        /* copy rc, transno and disp; steal locks */
        req->rq_transno = mcd->mcd_last_transno;
        req->rq_status = mcd->mcd_last_result;
        intent_set_disposition(rep, mcd->mcd_last_data);

        if (oldreq)
                mds_steal_ack_locks(req->rq_export, req);

        /* Only replay if create or open actually happened. */
        if (!intent_disposition(rep, DISP_OPEN_CREATE | DISP_OPEN_OPEN) ) {
                EXIT;
                return; /* error looking up parent or child */
        }

        parent = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        LASSERT(!IS_ERR(parent));

        child = ll_lookup_one_len(rec->ur_name, parent, rec->ur_namelen - 1);
        LASSERT(!IS_ERR(child));

        if (!child->d_inode) {
                GOTO(out_dput, 0); /* child not present to open */
        }

        /* At this point, we know we have a child. We'll send
         * it back _unless_ it not created and open failed.
         */
        if (intent_disposition(rep, DISP_OPEN_OPEN) &&
            !intent_disposition(rep, DISP_OPEN_CREATE) &&
            req->rq_status) {
                GOTO(out_dput, 0);
        }

        /* get lock (write for O_CREAT, read otherwise) */

        mds_pack_inode2fid(&body->fid1, child->d_inode);
        mds_pack_inode2body(body, child->d_inode);
        if (S_ISREG(child->d_inode->i_mode)) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body,
                                 child->d_inode);

                if (rc)
                        LASSERT(rc == req->rq_status);

                /* If we have LOV EA data, the OST holds size, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
        } else {
                /* XXX need to check this case */
        }

        /* If we're opening a file without an EA, change to a write
           lock (unless we already have one). */

        /* If we have -EEXIST as the status, and we were asked to create
         * exclusively, we can tell we failed because the file already existed.
         */
        if (req->rq_status == -EEXIST &&
            ((rec->ur_flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))) {
                GOTO(out_dput, 0);
        }

        /* If we didn't get as far as trying to open, then some locking thing
         * probably went wrong, and we'll just bail here.
         */
        if (!intent_disposition(rep, DISP_OPEN_OPEN))
                GOTO(out_dput, 0);

        /* If we failed, then we must have failed opening, so don't look for
         * file descriptor or anything, just give the client the bad news.
         */
        if (req->rq_status)
                GOTO(out_dput, 0);

        mfd = NULL;
        list_for_each(t, &med->med_open_head) {
                mfd = list_entry(t, struct mds_file_data, mfd_list);
                if (mfd->mfd_xid == req->rq_xid)
                        break;
                mfd = NULL;
        }

        if (oldreq) {
                /* if we're not recovering, it had better be found */
                LASSERT(mfd);
        } else if (mfd == NULL) {
                mntget(mds->mds_vfsmnt);
                CERROR("Re-opened file \n");
                mfd = mds_dentry_open(child, mds->mds_vfsmnt,
                                   rec->ur_flags & ~(O_DIRECT | O_TRUNC), req);
                if (!mfd) {
                        CERROR("mds: out of memory\n");
                        GOTO(out_dput, req->rq_status = -ENOMEM);
                }
                put_child = 0;
        }

        body->handle.cookie = mfd->mfd_handle.h_cookie;

 out_dput:
        if (put_child)
                l_dput(child);
        l_dput(parent);
        EXIT;
}

int mds_pin(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        struct mds_file_data *mfd = NULL;
        struct mds_body *body;
        struct dentry *dchild;
        struct obd_run_ctxt saved;
        char fidname[LL_FID_NAMELEN];
        int fidlen = 0, rc, cleanup_phase = 0, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));

        down(&pending_dir->i_sem);
        fidlen = ll_fid2str(fidname, body->fid1.id, body->fid1.generation);
        dchild = lookup_one_len(fidname, mds->mds_pending_dir, fidlen);
        if (IS_ERR(dchild)) {
                up(&pending_dir->i_sem);
                rc = PTR_ERR(dchild);
                CERROR("error looking up %s in PENDING: rc = %d\n",
                       fidname, rc);
                RETURN(rc);
        }

        cleanup_phase = 2;

        if (dchild->d_inode) {
                up(&pending_dir->i_sem);
                mds_inode_set_orphan(dchild->d_inode);
                mds_pack_inode2fid(&body->fid1, dchild->d_inode);
                mds_pack_inode2body(body, dchild->d_inode);
                GOTO(openit, rc = 0);
        }
        dput(dchild);
        up(&pending_dir->i_sem);

        /* We didn't find it in PENDING so it isn't an orphan.  See
         * if it's a regular inode. */
        dchild = mds_fid2dentry(mds, &body->fid1, NULL);
        if (!IS_ERR(dchild)) {
                mds_pack_inode2fid(&body->fid1, dchild->d_inode);
                mds_pack_inode2body(body, dchild->d_inode);
                GOTO(openit, rc = 0);
        }

        /* We didn't find this inode on disk, but we're trying to pin it.
         * This should never happen. */
        CERROR("ENOENT during mds_pin for fid "LPU64"/%u\n", body->fid1.id,
               body->fid1.generation);
        RETURN(-ENOENT);

 openit:
        /* dentry_open does a dput(de) and mntput(mds->mds_vfsmnt) on error */
        mfd = mds_dentry_open(dchild, mds->mds_vfsmnt, body->flags, req);
        if (IS_ERR(mfd)) {
                dchild = NULL; /* prevent a double dput in cleanup phase 2 */
                GOTO(cleanup, rc = PTR_ERR(mfd));
        }

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("out of memoryK\n");
                GOTO(cleanup, rc);
        }
        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));

        cleanup_phase = 4; /* mfd allocated */
        body->handle.cookie = mfd->mfd_handle.h_cookie;
        CDEBUG(D_INODE, "mfd %p, cookie "LPX64"\n", mfd,
               mfd->mfd_handle.h_cookie);
        GOTO(cleanup, rc = 0);

 cleanup:
        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, NULL,
                                req, rc, 0);
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);
        /* XXX what do we do here if mds_finish_transno itself failed? */
        switch (cleanup_phase) {
        case 4:
                if (rc)
                        mds_mfd_destroy(mfd);
        case 2:
                if (rc || S_ISLNK(dchild->d_inode->i_mode))
                        l_dput(dchild);
        }
        return rc;
}

int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *child_lockh)
{
        /* XXX ALLOCATE _something_ - 464 bytes on stack here */
        static const char acc_table [] = {[O_RDONLY] MAY_READ,
                                          [O_WRONLY] MAY_WRITE,
                                          [O_RDWR]   MAY_READ | MAY_WRITE};
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ldlm_reply *rep = NULL;
        struct mds_body *body = NULL;
        struct dentry *dchild = NULL, *parent = NULL;
        struct mds_export_data *med;
        struct mds_file_data *mfd = NULL;
        struct ldlm_res_id child_res_id = { .name = {0} };
        struct lustre_handle parent_lockh;
        int rc = 0, parent_mode, child_mode = LCK_PR, lock_flags, created = 0;
        int cleanup_phase = 0, acc_mode;
        void *handle = NULL;
        ENTRY;

        if (offset == 2) { /* intent */
                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));
        } else if (offset == 0) { /* non-intent reint */
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        } else {
                body = NULL;
                LBUG();
        }

        MDS_CHECK_RESENT(req, reconstruct_open(rec, offset, req, child_lockh));

        /* Step 0: If we are passed a fid, then we assume the client already
         * opened this file and is only replaying the RPC, so we open the
         * inode by fid (at some large expense in security).
         */
        if (rec->ur_fid2->id) {
                struct inode *pending_dir = mds->mds_pending_dir->d_inode;
                char fidname[LL_FID_NAMELEN];
                int fidlen = 0;

                down(&pending_dir->i_sem);
                fidlen = ll_fid2str(fidname, rec->ur_fid2->id,
                                    rec->ur_fid2->generation);
                dchild = lookup_one_len(fidname, mds->mds_pending_dir, fidlen);
                if (IS_ERR(dchild)) {
                        up(&pending_dir->i_sem);
                        rc = PTR_ERR(dchild);
                        CERROR("error looking up %s in PENDING: rc = %d\n",
                               fidname, rc);
                        RETURN(rc);
                }

                if (dchild->d_inode) {
                        up(&pending_dir->i_sem);
                        mds_inode_set_orphan(dchild->d_inode);
                        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
                        mds_pack_inode2body(body, dchild->d_inode);
                        cleanup_phase = 2;
                        GOTO(openit, rc = 0);
                }
                dput(dchild);
                up(&pending_dir->i_sem);

                /* We didn't find it in PENDING so it isn't an orphan.  See
                 * if it was a regular inode that was previously created.
                 */
                dchild = mds_fid2dentry(mds, rec->ur_fid2, NULL);
                if (!IS_ERR(dchild)) {
                        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
                        mds_pack_inode2body(body, dchild->d_inode);
                        cleanup_phase = 2;
                        GOTO(openit, rc = 0);
                }

                /* We didn't find the correct inode on disk either, so we
                 * need to re-create it via a regular replay.  Do that below.
                 */
                LASSERT(rec->ur_flags & O_CREAT);
        }
        LASSERT(offset == 2); /* If we got here, we must be called via intent */

        med = &req->rq_export->exp_mds_data;
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("test case OBD_FAIL_MDS_OPEN_PACK\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        if ((rec->ur_flags & O_ACCMODE) >= sizeof (acc_table))
                RETURN(-EINVAL);
        acc_mode = acc_table[rec->ur_flags & O_ACCMODE];
        if ((rec->ur_flags & O_TRUNC) != 0)
                acc_mode |= MAY_WRITE;

        /* Step 1: Find and lock the parent */
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);
        parent_mode = (rec->ur_flags & O_CREAT) ? LCK_PW : LCK_PR;
        parent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, parent_mode,
                                       &parent_lockh);
        if (IS_ERR(parent)) {
                rc = PTR_ERR(parent);
                CERROR("parent lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }
        LASSERT(parent->d_inode);

        cleanup_phase = 1; /* parent dentry and lock */

        /* Step 2: Lookup the child */
        dchild = ll_lookup_one_len(rec->ur_name, parent, rec->ur_namelen - 1);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));

        cleanup_phase = 2; /* child dentry */

        if (dchild->d_inode)
                intent_set_disposition(rep, DISP_LOOKUP_POS);
        else
                intent_set_disposition(rep, DISP_LOOKUP_NEG);

        /* Step 3: If the child was negative, and we're supposed to,
         * create it. */
        if (!dchild->d_inode) {
                unsigned long ino = rec->ur_fid2->id;

                if (!(rec->ur_flags & O_CREAT)) {
                        /* It's negative and we weren't supposed to create it */
                        GOTO(cleanup, rc = -ENOENT);
                }

                intent_set_disposition(rep, DISP_OPEN_CREATE);
                handle = fsfilt_start(obd, parent->d_inode, FSFILT_OP_CREATE,
                                      NULL);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }
                if (ino)
                        dchild->d_fsdata = (void *)(unsigned long)ino;

                rc = vfs_create(parent->d_inode, dchild, rec->ur_mode);
                if (dchild->d_fsdata == (void *)(unsigned long)ino)
                        dchild->d_fsdata = NULL;

                if (rc) {
                        CDEBUG(D_INODE, "error during create: %d\n", rc);
                        GOTO(cleanup, rc);
                } else {
                        struct iattr iattr;
                        struct inode *inode = dchild->d_inode;

                        if (ino) {
                                LASSERT(ino == inode->i_ino);
                                /* Written as part of setattr */
                                inode->i_generation = rec->ur_fid2->generation;
                                CDEBUG(D_HA, "recreated ino %lu with gen %x\n",
                                       inode->i_ino, inode->i_generation);
                        }

                        created = 1;
                        LTIME_S(iattr.ia_atime) = rec->ur_time;
                        LTIME_S(iattr.ia_ctime) = rec->ur_time;
                        LTIME_S(iattr.ia_mtime) = rec->ur_time;

                        iattr.ia_uid = rec->ur_uid;
                        if (parent->d_inode->i_mode & S_ISGID) {
                                iattr.ia_gid = parent->d_inode->i_gid;
                        } else
                                iattr.ia_gid = rec->ur_gid;

                        iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                                ATTR_MTIME | ATTR_CTIME;

                        rc = fsfilt_setattr(obd, dchild, handle, &iattr, 0);
                        if (rc) {
                                CERROR("error on setattr: rc = %d\n", rc);
                                /* XXX should we abort here in case of error? */
                        }
                }

                child_mode = LCK_PW;
                acc_mode = 0;                  /* Don't check for permissions */
        }

        LASSERT(!mds_inode_is_orphan(dchild->d_inode));

        /* Step 4: It's positive, so lock the child */
        child_res_id.name[0] = dchild->d_inode->i_ino;
        child_res_id.name[1] = dchild->d_inode->i_generation;
 reacquire:
        lock_flags = 0;
        /* For the open(O_CREAT) case, this would technically be a lock
         * inversion (getting a VFS lock after starting a transaction),
         * but in that case we cannot possibly block on this lock because
         * we just created the child and also hold a write lock on the
         * parent, so nobody could be holding the lock yet.
         */
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0, child_mode,
                              &lock_flags, ldlm_completion_ast,
                              mds_blocking_ast, NULL, child_lockh);
        if (rc != ELDLM_OK) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                GOTO(cleanup, rc = -EIO);
        }

        cleanup_phase = 3; /* child lock */

        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);

        if (S_ISREG(dchild->d_inode->i_mode)) {
                /* Check permissions etc */
                rc = permission(dchild->d_inode, acc_mode);
                if (rc != 0)
                        GOTO(cleanup, rc);

                /* Can't write to a read-only file */
                if (IS_RDONLY(dchild->d_inode) && (acc_mode & MAY_WRITE) != 0)
                        GOTO(cleanup, rc = -EPERM);

                /* An append-only file must be opened in append mode for
                 * writing */
                if (IS_APPEND(dchild->d_inode) && (acc_mode & MAY_WRITE) != 0 &&
                    ((rec->ur_flags & O_APPEND) == 0 ||
                     (rec->ur_flags & O_TRUNC) != 0))
                        GOTO(cleanup, rc = -EPERM);

                rc = mds_pack_md(obd, req->rq_repmsg, 2, body, dchild->d_inode);
                if (rc)
                        GOTO(cleanup, rc);

                /* If we have LOV EA data, the OST holds size, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
        }

        if (!created && (rec->ur_flags & O_CREAT) &&
            (rec->ur_flags & O_EXCL)) {
                /* File already exists, we didn't just create it, and we
                 * were passed O_EXCL; err-or. */
                GOTO(cleanup, rc = -EEXIST); // returns a lock to the client
        }

        /* If we're opening a file without an EA for write, the client needs
         * a write lock. */
        if (S_ISREG(dchild->d_inode->i_mode) && (rec->ur_flags & O_ACCMODE) &&
            child_mode != LCK_PW && !(body->valid & OBD_MD_FLEASIZE)) {
                ldlm_lock_decref(child_lockh, child_mode);
                child_mode = LCK_PW;
                goto reacquire;
        }

        /* if we are following a symlink, don't open */
        if (S_ISLNK(dchild->d_inode->i_mode))
                GOTO(cleanup, rc = 0);

        if ((rec->ur_flags & O_DIRECTORY) && !S_ISDIR(dchild->d_inode->i_mode))
                GOTO(cleanup, rc = -ENOTDIR);

        /* Step 5: mds_open it */
        intent_set_disposition(rep, DISP_OPEN_OPEN);
 openit:
        /* dentry_open does a dput(de) and mntput(mds->mds_vfsmnt) on error */
        mfd = mds_dentry_open(dchild, mds->mds_vfsmnt,
                              rec->ur_flags & ~(O_DIRECT | O_TRUNC), req);
        if (IS_ERR(mfd)) {
                dchild = NULL; /* prevent a double dput in cleanup phase 2 */
                GOTO(cleanup, rc = PTR_ERR(mfd));
        }

        cleanup_phase = 4; /* mfd allocated */
        body->handle.cookie = mfd->mfd_handle.h_cookie;
        CDEBUG(D_INODE, "mfd %p, cookie "LPX64"\n", mfd,
               mfd->mfd_handle.h_cookie);
        GOTO(cleanup, rc = 0); /* returns a lock to the client */

 cleanup:
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, handle,
                                req, rc, rep->lock_policy_res1);
        /* XXX what do we do here if mds_finish_transno itself failed? */
        switch (cleanup_phase) {
        case 4:
                if (rc && !S_ISLNK(dchild->d_inode->i_mode))
                        mds_mfd_destroy(mfd);
        case 3:
                /* This is the same logic as in the IT_OPEN part of
                 * ldlm_intent_policy: if we found the dentry, or we tried to
                 * open it (meaning that we created, if it wasn't found), then
                 * we return the lock to the caller and client. */
                if (intent_disposition(rep, DISP_LOOKUP_NEG) &&
                    !intent_disposition(rep, DISP_OPEN_OPEN))
                        ldlm_lock_decref(child_lockh, child_mode);
        case 2:
                if (rc || S_ISLNK(dchild->d_inode->i_mode))
                        l_dput(dchild);
        case 1:
                if (parent) {
                        l_dput(parent);
                        if (rc) {
                                ldlm_lock_decref(&parent_lockh, parent_mode);
                        } else {
                                memcpy(&req->rq_ack_locks[0].lock,&parent_lockh,
                                       sizeof(parent_lockh));
                                req->rq_ack_locks[0].mode = parent_mode;
                        }
                }
        }
        RETURN(rc);
}
