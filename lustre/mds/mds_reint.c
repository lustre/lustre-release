/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_reint.c
 *  Lustre Metadata Server (mds) reintegration routines
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_fsfilt.h>

extern inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req);

static void mds_last_rcvd_cb(struct obd_device *obd, __u64 last_rcvd, int error)
{
        CDEBUG(D_HA, "got callback for last_rcvd "LPD64": rc = %d\n",
               last_rcvd, error);
        if (!error && last_rcvd > obd->obd_last_committed)
                obd->obd_last_committed = last_rcvd;
}

void mds_start_transno(struct mds_obd *mds)
{
        ENTRY;
        down(&mds->mds_transno_sem);
}

/* Assumes caller has already pushed us into the kernel context. */
int mds_finish_transno(struct mds_obd *mds, void *handle,
                       struct ptlrpc_request *req, int rc)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        __u64 last_rcvd;
        loff_t off;
        ssize_t written;

        /* Propagate error code. */
        if (rc)
                GOTO(out, rc);

        /* we don't allocate new transnos for replayed requests */
        if (req->rq_level == LUSTRE_CONN_RECOVD)
                GOTO(out, rc = 0);

        off = MDS_LR_CLIENT + med->med_off * MDS_LR_SIZE;

        last_rcvd = ++mds->mds_last_rcvd;
        req->rq_repmsg->transno = HTON__u64(last_rcvd);
        mcd->mcd_last_rcvd = cpu_to_le64(last_rcvd);
        mcd->mcd_mount_count = cpu_to_le64(mds->mds_mount_count);
        mcd->mcd_last_xid = cpu_to_le64(req->rq_xid);

        fsfilt_set_last_rcvd(req->rq_export->exp_obd, last_rcvd, handle,
                             mds_last_rcvd_cb);
        written = lustre_fwrite(mds->mds_rcvd_filp, (char *)mcd, sizeof(*mcd),
                                &off);
        CDEBUG(D_INODE, "wrote trans #"LPD64" for client %s at #%d: written = "
               LPSZ"\n", last_rcvd, mcd->mcd_uuid, med->med_off, written);

        if (written == sizeof(*mcd))
                GOTO(out, rc = 0);
        CERROR("error writing to last_rcvd file: rc = %d\n", rc);
        if (written >= 0)
                GOTO(out, rc = -EIO);

        rc = 0;

        EXIT;
 out:
        up(&mds->mds_transno_sem);
        return rc;
}

/* In the write-back case, the client holds a lock on a subtree (not supported).
 * In the intent case, the client holds a lock on the child inode. */
static int mds_reint_setattr(struct mds_update_record *rec, int offset,
                             struct ptlrpc_request *req,
                             struct lustre_handle *lh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body;
        struct dentry *de;
        struct inode *inode;
        void *handle;
        int rc = 0, err;

        de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de))
                GOTO(out_setattr, rc = PTR_ERR(de));
        inode = de->d_inode;

        LASSERT(inode);
        CDEBUG(D_INODE, "ino %lu\n", inode->i_ino);

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_SETATTR_WRITE,
                       to_kdev_t(inode->i_sb->s_dev));

        mds_start_transno(mds);
        handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                (void)mds_finish_transno(mds, handle, req, rc);
                GOTO(out_setattr_de, rc);
        }

        rc = fsfilt_setattr(obd, de, handle, &rec->ur_iattr);
        if (rc == 0 && S_ISREG(inode->i_mode) &&
            req->rq_reqmsg->bufcount > 1) {
                rc = fsfilt_set_md(obd, inode, handle,
                                   lustre_msg_buf(req->rq_reqmsg, 1),
                                   req->rq_reqmsg->buflens[1]);
        }

        body = lustre_msg_buf(req->rq_repmsg, 0);
        mds_pack_inode2fid(&body->fid1, inode);
        mds_pack_inode2body(body, inode);

        rc = mds_finish_transno(mds, handle, req, rc);
        err = fsfilt_commit(obd, de->d_inode, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        EXIT;
out_setattr_de:
        l_dput(de);
out_setattr:
        req->rq_status = rc;
        return 0;
}

static int mds_reint_create(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lh)
{
        struct dentry *de = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *dchild = NULL;
        struct inode *dir;
        void *handle;
        struct lustre_handle lockh;
        int rc = 0, err, type = rec->ur_mode & S_IFMT;
        ENTRY;

        LASSERT(offset == 0);
        LASSERT(!strcmp(req->rq_export->exp_obd->obd_type->typ_name, "mds"));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
                GOTO(out_create, rc = -ESTALE);

        de = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_PW, &lockh);
        if (IS_ERR(de)) {
                rc = PTR_ERR(de);
                CERROR("parent lookup error %d\n", rc);
                LBUG();
                GOTO(out_create, rc);
        }
        dir = de->d_inode;
        LASSERT(dir);
        CDEBUG(D_INODE, "parent ino %lu creating name %s mode %o\n",
               dir->i_ino, rec->ur_name, rec->ur_mode);

        ldlm_lock_dump_handle(D_OTHER, &lockh);

        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                CERROR("child lookup error %d\n", rc);
                GOTO(out_create_de, rc);
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_CREATE_WRITE,
                       to_kdev_t(dir->i_sb->s_dev));

        if (dir->i_mode & S_ISGID) {
                rec->ur_gid = dir->i_gid;
                if (S_ISDIR(rec->ur_mode))
                        rec->ur_mode |= S_ISGID;
        }

        if (rec->ur_fid2->id)
                dchild->d_fsdata = (void *)(unsigned long)rec->ur_fid2->id;
        else
                LASSERT(!(rec->ur_opcode & REINT_REPLAYING));

        /* From here on, we must exit via a path that calls mds_finish_transno,
         * so that we release the mds_transno_sem (and, in the case of success,
         * update the transno correctly).  out_create_commit and
         * out_transno_dchild are good candidates.
         */
        mds_start_transno(mds);

        switch (type) {
        case S_IFREG:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_CREATE);
                if (IS_ERR(handle))
                        GOTO(out_transno_dchild, rc = PTR_ERR(handle));
                rc = vfs_create(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFDIR:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_MKDIR);
                if (IS_ERR(handle))
                        GOTO(out_transno_dchild, rc = PTR_ERR(handle));
                rc = vfs_mkdir(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFLNK:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_SYMLINK);
                if (IS_ERR(handle))
                        GOTO(out_transno_dchild, rc = PTR_ERR(handle));
                rc = vfs_symlink(dir, dchild, rec->ur_tgt);
                EXIT;
                break;
        }
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:{
                int rdev = rec->ur_rdev;
                handle = fsfilt_start(obd, dir, FSFILT_OP_MKNOD);
                if (IS_ERR(handle))
                        GOTO(out_transno_dchild, rc = PTR_ERR(handle));
                rc = vfs_mknod(dir, dchild, rec->ur_mode, rdev);
                EXIT;
                break;
        }
        default:
                CERROR("bad file type %o creating %s\n", type, rec->ur_name);
                handle = NULL; /* quell uninitialized warning */
                GOTO(out_transno_dchild, rc = -EINVAL);
        }

        /* In case we stored the desired inum in here, we want to clean up.
         * We also do this in the out_transno_dchild block, for the error cases.
         */
        dchild->d_fsdata = NULL;

        if (rc) {
                CDEBUG(D_INODE, "error during create: %d\n", rc);
                GOTO(out_create_commit, rc);
        } else {
                struct iattr iattr;
                struct inode *inode = dchild->d_inode;
                struct mds_body *body;

                iattr.ia_atime = rec->ur_time;
                iattr.ia_ctime = rec->ur_time;
                iattr.ia_mtime = rec->ur_time;
                iattr.ia_uid = rec->ur_uid;
                iattr.ia_gid = rec->ur_gid;
                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                if (rec->ur_fid2->id) {
                        LASSERT(rec->ur_fid2->id == inode->i_ino);
                        inode->i_generation = rec->ur_fid2->generation;
                        /* Dirtied and committed by the upcoming setattr. */
                        CDEBUG(D_INODE, "recreated ino %lu with gen %x\n",
                               inode->i_ino, inode->i_generation);
                } else {
                        CDEBUG(D_INODE, "created ino %lu with gen %x\n",
                               inode->i_ino, inode->i_generation);
                }

                rc = fsfilt_setattr(obd, dchild, handle, &iattr);
                if (rc) {
                        CERROR("error on setattr: rc = %d\n", rc);
                        /* XXX should we abort here in case of error? */
                }

                body = lustre_msg_buf(req->rq_repmsg, offset);
                mds_pack_inode2fid(&body->fid1, inode);
                mds_pack_inode2body(body, inode);
        }
        EXIT;
out_create_commit:
        if (rc) {
                rc = mds_finish_transno(mds, handle, req, rc);
        } else {
                rc = mds_finish_transno(mds, handle, req, rc);
                if (rc)
                        GOTO(out_create_unlink, rc);
        }
        err = fsfilt_commit(obd, dir, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }
out_create_dchild:
        l_dput(dchild);
out_create_de:
        ldlm_lock_decref(&lockh, LCK_PW);
        l_dput(de);
out_create:
        req->rq_status = rc;
        return 0;

out_transno_dchild:
        dchild->d_fsdata = NULL;
        /* Need to release the transno lock, and then put the dchild. */
        LASSERT(rc);
        mds_finish_transno(mds, handle, req, rc);
        goto out_create_dchild;

out_create_unlink:
        /* Destroy the file we just created.  This should not need extra
         * journal credits, as we have already modified all of the blocks
         * needed in order to create the file in the first place.
         */
        switch (type) {
        case S_IFDIR:
                err = vfs_rmdir(dir, dchild);
                if (err)
                        CERROR("failed rmdir in error path: rc = %d\n", err);
                break;
        default:
                err = vfs_unlink(dir, dchild);
                if (err)
                        CERROR("failed unlink in error path: rc = %d\n", err);
                break;
        }

        goto out_create_commit;
}

/* This function doesn't use ldlm_match_or_enqueue because we're always called
 * with EX or PW locks, and the MDS is no longer allowed to match write locks,
 * because they take the place of local semaphores.
 *
 * Two locks are taken in numerical order */
int enqueue_ordered_locks(int lock_mode, struct obd_device *obd,
                          struct ldlm_res_id *p1_res_id,
                          struct ldlm_res_id *p2_res_id,
                          struct lustre_handle *p1_lockh,
                          struct lustre_handle *p2_lockh)
{
        struct ldlm_res_id res_id[2];
        struct lustre_handle *handles[2] = {p1_lockh, p2_lockh};
        int rc, flags;
        ENTRY;

        LASSERT(p1_res_id != NULL && p2_res_id != NULL);

        CDEBUG(D_INFO, "locks before: "LPU64"/"LPU64"\n",
               p1_res_id[0].name[0], p2_res_id[0].name[0]);

        if (p1_res_id->name[0] < p2_res_id->name[0]) {
                handles[0] = p1_lockh;
                handles[1] = p2_lockh;
                res_id[0] = *p1_res_id;
                res_id[1] = *p2_res_id;
        } else {
                handles[1] = p1_lockh;
                handles[0] = p2_lockh;
                res_id[1] = *p1_res_id;
                res_id[0] = *p2_res_id;
        }

        CDEBUG(D_INFO, "lock order: "LPU64"/"LPU64"\n",
               p1_res_id[0].name[0], p2_res_id[0].name[0]);

        flags = LDLM_FL_LOCAL_ONLY;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL, res_id[0],
                              LDLM_PLAIN, NULL, 0, lock_mode, &flags,
                              ldlm_completion_ast, mds_blocking_ast, NULL,
                              NULL, handles[0]);
        if (rc != ELDLM_OK)
                RETURN(-EIO);
        ldlm_lock_dump_handle(D_OTHER, handles[0]);

        if (memcmp(&res_id[0], &res_id[1], sizeof(res_id[0])) == 0) {
                memcpy(handles[1], handles[0], sizeof(*(handles[1])));
                ldlm_lock_addref(handles[1], lock_mode);
        } else {
                flags = LDLM_FL_LOCAL_ONLY;
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id[1], LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, 0, handles[1]);
                if (rc != ELDLM_OK) {
                        ldlm_lock_decref(handles[0], lock_mode);
                        RETURN(-EIO);
                }
        }
        ldlm_lock_dump_handle(D_OTHER, handles[1]);

        RETURN(0);
}

static int mds_reint_unlink(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *child_lockh)
{
        struct dentry *dir_de = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body = NULL;
        struct inode *dir_inode, *child_inode;
        struct lustre_handle *handle, parent_lockh;
        struct ldlm_res_id child_res_id = { .name = {0} };
        char *name;
        int namelen, err, rc = 0, flags = 0, return_lock = 0;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                GOTO(out, rc = -ENOENT);

        /* Step 1: Lookup the parent by FID */
        dir_de = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_PW,
                                       &parent_lockh);
        if (IS_ERR(dir_de))
                GOTO(out, rc = PTR_ERR(dir_de));
        dir_inode = dir_de->d_inode;
        LASSERT(dir_inode);

        /* Step 2: Lookup the child */
        name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        namelen = req->rq_reqmsg->buflens[offset + 1] - 1;

        dchild = lookup_one_len(name, dir_de, namelen);
        if (IS_ERR(dchild))
                GOTO(out_step_2a, rc = PTR_ERR(dchild));
        child_inode = dchild->d_inode;
        if (child_inode == NULL) {
                if (rec->ur_opcode & REINT_REPLAYING) {
                        CDEBUG(D_INODE,
                               "child missing (%lu/%s); OK for REPLAYING\n",
                               dir_inode->i_ino, rec->ur_name);
                        rc = 0;
                } else {
                        CDEBUG(D_INODE,
                               "child doesn't exist (dir %lu, name %s)\n",
                               dir_inode->i_ino, rec->ur_name);
                        rc = -ENOENT;
                }
                GOTO(out_step_2b, rc);
        }

        DEBUG_REQ(D_INODE, req, "parent ino %lu, child ino %lu",
                  dir_inode->i_ino, child_inode->i_ino);

        /* Step 3: Get lock a lock on the child */
        child_res_id.name[0] = child_inode->i_ino;
        child_res_id.name[1] = child_inode->i_generation;

        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0, LCK_EX,
                              &flags, ldlm_completion_ast, mds_blocking_ast,
                              NULL, NULL, child_lockh);
        if (rc != ELDLM_OK)
                GOTO(out_step_2b, rc);

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_UNLINK_WRITE,
                       to_kdev_t(dir_inode->i_sb->s_dev));

        /* Slightly magical; see ldlm_intent_policy */
        if (offset)
                offset = 1;

        body = lustre_msg_buf(req->rq_repmsg, offset);

        /* Step 4: Do the unlink: client decides between rmdir/unlink!
         * (bug 72) */
        mds_start_transno(mds);
        switch (rec->ur_mode & S_IFMT) {
        case S_IFDIR:
                handle = fsfilt_start(obd, dir_inode, FSFILT_OP_RMDIR);
                if (IS_ERR(handle))
                        GOTO(out_cancel_transno, rc = PTR_ERR(handle));
                rc = vfs_rmdir(dir_inode, dchild);
                break;
        case S_IFREG:
                /* If this is the last reference to this inode, get the OBD EA
                 * data first so the client can destroy OST objects */
                if ((child_inode->i_mode & S_IFMT) == S_IFREG &&
                    child_inode->i_nlink == 1) {
                        mds_pack_inode2fid(&body->fid1, child_inode);
                        mds_pack_inode2body(body, child_inode);
                        mds_pack_md(obd, req->rq_repmsg, offset + 1,
                                    body, child_inode);
                        if (body->valid & OBD_MD_FLEASIZE)
                                return_lock = 1;
                }
                /* no break */
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                handle = fsfilt_start(obd, dir_inode, FSFILT_OP_UNLINK);
                if (IS_ERR(handle))
                        GOTO(out_cancel_transno, rc = PTR_ERR(handle));
                rc = vfs_unlink(dir_inode, dchild);
                break;
        default:
                CERROR("bad file type %o unlinking %s\n", rec->ur_mode, name);
                handle = NULL;
                LBUG();
                GOTO(out_cancel_transno, rc = -EINVAL);
        }

        rc = mds_finish_transno(mds, handle, req, rc);
        err = fsfilt_commit(obd, dir_inode, handle);
        if (rc != 0 || err != 0) {
                /* Don't unlink the OST objects if the MDS unlink failed */
                body->valid = 0;
        }
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        GOTO(out_step_4, rc);
 out_step_4:
        if (rc != 0 || return_lock == 0)
                ldlm_lock_decref(child_lockh, LCK_EX);
 out_step_2b:
        l_dput(dchild);
 out_step_2a:
        ldlm_lock_decref(&parent_lockh, LCK_EX);
        l_dput(dir_de);
 out:
        req->rq_status = rc;
        return 0;

 out_cancel_transno:
        rc = mds_finish_transno(mds, handle, req, rc);
        goto out_step_4;
}

static int mds_reint_link(struct mds_update_record *rec, int offset,
                          struct ptlrpc_request *req, struct lustre_handle *lh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_src = NULL;
        struct dentry *de_tgt_dir = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle *handle, tgt_dir_lockh, src_lockh;
        struct ldlm_res_id src_res_id = { .name = {0} };
        struct ldlm_res_id tgt_dir_res_id = { .name = {0} };
        int lock_mode, rc = 0, err;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
                GOTO(out, rc = -ENOENT);

        /* Step 1: Lookup the source inode and target directory by FID */
        de_src = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_src))
                GOTO(out, rc = PTR_ERR(de_src));

        de_tgt_dir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgt_dir))
                GOTO(out_de_src, rc = PTR_ERR(de_tgt_dir));

        CDEBUG(D_INODE, "linking %*s/%s to inode %lu\n",
               de_tgt_dir->d_name.len, de_tgt_dir->d_name.name, rec->ur_name,
               de_src->d_inode->i_ino);

        /* Step 2: Take the two locks */
        lock_mode = LCK_EX;
        src_res_id.name[0] = de_src->d_inode->i_ino;
        src_res_id.name[1] = de_src->d_inode->i_generation;
        tgt_dir_res_id.name[0] = de_tgt_dir->d_inode->i_ino;
        tgt_dir_res_id.name[1] = de_tgt_dir->d_inode->i_generation;

        rc = enqueue_ordered_locks(LCK_EX, obd, &src_res_id, &tgt_dir_res_id,
                                   &src_lockh, &tgt_dir_lockh);
        if (rc != ELDLM_OK)
                GOTO(out_tgt_dir, rc = -EIO);

        /* Step 3: Lookup the child */
        dchild = lookup_one_len(rec->ur_name, de_tgt_dir, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                GOTO(out_drop_locks, rc = PTR_ERR(dchild));
        }

        if (dchild->d_inode) {
                if (rec->ur_opcode & REINT_REPLAYING) {
                        /* XXX verify that the link is to the the right file? */
                        CDEBUG(D_INODE,
                               "child exists (dir %lu, name %s) (REPLAYING)\n",
                               de_tgt_dir->d_inode->i_ino, rec->ur_name);
                        rc = 0;
                } else {
                        CDEBUG(D_INODE, "child exists (dir %lu, name %s)\n",
                               de_tgt_dir->d_inode->i_ino, rec->ur_name);
                        rc = -EEXIST;
                }
                GOTO(out_drop_child, rc);
        }

        /* Step 4: Do it. */
        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_LINK_WRITE,
                       to_kdev_t(de_src->d_inode->i_sb->s_dev));

        mds_start_transno(mds);
        handle = fsfilt_start(obd, de_tgt_dir->d_inode, FSFILT_OP_LINK);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                mds_finish_transno(mds, handle, req, rc);
                GOTO(out_drop_child, rc);
        }

        rc = vfs_link(de_src, de_tgt_dir->d_inode, dchild);
        if (rc)
                CERROR("link error %d\n", rc);
        rc = mds_finish_transno(mds, handle, req, rc);

        err = fsfilt_commit(obd, de_tgt_dir->d_inode, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        EXIT;

out_drop_child:
        l_dput(dchild);
out_drop_locks:
        ldlm_lock_decref(&src_lockh, lock_mode);
        ldlm_lock_decref(&tgt_dir_lockh, lock_mode);
out_tgt_dir:
        l_dput(de_tgt_dir);
out_de_src:
        l_dput(de_src);
out:
        req->rq_status = rc;
        return 0;
}

static int mds_reint_rename(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_srcdir = NULL;
        struct dentry *de_tgtdir = NULL;
        struct dentry *de_old = NULL;
        struct dentry *de_new = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle dlm_handles[4];
        struct ldlm_res_id p1_res_id = { .name = {0} };
        struct ldlm_res_id p2_res_id = { .name = {0} };
        struct ldlm_res_id c1_res_id = { .name = {0} };
        struct ldlm_res_id c2_res_id = { .name = {0} };
        int rc = 0, err, lock_count = 3, flags = LDLM_FL_LOCAL_ONLY;
        void *handle;
        ENTRY;

        de_srcdir = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_srcdir))
                GOTO(out, rc = PTR_ERR(de_srcdir));
        de_tgtdir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgtdir))
                GOTO(out_put_srcdir, rc = PTR_ERR(de_tgtdir));

        /* The idea here is that we need to get four locks in the end:
         * one on each parent directory, one on each child.  We need to take
         * these locks in some kind of order (to avoid deadlocks), and the order
         * I selected is "increasing resource number" order.  We need to take
         * the locks on the parent directories, however, before we can lookup
         * the children.  Thus the following plan:
         *
         * 1. Take locks on the parent(s), in order
         * 2. Lookup the children
         * 3. Take locks on the children, in order
         * 4. Execute the rename
         */

        /* Step 1: Take locks on the parent(s), in order */
        p1_res_id.name[0] = de_srcdir->d_inode->i_ino;
        p1_res_id.name[1] = de_srcdir->d_inode->i_generation;

        p2_res_id.name[0] = de_tgtdir->d_inode->i_ino;
        p2_res_id.name[1] = de_tgtdir->d_inode->i_generation;

        rc = enqueue_ordered_locks(LCK_EX, obd, &p1_res_id, &p2_res_id,
                                   &(dlm_handles[0]), &(dlm_handles[1]));
        if (rc != ELDLM_OK)
                GOTO(out_put_tgtdir, rc);

        /* Step 2: Lookup the children */
        de_old = lookup_one_len(rec->ur_name, de_srcdir, rec->ur_namelen - 1);
        if (IS_ERR(de_old)) {
                CERROR("old child lookup error (%*s): %ld\n",
                       rec->ur_namelen - 1, rec->ur_name, PTR_ERR(de_old));
                GOTO(out_step_2a, rc = PTR_ERR(de_old));
        }

        if (de_old->d_inode == NULL)
                GOTO(out_step_2b, rc = -ENOENT);

        de_new = lookup_one_len(rec->ur_tgt, de_tgtdir, rec->ur_tgtlen - 1);
        if (IS_ERR(de_new)) {
                CERROR("new child lookup error (%*s): %ld\n",
                       rec->ur_tgtlen - 1, rec->ur_tgt, PTR_ERR(de_new));
                GOTO(out_step_2b, rc = PTR_ERR(de_new));
        }

        /* Step 3: Take locks on the children */
        c1_res_id.name[0] = de_old->d_inode->i_ino;
        c1_res_id.name[1] = de_old->d_inode->i_generation;
        if (de_new->d_inode == NULL) {
                flags = LDLM_FL_LOCAL_ONLY;
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      c1_res_id, LDLM_PLAIN, NULL, 0, LCK_EX,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, NULL,
                                      &(dlm_handles[2]));
                lock_count = 3;
        } else {
                c2_res_id.name[0] = de_new->d_inode->i_ino;
                c2_res_id.name[1] = de_new->d_inode->i_generation;
                rc = enqueue_ordered_locks(LCK_EX, obd, &c1_res_id, &c2_res_id,
                                           &(dlm_handles[2]),
                                           &(dlm_handles[3]));
                lock_count = 4;
        }
        if (rc != ELDLM_OK)
                GOTO(out_step_3, rc);

        /* Step 4: Execute the rename */
        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE,
                       to_kdev_t(de_srcdir->d_inode->i_sb->s_dev));

        mds_start_transno(mds);
        handle = fsfilt_start(obd, de_tgtdir->d_inode, FSFILT_OP_RENAME);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                mds_finish_transno(mds, handle, req, rc);
                GOTO(out_step_4, rc);
        }

        lock_kernel();
        rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new,
                        NULL);
        unlock_kernel();

        rc = mds_finish_transno(mds, handle, req, rc);

        err = fsfilt_commit(obd, de_tgtdir->d_inode, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        EXIT;
 out_step_4:
        ldlm_lock_decref(&(dlm_handles[2]), LCK_EX);
        if (lock_count == 4)
                ldlm_lock_decref(&(dlm_handles[3]), LCK_EX);
 out_step_3:
        l_dput(de_new);
 out_step_2b:
        l_dput(de_old);
 out_step_2a:
        ldlm_lock_decref(&(dlm_handles[0]), LCK_EX);
        ldlm_lock_decref(&(dlm_handles[1]), LCK_EX);
 out_put_tgtdir:
        l_dput(de_tgtdir);
 out_put_srcdir:
        l_dput(de_srcdir);
 out:
        req->rq_status = rc;
        return 0;
}

typedef int (*mds_reinter)(struct mds_update_record *, int offset,
                           struct ptlrpc_request *, struct lustre_handle *);

static mds_reinter reinters[REINT_MAX + 1] = {
        [REINT_SETATTR] mds_reint_setattr,
        [REINT_CREATE] mds_reint_create,
        [REINT_UNLINK] mds_reint_unlink,
        [REINT_LINK] mds_reint_link,
        [REINT_RENAME] mds_reint_rename,
        [REINT_OPEN] mds_open
};

int mds_reint_rec(struct mds_update_record *rec, int offset,
                  struct ptlrpc_request *req, struct lustre_handle *lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_run_ctxt saved;
        struct obd_ucred uc;
        int realop = rec->ur_opcode & REINT_OPCODE_MASK, rc;
        ENTRY;

        if (realop < 1 || realop > REINT_MAX) {
                CERROR("opcode %d not valid (%sREPLAYING)\n", realop,
                       rec->ur_opcode & REINT_REPLAYING ? "" : "not ");
                rc = req->rq_status = -EINVAL;
                RETURN(rc);
        }

        uc.ouc_fsuid = rec->ur_fsuid;
        uc.ouc_fsgid = rec->ur_fsgid;
        uc.ouc_cap = rec->ur_cap;
        uc.ouc_suppgid = rec->ur_suppgid;

        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        rc = reinters[realop] (rec, offset, req, lockh);
        pop_ctxt(&saved, &mds->mds_ctxt, &uc);

        RETURN(rc);
}
