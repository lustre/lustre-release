/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_reint.c
 *
 *  Lustre Metadata Server (mds) reintegration routines
 *
 *  Copyright (C) 2002  Cluster File Systems, Inc.
 *  author: Peter Braam <braam@clusterfs.com>
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 */

// XXX - add transaction sequence numbers

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_class.h>

extern inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req);

/* Assumes caller has already pushed us into the kernel context. */
int mds_update_last_rcvd(struct mds_obd *mds, void *handle,
                         struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        loff_t off;
        int rc;

        off = MDS_LR_CLIENT + med->med_off * MDS_LR_SIZE;

        ++mds->mds_last_rcvd;   /* lock this, or make it an LDLM function? */
        req->rq_repmsg->transno = HTON__u64(mds->mds_last_rcvd);
        mcd->mcd_last_rcvd = cpu_to_le64(mds->mds_last_rcvd);
        mcd->mcd_mount_count = cpu_to_le64(mds->mds_mount_count);
        mcd->mcd_last_xid = cpu_to_le64(req->rq_xid);

        mds_fs_set_last_rcvd(mds, handle);
        rc = lustre_fwrite(mds->mds_rcvd_filp, (char *)mcd, sizeof(*mcd), &off);
        CDEBUG(D_INODE, "wrote trans #%Ld for client '%s' at #%d: rc = %d\n",
               mds->mds_last_rcvd, mcd->mcd_uuid, med->med_off, rc);
        // store new value and last committed value in req struct

        if (rc == sizeof(*mcd))
                rc = 0;
        else {
                CERROR("error writing to last_rcvd file: rc = %d\n", rc);
                if (rc >= 0)
                        rc = -EIO;
        }

        return rc;
}

/* In the write-back case, the client holds a lock on a subtree.
 * In the intent case, the client holds a lock on the child inode.
 * In the pathname case, the client (may) hold a lock on the child inode. */
static int mds_reint_setattr(struct mds_update_record *rec, int offset,
                             struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de;
        void *handle;
        struct lustre_handle child_lockh;
        int rc = 0, err;

        if (req->rq_reqmsg->bufcount > offset + 1) {
                struct dentry *dir;
                struct lustre_handle dir_lockh;
                char *name;
                int namelen;

                /* a name was supplied by the client; fid1 is the directory */
                dir = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_PR,
                                            &dir_lockh);
                if (IS_ERR(dir)) {
                        LBUG();
                        GOTO(out_setattr, rc = PTR_ERR(dir));
                }

                name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
                namelen = req->rq_reqmsg->buflens[offset + 1] - 1;
                de = mds_name2locked_dentry(obd, dir, NULL, name, namelen,
                                            0, &child_lockh, LCK_PR);
                l_dput(dir);
                if (IS_ERR(de)) {
                        LBUG();
                        GOTO(out_setattr_de, rc = PTR_ERR(de));
                }
        } else {
                de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
                if (!de || IS_ERR(de)) {
                        LBUG();
                        GOTO(out_setattr_de, rc = -ESTALE);
                }
        }
        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_SETATTR_WRITE,
                       de->d_inode->i_sb->s_dev);

        lock_kernel();
        handle = mds_fs_start(mds, de->d_inode, MDS_FSOP_SETATTR);
        if (!handle)
                GOTO(out_unlock, rc = PTR_ERR(handle));
        rc = mds_fs_setattr(mds, de, handle, &rec->ur_iattr);

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);

        err = mds_fs_commit(mds, de->d_inode, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        EXIT;
out_unlock:
        unlock_kernel();
out_setattr_de:
        l_dput(de);
out_setattr:
        req->rq_status = rc;
        return (0);
}

static int mds_reint_recreate(struct mds_update_record *rec, int offset,
                              struct ptlrpc_request *req)
{
        struct dentry *de = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct dentry *dchild = NULL;
        struct inode *dir;
        int rc = 0;
        ENTRY;

        de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE)) {
                LBUG();
                GOTO(out_create_de, rc = -ESTALE);
        }
        dir = de->d_inode;
        CDEBUG(D_INODE, "parent ino %ld\n", dir->i_ino);

        down(&dir->i_sem);
        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                up(&dir->i_sem);
                LBUG();
                GOTO(out_create_dchild, rc = -ESTALE);
        }

        if (dchild->d_inode) {
                struct mds_body *body;
                rc = 0;
                body = lustre_msg_buf(req->rq_repmsg, 0);
                body->ino = dchild->d_inode->i_ino;
                body->generation = dchild->d_inode->i_generation;
        } else {
                CERROR("child doesn't exist (dir %ld, name %s)\n",
                       dir->i_ino, rec->ur_name);
                rc = -ENOENT;
                LBUG();
        }

out_create_dchild:
        l_dput(dchild);
        up(&dir->i_sem);
out_create_de:
        l_dput(de);
        req->rq_status = rc;
        return 0;
}

static int mds_reint_create(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req)
{
        struct dentry *de = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *dchild = NULL;
        struct inode *dir;
        void *handle;
        struct lustre_handle lockh;
        int rc = 0, err, lock_mode, type = rec->ur_mode & S_IFMT;
        ENTRY;

        /* requests were at offset 2, replies go back at 1 */
        if (offset)
                offset = 1;

        if (strcmp(req->rq_export->exp_obd->obd_type->typ_name, "mds") != 0)
                LBUG();

        lock_mode = (req->rq_reqmsg->opc == MDS_REINT) ? LCK_CW : LCK_PW;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
                GOTO(out_create, rc = -ESTALE);

        de = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, lock_mode, &lockh);
        if (IS_ERR(de)) {
                rc = PTR_ERR(de);
                CERROR("parent lookup error %d\n", rc);
                LBUG();
                GOTO(out_create, rc);
        }
        dir = de->d_inode;
        CDEBUG(D_INODE, "parent ino %ld name %s mode %o\n",
               dir->i_ino, rec->ur_name, rec->ur_mode);

        ldlm_lock_dump((void *)(unsigned long)lockh.addr);

        down(&dir->i_sem);
        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                LBUG();
                GOTO(out_create_de, rc = -ESTALE);
        }

        if (dchild->d_inode) {
                struct mds_body *body;
                struct inode *inode = dchild->d_inode;
                struct lov_mds_md *md;
                CDEBUG(D_INODE, "child exists (dir %ld, name %s, ino %ld)\n",
                       dir->i_ino, rec->ur_name, dchild->d_inode->i_ino);

                body = lustre_msg_buf(req->rq_repmsg, offset);
                mds_pack_inode2fid(&body->fid1, inode);
                mds_pack_inode2body(body, inode);
                if (S_ISREG(inode->i_mode)) {
                        md = lustre_msg_buf(req->rq_repmsg, offset + 1);
                        md->lmd_easize = mds->mds_max_mdsize;

                        if (mds_fs_get_md(mds, inode, md) < 0)
                                memset(md, 0, md->lmd_easize);
                }
                /* now a normal case for intent locking */
                GOTO(out_create_dchild, rc = -EEXIST);
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_CREATE_WRITE, dir->i_sb->s_dev);

        if (dir->i_mode & S_ISGID) {
                rec->ur_gid = dir->i_gid;
                if (S_ISDIR(rec->ur_mode))
                        rec->ur_mode |= S_ISGID;
        }

        switch (type) {
        case S_IFREG:{
                handle = mds_fs_start(mds, dir, MDS_FSOP_CREATE);
                if (!handle)
                        GOTO(out_create_dchild, PTR_ERR(handle));
                rc = vfs_create(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFDIR:{
                handle = mds_fs_start(mds, dir, MDS_FSOP_MKDIR);
                if (!handle)
                        GOTO(out_create_dchild, PTR_ERR(handle));
                rc = vfs_mkdir(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFLNK:{
                handle = mds_fs_start(mds, dir, MDS_FSOP_SYMLINK);
                if (!handle)
                        GOTO(out_create_dchild, PTR_ERR(handle));
                rc = vfs_symlink(dir, dchild, rec->ur_tgt);
                EXIT;
                break;
        }
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:{
                int rdev = rec->ur_rdev;
                handle = mds_fs_start(mds, dir, MDS_FSOP_MKNOD);
                if (!handle)
                        GOTO(out_create_dchild, PTR_ERR(handle));
                rc = vfs_mknod(dir, dchild, rec->ur_mode, rdev);
                EXIT;
                break;
        }
        default:
                CERROR("bad file type %o creating %s\n", type, rec->ur_name);
                GOTO(out_create_dchild, rc = -EINVAL);
        }

        if (rc) {
                CERROR("error during create: %d\n", rc);
                if (rc != -ENOSPC)
                        LBUG();
                GOTO(out_create_commit, rc);
        } else {
                struct iattr iattr;
                struct inode *inode = dchild->d_inode;
                struct mds_body *body;

                CDEBUG(D_INODE, "created ino %ld\n", dchild->d_inode->i_ino);
                if (!offset && type == S_IFREG) {
                        struct lov_mds_md *md;
                        md = lustre_msg_buf(req->rq_reqmsg, 2);
                        rc = mds_fs_set_md(mds, inode, handle, md);
                        if (rc) {
                                CERROR("error %d setting LOV MD for %ld\n",
                                       rc, inode->i_ino);
                                GOTO(out_create_unlink, rc);
                        }
                }

                iattr.ia_atime = rec->ur_time;
                iattr.ia_ctime = rec->ur_time;
                iattr.ia_mtime = rec->ur_time;
                iattr.ia_uid = rec->ur_uid;
                iattr.ia_gid = rec->ur_gid;
                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                rc = mds_fs_setattr(mds, dchild, handle, &iattr);
                if (rc) {
                        CERROR("error on setattr: rc = %d\n", rc);
                        /* XXX should we abort here in case of error? */
                }

                rc = mds_update_last_rcvd(mds, handle, req);
                if (rc) {
                        CERROR("error on update_last_rcvd: rc = %d\n", rc);
                        /* XXX should we abort here in case of error? */
                }

                body = lustre_msg_buf(req->rq_repmsg, offset);
                body->ino = inode->i_ino;
                body->generation = inode->i_generation;
                body->valid = OBD_MD_FLID | OBD_MD_FLGENER;
        }
        EXIT;
out_create_commit:
        err = mds_fs_commit(mds, dir, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }
out_create_dchild:
        l_dput(dchild);
        ldlm_lock_decref(&lockh, lock_mode);
out_create_de:
        up(&dir->i_sem);
        l_dput(de);
out_create:
        req->rq_status = rc;
        return 0;

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
        }

        goto out_create_commit;
}

static int mds_reint_unlink(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req)
{
        struct dentry *de = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        char *name;
        struct inode *dir, *inode;
        struct lustre_handle lockh, child_lockh;
        void *handle;
        int namelen, lock_mode, err, rc = 0;
        ENTRY;

        /* a name was supplied by the client; fid1 is the directory */
        lock_mode = (req->rq_reqmsg->opc == MDS_REINT) ? LCK_CW : LCK_PW;
        de = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, lock_mode, &lockh);
        if (IS_ERR(de)) {
                LBUG();
                RETURN(PTR_ERR(de));
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                GOTO(out_unlink, rc = -ENOENT);

        name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        namelen = req->rq_reqmsg->buflens[offset + 1] - 1;
        dchild = mds_name2locked_dentry(obd, de, NULL, name, namelen,
                                        LCK_EX, &child_lockh, lock_mode);

        if (IS_ERR(dchild)) {
                LBUG();
                GOTO(out_unlink, rc = PTR_ERR(dchild));
        }

        dir = de->d_inode;
        inode = dchild->d_inode;
        CDEBUG(D_INODE, "parent ino %ld\n", dir->i_ino);

        if (!inode) {
                CDEBUG(D_INODE, "child doesn't exist (dir %ld, name %s\n",
                       dir->i_ino, rec->ur_name);
                GOTO(out_unlink_cancel, rc = -ENOENT);
        } else if (offset) {
                struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
                mds_pack_inode2fid(&body->fid1, inode);
                mds_pack_inode2body(body, inode);
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_UNLINK_WRITE, dir->i_sb->s_dev);

        switch (rec->ur_mode /* & S_IFMT ? */) {
        case S_IFDIR:
                handle = mds_fs_start(mds, dir, MDS_FSOP_RMDIR);
                if (!handle)
                        GOTO(out_unlink_cancel, rc = PTR_ERR(handle));
                rc = vfs_rmdir(dir, dchild);
                break;
        case S_IFREG:
                /* get OBD EA data first so client can also destroy object */
                if ((inode->i_mode & S_IFMT) == S_IFREG && offset) {
                        struct lov_mds_md *md;

                        md = lustre_msg_buf(req->rq_repmsg, 2);
                        md->lmd_easize = mds->mds_max_mdsize;
                        if ((rc = mds_fs_get_md(mds, inode, md)) < 0) {
                                CDEBUG(D_INFO, "No md for ino %ld: rc = %d\n",
                                       inode->i_ino, rc);
                                memset(md, 0, md->lmd_easize);
                        }
                }
                /* no break */
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                handle = mds_fs_start(mds, dir, MDS_FSOP_UNLINK);
                if (!handle)
                        GOTO(out_unlink_cancel, rc = PTR_ERR(handle));
                rc = vfs_unlink(dir, dchild);
                break;
        default:
                CERROR("bad file type %o unlinking %s\n", rec->ur_mode, name);
                handle = NULL;
                LBUG();
                GOTO(out_unlink_cancel, rc = -EINVAL);
        }

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);
        err = mds_fs_commit(mds, dir, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        EXIT;

out_unlink_cancel:
        ldlm_lock_decref(&child_lockh, LCK_EX);
        err = ldlm_cli_cancel(&child_lockh);
        if (err < 0) {
                CERROR("failed to cancel child inode lock: err = %d\n", err);
                if (!rc)
                        rc = -ENOLCK;   /*XXX translate LDLM lock error */
        }
//out_unlink_dchild:
        l_dput(dchild);
        up(&dir->i_sem);
out_unlink:
        ldlm_lock_decref(&lockh, lock_mode);
        l_dput(de);
        req->rq_status = rc;
        return 0;
}

static int mds_reint_link(struct mds_update_record *rec, int offset,
                          struct ptlrpc_request *req)
{
        struct dentry *de_src = NULL;
        struct dentry *de_tgt_dir = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        void *handle;
        int rc = 0;
        int err;

        ENTRY;
        de_src = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_src) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK)) {
                GOTO(out_link, rc = -ESTALE);
        }

        de_tgt_dir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgt_dir)) {
                GOTO(out_link_de_src, rc = -ESTALE);
        }

        down(&de_tgt_dir->d_inode->i_sem);
        dchild = lookup_one_len(rec->ur_name, de_tgt_dir, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                GOTO(out_link_de_tgt_dir, rc = -ESTALE);
        }

        if (dchild->d_inode) {
                CERROR("child exists (dir %ld, name %s\n",
                       de_tgt_dir->d_inode->i_ino, rec->ur_name);
                GOTO(out_link_dchild, rc = -EEXIST);
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_LINK_WRITE,
                       de_src->d_inode->i_sb->s_dev);

        handle = mds_fs_start(mds, de_tgt_dir->d_inode, MDS_FSOP_LINK);
        if (!handle)
                GOTO(out_link_dchild, rc = PTR_ERR(handle));

        rc = vfs_link(de_src, de_tgt_dir->d_inode, dchild);

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);

        err = mds_fs_commit(mds, de_tgt_dir->d_inode, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }
        EXIT;

out_link_dchild:
        l_dput(dchild);
out_link_de_tgt_dir:
        up(&de_tgt_dir->d_inode->i_sem);
        l_dput(de_tgt_dir);
out_link_de_src:
        l_dput(de_src);
out_link:
        req->rq_status = rc;
        return 0;
}

static int mds_reint_rename(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_srcdir = NULL;
        struct dentry *de_tgtdir = NULL;
        struct dentry *de_old = NULL;
        struct dentry *de_new = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle tgtlockh, srclockh, oldhandle;
        int flags, lock_mode, rc = 0, err;
        void *handle;
        __u64 res_id[3] = { 0 };
        ENTRY;

        de_srcdir = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_srcdir))
                GOTO(out_rename, rc = -ESTALE);

        lock_mode = (req->rq_reqmsg->opc == MDS_REINT) ? LCK_CW : LCK_PW;
        res_id[0] = de_srcdir->d_inode->i_ino;

        rc = ldlm_lock_match(obd->obd_namespace, res_id, LDLM_PLAIN,
                             NULL, 0, lock_mode, &srclockh);
        if (rc == 0) {
                LDLM_DEBUG_NOLOCK("enqueue res %Lu", res_id[0]);
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, 0, &srclockh);
                if (rc != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        GOTO(out_rename_srcput, rc = -EIO);
                }
        } else
                ldlm_lock_dump((void *)(unsigned long)srclockh.addr);

        de_tgtdir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgtdir))
                GOTO(out_rename_srcdir, rc = -ESTALE);

        lock_mode = (req->rq_reqmsg->opc == MDS_REINT) ? LCK_CW : LCK_PW;
        res_id[0] = de_tgtdir->d_inode->i_ino;

        rc = ldlm_lock_match(obd->obd_namespace, res_id, LDLM_PLAIN,
                             NULL, 0, lock_mode, &tgtlockh);
        if (rc == 0) {
                LDLM_DEBUG_NOLOCK("enqueue res %Lu", res_id[0]);
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, 0, &tgtlockh);
                if (rc != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        GOTO(out_rename_tgtput, rc = -EIO);
                }
        } else
                ldlm_lock_dump((void *)(unsigned long)tgtlockh.addr);

        double_lock(de_tgtdir, de_srcdir);

        de_old = lookup_one_len(rec->ur_name, de_srcdir, rec->ur_namelen - 1);
        if (IS_ERR(de_old)) {
                CERROR("old child lookup error (%*s): %ld\n",
                       rec->ur_namelen - 1, rec->ur_name, PTR_ERR(de_old));
                GOTO(out_rename_tgtdir, rc = -ENOENT);
        }

        de_new = lookup_one_len(rec->ur_tgt, de_tgtdir, rec->ur_tgtlen - 1);
        if (IS_ERR(de_new)) {
                CERROR("new child lookup error (%*s): %ld\n",
                       rec->ur_tgtlen - 1, rec->ur_tgt, PTR_ERR(de_new));
                GOTO(out_rename_deold, rc = -ENOENT);
        }
        
        /* in intent case ship back attributes to client */
        if (offset) { 
                struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
                struct inode *inode = de_new->d_inode;

                if (!inode) {
                        body->valid = 0; 
                } else {
                        mds_pack_inode2fid(&body->fid1, inode);
                        mds_pack_inode2body(body, inode);
                        if (S_ISREG(inode->i_mode)) { 
                                struct lov_mds_md *md;
                                
                                md = lustre_msg_buf(req->rq_repmsg, 2);
                                md->lmd_easize = mds->mds_max_mdsize;
                                if ((rc = mds_fs_get_md(mds, inode, md)) < 0) {
                                        CDEBUG(D_INFO,"No md for %ld: rc %d\n",
                                               inode->i_ino, rc);
                                        memset(md, 0, md->lmd_easize);
                                }
                        }
                }
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE,
                       de_srcdir->d_inode->i_sb->s_dev);

        handle = mds_fs_start(mds, de_tgtdir->d_inode, MDS_FSOP_RENAME);
        if (!handle)
                GOTO(out_rename_denew, rc = PTR_ERR(handle));
        lock_kernel();
        rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new,
                        NULL);
        unlock_kernel();

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);

        err = mds_fs_commit(mds, de_tgtdir->d_inode, handle);
        if (err) {
                CERROR("error on commit: err = %d\n", err);
                if (!rc)
                        rc = err;
        }
        EXIT;

      out_rename_denew:
        l_dput(de_new);
      out_rename_deold:
        if (!rc) {
                res_id[0] = de_old->d_inode->i_ino;
                /* Take an exclusive lock on the resource that we're
                 * about to free, to force everyone to drop their
                 * locks. */
                LDLM_DEBUG_NOLOCK("getting EX lock res %Lu", res_id[0]);
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id, LDLM_PLAIN, NULL, 0, LCK_EX,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, 0, &oldhandle);
                if (rc)
                        CERROR("failed to get child inode lock (child ino %Ld, "
                               "dir ino %ld)\n",
                               res_id[0], de_old->d_inode->i_ino);
        }

        l_dput(de_old);

        if (!rc) {
                ldlm_lock_decref(&oldhandle, LCK_EX);
                rc = ldlm_cli_cancel(&oldhandle);
                if (rc < 0)
                        CERROR("failed to cancel child inode lock ino "
                               "%Ld: %d\n", res_id[0], rc);
        }
out_rename_tgtdir:
        double_up(&de_srcdir->d_inode->i_sem, &de_tgtdir->d_inode->i_sem);
        ldlm_lock_decref(&tgtlockh, lock_mode);
out_rename_tgtput:
        l_dput(de_tgtdir);
out_rename_srcdir:
        ldlm_lock_decref(&srclockh, lock_mode);
out_rename_srcput:
        l_dput(de_srcdir);
out_rename:
        req->rq_status = rc;
        return 0;
}

typedef int (*mds_reinter) (struct mds_update_record *, int offset,
                            struct ptlrpc_request *);

static mds_reinter reinters[REINT_MAX + 1] = {
        [REINT_SETATTR] mds_reint_setattr,
        [REINT_CREATE] mds_reint_create,
        [REINT_UNLINK] mds_reint_unlink,
        [REINT_LINK] mds_reint_link,
        [REINT_RENAME] mds_reint_rename,
        [REINT_RECREATE] mds_reint_recreate,
};

int mds_reint_rec(struct mds_update_record *rec, int offset,
                  struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_run_ctxt saved;

        int rc;

        if (rec->ur_opcode < 1 || rec->ur_opcode > REINT_MAX) {
                CERROR("opcode %d not valid\n", rec->ur_opcode);
                rc = req->rq_status = -EINVAL;
                RETURN(rc);
        }

        push_ctxt(&saved, &mds->mds_ctxt);
        rc = reinters[rec->ur_opcode] (rec, offset, req);
        pop_ctxt(&saved);

        return rc;
}
