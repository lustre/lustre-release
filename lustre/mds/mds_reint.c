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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>

struct mds_client_info *mds_uuid_to_mci(struct mds_obd *mds, __u8 *uuid)
{
        struct list_head *p;

        if (!uuid)
                return NULL;

        list_for_each(p, &mds->mds_client_info) {
                struct mds_client_info *mci;

                mci = list_entry(p, struct mds_client_info, mci_list);
                CDEBUG(D_INFO, "checking client UUID '%s'\n",
                       mci->mci_mcd->mcd_uuid);
                if (!strncmp(mci->mci_mcd->mcd_uuid, uuid,
                             sizeof(mci->mci_mcd->mcd_uuid)))
                        return mci;
        }
        CDEBUG(D_INFO, "no client UUID found for '%s'\n", uuid);
        return NULL;
}

int mds_update_last_rcvd(struct mds_obd *mds, void *handle,
                         struct ptlrpc_request *req)
{
        /* get from req->rq_connection-> or req->rq_client */
        struct mds_client_info *mci;
        loff_t off;
        int rc;

        mci = mds_uuid_to_mci(mds, req->rq_connection->c_remote_uuid);
        if (!mci) {
                CERROR("unable to locate MDS client data for UUID '%s'\n",
                       ptlrpc_req_to_uuid(req));
                /* This will be a real error once everything is working */
                //LBUG();
                RETURN(0);
        }

        off = MDS_LR_CLIENT + mci->mci_off * MDS_LR_SIZE;

        ++mds->mds_last_rcvd;   /* lock this, or make it an LDLM function? */
        req->rq_repmsg->transno = HTON__u64(mds->mds_last_rcvd);
        mci->mci_mcd->mcd_last_rcvd = cpu_to_le64(mds->mds_last_rcvd);
        mci->mci_mcd->mcd_mount_count = cpu_to_le64(mds->mds_mount_count);
        mci->mci_mcd->mcd_last_xid = cpu_to_le32(req->rq_reqmsg->xid);

        mds_fs_set_last_rcvd(mds, handle);
        rc = lustre_fwrite(mds->mds_rcvd_filp, (char *)mci->mci_mcd,
                           sizeof(*mci->mci_mcd), &off);
        CDEBUG(D_INODE, "wrote trans #%Ld for client '%s' at #%d: rc = %d\n",
               mds->mds_last_rcvd, mci->mci_mcd->mcd_uuid, mci->mci_off, rc);
        // store new value and last committed value in req struct

        if (rc == sizeof(mci->mci_mcd))
                rc = 0;
        else if (rc >= 0)
                rc = -EIO;

        return rc;
}

static int mds_reint_setattr(struct mds_update_record *rec,
                             struct ptlrpc_request *req)
{
        struct mds_obd *mds = &req->rq_obd->u.mds;
        struct dentry *de;
        void *handle;
        int rc = 0;

        de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_SETATTR)) {
                GOTO(out_setattr, rc = -ESTALE);
        }

        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_SETATTR_WRITE,
                       de->d_inode->i_sb->s_dev);

        handle = mds_fs_start(mds, de->d_inode, MDS_FSOP_SETATTR);
        if (!handle)
                GOTO(out_setattr_de, rc = PTR_ERR(handle));
        rc = mds_fs_setattr(mds, de, handle, &rec->ur_iattr);

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);
        /* FIXME: need to return last_rcvd, last_committed */

        EXIT;

        /* FIXME: keep rc intact */
        rc = mds_fs_commit(mds, de->d_inode, handle);
out_setattr_de:
        l_dput(de);
out_setattr:
        req->rq_status = rc;
        return(0);
}

static int mds_reint_create(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de = NULL;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        struct dentry *dchild = NULL;
        struct inode *dir;
        void *handle;
        int rc = 0, type = rec->ur_mode & S_IFMT;
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
                CERROR("child exists (dir %ld, name %s, ino %ld)\n",
                       dir->i_ino, rec->ur_name, dchild->d_inode->i_ino);
                LBUG();
                GOTO(out_create_dchild, rc = -EEXIST);
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_CREATE_WRITE, dir->i_sb->s_dev);

        switch (type) {
        case S_IFREG: {
                handle = mds_fs_start(mds, dir, MDS_FSOP_CREATE);
                if (!handle)
                        GOTO(out_create_dchild, PTR_ERR(handle));
                rc = vfs_create(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFDIR: {
                handle = mds_fs_start(mds, dir, MDS_FSOP_MKDIR);
                if (!handle)
                        GOTO(out_create_dchild, PTR_ERR(handle));
                rc = vfs_mkdir(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFLNK: {
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
        case S_IFSOCK: {
                int rdev = rec->ur_id;
                handle = mds_fs_start(mds, dir, MDS_FSOP_MKNOD);
                if (!handle)
                        GOTO(out_create_dchild, PTR_ERR(handle));
                rc = vfs_mknod(dir, dchild, rec->ur_mode, rdev);
                EXIT;
                break;
        }
        default:
                CERROR("bad file type %d for create of %s\n",type,rec->ur_name);
                GOTO(out_create_dchild, rc = -EINVAL);
        }

        if (rc) {
                CERROR("error during create: %d\n", rc);
                LBUG();
                GOTO(out_create_commit, rc);
        } else {
                struct iattr iattr;
                struct inode *inode = dchild->d_inode;
                struct mds_body *body;

                CDEBUG(D_INODE, "created ino %ld\n", dchild->d_inode->i_ino);
                if (type == S_IFREG) {
                        rc = mds_fs_set_objid(mds, inode, handle, rec->ur_id);
                        if (rc)
                                CERROR("error %d setting objid for %ld\n",
                                       rc, inode->i_ino);
                }

                iattr.ia_atime = rec->ur_time;
                iattr.ia_ctime = rec->ur_time;
                iattr.ia_mtime = rec->ur_time;
                iattr.ia_uid = rec->ur_uid;
                iattr.ia_gid = rec->ur_gid;
                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                rc = mds_fs_setattr(mds, dchild, handle, &iattr);
                /* XXX should we abort here in case of error? */

                //if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);

                body = lustre_msg_buf(req->rq_repmsg, 0);
                body->ino = inode->i_ino;
                body->generation = inode->i_generation;
        }

out_create_commit:
        /* FIXME: keep rc intact */
        rc = mds_fs_commit(mds, dir, handle);
out_create_dchild:
        l_dput(dchild);
        up(&dir->i_sem);
out_create_de:
        l_dput(de);
        req->rq_status = rc;
        return 0;
}

static int mds_reint_unlink(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        struct inode *dir, *inode;
        void *handle;
        int rc = 0;
        ENTRY;

        de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK)) {
                LBUG();
                GOTO(out_unlink, rc = -ESTALE);
        }
        dir = de->d_inode;
        CDEBUG(D_INODE, "parent ino %ld\n", dir->i_ino);

        down(&dir->i_sem);
        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                LBUG();
                GOTO(out_unlink_de, rc = -ESTALE);
        }

        inode = dchild->d_inode;
        if (!inode) {
                CERROR("child doesn't exist (dir %ld, name %s\n",
                       dir->i_ino, rec->ur_name);
                LBUG();
                GOTO(out_unlink_dchild, rc = -ESTALE);
        }

        if (inode->i_ino != rec->ur_fid2->id) {
                CERROR("inode and FID ID do not match (%ld != %Ld)\n",
                       inode->i_ino, rec->ur_fid2->id);
                LBUG();
                GOTO(out_unlink_dchild, rc = -ESTALE);
        }
        if (inode->i_generation != rec->ur_fid2->generation) {
                CERROR("inode and FID GENERATION do not match (%d != %d)\n",
                       inode->i_generation, rec->ur_fid2->generation);
                LBUG();
                GOTO(out_unlink_dchild, rc = -ESTALE);
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_UNLINK_WRITE, dir->i_sb->s_dev);

        switch (dchild->d_inode->i_mode & S_IFMT) {
        case S_IFDIR:
                handle = mds_fs_start(mds, dir, MDS_FSOP_RMDIR);
                if (!handle)
                        GOTO(out_unlink_dchild, rc = PTR_ERR(handle));
                rc = vfs_rmdir(dir, dchild);
                break;
        default:
                handle = mds_fs_start(mds, dir, MDS_FSOP_UNLINK);
                if (!handle)
                        GOTO(out_unlink_dchild, rc = PTR_ERR(handle));
                rc = vfs_unlink(dir, dchild);
                break;
        }

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);
        /* FIXME: need to return last_rcvd, last_committed */
        /* FIXME: keep rc intact */
        rc = mds_fs_commit(mds, dir, handle);

        EXIT;
out_unlink_dchild:
        l_dput(dchild);
out_unlink_de:
        up(&dir->i_sem);
        l_dput(de);
out_unlink:
        req->rq_status = rc;
        return 0;
}

static int mds_reint_link(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de_src = NULL;
        struct dentry *de_tgt_dir = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        void *handle;
        int rc = 0;

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
                       dchild->d_inode->i_sb->s_dev);

        handle = mds_fs_start(mds, de_tgt_dir->d_inode, MDS_FSOP_LINK);
        if (!handle)
                GOTO(out_link_dchild, rc = PTR_ERR(handle));

        rc = vfs_link(de_src, de_tgt_dir->d_inode, dchild);

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);

        /* FIXME: need to return last_rcvd, last_committed */
        /* FIXME: keep rc intact */
        rc = mds_fs_commit(mds, de_tgt_dir->d_inode, handle);
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

static int mds_reint_rename(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de_srcdir = NULL;
        struct dentry *de_tgtdir = NULL;
        struct dentry *de_old = NULL;
        struct dentry *de_new = NULL;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        void *handle;
        int rc = 0;
        ENTRY;

        de_srcdir = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_srcdir)) {
                GOTO(out_rename, rc = -ESTALE);
        }

        de_tgtdir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgtdir)) {
                GOTO(out_rename_srcdir, rc = -ESTALE);
        }

        de_old = lookup_one_len(rec->ur_name, de_srcdir, rec->ur_namelen - 1);
        if (IS_ERR(de_old)) {
                CERROR("old child lookup error %ld\n", PTR_ERR(de_old));
                GOTO(out_rename_tgtdir, rc = -ESTALE);
        }

        de_new = lookup_one_len(rec->ur_tgt, de_tgtdir, rec->ur_tgtlen - 1);
        if (IS_ERR(de_new)) {
                CERROR("new child lookup error %ld\n", PTR_ERR(de_new));
                GOTO(out_rename_deold, rc = -ESTALE);
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE,
                       de_srcdir->d_inode->i_sb->s_dev);

        handle = mds_fs_start(mds, de_tgtdir->d_inode, MDS_FSOP_RENAME);
        if (!handle)
                GOTO(out_rename_denew, rc = PTR_ERR(handle));
        rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new);

        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);

        /* FIXME: need to return last_rcvd, last_committed */
        /* FIXME: keep rc intact */
        rc = mds_fs_commit(mds, de_tgtdir->d_inode, handle);
        EXIT;

out_rename_denew:
        l_dput(de_new);
out_rename_deold:
        l_dput(de_old);
out_rename_tgtdir:
        l_dput(de_tgtdir);
out_rename_srcdir:
        l_dput(de_srcdir);
out_rename:
        req->rq_status = rc;
        return 0;
}

typedef int (*mds_reinter)(struct mds_update_record *, struct ptlrpc_request*);

static mds_reinter reinters[REINT_MAX+1] = {
        [REINT_SETATTR]   mds_reint_setattr,
        [REINT_CREATE]    mds_reint_create,
        [REINT_UNLINK]    mds_reint_unlink,
        [REINT_LINK]      mds_reint_link,
        [REINT_RENAME]    mds_reint_rename,
};

int mds_reint_rec(struct mds_update_record *rec, struct ptlrpc_request *req)
{
        int rc, size = sizeof(struct mds_body);

        if (rec->ur_opcode < 1 || rec->ur_opcode > REINT_MAX) {
                CERROR("opcode %d not valid\n", rec->ur_opcode);
                rc = req->rq_status = -EINVAL;
                RETURN(rc);
        }

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("mds: out of memory\n");
                rc = req->rq_status = -ENOMEM;
                RETURN(rc);
        }

        rc = reinters[rec->ur_opcode](rec, req);

        return rc;
}
