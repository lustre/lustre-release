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

static int mds_reint_setattr(struct mds_update_record *rec,
                             struct ptlrpc_request *req)
{
        struct mds_obd *mds = &req->rq_obd->u.mds;
        struct dentry *de;

        de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_SETATTR)) {
                req->rq_status = -ESTALE;
                RETURN(0);
        }

        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_SETATTR_WRITE,
                       de->d_inode->i_sb->s_dev);

        req->rq_status = mds_fs_setattr(mds, de, NULL, &rec->ur_iattr);

        l_dput(de);
        RETURN(0);
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
                GOTO(out_reint_create, (rc = -ESTALE));
        }
        dir = de->d_inode;
        CDEBUG(D_INODE, "ino %ld\n", dir->i_ino);

        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                LBUG();
                GOTO(out_reint_create, (rc = -ESTALE));
        }

        if (dchild->d_inode) {
                CERROR("child exists (dir %ld, name %s)\n",
                       dir->i_ino, rec->ur_name);
                LBUG();
                GOTO(out_reint_create, (rc = -EEXIST));
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_CREATE_WRITE, dir->i_sb->s_dev);

        switch (type) {
        case S_IFREG: {
                handle = mds_fs_start(mds, dir, MDS_FSOP_CREATE);
                if (!handle)
                        GOTO(out_reint_create, PTR_ERR(handle));
                rc = vfs_create(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFDIR: {
                handle = mds_fs_start(mds, dir, MDS_FSOP_MKDIR);
                if (!handle)
                        GOTO(out_reint_create, PTR_ERR(handle));
                rc = vfs_mkdir(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFLNK: {
                handle = mds_fs_start(mds, dir, MDS_FSOP_SYMLINK);
                if (!handle)
                        GOTO(out_reint_create, PTR_ERR(handle));
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
                        GOTO(out_reint_create, PTR_ERR(handle));
                rc = vfs_mknod(dir, dchild, rec->ur_mode, rdev);
                EXIT;
                break;
        }
        default:
                CERROR("bad file type %d for create of %s\n",type,rec->ur_name);
                GOTO(out_reint_create, rc = -EINVAL);
        }

        if (rc) {
                CERROR("error during create: %d\n", rc);
                LBUG();
                GOTO(out_reint_commit, rc);
        } else {
                struct iattr iattr;
                struct inode *inode = dchild->d_inode;
                struct mds_body *body;

                if (type == S_IFREG) {
                        rc = mds_fs_set_objid(mds, inode, handle, rec->ur_id);
                        if (rc)
                                CERROR("error setting objid for %ld\n",
                                       inode->i_ino);
                }

                iattr.ia_atime = rec->ur_time;
                iattr.ia_ctime = rec->ur_time;
                iattr.ia_mtime = rec->ur_time;
                iattr.ia_uid = rec->ur_uid;
                iattr.ia_gid = rec->ur_gid;
                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                rc = mds_fs_setattr(mds, dchild, handle, &iattr);

                body = lustre_msg_buf(req->rq_repmsg, 0);
                body->ino = inode->i_ino;
                body->generation = inode->i_generation;
        }

out_reint_commit:
        rc = mds_fs_commit(mds, dir, handle);

out_reint_create:
        req->rq_status = rc;
        l_dput(dchild);
        l_dput(de);
        RETURN(0);
}

static int mds_reint_unlink(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        struct inode *dir;
        int rc = 0;
        ENTRY;

        de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK)) {
                LBUG();
                GOTO(out_unlink, (rc = -ESTALE));
        }
        dir = de->d_inode;
        CDEBUG(D_INODE, "ino %ld\n", dir->i_ino);

        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                LBUG();
                GOTO(out_unlink, (rc = -ESTALE));
        }

        if (!dchild->d_inode) {
                CERROR("child doesn't exist (dir %ld, name %s\n",
                       dir->i_ino, rec->ur_name);
                LBUG();
                GOTO(out_unlink, (rc = -ESTALE));
        }

        if (dchild->d_inode->i_ino != rec->ur_fid2->id)
                LBUG();
        if (dchild->d_inode->i_generation != rec->ur_fid2->generation)
                LBUG();

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_UNLINK_WRITE, dir->i_sb->s_dev);

        switch (dchild->d_inode->i_mode & S_IFMT) {
        case S_IFDIR:
                rc = vfs_rmdir(dir, dchild);
                EXIT;
                break;
        default:
                rc = vfs_unlink(dir, dchild);
                EXIT;
                break;
        }

out_unlink:
        req->rq_status = rc;
        l_dput(dchild);
        l_dput(de);
        RETURN(0);
}

static int mds_reint_link(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de_src = NULL;
        struct dentry *de_tgt_dir = NULL;
        struct dentry *dchild = NULL;
        int rc = 0;

        ENTRY;
        de_src = mds_fid2dentry(&req->rq_obd->u.mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_src) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK)) {
                GOTO(out_link, (rc = -ESTALE));
        }

        de_tgt_dir = mds_fid2dentry(&req->rq_obd->u.mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgt_dir)) {
                GOTO(out_link, (rc = -ESTALE));
        }

        dchild = lookup_one_len(rec->ur_name, de_tgt_dir, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                GOTO(out_link, (rc = -ESTALE));
        }

        if (dchild->d_inode) {
                CERROR("child exists (dir %ld, name %s\n",
                       de_tgt_dir->d_inode->i_ino, rec->ur_name);
                GOTO(out_link, (rc = -EEXIST));
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_LINK_WRITE,
                       dchild->d_inode->i_sb->s_dev);

        rc = vfs_link(de_src, de_tgt_dir->d_inode, dchild);
        EXIT;

 out_link:
        req->rq_status = rc;
        l_dput(dchild);
        l_dput(de_tgt_dir);
        l_dput(de_src);
        return 0;
}

static int mds_reint_rename(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de_srcdir = NULL;
        struct dentry *de_tgtdir = NULL;
        struct dentry *de_old = NULL;
        struct dentry *de_new = NULL;
        int rc = 0;
        ENTRY;

        de_srcdir = mds_fid2dentry(&req->rq_obd->u.mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_srcdir)) {
                GOTO(out_rename, (rc = -ESTALE));
        }

        de_tgtdir = mds_fid2dentry(&req->rq_obd->u.mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgtdir)) {
                GOTO(out_rename, (rc = -ESTALE));
        }

        de_old = lookup_one_len(rec->ur_name, de_srcdir, rec->ur_namelen - 1);
        if (IS_ERR(de_old)) {
                CERROR("child lookup error %ld\n", PTR_ERR(de_old));
                GOTO(out_rename, (rc = -ESTALE));
        }

        de_new = lookup_one_len(rec->ur_tgt, de_tgtdir, rec->ur_tgtlen - 1);
        if (IS_ERR(de_new)) {
                CERROR("child lookup error %ld\n", PTR_ERR(de_new));
                GOTO(out_rename, (rc = -ESTALE));
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE,
                       de_srcdir->d_inode->i_sb->s_dev);

        rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new);
        EXIT;

 out_rename:
        req->rq_status = rc;
        l_dput(de_new);
        l_dput(de_old);
        l_dput(de_tgtdir);
        l_dput(de_srcdir);
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
