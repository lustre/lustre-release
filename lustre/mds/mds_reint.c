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
#include <linux/ext2_fs.h>
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

extern struct ptlrpc_request *mds_prep_req(int size, int opcode, int namelen, char *name, int tgtlen, char *tgt);

static int mds_reint_setattr(struct mds_update_record *rec, struct ptlrpc_request *req)
{
        struct dentry *de;
        struct inode *inode;

        de = mds_fid2dentry(&req->rq_obd->u.mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_SETATTR)) {
                req->rq_rephdr->status = -ESTALE;
                RETURN(0);
        }

        inode = de->d_inode;
        CDEBUG(D_INODE, "ino %ld\n", inode->i_ino);

        /* a _really_ horrible hack to avoid removing the data stored
           in the block pointers; this data is the object id
           this will go into an extended attribute at some point.
        */
        if ( rec->ur_iattr.ia_valid & ATTR_SIZE ) {
                /* ATTR_SIZE would invoke truncate: clear it */
                rec->ur_iattr.ia_valid &= ~ATTR_SIZE;
                inode->i_size = rec->ur_iattr.ia_size;

                /* an _even_more_ horrible hack to make this hack work with
                 * ext3.  This is because ext3 keeps a separate inode size
                 * until the inode is committed to ensure consistency.  This
                 * will also go away with the move to EAs.
                 */
                if (!strcmp(inode->i_sb->s_type->name, "ext3"))
                        inode->u.ext3_i.i_disksize = inode->i_size;

                /* make sure _something_ gets set - so new inode
                   goes to disk (probably won't work over XFS */
                if (!rec->ur_iattr.ia_valid & ATTR_MODE) {
                        rec->ur_iattr.ia_valid |= ATTR_MODE;
                        rec->ur_iattr.ia_mode = inode->i_mode;
                }
        }
        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_SETATTR_WRITE);
        if ( inode->i_op->setattr ) {
                req->rq_rephdr->status =
                        inode->i_op->setattr(de, &rec->ur_iattr);
        } else {
                req->rq_rephdr->status =
                        inode_setattr(inode, &rec->ur_iattr);
        }

        l_dput(de);
        RETURN(0);
}

/*
   XXX nasty hack: store the object id in the first two
   direct block spots
*/
static inline void mds_store_objid(struct inode *inode, __u64 *id)
{
        /* FIXME: it is only by luck that this works on ext3 */
        memcpy(&inode->u.ext2_i.i_data, id, sizeof(*id));
}


static int mds_reint_create(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        int type = rec->ur_mode & S_IFMT;
        struct dentry *de = NULL;
        struct mds_rep *rep = req->rq_rep.mds;
        struct dentry *dchild = NULL;
        int rc = 0;
        ENTRY;

        de = mds_fid2dentry(&req->rq_obd->u.mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE)) {
                LBUG();
                GOTO(out_reint_create, (rc = -ESTALE));
        }
        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                LBUG();
                GOTO(out_reint_create, (rc = -ESTALE));
        }

        if (dchild->d_inode) {
                CERROR("child exists (dir %ld, name %s)\n",
                       de->d_inode->i_ino, rec->ur_name);
                LBUG();
                GOTO(out_reint_create, (rc = -EEXIST));
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_CREATE_WRITE);

        switch (type) {
        case S_IFREG: {
                rc = vfs_create(de->d_inode, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFDIR: {
                rc = vfs_mkdir(de->d_inode, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFLNK: {
                rc = vfs_symlink(de->d_inode, dchild, rec->ur_tgt);
                EXIT;
                break;
        }
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK: {
                int rdev = rec->ur_id;
                rc = vfs_mknod(de->d_inode, dchild, rec->ur_mode, rdev);
                EXIT;
                break;
        }
        }

        if (!rc) {
                if (type == S_IFREG)
                        mds_store_objid(dchild->d_inode, &rec->ur_id);
                dchild->d_inode->i_atime = rec->ur_time;
                dchild->d_inode->i_ctime = rec->ur_time;
                dchild->d_inode->i_mtime = rec->ur_time;
                dchild->d_inode->i_uid = rec->ur_uid;
                dchild->d_inode->i_gid = rec->ur_gid;
                rep->ino = dchild->d_inode->i_ino;
                rep->generation = dchild->d_inode->i_generation;
        }

out_reint_create:
        req->rq_rephdr->status = rc;
        l_dput(de);
        l_dput(dchild);
        RETURN(0);
}

static int mds_reint_unlink(struct mds_update_record *rec,
                            struct ptlrpc_request *req)
{
        struct dentry *de = NULL;
        struct dentry *dchild = NULL;
        int rc = 0;
        ENTRY;

        de = mds_fid2dentry(&req->rq_obd->u.mds, rec->ur_fid1, NULL);
        if (IS_ERR(de) || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK)) {
                LBUG();
                GOTO(out_unlink, (rc = -ESTALE));
        }
        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

        dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                LBUG();
                GOTO(out_unlink, (rc = -ESTALE));
        }

        if (!dchild->d_inode) {
                CERROR("child doesn't exist (dir %ld, name %s\n",
                       de->d_inode->i_ino, rec->ur_name);
                LBUG();
                GOTO(out_unlink, (rc = -ESTALE));
        }

        if (dchild->d_inode->i_ino != rec->ur_fid2->id)
                LBUG();
        if (dchild->d_inode->i_generation != rec->ur_fid2->generation)
                LBUG();

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_UNLINK_WRITE);

        switch (dchild->d_inode->i_mode & S_IFMT) {
        case S_IFDIR:
                rc = vfs_rmdir(de->d_inode, dchild);
                EXIT;
                break;
        default:
                rc = vfs_unlink(de->d_inode, dchild);
                EXIT;
                break;
        }

out_unlink:
        req->rq_rephdr->status = rc;
        l_dput(de);
        l_dput(dchild);
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

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_LINK_WRITE);

        rc = vfs_link(de_src, de_tgt_dir->d_inode, dchild);
        EXIT;

 out_link:
        req->rq_rephdr->status = rc;
        l_dput(de_src);
        l_dput(de_tgt_dir);
        l_dput(dchild);
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

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE);

        rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new);
        EXIT;

 out_rename:
        req->rq_rephdr->status = rc;
        l_dput(de_new);
        l_dput(de_old);
        l_dput(de_tgtdir);
        l_dput(de_srcdir);
        return 0;
}

typedef int (*mds_reinter)(struct mds_update_record *, struct ptlrpc_request*);

static mds_reinter  reinters[REINT_MAX+1] = {
        [REINT_SETATTR]   mds_reint_setattr,
        [REINT_CREATE]    mds_reint_create,
        [REINT_UNLINK]    mds_reint_unlink,
        [REINT_LINK]      mds_reint_link,
        [REINT_RENAME]    mds_reint_rename
};

int mds_reint_rec(struct mds_update_record *rec, struct ptlrpc_request *req)
{
        int rc;

        if (rec->ur_opcode < 0 || rec->ur_opcode > REINT_MAX) {
                CERROR("opcode %d not valid\n", rec->ur_opcode);
                rc = req->rq_status = -EINVAL;
                RETURN(rc);
        }

        rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep,
                          &req->rq_replen, &req->rq_repbuf);
        if (rc) {
                CERROR("mds: out of memory\n");
                rc = req->rq_status = -ENOMEM;
                RETURN(rc);
        }
        req->rq_rephdr->xid = req->rq_reqhdr->xid;

        rc = reinters[rec->ur_opcode](rec, req);
        return rc;
}
