/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_extN.c
 *
 *  Lustre Metadata Server (mds) journal abstraction routines
 *
 *  Copyright (C) 2002  Cluster File Systems, Inc.
 *  author: Andreas Dilger <adilger@clusterfs.com>
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/extN_fs.h>
#include <linux/extN_jbd.h>
#include <linux/extN_xattr.h>
#include <linux/lustre_mds.h>
#include <linux/module.h>
#include <linux/obd_lov.h>

static struct mds_fs_operations mds_extN_fs_ops;
static kmem_cache_t *jcb_cache;
static int jcb_cache_count;

struct mds_cb_data {
        struct journal_callback cb_jcb;
        struct mds_obd *cb_mds;
        __u64 cb_last_rcvd;
};

#define EXTN_XATTR_INDEX_LUSTRE         5
#define XATTR_LUSTRE_MDS_OBJID          "system.lustre_mds_objid"

#define XATTR_MDS_MO_MAGIC              0x4711

/*
 * We don't currently need any additional blocks for rmdir and
 * unlink transactions because we are storing the OST oa_id inside
 * the inode (which we will be changing anyways as part of this
 * transaction).
 */
static void *mds_extN_start(struct inode *inode, int op)
{
        /* For updates to the last recieved file */
        int nblocks = EXTN_DATA_TRANS_BLOCKS;

        switch(op) {
        case MDS_FSOP_RMDIR:
        case MDS_FSOP_UNLINK:
                nblocks += EXTN_DELETE_TRANS_BLOCKS;
                break;
        case MDS_FSOP_RENAME:
                /* We may be modifying two directories */
                nblocks += EXTN_DATA_TRANS_BLOCKS;
        case MDS_FSOP_SYMLINK:
                /* Possible new block + block bitmap + GDT for long symlink */
                nblocks += 3;
        case MDS_FSOP_CREATE:
        case MDS_FSOP_MKDIR:
        case MDS_FSOP_MKNOD:
                /* New inode + block bitmap + GDT for new file */
                nblocks += 3;
        case MDS_FSOP_LINK:
                /* Change parent directory */
                nblocks += EXTN_INDEX_EXTRA_TRANS_BLOCKS+EXTN_DATA_TRANS_BLOCKS;
                break;
        case MDS_FSOP_SETATTR:
                /* Setattr on inode */
                nblocks += 1;
                break;
        default: CERROR("unknown transaction start op %d\n", op);
                 LBUG();
        }

        return journal_start(EXTN_JOURNAL(inode), nblocks);
}

static int mds_extN_commit(struct inode *inode, void *handle)
{
        return journal_stop((handle_t *)handle);
}

static int mds_extN_setattr(struct dentry *dentry, void *handle,
                            struct iattr *iattr)
{
        struct inode *inode = dentry->d_inode;

        if (inode->i_op->setattr)
                return inode->i_op->setattr(dentry, iattr);
        else
                return inode_setattr(inode, iattr);
}

static int mds_extN_set_md(struct inode *inode, void *handle,
                             struct lov_stripe_md *md)
{
        int rc;



        lock_kernel();
        down(&inode->i_sem);
        if (md == NULL)
                rc = extN_xattr_set(handle, inode, EXTN_XATTR_INDEX_LUSTRE,
                                    XATTR_LUSTRE_MDS_OBJID, NULL, 0, 0);
        else { 
                md->lmd_magic = cpu_to_le32(XATTR_MDS_MO_MAGIC);
                rc = extN_xattr_set(handle, inode, EXTN_XATTR_INDEX_LUSTRE,
                                    XATTR_LUSTRE_MDS_OBJID, md, 
                                    md->lmd_size, XATTR_CREATE);
        }
        up(&inode->i_sem);
        unlock_kernel();

        if (rc)
                CERROR("error adding objectid %Ld to inode %ld\n",
                       (unsigned long long)md->lmd_object_id, inode->i_ino);
        return rc;
}

static int mds_extN_get_md(struct inode *inode, struct lov_stripe_md *md)
{
        int rc;
        int size = md->lmd_size;

        lock_kernel();
        down(&inode->i_sem);
        rc = extN_xattr_get(inode, EXTN_XATTR_INDEX_LUSTRE,
                            XATTR_LUSTRE_MDS_OBJID, md, size);

        up(&inode->i_sem);
        unlock_kernel();

        if (rc < 0) {
                CDEBUG(D_INFO, "error getting EA %s from MDS inode %ld: "
                       "rc = %d\n", XATTR_LUSTRE_MDS_OBJID, inode->i_ino, rc);
                memset(md, 0, size); 
        } else if (md->lmd_magic != cpu_to_le32(XATTR_MDS_MO_MAGIC)) {
                CERROR("MDS striping md for ino %ld has bad magic\n",
                       inode->i_ino);
                rc = -EINVAL;
        } else {
                /* This field is byteswapped because it appears in the
                 * catalogue.  All others are opaque to the MDS */
                md->lmd_object_id = le64_to_cpu(md->lmd_object_id);
        }

        return rc;
}

static ssize_t mds_extN_readpage(struct file *file, char *buf, size_t count,
                                 loff_t *offset)
{
        struct inode *inode = file->f_dentry->d_inode;
        int rc = 0;

        if (S_ISREG(inode->i_mode))
                rc = file->f_op->read(file, buf, count, offset);
        else {
                struct buffer_head *bh;

                /* FIXME: this assumes the blocksize == count, but the calling
                 *        function will detect this as an error for now */
                bh = extN_bread(NULL, inode,
                                *offset >> inode->i_sb->s_blocksize_bits,
                                0, &rc);

                if (bh) {
                        memcpy(buf, bh->b_data, inode->i_blksize);
                        brelse(bh);
                        rc = inode->i_blksize;
                }
        }

        return rc;
}

static void mds_extN_delete_inode(struct inode *inode)
{
        if (S_ISREG(inode->i_mode)) {
                void *handle = mds_extN_start(inode, MDS_FSOP_UNLINK);

                if (IS_ERR(handle)) {
                        CERROR("unable to start transaction");
                        EXIT;
                        return;
                }
                if (mds_extN_set_md(inode, handle, NULL))
                        CERROR("error clearing obdo on %ld\n", inode->i_ino);

                if (mds_extN_fs_ops.cl_delete_inode)
                        mds_extN_fs_ops.cl_delete_inode(inode);

                if (mds_extN_commit(inode, handle))
                        CERROR("error closing handle on %ld\n", inode->i_ino);
        } else
                mds_extN_fs_ops.cl_delete_inode(inode);
}

static void mds_extN_callback_status(void *jcb, int error)
{
        struct mds_cb_data *mcb = (struct mds_cb_data *)jcb;

        CDEBUG(D_EXT2, "got callback for last_rcvd %Ld: rc = %d\n",
               mcb->cb_last_rcvd, error);
        if (!error && mcb->cb_last_rcvd > mcb->cb_mds->mds_last_committed)
                mcb->cb_mds->mds_last_committed = mcb->cb_last_rcvd;

        kmem_cache_free(jcb_cache, jcb);
        --jcb_cache_count;
}

#ifdef HAVE_JOURNAL_CALLBACK
static void mds_extN_callback_func(void *cb_data)
{
        mds_extN_callback_status(cb_data, 0);
}
#endif

static int mds_extN_set_last_rcvd(struct mds_obd *mds, void *handle)
{
        struct mds_cb_data *mcb;

        mcb = kmem_cache_alloc(jcb_cache, GFP_NOFS);
        if (!mcb)
                RETURN(-ENOMEM);

        ++jcb_cache_count;
        mcb->cb_mds = mds;
        mcb->cb_last_rcvd = mds->mds_last_rcvd;

#ifdef HAVE_JOURNAL_CALLBACK_STATUS
        CDEBUG(D_EXT2, "set callback for last_rcvd: %Ld\n",
               (unsigned long long)mcb->cb_last_rcvd);
        journal_callback_set(handle, mds_extN_callback_status,
                             (void *)mcb);
#elif defined(HAVE_JOURNAL_CALLBACK)
        /* XXX original patch version - remove soon */
#warning "using old journal callback kernel patch, please update"
        CDEBUG(D_EXT2, "set callback for last_rcvd: %Ld\n",
               (unsigned long long)mcb->cb_last_rcvd);
        journal_callback_set(handle, mds_extN_callback_func, mcb);
#else
#warning "no journal callback kernel patch, faking it..."
        {
        static long next = 0;

        if (time_after(jiffies, next)) {
                CERROR("no journal callback kernel patch, faking it...\n");
                next = jiffies + 300 * HZ;
        }
        }
        mds_extN_callback_status((struct journal_callback *)mcb, 0);
#endif

        return 0;
}

static int mds_extN_journal_data(struct file *filp)
{
        struct inode *inode = filp->f_dentry->d_inode;

        EXTN_I(inode)->i_flags |= EXTN_JOURNAL_DATA_FL;

        return 0;
}

/*
 * We need to hack the return value for the free inode counts because
 * the current EA code requires one filesystem block per inode with EAs,
 * so it is possible to run out of blocks before we run out of inodes.
 *
 * This can be removed when the extN EA code is fixed.
 */
static int mds_extN_statfs(struct super_block *sb, struct statfs *sfs)
{
        int rc = vfs_statfs(sb, sfs);

        if (!rc && sfs->f_bfree < sfs->f_ffree)
                sfs->f_ffree = sfs->f_bfree;

        return rc;
}

static struct mds_fs_operations mds_extN_fs_ops = {
        fs_start:               mds_extN_start,
        fs_commit:              mds_extN_commit,
        fs_setattr:             mds_extN_setattr,
        fs_set_md:            mds_extN_set_md,
        fs_get_md:            mds_extN_get_md,
        fs_readpage:            mds_extN_readpage,
        fs_delete_inode:        mds_extN_delete_inode,
        cl_delete_inode:        clear_inode,
        fs_journal_data:        mds_extN_journal_data,
        fs_set_last_rcvd:       mds_extN_set_last_rcvd,
        fs_statfs:              mds_extN_statfs,
};

static int __init mds_extN_init(void)
{
        int rc;

        //rc = extN_xattr_register();
        jcb_cache = kmem_cache_create("mds_extN_jcb",
                                      sizeof(struct mds_cb_data), 0,
                                      0, NULL, NULL);
        if (!jcb_cache) {
                CERROR("error allocating MDS journal callback cache\n");
                GOTO(out, rc = -ENOMEM);
        }
        rc = mds_register_fs_type(&mds_extN_fs_ops, "extN");

        if (rc)
                kmem_cache_destroy(jcb_cache);
out:
        return rc;
}

static void __exit mds_extN_exit(void)
{
        int rc;

        mds_unregister_fs_type("extN");
        rc = kmem_cache_destroy(jcb_cache);

        if (rc || jcb_cache_count) {
                CERROR("can't free MDS callback cache: count %d, rc = %d\n",
                       jcb_cache_count, rc);
        }

        //rc = extN_xattr_unregister();
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre MDS extN Filesystem Helper v0.1");
MODULE_LICENSE("GPL");

module_init(mds_extN_init);
module_exit(mds_extN_exit);
