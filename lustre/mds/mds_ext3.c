/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_ext3.c
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
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#include <linux/lustre_mds.h>
#include <linux/module.h>

static struct mds_fs_operations mds_ext3_fs_ops;
static kmem_cache_t *jcb_cache;
static int jcb_cache_count;

struct mds_cb_data {
        struct journal_callback cb_jcb;
        struct mds_obd *cb_mds;
        __u64 cb_last_rcvd;
};

/*
 * We don't currently need any additional blocks for rmdir and
 * unlink transactions because we are storing the OST oa_id inside
 * the inode (which we will be changing anyways as part of this
 * transaction).
 */
static void *mds_ext3_start(struct inode *inode, int op)
{
        /* For updates to the last recieved file */
        int nblocks = EXT3_DATA_TRANS_BLOCKS;

        switch(op) {
        case MDS_FSOP_RMDIR:
        case MDS_FSOP_UNLINK:
                nblocks += EXT3_DELETE_TRANS_BLOCKS;
                break;
        case MDS_FSOP_RENAME:
                /* We may be modifying two directories */
                nblocks += EXT3_DATA_TRANS_BLOCKS;
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
                nblocks += EXT3_DATA_TRANS_BLOCKS;
                break;
        case MDS_FSOP_SETATTR:
                /* Setattr on inode */
                nblocks += 1;
                break;
        default: CERROR("unknown transaction start op %d\n", op);
                 LBUG();
        }

        return journal_start(EXT3_JOURNAL(inode), nblocks);
}

static int mds_ext3_commit(struct inode *inode, void *handle)
{
        return journal_stop((handle_t *)handle);
}

static int mds_ext3_setattr(struct dentry *dentry, void *handle,
                            struct iattr *iattr)
{
        struct inode *inode = dentry->d_inode;

        /* a _really_ horrible hack to avoid removing the data stored
           in the block pointers; this data is the object id
           this will go into an extended attribute at some point.
        */
        if (iattr->ia_valid & ATTR_SIZE) {
                /* ATTR_SIZE would invoke truncate: clear it */
                iattr->ia_valid &= ~ATTR_SIZE;
                inode->i_size = iattr->ia_size;

                /* an _even_more_ horrible hack to make this hack work with
                 * ext3.  This is because ext3 keeps a separate inode size
                 * until the inode is committed to ensure consistency.  This
                 * will also go away with the move to EAs.
                 */
                EXT3_I(inode)->i_disksize = inode->i_size;

                /* make sure _something_ gets set - so new inode
                   goes to disk (probably won't work over XFS */
                if (!iattr->ia_valid & ATTR_MODE) {
                        iattr->ia_valid |= ATTR_MODE;
                        iattr->ia_mode = inode->i_mode;
                }
        }

        if (inode->i_op->setattr)
                return inode->i_op->setattr(dentry, iattr);
        else
                return inode_setattr(inode, iattr);
}

/*
 * FIXME: nasty hack - store the object id in the first two
 *        direct block spots.  This should be done with EAs...
 *        Note also that this does not currently mark the inode
 *        dirty (it currently is used with other operations that
 *        subsequently also mark the inode dirty).
 */
static int mds_ext3_set_objid(struct inode *inode, void *handle, obd_id id)
{
        *((__u64 *)EXT3_I(inode)->i_data) = cpu_to_le64(id);
        return 0;
}

static int mds_ext3_get_objid(struct inode *inode, obd_id *id)
{
        *id = le64_to_cpu(*((__u64 *)EXT3_I(inode)->i_data));

        return 0;
}

static ssize_t mds_ext3_readpage(struct file *file, char *buf, size_t count,
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
                bh = ext3_bread(NULL, inode,
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

static void mds_ext3_delete_inode(struct inode *inode)
{
        if (S_ISREG(inode->i_mode)) {
                void *handle = mds_ext3_start(inode, MDS_FSOP_UNLINK);

                if (IS_ERR(handle)) {
                        CERROR("unable to start transaction");
                        EXIT;
                        return;
                }
                if (mds_ext3_set_objid(inode, handle, 0))
                        CERROR("error clearing objid on %ld\n", inode->i_ino);

                if (mds_ext3_fs_ops.cl_delete_inode)
                        mds_ext3_fs_ops.cl_delete_inode(inode);

                if (mds_ext3_commit(inode, handle))
                        CERROR("error closing handle on %ld\n", inode->i_ino);
        } else
                mds_ext3_fs_ops.cl_delete_inode(inode);
}


static void mds_ext3_callback_status(void *jcb, int error)
{
        struct mds_cb_data *mcb = (struct mds_cb_data *)jcb;

        CDEBUG(D_EXT2, "got callback for last_rcvd %Ld: rc = %d\n",
               mcb->cb_last_rcvd, error);
        if (!error && mcb->cb_last_rcvd > mcb->cb_mds->mds_last_committed)
                mcb->cb_mds->mds_last_committed = mcb->cb_last_rcvd;

        kmem_cache_free(jcb_cache, mcb);
        --jcb_cache_count;
}

#ifdef HAVE_JOURNAL_CALLBACK
static void mds_ext3_callback_func(void *cb_data)
{
        mds_ext3_callback_status(cb_data, 0);
}
#endif

static int mds_ext3_set_last_rcvd(struct mds_obd *mds, void *handle)
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
        journal_callback_set(handle, mds_ext3_callback_status,
                             (void *)mcb);
#elif defined(HAVE_JOURNAL_CALLBACK)
        /* XXX original patch version - remove soon */
#warning "using old journal callback kernel patch, please update"
        CDEBUG(D_EXT2, "set callback for last_rcvd: %Ld\n",
               (unsigned long long)mcb->cb_last_rcvd);
        journal_callback_set(handle, mds_ext3_callback_func, mcb);
#else
#warning "no journal callback kernel patch, faking it..."
        {
        static long next = 0;

        if (time_after(jiffies, next)) {
                CERROR("no journal callback kernel patch, faking it...\n");
                next = jiffies + 300 * HZ;
        }
        }
        mds_ext3_callback_status((struct journal_callback *)mcb, 0);
#endif

        return 0;
}

static int mds_ext3_journal_data(struct file *filp)
{
        struct inode *inode = filp->f_dentry->d_inode;

        EXT3_I(inode)->i_flags |= EXT3_JOURNAL_DATA_FL;

        return 0;
}

static struct mds_fs_operations mds_ext3_fs_ops = {
        fs_owner:               THIS_MODULE,
        fs_start:               mds_ext3_start,
        fs_commit:              mds_ext3_commit,
        fs_setattr:             mds_ext3_setattr,
        fs_set_objid:           mds_ext3_set_objid,
        fs_get_objid:           mds_ext3_get_objid,
        fs_readpage:            mds_ext3_readpage,
        fs_delete_inode:        mds_ext3_delete_inode,
        cl_delete_inode:        clear_inode,
        fs_journal_data:        mds_ext3_journal_data,
        fs_set_last_rcvd:       mds_ext3_set_last_rcvd,
};

static int __init mds_ext3_init(void)
{
        int rc;

        jcb_cache = kmem_cache_create("mds_ext3_jcb",
                                      sizeof(struct mds_cb_data), 0,
                                      0, NULL, NULL);
        if (!jcb_cache) {
                CERROR("error allocating MDS journal callback cache\n");
                GOTO(out, rc = -ENOMEM);
        }

        rc = mds_register_fs_type(&mds_ext3_fs_ops, "ext3");

        if (rc)
                kmem_cache_destroy(jcb_cache);
out:
        return rc;
}

static void __exit mds_ext3_exit(void)
{
        int rc = 0;

        mds_unregister_fs_type("ext3");
        rc = kmem_cache_destroy(jcb_cache);

        if (rc || jcb_cache_count) {
                CERROR("can't free MDS callback cache: count %d, rc = %d\n",
                       jcb_cache_count, rc);
        }
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre MDS ext3 Filesystem Helper v0.1");
MODULE_LICENSE("GPL");

module_init(mds_ext3_init);
module_exit(mds_ext3_exit);
