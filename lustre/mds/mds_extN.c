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

static int mds_extN_set_obdo(struct inode *inode, void *handle,
                             struct obdo *obdo)
{
        struct mds_objid *data = (struct mds_objid *)obdo->o_inline;
        int rc;

        data->mo_magic = cpu_to_le64(XATTR_MDS_MO_MAGIC);

        lock_kernel();
        down(&inode->i_sem);
        if (obdo == NULL)
                rc = extN_xattr_set(handle, inode, EXTN_XATTR_INDEX_LUSTRE,
                                    XATTR_LUSTRE_MDS_OBJID, NULL, 0, 0);
        else
                rc = extN_xattr_set(handle, inode, EXTN_XATTR_INDEX_LUSTRE,
                                    XATTR_LUSTRE_MDS_OBJID, obdo->o_inline,
                                    OBD_INLINESZ, XATTR_CREATE);
        up(&inode->i_sem);
        unlock_kernel();

        if (rc)
                CERROR("error adding objectid %Ld to inode %ld\n",
                       (unsigned long long)obdo->o_id, inode->i_ino);
        return rc;
}

static int mds_extN_get_obdo(struct inode *inode, struct obdo *obdo)
{
        struct mds_objid *data;
        int rc;

        lock_kernel();
        down(&inode->i_sem);
        rc = extN_xattr_get(inode, EXTN_XATTR_INDEX_LUSTRE,
                            XATTR_LUSTRE_MDS_OBJID, obdo->o_inline,
                            OBD_INLINESZ);
        data = (struct mds_objid *)obdo->o_inline;

        up(&inode->i_sem);
        unlock_kernel();

        if (rc < 0) {
                CERROR("error getting EA %s from MDS inode %ld: rc = %d\n",
                       XATTR_LUSTRE_MDS_OBJID, inode->i_ino, rc);
                obdo->o_id = 0;
        } else if (data->mo_magic != cpu_to_le64(XATTR_MDS_MO_MAGIC)) {
                CERROR("MDS object id %Ld has bad magic %Lx\n",
                       (unsigned long long)obdo->o_id,
                       (unsigned long long)le64_to_cpu(data->mo_magic));
                rc = -EINVAL;
        } else {
                /* This field is byteswapped because it appears in the
                 * catalogue.  All others are opaque to the MDS */
                obdo->o_id = le64_to_cpu(data->mo_lov_md.lmd_object_id);
        }

#warning FIXME: pass this buffer to caller for transmission when size exceeds OBD_INLINESZ
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
                if (mds_extN_set_obdo(inode, handle, NULL))
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

static struct mds_fs_operations mds_extN_fs_ops = {
        fs_start:               mds_extN_start,
        fs_commit:              mds_extN_commit,
        fs_setattr:             mds_extN_setattr,
        fs_set_obdo:            mds_extN_set_obdo,
        fs_get_obdo:            mds_extN_get_obdo,
        fs_readpage:            mds_extN_readpage,
        fs_delete_inode:        mds_extN_delete_inode,
        cl_delete_inode:        clear_inode,
        fs_journal_data:        mds_extN_journal_data,
        fs_set_last_rcvd:       mds_extN_set_last_rcvd,
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

MODULE_AUTHOR("Cluster File Systems, Inc. <adilger@clusterfs.com>");
MODULE_DESCRIPTION("Lustre MDS extN Filesystem Helper v0.1");
MODULE_LICENSE("GPL");

module_init(mds_extN_init);
module_exit(mds_extN_exit);
