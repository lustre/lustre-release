/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/fsfilt_extN.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/slab.h>
#include <linux/extN_fs.h>
#include <linux/extN_jbd.h>
#include <linux/extN_xattr.h>
#include <linux/kp30.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd.h>
#include <linux/module.h>

static kmem_cache_t *fcb_cache;
static int fcb_cache_count;

struct fsfilt_cb_data {
        struct journal_callback cb_jcb; /* data private to jbd */
        fsfilt_cb_t cb_func;            /* MDS/OBD completion function */
        struct obd_device *cb_obd;      /* MDS/OBD completion device */
        __u64 cb_last_rcvd;             /* MDS/OST last committed operation */
};

#define EXTN_XATTR_INDEX_LUSTRE         5
#define XATTR_LUSTRE_MDS_OBJID          "system.lustre_mds_objid"

/*
 * We don't currently need any additional blocks for rmdir and
 * unlink transactions because we are storing the OST oa_id inside
 * the inode (which we will be changing anyways as part of this
 * transaction).
 */
static void *fsfilt_extN_start(struct inode *inode, int op)
{
        /* For updates to the last recieved file */
        int nblocks = EXTN_DATA_TRANS_BLOCKS;
        void *handle;

        switch(op) {
        case FSFILT_OP_RMDIR:
        case FSFILT_OP_UNLINK:
                nblocks += EXTN_DELETE_TRANS_BLOCKS;
                break;
        case FSFILT_OP_RENAME:
                /* We may be modifying two directories */
                nblocks += EXTN_DATA_TRANS_BLOCKS;
        case FSFILT_OP_SYMLINK:
                /* Possible new block + block bitmap + GDT for long symlink */
                nblocks += 3;
        case FSFILT_OP_CREATE:
        case FSFILT_OP_MKDIR:
        case FSFILT_OP_MKNOD:
                /* New inode + block bitmap + GDT for new file */
                nblocks += 3;
        case FSFILT_OP_LINK:
                /* Change parent directory */
                nblocks += EXTN_INDEX_EXTRA_TRANS_BLOCKS+EXTN_DATA_TRANS_BLOCKS;
                break;
        case FSFILT_OP_SETATTR:
                /* Setattr on inode */
                nblocks += 1;
                break;
        default: CERROR("unknown transaction start op %d\n", op);
                 LBUG();
        }

        lock_kernel();
        handle = journal_start(EXTN_JOURNAL(inode), nblocks);
        unlock_kernel();

        return handle;
}

static int fsfilt_extN_commit(struct inode *inode, void *handle)
{
        int rc;

        lock_kernel();
        rc = journal_stop((handle_t *)handle);
        unlock_kernel();

        return rc;
}

static int fsfilt_extN_setattr(struct dentry *dentry, void *handle,
                               struct iattr *iattr)
{
        struct inode *inode = dentry->d_inode;
        int rc;

        lock_kernel();
        if (inode->i_op->setattr)
                rc = inode->i_op->setattr(dentry, iattr);
        else
                rc = inode_setattr(inode, iattr);

        unlock_kernel();

        return rc;
}

static int fsfilt_extN_set_md(struct inode *inode, void *handle,
                              void *lmm, int lmm_size)
{
        int rc;

        down(&inode->i_sem);
        lock_kernel();
        rc = extN_xattr_set(handle, inode, EXTN_XATTR_INDEX_LUSTRE,
                            XATTR_LUSTRE_MDS_OBJID, lmm, lmm_size, 0);
        unlock_kernel();
        up(&inode->i_sem);

        if (rc) {
                CERROR("error adding MD data to inode %lu: rc = %d\n",
                       inode->i_ino, rc);
                if (rc != -ENOSPC) LBUG();
        }
        return rc;
}

static int fsfilt_extN_get_md(struct inode *inode, void *lmm, int size)
{
        int rc;

        down(&inode->i_sem);
        lock_kernel();
        rc = extN_xattr_get(inode, EXTN_XATTR_INDEX_LUSTRE,
                            XATTR_LUSTRE_MDS_OBJID, lmm, size);
        unlock_kernel();
        up(&inode->i_sem);

        /* This gives us the MD size */
        if (lmm == NULL)
                return (rc == -ENODATA) ? 0 : rc;

        if (rc < 0) {
                CDEBUG(D_INFO, "error getting EA %s from inode %lu: "
                       "rc = %d\n", XATTR_LUSTRE_MDS_OBJID, inode->i_ino, rc);
                memset(lmm, 0, size);
                return (rc == -ENODATA) ? 0 : rc;
        }

        return rc;
}

static ssize_t fsfilt_extN_readpage(struct file *file, char *buf, size_t count,
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

static void fsfilt_extN_cb_func(struct journal_callback *jcb, int error)
{
        struct fsfilt_cb_data *fcb = (struct fsfilt_cb_data *)jcb;

        fcb->cb_func(fcb->cb_obd, fcb->cb_last_rcvd, error);

        kmem_cache_free(fcb_cache, fcb);
        --fcb_cache_count;
}

static int fsfilt_extN_set_last_rcvd(struct obd_device *obd, __u64 last_rcvd,
                                     void *handle, fsfilt_cb_t cb_func)
{
#ifdef HAVE_JOURNAL_CALLBACK_STATUS
        struct fsfilt_cb_data *fcb;

        fcb = kmem_cache_alloc(fcb_cache, GFP_NOFS);
        if (!fcb)
                RETURN(-ENOMEM);

        ++fcb_cache_count;
        fcb->cb_func = cb_func;
        fcb->cb_obd = obd;
        fcb->cb_last_rcvd = last_rcvd;

        CDEBUG(D_EXT2, "set callback for last_rcvd: "LPD64"\n", last_rcvd);
        lock_kernel();
        /* Note that an "incompatible pointer" warning here is OK for now */
        journal_callback_set(handle, fsfilt_extN_cb_func,
                             (struct journal_callback *)fcb);
        unlock_kernel();
#else
#warning "no journal callback kernel patch, faking it..."
        static long next = 0;

        if (time_after(jiffies, next)) {
                CERROR("no journal callback kernel patch, faking it...\n");
                next = jiffies + 300 * HZ;
        }

        cb_func(obd, last_rcvd, 0);
#endif

        return 0;
}

static int fsfilt_extN_journal_data(struct file *filp)
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
static int fsfilt_extN_statfs(struct super_block *sb, struct statfs *sfs)
{
        int rc = vfs_statfs(sb, sfs);

        if (!rc && sfs->f_bfree < sfs->f_ffree)
                sfs->f_ffree = sfs->f_bfree;

        return rc;
}

static struct fsfilt_operations fsfilt_extN_fs_ops = {
        fs_type:                "extN",
        fs_owner:               THIS_MODULE,
        fs_start:               fsfilt_extN_start,
        fs_commit:              fsfilt_extN_commit,
        fs_setattr:             fsfilt_extN_setattr,
        fs_set_md:              fsfilt_extN_set_md,
        fs_get_md:              fsfilt_extN_get_md,
        fs_readpage:            fsfilt_extN_readpage,
        fs_journal_data:        fsfilt_extN_journal_data,
        fs_set_last_rcvd:       fsfilt_extN_set_last_rcvd,
        fs_statfs:              fsfilt_extN_statfs,
};

static int __init fsfilt_extN_init(void)
{
        int rc;

        //rc = extN_xattr_register();
        fcb_cache = kmem_cache_create("fsfilt_extN_fcb",
                                      sizeof(struct fsfilt_cb_data), 0,
                                      0, NULL, NULL);
        if (!fcb_cache) {
                CERROR("error allocating fsfilt journal callback cache\n");
                GOTO(out, rc = -ENOMEM);
        }

        rc = fsfilt_register_fs_type(&fsfilt_extN_fs_ops);

        if (rc)
                kmem_cache_destroy(fcb_cache);
out:
        return rc;
}

static void __exit fsfilt_extN_exit(void)
{
        int rc;

        fsfilt_unregister_fs_type("extN");
        rc = kmem_cache_destroy(fcb_cache);

        if (rc || fcb_cache_count) {
                CERROR("can't free fsfilt callback cache: count %d, rc = %d\n",
                       fcb_cache_count, rc);
        }

        //rc = extN_xattr_unregister();
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre extN Filesystem Helper v0.1");
MODULE_LICENSE("GPL");

module_init(fsfilt_extN_init);
module_exit(fsfilt_extN_exit);
