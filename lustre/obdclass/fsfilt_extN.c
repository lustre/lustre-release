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
#include <linux/pagemap.h>
#include <linux/quotaops.h>
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
                /* modify additional directory */
                nblocks += EXTN_DATA_TRANS_BLOCKS;
                /* no break */
        case FSFILT_OP_SYMLINK:
                /* additional block + block bitmap + GDT for long symlink */
                nblocks += 3;
                /* no break */
        case FSFILT_OP_CREATE:
        case FSFILT_OP_MKDIR:
        case FSFILT_OP_MKNOD:
                /* modify one inode + block bitmap + GDT */
                nblocks += 3;
                /* no break */
        case FSFILT_OP_LINK:
                /* modify parent directory */
                nblocks += EXTN_INDEX_EXTRA_TRANS_BLOCKS+EXTN_DATA_TRANS_BLOCKS;
                break;
        case FSFILT_OP_SETATTR:
                /* Setattr on inode */
                nblocks += 1;
                break;
        default: CERROR("unknown transaction start op %d\n", op);
                 LBUG();
        }

        LASSERT(!current->journal_info);
        lock_kernel();
        handle = journal_start(EXTN_JOURNAL(inode), nblocks);
        unlock_kernel();

        return handle;
}

/*
 * Calculate the number of buffer credits needed to write multiple pages in
 * a single extN transaction.  No, this shouldn't be here, but as yet extN
 * doesn't have a nice API for calculating this sort of thing in advance.
 *
 * See comment above extN_writepage_trans_blocks for details.  We assume
 * no data journaling is being done, but it does allow for all of the pages
 * being non-contiguous.  If we are guaranteed contiguous pages we could
 * reduce the number of (d)indirect blocks a lot.
 *
 * With N blocks per page and P pages, for each inode we have at most:
 * N*P indirect
 * min(N*P, blocksize/4 + 1) dindirect blocks
 * niocount tindirect
 *
 * For the entire filesystem, we have at most:
 * min(sum(nindir + P), ngroups) bitmap blocks (from the above)
 * min(sum(nindir + P), gdblocks) group descriptor blocks (from the above)
 * objcount inode blocks
 * 1 superblock
 * 2 * EXTN_SINGLEDATA_TRANS_BLOCKS for the quota files
 */
static int fsfilt_extN_credits_needed(int objcount, struct fsfilt_objinfo *fso)
{
        struct super_block *sb = fso->fso_dentry->d_inode->i_sb;
        int blockpp = 1 << (PAGE_CACHE_SHIFT - sb->s_blocksize_bits);
        int addrpp = EXTN_ADDR_PER_BLOCK(sb) * blockpp;
        int nbitmaps = 0;
        int ngdblocks = 0;
        int needed = objcount + 1;
        int i;

        for (i = 0; i < objcount; i++, fso++) {
                int nblocks = fso->fso_bufcnt * blockpp;
                int ndindirect = min(nblocks, addrpp + 1);
                int nindir = nblocks + ndindirect + 1;

                nbitmaps += nindir + nblocks;
                ngdblocks += nindir + nblocks;

                needed += nindir;
        }

        /* Assumes extN and extN have same sb_info layout at the start. */
        if (nbitmaps > EXTN_SB(sb)->s_groups_count)
                nbitmaps = EXTN_SB(sb)->s_groups_count;
        if (ngdblocks > EXTN_SB(sb)->s_gdb_count)
                ngdblocks = EXTN_SB(sb)->s_gdb_count;

        needed += nbitmaps + ngdblocks;

#ifdef CONFIG_QUOTA
        /* We assume that there will be 1 bit set in s_dquot.flags for each
         * quota file that is active.  This is at least true for now.
         */
        needed += hweight32(sb_any_quota_enabled(sb)) *
                EXTN_SINGLEDATA_TRANS_BLOCKS;
#endif

        return needed;
}

/* We have to start a huge journal transaction here to hold all of the
 * metadata for the pages being written here.  This is necessitated by
 * the fact that we do lots of prepare_write operations before we do
 * any of the matching commit_write operations, so even if we split
 * up to use "smaller" transactions none of them could complete until
 * all of them were opened.  By having a single journal transaction,
 * we eliminate duplicate reservations for common blocks like the
 * superblock and group descriptors or bitmaps.
 *
 * We will start the transaction here, but each prepare_write will
 * add a refcount to the transaction, and each commit_write will
 * remove a refcount.  The transaction will be closed when all of
 * the pages have been written.
 */
static void *fsfilt_extN_brw_start(int objcount, struct fsfilt_objinfo *fso,
                                   int niocount, struct niobuf_remote *nb)
{
        journal_t *journal;
        handle_t *handle;
        int needed;
        ENTRY;

        LASSERT(!current->journal_info);
        journal = EXTN_SB(fso->fso_dentry->d_inode->i_sb)->s_journal;
        needed = fsfilt_extN_credits_needed(objcount, fso);

        /* The number of blocks we could _possibly_ dirty can very large.
         * We reduce our request if it is absurd (and we couldn't get that
         * many credits for a single handle anyways).
         *
         * At some point we have to limit the size of I/Os sent at one time,
         * increase the size of the journal, or we have to calculate the
         * actual journal requirements more carefully by checking all of
         * the blocks instead of being maximally pessimistic.  It remains to
         * be seen if this is a real problem or not.
         */
        if (needed > journal->j_max_transaction_buffers) {
                CERROR("want too many journal credits (%d) using %d instead\n",
                       needed, journal->j_max_transaction_buffers);
                needed = journal->j_max_transaction_buffers;
        }

        lock_kernel();
        handle = journal_start(journal, needed);
        unlock_kernel();
        if (IS_ERR(handle))
                CERROR("can't get handle for %d credits: rc = %ld\n", needed,
                       PTR_ERR(handle));

        RETURN(handle);
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

        /* A _really_ horrible hack to avoid removing the data stored
         * in the block pointers; this is really the "small" stripe MD data.
         * We can avoid further hackery by virtue of the MDS file size being
         * zero all the time (which doesn't invoke block truncate at unlink
         * time), so we assert we never change the MDS file size from zero.
         */
        if (iattr->ia_valid & ATTR_SIZE) {
                CERROR("hmm, setting %*s file size to "LPU64"\n",
                       dentry->d_name.len, dentry->d_name.name, iattr->ia_size);
                LASSERT(iattr->ia_size == 0);
#if 0
                /* ATTR_SIZE would invoke truncate: clear it */
                iattr->ia_valid &= ~ATTR_SIZE;
                inode->i_size = iattr->ia_size;

                /* make sure _something_ gets set - so new inode
                 * goes to disk (probably won't work over XFS
                 */
                if (!iattr->ia_valid & ATTR_MODE) {
                        iattr->ia_valid |= ATTR_MODE;
                        iattr->ia_mode = inode->i_mode;
                }
#endif
        }
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

        /* Nasty hack city - store stripe MD data in the block pointers if
         * it will fit, because putting it in an EA currently kills the MDS
         * performance.  We'll fix this with "fast EAs" in the future.
         */
        if (lmm_size <= sizeof(EXTN_I(inode)->i_data) -
                        sizeof(EXTN_I(inode)->i_data[0])) {
                /* XXX old_size is debugging only */
                int old_size = EXTN_I(inode)->i_data[0];
                if (old_size != 0) {
                        LASSERT(old_size < sizeof(EXTN_I(inode)->i_data));
                        CERROR("setting EA on %lu again... interesting\n",
                               inode->i_ino);
                }

                EXTN_I(inode)->i_data[0] = cpu_to_le32(lmm_size);
                memcpy(&EXTN_I(inode)->i_data[1], lmm, lmm_size);
                mark_inode_dirty(inode);
                return 0;
        } else {
                down(&inode->i_sem);
                lock_kernel();
                rc = extN_xattr_set(handle, inode, EXTN_XATTR_INDEX_LUSTRE,
                                    XATTR_LUSTRE_MDS_OBJID, lmm, lmm_size, 0);
                unlock_kernel();
                up(&inode->i_sem);
        }

        if (rc)
                CERROR("error adding MD data to inode %lu: rc = %d\n",
                       inode->i_ino, rc);
        return rc;
}

static int fsfilt_extN_get_md(struct inode *inode, void *lmm, int lmm_size)
{
        int rc;

        if (EXTN_I(inode)->i_data[0]) {
                int size = le32_to_cpu(EXTN_I(inode)->i_data[0]);
                LASSERT(size < sizeof(EXTN_I(inode)->i_data));
                if (lmm) {
                        if (size > lmm_size)
                                return -ERANGE;
                        memcpy(lmm, &EXTN_I(inode)->i_data[1], size);
                }
                return size;
        }

        down(&inode->i_sem);
        lock_kernel();
        rc = extN_xattr_get(inode, EXTN_XATTR_INDEX_LUSTRE,
                            XATTR_LUSTRE_MDS_OBJID, lmm, lmm_size);
        unlock_kernel();
        up(&inode->i_sem);

        /* This gives us the MD size */
        if (lmm == NULL)
                return (rc == -ENODATA) ? 0 : rc;

        if (rc < 0) {
                CDEBUG(D_INFO, "error getting EA %s from inode %lu: "
                       "rc = %d\n", XATTR_LUSTRE_MDS_OBJID, inode->i_ino, rc);
                memset(lmm, 0, lmm_size);
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
static int fsfilt_extN_statfs(struct super_block *sb, struct obd_statfs *osfs)
{
        struct statfs sfs;
        int rc = vfs_statfs(sb, &sfs);

        if (!rc && sfs.f_bfree < sfs.f_ffree)
                sfs.f_ffree = sfs.f_bfree;

        statfs_pack(osfs, &sfs);
        return rc;
}

static struct fsfilt_operations fsfilt_extN_ops = {
        fs_type:                "extN",
        fs_owner:               THIS_MODULE,
        fs_start:               fsfilt_extN_start,
        fs_brw_start:           fsfilt_extN_brw_start,
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

        rc = fsfilt_register_ops(&fsfilt_extN_ops);

        if (rc)
                kmem_cache_destroy(fcb_cache);
out:
        return rc;
}

static void __exit fsfilt_extN_exit(void)
{
        int rc;

        fsfilt_unregister_ops(&fsfilt_extN_ops);
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
