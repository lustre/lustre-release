/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/fsfilt_ext3.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#include <linux/version.h>
/* XXX ugh */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
 #include <linux/ext3_xattr.h>
#else
 #include <linux/../../fs/ext3/xattr.h>
#endif
#include <linux/kp30.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/module.h>

static kmem_cache_t *fcb_cache;
static atomic_t fcb_cache_count = ATOMIC_INIT(0);

struct fsfilt_cb_data {
        struct journal_callback cb_jcb; /* jbd private data - MUST BE FIRST */
        fsfilt_cb_t cb_func;            /* MDS/OBD completion function */
        struct obd_device *cb_obd;      /* MDS/OBD completion device */
        __u64 cb_last_rcvd;             /* MDS/OST last committed operation */
        void *cb_data;                  /* MDS/OST completion function data */
};

#ifndef EXT3_XATTR_INDEX_TRUSTED        /* temporary until we hit l28 kernel */
#define EXT3_XATTR_INDEX_TRUSTED        4
#endif
#define XATTR_LUSTRE_MDS_LOV_EA         "lov"

#define EXT3_XATTR_INDEX_LUSTRE         5                         /* old */
#define XATTR_LUSTRE_MDS_OBJID          "system.lustre_mds_objid" /* old */

/*
 * We don't currently need any additional blocks for rmdir and
 * unlink transactions because we are storing the OST oa_id inside
 * the inode (which we will be changing anyways as part of this
 * transaction).
 */
static void *fsfilt_ext3_start(struct inode *inode, int op, void *desc_private)
{
        /* For updates to the last recieved file */
        int nblocks = EXT3_DATA_TRANS_BLOCKS;
        void *handle;

        if (current->journal_info) {
                CDEBUG(D_INODE, "increasing refcount on %p\n", current->journal_info);
                goto journal_start;
        }

        switch(op) {
        case FSFILT_OP_CREATE_LOG:
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS+EXT3_DATA_TRANS_BLOCKS;
                op = FSFILT_OP_CREATE;
                break;
        case FSFILT_OP_UNLINK_LOG:
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS+EXT3_DATA_TRANS_BLOCKS;
                op = FSFILT_OP_UNLINK;
                break;
        }

        switch(op) {
        case FSFILT_OP_RMDIR:
        case FSFILT_OP_UNLINK:
                nblocks += EXT3_DELETE_TRANS_BLOCKS;
                break;
        case FSFILT_OP_RENAME:
                /* modify additional directory */
                nblocks += EXT3_DATA_TRANS_BLOCKS;
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
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS+EXT3_DATA_TRANS_BLOCKS;
                break;
        case FSFILT_OP_SETATTR:
                /* Setattr on inode */
                nblocks += 1;
                break;
        default: CERROR("unknown transaction start op %d\n", op);
                 LBUG();
        }

        LASSERT(current->journal_info == desc_private);

 journal_start:
        lock_kernel();
        handle = journal_start(EXT3_JOURNAL(inode), nblocks);
        unlock_kernel();

        if (!IS_ERR(handle))
                LASSERT(current->journal_info == handle);
        return handle;
}

/*
 * Calculate the number of buffer credits needed to write multiple pages in
 * a single ext3 transaction.  No, this shouldn't be here, but as yet ext3
 * doesn't have a nice API for calculating this sort of thing in advance.
 *
 * See comment above ext3_writepage_trans_blocks for details.  We assume
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
 * 2 * EXT3_SINGLEDATA_TRANS_BLOCKS for the quota files
 *
 * 1 EXT3_DATA_TRANS_BLOCKS for the last_rcvd update.
 */
static int fsfilt_ext3_credits_needed(int objcount, struct fsfilt_objinfo *fso)
{
        struct super_block *sb = fso->fso_dentry->d_inode->i_sb;
        int blockpp = 1 << (PAGE_CACHE_SHIFT - sb->s_blocksize_bits);
        int addrpp = EXT3_ADDR_PER_BLOCK(sb) * blockpp;
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

        /* Assumes ext3 and ext3 have same sb_info layout at the start. */
        if (nbitmaps > EXT3_SB(sb)->s_groups_count)
                nbitmaps = EXT3_SB(sb)->s_groups_count;
        if (ngdblocks > EXT3_SB(sb)->s_gdb_count)
                ngdblocks = EXT3_SB(sb)->s_gdb_count;

        needed += nbitmaps + ngdblocks;

        /* last_rcvd update */
        needed += EXT3_DATA_TRANS_BLOCKS;

#ifdef CONFIG_QUOTA
        /* We assume that there will be 1 bit set in s_dquot.flags for each
         * quota file that is active.  This is at least true for now.
         */
        needed += hweight32(sb_any_quota_enabled(sb)) *
                EXT3_SINGLEDATA_TRANS_BLOCKS;
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
static void *fsfilt_ext3_brw_start(int objcount, struct fsfilt_objinfo *fso,
                                   int niocount, void *desc_private)
{
        journal_t *journal;
        handle_t *handle;
        int needed;
        ENTRY;

        LASSERT(current->journal_info == desc_private);
        journal = EXT3_SB(fso->fso_dentry->d_inode->i_sb)->s_journal;
        needed = fsfilt_ext3_credits_needed(objcount, fso);

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
        if (IS_ERR(handle)) {
                CERROR("can't get handle for %d credits: rc = %ld\n", needed,
                       PTR_ERR(handle));
        } else {
                LASSERT(handle->h_buffer_credits >= needed);
                LASSERT(current->journal_info == handle);
        }

        RETURN(handle);
}

static int fsfilt_ext3_commit(struct inode *inode, void *h, int force_sync)
{
        int rc;
        handle_t *handle = h;

        LASSERT(current->journal_info == handle);
        if (force_sync)
                handle->h_sync = 1; /* recovery likes this */

        lock_kernel();
        rc = journal_stop(handle);
        unlock_kernel();

        // LASSERT(current->journal_info == NULL);
        return rc;
}

static int fsfilt_ext3_commit_async(struct inode *inode, void *h,
                                        void **wait_handle)
{
        transaction_t *transaction;
        unsigned long tid, rtid;
        handle_t *handle = h;
        journal_t *journal;
        int rc;

        LASSERT(current->journal_info == handle);

        lock_kernel();
        transaction = handle->h_transaction;
        journal = transaction->t_journal;
        tid = transaction->t_tid;
        /* we don't want to be blocked */
        handle->h_sync = 0;
        rc = journal_stop(handle);
        if (rc) {
                CERROR("error while stopping transaction: %d\n", rc);
                unlock_kernel();
                return rc;
        }

        rtid = log_start_commit(journal, transaction);
        if (rtid != tid)
                CERROR("strange race: %lu != %lu\n",
                       (unsigned long) tid, (unsigned long) rtid);
        unlock_kernel();

        *wait_handle = (void *) tid;
        CDEBUG(D_INODE, "commit async: %lu\n", (unsigned long) tid);
        return 0;
}

static int fsfilt_ext3_commit_wait(struct inode *inode, void *h)
{
        tid_t tid = (tid_t) h;

        CDEBUG(D_INODE, "commit wait: %lu\n", (unsigned long) tid);
	if (is_journal_aborted(EXT3_JOURNAL(inode)))
                return -EIO;

        log_wait_commit(EXT3_JOURNAL(inode), tid);

        return 0;
}

static int fsfilt_ext3_setattr(struct dentry *dentry, void *handle,
                               struct iattr *iattr, int do_trunc)
{
        struct inode *inode = dentry->d_inode;
        int rc;

        lock_kernel();

        /* A _really_ horrible hack to avoid removing the data stored
         * in the block pointers; this is really the "small" stripe MD data.
         * We can avoid further hackery by virtue of the MDS file size being
         * zero all the time (which doesn't invoke block truncate at unlink
         * time), so we assert we never change the MDS file size from zero. */
        if (iattr->ia_valid & ATTR_SIZE && !do_trunc) {
                /* ATTR_SIZE would invoke truncate: clear it */
                iattr->ia_valid &= ~ATTR_SIZE;
                EXT3_I(inode)->i_disksize = inode->i_size = iattr->ia_size;

                /* make sure _something_ gets set - so new inode
                 * goes to disk (probably won't work over XFS */
                if (!(iattr->ia_valid & (ATTR_MODE | ATTR_MTIME | ATTR_CTIME))){
                        iattr->ia_valid |= ATTR_MODE;
                        iattr->ia_mode = inode->i_mode;
                }
        }

        /* Don't allow setattr to change file type */
        iattr->ia_mode = (inode->i_mode & S_IFMT)|(iattr->ia_mode & ~S_IFMT);

        /* We set these flags on the client, but have already checked perms
         * so don't confuse inode_change_ok. */
        iattr->ia_valid &= ~(ATTR_MTIME_SET | ATTR_ATIME_SET);

        if (inode->i_op->setattr) {
                rc = inode->i_op->setattr(dentry, iattr);
        } else {
                rc = inode_change_ok(inode, iattr);
                if (!rc)
                        rc = inode_setattr(inode, iattr);
        }

        unlock_kernel();

        return rc;
}

static int fsfilt_ext3_iocontrol(struct inode * inode, struct file *file,
                                 unsigned int cmd, unsigned long arg)
{
        int rc = 0;
        ENTRY;

        if (inode->i_fop->ioctl)
                rc = inode->i_fop->ioctl(inode, file, cmd, arg);
        else
                RETURN(-ENOTTY);

        RETURN(rc);
}

#undef INLINE_EA
#undef OLD_EA
static int fsfilt_ext3_set_md(struct inode *inode, void *handle,
                              void *lmm, int lmm_size)
{
        int rc, old_ea = 0;

#ifdef INLINE_EA  /* can go away before 1.0 - just for testing bug 2097 now */
        /* Nasty hack city - store stripe MD data in the block pointers if
         * it will fit, because putting it in an EA currently kills the MDS
         * performance.  We'll fix this with "fast EAs" in the future.
         */
        if (inode->i_blocks == 0 && lmm_size <= sizeof(EXT3_I(inode)->i_data) -
                                            sizeof(EXT3_I(inode)->i_data[0])) {
                unsigned old_size = EXT3_I(inode)->i_data[0];
                if (old_size != 0) {
                        LASSERT(old_size < sizeof(EXT3_I(inode)->i_data));
                        CERROR("setting EA on %lu/%u again... interesting\n",
                               inode->i_ino, inode->i_generation);
                }

                EXT3_I(inode)->i_data[0] = cpu_to_le32(lmm_size);
                memcpy(&EXT3_I(inode)->i_data[1], lmm, lmm_size);
                mark_inode_dirty(inode);
                return 0;
        }
#endif
#ifdef OLD_EA
        /* keep this when we get rid of OLD_EA (too noisy during conversion) */
        if (EXT3_I(inode)->i_file_acl /* || large inode EA flag */) {
                CWARN("setting EA on %lu/%u again... interesting\n",
                       inode->i_ino, inode->i_generation);
                old_ea = 1;
        }

        lock_kernel();
        /* this can go away before 1.0.  For bug 2097 testing only. */
        rc = ext3_xattr_set_handle(handle, inode, EXT3_XATTR_INDEX_LUSTRE,
                                   XATTR_LUSTRE_MDS_OBJID, lmm, lmm_size, 0);
#else
        lock_kernel();
        rc = ext3_xattr_set_handle(handle, inode, EXT3_XATTR_INDEX_TRUSTED,
                                   XATTR_LUSTRE_MDS_LOV_EA, lmm, lmm_size, 0);

        /* This tries to delete the old-format LOV EA, but only as long as we
         * have successfully saved the new-format LOV EA (we can always try
         * the conversion again the next time the file is accessed).  It is
         * possible (although unlikely) that the new-format LOV EA couldn't be
         * saved because it ran out of space but we would need a file striped
         * over least 123 OSTs before the two EAs filled a 4kB block.
         *
         * This can be removed when all filesystems have converted to the
         * new EA format, but otherwise adds little if any overhead.  If we
         * wanted backward compatibility for existing files, we could keep
         * the old EA around for a while but we'd have to clean it up later. */
        if (rc >= 0 && old_ea) {
                int err = ext3_xattr_set_handle(handle, inode,
                                                EXT3_XATTR_INDEX_LUSTRE,
                                                XATTR_LUSTRE_MDS_OBJID,
                                                NULL, 0, 0);
                if (err)
                        CERROR("error deleting old LOV EA on %lu/%u: rc %d\n",
                               inode->i_ino, inode->i_generation, err);
        }
#endif
        unlock_kernel();

        if (rc)
                CERROR("error adding MD data to inode %lu: rc = %d\n",
                       inode->i_ino, rc);
        return rc;
}

/* Must be called with i_sem held */
static int fsfilt_ext3_get_md(struct inode *inode, void *lmm, int lmm_size)
{
        int rc;

        LASSERT(down_trylock(&inode->i_sem) != 0);
        lock_kernel();
        /* Keep support for reading "inline EAs" until we convert
         * users over to new format entirely.  See bug 841/2097. */
        if (inode->i_blocks == 0 && EXT3_I(inode)->i_data[0]) {
                unsigned size = le32_to_cpu(EXT3_I(inode)->i_data[0]);
                void *handle;

                LASSERT(size < sizeof(EXT3_I(inode)->i_data));
                if (lmm) {
                        if (size > lmm_size) {
                                CERROR("inline EA on %lu/%u bad size %u > %u\n",
                                       inode->i_ino, inode->i_generation,
                                       size, lmm_size);
                                return -ERANGE;
                        }
                        memcpy(lmm, &EXT3_I(inode)->i_data[1], size);
                }

#ifndef INLINE_EA
                /* migrate LOV EA data to external block - keep same format */
                CWARN("DEBUG: migrate inline EA for inode %lu/%u to block\n",
                      inode->i_ino, inode->i_generation);

                handle = journal_start(EXT3_JOURNAL(inode),
                                       EXT3_XATTR_TRANS_BLOCKS);
                if (!IS_ERR(handle)) {
                        int err;
                        rc = fsfilt_ext3_set_md(inode, handle,
                                                &EXT3_I(inode)->i_data[1],size);
                        if (rc == 0) {
                                memset(EXT3_I(inode)->i_data, 0,
                                       sizeof(EXT3_I(inode)->i_data));
                                mark_inode_dirty(inode);
                        }
                        err = journal_stop(handle);
                        if (err && rc == 0)
                                rc = err;
                } else {
                        rc = PTR_ERR(handle);
                }
#endif
                unlock_kernel();
                return size;
        }

        rc = ext3_xattr_get(inode, EXT3_XATTR_INDEX_TRUSTED,
                            XATTR_LUSTRE_MDS_LOV_EA, lmm, lmm_size);
        /* try old EA type if new one failed - MDS will convert it for us */
        if (rc == -ENODATA) {
                CDEBUG(D_INFO,"failed new LOV EA %d/%s from inode %lu: rc %d\n",
                       EXT3_XATTR_INDEX_TRUSTED, XATTR_LUSTRE_MDS_LOV_EA,
                       inode->i_ino, rc);

                rc = ext3_xattr_get(inode, EXT3_XATTR_INDEX_LUSTRE,
                                    XATTR_LUSTRE_MDS_OBJID, lmm, lmm_size);
        }
        unlock_kernel();

        /* This gives us the MD size */
        if (lmm == NULL)
                return (rc == -ENODATA) ? 0 : rc;

        if (rc < 0) {
                CDEBUG(D_INFO, "error getting EA %d/%s from inode %lu: rc %d\n",
                       EXT3_XATTR_INDEX_LUSTRE, XATTR_LUSTRE_MDS_OBJID,
                       inode->i_ino, rc);
                memset(lmm, 0, lmm_size);
                return (rc == -ENODATA) ? 0 : rc;
        }

        return rc;
}

static ssize_t fsfilt_ext3_readpage(struct file *file, char *buf, size_t count,
                                    loff_t *off)
{
        struct inode *inode = file->f_dentry->d_inode;
        int rc = 0;

        if (S_ISREG(inode->i_mode))
                rc = file->f_op->read(file, buf, count, off);
        else {
                const int blkbits = inode->i_sb->s_blocksize_bits;
                const int blksize = inode->i_sb->s_blocksize;

                CDEBUG(D_EXT2, "reading "LPSZ" at dir %lu+%llu\n",
                       count, inode->i_ino, *off);
                while (count > 0) {
                        struct buffer_head *bh;

                        bh = NULL;
                        if (*off < inode->i_size) {
                                int err = 0;

                                bh = ext3_bread(NULL, inode, *off >> blkbits,
                                                0, &err);

                                CDEBUG(D_EXT2, "read %u@%llu\n", blksize, *off);

                                if (bh) {
                                        memcpy(buf, bh->b_data, blksize);
                                        brelse(bh);
                                } else if (err) {
                                        /* XXX in theory we should just fake
                                         * this buffer and continue like ext3,
                                         * especially if this is a partial read
                                         */
                                        CERROR("error read dir %lu+%llu: %d\n",
                                               inode->i_ino, *off, err);
                                        RETURN(err);
                                }
                        }
                        if (!bh) {
                                struct ext3_dir_entry_2 *fake = (void *)buf;

                                CDEBUG(D_EXT2, "fake %u@%llu\n", blksize, *off);
                                memset(fake, 0, sizeof(*fake));
                                fake->rec_len = cpu_to_le32(blksize);
                        }
                        count -= blksize;
                        buf += blksize;
                        *off += blksize;
                        rc += blksize;
                }
        }

        return rc;
}

static void fsfilt_ext3_cb_func(struct journal_callback *jcb, int error)
{
        struct fsfilt_cb_data *fcb = (struct fsfilt_cb_data *)jcb;

        fcb->cb_func(fcb->cb_obd, fcb->cb_last_rcvd, fcb->cb_data, error);

        OBD_SLAB_FREE(fcb, fcb_cache, sizeof *fcb);
        atomic_dec(&fcb_cache_count);
}

static int fsfilt_ext3_add_journal_cb(struct obd_device *obd, __u64 last_rcvd,
                                      void *handle, fsfilt_cb_t cb_func,
                                      void *cb_data)
{
        struct fsfilt_cb_data *fcb;

        OBD_SLAB_ALLOC(fcb, fcb_cache, GFP_NOFS, sizeof *fcb);
        if (fcb == NULL)
                RETURN(-ENOMEM);

        atomic_inc(&fcb_cache_count);
        fcb->cb_func = cb_func;
        fcb->cb_obd = obd;
        fcb->cb_last_rcvd = last_rcvd;
        fcb->cb_data = cb_data;

        CDEBUG(D_EXT2, "set callback for last_rcvd: "LPD64"\n", last_rcvd);
        lock_kernel();
        journal_callback_set(handle, fsfilt_ext3_cb_func,
                             (struct journal_callback *)fcb);
        unlock_kernel();

        return 0;
}

/*
 * We need to hack the return value for the free inode counts because
 * the current EA code requires one filesystem block per inode with EAs,
 * so it is possible to run out of blocks before we run out of inodes.
 *
 * This can be removed when the ext3 EA code is fixed.
 */
static int fsfilt_ext3_statfs(struct super_block *sb, struct obd_statfs *osfs)
{
        struct kstatfs sfs;
        int rc = vfs_statfs(sb, &sfs);

        if (!rc && sfs.f_bfree < sfs.f_ffree) {
                sfs.f_files = (sfs.f_files - sfs.f_ffree) + sfs.f_bfree;
                sfs.f_ffree = sfs.f_bfree;
        }

        statfs_pack(osfs, &sfs);
        return rc;
}

static int fsfilt_ext3_sync(struct super_block *sb)
{
        return ext3_force_commit(sb);
}

extern int ext3_prep_san_write(struct inode *inode, long *blocks,
                               int nblocks, loff_t newsize);
static int fsfilt_ext3_prep_san_write(struct inode *inode, long *blocks,
                                      int nblocks, loff_t newsize)
{
        return ext3_prep_san_write(inode, blocks, nblocks, newsize);
}

static int fsfilt_ext3_read_record(struct file * file, void *buf,
                                   int size, loff_t *offs)
{
        struct buffer_head *bh;
        unsigned long block, boffs;
        struct inode *inode = file->f_dentry->d_inode;
        int err;

        if (inode->i_size < *offs + size) {
                size = inode->i_size - *offs;
                if (size < 0) {
                        CERROR("size %llu is too short for read %u@%llu\n",
                                        inode->i_size, size, *offs);
                        return -EIO;
                } else if (size == 0)
                        return 0;
        }

        block = *offs >> inode->i_blkbits;
        bh = ext3_bread(NULL, inode, block, 0, &err);
        if (!bh) {
                CERROR("can't read block: %d\n", err);
                return err;
        }

        boffs = (unsigned)*offs % bh->b_size;
        if (boffs + size > bh->b_size) {
                CERROR("request crosses block's border. offset %llu, size %u\n",
                       *offs, size);
                brelse(bh);
                return -EIO;
        }

        memcpy(buf, bh->b_data + boffs, size);
        brelse(bh);
        *offs += size;
        return 0;
}

static int fsfilt_ext3_write_record(struct file *file, void *buf, int size,
                                    loff_t *offs, int force_sync)
{
        struct buffer_head *bh;
        unsigned long block, boffs;
        struct inode *inode = file->f_dentry->d_inode;
        loff_t old_size = inode->i_size;
        journal_t *journal;
        handle_t *handle;
        int err;

        journal = EXT3_SB(inode->i_sb)->s_journal;
        handle = journal_start(journal, EXT3_DATA_TRANS_BLOCKS + 2);
        if (IS_ERR(handle)) {
                CERROR("can't start transaction\n");
                return PTR_ERR(handle);
        }

        block = *offs >> inode->i_blkbits;
        if (*offs + size > inode->i_size) {
                down(&inode->i_sem);
                if (*offs + size > inode->i_size)
                        inode->i_size = *offs + size;
                if (inode->i_size > EXT3_I(inode)->i_disksize)
                        EXT3_I(inode)->i_disksize = inode->i_size;
                up(&inode->i_sem);
        }

        bh = ext3_bread(handle, inode, block, 1, &err);
        if (!bh) {
                CERROR("can't read/create block: %d\n", err);
                goto out;
        }

        /* This is a hack only needed because ext3_get_block_handle() updates
         * i_disksize after marking the inode dirty in ext3_splice_branch().
         * We will fix that when we get a chance, as ext3_mark_inode_dirty()
         * is not without cost, nor is it even exported.
         */
        if (inode->i_size > old_size)
                mark_inode_dirty(inode);

        boffs = (unsigned)*offs % bh->b_size;
        if (boffs + size > bh->b_size) {
                CERROR("request crosses block's border. offset %llu, size %u\n",
                       *offs, size);
                err = -EIO;
                goto out;
        }

        err = ext3_journal_get_write_access(handle, bh);
        if (err) {
                CERROR("journal_get_write_access() returned error %d\n", err);
                goto out;
        }
        memcpy(bh->b_data + boffs, buf, size);
        err = ext3_journal_dirty_metadata(handle, bh);
        if (err) {
                CERROR("journal_dirty_metadata() returned error %d\n", err);
                goto out;
        }

        if (force_sync)
                handle->h_sync = 1; /* recovery likes this */
out:
        if (bh)
                brelse(bh);
        journal_stop(handle);
        if (err == 0)
                *offs += size;
        return err;
}

static int fsfilt_ext3_setup(struct super_block *sb)
{
#if 0
        EXT3_SB(sb)->dx_lock = fsfilt_ext3_dx_lock;
        EXT3_SB(sb)->dx_unlock = fsfilt_ext3_dx_unlock;
#endif
#ifdef S_PDIROPS
        CERROR("Enabling PDIROPS\n");
        set_opt(EXT3_SB(sb)->s_mount_opt, PDIROPS);
        sb->s_flags |= S_PDIROPS;
#endif
        return 0;
}

static struct fsfilt_operations fsfilt_ext3_ops = {
        fs_type:                "ext3",
        fs_owner:               THIS_MODULE,
        fs_start:               fsfilt_ext3_start,
        fs_brw_start:           fsfilt_ext3_brw_start,
        fs_commit:              fsfilt_ext3_commit,
        fs_commit_async:        fsfilt_ext3_commit_async,
        fs_commit_wait:         fsfilt_ext3_commit_wait,
        fs_setattr:             fsfilt_ext3_setattr,
        fs_iocontrol:           fsfilt_ext3_iocontrol,
        fs_set_md:              fsfilt_ext3_set_md,
        fs_get_md:              fsfilt_ext3_get_md,
        fs_readpage:            fsfilt_ext3_readpage,
        fs_add_journal_cb:      fsfilt_ext3_add_journal_cb,
        fs_statfs:              fsfilt_ext3_statfs,
        fs_sync:                fsfilt_ext3_sync,
        fs_prep_san_write:      fsfilt_ext3_prep_san_write,
        fs_write_record:        fsfilt_ext3_write_record,
        fs_read_record:         fsfilt_ext3_read_record,
        fs_setup:               fsfilt_ext3_setup,
};

static int __init fsfilt_ext3_init(void)
{
        int rc;

        //rc = ext3_xattr_register();
        fcb_cache = kmem_cache_create("fsfilt_ext3_fcb",
                                      sizeof(struct fsfilt_cb_data), 0,
                                      0, NULL, NULL);
        if (!fcb_cache) {
                CERROR("error allocating fsfilt journal callback cache\n");
                GOTO(out, rc = -ENOMEM);
        }

        rc = fsfilt_register_ops(&fsfilt_ext3_ops);

        if (rc)
                kmem_cache_destroy(fcb_cache);
out:
        return rc;
}

static void __exit fsfilt_ext3_exit(void)
{
        int rc;

        fsfilt_unregister_ops(&fsfilt_ext3_ops);
        rc = kmem_cache_destroy(fcb_cache);

        if (rc || atomic_read(&fcb_cache_count)) {
                CERROR("can't free fsfilt callback cache: count %d, rc = %d\n",
                       atomic_read(&fcb_cache_count), rc);
        }

        //rc = ext3_xattr_unregister();
}

module_init(fsfilt_ext3_init);
module_exit(fsfilt_ext3_exit);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre ext3 Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
