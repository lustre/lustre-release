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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#include <linux/ext3_extents.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/ext3_xattr.h>
#else
#include <ext3/xattr.h>
#endif

#include <libcfs/kp30.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/module.h>
#include <linux/iobuf.h>
#endif


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7))
# define lock_24kernel() lock_kernel()
# define unlock_24kernel() unlock_kernel()
#else
# define lock_24kernel() do {} while (0)
# define unlock_24kernel() do {} while (0)
#endif

static kmem_cache_t *fcb_cache;
static atomic_t fcb_cache_count = ATOMIC_INIT(0);

struct fsfilt_cb_data {
        struct journal_callback cb_jcb; /* jbd private data - MUST BE FIRST */
        fsfilt_cb_t cb_func;            /* MDS/OBD completion function */
        struct obd_device *cb_obd;      /* MDS/OBD completion device */
        __u64 cb_last_num;              /* MDS/OST last committed operation */
        void *cb_data;                  /* MDS/OST completion function data */
};

#ifndef EXT3_XATTR_INDEX_TRUSTED        /* temporary until we hit l28 kernel */
#define EXT3_XATTR_INDEX_TRUSTED        4
#endif

#define XATTR_LUSTRE_MDS_LOV_EA         "lov"
#define XATTR_LUSTRE_MDS_MEA_EA         "mea"
#define XATTR_LUSTRE_MDS_MID_EA         "mid"
#define XATTR_LUSTRE_MDS_SID_EA         "sid"

/*
 * We don't currently need any additional blocks for rmdir and
 * unlink transactions because we are storing the OST oa_id inside
 * the inode (which we will be changing anyways as part of this
 * transaction).
 */
static void *fsfilt_ext3_start(struct inode *inode, int op, void *desc_private,
                               int logs)
{
        /* For updates to the last recieved file */
        int nblocks = EXT3_SINGLEDATA_TRANS_BLOCKS;
        journal_t *journal;
        void *handle;

        if (current->journal_info) {
                CDEBUG(D_INODE, "increasing refcount on %p\n",
                       current->journal_info);
                goto journal_start;
        }

	if (logs)
		nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            EXT3_SINGLEDATA_TRANS_BLOCKS) * logs;
                
        switch(op) {
        case FSFILT_OP_RMDIR:
        case FSFILT_OP_UNLINK:
                /* delete one file + create/update logs for each stripe */
                nblocks += EXT3_DELETE_TRANS_BLOCKS;
                /*nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            EXT3_SINGLEDATA_TRANS_BLOCKS) * logs;*/
                break;
        case FSFILT_OP_RENAME:
                /* modify additional directory */
                nblocks += EXT3_SINGLEDATA_TRANS_BLOCKS;
                /* no break */
        case FSFILT_OP_SYMLINK:
                /* additional block + block bitmap + GDT for long symlink */
                nblocks += 3;
                /* no break */
        case FSFILT_OP_CREATE:
                /* create/update logs for each stripe */
                /*nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            EXT3_SINGLEDATA_TRANS_BLOCKS) * logs;*/
                /* no break */
        case FSFILT_OP_MKDIR:
        case FSFILT_OP_MKNOD:
                /* modify one inode + block bitmap + GDT */
                nblocks += 3;
                /* no break */
        case FSFILT_OP_LINK:
                /* modify parent directory */
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                        EXT3_DATA_TRANS_BLOCKS;
                break;
        case FSFILT_OP_SETATTR:
                /* Setattr on inode */
                nblocks += 1;
                break;
        case FSFILT_OP_CANCEL_UNLINK:
                /* blocks for log header bitmap update OR
                 * blocks for catalog header bitmap update + unlink of logs */
                nblocks = (LLOG_CHUNK_SIZE >> inode->i_blkbits) +
                        EXT3_DELETE_TRANS_BLOCKS * logs;
                break;
        case FSFILT_OP_NOOP:
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS+EXT3_DATA_TRANS_BLOCKS;
                break;
        default: CERROR("unknown transaction start op %d\n", op);
                LBUG();
        }

        LASSERT(current->journal_info == desc_private);
        journal = EXT3_SB(inode->i_sb)->s_journal;
        if (nblocks > journal->j_max_transaction_buffers) {
                CERROR("too many credits %d for op %ux%u using %d instead\n",
                       nblocks, op, logs, journal->j_max_transaction_buffers);
                nblocks = journal->j_max_transaction_buffers;
        }

 journal_start:
        LASSERTF(nblocks > 0, "can't start %d credit transaction\n", nblocks);
        lock_24kernel();
        handle = journal_start(EXT3_JOURNAL(inode), nblocks);
        unlock_24kernel();

        if (!IS_ERR(handle))
                LASSERT(current->journal_info == handle);
        else
                CERROR("error starting handle for op %u (%u credits): rc %ld\n",
                       op, nblocks, PTR_ERR(handle));
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
static int fsfilt_ext3_credits_needed(int objcount, struct fsfilt_objinfo *fso,
                                      int niocount, struct niobuf_local *nb)
{
        struct super_block *sb = fso->fso_dentry->d_inode->i_sb;
        __u64 next_indir;
        const int blockpp = 1 << (PAGE_CACHE_SHIFT - sb->s_blocksize_bits);
        int nbitmaps = 0, ngdblocks;
        int needed = objcount + 1; /* inodes + superblock */
        int i, j;

        for (i = 0, j = 0; i < objcount; i++, fso++) {
                /* two or more dindirect blocks in case we cross boundary */
                int ndind = (long)((nb[j + fso->fso_bufcnt - 1].offset -
                                    nb[j].offset) >>
                                   sb->s_blocksize_bits) /
                        (EXT3_ADDR_PER_BLOCK(sb) * EXT3_ADDR_PER_BLOCK(sb));
                nbitmaps += min(fso->fso_bufcnt, ndind > 0 ? ndind : 2);

                /* leaf, indirect, tindirect blocks for first block */
                nbitmaps += blockpp + 2;

                j += fso->fso_bufcnt;
        }

        next_indir = nb[0].offset +
                (EXT3_ADDR_PER_BLOCK(sb) << sb->s_blocksize_bits);
        for (i = 1; i < niocount; i++) {
                if (nb[i].offset >= next_indir) {
                        nbitmaps++;     /* additional indirect */
                        next_indir = nb[i].offset +
                                (EXT3_ADDR_PER_BLOCK(sb)<<sb->s_blocksize_bits);
                } else if (nb[i].offset != nb[i - 1].offset + sb->s_blocksize) {
                        nbitmaps++;     /* additional indirect */
                }
                nbitmaps += blockpp;    /* each leaf in different group? */
        }

        ngdblocks = nbitmaps;
        if (nbitmaps > EXT3_SB(sb)->s_groups_count)
                nbitmaps = EXT3_SB(sb)->s_groups_count;
        if (ngdblocks > EXT3_SB(sb)->s_gdb_count)
                ngdblocks = EXT3_SB(sb)->s_gdb_count;

        needed += nbitmaps + ngdblocks;

        /* last_rcvd update */
        needed += EXT3_DATA_TRANS_BLOCKS;

#if defined(CONFIG_QUOTA) && !defined(__x86_64__) /* XXX */
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
                                   int niocount, struct niobuf_local *nb,
                                   void *desc_private, int logs)
{
        journal_t *journal;
        handle_t *handle;
        int needed;
        ENTRY;

        LASSERT(current->journal_info == desc_private);
        journal = EXT3_SB(fso->fso_dentry->d_inode->i_sb)->s_journal;
        needed = fsfilt_ext3_credits_needed(objcount, fso, niocount, nb);

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

        LASSERTF(needed > 0, "can't start %d credit transaction\n", needed);
        lock_24kernel();
        handle = journal_start(journal, needed);
        unlock_24kernel();
        if (IS_ERR(handle)) {
                CERROR("can't get handle for %d credits: rc = %ld\n", needed,
                       PTR_ERR(handle));
        } else {
                LASSERT(handle->h_buffer_credits >= needed);
                LASSERT(current->journal_info == handle);
        }

        RETURN(handle);
}

static int fsfilt_ext3_commit(struct super_block *sb, struct inode *inode, 
                              void *h, int force_sync)
{
        int rc;
        handle_t *handle = h;

        LASSERT(current->journal_info == handle);
        if (force_sync)
                handle->h_sync = 1; /* recovery likes this */

        lock_24kernel();
        rc = journal_stop(handle);
        unlock_24kernel();

        return rc;
}

static int fsfilt_ext3_commit_async(struct inode *inode, void *h,
                                    void **wait_handle)
{
        unsigned long tid;
        transaction_t *transaction;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
        unsigned long rtid;
#endif
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
        rtid = log_start_commit(journal, transaction);
        if (rtid != tid)
                CERROR("strange race: %lu != %lu\n",
                       (unsigned long) tid, (unsigned long) rtid);
#else
        log_start_commit(journal, transaction->t_tid);
#endif
        unlock_kernel();

        *wait_handle = (void *) tid;
        CDEBUG(D_INODE, "commit async: %lu\n", (unsigned long) tid);
        return 0;
}

static int fsfilt_ext3_commit_wait(struct inode *inode, void *h)
{
        tid_t tid = (tid_t)(long)h;

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

static int fsfilt_ext3_set_xattr(struct inode * inode, void *handle, char *name,
                                 void *buffer, int buffer_size)
{
        int rc = 0;

        lock_kernel();

        rc = ext3_xattr_set_handle(handle, inode, EXT3_XATTR_INDEX_TRUSTED,
                                   name, buffer, buffer_size, 0);
        unlock_kernel();
        if (rc)
                CERROR("set xattr %s from inode %lu: rc %d\n",
                       name,  inode->i_ino, rc);
        return rc;
}

static int fsfilt_ext3_get_xattr(struct inode *inode, char *name,
                                 void *buffer, int buffer_size)
{
        int rc = 0;
       
        lock_kernel();

        rc = ext3_xattr_get(inode, EXT3_XATTR_INDEX_TRUSTED,
                            name, buffer, buffer_size);
        unlock_kernel();

        if (buffer == NULL)
                return (rc == -ENODATA) ? 0 : rc;
        if (rc < 0) {
                CDEBUG(D_INFO, "error getting EA %s from inode %lu: rc %d\n",
                       name,  inode->i_ino, rc);
                memset(buffer, 0, buffer_size);
                return (rc == -ENODATA) ? 0 : rc;
        }

        return rc;
}

static int fsfilt_ext3_set_md(struct inode *inode, void *handle,
                              void *lmm, int lmm_size,
                              enum ea_type type)
{
        int rc;
        
        switch(type) {
        case EA_LOV:
                rc = fsfilt_ext3_set_xattr(inode, handle,
                                           XATTR_LUSTRE_MDS_LOV_EA,
                                           lmm, lmm_size);
                break;
        case EA_MEA:
                rc = fsfilt_ext3_set_xattr(inode, handle,
                                           XATTR_LUSTRE_MDS_MEA_EA,
                                           lmm, lmm_size);
                break;
        case EA_SID:
                rc = fsfilt_ext3_set_xattr(inode, handle,
                                           XATTR_LUSTRE_MDS_SID_EA,
                                           lmm, lmm_size);
                break;
        case EA_MID:
                rc = fsfilt_ext3_set_xattr(inode, handle,
                                           XATTR_LUSTRE_MDS_MID_EA,
                                           lmm, lmm_size);
                break;
        default:
                return -EINVAL;
        }

        return rc;
}

static int fsfilt_ext3_get_md(struct inode *inode, void *lmm,
                              int lmm_size, enum ea_type type)
{
        int rc;
        
        switch (type) {
        case EA_LOV:
                rc = fsfilt_ext3_get_xattr(inode,
                                           XATTR_LUSTRE_MDS_LOV_EA,
                                           lmm, lmm_size);
                break;
        case EA_MEA:
                rc = fsfilt_ext3_get_xattr(inode,
                                           XATTR_LUSTRE_MDS_MEA_EA,
                                           lmm, lmm_size);
                break;
        case EA_SID:
                rc = fsfilt_ext3_get_xattr(inode,
                                           XATTR_LUSTRE_MDS_SID_EA,
                                           lmm, lmm_size);
                break;
        case EA_MID:
                rc = fsfilt_ext3_get_xattr(inode,
                                           XATTR_LUSTRE_MDS_MID_EA,
                                           lmm, lmm_size);
                break;
        default:
                return -EINVAL;
        }
        
        return rc;
}

static int fsfilt_ext3_send_bio(int rw, struct inode *inode, void *bio)
{
	int rc = 0;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        submit_bio(rw, (struct bio *)bio);
#else
	struct bio *b = (struct kiobuf *)bio;
        int blocks_per_page;
	
        rc = brw_kiovec(rw, 1, &b, inode->i_dev,
                        b->blocks, 1 << inode->i_blkbits);

        blocks_per_page = PAGE_SIZE >> inode->i_blkbits;

        if (rc != (1 << inode->i_blkbits) * b->nr_pages * blocks_per_page) {
                CERROR("short write?  expected %d, wrote %d\n",
                       (1 << inode->i_blkbits) * b->nr_pages *
                       blocks_per_page, rc);
        }
#endif
        return rc;
}

static struct page *fsfilt_ext3_getpage(struct inode *inode, long int index)
{
        int rc;
        struct page *page;

        page = grab_cache_page(inode->i_mapping, index);
        if (page == NULL)
                return ERR_PTR(-ENOMEM);

        if (PageUptodate(page)) {
                unlock_page(page);
                return page;
        }

        rc = inode->i_mapping->a_ops->readpage(NULL, page);
        if (rc < 0) {
                page_cache_release(page);
                return ERR_PTR(rc);
        }

        return page;
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

        fcb->cb_func(fcb->cb_obd, fcb->cb_last_num, fcb->cb_data, error);

        OBD_SLAB_FREE(fcb, fcb_cache, sizeof *fcb);
        atomic_dec(&fcb_cache_count);
}

static int fsfilt_ext3_add_journal_cb(struct obd_device *obd,
                                      struct super_block *sb,
                                      __u64 last_num, void *handle,
                                      fsfilt_cb_t cb_func,
                                      void *cb_data)
{
        struct fsfilt_cb_data *fcb;

        OBD_SLAB_ALLOC(fcb, fcb_cache, GFP_NOFS, sizeof *fcb);
        if (fcb == NULL)
                RETURN(-ENOMEM);

        atomic_inc(&fcb_cache_count);
        fcb->cb_func = cb_func;
        fcb->cb_obd = obd;
        fcb->cb_last_num = last_num;
        fcb->cb_data = cb_data;

        CDEBUG(D_EXT2, "set callback for last_num: "LPD64"\n", last_num);
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
        int rc;

        memset(&sfs, 0, sizeof(sfs));

        rc = sb->s_op->statfs(sb, &sfs);

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

#ifdef EXT3_MULTIBLOCK_ALLOCATOR
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define ext3_up_truncate_sem(inode)  up_write(&EXT3_I(inode)->truncate_sem);
#define ext3_down_truncate_sem(inode)  down_write(&EXT3_I(inode)->truncate_sem);
#else
#define ext3_up_truncate_sem(inode)  up(&EXT3_I(inode)->truncate_sem);
#define ext3_down_truncate_sem(inode)  down(&EXT3_I(inode)->truncate_sem);
#endif

#include <linux/lustre_version.h>
#if EXT3_EXT_MAGIC == 0xf301
#define ee_start e_start
#define ee_block e_block
#define ee_len   e_num
#endif
#ifndef EXT3_BB_MAX_BLOCKS
#define ext3_mb_new_blocks(handle, inode, goal, count, aflags, err) \
        ext3_new_blocks(handle, inode, count, goal, err)
#endif

struct bpointers {
        unsigned long *blocks;
        int *created;
        unsigned long start;
        int num;
        int init_num;
        int create;
};
static int ext3_ext_find_goal(struct inode *inode, struct ext3_ext_path *path,
                                unsigned long block, int *aflags)
{
        struct ext3_inode_info *ei = EXT3_I(inode);
        unsigned long bg_start;
        unsigned long colour;
        int depth;
                                                                                                                                                                                                     
        if (path) {
                struct ext3_extent *ex;
                depth = path->p_depth;
                                                                                                                                                                                                     
                /* try to predict block placement */
                if ((ex = path[depth].p_ext)) {
                        if (ex->ee_block + ex->ee_len == block)
                                *aflags |= 1;
                        return ex->ee_start + (block - ex->ee_block);
                }
                                                                                                                                                                                                     
                /* it looks index is empty
                 * try to find starting from index itself */
                if (path[depth].p_bh)
                        return path[depth].p_bh->b_blocknr;
        }
                                                                                                                                                                                                     
        /* OK. use inode's group */
        bg_start = (ei->i_block_group * EXT3_BLOCKS_PER_GROUP(inode->i_sb)) +
                le32_to_cpu(EXT3_SB(inode->i_sb)->s_es->s_first_data_block);
        colour = (current->pid % 16) *
                        (EXT3_BLOCKS_PER_GROUP(inode->i_sb) / 16);
        return bg_start + colour + block;
}

static int ext3_ext_new_extent_cb(struct ext3_extents_tree *tree,
                                  struct ext3_ext_path *path,
                                  struct ext3_extent *newex, int exist)
{
        struct inode *inode = tree->inode;
        struct bpointers *bp = tree->private;
        int count, err, goal;
        unsigned long pblock;
        unsigned long tgen;
        loff_t new_i_size;
        handle_t *handle;
        int i, aflags = 0;
        
        i = EXT_DEPTH(tree);
        EXT_ASSERT(i == path->p_depth);
        EXT_ASSERT(path[i].p_hdr);
        
        if (exist) {
                err = EXT_CONTINUE;
                goto map;
        }
        
        if (bp->create == 0) {
                i = 0;
                if (newex->ee_block < bp->start)
                        i = bp->start - newex->ee_block;
                if (i >= newex->ee_len)
                        CERROR("nothing to do?! i = %d, e_num = %u\n",
                                        i, newex->ee_len);
                for (; i < newex->ee_len && bp->num; i++) {
                        *(bp->created) = 0;
                        bp->created++;
                        *(bp->blocks) = 0;
                        bp->blocks++;
                        bp->num--;
                        bp->start++;
                }
                                                                                                                                                                                                     
                return EXT_CONTINUE;
        }
        tgen = EXT_GENERATION(tree);
        count = ext3_ext_calc_credits_for_insert(tree, path);
        ext3_up_truncate_sem(inode);
        lock_kernel();
        handle = journal_start(EXT3_JOURNAL(inode), count + EXT3_ALLOC_NEEDED + 1);
        unlock_kernel();
        if (IS_ERR(handle)) {
                ext3_down_truncate_sem(inode);
                return PTR_ERR(handle);
        }
        
        if (tgen != EXT_GENERATION(tree)) {
                /* the tree has changed. so path can be invalid at moment */
                lock_kernel();
                journal_stop(handle);
                unlock_kernel();
                ext3_down_truncate_sem(inode);
                return EXT_REPEAT;
        }
        ext3_down_truncate_sem(inode);
        count = newex->ee_len;
        goal = ext3_ext_find_goal(inode, path, newex->ee_block, &aflags);
        aflags |= 2; /* block have been already reserved */
        pblock = ext3_mb_new_blocks(handle, inode, goal, &count, aflags, &err);
        if (!pblock)
                goto out;
        EXT_ASSERT(count <= newex->ee_len);
                                                                                                                                                                                                     
        /* insert new extent */
        newex->ee_start = pblock;
        newex->ee_len = count;
        err = ext3_ext_insert_extent(handle, tree, path, newex);
        if (err)
                goto out;
                                                                                                                                                                                                     
        /* correct on-disk inode size */
        if (newex->ee_len > 0) {
                new_i_size = (loff_t) newex->ee_block + newex->ee_len;
                new_i_size = new_i_size << inode->i_blkbits;
                if (new_i_size > EXT3_I(inode)->i_disksize) {
                        EXT3_I(inode)->i_disksize = new_i_size;
                        err = ext3_mark_inode_dirty(handle, inode);
                }
        }
out:
        lock_24kernel();
        journal_stop(handle);
        unlock_24kernel();
map:
        if (err >= 0) {
                /* map blocks */
                if (bp->num == 0) {
                        CERROR("hmm. why do we find this extent?\n");
                        CERROR("initial space: %lu:%u\n",
                                bp->start, bp->init_num);
                        CERROR("current extent: %u/%u/%u %d\n",
                                newex->ee_block, newex->ee_len,
                                newex->ee_start, exist);
                }
                i = 0;
                if (newex->ee_block < bp->start)
                        i = bp->start - newex->ee_block;
                if (i >= newex->ee_len)
                        CERROR("nothing to do?! i = %d, e_num = %u\n",
                                        i, newex->ee_len);
                for (; i < newex->ee_len && bp->num; i++) {
                        *(bp->created) = (exist == 0 ? 1 : 0);
                        bp->created++;
                        *(bp->blocks) = newex->ee_start + i;
                        bp->blocks++;
                        bp->num--;
                        bp->start++;
                }
        }
        return err;
}
                                                                                                                                                                                                     
int fsfilt_map_nblocks(struct inode *inode, unsigned long block,
                       unsigned long num, unsigned long *blocks,
                       int *created, int create)
{
        struct ext3_extents_tree tree;
        struct bpointers bp;
        int err;
                                                                                                                                                                                                     
        CDEBUG(D_OTHER, "blocks %lu-%lu requested for inode %u\n",
                block, block + num, (unsigned) inode->i_ino);
                                                                                                                                                                                                     
        ext3_init_tree_desc(&tree, inode);
        tree.private = &bp;
        bp.blocks = blocks;
        bp.created = created;
        bp.start = block;
        bp.init_num = bp.num = num;
        bp.create = create;
        
        ext3_down_truncate_sem(inode);
        err = ext3_ext_walk_space(&tree, block, num, ext3_ext_new_extent_cb);
        ext3_ext_invalidate_cache(&tree);
        ext3_up_truncate_sem(inode);
        return err;
}

int fsfilt_ext3_map_ext_inode_pages(struct inode *inode, struct page **page,
                                    int pages, unsigned long *blocks,
                                    int *created, int create)
{
        int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
        int rc = 0, i = 0;
        struct page *fp = NULL;
        int clen = 0;

        CDEBUG(D_OTHER, "inode %lu: map %d pages from %lu\n",
                inode->i_ino, pages, (*page)->index);

        /* pages are sorted already. so, we just have to find
         * contig. space and process them properly */
        while (i < pages) {
                if (fp == NULL) {
                        /* start new extent */
                        fp = *page++;
                        clen = 1;
                        i++;
                        continue;
                } else if (fp->index + clen == (*page)->index) {
                        /* continue the extent */
                        page++;
                        clen++;
                        i++;
                        continue;
                }

                /* process found extent */
                rc = fsfilt_map_nblocks(inode, fp->index * blocks_per_page,
                                        clen * blocks_per_page, blocks,
                                        created, create);
                if (rc)
                        GOTO(cleanup, rc);

                /* look for next extent */
                fp = NULL;
                blocks += blocks_per_page * clen;
                created += blocks_per_page * clen;
        }

        if (fp)
                rc = fsfilt_map_nblocks(inode, fp->index * blocks_per_page,
                                        clen * blocks_per_page, blocks,
                                        created, create);
cleanup:
        return rc;
}
#endif

extern int ext3_map_inode_page(struct inode *inode, struct page *page,
                               unsigned long *blocks, int *created, int create);
int fsfilt_ext3_map_bm_inode_pages(struct inode *inode, struct page **page,
                                   int pages, unsigned long *blocks,
                                   int *created, int create)
{
        int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
        unsigned long *b;
        int rc = 0, i, *cr;

        for (i = 0, cr = created, b = blocks; i < pages; i++, page++) {
                rc = ext3_map_inode_page(inode, *page, b, cr, create);
                if (rc) {
                        CERROR("ino %lu, blk %lu cr %u create %d: rc %d\n",
                               inode->i_ino, *b, *cr, create, rc);
                        break;
                }

                b += blocks_per_page;
                cr += blocks_per_page;
        }
        return rc;
}

int fsfilt_ext3_map_inode_pages(struct inode *inode, struct page **page,
                                int pages, unsigned long *blocks,
                                int *created, int create,
                                struct semaphore *optional_sem)
{
        int rc;
#ifdef EXT3_MULTIBLOCK_ALLOCATOR
        if (EXT3_I(inode)->i_flags & EXT3_EXTENTS_FL) {
                rc = fsfilt_ext3_map_ext_inode_pages(inode, page, pages,
                                                     blocks, created, create);
                return rc;
        }
#endif
        if (optional_sem != NULL)
                down(optional_sem);
        rc = fsfilt_ext3_map_bm_inode_pages(inode, page, pages, blocks,
                                            created, create);
        if (optional_sem != NULL)
                up(optional_sem);

        return rc;
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
        struct inode *inode = file->f_dentry->d_inode;
        unsigned long block;
        struct buffer_head *bh;
        int err, blocksize, csize, boffs;

        /* prevent reading after eof */
        lock_kernel();
        if (inode->i_size < *offs + size) {
                size = inode->i_size - *offs;
                unlock_kernel();
                if (size < 0) {
                        CERROR("size %llu is too short for read %u@%llu\n",
                               inode->i_size, size, *offs);
                        return -EIO;
                } else if (size == 0) {
                        return 0;
                }
        } else {
                unlock_kernel();
        }

        blocksize = 1 << inode->i_blkbits;

        while (size > 0) {
                block = *offs >> inode->i_blkbits;
                boffs = *offs & (blocksize - 1);
                csize = min(blocksize - boffs, size);
                bh = ext3_bread(NULL, inode, block, 0, &err);
                if (!bh) {
                        CERROR("can't read block: %d\n", err);
                        return err;
                }

                memcpy(buf, bh->b_data + boffs, csize);
                brelse(bh);

                *offs += csize;
                buf += csize;
                size -= csize;
        }
        return 0;
}

static int fsfilt_ext3_write_record(struct file *file, void *buf, int bufsize,
                                    loff_t *offs, int force_sync)
{
        struct buffer_head *bh = NULL;
        unsigned long block;
        struct inode *inode = file->f_dentry->d_inode;
        loff_t old_size = inode->i_size, offset = *offs;
        loff_t new_size = inode->i_size;
        journal_t *journal;
        handle_t *handle;
        int err = 0, block_count = 0, blocksize, size, boffs;

        /* Determine how many transaction credits are needed */
        blocksize = 1 << inode->i_blkbits;
        block_count = (*offs & (blocksize - 1)) + bufsize;
        block_count = (block_count + blocksize - 1) >> inode->i_blkbits;

        journal = EXT3_SB(inode->i_sb)->s_journal;
        lock_24kernel();
        handle = journal_start(journal,
                               block_count * EXT3_DATA_TRANS_BLOCKS + 2);
        unlock_24kernel();
        if (IS_ERR(handle)) {
                CERROR("can't start transaction\n");
                return PTR_ERR(handle);
        }

        while (bufsize > 0) {
                if (bh != NULL)
                        brelse(bh);

                block = offset >> inode->i_blkbits;
                boffs = offset & (blocksize - 1);
                size = min(blocksize - boffs, bufsize);
                bh = ext3_bread(handle, inode, block, 1, &err);
                if (!bh) {
                        CERROR("can't read/create block: %d\n", err);
                        goto out;
                }

                err = ext3_journal_get_write_access(handle, bh);
                if (err) {
                        CERROR("journal_get_write_access() returned error %d\n",
                               err);
                        goto out;
                }
                LASSERT(bh->b_data + boffs + size <= bh->b_data + bh->b_size);
                memcpy(bh->b_data + boffs, buf, size);
                err = ext3_journal_dirty_metadata(handle, bh);
                if (err) {
                        CERROR("journal_dirty_metadata() returned error %d\n",
                               err);
                        goto out;
                }
                if (offset + size > new_size)
                        new_size = offset + size;
                offset += size;
                bufsize -= size;
                buf += size;
        }

        if (force_sync)
                handle->h_sync = 1; /* recovery likes this */
out:
        if (bh)
                brelse(bh);

        /* correct in-core and on-disk sizes */
        if (new_size > inode->i_size) {
                lock_kernel();
                if (new_size > inode->i_size)
                        inode->i_size = new_size;
                if (inode->i_size > EXT3_I(inode)->i_disksize)
                        EXT3_I(inode)->i_disksize = inode->i_size;
                if (inode->i_size > old_size)
                        mark_inode_dirty(inode);
                unlock_kernel();
        }

        lock_24kernel();
        journal_stop(handle);
        unlock_24kernel();

        if (err == 0)
                *offs = offset;
        return err;
}

static int fsfilt_ext3_setup(struct obd_device *obd, struct super_block *sb)
{
#ifdef EXT3_FEATURE_INCOMPAT_MDSNUM
        struct mds_obd *mds = &obd->u.mds;
#endif
#if 0
        EXT3_SB(sb)->dx_lock = fsfilt_ext3_dx_lock;
        EXT3_SB(sb)->dx_unlock = fsfilt_ext3_dx_unlock;
#endif
#ifdef S_PDIROPS
        CWARN("Enabling PDIROPS\n");
        set_opt(EXT3_SB(sb)->s_mount_opt, PDIROPS);
        sb->s_flags |= S_PDIROPS;
#endif
        /* setup mdsnum in underlying fs */
#ifdef EXT3_FEATURE_INCOMPAT_MDSNUM
        if (mds->mds_md_obd) {
                struct ext3_sb_info *sbi = EXT3_SB(sb);
                struct ext3_super_block *es = sbi->s_es;
                handle_t *handle;
                int err;
                
                if (!EXT3_HAS_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_MDSNUM)) {
                        CWARN("%s: set mdsnum %d in ext3\n",
                              obd->obd_name, mds->mds_num);
                        lock_kernel();
                        handle = journal_start(sbi->s_journal, 1);
                        unlock_kernel();
                        LASSERT(!IS_ERR(handle));
                        err = ext3_journal_get_write_access(handle, sbi->s_sbh);
                        LASSERT(err == 0);
                        EXT3_SET_INCOMPAT_FEATURE(sb,
                                                EXT3_FEATURE_INCOMPAT_MDSNUM);
                        es->s_mdsnum = mds->mds_num;
                        err = ext3_journal_dirty_metadata(handle, sbi->s_sbh);
                        LASSERT(err == 0);
                        lock_kernel();
                        journal_stop(handle);
                        unlock_kernel();
                } else {
                        CWARN("%s: mdsnum initialized to %u in ext3fs\n",
                                obd->obd_name, es->s_mdsnum);
                }
                sbi->s_mdsnum = es->s_mdsnum;
        }
#endif
        return 0;
}

extern int ext3_add_dir_entry(struct dentry *dentry);
extern int ext3_del_dir_entry(struct dentry *dentry);

static int fsfilt_ext3_add_dir_entry(struct obd_device *obd,
                                     struct dentry *parent,
                                     char *name, int namelen,
                                     unsigned long ino,
                                     unsigned long generation,
                                     unsigned long mds, 
                                     unsigned long fid)
{
#ifdef EXT3_FEATURE_INCOMPAT_MDSNUM
        struct dentry *dentry;
        int err;
        LASSERT(ino != 0);
        LASSERT(namelen != 0);
        dentry = ll_lookup_one_len(name, parent, namelen);
        if (IS_ERR(dentry)) {
                CERROR("can't lookup %*s in %lu/%lu: %d\n", dentry->d_name.len,
                       dentry->d_name.name, dentry->d_inode->i_ino,
                       (unsigned long) dentry->d_inode->i_generation,
                       (int) PTR_ERR(dentry));
                RETURN(PTR_ERR(dentry));
        }
        if (dentry->d_inode != NULL || dentry->d_flags & DCACHE_CROSS_REF) {
                CERROR("dentry %*s(0x%p) found\n", dentry->d_name.len,
                       dentry->d_name.name, dentry);
                l_dput(dentry);
                RETURN(-EEXIST);
        }

        /* mds_reint_rename() may use this method to add dir entry 
         * that points onto local inode. and we don't want to find
         * it cross-ref by subsequent lookups */
        d_drop(dentry);

        dentry->d_flags |= DCACHE_CROSS_REF;
        dentry->d_inum = ino;
        dentry->d_mdsnum = mds;
        dentry->d_generation = generation;
        dentry->d_fid = fid;
        lock_kernel();
        err = ext3_add_dir_entry(dentry);
        unlock_kernel();
        
        l_dput(dentry);

        RETURN(err);
#else
#error "rebuild kernel and lustre with ext3-mds-num patch!"
        LASSERT(0);
#endif
}

static int fsfilt_ext3_del_dir_entry(struct obd_device *obd,
                                 struct dentry *dentry)
{
#ifdef EXT3_FEATURE_INCOMPAT_MDSNUM
        int err;
        lock_kernel();
        err = ext3_del_dir_entry(dentry);
        unlock_kernel();
        if (err == 0)
                d_drop(dentry);
        return err;
#else
#error "rebuild kernel and lustre with ext3-mds-num patch!"
        LASSERT(0);
#endif
}

/* If fso is NULL, op is FSFILT operation, otherwise op is number of fso
   objects. Logs is number of logfiles to update */
static int fsfilt_ext3_get_op_len(int op, struct fsfilt_objinfo *fso, int logs)
{
        if ( !fso ) {
                switch(op) {
                case FSFILT_OP_CREATE:
                                 /* directory leaf, index & indirect & EA*/
                        return 4 + 3 * logs;
                case FSFILT_OP_UNLINK:
                        return 3 * logs;
                }
        } else {
                int i;
                int needed = 0;
                struct super_block *sb = fso->fso_dentry->d_inode->i_sb;
                int blockpp = 1 << (PAGE_CACHE_SHIFT - sb->s_blocksize_bits);
                int addrpp = EXT3_ADDR_PER_BLOCK(sb) * blockpp;
                for (i = 0; i < op; i++, fso++) {
                        int nblocks = fso->fso_bufcnt * blockpp;
                        int ndindirect = min(nblocks, addrpp + 1);
                        int nindir = nblocks + ndindirect + 1;

                        needed += nindir;
                }
                return needed + 3 * logs;
        }

        return 0;
}


#define EXTENTS_EA "write_extents"
#define EXTENTS_EA_SIZE 64

int ext3_ext_in_ea_alloc_space(struct inode *, int, const char *, unsigned long, unsigned long);
int ext3_ext_in_ea_remove_space(struct inode *, int, const char *, unsigned long, unsigned long);
int ext3_ext_in_ea_get_extents(struct inode *, int, const char *, char **, int *);
int ext3_ext_in_ea_get_extents_num(struct inode *, int, const char *, int *);

static int fsfilt_ext3_insert_extents_ea(struct inode *inode, 
                                      unsigned long from, 
                                      unsigned long num) 
{
        int rc = 0;

        rc = ext3_ext_in_ea_alloc_space(inode, EXT3_XATTR_INDEX_TRUSTED,
                                        EXTENTS_EA, from, num);  
        return rc;
}

static int fsfilt_ext3_remove_extents_ea(struct inode *inode, 
                                         unsigned long from, 
                                         unsigned long num) 
{
        int rc = 0;

        rc = ext3_ext_in_ea_remove_space(inode, EXT3_XATTR_INDEX_TRUSTED,
                                         EXTENTS_EA, from, num);  
        return rc;
}

extern int ext3_init_tree_in_ea(struct inode *inode, int name_index,
				const char *eaname, int size);
                                
static int fsfilt_ext3_init_extents_ea(struct inode *inode)
{
        int rc = 0;

        rc = ext3_init_tree_in_ea(inode, EXT3_XATTR_INDEX_TRUSTED,
                                  EXTENTS_EA, 64);  
        return rc;
}

static int fsfilt_ext3_get_inode_write_extents(struct inode *inode, 
                                         char **pbuf, int *size)
{
        int rc = 0;
        
        rc = ext3_ext_in_ea_get_extents(inode, EXT3_XATTR_INDEX_TRUSTED,
                                        EXTENTS_EA,  pbuf, size);
        return rc; 
} 

static int fsfilt_ext3_get_write_extents_num(struct inode *inode, int *size)
{
        int rc = 0;
        
        rc = ext3_ext_in_ea_get_extents_num(inode, EXT3_XATTR_INDEX_TRUSTED, 
                                            EXTENTS_EA, size);
        return rc; 
} 

static struct fsfilt_operations fsfilt_ext3_ops = {
        .fs_type                    = "ext3",
        .fs_owner                   = THIS_MODULE,
        .fs_start                   = fsfilt_ext3_start,
        .fs_brw_start               = fsfilt_ext3_brw_start,
        .fs_commit                  = fsfilt_ext3_commit,
        .fs_commit_async            = fsfilt_ext3_commit_async,
        .fs_commit_wait             = fsfilt_ext3_commit_wait,
        .fs_setattr                 = fsfilt_ext3_setattr,
        .fs_iocontrol               = fsfilt_ext3_iocontrol,
        .fs_set_md                  = fsfilt_ext3_set_md,
        .fs_get_md                  = fsfilt_ext3_get_md,
        .fs_readpage                = fsfilt_ext3_readpage,
        .fs_add_journal_cb          = fsfilt_ext3_add_journal_cb,
        .fs_statfs                  = fsfilt_ext3_statfs,
        .fs_sync                    = fsfilt_ext3_sync,
        .fs_map_inode_pages         = fsfilt_ext3_map_inode_pages,
        .fs_prep_san_write          = fsfilt_ext3_prep_san_write,
        .fs_write_record            = fsfilt_ext3_write_record,
        .fs_read_record             = fsfilt_ext3_read_record,
        .fs_setup                   = fsfilt_ext3_setup,
        .fs_getpage                 = fsfilt_ext3_getpage,
        .fs_send_bio                = fsfilt_ext3_send_bio,
        .fs_set_xattr               = fsfilt_ext3_set_xattr,
        .fs_get_xattr               = fsfilt_ext3_get_xattr,
        .fs_get_op_len              = fsfilt_ext3_get_op_len,
        .fs_add_dir_entry           = fsfilt_ext3_add_dir_entry,
        .fs_del_dir_entry           = fsfilt_ext3_del_dir_entry,
        .fs_init_extents_ea         = fsfilt_ext3_init_extents_ea,
        .fs_insert_extents_ea       = fsfilt_ext3_insert_extents_ea,
        .fs_remove_extents_ea       = fsfilt_ext3_remove_extents_ea,
        .fs_get_inode_write_extents = fsfilt_ext3_get_inode_write_extents,
        .fs_get_write_extents_num   = fsfilt_ext3_get_write_extents_num,
};

static int __init fsfilt_ext3_init(void)
{
        int rc;

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
        fsfilt_unregister_ops(&fsfilt_ext3_ops);
        LASSERTF(kmem_cache_destroy(fcb_cache) == 0,
                 "can't free fsfilt callback cache: count %d\n",
                 atomic_read(&fcb_cache_count));
}

module_init(fsfilt_ext3_init);
module_exit(fsfilt_ext3_exit);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre ext3 Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
