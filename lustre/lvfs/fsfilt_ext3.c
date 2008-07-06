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
#include <linux/version.h>
#include <linux/bitops.h>
#include <linux/quota.h>
#include <linux/quotaio_v1.h>
#include <linux/quotaio_v2.h>
#include <linux/parser.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/ext3_xattr.h>
#else
#include <ext3/xattr.h>
#endif

#include <libcfs/kp30.h>
#include <lustre_fsfilt.h>
#include <obd.h>
#include <lustre_quota.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/iobuf.h>
#endif
#include <linux/lustre_compat25.h>
#include <linux/lprocfs_status.h>

#ifdef EXT3_MULTIBLOCK_ALLOCATOR
#include <linux/ext3_extents.h>
#endif

#include "lustre_quota_fmt.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#define FSFILT_DATA_TRANS_BLOCKS(sb)      EXT3_DATA_TRANS_BLOCKS
#define FSFILT_DELETE_TRANS_BLOCKS(sb)    EXT3_DELETE_TRANS_BLOCKS
#else
#define FSFILT_DATA_TRANS_BLOCKS(sb)      EXT3_DATA_TRANS_BLOCKS(sb)
#define FSFILT_DELETE_TRANS_BLOCKS(sb)    EXT3_DELETE_TRANS_BLOCKS(sb)
#endif

#ifdef EXT3_SINGLEDATA_TRANS_BLOCKS_HAS_SB
/* for kernels 2.6.18 and later */
#define FSFILT_SINGLEDATA_TRANS_BLOCKS(sb) EXT3_SINGLEDATA_TRANS_BLOCKS(sb)
#else
#define FSFILT_SINGLEDATA_TRANS_BLOCKS(sb) EXT3_SINGLEDATA_TRANS_BLOCKS
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define fsfilt_ext3_journal_start(inode, nblocks) \
                                journal_start(EXT3_JOURNAL(inode),nblocks)
#define fsfilt_ext3_journal_stop(handle)          journal_stop(handle)
#else
#define fsfilt_ext3_journal_start(inode, nblocks) ext3_journal_start(inode, nblocks)
#define fsfilt_ext3_journal_stop(handle)          ext3_journal_stop(handle)
#endif

static cfs_mem_cache_t *fcb_cache;

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

static char *fsfilt_ext3_get_label(struct super_block *sb)
{
        return EXT3_SB(sb)->s_es->s_volume_name;
}

static int fsfilt_ext3_set_label(struct super_block *sb, char *label)
{
        /* see e.g. fsfilt_ext3_write_record() */
        journal_t *journal;
        handle_t *handle;
        int err;

        journal = EXT3_SB(sb)->s_journal;
        lock_24kernel();
        handle = journal_start(journal, 1);
        unlock_24kernel();
        if (IS_ERR(handle)) {
                CERROR("can't start transaction\n");
                return(PTR_ERR(handle));
        }

        err = ext3_journal_get_write_access(handle, EXT3_SB(sb)->s_sbh);
        if (err)
                goto out;

        memcpy(EXT3_SB(sb)->s_es->s_volume_name, label,
               sizeof(EXT3_SB(sb)->s_es->s_volume_name));

        err = ext3_journal_dirty_metadata(handle, EXT3_SB(sb)->s_sbh);

out:
        lock_24kernel();
        journal_stop(handle);
        unlock_24kernel();

        return(err);
}

static char *fsfilt_ext3_uuid(struct super_block *sb)
{
        return EXT3_SB(sb)->s_es->s_uuid;
}

#ifdef HAVE_DISK_INODE_VERSION
/*
 * Get the 64-bit version for an inode.
 */
static __u64 fsfilt_ext3_get_version(struct inode *inode)
{
        return EXT3_I(inode)->i_fs_version;
}

/*
 * Set the 64-bit version and return the old version.
 */
static __u64 fsfilt_ext3_set_version(struct inode *inode, __u64 new_version)
{
        __u64 old_version = EXT3_I(inode)->i_fs_version;

        (EXT3_I(inode))->i_fs_version = new_version;
        return old_version;
}

#endif

/*
 * We don't currently need any additional blocks for rmdir and
 * unlink transactions because we are storing the OST oa_id inside
 * the inode (which we will be changing anyways as part of this
 * transaction).
 */
static void *fsfilt_ext3_start(struct inode *inode, int op, void *desc_private,
                               int logs)
{
        /* For updates to the last received file */
        int nblocks = FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb);
        journal_t *journal;
        void *handle;

        if (current->journal_info) {
                CDEBUG(D_INODE, "increasing refcount on %p\n",
                       current->journal_info);
                goto journal_start;
        }

        switch(op) {
        case FSFILT_OP_RMDIR:
        case FSFILT_OP_UNLINK:
                /* delete one file + create/update logs for each stripe */
                nblocks += FSFILT_DELETE_TRANS_BLOCKS(inode->i_sb);
                nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb)) * logs;
                break;
        case FSFILT_OP_RENAME:
                /* modify additional directory */
                nblocks += FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb);
                /* no break */
        case FSFILT_OP_SYMLINK:
                /* additional block + block bitmap + GDT for long symlink */
                nblocks += 3;
                /* no break */
        case FSFILT_OP_CREATE: {
#if defined(EXT3_EXTENTS_FL) && defined(EXT3_INDEX_FL)
                static int warned;
                if (!warned) {
                        if (!test_opt(inode->i_sb, EXTENTS)) {
                                warned = 1;
                        } else if (((EXT3_I(inode)->i_flags &
                              cpu_to_le32(EXT3_EXTENTS_FL | EXT3_INDEX_FL)) ==
                              cpu_to_le32(EXT3_EXTENTS_FL | EXT3_INDEX_FL))) {
                                CWARN("extent-mapped directory found - contact "
                                      "CFS: support@clusterfs.com\n");
                                warned = 1;
                        }
                }
#endif
                /* no break */
        }
        case FSFILT_OP_MKDIR:
        case FSFILT_OP_MKNOD:
                /* modify one inode + block bitmap + GDT */
                nblocks += 3;
                /* no break */
        case FSFILT_OP_LINK:
                /* modify parent directory */
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                         FSFILT_DATA_TRANS_BLOCKS(inode->i_sb);
                /* create/update logs for each stripe */
                nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb)) * logs;
                break;
        case FSFILT_OP_SETATTR:
                /* Setattr on inode */
                nblocks += 1;
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                         FSFILT_DATA_TRANS_BLOCKS(inode->i_sb);
                /* quota chown log for each stripe */
                nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb)) * logs;
                break;
        case FSFILT_OP_CANCEL_UNLINK:
                /* blocks for log header bitmap update OR
                 * blocks for catalog header bitmap update + unlink of logs */
                nblocks = (LLOG_CHUNK_SIZE >> inode->i_blkbits) +
                        FSFILT_DELETE_TRANS_BLOCKS(inode->i_sb) * logs;
                break;
        case FSFILT_OP_JOIN:
                /* delete 2 file(file + array id) + create 1 file (array id) 
                 * create/update logs for each stripe */
                nblocks += 2 * FSFILT_DELETE_TRANS_BLOCKS(inode->i_sb);
               
                /*create array log for head file*/ 
                nblocks += 3;
                nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb));
                /*update head file array */
                nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                         FSFILT_DATA_TRANS_BLOCKS(inode->i_sb);
                break;
        default: CERROR("unknown transaction start op %d\n", op);
                LBUG();
        }

        LASSERT(current->journal_info == desc_private);
        journal = EXT3_SB(inode->i_sb)->s_journal;
        if (nblocks > journal->j_max_transaction_buffers) {
                CWARN("too many credits %d for op %ux%u using %d instead\n",
                      nblocks, op, logs, journal->j_max_transaction_buffers);
                nblocks = journal->j_max_transaction_buffers;
        }

 journal_start:
        LASSERTF(nblocks > 0, "can't start %d credit transaction\n", nblocks);
        lock_24kernel();
        handle = fsfilt_ext3_journal_start(inode, nblocks);
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
        const int blockpp = 1 << (CFS_PAGE_SHIFT - sb->s_blocksize_bits);
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
        needed += FSFILT_DATA_TRANS_BLOCKS(sb);

#if defined(CONFIG_QUOTA)
        /* We assume that there will be 1 bit set in s_dquot.flags for each
         * quota file that is active.  This is at least true for now.
         */
        needed += hweight32(sb_any_quota_enabled(sb)) *
                FSFILT_SINGLEDATA_TRANS_BLOCKS(sb);
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
        handle = fsfilt_ext3_journal_start(fso->fso_dentry->d_inode, needed);
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

static int fsfilt_ext3_extend(struct inode *inode, unsigned int nblocks,void *h)
{
       handle_t *handle = h;

       /* fsfilt_extend called with nblocks = 0 for testing in special cases */
       if (nblocks == 0) {
               handle->h_buffer_credits = 0;
               CWARN("setting credits of handle %p to zero by request\n", h);
       }

       if (handle->h_buffer_credits > nblocks)
                return 0;
       if (journal_extend(handle, nblocks) == 0)
                return 0;

       ext3_mark_inode_dirty(handle, inode);
       return journal_restart(handle, nblocks);
}

static int fsfilt_ext3_commit(struct inode *inode, void *h, int force_sync)
{
        int rc;
        handle_t *handle = h;

        LASSERT(current->journal_info == handle);
        if (force_sync)
                handle->h_sync = 1; /* recovery likes this */

        lock_24kernel();
        rc = fsfilt_ext3_journal_stop(handle);
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

        lock_24kernel();
        transaction = handle->h_transaction;
        journal = transaction->t_journal;
        tid = transaction->t_tid;
        /* we don't want to be blocked */
        handle->h_sync = 0;
        rc = fsfilt_ext3_journal_stop(handle);
        if (rc) {
                CERROR("error while stopping transaction: %d\n", rc);
                unlock_24kernel();
                return rc;
        }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
        rtid = log_start_commit(journal, transaction);
        if (rtid != tid)
                CERROR("strange race: %lu != %lu\n",
                       (unsigned long) tid, (unsigned long) rtid);
#else
        log_start_commit(journal, tid);
#endif
        unlock_24kernel();

        *wait_handle = (void *) tid;
        CDEBUG(D_INODE, "commit async: %lu\n", (unsigned long) tid);
        return 0;
}

static int fsfilt_ext3_commit_wait(struct inode *inode, void *h)
{
        journal_t *journal = EXT3_JOURNAL(inode);
        tid_t tid = (tid_t)(long)h;

        CDEBUG(D_INODE, "commit wait: %lu\n", (unsigned long) tid);
        if (unlikely(is_journal_aborted(journal)))
                return -EIO;

        log_wait_commit(EXT3_JOURNAL(inode), tid);

        if (unlikely(is_journal_aborted(journal)))
                return -EIO;
        return 0;
}

static int fsfilt_ext3_setattr(struct dentry *dentry, void *handle,
                               struct iattr *iattr, int do_trunc)
{
        struct inode *inode = dentry->d_inode;
        int rc = 0;

        lock_24kernel();

        /* Avoid marking the inode dirty on the superblock list unnecessarily.
         * We are already writing the inode to disk as part of this
         * transaction and want to avoid a lot of extra inode writeout
         * later on. b=9828 */
        if (iattr->ia_valid & ATTR_SIZE && !do_trunc) {
                /* ATTR_SIZE would invoke truncate: clear it */
                iattr->ia_valid &= ~ATTR_SIZE;
                EXT3_I(inode)->i_disksize = iattr->ia_size;
                i_size_write(inode, iattr->ia_size);

                if (iattr->ia_valid & ATTR_UID)
                        inode->i_uid = iattr->ia_uid;
                if (iattr->ia_valid & ATTR_GID)
                        inode->i_gid = iattr->ia_gid;
                if (iattr->ia_valid & ATTR_ATIME)
                        inode->i_atime = iattr->ia_atime;
                if (iattr->ia_valid & ATTR_MTIME)
                        inode->i_mtime = iattr->ia_mtime;
                if (iattr->ia_valid & ATTR_CTIME)
                        inode->i_ctime = iattr->ia_ctime;
                if (iattr->ia_valid & ATTR_MODE) {
                        inode->i_mode = iattr->ia_mode;

                        if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
                                inode->i_mode &= ~S_ISGID;
                }

                inode->i_sb->s_op->dirty_inode(inode);

                goto out;
        }

        /* Don't allow setattr to change file type */
        if (iattr->ia_valid & ATTR_MODE)
                iattr->ia_mode = (inode->i_mode & S_IFMT) |
                                 (iattr->ia_mode & ~S_IFMT);

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

 out:
        unlock_24kernel();
        RETURN(rc);
}

static int fsfilt_ext3_iocontrol(struct inode * inode, struct file *file,
                                 unsigned int cmd, unsigned long arg)
{
        int rc = 0;
        ENTRY;

        /* FIXME: Can't do this because of nested transaction deadlock */
        if (cmd == EXT3_IOC_SETFLAGS && (*(int *)arg) & EXT3_JOURNAL_DATA_FL) {
                CERROR("can't set data journal flag on file\n");
                RETURN(-EPERM);
        }

        if (inode->i_fop->ioctl)
                rc = inode->i_fop->ioctl(inode, file, cmd, arg);
        else
                RETURN(-ENOTTY);

        RETURN(rc);
}

static int fsfilt_ext3_set_md(struct inode *inode, void *handle,
                              void *lmm, int lmm_size, const char *name)
{
        int rc;

        LASSERT(TRYLOCK_INODE_MUTEX(inode) == 0);

        lock_24kernel();
        rc = ext3_xattr_set_handle(handle, inode, EXT3_XATTR_INDEX_TRUSTED,
                                   name, lmm, lmm_size, 0);

        unlock_24kernel();

        if (rc && rc != -EROFS)
                CERROR("error adding MD data to inode %lu: rc = %d\n",
                       inode->i_ino, rc);
        return rc;
}

/* Must be called with i_mutex held */
static int fsfilt_ext3_get_md(struct inode *inode, void *lmm, int lmm_size,
                              const char *name)
{
        int rc;

        LASSERT(TRYLOCK_INODE_MUTEX(inode) == 0);
        lock_24kernel();

        rc = ext3_xattr_get(inode, EXT3_XATTR_INDEX_TRUSTED,
                            name, lmm, lmm_size);
        unlock_24kernel();

        /* This gives us the MD size */
        if (lmm == NULL)
                return (rc == -ENODATA) ? 0 : rc;

        if (rc < 0) {
                CDEBUG(D_INFO, "error getting EA %d/%s from inode %lu: rc %d\n",
                       EXT3_XATTR_INDEX_TRUSTED, name,
                       inode->i_ino, rc);
                memset(lmm, 0, lmm_size);
                return (rc == -ENODATA) ? 0 : rc;
        }

        return rc;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int fsfilt_ext3_send_bio(int rw, struct inode *inode, struct bio *bio)
{
        submit_bio(rw, bio);
        return 0;
}
#else
static int fsfilt_ext3_send_bio(int rw, struct inode *inode, struct kiobuf *bio)
{
        int rc, blk_per_page;

        rc = brw_kiovec(rw, 1, &bio, inode->i_dev,
                        KIOBUF_GET_BLOCKS(bio), 1 << inode->i_blkbits);
        /*
         * brw_kiovec() returns number of bytes actually written. If error
         * occurred after something was written, error code is returned though
         * kiobuf->errno. (See bug 6854.)
         */

        blk_per_page = CFS_PAGE_SIZE >> inode->i_blkbits;

        if (rc != (1 << inode->i_blkbits) * bio->nr_pages * blk_per_page) {
                CERROR("short write?  expected %d, wrote %d (%d)\n",
                       (1 << inode->i_blkbits) * bio->nr_pages * blk_per_page,
                       rc, bio->errno);
        }
        if (bio->errno != 0) {
                CERROR("IO error. Wrote %d of %d (%d)\n",
                       rc,
                       (1 << inode->i_blkbits) * bio->nr_pages * blk_per_page,
                       bio->errno);
                rc = bio->errno;
        }

        return rc;
}
#endif

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
                        if (*off < i_size_read(inode)) {
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
                                fake->rec_len = cpu_to_le16(blksize);
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
}

static int fsfilt_ext3_add_journal_cb(struct obd_device *obd, __u64 last_rcvd,
                                      void *handle, fsfilt_cb_t cb_func,
                                      void *cb_data)
{
        struct fsfilt_cb_data *fcb;

        OBD_SLAB_ALLOC(fcb, fcb_cache, CFS_ALLOC_IO, sizeof *fcb);
        if (fcb == NULL)
                RETURN(-ENOMEM);

        fcb->cb_func = cb_func;
        fcb->cb_obd = obd;
        fcb->cb_last_rcvd = last_rcvd;
        fcb->cb_data = cb_data;

        CDEBUG(D_EXT2, "set callback for last_rcvd: "LPD64"\n", last_rcvd);
        lock_24kernel();
        journal_callback_set(handle, fsfilt_ext3_cb_func,
                             (struct journal_callback *)fcb);
        unlock_24kernel();

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
        rc = ll_do_statfs(sb,&sfs);

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

#if defined(EXT3_MULTIBLOCK_ALLOCATOR) && (!defined(EXT3_EXT_CACHE_NO) || defined(EXT_CACHE_MARK))
#warning "kernel code has old extents/mballoc patch, disabling"
#undef EXT3_MULTIBLOCK_ALLOCATOR
#endif
#ifndef EXT3_EXTENTS_FL
#define EXT3_EXTENTS_FL                 0x00080000 /* Inode uses extents */
#endif

#ifdef EXT3_MULTIBLOCK_ALLOCATOR
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define ext3_up_truncate_sem(inode)  up_write(&EXT3_I(inode)->truncate_sem);
#define ext3_down_truncate_sem(inode)  down_write(&EXT3_I(inode)->truncate_sem);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#define ext3_up_truncate_sem(inode)  up(&EXT3_I(inode)->truncate_sem);
#define ext3_down_truncate_sem(inode)  down(&EXT3_I(inode)->truncate_sem);
#else
#define ext3_up_truncate_sem(inode)  mutex_unlock(&EXT3_I(inode)->truncate_mutex);
#define ext3_down_truncate_sem(inode)  mutex_lock(&EXT3_I(inode)->truncate_mutex);
#endif

#ifndef EXT_ASSERT
#define EXT_ASSERT(cond)  BUG_ON(!(cond))
#endif

#ifdef EXT3_EXT_HAS_NO_TREE
/* for kernels 2.6.18 and later */
#define ext3_ext_base                   inode
#define ext3_ext_base2inode(inode)      (inode)
#define EXT_DEPTH(inode)                ext_depth(inode)
#define EXT_GENERATION(inode)           ext_generation(inode)
#define fsfilt_ext3_ext_walk_space(inode, block, num, cb, cbdata) \
                        ext3_ext_walk_space(inode, block, num, cb, cbdata);
#else
#define ext3_ext_base                   ext3_extents_tree
#define ext3_ext_base2inode(tree)       (tree->inode)
#define fsfilt_ext3_ext_walk_space(tree, block, num, cb, cbdata) \
                        ext3_ext_walk_space(tree, block, num, cb);
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
#if 0
                        /* This prefers to eat into a contiguous extent
                         * rather than find an extent that the whole
                         * request will fit into.  This can fragment data
                         * block allocation and prevents our lovely 1M I/Os
                         * from reaching the disk intact. */
                        if (ex->ee_block + ex->ee_len == block)
                                *aflags |= 1;
#endif
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/locks.h>
static void ll_unmap_underlying_metadata(struct super_block *sb,
                                         unsigned long blocknr)
{
        struct buffer_head *old_bh;

        old_bh = get_hash_table(sb->s_dev, blocknr, sb->s_blocksize);
        if (old_bh) {
                mark_buffer_clean(old_bh);
                wait_on_buffer(old_bh);
                clear_bit(BH_Req, &old_bh->b_state);
                __brelse(old_bh);
        }
}
#else
#define ll_unmap_underlying_metadata(sb, blocknr) \
        unmap_underlying_metadata((sb)->s_bdev, blocknr)
#endif

#ifndef EXT3_MB_HINT_GROUP_ALLOC
static unsigned long new_blocks(handle_t *handle, struct ext3_ext_base *base,
                                struct ext3_ext_path *path, unsigned long block,
                                unsigned long *count, int *err)
{
        unsigned long pblock, goal;
        int aflags = 0;
        struct inode *inode = ext3_ext_base2inode(base);

        goal = ext3_ext_find_goal(inode, path, block, &aflags);
        aflags |= 2; /* block have been already reserved */
        lock_24kernel();
        pblock = ext3_mb_new_blocks(handle, inode, goal, count, aflags, err);
        unlock_24kernel();
        return pblock;

}
#else
static unsigned long new_blocks(handle_t *handle, struct ext3_ext_base *base,
                                struct ext3_ext_path *path, unsigned long block,
                                unsigned long *count, int *err)
{
        struct inode *inode = ext3_ext_base2inode(base);
        struct ext3_allocation_request ar;
        unsigned long pblock;
        int aflags;

        /* find neighbour allocated blocks */
        ar.lleft = block;
        *err = ext3_ext_search_left(base, path, &ar.lleft, &ar.pleft);
        if (*err)
                return 0;
        ar.lright = block;
        *err = ext3_ext_search_right(base, path, &ar.lright, &ar.pright);
        if (*err)
                return 0;

        /* allocate new block */
        ar.goal = ext3_ext_find_goal(inode, path, block, &aflags);
        ar.inode = inode;
        ar.logical = block;
        ar.len = *count;
        ar.flags = EXT3_MB_HINT_DATA;
        pblock = ext3_mb_new_blocks(handle, &ar, err);
        *count = ar.len;
        return pblock;
}
#endif

#ifdef EXT3_EXT_HAS_NO_TREE
static int ext3_ext_new_extent_cb(struct ext3_ext_base *base,
                                  struct ext3_ext_path *path,
                                  struct ext3_ext_cache *cex,
#ifdef HAVE_EXT_PREPARE_CB_EXTENT
                                  struct ext3_extent *ex,
#endif
                                  void *cbdata)
{
        struct bpointers *bp = cbdata;
#else
static int ext3_ext_new_extent_cb(struct ext3_ext_base *base,
                                  struct ext3_ext_path *path,
                                  struct ext3_ext_cache *cex
#ifdef HAVE_EXT_PREPARE_CB_EXTENT
                                  , struct ext3_extent *ex
#endif
                                 )
{
        struct bpointers *bp = base->private;
#endif
        struct inode *inode = ext3_ext_base2inode(base);
        struct ext3_extent nex;
        unsigned long pblock;
        unsigned long tgen;
        int err, i;
        unsigned long count;
        handle_t *handle;

        i = EXT_DEPTH(base);
        EXT_ASSERT(i == path->p_depth);
        EXT_ASSERT(path[i].p_hdr);

        if (cex->ec_type == EXT3_EXT_CACHE_EXTENT) {
                err = EXT_CONTINUE;
                goto map;
        }

        if (bp->create == 0) {
                i = 0;
                if (cex->ec_block < bp->start)
                        i = bp->start - cex->ec_block;
                if (i >= cex->ec_len)
                        CERROR("nothing to do?! i = %d, e_num = %u\n",
                                        i, cex->ec_len);
                for (; i < cex->ec_len && bp->num; i++) {
                        *(bp->created) = 0;
                        bp->created++;
                        *(bp->blocks) = 0;
                        bp->blocks++;
                        bp->num--;
                        bp->start++;
                }

                return EXT_CONTINUE;
        }

        tgen = EXT_GENERATION(base);
        count = ext3_ext_calc_credits_for_insert(base, path);
        ext3_up_truncate_sem(inode);

        lock_24kernel();
        handle = fsfilt_ext3_journal_start(inode, count+EXT3_ALLOC_NEEDED+1);
        unlock_24kernel();
        if (IS_ERR(handle)) {
                ext3_down_truncate_sem(inode);
                return PTR_ERR(handle);
        }

        ext3_down_truncate_sem(inode);
        if (tgen != EXT_GENERATION(base)) {
                /* the tree has changed. so path can be invalid at moment */
                lock_24kernel();
                fsfilt_ext3_journal_stop(handle);
                unlock_24kernel();
                return EXT_REPEAT;
        }

        count = cex->ec_len;
        pblock = new_blocks(handle, base, path, cex->ec_block, &count, &err);
        if (!pblock)
                goto out;
        EXT_ASSERT(count <= cex->ec_len);

        /* insert new extent */
        nex.ee_block = cex->ec_block;
        nex.ee_start = pblock;
        nex.ee_len = count;
        err = ext3_ext_insert_extent(handle, base, path, &nex);
        if (err) {
                CERROR("can't insert extent: %d\n", err);
                /* XXX: export ext3_free_blocks() */
                /*ext3_free_blocks(handle, inode, nex.ee_start, nex.ee_len, 0);*/
                goto out;
        }

        /*
         * Putting len of the actual extent we just inserted,
         * we are asking ext3_ext_walk_space() to continue
         * scaning after that block
         */
        cex->ec_len = nex.ee_len;
        cex->ec_start = nex.ee_start;
        BUG_ON(nex.ee_len == 0);
        BUG_ON(nex.ee_block != cex->ec_block);

out:
        lock_24kernel();
        fsfilt_ext3_journal_stop(handle);
        unlock_24kernel();
map:
        if (err >= 0) {
                /* map blocks */
                if (bp->num == 0) {
                        CERROR("hmm. why do we find this extent?\n");
                        CERROR("initial space: %lu:%u\n",
                                bp->start, bp->init_num);
                        CERROR("current extent: %u/%u/%u %d\n",
                                cex->ec_block, cex->ec_len,
                                cex->ec_start, cex->ec_type);
                }
                i = 0;
                if (cex->ec_block < bp->start)
                        i = bp->start - cex->ec_block;
                if (i >= cex->ec_len)
                        CERROR("nothing to do?! i = %d, e_num = %u\n",
                                        i, cex->ec_len);
                for (; i < cex->ec_len && bp->num; i++) {
                        *(bp->blocks) = cex->ec_start + i;
                        if (cex->ec_type == EXT3_EXT_CACHE_EXTENT) {
                                *(bp->created) = 0;
                        } else {
                                *(bp->created) = 1;
                                /* unmap any possible underlying metadata from
                                 * the block device mapping.  bug 6998. */
                                ll_unmap_underlying_metadata(inode->i_sb,
                                                             *(bp->blocks));
                        }
                        bp->created++;
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
#ifdef EXT3_EXT_HAS_NO_TREE
        struct ext3_ext_base *base = inode;
#else
        struct ext3_extents_tree tree;
        struct ext3_ext_base *base = &tree;
#endif
        struct bpointers bp;
        int err;

        CDEBUG(D_OTHER, "blocks %lu-%lu requested for inode %u\n",
               block, block + num - 1, (unsigned) inode->i_ino);

#ifndef EXT3_EXT_HAS_NO_TREE
        ext3_init_tree_desc(base, inode);
        tree.private = &bp;
#endif
        bp.blocks = blocks;
        bp.created = created;
        bp.start = block;
        bp.init_num = bp.num = num;
        bp.create = create;

        ext3_down_truncate_sem(inode);
        err = fsfilt_ext3_ext_walk_space(base, block, num, ext3_ext_new_extent_cb, &bp);
        ext3_ext_invalidate_cache(base);
        ext3_up_truncate_sem(inode);

        return err;
}

int fsfilt_ext3_map_ext_inode_pages(struct inode *inode, struct page **page,
                                    int pages, unsigned long *blocks,
                                    int *created, int create)
{
        int blocks_per_page = CFS_PAGE_SIZE >> inode->i_blkbits;
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
#endif /* EXT3_MULTIBLOCK_ALLOCATOR */

extern int ext3_map_inode_page(struct inode *inode, struct page *page,
                               unsigned long *blocks, int *created, int create);
int fsfilt_ext3_map_bm_inode_pages(struct inode *inode, struct page **page,
                                   int pages, unsigned long *blocks,
                                   int *created, int create)
{
        int blocks_per_page = CFS_PAGE_SIZE >> inode->i_blkbits;
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

static int fsfilt_ext3_read_record(struct file * file, void *buf,
                                   int size, loff_t *offs)
{
        struct inode *inode = file->f_dentry->d_inode;
        unsigned long block;
        struct buffer_head *bh;
        int err, blocksize, csize, boffs;

        /* prevent reading after eof */
        lock_kernel();
        if (i_size_read(inode) < *offs + size) {
                size = i_size_read(inode) - *offs;
                unlock_kernel();
                if (size < 0) {
                        CERROR("size %llu is too short for read %u@%llu\n",
                               i_size_read(inode), size, *offs);
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
        loff_t old_size = i_size_read(inode), offset = *offs;
        loff_t new_size = i_size_read(inode);
        handle_t *handle;
        int err = 0, block_count = 0, blocksize, size, boffs;

        /* Determine how many transaction credits are needed */
        blocksize = 1 << inode->i_blkbits;
        block_count = (*offs & (blocksize - 1)) + bufsize;
        block_count = (block_count + blocksize - 1) >> inode->i_blkbits;

        lock_24kernel();
        handle = fsfilt_ext3_journal_start(inode,
                               block_count * FSFILT_DATA_TRANS_BLOCKS(inode->i_sb) + 2);
        unlock_24kernel();
        if (IS_ERR(handle)) {
                CERROR("can't start transaction for %d blocks (%d bytes)\n",
                       block_count * FSFILT_DATA_TRANS_BLOCKS(inode->i_sb) + 2, bufsize);
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
        if (new_size > i_size_read(inode)) {
                lock_kernel();
                if (new_size > i_size_read(inode))
                        i_size_write(inode, new_size);
                if (i_size_read(inode) > EXT3_I(inode)->i_disksize)
                        EXT3_I(inode)->i_disksize = i_size_read(inode);
                if (i_size_read(inode) > old_size)
                        mark_inode_dirty(inode);
                unlock_kernel();
        }

        lock_24kernel();
        fsfilt_ext3_journal_stop(handle);
        unlock_24kernel();

        if (err == 0)
                *offs = offset;
        return err;
}

static int fsfilt_ext3_setup(struct super_block *sb)
{
        struct ext3_sb_info *sbi = EXT3_SB(sb);
#if 0
        sbi->dx_lock = fsfilt_ext3_dx_lock;
        sbi->dx_unlock = fsfilt_ext3_dx_unlock;
#endif
#ifdef S_PDIROPS
        CWARN("Enabling PDIROPS\n");
        set_opt(sbi->s_mount_opt, PDIROPS);
        sb->s_flags |= S_PDIROPS;
#endif
        if (!EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_DIR_INDEX))
                CWARN("filesystem doesn't have dir_index feature enabled\n");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) && HAVE_QUOTA_SUPPORT
        /* enable journaled quota support */
        /* kfreed in ext3_put_super() */
        sbi->s_qf_names[USRQUOTA] = kstrdup("lquota.user.reserved", GFP_KERNEL);
        if (!sbi->s_qf_names[USRQUOTA])
                return -ENOMEM;
        sbi->s_qf_names[GRPQUOTA] = kstrdup("lquota.group.reserved", GFP_KERNEL);
        if (!sbi->s_qf_names[GRPQUOTA]) {
                kfree(sbi->s_qf_names[USRQUOTA]);
                sbi->s_qf_names[USRQUOTA] = NULL;
                return -ENOMEM;
        }
        sbi->s_jquota_fmt = QFMT_VFS_V0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13))
        set_opt(sbi->s_mount_opt, QUOTA);
#endif
#endif
        return 0;
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
                int blockpp = 1 << (CFS_PAGE_SHIFT - sb->s_blocksize_bits);
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

#define DQINFO_COPY(out, in)                    \
do {                                            \
        Q_COPY(out, in, dqi_bgrace);            \
        Q_COPY(out, in, dqi_igrace);            \
        Q_COPY(out, in, dqi_flags);             \
        Q_COPY(out, in, dqi_valid);             \
} while (0)

#define DQBLK_COPY(out, in)                     \
do {                                            \
        Q_COPY(out, in, dqb_bhardlimit);        \
        Q_COPY(out, in, dqb_bsoftlimit);        \
        Q_COPY(out, in, dqb_curspace);          \
        Q_COPY(out, in, dqb_ihardlimit);        \
        Q_COPY(out, in, dqb_isoftlimit);        \
        Q_COPY(out, in, dqb_curinodes);         \
        Q_COPY(out, in, dqb_btime);             \
        Q_COPY(out, in, dqb_itime);             \
        Q_COPY(out, in, dqb_valid);             \
} while (0)

      

static int fsfilt_ext3_quotactl(struct super_block *sb,
                                struct obd_quotactl *oqc)
{
        int i, rc = 0, error = 0;
        struct quotactl_ops *qcop;
        struct if_dqinfo *info;
        struct if_dqblk *dqblk;
        ENTRY;

        if (!sb->s_qcop)
                RETURN(-ENOSYS);

        OBD_ALLOC_PTR(info);
        if (!info)
                RETURN(-ENOMEM);
        OBD_ALLOC_PTR(dqblk);
        if (!dqblk) {
                OBD_FREE_PTR(info);
                RETURN(-ENOMEM);
        }

        DQINFO_COPY(info, &oqc->qc_dqinfo);
        DQBLK_COPY(dqblk, &oqc->qc_dqblk);

        qcop = sb->s_qcop;
        if (oqc->qc_cmd == Q_QUOTAON || oqc->qc_cmd == Q_QUOTAOFF) {
                for (i = 0; i < MAXQUOTAS; i++) {
                        if (!Q_TYPESET(oqc, i))
                                continue;

                        if (oqc->qc_cmd == Q_QUOTAON) {
                                lustre_quota_version_t qfmt = oqc->qc_id;
                                char *name[][MAXQUOTAS] = LUSTRE_OPQFILES_NAMES;

                                if (!qcop->quota_on)
                                        GOTO(out, rc = -ENOSYS);

                                rc = qcop->quota_on(sb, i, QFMT_VFS_V0,
                                                    name[qfmt][i]);
#ifdef HAVE_QUOTA64
                                if (rc == -ENOENT || rc == -EINVAL) {
                                        /* see bug 13904 */
                                        rc = lustre_slave_quota_convert(qfmt, i);
                                        if (!rc)
                                                rc = qcop->quota_on(sb, i,
                                                                QFMT_VFS_V0,
                                                                name[qfmt][i]);
                                        else if (rc == -ESTALE)
                                                rc = -ENOENT;
                                }
#endif
                        } else if (oqc->qc_cmd == Q_QUOTAOFF) {
                                if (!qcop->quota_off)
                                        GOTO(out, rc = -ENOSYS);
                                rc = qcop->quota_off(sb, i);
                        }

                        if (rc == -EBUSY)
                                error = rc;
                        else if (rc)
                                GOTO(out, rc);
                }
                GOTO(out, rc ?: error);
        }

        switch (oqc->qc_cmd) {
        case Q_GETOINFO:
        case Q_GETINFO:
                if (!qcop->get_info)
                        GOTO(out, rc = -ENOSYS);
                rc = qcop->get_info(sb, oqc->qc_type, info);
                break;
        case Q_SETQUOTA:
        case Q_INITQUOTA:
                if (!qcop->set_dqblk)
                        GOTO(out, rc = -ENOSYS);
                rc = qcop->set_dqblk(sb, oqc->qc_type, oqc->qc_id, dqblk);
                break;
        case Q_GETOQUOTA:
        case Q_GETQUOTA:
                if (!qcop->get_dqblk)
                        GOTO(out, rc = -ENOSYS);
                rc = qcop->get_dqblk(sb, oqc->qc_type, oqc->qc_id, dqblk);
                if (!rc)
                        dqblk->dqb_valid = QIF_LIMITS | QIF_USAGE;
                break;
        case Q_SYNC:
                if (!sb->s_qcop->quota_sync)
                        GOTO(out, rc = -ENOSYS);
                qcop->quota_sync(sb, oqc->qc_type);
                break;
        case Q_FINVALIDATE:
                CDEBUG(D_WARNING, "invalidating operational quota files\n");
                for (i = 0; i < MAXQUOTAS; i++) {
                        struct file *fp;
                        lustre_quota_version_t qfmt = oqc->qc_id;
                        char *name[][MAXQUOTAS] = LUSTRE_OPQFILES_NAMES;

                        if (!Q_TYPESET(oqc, i))
                                continue;

                        fp = filp_open(name[qfmt][i], O_CREAT | O_TRUNC | O_RDWR, 0644);
                        if (IS_ERR(fp)) {
                                rc = PTR_ERR(fp);
                                CERROR("error invalidating operational quota file"
                                       " %s (rc:%d)\n", name[qfmt][i], rc);
                        } else {
                                filp_close(fp, 0);
                        }

                }
                break;
        default:
                CERROR("unsupported quotactl command: %d\n", oqc->qc_cmd);
                LBUG();
        }
out:
        DQINFO_COPY(&oqc->qc_dqinfo, info);
        DQBLK_COPY(&oqc->qc_dqblk, dqblk);

        OBD_FREE_PTR(info);
        OBD_FREE_PTR(dqblk);

        if (rc)
                CDEBUG(D_QUOTA, "quotactl command %#x, id %u, type %d "
                                "failed: %d\n",
                       oqc->qc_cmd, oqc->qc_id, oqc->qc_type, rc);
        RETURN(rc);
}

struct chk_dqblk{
        struct hlist_node       dqb_hash;        /* quotacheck hash */
        struct list_head        dqb_list;        /* in list also */
        qid_t                   dqb_id;          /* uid/gid */
        short                   dqb_type;        /* USRQUOTA/GRPQUOTA */
        qsize_t                 dqb_bhardlimit;  /* block hard limit */
        qsize_t                 dqb_bsoftlimit;  /* block soft limit */
        qsize_t                 dqb_curspace;    /* current space */
        qsize_t                 dqb_ihardlimit;  /* inode hard limit */
        qsize_t                 dqb_isoftlimit;  /* inode soft limit */
        qsize_t                 dqb_curinodes;   /* current inodes */
        __u64                   dqb_btime;       /* block grace time */
        __u64                   dqb_itime;       /* inode grace time */
        __u32                   dqb_valid;       /* flag for above fields */
};

static inline unsigned int chkquot_hash(qid_t id, int type)
                                        __attribute__((__const__));

static inline unsigned int chkquot_hash(qid_t id, int type)
{
        return (id * (MAXQUOTAS - type)) % NR_DQHASH;
}

static inline struct chk_dqblk *
find_chkquot(struct hlist_head *head, qid_t id, int type)
{
        struct hlist_node *node;
        struct chk_dqblk *cdqb;

        hlist_for_each(node, head) {
                cdqb = hlist_entry(node, struct chk_dqblk, dqb_hash);
                if (cdqb->dqb_id == id && cdqb->dqb_type == type)
                        return cdqb;
        }

        return NULL;
}

static struct chk_dqblk *alloc_chkquot(qid_t id, int type)
{
        struct chk_dqblk *cdqb;

        OBD_ALLOC_PTR(cdqb);
        if (cdqb) {
                INIT_HLIST_NODE(&cdqb->dqb_hash);
                INIT_LIST_HEAD(&cdqb->dqb_list);
                cdqb->dqb_id = id;
                cdqb->dqb_type = type;
        }

        return cdqb;
}

static struct chk_dqblk *
cqget(struct super_block *sb, struct hlist_head *hash, struct list_head *list,
      qid_t id, int type, int first_check)
{
        struct hlist_head *head = hash + chkquot_hash(id, type);
        struct if_dqblk dqb;
        struct chk_dqblk *cdqb;
        int rc;

        cdqb = find_chkquot(head, id, type);
        if (cdqb)
                return cdqb;

        cdqb = alloc_chkquot(id, type);
        if (!cdqb)
                return NULL;

        if (!first_check) {
                rc = sb->s_qcop->get_dqblk(sb, type, id, &dqb);
                if (rc) {
                        CERROR("get_dqblk of id %u, type %d failed: %d\n",
                               id, type, rc);
                } else {
                        DQBLK_COPY(cdqb, &dqb);
                        cdqb->dqb_curspace = 0;
                        cdqb->dqb_curinodes = 0;
                }
        }

        hlist_add_head(&cdqb->dqb_hash, head);
        list_add_tail(&cdqb->dqb_list, list);

        return cdqb;
}

static inline int quota_onoff(struct super_block *sb, int cmd, int type, int qfmt)
{
        struct obd_quotactl *oqctl;
        int rc;

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl)
                RETURN(-ENOMEM);

        oqctl->qc_cmd = cmd;
        oqctl->qc_id = qfmt;
        oqctl->qc_type = type;
        rc = fsfilt_ext3_quotactl(sb, oqctl);

        OBD_FREE_PTR(oqctl);
        return rc;
}

static inline int read_old_dqinfo(struct super_block *sb, int type,
                                  struct if_dqinfo *dqinfo)
{
        struct obd_quotactl *oqctl;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl)
                RETURN(-ENOMEM);

        oqctl->qc_cmd = Q_GETINFO;
        oqctl->qc_type = type;
        rc = fsfilt_ext3_quotactl(sb, oqctl);
        if (!rc)
                ((struct obd_dqinfo *)dqinfo)[type] = oqctl->qc_dqinfo;

        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

static inline struct ext3_group_desc *
get_group_desc(struct super_block *sb, int group)
{
        unsigned long desc_block, desc;
        struct ext3_group_desc *gdp;

        desc_block = group / EXT3_DESC_PER_BLOCK(sb);
        desc = group % EXT3_DESC_PER_BLOCK(sb);
        gdp = (struct ext3_group_desc *)
              EXT3_SB(sb)->s_group_desc[desc_block]->b_data;

        return gdp + desc;
}

static inline struct buffer_head *
read_inode_bitmap(struct super_block *sb, unsigned long group)
{
        struct ext3_group_desc *desc;
        struct buffer_head *bh;

        desc = get_group_desc(sb, group);
        bh = sb_bread(sb, le32_to_cpu(desc->bg_inode_bitmap));

        return bh;
}

static inline struct inode *ext3_iget_inuse(struct super_block *sb,
                                     struct buffer_head *bitmap_bh,
                                     int index, unsigned long ino)
{
        struct inode *inode = NULL;

        if (ext3_test_bit(index, bitmap_bh->b_data))
                inode = iget(sb, ino);

        return inode;
}

struct qchk_ctxt {
        struct hlist_head       qckt_hash[NR_DQHASH];        /* quotacheck hash */
        struct list_head        qckt_list;                   /* quotacheck list */
        int                     qckt_first_check[MAXQUOTAS]; /* 1 if no old quotafile */
        struct if_dqinfo        qckt_dqinfo[MAXQUOTAS];      /* old dqinfo */
};

static int add_inode_quota(struct inode *inode, struct qchk_ctxt *qctxt,
                           struct obd_quotactl *oqc)
{
        struct chk_dqblk *cdqb[MAXQUOTAS] = { NULL, };
        loff_t size = 0;
        qid_t qid[MAXQUOTAS];
        int cnt, i, rc = 0;

        if (!inode)
                return 0;

        qid[USRQUOTA] = inode->i_uid;
        qid[GRPQUOTA] = inode->i_gid;

        if (S_ISDIR(inode->i_mode) ||
            S_ISREG(inode->i_mode) ||
            S_ISLNK(inode->i_mode))
                size = inode_get_bytes(inode);

        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                if (!Q_TYPESET(oqc, cnt))
                        continue;

                cdqb[cnt] = cqget(inode->i_sb, qctxt->qckt_hash,
                                &qctxt->qckt_list, qid[cnt], cnt,
                                qctxt->qckt_first_check[cnt]);
                if (!cdqb[cnt]) {
                        rc = -ENOMEM;
                        break;
                }

                cdqb[cnt]->dqb_curspace += size;
                cdqb[cnt]->dqb_curinodes++;
        }

        if (rc) {
                for (i = 0; i < cnt; i++) {
                        if (!Q_TYPESET(oqc, i))
                                continue;
                        LASSERT(cdqb[i]);
                        cdqb[i]->dqb_curspace -= size;
                        cdqb[i]->dqb_curinodes--;
                }
        }

        return rc;
}

static int v2_write_dqheader(struct file *f, int type)
{
        static const __u32 quota_magics[] = V2_INITQMAGICS;
#ifdef HAVE_QUOTA64
        static const __u32 quota_versions[] = V2_INITQVERSIONS_R0;
#else
        static const __u32 quota_versions[] = V2_INITQVERSIONS;
#endif
        struct v2_disk_dqheader dqhead;
        loff_t offset = 0;

        CLASSERT(ARRAY_SIZE(quota_magics) == ARRAY_SIZE(quota_versions));
        LASSERT(0 <= type && type < ARRAY_SIZE(quota_magics));

        dqhead.dqh_magic = cpu_to_le32(quota_magics[type]);
        dqhead.dqh_version = cpu_to_le32(quota_versions[type]);

        return cfs_user_write(f, (char *)&dqhead, sizeof(dqhead), &offset);
}

/* write dqinfo struct in a new quota file */
static int v2_write_dqinfo(struct file *f, int type, struct if_dqinfo *info)
{
        struct v2_disk_dqinfo dqinfo;
        __u32 blocks = V2_DQTREEOFF + 1;
        loff_t offset = V2_DQINFOOFF;

        if (info) {
                dqinfo.dqi_bgrace = cpu_to_le32(info->dqi_bgrace);
                dqinfo.dqi_igrace = cpu_to_le32(info->dqi_igrace);
                dqinfo.dqi_flags = cpu_to_le32(info->dqi_flags & DQF_MASK &
                                               ~DQF_INFO_DIRTY);
        } else {
                dqinfo.dqi_bgrace = cpu_to_le32(MAX_DQ_TIME);
                dqinfo.dqi_igrace = cpu_to_le32(MAX_IQ_TIME);
                dqinfo.dqi_flags = 0;
        }

        dqinfo.dqi_blocks = cpu_to_le32(blocks);
        dqinfo.dqi_free_blk = 0;
        dqinfo.dqi_free_entry = 0;

        return cfs_user_write(f, (char *)&dqinfo, sizeof(dqinfo), &offset);
}

#ifdef HAVE_QUOTA64
static int v3_write_dqheader(struct file *f, int type)
{
        static const __u32 quota_magics[] = V2_INITQMAGICS;
        static const __u32 quota_versions[] = V2_INITQVERSIONS_R1;
        struct v2_disk_dqheader dqhead;
        loff_t offset = 0;

        CLASSERT(ARRAY_SIZE(quota_magics) == ARRAY_SIZE(quota_versions));
        LASSERT(0 <= type && type < ARRAY_SIZE(quota_magics));

        dqhead.dqh_magic = cpu_to_le32(quota_magics[type]);
        dqhead.dqh_version = cpu_to_le32(quota_versions[type]);

        return cfs_user_write(f, (char *)&dqhead, sizeof(dqhead), &offset);
}

/* write dqinfo struct in a new quota file */
static int v3_write_dqinfo(struct file *f, int type, struct if_dqinfo *info)
{
        return v2_write_dqinfo(f, type, info);
}
#endif

static int create_new_quota_files(struct qchk_ctxt *qctxt,
                                  struct obd_quotactl *oqc)
{
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < MAXQUOTAS; i++) {
                struct if_dqinfo *info = qctxt->qckt_first_check[i]?
                                         NULL : &qctxt->qckt_dqinfo[i];
                struct file *file;
                const char *name[][MAXQUOTAS] = LUSTRE_OPQFILES_NAMES;
                int (*write_dqheader)(struct file *, int);
                int (*write_dqinfo)(struct file *, int, struct if_dqinfo *);

                if (!Q_TYPESET(oqc, i))
                        continue;

                file = filp_open(name[oqc->qc_id][i],
                                 O_RDWR | O_CREAT | O_TRUNC, 0644);
                if (IS_ERR(file)) {
                        rc = PTR_ERR(file);
                        CERROR("can't create %s file: rc = %d\n",
                               name[oqc->qc_id][i], rc);
                        GOTO(out, rc);
                }

                if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                        CERROR("file %s is not regular", name[oqc->qc_id][i]);
                        filp_close(file, 0);
                        GOTO(out, rc = -EINVAL);
                }

                DQUOT_DROP(file->f_dentry->d_inode);

                switch (oqc->qc_id) {
                case LUSTRE_QUOTA_V1 : write_dqheader = v2_write_dqheader;
                                       write_dqinfo   = v2_write_dqinfo;
                                       break;
#ifdef HAVE_QUOTA64
                case LUSTRE_QUOTA_V2 : write_dqheader = v3_write_dqheader;
                                       write_dqinfo   = v3_write_dqinfo;
                                       break;
#endif
                default              : CERROR("unknown quota format!\n");
                                       LBUG();
                }

                rc = (*write_dqheader)(file, i);
                if (rc) {
                        filp_close(file, 0);
                        GOTO(out, rc);
                }

                rc = (*write_dqinfo)(file, i, info);
                filp_close(file, 0);
                if (rc)
                        GOTO(out, rc);
        }

out:
        RETURN(rc);
}


static int commit_chkquot(struct super_block *sb, struct qchk_ctxt *qctxt,
                          struct chk_dqblk *cdqb)
{
        struct obd_quotactl *oqc;
        long now;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(oqc);
        if (!oqc)
                RETURN(-ENOMEM);

        now = CURRENT_SECONDS;

        if (cdqb->dqb_bsoftlimit &&
            toqb(cdqb->dqb_curspace) >= cdqb->dqb_bsoftlimit &&
            !cdqb->dqb_btime)
                cdqb->dqb_btime =
                        now + qctxt->qckt_dqinfo[cdqb->dqb_type].dqi_bgrace;

        if (cdqb->dqb_isoftlimit &&
            cdqb->dqb_curinodes >= cdqb->dqb_isoftlimit &&
            !cdqb->dqb_itime)
                cdqb->dqb_itime =
                        now + qctxt->qckt_dqinfo[cdqb->dqb_type].dqi_igrace;

        cdqb->dqb_valid = QIF_ALL;

        oqc->qc_cmd = Q_SETQUOTA;
        oqc->qc_type = cdqb->dqb_type;
        oqc->qc_id = cdqb->dqb_id;
        DQBLK_COPY(&oqc->qc_dqblk, cdqb);

        rc = fsfilt_ext3_quotactl(sb, oqc);
        OBD_FREE_PTR(oqc);
        RETURN(rc);
}

static int prune_chkquots(struct super_block *sb,
                          struct qchk_ctxt *qctxt, int error)
{
        struct chk_dqblk *cdqb, *tmp;
        int rc;

        list_for_each_entry_safe(cdqb, tmp, &qctxt->qckt_list, dqb_list) {
                if (!error) {
                        rc = commit_chkquot(sb, qctxt, cdqb);
                        if (rc)
                                error = rc;
                }
                hlist_del_init(&cdqb->dqb_hash);
                list_del(&cdqb->dqb_list);
                OBD_FREE_PTR(cdqb);
        }

        return error;
}

static int fsfilt_ext3_quotacheck(struct super_block *sb,
                                  struct obd_quotactl *oqc)
{
        struct ext3_sb_info *sbi = EXT3_SB(sb);
        int i, group;
        struct qchk_ctxt *qctxt;
        struct buffer_head *bitmap_bh = NULL;
        unsigned long ino;
        struct inode *inode;
        int rc = 0;
        ENTRY;

        /* turn on quota and read dqinfo if existed */
        OBD_ALLOC_PTR(qctxt);
        if (!qctxt) {
                oqc->qc_stat = -ENOMEM;
                RETURN(-ENOMEM);
        }

        for (i = 0; i < NR_DQHASH; i++)
                INIT_HLIST_HEAD(&qctxt->qckt_hash[i]);
        INIT_LIST_HEAD(&qctxt->qckt_list);

        for (i = 0; i < MAXQUOTAS; i++) {
                if (!Q_TYPESET(oqc, i))
                        continue;

                rc = quota_onoff(sb, Q_QUOTAON, i, oqc->qc_id);
                if (!rc || rc == -EBUSY) {
                        rc = read_old_dqinfo(sb, i, qctxt->qckt_dqinfo);
                        if (rc)
                                GOTO(out, rc);
                } else if (rc == -ENOENT || rc == -EINVAL || rc == -EEXIST) {
                        qctxt->qckt_first_check[i] = 1;
                } else if (rc) {
                        GOTO(out, rc);
                }
        }

        /* check quota and update in hash */
        for (group = 0; group < sbi->s_groups_count; group++) {
                ino = group * sbi->s_inodes_per_group + 1;
                bitmap_bh = read_inode_bitmap(sb, group);
                if (!bitmap_bh) {
                        CERROR("read_inode_bitmap group %d failed", group);
                        GOTO(out, -EIO);
                }

                for (i = 0; i < sbi->s_inodes_per_group; i++, ino++) {
                        if (ino < sbi->s_first_ino)
                                continue;

                        inode = ext3_iget_inuse(sb, bitmap_bh, i, ino);
                        rc = add_inode_quota(inode, qctxt, oqc);
                        iput(inode);
                        if (rc) {
                                brelse(bitmap_bh);
                                GOTO(out, rc);
                        }
                }

                brelse(bitmap_bh);
        }

        /* read old quota limits from old quota file. (only for the user
         * has limits but hasn't file) */
#ifdef HAVE_QUOTA_SUPPORT
        for (i = 0; i < MAXQUOTAS; i++) {
                struct list_head id_list;
                struct dquot_id *dqid, *tmp;

                if (!Q_TYPESET(oqc, i))
                        continue;

                if (qctxt->qckt_first_check[i])
                        continue;


                LASSERT(sb_dqopt(sb)->files[i] != NULL);
                INIT_LIST_HEAD(&id_list);
#ifndef KERNEL_SUPPORTS_QUOTA_READ 
                rc = lustre_get_qids(sb_dqopt(sb)->files[i], NULL, i, &id_list);
#else
                rc = lustre_get_qids(NULL, sb_dqopt(sb)->files[i], i, &id_list);
#endif
                if (rc)
                        CERROR("read old limits failed. (rc:%d)\n", rc);

                list_for_each_entry_safe(dqid, tmp, &id_list, di_link) {
                        list_del_init(&dqid->di_link);

                        if (!rc)
                                cqget(sb, qctxt->qckt_hash, &qctxt->qckt_list,
                                      dqid->di_id, i,
                                      qctxt->qckt_first_check[i]);
                        kfree(dqid);
                }
        }
#endif
        /* turn off quota cause we are to dump chk_dqblk to files */
        quota_onoff(sb, Q_QUOTAOFF, oqc->qc_type, oqc->qc_id);

        rc = create_new_quota_files(qctxt, oqc);
        if (rc)
                GOTO(out, rc);

        /* we use vfs functions to set dqblk, so turn quota on */
        rc = quota_onoff(sb, Q_QUOTAON, oqc->qc_type, oqc->qc_id);
out:
        /* dump and free chk_dqblk */
        rc = prune_chkquots(sb, qctxt, rc);
        OBD_FREE_PTR(qctxt);

        /* turn off quota, `lfs quotacheck` will turn on when all
         * nodes quotacheck finish. */
        quota_onoff(sb, Q_QUOTAOFF, oqc->qc_type, oqc->qc_id);

        oqc->qc_stat = rc;
        if (rc)
                CERROR("quotacheck failed: rc = %d\n", rc);

        RETURN(rc);
}

#ifdef HAVE_QUOTA_SUPPORT
static int fsfilt_ext3_quotainfo(struct lustre_quota_info *lqi, int type, 
                                 int cmd)
{
        int rc = 0;
        ENTRY;

        if (lqi->qi_files[type] == NULL) {
                CERROR("operate qinfo before it's enabled!\n");
                RETURN(-EIO);
        }

        switch (cmd) {
        case QFILE_CHK:
                rc = lustre_check_quota_file(lqi, type);
                break;
        case QFILE_RD_INFO:
                rc = lustre_read_quota_info(lqi, type);
                break;
        case QFILE_WR_INFO:
                rc = lustre_write_quota_info(lqi, type);
                break;
        case QFILE_INIT_INFO:
                rc = lustre_init_quota_info(lqi, type);
                break;
        case QFILE_CONVERT:
                rc = lustre_quota_convert(lqi, type);
                break;
        default:
                rc = -ENOTSUPP;
                CERROR("Unsupported admin quota file cmd %d\n"
                       "Are lquota.ko and fsfilt_ldiskfs.ko modules in sync?\n",
                       cmd);
                break;
        }
        RETURN(rc);
}

static int fsfilt_ext3_qids(struct file *file, struct inode *inode, int type,
                            struct list_head *list)
{
        return lustre_get_qids(file, inode, type, list);
}

static int fsfilt_ext3_dquot(struct lustre_dquot *dquot, int cmd)
{
        int rc = 0;
        ENTRY;

        if (dquot->dq_info->qi_files[dquot->dq_type] == NULL) {
                CERROR("operate dquot before it's enabled!\n");
                RETURN(-EIO);
        }

        switch (cmd) {
        case QFILE_RD_DQUOT:
                rc = lustre_read_dquot(dquot);
                break;
        case QFILE_WR_DQUOT:
                if (dquot->dq_dqb.dqb_ihardlimit ||
                    dquot->dq_dqb.dqb_isoftlimit ||
                    dquot->dq_dqb.dqb_bhardlimit ||
                    dquot->dq_dqb.dqb_bsoftlimit)
                        clear_bit(DQ_FAKE_B, &dquot->dq_flags);
                else
                        set_bit(DQ_FAKE_B, &dquot->dq_flags);

                rc = lustre_commit_dquot(dquot);
                if (rc >= 0)
                        rc = 0;
                break;
        default:
                CERROR("Unsupported admin quota file cmd %d\n", cmd);
                LBUG();
                break;
        }
        RETURN(rc);
}
#endif

static lvfs_sbdev_type fsfilt_ext3_journal_sbdev(struct super_block *sb)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return (EXT3_SB(sb)->journal_bdev);
#else
        return kdev_t_to_nr(EXT3_SB(sb)->s_journal->j_dev);
#endif
}

static struct fsfilt_operations fsfilt_ext3_ops = {
        .fs_type                = "ext3",
        .fs_owner               = THIS_MODULE,
        .fs_getlabel            = fsfilt_ext3_get_label,
        .fs_setlabel            = fsfilt_ext3_set_label,
        .fs_uuid                = fsfilt_ext3_uuid,
        .fs_start               = fsfilt_ext3_start,
        .fs_brw_start           = fsfilt_ext3_brw_start,
        .fs_extend              = fsfilt_ext3_extend,
        .fs_commit              = fsfilt_ext3_commit,
        .fs_commit_async        = fsfilt_ext3_commit_async,
        .fs_commit_wait         = fsfilt_ext3_commit_wait,
        .fs_setattr             = fsfilt_ext3_setattr,
        .fs_iocontrol           = fsfilt_ext3_iocontrol,
        .fs_set_md              = fsfilt_ext3_set_md,
        .fs_get_md              = fsfilt_ext3_get_md,
        .fs_readpage            = fsfilt_ext3_readpage,
        .fs_add_journal_cb      = fsfilt_ext3_add_journal_cb,
        .fs_statfs              = fsfilt_ext3_statfs,
        .fs_sync                = fsfilt_ext3_sync,
        .fs_map_inode_pages     = fsfilt_ext3_map_inode_pages,
        .fs_write_record        = fsfilt_ext3_write_record,
        .fs_read_record         = fsfilt_ext3_read_record,
        .fs_setup               = fsfilt_ext3_setup,
        .fs_send_bio            = fsfilt_ext3_send_bio,
        .fs_get_op_len          = fsfilt_ext3_get_op_len,
        .fs_quotactl            = fsfilt_ext3_quotactl,
        .fs_quotacheck          = fsfilt_ext3_quotacheck,
#ifdef HAVE_DISK_INODE_VERSION
        .fs_get_version         = fsfilt_ext3_get_version,
        .fs_set_version         = fsfilt_ext3_set_version,
#endif
#ifdef HAVE_QUOTA_SUPPORT
        .fs_quotainfo           = fsfilt_ext3_quotainfo,
        .fs_qids                = fsfilt_ext3_qids,
        .fs_dquot               = fsfilt_ext3_dquot,
#endif
        .fs_journal_sbdev       = fsfilt_ext3_journal_sbdev,
};

static int __init fsfilt_ext3_init(void)
{
        int rc;

        fcb_cache = cfs_mem_cache_create("fsfilt_ext3_fcb",
                                         sizeof(struct fsfilt_cb_data), 0, 0);
        if (!fcb_cache) {
                CERROR("error allocating fsfilt journal callback cache\n");
                GOTO(out, rc = -ENOMEM);
        }

        rc = fsfilt_register_ops(&fsfilt_ext3_ops);

        if (rc) {
                int err = cfs_mem_cache_destroy(fcb_cache);
                LASSERTF(err == 0, "error destroying new cache: rc %d\n", err);
        }
out:
        return rc;
}

static void __exit fsfilt_ext3_exit(void)
{
        int rc;

        fsfilt_unregister_ops(&fsfilt_ext3_ops);
        rc = cfs_mem_cache_destroy(fcb_cache);
        LASSERTF(rc == 0, "couldn't destroy fcb_cache slab\n");
}

module_init(fsfilt_ext3_init);
module_exit(fsfilt_ext3_exit);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre ext3 Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
