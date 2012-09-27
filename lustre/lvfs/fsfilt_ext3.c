/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lvfs/fsfilt_ext3.c
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#ifdef HAVE_LINUX_EXPORTFS_H
#include <linux/exportfs.h>
#endif
#include <ext4/ext4.h>
#include <ext4/ext4_jbd2.h>
#include <linux/version.h>
#include <linux/bitops.h>
#include <linux/quota.h>

#if defined(HAVE_EXT3_XATTR_H)
# include <ext3/xattr.h>
#elif !defined(EXT3_XATTR_INDEX_TRUSTED)
/* ext3 xattr.h not available in rh style kernel-devel rpm */
/* CHAOS kernel-devel package will not include fs/ldiskfs/xattr.h */
# define EXT3_XATTR_INDEX_TRUSTED        4
extern int ext3_xattr_get(struct inode *, int, const char *, void *, size_t);
extern int ext3_xattr_set_handle(handle_t *, struct inode *, int, const char *, const void *, size_t, int);
#endif

#include <libcfs/libcfs.h>
#include <lustre_fsfilt.h>
#include <obd.h>
#include <linux/lustre_compat25.h>
#include <linux/lprocfs_status.h>

#include <ext4/ext4_extents.h>

/* for kernels 2.6.18 and later */
#define FSFILT_SINGLEDATA_TRANS_BLOCKS(sb) EXT3_SINGLEDATA_TRANS_BLOCKS(sb)

#define fsfilt_ext3_ext_insert_extent(handle, inode, path, newext, flag) \
               ext3_ext_insert_extent(handle, inode, path, newext, flag)

#define ext3_mb_discard_inode_preallocations(inode) \
                 ext3_discard_preallocations(inode)

#define fsfilt_log_start_commit(journal, tid) jbd2_log_start_commit(journal, tid)
#define fsfilt_log_wait_commit(journal, tid) jbd2_log_wait_commit(journal, tid)

#ifdef HAVE_EXT4_JOURNAL_CALLBACK_ADD
# define journal_callback ext4_journal_cb_entry
# define fsfilt_journal_callback_set(handle, func, jcb) \
         ext4_journal_callback_add(handle, func, jcb)
#elif defined(HAVE_JBD2_JOURNAL_CALLBACK_SET)
# define fsfilt_journal_callback_set(handle, func, jcb) \
         jbd2_journal_callback_set(handle, func, jcb)
#elif defined(HAVE_JOURNAL_CALLBACK_SET)
# define fsfilt_journal_callback_set(handle, func, jcb) \
         journal_callback_set(handle, func, jcb)
#else
# error missing journal commit callback
#endif /* HAVE_EXT4_JOURNAL_CALLBACK_ADD */

static cfs_mem_cache_t *fcb_cache;

struct fsfilt_cb_data {
        struct journal_callback cb_jcb; /* jbd private data - MUST BE FIRST */
        fsfilt_cb_t cb_func;            /* MDS/OBD completion function */
        struct obd_device *cb_obd;      /* MDS/OBD completion device */
        __u64 cb_last_rcvd;             /* MDS/OST last committed operation */
        void *cb_data;                  /* MDS/OST completion function data */
};

#ifndef ext3_find_next_bit
#define ext3_find_next_bit           ext2_find_next_bit
#endif

#ifndef ext2_find_next_bit
#ifdef __LITTLE_ENDIAN
#define ext2_find_next_bit(addr, size, off) find_next_bit((unsigned long *)(addr), (size), (off))
#else
error "Need implementation of find_next_bit on big-endian systems"
#endif	/* __LITTLE_ENDIAN */
#endif	/* !ext2_find_next_le_bit */

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
        handle = ext3_journal_start_sb(sb, 1);
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
        ext3_journal_stop(handle);

        return(err);
}

static char *fsfilt_ext3_uuid(struct super_block *sb)
{
        return EXT3_SB(sb)->s_es->s_uuid;
}

#ifdef HAVE_DISK_INODE_VERSION

static __u64 get_i_version(struct inode *inode)
{
        return EXT3_I(inode)->i_fs_version;
}

static void set_i_version(struct inode *inode, __u64 new_version)
{
        (EXT3_I(inode))->i_fs_version = new_version;
}

/*
 * Get the 64-bit version for an inode.
 */
static __u64 fsfilt_ext3_get_version(struct inode *inode)
{
        CDEBUG(D_INFO, "Get version "LPX64" for inode %lu\n",
               get_i_version(inode), inode->i_ino);
        return get_i_version(inode);
}

/*
 * Set the 64-bit version and return the old version.
 */
static __u64 fsfilt_ext3_set_version(struct inode *inode, __u64 new_version)
{
        __u64 old_version = get_i_version(inode);

        CDEBUG(D_INFO, "Set version "LPX64" (old "LPX64") for inode %lu\n",
               new_version, old_version, inode->i_ino);
        set_i_version(inode, new_version);
        /* version is set after all inode operations are finished, so we should
         * mark it dirty here */
        inode->i_sb->s_op->dirty_inode(inode);
        return old_version;
}

#endif

/* kernel has ext4_blocks_for_truncate since linux-3.1.1 */
#ifdef HAVE_BLOCKS_FOR_TRUNCATE
# include <ext4/truncate.h>
#else
static inline unsigned long ext4_blocks_for_truncate(struct inode *inode)
{
	ext4_lblk_t needed;

	needed = inode->i_blocks >> (inode->i_sb->s_blocksize_bits - 9);
	if (needed < 2)
		needed = 2;
	if (needed > EXT4_MAX_TRANS_DATA)
		needed = EXT4_MAX_TRANS_DATA;
	return EXT4_DATA_TRANS_BLOCKS(inode->i_sb) + needed;
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
		nblocks += EXT3_DELETE_TRANS_BLOCKS(inode->i_sb);
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
			   EXT3_DATA_TRANS_BLOCKS(inode->i_sb);
                /* create/update logs for each stripe */
                nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb)) * logs;
                break;
        case FSFILT_OP_SETATTR:
                /* Setattr on inode */
		nblocks += 1;
		nblocks += EXT3_INDEX_EXTRA_TRANS_BLOCKS +
			   EXT3_DATA_TRANS_BLOCKS(inode->i_sb);
                /* quota chown log for each stripe */
                nblocks += (EXT3_INDEX_EXTRA_TRANS_BLOCKS +
                            FSFILT_SINGLEDATA_TRANS_BLOCKS(inode->i_sb)) * logs;
                break;
        case FSFILT_OP_CANCEL_UNLINK:
		LASSERT(logs == 1);

		/* blocks for log header bitmap update OR
		 * blocks for catalog header bitmap update + unlink of logs +
		 * blocks for delete the inode (include blocks truncating). */
		nblocks = (LLOG_CHUNK_SIZE >> inode->i_blkbits) +
			  EXT3_DELETE_TRANS_BLOCKS(inode->i_sb) +
			  ext4_blocks_for_truncate(inode) + 3;
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
        handle = ext3_journal_start(inode, nblocks);

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
		int ndind =
			(long)((nb[j + fso->fso_bufcnt - 1].lnb_file_offset -
				nb[j].lnb_file_offset) >>
			       sb->s_blocksize_bits) /
			(EXT3_ADDR_PER_BLOCK(sb) * EXT3_ADDR_PER_BLOCK(sb));
                nbitmaps += min(fso->fso_bufcnt, ndind > 0 ? ndind : 2);

                /* leaf, indirect, tindirect blocks for first block */
                nbitmaps += blockpp + 2;

                j += fso->fso_bufcnt;
        }

	next_indir = nb[0].lnb_file_offset +
		     (EXT3_ADDR_PER_BLOCK(sb) << sb->s_blocksize_bits);
	for (i = 1; i < niocount; i++) {
		if (nb[i].lnb_file_offset >= next_indir) {
			nbitmaps++;     /* additional indirect */
			next_indir = nb[i].lnb_file_offset +
				     (EXT3_ADDR_PER_BLOCK(sb) <<
				      sb->s_blocksize_bits);
		} else if (nb[i].lnb_file_offset !=
			   nb[i - 1].lnb_file_offset + sb->s_blocksize) {
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
	needed += EXT3_DATA_TRANS_BLOCKS(sb);

#if defined(CONFIG_QUOTA)
	/* We assume that there will be 1 bit set in s_dquot.flags for each
	 * quota file that is active.  This is at least true for now.
	 */
	needed += hweight32(sb_any_quota_loaded(sb)) *
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
        handle = ext3_journal_start(fso->fso_dentry->d_inode, needed);
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
       if (ext3_journal_extend(handle, nblocks) == 0)
                return 0;

       ext3_mark_inode_dirty(handle, inode);
       return ext3_journal_restart(handle, nblocks);
}

static int fsfilt_ext3_commit(struct inode *inode, void *h, int force_sync)
{
        int rc;
        handle_t *handle = h;

        LASSERT(current->journal_info == handle);
        if (force_sync)
                handle->h_sync = 1; /* recovery likes this */

        rc = ext3_journal_stop(handle);

        return rc;
}

static int fsfilt_ext3_commit_async(struct inode *inode, void *h,
                                    void **wait_handle)
{
        unsigned long tid;
        transaction_t *transaction;
        handle_t *handle = h;
        journal_t *journal;
        int rc;

        LASSERT(current->journal_info == handle);

        transaction = handle->h_transaction;
        journal = transaction->t_journal;
        tid = transaction->t_tid;
        /* we don't want to be blocked */
        handle->h_sync = 0;
        rc = ext3_journal_stop(handle);
        if (rc) {
                CERROR("error while stopping transaction: %d\n", rc);
                return rc;
        }
        fsfilt_log_start_commit(journal, tid);

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

        fsfilt_log_wait_commit(EXT3_JOURNAL(inode), tid);

        if (unlikely(is_journal_aborted(journal)))
                return -EIO;
        return 0;
}

static int fsfilt_ext3_setattr(struct dentry *dentry, void *handle,
                               struct iattr *iattr, int do_trunc)
{
        struct inode *inode = dentry->d_inode;
        int rc = 0;

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 7, 50, 0)
        /* Try to correct for a bug in 2.1.0 (LU-221) that caused negative
         * timestamps to appear to be in the far future, due old timestamp
         * being stored on disk as an unsigned value.  This fixes up any
         * bad values held by the client before storing them on disk,
         * and ensures any timestamp updates are correct.  LU-1042 */
        if (unlikely(LTIME_S(inode->i_atime) == LU221_BAD_TIME &&
                     !(iattr->ia_valid & ATTR_ATIME))) {
                iattr->ia_valid |= ATTR_ATIME;
                LTIME_S(iattr->ia_atime) = 0;
        }
        if (unlikely(LTIME_S(inode->i_mtime) == LU221_BAD_TIME &&
                     !(iattr->ia_valid & ATTR_MTIME))) {
                iattr->ia_valid |= ATTR_MTIME;
                LTIME_S(iattr->ia_mtime) = 0;
        }
        if (unlikely((LTIME_S(inode->i_ctime) == LU221_BAD_TIME ||
                      LTIME_S(inode->i_ctime) == 0) &&
                     !(iattr->ia_valid & ATTR_CTIME))) {
                iattr->ia_valid |= ATTR_CTIME;
                LTIME_S(iattr->ia_ctime) = 0;
        }
#else
#warning "remove old LU-221/LU-1042 workaround code"
#endif

        /* When initializating timestamps for new inodes, use the filesystem
         * mkfs time for ctime to avoid e2fsck ibadness incorrectly thinking
         * that this is potentially an invalid inode.  Files with an old ctime
         * migrated to a newly-formatted OST with a newer s_mkfs_time will not
         * hit this check, since it is only for ctime == 0.  LU-1010/LU-1042 */
        if ((iattr->ia_valid & ATTR_CTIME) && LTIME_S(iattr->ia_ctime) == 0)
                LTIME_S(iattr->ia_ctime) =
                        EXT4_SB(inode->i_sb)->s_es->s_mkfs_time;

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

                        if (!cfs_curproc_is_in_groups(inode->i_gid) &&
                            !cfs_capable(CFS_CAP_FSETID))
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
        iattr->ia_valid &= ~TIMES_SET_FLAGS;

        if (inode->i_op->setattr) {
                rc = inode->i_op->setattr(dentry, iattr);
        } else {
#ifndef HAVE_SIMPLE_SETATTR /* simple_setattr() already call it */
                rc = inode_change_ok(inode, iattr);
                if (!rc)
#endif
                        rc = simple_setattr(dentry, iattr);
        }

 out:
        RETURN(rc);
}

static int fsfilt_ext3_iocontrol(struct inode *inode, struct file *file,
                                 unsigned int cmd, unsigned long arg)
{
        int rc = 0;
        ENTRY;

        /* FIXME: Can't do this because of nested transaction deadlock */
        if (cmd == EXT3_IOC_SETFLAGS) {
                /* We can't enable data journaling on OST objects, because
                * this forces the transaction to be closed in order to
                * flush the journal, but the caller will already have a
                * compound transaction open to update the last_rcvd file,
                * and this thread would deadlock trying to set the flag. */
                if ((*(int *)arg) & EXT3_JOURNAL_DATA_FL) {
                        CERROR("can't set data journal flag on file\n");
                        RETURN(-EPERM);
                }
                /* Because the MDS does not see the EXTENTS_FL set on the
                 * OST objects, mask this flag into all set flags.  It is
                 * not legal to clear this flag in any case, so we are not
                 * changing the functionality by doing this.  b=22911 */
                *(int *)arg |= EXT3_I(inode)->i_flags & EXT3_EXTENTS_FL;
        }

        /* ext4_ioctl does not have a inode argument */
        if (inode->i_fop->unlocked_ioctl)
                rc = inode->i_fop->unlocked_ioctl(file, cmd, arg);
        else
                RETURN(-ENOTTY);

        RETURN(rc);
}

static int fsfilt_ext3_set_md(struct inode *inode, void *handle,
			      void *lmm, int lmm_size, const char *name)
{
	int rc;

	LASSERT(mutex_trylock(&inode->i_mutex) == 0);

	rc = ext3_xattr_set_handle(handle, inode, EXT3_XATTR_INDEX_TRUSTED,
				   name, lmm, lmm_size, XATTR_NO_CTIME);

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

	LASSERT(mutex_trylock(&inode->i_mutex) == 0);

	rc = ext3_xattr_get(inode, EXT3_XATTR_INDEX_TRUSTED,
			    name, lmm, lmm_size);

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

static int fsfilt_ext3_send_bio(int rw, struct inode *inode, struct bio *bio)
{
        submit_bio(rw, bio);
        return 0;
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

                CDEBUG(D_EXT2, "reading %lu at dir %lu+%llu\n",
                       (unsigned long)count, inode->i_ino, *off);
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

#ifdef HAVE_EXT4_JOURNAL_CALLBACK_ADD
static void fsfilt_ext3_cb_func(struct super_block *sb,
                                struct journal_callback *jcb, int error)
#else
static void fsfilt_ext3_cb_func(struct journal_callback *jcb, int error)
#endif
{
        struct fsfilt_cb_data *fcb = container_of(jcb, typeof(*fcb), cb_jcb);

        fcb->cb_func(fcb->cb_obd, fcb->cb_last_rcvd, fcb->cb_data, error);

        OBD_SLAB_FREE(fcb, fcb_cache, sizeof *fcb);
}

static int fsfilt_ext3_add_journal_cb(struct obd_device *obd, __u64 last_rcvd,
                                      void *handle, fsfilt_cb_t cb_func,
                                      void *cb_data)
{
        struct fsfilt_cb_data *fcb;

        OBD_SLAB_ALLOC_PTR_GFP(fcb, fcb_cache, CFS_ALLOC_IO);
        if (fcb == NULL)
                RETURN(-ENOMEM);

        fcb->cb_func = cb_func;
        fcb->cb_obd = obd;
        fcb->cb_last_rcvd = last_rcvd;
        fcb->cb_data = cb_data;

        CDEBUG(D_EXT2, "set callback for last_rcvd: "LPD64"\n", last_rcvd);
        fsfilt_journal_callback_set(handle, fsfilt_ext3_cb_func, &fcb->cb_jcb);

        return 0;
}

static int fsfilt_ext3_statfs(struct super_block *sb, struct obd_statfs *osfs)
{
	struct kstatfs sfs;
	int rc;

	memset(&sfs, 0, sizeof(sfs));
	rc = sb->s_op->statfs(sb->s_root, &sfs);
	statfs_pack(osfs, &sfs);
	return rc;
}

static int fsfilt_ext3_sync(struct super_block *sb)
{
        return ext3_force_commit(sb);
}

#ifndef EXT3_EXTENTS_FL
#define EXT3_EXTENTS_FL                 0x00080000 /* Inode uses extents */
#endif

#ifndef EXT_ASSERT
#define EXT_ASSERT(cond)  BUG_ON(!(cond))
#endif

#define EXT_GENERATION(inode)           (EXT4_I(inode)->i_ext_generation)
#define ext3_ext_base                   inode
#define ext3_ext_base2inode(inode)      (inode)
#define EXT_DEPTH(inode)                ext_depth(inode)
#define fsfilt_ext3_ext_walk_space(inode, block, num, cb, cbdata) \
                        ext3_ext_walk_space(inode, block, num, cb, cbdata);

struct bpointers {
        unsigned long *blocks;
        int *created;
        unsigned long start;
        int num;
        int init_num;
        int create;
};

static long ext3_ext_find_goal(struct inode *inode, struct ext3_ext_path *path,
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
                if ((ex = path[depth].p_ext))
                        return ext_pblock(ex) + (block - le32_to_cpu(ex->ee_block));

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

#define ll_unmap_underlying_metadata(sb, blocknr) \
        unmap_underlying_metadata((sb)->s_bdev, blocknr)

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
        pblock = ext3_mb_new_blocks(handle, inode, goal, count, aflags, err);
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

static int ext3_ext_new_extent_cb(struct ext3_ext_base *base,
                                  struct ext3_ext_path *path,
                                  struct ext3_ext_cache *cex,
#ifdef HAVE_EXT_PREPARE_CB_EXTENT
                                   struct ext3_extent *ex,
#endif
                                  void *cbdata)
{
        struct bpointers *bp = cbdata;
        struct inode *inode = ext3_ext_base2inode(base);
        struct ext3_extent nex;
        unsigned long pblock;
        unsigned long tgen;
        int err, i;
        unsigned long count;
        handle_t *handle;

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

	handle = ext3_journal_start(inode, count+EXT3_ALLOC_NEEDED+1);
	if (IS_ERR(handle)) {
		return PTR_ERR(handle);
	}

        if (tgen != EXT_GENERATION(base)) {
                /* the tree has changed. so path can be invalid at moment */
                ext3_journal_stop(handle);
                return EXT_REPEAT;
        }

        /* In 2.6.32 kernel, ext4_ext_walk_space()'s callback func is not
         * protected by i_data_sem as whole. so we patch it to store
	 * generation to path and now verify the tree hasn't changed */
        down_write((&EXT4_I(inode)->i_data_sem));

        /* validate extent, make sure the extent tree does not changed */
	if (EXT_GENERATION(base) != path[0].p_generation) {
                /* cex is invalid, try again */
                up_write(&EXT4_I(inode)->i_data_sem);
                ext3_journal_stop(handle);
                return EXT_REPEAT;
        }

        count = cex->ec_len;
        pblock = new_blocks(handle, base, path, cex->ec_block, &count, &err);
        if (!pblock)
                goto out;
        EXT_ASSERT(count <= cex->ec_len);

        /* insert new extent */
        nex.ee_block = cpu_to_le32(cex->ec_block);
        ext3_ext_store_pblock(&nex, pblock);
        nex.ee_len = cpu_to_le16(count);
        err = fsfilt_ext3_ext_insert_extent(handle, base, path, &nex, 0);
        if (err) {
                /* free data blocks we just allocated */
                /* not a good idea to call discard here directly,
                 * but otherwise we'd need to call it every free() */
#ifdef EXT3_MB_HINT_GROUP_ALLOC
                ext3_mb_discard_inode_preallocations(inode);
#endif
                ext3_free_blocks(handle, inode, ext_pblock(&nex),
                                 cpu_to_le16(nex.ee_len), 0);
                goto out;
        }

        /*
         * Putting len of the actual extent we just inserted,
         * we are asking ext3_ext_walk_space() to continue
         * scaning after that block
         */
        cex->ec_len = le16_to_cpu(nex.ee_len);
        cex->ec_start = ext_pblock(&nex);
        BUG_ON(le16_to_cpu(nex.ee_len) == 0);
        BUG_ON(le32_to_cpu(nex.ee_block) != cex->ec_block);

out:
        up_write((&EXT4_I(inode)->i_data_sem));
        ext3_journal_stop(handle);
map:
        if (err >= 0) {
                /* map blocks */
                if (bp->num == 0) {
                        CERROR("hmm. why do we find this extent?\n");
                        CERROR("initial space: %lu:%u\n",
                                bp->start, bp->init_num);
                        CERROR("current extent: %u/%u/%llu %d\n",
                                cex->ec_block, cex->ec_len,
                                (unsigned long long)cex->ec_start,
                                cex->ec_type);
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
        struct ext3_ext_base *base = inode;
        struct bpointers bp;
        int err;

        CDEBUG(D_OTHER, "blocks %lu-%lu requested for inode %u\n",
               block, block + num - 1, (unsigned) inode->i_ino);

        bp.blocks = blocks;
        bp.created = created;
        bp.start = block;
        bp.init_num = bp.num = num;
        bp.create = create;

	err = fsfilt_ext3_ext_walk_space(base, block, num,
					 ext3_ext_new_extent_cb, &bp);
	ext3_ext_invalidate_cache(base);

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
                                cfs_mutex_t *optional_mutex)
{
        int rc;

        if (EXT3_I(inode)->i_flags & EXT3_EXTENTS_FL) {
                rc = fsfilt_ext3_map_ext_inode_pages(inode, page, pages,
                                                     blocks, created, create);
                return rc;
        }
        if (optional_mutex != NULL)
                cfs_mutex_lock(optional_mutex);
        rc = fsfilt_ext3_map_bm_inode_pages(inode, page, pages, blocks,
                                            created, create);
        if (optional_mutex != NULL)
                cfs_mutex_unlock(optional_mutex);

        return rc;
}

int fsfilt_ext3_read(struct inode *inode, void *buf, int size, loff_t *offs)
{
        unsigned long block;
        struct buffer_head *bh;
        int err, blocksize, csize, boffs, osize = size;

        /* prevent reading after eof */
	spin_lock(&inode->i_lock);
        if (i_size_read(inode) < *offs + size) {
                size = i_size_read(inode) - *offs;
		spin_unlock(&inode->i_lock);
                if (size < 0) {
                        CDEBUG(D_EXT2, "size %llu is too short for read @%llu\n",
                               i_size_read(inode), *offs);
                        return -EBADR;
                } else if (size == 0) {
                        return 0;
                }
        } else {
		spin_unlock(&inode->i_lock);
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
        return osize;
}
EXPORT_SYMBOL(fsfilt_ext3_read);

static int fsfilt_ext3_read_record(struct file * file, void *buf,
                                   int size, loff_t *offs)
{
        int rc;
        rc = fsfilt_ext3_read(file->f_dentry->d_inode, buf, size, offs);
        if (rc > 0)
                rc = 0;
        return rc;
}

int fsfilt_ext3_write_handle(struct inode *inode, void *buf, int bufsize,
                                loff_t *offs, handle_t *handle)
{
        struct buffer_head *bh = NULL;
        loff_t old_size = i_size_read(inode), offset = *offs;
        loff_t new_size = i_size_read(inode);
        unsigned long block;
        int err = 0, blocksize = 1 << inode->i_blkbits, size, boffs;

        while (bufsize > 0) {
                if (bh != NULL)
                        brelse(bh);

                block = offset >> inode->i_blkbits;
                boffs = offset & (blocksize - 1);
                size = min(blocksize - boffs, bufsize);
                bh = ext3_bread(handle, inode, block, 1, &err);
                if (!bh) {
                        CERROR("can't read/create block: %d\n", err);
                        break;
                }

                err = ext3_journal_get_write_access(handle, bh);
                if (err) {
                        CERROR("journal_get_write_access() returned error %d\n",
                               err);
                        break;
                }
                LASSERT(bh->b_data + boffs + size <= bh->b_data + bh->b_size);
                memcpy(bh->b_data + boffs, buf, size);
                err = ext3_journal_dirty_metadata(handle, bh);
                if (err) {
                        CERROR("journal_dirty_metadata() returned error %d\n",
                               err);
                        break;
                }
                if (offset + size > new_size)
                        new_size = offset + size;
                offset += size;
                bufsize -= size;
                buf += size;
        }
        if (bh)
                brelse(bh);

        /* correct in-core and on-disk sizes */
        if (new_size > i_size_read(inode)) {
		spin_lock(&inode->i_lock);
                if (new_size > i_size_read(inode))
                        i_size_write(inode, new_size);
                if (i_size_read(inode) > EXT3_I(inode)->i_disksize)
                        EXT3_I(inode)->i_disksize = i_size_read(inode);
                if (i_size_read(inode) > old_size) {
			spin_unlock(&inode->i_lock);
                        mark_inode_dirty(inode);
                } else {
			spin_unlock(&inode->i_lock);
                }
        }

        if (err == 0)
                *offs = offset;
        return err;
}
EXPORT_SYMBOL(fsfilt_ext3_write_handle);

static int fsfilt_ext3_write_record(struct file *file, void *buf, int bufsize,
                                    loff_t *offs, int force_sync)
{
        struct inode *inode = file->f_dentry->d_inode;
        handle_t *handle;
        int err, block_count = 0, blocksize;

        /* Determine how many transaction credits are needed */
        blocksize = 1 << inode->i_blkbits;
        block_count = (*offs & (blocksize - 1)) + bufsize;
        block_count = (block_count + blocksize - 1) >> inode->i_blkbits;

	handle = ext3_journal_start(inode,
			block_count * EXT3_DATA_TRANS_BLOCKS(inode->i_sb) + 2);
	if (IS_ERR(handle)) {
		CERROR("can't start transaction for %d blocks (%d bytes)\n",
		       block_count * EXT3_DATA_TRANS_BLOCKS(inode->i_sb) + 2,
		       bufsize);
		return PTR_ERR(handle);
	}

        err = fsfilt_ext3_write_handle(inode, buf, bufsize, offs, handle);

        if (!err && force_sync)
                handle->h_sync = 1; /* recovery likes this */

        ext3_journal_stop(handle);

        return err;
}

static int fsfilt_ext3_setup(struct super_block *sb)
{
        if (!EXT3_HAS_COMPAT_FEATURE(sb,
                                EXT3_FEATURE_COMPAT_HAS_JOURNAL)) {
                CERROR("ext3 mounted without journal\n");
                return -EINVAL;
        }

#ifdef S_PDIROPS
        CWARN("Enabling PDIROPS\n");
        set_opt(EXT3_SB(sb)->s_mount_opt, PDIROPS);
        sb->s_flags |= S_PDIROPS;
#endif
        if (!EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_DIR_INDEX))
                CWARN("filesystem doesn't have dir_index feature enabled\n");
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

lvfs_sbdev_type fsfilt_ext3_journal_sbdev(struct super_block *sb)
{
        return (EXT3_SB(sb)->journal_bdev);
}
EXPORT_SYMBOL(fsfilt_ext3_journal_sbdev);

static int ll_decode_fh_accept(void *context, struct dentry *de)
{
        return 1;
}

#ifdef HAVE_EXPORTFS_DECODE_FH
# define ll_exportfs_decode_fh(mnt, fid, len, type, acceptable, context) \
         exportfs_decode_fh(mnt, (struct fid*)(fid), len, type,          \
                            acceptable, context)
#else
# define ll_exportfs_decode_fh(mnt, fid, len, type, acceptable, context) \
         export_op_default.decode_fh((mnt)->mnt_sb, &(fid)->ino, len,    \
                                     type, acceptable, context)
# define FILEID_INO32_GEN 1
extern struct export_operations export_op_default;
#endif

struct dentry *fsfilt_ext3_fid2dentry(struct vfsmount *mnt,
                                      struct fsfilt_fid *fid, int ignore_gen)
{
        struct inode  *inode;
        struct dentry *result;

        result = ll_exportfs_decode_fh(mnt, fid, 2, FILEID_INO32_GEN,
                                       ll_decode_fh_accept, NULL);
        if (IS_ERR(result)) {
                CDEBUG(D_DENTRY, "%s of %u/%u failed %ld\n", __func__,
                       fid->ino, fid->gen, PTR_ERR(result));
                return result;
        }

        CDEBUG(D_DENTRY, "%s of %u/%u succeeded\n", __func__,
               fid->ino, fid->gen);
        inode = result->d_inode;
        if (inode == NULL)
                goto err_out;

        if (inode->i_nlink == 0 &&
            inode->i_mode == 0 && LTIME_S(inode->i_ctime) == 0) {
                LCONSOLE_WARN("Found inode with zero nlink, mode and"
                              " ctime -- this may indicate disk "
                              "corruption (inode: %lu, link: %lu, "
                              "count: %d)\n", inode->i_ino,
                              (unsigned long)inode->i_nlink,
                              atomic_read(&inode->i_count));
                goto err_out;
        }
        if (fid->gen && inode->i_generation != fid->gen) {
                /* we didn't find the right inode.. */
                CDEBUG(D_INODE, "found wrong generation: inode %lu, link: %lu, "
                       "count: %d, generation %u/%u\n",
                       inode->i_ino, (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       fid->gen);
                goto err_out;
        }

        return result;
err_out:
        l_dput(result);
        return ERR_PTR(-ENOENT);
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
#ifdef HAVE_DISK_INODE_VERSION
        .fs_get_version         = fsfilt_ext3_get_version,
        .fs_set_version         = fsfilt_ext3_set_version,
#endif
        .fs_journal_sbdev       = fsfilt_ext3_journal_sbdev,
        .fs_fid2dentry          = fsfilt_ext3_fid2dentry,
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

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre ext3 Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
