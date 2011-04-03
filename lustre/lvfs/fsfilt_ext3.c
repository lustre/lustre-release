/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
#ifdef HAVE_EXT4_LDISKFS
#include <ext4/ext4.h>
#include <ext4/ext4_jbd2.h>
#else
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#endif
#include <linux/version.h>
#include <linux/bitops.h>
#include <linux/quota.h>
#ifdef HAVE_QUOTAIO_H
# include <linux/quotaio_v2.h>
#elif defined(HAVE_FS_QUOTA_QUOTAIO_H)
# include <quota/quotaio_v2.h>
# include <quota/quota_tree.h>
# define V2_DQTREEOFF    QT_TREEOFF
#elif defined(HAVE_FS_QUOTAIO_V1_H)
# include <quotaio_v2.h>
# include <quota_tree.h>
# define V2_DQTREEOFF    QT_TREEOFF
# define V2_INITQVERSIONS_R1 V2_INITQVERSIONS
#endif

#ifdef QFMT_VFS_V1
#define QFMT_LUSTRE QFMT_VFS_V1
#else
#define QFMT_LUSTRE QFMT_VFS_V0
#endif

#if defined(HAVE_EXT3_XATTR_H)
#include <ext3/xattr.h>
#else
/* ext3 xattr.h not available in rh style kernel-devel rpm */
extern int ext3_xattr_get(struct inode *, int, const char *, void *, size_t);
extern int ext3_xattr_set_handle(handle_t *, struct inode *, int, const char *, const void *, size_t, int);
#endif

#include <libcfs/libcfs.h>
#include <lustre_fsfilt.h>
#include <obd.h>
#include <lustre_quota.h>
#include <linux/lustre_compat25.h>
#include <linux/lprocfs_status.h>

#ifdef HAVE_EXT4_LDISKFS
#include <ext4/ext4_extents.h>
#else
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

#ifdef EXT_INSERT_EXTENT_WITH_5ARGS
#define fsfilt_ext3_ext_insert_extent(handle, inode, path, newext, flag) \
               ext3_ext_insert_extent(handle, inode, path, newext, flag)
#else
#define fsfilt_ext3_ext_insert_extent(handle, inode, path, newext, flag) \
               ext3_ext_insert_extent(handle, inode, path, newext)
#endif

#ifdef EXT3_DISCARD_PREALLOCATIONS
#define ext3_mb_discard_inode_preallocations(inode) \
                 ext3_discard_preallocations(inode)
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

#ifdef HAVE_EXT4_LDISKFS
#define fsfilt_log_start_commit(journal, tid) jbd2_log_start_commit(journal, tid)
#define fsfilt_log_wait_commit(journal, tid) jbd2_log_wait_commit(journal, tid)
#define fsfilt_journal_callback_set(handle, func, jcb) jbd2_journal_callback_set(handle, func, jcb)
#else
#define fsfilt_log_start_commit(journal, tid) log_start_commit(journal, tid)
#define fsfilt_log_wait_commit(journal, tid) log_wait_commit(journal, tid)
#define fsfilt_journal_callback_set(handle, func, jcb) journal_callback_set(handle, func, jcb)
#define ext_pblock(ex) le32_to_cpu((ex)->ee_start)
#define ext3_ext_store_pblock(ex, pblock)  ((ex)->ee_start = cpu_to_le32(pblock))
#define ext3_inode_bitmap(sb,desc) le32_to_cpu((desc)->bg_inode_bitmap)
#endif

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
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)) && defined(HAVE_EXT4_LDISKFS)
        return inode->i_version;
#else
        return EXT3_I(inode)->i_fs_version;
#endif
}

static void set_i_version(struct inode *inode, __u64 new_version)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)) && defined(HAVE_EXT4_LDISKFS)
        inode->i_version = new_version;
#else
        (EXT3_I(inode))->i_fs_version = new_version;
#endif
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
#if defined(EXT3_EXTENTS_FL) && defined(EXT3_INDEX_FL) && !defined(HAVE_EXT4_LDISKFS)
                static int warned;
                if (!warned) {
                        if (!test_opt(inode->i_sb, EXTENTS)) {
                                warned = 1;
                        } else if (((EXT3_I(inode)->i_flags &
                              cpu_to_le32(EXT3_EXTENTS_FL | EXT3_INDEX_FL)) ==
                              cpu_to_le32(EXT3_EXTENTS_FL | EXT3_INDEX_FL))) {
                                CWARN("extent-mapped directory found with "
                                      "ext3-based ldiskfs - contact "
                                      "http://bugzilla.lustre.org/\n");
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
        needed += hweight32(ll_sb_any_quota_active(sb)) *
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
        iattr->ia_valid &= ~(ATTR_MTIME_SET | ATTR_ATIME_SET);

        if (inode->i_op->setattr) {
                rc = inode->i_op->setattr(dentry, iattr);
        } else {
                rc = inode_change_ok(inode, iattr);
                if (!rc)
                        rc = inode_setattr(inode, iattr);
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

#ifdef HAVE_EXT4_LDISKFS
        /* ext4_ioctl does not have a inode argument */
        if (inode->i_fop->unlocked_ioctl)
                rc = inode->i_fop->unlocked_ioctl(file, cmd, arg);
#else
        if (inode->i_fop->ioctl)
                rc = inode->i_fop->ioctl(inode, file, cmd, arg);
#endif
        else
                RETURN(-ENOTTY);

        RETURN(rc);
}

static int fsfilt_ext3_set_md(struct inode *inode, void *handle,
                              void *lmm, int lmm_size, const char *name)
{
        int rc;

        LASSERT(TRYLOCK_INODE_MUTEX(inode) == 0);

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

        LASSERT(TRYLOCK_INODE_MUTEX(inode) == 0);

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

        OBD_SLAB_ALLOC_PTR_GFP(fcb, fcb_cache, CFS_ALLOC_IO);
        if (fcb == NULL)
                RETURN(-ENOMEM);

        fcb->cb_func = cb_func;
        fcb->cb_obd = obd;
        fcb->cb_last_rcvd = last_rcvd;
        fcb->cb_data = cb_data;

        CDEBUG(D_EXT2, "set callback for last_rcvd: "LPD64"\n", last_rcvd);
        fsfilt_journal_callback_set(handle, fsfilt_ext3_cb_func,
                                    (struct journal_callback *)fcb);

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
        rc = ll_do_statfs(sb, &sfs);
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

#ifndef EXT3_EXTENTS_FL
#define EXT3_EXTENTS_FL                 0x00080000 /* Inode uses extents */
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
# define fsfilt_up_truncate_sem(inode)  up(&LDISKFS_I(inode)->truncate_sem);
# define fsfilt_down_truncate_sem(inode)  down(&LDISKFS_I(inode)->truncate_sem);
#else
# ifdef HAVE_EXT4_LDISKFS
#  ifdef WALK_SPACE_HAS_DATA_SEM /* We only use it in fsfilt_map_nblocks() for now */
#   define fsfilt_up_truncate_sem(inode) do{ }while(0)
#   define fsfilt_down_truncate_sem(inode) do{ }while(0)
#  else
#   define fsfilt_up_truncate_sem(inode) up_write((&EXT4_I(inode)->i_data_sem))
#   define fsfilt_down_truncate_sem(inode) down_write((&EXT4_I(inode)->i_data_sem))
#  endif
# else
#  define fsfilt_up_truncate_sem(inode)  mutex_unlock(&EXT3_I(inode)->truncate_mutex)
#  define fsfilt_down_truncate_sem(inode)  mutex_lock(&EXT3_I(inode)->truncate_mutex)
# endif
#endif

#ifndef EXT_ASSERT
#define EXT_ASSERT(cond)  BUG_ON(!(cond))
#endif

#ifdef EXT3_EXT_HAS_NO_TREE
/* for kernels 2.6.18 and later */
#ifdef HAVE_EXT4_LDISKFS
#define EXT_GENERATION(inode)           (EXT4_I(inode)->i_ext_generation)
#else
#define EXT_GENERATION(inode)           ext_generation(inode)
#endif
#define ext3_ext_base                   inode
#define ext3_ext_base2inode(inode)      (inode)
#define EXT_DEPTH(inode)                ext_depth(inode)
#define fsfilt_ext3_ext_walk_space(inode, block, num, cb, cbdata) \
                        ext3_ext_walk_space(inode, block, num, cb, cbdata);
#else
#define ext3_ext_base                   ext3_extents_tree
#define ext3_ext_base2inode(tree)       (tree->inode)
#define fsfilt_ext3_ext_walk_space(tree, block, num, cb, cbdata) \
                        ext3_ext_walk_space(tree, block, num, cb);
#endif

#ifdef EXT_INSERT_EXTENT_WITH_5ARGS
#define fsfilt_ext3_ext_insert_extent(handle, inode, path, newext, flag) \
               ext3_ext_insert_extent(handle, inode, path, newext, flag)
#else
#define fsfilt_ext3_ext_insert_extent(handle, inode, path, newext, flag) \
               ext3_ext_insert_extent(handle, inode, path, newext)
#endif

#include <linux/lustre_version.h>

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
        fsfilt_up_truncate_sem(inode);

        handle = ext3_journal_start(inode, count+EXT3_ALLOC_NEEDED+1);
        if (IS_ERR(handle)) {
                fsfilt_down_truncate_sem(inode);
                return PTR_ERR(handle);
        }

        fsfilt_down_truncate_sem(inode);
        if (tgen != EXT_GENERATION(base)) {
                /* the tree has changed. so path can be invalid at moment */
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

        fsfilt_down_truncate_sem(inode);
        err = fsfilt_ext3_ext_walk_space(base, block, num,
                                         ext3_ext_new_extent_cb, &bp);
        ext3_ext_invalidate_cache(base);
        fsfilt_up_truncate_sem(inode);

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
                                cfs_semaphore_t *optional_sem)
{
        int rc;

        if (EXT3_I(inode)->i_flags & EXT3_EXTENTS_FL) {
                rc = fsfilt_ext3_map_ext_inode_pages(inode, page, pages,
                                                     blocks, created, create);
                return rc;
        }
        if (optional_sem != NULL)
                cfs_down(optional_sem);
        rc = fsfilt_ext3_map_bm_inode_pages(inode, page, pages, blocks,
                                            created, create);
        if (optional_sem != NULL)
                cfs_up(optional_sem);

        return rc;
}

int fsfilt_ext3_read(struct inode *inode, void *buf, int size, loff_t *offs)
{
        unsigned long block;
        struct buffer_head *bh;
        int err, blocksize, csize, boffs, osize = size;

        /* prevent reading after eof */
        cfs_lock_kernel();
        if (i_size_read(inode) < *offs + size) {
                size = i_size_read(inode) - *offs;
                cfs_unlock_kernel();
                if (size < 0) {
                        CDEBUG(D_EXT2, "size %llu is too short for read @%llu\n",
                               i_size_read(inode), *offs);
                        return -EBADR;
                } else if (size == 0) {
                        return 0;
                }
        } else {
                cfs_unlock_kernel();
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
                cfs_lock_kernel();
                if (new_size > i_size_read(inode))
                        i_size_write(inode, new_size);
                if (i_size_read(inode) > EXT3_I(inode)->i_disksize)
                        EXT3_I(inode)->i_disksize = i_size_read(inode);
                if (i_size_read(inode) > old_size)
                        mark_inode_dirty(inode);
                cfs_unlock_kernel();
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
                               block_count * FSFILT_DATA_TRANS_BLOCKS(inode->i_sb) + 2);
        if (IS_ERR(handle)) {
                CERROR("can't start transaction for %d blocks (%d bytes)\n",
                       block_count * FSFILT_DATA_TRANS_BLOCKS(inode->i_sb) + 2, bufsize);
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
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) && \
     defined(HAVE_QUOTA_SUPPORT)) || defined(S_PDIROPS)
        struct ext3_sb_info *sbi = EXT3_SB(sb);
#if 0
        sbi->dx_lock = fsfilt_ext3_dx_lock;
        sbi->dx_unlock = fsfilt_ext3_dx_unlock;
#endif
#endif
#ifdef S_PDIROPS
        CWARN("Enabling PDIROPS\n");
        set_opt(sbi->s_mount_opt, PDIROPS);
        sb->s_flags |= S_PDIROPS;
#endif
        if (!EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_DIR_INDEX))
                CWARN("filesystem doesn't have dir_index feature enabled\n");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) && defined(HAVE_QUOTA_SUPPORT)
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
        sbi->s_jquota_fmt = QFMT_LUSTRE;
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

#ifdef HAVE_QUOTA_SUPPORT
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
        const struct quotactl_ops *qcop;
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
                                char *name[MAXQUOTAS] = LUSTRE_OPQFILES_NAMES_V2;

                                LASSERT(oqc->qc_id == LUSTRE_QUOTA_V2);

                                rc = ll_quota_on(sb, i, QFMT_LUSTRE,
                                                 name[i], 0);
                        } else if (oqc->qc_cmd == Q_QUOTAOFF) {
                                rc = ll_quota_off(sb, i, 0);
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
                        char *name[MAXQUOTAS] = LUSTRE_OPQFILES_NAMES_V2;

                        LASSERT(oqc->qc_id == LUSTRE_QUOTA_V2);

                        if (!Q_TYPESET(oqc, i))
                                continue;

                        fp = filp_open(name[i], O_CREAT | O_TRUNC | O_RDWR, 0644);
                        if (IS_ERR(fp)) {
                                rc = PTR_ERR(fp);
                                CERROR("error invalidating operational quota file"
                                       " %s (rc:%d)\n", name[i], rc);
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
                CDEBUG(D_QUOTA, "quotactl command %#x, id %u, type %u "
                                "failed: %d\n",
                       oqc->qc_cmd, oqc->qc_id, oqc->qc_type, rc);
        RETURN(rc);
}

struct chk_dqblk{
        cfs_hlist_node_t        dqb_hash;        /** quotacheck hash */
        cfs_list_t              dqb_list;        /** in list also */
        qid_t                   dqb_id;          /** uid/gid */
        short                   dqb_type;        /** USRQUOTA/GRPQUOTA */
        qsize_t                 dqb_bhardlimit;  /** block hard limit */
        qsize_t                 dqb_bsoftlimit;  /** block soft limit */
        qsize_t                 dqb_curspace;    /** current space */
        qsize_t                 dqb_ihardlimit;  /** inode hard limit */
        qsize_t                 dqb_isoftlimit;  /** inode soft limit */
        qsize_t                 dqb_curinodes;   /** current inodes */
        obd_time                dqb_btime;       /** block grace time */
        obd_time                dqb_itime;       /** inode grace time */
        __u32                   dqb_valid;       /** flag for above fields */
};

static inline unsigned int chkquot_hash(qid_t id, int type)
                                        __attribute__((__const__));

static inline unsigned int chkquot_hash(qid_t id, int type)
{
        return (id * (MAXQUOTAS - type)) % NR_DQHASH;
}

static inline struct chk_dqblk *
find_chkquot(cfs_hlist_head_t *head, qid_t id, int type)
{
        cfs_hlist_node_t *node;
        struct chk_dqblk *cdqb;

        cfs_hlist_for_each(node, head) {
                cdqb = cfs_hlist_entry(node, struct chk_dqblk, dqb_hash);
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
                CFS_INIT_HLIST_NODE(&cdqb->dqb_hash);
                CFS_INIT_LIST_HEAD(&cdqb->dqb_list);
                cdqb->dqb_id = id;
                cdqb->dqb_type = type;
        }

        return cdqb;
}

static struct chk_dqblk *
cqget(struct super_block *sb, cfs_hlist_head_t *hash,
      cfs_list_t *list, qid_t id, int type, int first_check)
{
        cfs_hlist_head_t *head = hash + chkquot_hash(id, type);
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

        cfs_hlist_add_head(&cdqb->dqb_hash, head);
        cfs_list_add_tail(&cdqb->dqb_list, list);

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

#ifndef HAVE_EXT4_LDISKFS
static inline struct ext3_group_desc *
get_group_desc(struct super_block *sb, int group, struct buffer_head **bh)
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
ext3_read_inode_bitmap(struct super_block *sb, unsigned long group)
{
        struct ext3_group_desc *desc;
        struct buffer_head *bh;

        desc = get_group_desc(sb, group, NULL);
        bh = sb_bread(sb, ext3_inode_bitmap(sb, desc));
        return bh;
}

static __u32 ext3_itable_unused_count(struct super_block *sb,
                               struct ext3_group_desc *bg) {
       return le16_to_cpu(bg->bg_itable_unused);
}
#else
#define get_group_desc ext3_get_group_desc
#endif

struct qchk_ctxt {
        cfs_hlist_head_t        qckt_hash[NR_DQHASH];      /* quotacheck hash */
        cfs_list_t              qckt_list;                 /* quotacheck list */
        int                     qckt_first_check[MAXQUOTAS]; /* 1 if no old quotafile */
        struct if_dqinfo        qckt_dqinfo[MAXQUOTAS];    /* old dqinfo */
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

/* write dqinfo struct in a new quota file */
static int v3_write_dqinfo(struct file *f, int type, struct if_dqinfo *info)
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

static int v3_write_dqheader(struct file *f, int type)
{
        static const __u32 quota_magics[] = V2_INITQMAGICS;
        static const __u32 quota_versions[] = LUSTRE_INITQVERSIONS_V2;
        struct v2_disk_dqheader dqhead;
        loff_t offset = 0;

        CLASSERT(ARRAY_SIZE(quota_magics) == ARRAY_SIZE(quota_versions));
        LASSERT(0 <= type && type < ARRAY_SIZE(quota_magics));

        dqhead.dqh_magic = cpu_to_le32(quota_magics[type]);
        dqhead.dqh_version = cpu_to_le32(quota_versions[type]);

        return cfs_user_write(f, (char *)&dqhead, sizeof(dqhead), &offset);
}

static int create_new_quota_files(struct qchk_ctxt *qctxt,
                                  struct obd_quotactl *oqc)
{
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < MAXQUOTAS; i++) {
                struct if_dqinfo *info = qctxt->qckt_first_check[i]?
                                         NULL : &qctxt->qckt_dqinfo[i];
                struct file *file;
                const char *name[MAXQUOTAS] = LUSTRE_OPQFILES_NAMES_V2;

                if (!Q_TYPESET(oqc, i))
                        continue;

                LASSERT(oqc->qc_id == LUSTRE_QUOTA_V2);

                file = filp_open(name[i], O_RDWR | O_CREAT | O_TRUNC, 0644);
                if (IS_ERR(file)) {
                        rc = PTR_ERR(file);
                        CERROR("can't create %s file: rc = %d\n",
                               name[i], rc);
                        GOTO(out, rc);
                }

                if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                        CERROR("file %s is not regular", name[i]);
                        filp_close(file, 0);
                        GOTO(out, rc = -EINVAL);
                }

                ll_vfs_dq_drop(file->f_dentry->d_inode);

                rc = v3_write_dqheader(file, i);
                if (rc) {
                        filp_close(file, 0);
                        GOTO(out, rc);
                }

                rc = v3_write_dqinfo(file, i, info);
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

        now = cfs_time_current_sec();

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

        cfs_list_for_each_entry_safe(cdqb, tmp, &qctxt->qckt_list, dqb_list) {
                if (!error) {
                        rc = commit_chkquot(sb, qctxt, cdqb);
                        if (rc)
                                error = rc;
                }
                cfs_hlist_del_init(&cdqb->dqb_hash);
                cfs_list_del(&cdqb->dqb_list);
                OBD_FREE_PTR(cdqb);
        }

        return error;
}

#ifndef EXT3_FEATURE_RO_COMPAT_GDT_CSUM
#define EXT3_FEATURE_RO_COMPAT_GDT_CSUM 0x0010
#endif

static int fsfilt_ext3_quotacheck(struct super_block *sb,
                                  struct obd_quotactl *oqc)
{
        struct ext3_sb_info *sbi = EXT3_SB(sb);
        int i, group, uninit_feat = 0;
        struct qchk_ctxt *qctxt;
        struct buffer_head *bitmap_bh = NULL;
        unsigned long ino, inode_inuse;
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
                CFS_INIT_HLIST_HEAD(&qctxt->qckt_hash[i]);
        CFS_INIT_LIST_HEAD(&qctxt->qckt_list);

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
        if (EXT3_HAS_RO_COMPAT_FEATURE(sb, EXT3_FEATURE_RO_COMPAT_GDT_CSUM))
                /* This filesystem supports the uninit group feature */
                uninit_feat = 1;

        /* number of inodes that have been allocated */
        inode_inuse = sbi->s_inodes_per_group * sbi->s_groups_count -
                      percpu_counter_sum(&sbi->s_freeinodes_counter);

        /* check quota and update in hash */
        for (group = 0; group < sbi->s_groups_count && inode_inuse > 0;
             group++) {
                unsigned long used_count = sbi->s_inodes_per_group;

                if (uninit_feat) {
                        struct ext3_group_desc *desc;
                        desc = get_group_desc(sb, group, NULL);
                        if (!desc)
                                GOTO(out, -EIO);

                        /* we don't really need to take the group lock here,
                         * but it may be useful if one day we support online
                         * quotacheck */
#ifdef HAVE_EXT4_LDISKFS
                        ext4_lock_group(sb, group);
#else
                        spin_lock(sb_bgl_lock(sbi, group));
#endif
                        if (desc->bg_flags & cpu_to_le16(EXT3_BG_INODE_UNINIT)) {
                                /* no inode in use in this group, just skip it */
#ifdef HAVE_EXT4_LDISKFS
                                ext3_unlock_group(sb, group);
#else
                                spin_unlock(sb_bgl_lock(sbi, group));
#endif
                                continue;
                        }

                        used_count -= ext3_itable_unused_count(sb, desc);
#ifdef HAVE_EXT4_LDISKFS
                        ext3_unlock_group(sb, group);
#else
                        spin_unlock(sb_bgl_lock(sbi, group));
#endif
                }

                ino = group * sbi->s_inodes_per_group + 1;
                bitmap_bh = ext3_read_inode_bitmap(sb, group);
                if (!bitmap_bh) {
                        CERROR("%s: ext3_read_inode_bitmap group %d failed\n",
                               sb->s_id, group);
                        GOTO(out, -EIO);
                }

                i = 0;
                while (i < used_count &&
                       (i = ext3_find_next_bit(bitmap_bh->b_data,
                                               used_count, i)) < used_count) {
                        inode_inuse--;
                        i++;
                        ino = i + group * sbi->s_inodes_per_group;
                        if (ino < sbi->s_first_ino)
                                continue;
#if defined(HAVE_EXT4_LDISKFS) || !defined(HAVE_READ_INODE_IN_SBOPS)
                        inode = ext3_iget(sb, ino);
#else
                        inode = iget(sb, ino);
#endif
                        if (!inode || IS_ERR(inode))
                                continue;

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
                cfs_list_t id_list;
                struct dquot_id *dqid, *tmp;

                if (!Q_TYPESET(oqc, i))
                        continue;

                if (qctxt->qckt_first_check[i])
                        continue;


                LASSERT(sb_dqopt(sb)->files[i] != NULL);
                CFS_INIT_LIST_HEAD(&id_list);
#ifndef KERNEL_SUPPORTS_QUOTA_READ
                rc = lustre_get_qids(sb_dqopt(sb)->files[i], NULL, i, &id_list);
#else
                rc = lustre_get_qids(NULL, sb_dqopt(sb)->files[i], i, &id_list);
#endif
                if (rc)
                        CERROR("read old limits failed. (rc:%d)\n", rc);

                cfs_list_for_each_entry_safe(dqid, tmp, &id_list, di_link) {
                        cfs_list_del_init(&dqid->di_link);

                        if (!rc)
                                cqget(sb, qctxt->qckt_hash, &qctxt->qckt_list,
                                      dqid->di_id, i,
                                      qctxt->qckt_first_check[i]);
                        OBD_FREE_PTR(dqid);
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

static int fsfilt_ext3_quotainfo(struct lustre_quota_info *lqi, int type,
                                 int cmd)
{
        int rc = 0;
        ENTRY;

        if (lqi->qi_files[type] == NULL) {
                CERROR("operate qinfo before it's enabled!\n");
                RETURN(-ESRCH);
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
                rc = -ENOTSUPP;
                CERROR("quota CONVERT command is not supported\n");
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
                            cfs_list_t *list)
{
        return lustre_get_qids(file, inode, type, list);
}

static int fsfilt_ext3_dquot(struct lustre_dquot *dquot, int cmd)
{
        int rc = 0;
        ENTRY;

        if (dquot->dq_info->qi_files[dquot->dq_type] == NULL) {
                CERROR("operate dquot before it's enabled!\n");
                RETURN(-ESRCH);
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
                        cfs_clear_bit(DQ_FAKE_B, &dquot->dq_flags);
                else
                        cfs_set_bit(DQ_FAKE_B, &dquot->dq_flags);

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

static int fsfilt_ext3_get_mblk(struct super_block *sb, int *count,
                                struct inode *inode, int frags)
{
#ifdef EXT3_EXT_HAS_NO_TREE
        struct ext3_ext_base *base = inode;
#else
        struct ext3_extents_tree tree;
        struct ext3_ext_base *base = &tree;

        ext3_init_tree_desc(base, inode);
#endif
        /* for an ost_write request, it needs <#fragments> * <tree depth + 1>
         * metablocks at maxium b=16542 */
        *count = frags * (EXT_DEPTH(base) + 1) * EXT3_BLOCK_SIZE(sb);
        return 0;
}

#endif

lvfs_sbdev_type fsfilt_ext3_journal_sbdev(struct super_block *sb)
{
        return (EXT3_SB(sb)->journal_bdev);
}
EXPORT_SYMBOL(fsfilt_ext3_journal_sbdev);

ssize_t lustre_read_quota(struct file *f, struct inode *inode, int type,
                          char *buf, int count, loff_t pos)
{
        loff_t p = pos;
        int rc;

        if (!f && !inode) {
                CERROR("lustre_read_quota failed for no quota file!\n");
                libcfs_debug_dumpstack(NULL);
                return -EINVAL;
        }

        /* Support for both adm and op quota files must be provided */
        if (f) {
                rc = fsfilt_ext3_read_record(f, buf, count, &p);
                rc = rc < 0 ? rc : p - pos;
        } else {
                struct super_block *sb = inode->i_sb;
                rc = sb->s_op->quota_read(sb, type, buf, count, pos);
        }
        return rc;
}

ssize_t lustre_write_quota(struct file *f, char *buf, int count, loff_t pos)
{
        loff_t p = pos;
        int rc;

        /* Only adm quota files are supported, op updates are handled by vfs */
        rc = fsfilt_ext3_write_record(f, buf, count, &p, 0);
        rc = rc < 0 ? rc : p - pos;

        return rc;
}

void *lustre_quota_journal_start(struct inode *inode, int delete)
{
        handle_t *handle;
        unsigned block_count;

        if (delete) {
                /* each indirect block (+4) may become free, attaching to the
                 * header list of free blocks (+1); the data block (+1) may
                 * become a free block (+0) or a block with free dqentries (+0) */
                block_count = (4 + 1) + 1;
                handle = ext3_journal_start(inode,
                            block_count*FSFILT_DATA_TRANS_BLOCKS(inode->i_sb)+2);
        } else {
                /* indirect blocks are touched (+4), each causes file expansion (+0) or
                 * freeblk reusage with a header update (+1); dqentry is either reused
                 * causing update of the entry block (+1), prev (+1) and next (+1) or
                 * a new block allocation (+1) with a header update (+1)              */
                block_count = (4 + 1) + 3;
                handle = ext3_journal_start(inode,
                             block_count*FSFILT_DATA_TRANS_BLOCKS(inode->i_sb)+2);

        }

        return handle;
}

void lustre_quota_journal_stop(void *handle)
{
        ext3_journal_stop((handle_t *)handle);
}

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
#ifdef HAVE_QUOTA_SUPPORT
        .fs_quotactl            = fsfilt_ext3_quotactl,
        .fs_quotacheck          = fsfilt_ext3_quotacheck,
        .fs_quotainfo           = fsfilt_ext3_quotainfo,
        .fs_qids                = fsfilt_ext3_qids,
        .fs_dquot               = fsfilt_ext3_dquot,
        .fs_get_mblk            = fsfilt_ext3_get_mblk,
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
