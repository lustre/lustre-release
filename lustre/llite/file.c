/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/lustre_dlm.h>
#include <linux/lustre_lite.h>
#include <linux/obd_lov.h>      /* for lov_mds_md_size() in lov_setstripe() */
#include <linux/random.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/lustre_compat25.h>
#endif
#include "llite_internal.h"

int ll_mdc_close(struct obd_export *mdc_exp, struct inode *inode,
                        struct file *file)
{
        struct ll_file_data *fd = file->private_data;
        struct ptlrpc_request *req = NULL;
        struct obd_client_handle *och = &fd->fd_mds_och;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obdo obdo;
        int rc, valid;
        ENTRY;

        valid = OBD_MD_FLID;
        if (test_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags))
                valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

        memset(&obdo, 0, sizeof(obdo));
        obdo.o_id = inode->i_ino;
        obdo.o_mode = inode->i_mode;
        obdo.o_size = inode->i_size;
        obdo.o_blocks = inode->i_blocks;
        if (0 /* ll_is_inode_dirty(inode) */) {
                obdo.o_flags = MDS_BFLAG_UNCOMMITTED_WRITES;
                valid |= OBD_MD_FLFLAGS;
        }
        obdo.o_valid = valid;
        rc = mdc_close(mdc_exp, &obdo, och, &req);
        if (rc == EAGAIN) {
                /* We are the last writer, so the MDS has instructed us to get
                 * the file size and any write cookies, then close again. */
                //ll_queue_done_writing(inode);
                rc = 0;
        } else if (rc) {
                CERROR("inode %lu mdc close failed: rc = %d\n",
                       inode->i_ino, rc);
        }
        if (rc == 0) {
                rc = ll_objects_destroy(req, file->f_dentry->d_inode);
                if (rc)
                        CERROR("inode %lu ll_objects destroy: rc = %d\n",
                               inode->i_ino, rc);
        }

        mdc_clear_open_replay_data(och);
        ptlrpc_req_finished(req);
        och->och_fh.cookie = DEAD_HANDLE_MAGIC;
        file->private_data = NULL;
        OBD_SLAB_FREE(fd, ll_file_data_slab, sizeof *fd);

        RETURN(rc);
}

/* While this returns an error code, fput() the caller does not, so we need
 * to make every effort to clean up all of our state here.  Also, applications
 * rarely check close errors and even if an error is returned they will not
 * re-try the close call.
 */
int ll_file_release(struct inode *inode, struct file *file)
{
        struct ll_file_data *fd;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc;

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry)
                RETURN(0);

        lprocfs_counter_incr(sbi->ll_stats, LPROC_LL_RELEASE);
        fd = (struct ll_file_data *)file->private_data;
        LASSERT(fd != NULL);

        rc = ll_mdc_close(sbi->ll_mdc_exp, inode, file);
        RETURN(rc);
}

static int ll_intent_file_open(struct file *file, void *lmm,
                               int lmmsize, struct lookup_intent *itp)
{
        struct ll_sb_info *sbi = ll_i2sbi(file->f_dentry->d_inode);
        struct lustre_handle lockh;
        struct mdc_op_data data;
        struct dentry *parent = file->f_dentry->d_parent;
        const char *name = file->f_dentry->d_name.name;
        const int len = file->f_dentry->d_name.len;
        int rc;

        if (!parent)
                RETURN(-ENOENT);

        ll_prepare_mdc_op_data(&data, parent->d_inode, NULL, name, len, O_RDWR);

        rc = mdc_enqueue(sbi->ll_mdc_exp, LDLM_PLAIN, itp, LCK_PR, &data,
                         &lockh, lmm, lmmsize, ldlm_completion_ast,
                         ll_mdc_blocking_ast, parent->d_inode);
        if (rc < 0)
                CERROR("lock enqueue: err: %d\n", rc);
        RETURN(rc);
}

int ll_local_open(struct file *file, struct lookup_intent *it)
{
        struct ptlrpc_request *req = it->d.lustre.it_data;
        struct ll_inode_info *lli = ll_i2info(file->f_dentry->d_inode);
        struct ll_file_data *fd;
        struct mds_body *body;
        ENTRY;

        body = lustre_msg_buf (req->rq_repmsg, 1, sizeof (*body));
        LASSERT (body != NULL);                 /* reply already checked out */
        LASSERT_REPSWABBED (req, 1);            /* and swabbed down */

        LASSERT(!file->private_data);

        OBD_SLAB_ALLOC(fd, ll_file_data_slab, SLAB_KERNEL, sizeof *fd);
        /* We can't handle this well without reorganizing ll_file_open and
         * ll_mdc_close, so don't even try right now. */
        LASSERT(fd != NULL);

        memcpy(&fd->fd_mds_och.och_fh, &body->handle, sizeof(body->handle));
        fd->fd_mds_och.och_magic = OBD_CLIENT_HANDLE_MAGIC;
        file->private_data = fd;

        lli->lli_io_epoch = body->io_epoch;

        mdc_set_open_replay_data(&fd->fd_mds_och, it->d.lustre.it_data);

        RETURN(0);
}

/* Open a file, and (for the very first open) create objects on the OSTs at
 * this time.  If opened with O_LOV_DELAY_CREATE, then we don't do the object
 * creation or open until ll_lov_setstripe() ioctl is called.  We grab
 * lli_open_sem to ensure no other process will create objects, send the
 * stripe MD to the MDS, or try to destroy the objects if that fails.
 *
 * If we already have the stripe MD locally then we don't request it in
 * mdc_open(), by passing a lmm_size = 0.
 *
 * It is up to the application to ensure no other processes open this file
 * in the O_LOV_DELAY_CREATE case, or the default striping pattern will be
 * used.  We might be able to avoid races of that sort by getting lli_open_sem
 * before returning in the O_LOV_DELAY_CREATE case and dropping it here
 * or in ll_file_release(), but I'm not sure that is desirable/necessary.
 */
int ll_file_open(struct inode *inode, struct file *file)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lookup_intent *it;
        struct lov_stripe_md *lsm;
        struct ptlrpc_request *req;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry)
                RETURN(0);

        it = file->f_it;

        if (!it->d.lustre.it_disposition) {
                struct lookup_intent oit = { .it_op = IT_OPEN,
                                             .it_flags = file->f_flags };
                it = &oit;
                rc = ll_intent_file_open(file, NULL, 0, it);
                if (rc)
                        GOTO(out, rc);
        }

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_OPEN);
        rc = it_open_error(DISP_OPEN_OPEN, it);
        if (rc)
                GOTO(out, rc);

        rc = ll_local_open(file, it);
        if (rc)
                LBUG();

        if (!S_ISREG(inode->i_mode))
                GOTO(out, rc);

        lsm = lli->lli_smd;
        if (lsm == NULL) {
                if (file->f_flags & O_LOV_DELAY_CREATE ||
                    !(file->f_mode & FMODE_WRITE)) {
                        CDEBUG(D_INODE, "object creation was delayed\n");
                        GOTO(out, rc);
                }
        }
        file->f_flags &= ~O_LOV_DELAY_CREATE;
        GOTO(out, rc);
 out:
        req = it->d.lustre.it_data;
        ptlrpc_req_finished(req);
        if (rc == 0)
                ll_open_complete(inode);
        return rc;
}

/* Fills the obdo with the attributes for the inode defined by lsm */
int ll_lsm_getattr(struct obd_export *exp, struct lov_stripe_md *lsm,
                   struct obdo *oa)
{
        struct ptlrpc_request_set *set;
        int rc;
        ENTRY;

        LASSERT(lsm != NULL);

        memset(oa, 0, sizeof *oa);
        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = S_IFREG;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ | OBD_MD_FLMTIME |
                OBD_MD_FLCTIME;

        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR ("ENOMEM allocing request set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_getattr_async(exp, oa, lsm, set);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                ptlrpc_set_destroy(set);
        }
        if (rc)
                RETURN(rc);

        oa->o_valid &= (OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ | OBD_MD_FLMTIME | 
                        OBD_MD_FLCTIME | OBD_MD_FLSIZE);
        RETURN(0);
}

static inline void ll_remove_suid(struct inode *inode)
{
        unsigned int mode;

        /* set S_IGID if S_IXGRP is set, and always set S_ISUID */
        mode = (inode->i_mode & S_IXGRP)*(S_ISGID/S_IXGRP) | S_ISUID;

        /* was any of the uid bits set? */
        mode &= inode->i_mode;
        if (mode && !capable(CAP_FSETID)) {
                inode->i_mode &= ~mode;
                // XXX careful here - we cannot change the size
        }
}

/* Flush the page cache for an extent as its canceled.  No one can dirty the
 * extent until we've finished our work and they can enqueue another lock.
 * The DLM protects us from ll_file_read/write here, but other kernel actors
 * could have pages locked */
void ll_pgcache_remove_extent(struct inode *inode, struct lov_stripe_md *lsm,
                              struct ldlm_lock *lock)
{
        struct ldlm_extent *extent = &lock->l_policy_data.l_extent;
        struct obd_export *exp = ll_i2obdexp(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        unsigned long start, end, i;
        struct page *page;
        int rc, discard = lock->l_flags & LDLM_FL_DISCARD_DATA;
        ENTRY;

        CDEBUG(D_INODE, "obdo %lu inode %p ["LPU64"->"LPU64"] size: %llu\n",
               inode->i_ino, inode, extent->start, extent->end, inode->i_size);

        start = extent->start >> PAGE_CACHE_SHIFT;
        end = (extent->end >> PAGE_CACHE_SHIFT) + 1;
        if ((end << PAGE_CACHE_SHIFT) < extent->end)
                end = ~0;

        i = (inode->i_size + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
        if (end >= i)
                clear_bit(LLI_F_HAVE_OST_SIZE_LOCK,
                          &(ll_i2info(inode)->lli_flags));
        if (i < end)
                end = i;

        CDEBUG(D_INODE, "walking page indices start: %lu end: %lu\n", start,
               end);

        for (i = start; i < end; i++) {
                ll_pgcache_lock(inode->i_mapping);
                if (list_empty(&inode->i_mapping->dirty_pages) &&
                     list_empty(&inode->i_mapping->clean_pages) &&
                     list_empty(&inode->i_mapping->locked_pages)) {
                        CDEBUG(D_INODE, "nothing left\n");
                        ll_pgcache_unlock(inode->i_mapping);
                        break;
                }
                ll_pgcache_unlock(inode->i_mapping);

                conditional_schedule();

                page = find_get_page(inode->i_mapping, i);
                if (page == NULL)
                        continue;

                LL_CDEBUG_PAGE(page, "locking\n");
                lock_page(page);

                /* page->mapping to check with racing against teardown */
                if (page->mapping && PageDirty(page) && !discard) {
                        ClearPageDirty(page);
                        LL_CDEBUG_PAGE(page, "found dirty\n");
                        ll_pgcache_lock(inode->i_mapping);
                        list_del(&page->list);
                        list_add(&page->list, &inode->i_mapping->locked_pages);
                        ll_pgcache_unlock(inode->i_mapping);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        rc = inode->i_mapping->a_ops->writepage(page);
#else
                        rc = inode->i_mapping->a_ops->writepage(page, NULL);
#endif
                        if (rc != 0) {
                                CERROR("writepage of page %p failed: %d\n",
                                       page, rc);
                        } else {
                                lock_page(page); /* wait for io to complete */
                        }
                }

                /* checking again to account for writeback's lock_page() */
                if (page->mapping != NULL) {
                        LL_CDEBUG_PAGE(page, "truncating\n");
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        truncate_complete_page(page);
#else
                        truncate_complete_page(page->mapping, page);
#endif
                }
                unlock_page(page);
                page_cache_release(page);
        }

        if (test_bit(LLI_F_PREFER_EXTENDED_SIZE, &lli->lli_flags)) {
                rc = obd_lock_contains(exp, lsm, lock, inode->i_size - 1);
                if (rc != 0) {
                        if (rc < 0)
                                CERROR("obd_lock_contains: rc = %d\n", rc);
                        clear_bit(LLI_F_PREFER_EXTENDED_SIZE, &lli->lli_flags);
                }
        }

        EXIT;
}

static int ll_extent_lock_callback(struct ldlm_lock *lock,
                                   struct ldlm_lock_desc *new, void *data,
                                   int flag)
{
        struct lustre_handle lockh = { 0 };
        int rc;
        ENTRY;


        if ((unsigned long)data > 0 && (unsigned long)data < 0x1000) {
                LDLM_ERROR(lock, "cancelling lock with bad data %p", data);
                LBUG();
        }

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc != ELDLM_OK)
                        CERROR("ldlm_cli_cancel failed: %d\n", rc);
                break;
        case LDLM_CB_CANCELING: {
                struct inode *inode = ll_inode_from_lock(lock);
                struct ll_inode_info *lli;

                if (!inode)
                        RETURN(0);
                lli= ll_i2info(inode);
                if (!lli)
                        RETURN(0);
                if (!lli->lli_smd)
                        RETURN(0);

                ll_pgcache_remove_extent(inode, lli->lli_smd, lock);
                //ll_try_done_writing(inode);
                iput(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

/*
 * some callers, notably truncate, really don't want i_size set based
 * on the the size returned by the getattr, or lock acquisition in
 * the future.
 */
int ll_extent_lock_no_validate(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm,
                   int mode, struct ldlm_extent *extent,
                   struct lustre_handle *lockh, int ast_flags)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc;
        ENTRY;

        LASSERT(lockh->cookie == 0);

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        CDEBUG(D_DLMTRACE, "Locking inode %lu, start "LPU64" end "LPU64"\n",
               inode->i_ino, extent->start, extent->end);

        rc = obd_enqueue(sbi->ll_osc_exp, lsm, NULL, LDLM_EXTENT, extent,
                         sizeof(extent), mode, &ast_flags,
                         ll_extent_lock_callback, inode, lockh);
        if (rc > 0)
                rc = -EIO;
        RETURN(rc);
}

/*
 * this grabs a lock and manually implements behaviour that makes it look like
 * the OST is returning the file size with each lock acquisition.
 */
int ll_extent_lock(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm, int mode,
                   struct ldlm_extent *extent, struct lustre_handle *lockh)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_export *exp = ll_i2obdexp(inode);
        struct ldlm_extent size_lock;
        struct lustre_handle match_lockh = {0};
        struct obdo oa;
        obd_flag refresh_valid;
        int flags, rc, matched;
        ENTRY;

        rc = ll_extent_lock_no_validate(fd, inode, lsm, mode, extent, lockh, 0);
        if (rc != ELDLM_OK)
                RETURN(rc);

        if (test_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags))
                RETURN(0);

        rc = ll_lsm_getattr(exp, lsm, &oa);
        if (rc) {
                ll_extent_unlock(fd, inode, lsm, mode, lockh);
                RETURN(rc);
        }

        /* We set this flag in commit write as we extend the file size.  When
         * the bit is set and the lock is canceled that covers the file size,
         * we clear the bit.  This is enough to protect the window where our
         * local size extension is needed for writeback.  However, it relies on
         * behaviour that won't be true in the near future.  This assumes that
         * all getattr callers get extent locks, which they currnetly do.  It
         * also assumes that we only send discarding asts for {0,eof} truncates
         * as is currently the case.  This will have to be replaced by the
         * proper eoc communication between clients and the ost, which is on
         * its way. */
        refresh_valid = (OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ | OBD_MD_FLMTIME | 
                         OBD_MD_FLCTIME | OBD_MD_FLSIZE);
        if (test_bit(LLI_F_PREFER_EXTENDED_SIZE, &lli->lli_flags)) {
                if (oa.o_size < inode->i_size)
                        refresh_valid &= ~OBD_MD_FLSIZE;
                else 
                        clear_bit(LLI_F_PREFER_EXTENDED_SIZE, &lli->lli_flags);
        }
        obdo_refresh_inode(inode, &oa, refresh_valid);

        CDEBUG(D_INODE, "objid "LPX64" size %Lu, blocks %lu, blksize %lu\n",
               lsm->lsm_object_id, inode->i_size, inode->i_blocks,
               inode->i_blksize);

        size_lock.start = inode->i_size;
        size_lock.end = OBD_OBJECT_EOF;

        /* XXX I bet we should be checking the lock ignore flags.. */
        flags = LDLM_FL_CBPENDING | LDLM_FL_BLOCK_GRANTED;
        matched = obd_match(exp, lsm, LDLM_EXTENT, &size_lock,
                            sizeof(size_lock), LCK_PR, &flags, inode,
                            &match_lockh);
        if (matched < 0)
                RETURN(matched);

        /* hey, alright, we hold a size lock that covers the size we
         * just found, its not going to change for a while.. */
        if (matched == 1) {
                set_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags);
                obd_cancel(exp, lsm, LCK_PR, &match_lockh);
        }

        RETURN(0);
}

int ll_extent_unlock(struct ll_file_data *fd, struct inode *inode,
                     struct lov_stripe_md *lsm, int mode,
                     struct lustre_handle *lockh)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc;
        ENTRY;

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        rc = obd_cancel(sbi->ll_osc_exp, lsm, mode, lockh);

        RETURN(rc);
}

static ssize_t ll_file_read(struct file *filp, char *buf, size_t count,
                            loff_t *ppos)
{
        struct ll_file_data *fd = filp->private_data;
        struct inode *inode = filp->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct lustre_handle lockh = { 0 };
        struct ldlm_extent extent;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size="LPSZ",offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, count, *ppos);

        /* "If nbyte is 0, read() will return 0 and have no other results."
         *                      -- Single Unix Spec */
        if (count == 0)
                RETURN(0);

        lprocfs_counter_add(ll_i2sbi(inode)->ll_stats, LPROC_LL_READ_BYTES,
                            count);

        if (!lsm)
                RETURN(0);

        /* grab a -> eof extent to push extending writes out of node's caches
         * so we can see them at the getattr after lock acquisition.  this will
         * turn into a seperate [*ppos + count, EOF] 'size intent' lock attempt
         * in the future. */
        extent.start = *ppos;
        extent.end = OBD_OBJECT_EOF;

        err = ll_extent_lock(fd, inode, lsm, LCK_PR, &extent, &lockh);
        if (err != ELDLM_OK)
                RETURN(err);

        CDEBUG(D_INFO, "Reading inode %lu, "LPSZ" bytes, offset %Ld\n",
               inode->i_ino, count, *ppos);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        filp->f_ramax = 0; /* turn off generic_file_readahead() */
#else
        filp->f_ra.ra_pages = 0;
#endif
        retval = generic_file_read(filp, buf, count, ppos);

        /* XXX errors? */
        ll_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
        RETURN(retval);
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t ll_file_write(struct file *file, const char *buf, size_t count,
                             loff_t *ppos)
{
        struct ll_file_data *fd = file->private_data;
        struct inode *inode = file->f_dentry->d_inode;
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct lustre_handle lockh = { 0 };
        struct ldlm_extent extent;
        loff_t maxbytes = ll_file_maxbytes(inode);
        ldlm_error_t err;
        ssize_t retval;
        char should_validate = 1;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size="LPSZ",offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, count, *ppos);

        SIGNAL_MASK_ASSERT(); /* XXX BUG 1511 */

        /* POSIX, but surprised the VFS doesn't check this already */
        if (count == 0)
                RETURN(0);

        LASSERT(lsm);

        if (file->f_flags & O_APPEND) {
                extent.start = 0;
                extent.end = OBD_OBJECT_EOF;
        } else  {
                extent.start = *ppos;
                extent.end = *ppos + count - 1;
                /* we really don't care what i_size is if we're doing
                 * fully page aligned writes */
                if ((*ppos & ~PAGE_CACHE_MASK) == 0 &&
                    (count & ~PAGE_CACHE_MASK) == 0)
                        should_validate = 0;
        }

        if (should_validate)
                err = ll_extent_lock(fd, inode, lsm, LCK_PW, &extent, &lockh);
        else
                err = ll_extent_lock_no_validate(fd, inode, lsm, LCK_PW,
                                                 &extent, &lockh, 0);
        if (err != ELDLM_OK)
                RETURN(err);

        /* this is ok, g_f_w will overwrite this under i_sem if it races
         * with a local truncate, it just makes our maxbyte checking easier */
        if (file->f_flags & O_APPEND)
                *ppos = inode->i_size;

        if (*ppos >= maxbytes) {
                if (count || *ppos > maxbytes) {
                        send_sig(SIGXFSZ, current, 0);
                        GOTO(out, retval = -EFBIG);
                }
        }
        if (*ppos + count > maxbytes)
                count = maxbytes - *ppos;

        CDEBUG(D_INFO, "Writing inode %lu, "LPSZ" bytes, offset %Lu\n",
               inode->i_ino, count, *ppos);

        /* generic_file_write handles O_APPEND after getting i_sem */
        retval = generic_file_write(file, buf, count, ppos);

out:
        /* XXX errors? */
        lprocfs_counter_add(ll_i2sbi(inode)->ll_stats, LPROC_LL_WRITE_BYTES,
                            retval);
        ll_extent_unlock(fd, inode, lsm, LCK_PW, &lockh);
        RETURN(retval);
}

static int ll_lov_setstripe(struct inode *inode, struct file *file,
                            unsigned long arg)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct file *f;
        struct obd_export *exp = ll_i2obdexp(inode);
        struct lov_stripe_md *lsm;
        struct lookup_intent oit = {.it_op = IT_OPEN, .it_flags = FMODE_WRITE};
        struct lov_user_md lum, *lump = (struct lov_user_md *)arg;
        struct ptlrpc_request *req = NULL;
        struct lustre_md md;
        int rc;
        ENTRY;

        /* Bug 1152: copy properly when this is no longer true */
        LASSERT(sizeof(lum) == sizeof(*lump));
        LASSERT(sizeof(lum.lmm_objects[0]) == sizeof(lump->lmm_objects[0]));
        rc = copy_from_user(&lum, lump, sizeof(lum));
        if (rc)
                RETURN(-EFAULT);

        down(&lli->lli_open_sem);
        lsm = lli->lli_smd;
        if (lsm) {
                up(&lli->lli_open_sem);
                CDEBUG(D_IOCTL, "stripe already exists for ino %lu\n",
                       inode->i_ino);
                RETURN(-EEXIST);
        }

        f = get_empty_filp();
        if (!f)
                GOTO(out, -ENOMEM);

        f->f_dentry = file->f_dentry;
        f->f_vfsmnt = file->f_vfsmnt;

        rc = ll_intent_file_open(f, &lum, sizeof(lum), &oit);
        if (rc)
                GOTO(out, rc);
        if (it_disposition(&oit, DISP_LOOKUP_NEG))
                GOTO(out, -ENOENT);
        req = oit.d.lustre.it_data;
        rc = oit.d.lustre.it_status;

        if (rc < 0)
                GOTO(out, rc);

        rc = mdc_req2lustre_md(req, 1, exp, &md);
        if (rc)
                GOTO(out, rc);
        ll_update_inode(f->f_dentry->d_inode, md.body, md.lsm);

        rc = ll_local_open(f, &oit);
        if (rc)
                GOTO(out, rc);
        ll_intent_release(&oit);

        rc = ll_file_release(f->f_dentry->d_inode, f);

 out:
        if (f)
                put_filp(f);
        up(&lli->lli_open_sem);
        if (req != NULL)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int ll_lov_getstripe(struct inode *inode, unsigned long arg)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;

        if (!lsm)
                RETURN(-ENODATA);

        return obd_iocontrol(LL_IOC_LOV_GETSTRIPE, ll_i2obdexp(inode), 0, lsm,
                            (void *)arg);
}

int ll_file_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                  unsigned long arg)
{
        struct ll_file_data *fd = file->private_data;
        int flags;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),cmd=%x\n", inode->i_ino,
               inode->i_generation, inode, cmd);

        if (_IOC_TYPE(cmd) == 'T') /* tty ioctls */
                RETURN(-ENOTTY);

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_IOCTL);
        switch(cmd) {
        case LL_IOC_GETFLAGS:
                /* Get the current value of the file flags */
                return put_user(fd->fd_flags, (int *)arg);
        case LL_IOC_SETFLAGS:
        case LL_IOC_CLRFLAGS:
                /* Set or clear specific file flags */
                /* XXX This probably needs checks to ensure the flags are
                 *     not abused, and to handle any flag side effects.
                 */
                if (get_user(flags, (int *) arg))
                        RETURN(-EFAULT);

                if (cmd == LL_IOC_SETFLAGS)
                        fd->fd_flags |= flags;
                else
                        fd->fd_flags &= ~flags;
                RETURN(0);
        case LL_IOC_LOV_SETSTRIPE:
                RETURN(ll_lov_setstripe(inode, file, arg));
        case LL_IOC_LOV_GETSTRIPE:
                RETURN(ll_lov_getstripe(inode, arg));
        case EXT3_IOC_GETFLAGS:
        case EXT3_IOC_SETFLAGS:
                RETURN( ll_iocontrol(inode, file, cmd, arg) );
        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT2_IOC_GETVERSION_OLD:
        case EXT2_IOC_GETVERSION_NEW:
        case EXT2_IOC_SETVERSION_OLD:
        case EXT2_IOC_SETVERSION_NEW:
        */
        default:
                RETURN( obd_iocontrol(cmd, ll_i2obdexp(inode), 0, NULL,
                                      (void *)arg) );
        }
}

loff_t ll_file_seek(struct file *file, loff_t offset, int origin)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_file_data *fd = file->private_data;
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct lustre_handle lockh = {0};
        loff_t retval;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),to=%llu\n", inode->i_ino,
               inode->i_generation, inode,
               offset + ((origin==2) ? inode->i_size : file->f_pos));

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_LLSEEK);
        if (origin == 2) { /* SEEK_END */
                ldlm_error_t err;
                struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                err = ll_extent_lock(fd, inode, lsm, LCK_PR, &extent, &lockh);
                if (err != ELDLM_OK)
                        RETURN(err);

                offset += inode->i_size;
        } else if (origin == 1) { /* SEEK_CUR */
                offset += file->f_pos;
        }

        retval = -EINVAL;
        if (offset >= 0 && offset <= ll_file_maxbytes(inode)) {
                if (offset != file->f_pos) {
                        file->f_pos = offset;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        file->f_reada = 0;
                        file->f_version = ++event;
#endif
                }
                retval = offset;
        }

        if (origin == 2)
                ll_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
        RETURN(retval);
}

int ll_fsync(struct file *file, struct dentry *dentry, int data)
{
        struct inode *inode = dentry->d_inode;
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ll_fid fid;
        struct ptlrpc_request *req;
        int rc, err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_FSYNC);

        /* fsync's caller has already called _fdata{sync,write}, we want
         * that IO to finish before calling the osc and mdc sync methods */
        rc = filemap_fdatawait(inode->i_mapping);

        ll_inode2fid(&fid, inode);
        err = mdc_sync(ll_i2sbi(inode)->ll_mdc_exp, &fid, &req);
        if (!rc)
                rc = err;
        if (!err)
                ptlrpc_req_finished(req);

        if (data && lsm) {
                struct obdo *oa = obdo_alloc();

                if (!oa)
                        RETURN(rc ? rc : -ENOMEM);

                oa->o_id = lsm->lsm_object_id;
                oa->o_valid = OBD_MD_FLID;
                obdo_from_inode(oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                           OBD_MD_FLMTIME | OBD_MD_FLCTIME);

                err = obd_sync(ll_i2sbi(inode)->ll_osc_exp, oa, lsm,
                               0, OBD_OBJECT_EOF);
                if (!rc)
                        rc = err;
                obdo_free(oa);
        }

        RETURN(rc);
}

int ll_file_flock(struct file *file, int cmd, struct file_lock *file_lock)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct obd_device *obddev;
        struct ldlm_res_id res_id =
                    { .name = {inode->i_ino, inode->i_generation, LDLM_FLOCK} };
        struct lustre_handle lockh = {0};
        struct ldlm_flock flock;
        ldlm_mode_t mode = 0;
        int flags = 0;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu file_lock=%p\n",
               inode->i_ino, file_lock);

        flock.pid = file_lock->fl_pid;
        flock.start = file_lock->fl_start;
        flock.end = file_lock->fl_end;

        switch (file_lock->fl_type) {
        case F_RDLCK:
                mode = LCK_PR;
                break;
        case F_UNLCK:
                /* An unlock request may or may not have any relation to
                 * existing locks so we may not be able to pass a lock handle
                 * via a normal ldlm_lock_cancel() request. The request may even
                 * unlock a byte range in the middle of an existing lock. In
                 * order to process an unlock request we need all of the same
                 * information that is given with a normal read or write record
                 * lock request. To avoid creating another ldlm unlock (cancel)
                 * message we'll treat a LCK_NL flock request as an unlock. */
                mode = LCK_NL;
                break;
        case F_WRLCK:
                mode = LCK_PW;
                break;
        default:
                CERROR("unknown fcntl lock type: %d\n", file_lock->fl_type);
                LBUG();
        }

        switch (cmd) {
        case F_SETLKW:
                flags = 0;
                break;
        case F_SETLK:
                flags = LDLM_FL_BLOCK_NOWAIT;
                break;
        case F_GETLK:
                flags = LDLM_FL_TEST_LOCK;
                /* Save the old mode so that if the mode in the lock changes we
                 * can decrement the appropriate reader or writer refcount. */
                file_lock->fl_type = mode;
                break;
        default:
                CERROR("unknown fcntl lock command: %d\n", cmd);
                LBUG();
        }

        CDEBUG(D_DLMTRACE, "inode=%lu, pid=%u, flags=%#x, mode=%u, "
               "start="LPU64", end="LPU64"\n", inode->i_ino, flock.pid,
               flags, mode, flock.start, flock.end);

        obddev = sbi->ll_mdc_exp->exp_obd;
        rc = ldlm_cli_enqueue(sbi->ll_mdc_exp, NULL, obddev->obd_namespace,
                              NULL, res_id, LDLM_FLOCK, &flock, sizeof(flock),
                              mode, &flags, ldlm_flock_completion_ast, NULL,
                              file_lock, &lockh);
        RETURN(rc);
}

static int ll_have_md_lock(struct dentry *de)
{
        struct ll_sb_info *sbi = ll_s2sbi(de->d_sb);
        struct lustre_handle lockh;
        struct ldlm_res_id res_id = { .name = {0} };
        struct obd_device *obddev;
        int flags;
        ENTRY;

        if (!de->d_inode)
               RETURN(0);

        obddev = sbi->ll_mdc_exp->exp_obd;
        res_id.name[0] = de->d_inode->i_ino;
        res_id.name[1] = de->d_inode->i_generation;

        CDEBUG(D_INFO, "trying to match res "LPU64"\n", res_id.name[0]);

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING;
        if (ldlm_lock_match(obddev->obd_namespace, flags, &res_id, LDLM_PLAIN,
                            NULL, 0, LCK_PR, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PR);
                RETURN(1);
        }

        if (ldlm_lock_match(obddev->obd_namespace, flags, &res_id, LDLM_PLAIN,
                            NULL, 0, LCK_PW, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PW);
                RETURN(1);
        }
        RETURN(0);
}

int ll_inode_revalidate_it(struct dentry *dentry, struct lookup_intent *it)
{
        struct inode *inode = dentry->d_inode;
        struct lov_stripe_md *lsm;
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),name=%s\n",
               inode->i_ino, inode->i_generation, inode, dentry->d_name.name);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,5,0))
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_REVALIDATE);
#endif

        if (!ll_have_md_lock(dentry)) {
                struct ptlrpc_request *req = NULL;
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                struct ll_fid fid;
                unsigned long valid = 0;
                int rc, ealen = 0;

                if (S_ISREG(inode->i_mode)) {
                        ealen = obd_size_diskmd(sbi->ll_osc_exp, NULL);
                        valid |= OBD_MD_FLEASIZE;
                }
                ll_inode2fid(&fid, inode);
                rc = mdc_getattr(sbi->ll_mdc_exp, &fid, valid, ealen, &req);
                if (rc) {
                        CERROR("failure %d inode %lu\n", rc, inode->i_ino);
                        RETURN(-abs(rc));
                }
                rc = ll_prep_inode(sbi->ll_osc_exp, &inode, req, 0, NULL);
                if (rc) {
                        ptlrpc_req_finished(req);
                        RETURN(rc);
                }
                ptlrpc_req_finished(req);
        }

#if 0
        if (ll_have_md_lock(dentry) &&
            test_bit(LLI_F_HAVE_MDS_SIZE_LOCK, &ll_i2info(inode)->lli_flags))
                RETURN(0);
#endif

        lsm = ll_i2info(inode)->lli_smd;
        if (!lsm)       /* object not yet allocated, don't validate size */
                RETURN(0);

        /* unfortunately stat comes in through revalidate and we don't
         * differentiate this use from initial instantiation.  we're
         * also being wildly conservative and flushing write caches
         * so that stat really returns the proper size. */
        {
                struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                struct lustre_handle lockh = {0};
                ldlm_error_t err;

                err = ll_extent_lock(NULL, inode, lsm, LCK_PR, &extent, &lockh);
                if (err != ELDLM_OK)
                        RETURN(err);

                ll_extent_unlock(NULL, inode, lsm, LCK_PR, &lockh);
        }
        RETURN(0);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
int ll_getattr(struct vfsmount *mnt, struct dentry *de,
               struct lookup_intent *it, struct kstat *stat)
{
        int res = 0;
        struct inode *inode = de->d_inode;

        res = ll_inode_revalidate_it(de, it);
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_GETATTR);

        if (res)
                return res;

        stat->dev = inode->i_sb->s_dev;
        stat->ino = inode->i_ino;
        stat->mode = inode->i_mode;
        stat->nlink = inode->i_nlink;
        stat->uid = inode->i_uid;
        stat->gid = inode->i_gid;
        stat->rdev = kdev_t_to_nr(inode->i_rdev);
        stat->atime = inode->i_atime;
        stat->mtime = inode->i_mtime;
        stat->ctime = inode->i_ctime;
        stat->size = inode->i_size;
        stat->blksize = inode->i_blksize;
        stat->blocks = inode->i_blocks;
        return 0;
}
#endif


struct file_operations ll_file_operations = {
        read:           ll_file_read,
        write:          ll_file_write,
        ioctl:          ll_file_ioctl,
        open:           ll_file_open,
        release:        ll_file_release,
        mmap:           generic_file_mmap,
        llseek:         ll_file_seek,
        fsync:          ll_fsync,
        //lock:           ll_file_flock
};

struct inode_operations ll_file_inode_operations = {
        setattr_raw:    ll_setattr_raw,
        setattr:        ll_setattr,
        truncate:       ll_truncate,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        getattr_it:     ll_getattr,
#else
        revalidate_it:  ll_inode_revalidate_it,
#endif
};

