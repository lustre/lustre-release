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
#include <lustre_dlm.h>
#include <lustre_lite.h>
#include <lustre_mdc.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/lustre_compat25.h>
#endif
#include "llite_internal.h"

/* also used by llite/special.c:ll_special_open() */
struct ll_file_data *ll_file_data_get(void)
{
        struct ll_file_data *fd;

        OBD_SLAB_ALLOC(fd, ll_file_data_slab, SLAB_KERNEL, sizeof *fd);
        return fd;
}

static void ll_file_data_put(struct ll_file_data *fd)
{
        if (fd != NULL)
                OBD_SLAB_FREE(fd, ll_file_data_slab, sizeof *fd);
}

static int ll_close_inode_openhandle(struct obd_export *md_exp,
                                     struct inode *inode,
                                     struct obd_client_handle *och)
{
        struct md_op_data *op_data;
        struct ptlrpc_request *req = NULL;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);

        op_data->fid1 = ll_i2info(inode)->lli_fid;
        op_data->valid = OBD_MD_FLTYPE | OBD_MD_FLMODE |
                         OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                         OBD_MD_FLATIME | OBD_MD_FLMTIME |
                         OBD_MD_FLCTIME;

        op_data->atime = LTIME_S(inode->i_atime);
        op_data->mtime = LTIME_S(inode->i_mtime);
        op_data->ctime = LTIME_S(inode->i_ctime);
        op_data->size = inode->i_size;
        op_data->blocks = inode->i_blocks;
        op_data->flags = inode->i_flags;

        if (0 /* ll_is_inode_dirty(inode) */) {
                op_data->flags = MDS_BFLAG_UNCOMMITTED_WRITES;
                op_data->valid |= OBD_MD_FLFLAGS;
        }

        rc = md_close(md_exp, op_data, och, &req);
        OBD_FREE_PTR(op_data);
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
                rc = ll_objects_destroy(req, inode);
                if (rc)
                        CERROR("inode %lu ll_objects destroy: rc = %d\n",
                               inode->i_ino, rc);
        }

        md_clear_open_replay_data(md_exp, och);
        ptlrpc_req_finished(req); /* This is close request */

        RETURN(rc);
}

/* just for debugging by huanghua@clusterfs.com, will be removed later */
#include <lustre_lib.h>
struct mdc_open_data {
        struct obd_client_handle *mod_och;
        struct ptlrpc_request    *mod_open_req;
        struct ptlrpc_request    *mod_close_req;
};
/* --end: just for debugging by huanghua@clusterfs.com*/

int ll_md_close(struct obd_export *md_exp, struct inode *inode,
                struct file *file)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        struct obd_client_handle *och = &fd->fd_mds_och;
        int rc;
        ENTRY;

        /* clear group lock, if present */
        if (unlikely(fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
                struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);
                rc = ll_extent_unlock(fd, inode, lsm, LCK_GROUP,
                                      &fd->fd_cwlockh);
        }
        CDEBUG(D_INFO, "closing ino = %lu file = %p has open req = %p, type = %x, "
                       "transno = "LPU64", handle = "LPX64"\n",
                       inode->i_ino, file,
                       och->och_mod->mod_open_req,
                       och->och_mod->mod_open_req->rq_type,
                       och->och_mod->mod_open_req->rq_transno,
                       och->och_fh.cookie);

        rc = ll_close_inode_openhandle(md_exp, inode, och);
        och->och_fh.cookie = DEAD_HANDLE_MAGIC;
        LUSTRE_FPRIVATE(file) = NULL;
        ll_file_data_put(fd);

        RETURN(rc);
}

int lov_test_and_clear_async_rc(struct lov_stripe_md *lsm);

/* While this returns an error code, fput() the caller does not, so we need
 * to make every effort to clean up all of our state here.  Also, applications
 * rarely check close errors and even if an error is returned they will not
 * re-try the close call.
 */
int ll_file_release(struct inode *inode, struct file *file)
{
        struct ll_file_data *fd;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        int rc;

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        lprocfs_counter_incr(sbi->ll_stats, LPROC_LL_RELEASE);
        fd = LUSTRE_FPRIVATE(file);
        LASSERT(fd != NULL);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry) {
                LUSTRE_FPRIVATE(file) = NULL;
                ll_file_data_put(fd);
                RETURN(0);
        }

        if (lsm)
                lov_test_and_clear_async_rc(lsm);
        lli->lli_async_rc = 0;

        rc = ll_md_close(sbi->ll_md_exp, inode, file);
        RETURN(rc);
}

static int ll_intent_file_open(struct file *file, void *lmm,
                               int lmmsize, struct lookup_intent *itp)
{
        struct ll_sb_info *sbi = ll_i2sbi(file->f_dentry->d_inode);
        struct dentry *parent = file->f_dentry->d_parent;
        const char *name = file->f_dentry->d_name.name;
        const int len = file->f_dentry->d_name.len;
        struct lustre_handle lockh;
        struct md_op_data *op_data;
        int rc;

        if (!parent)
                RETURN(-ENOENT);

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);

        ll_prepare_md_op_data(op_data, parent->d_inode, NULL,
                              name, len, O_RDWR);

        rc = md_enqueue(sbi->ll_md_exp, LDLM_IBITS, itp, LCK_PW, op_data,
                        &lockh, lmm, lmmsize, ldlm_completion_ast,
                        ll_md_blocking_ast, NULL, 0);
        OBD_FREE_PTR(op_data);
        if (rc < 0) {
                CERROR("lock enqueue: err: %d\n", rc);
                RETURN(rc);
        }

        rc = ll_prep_inode(&file->f_dentry->d_inode,
                           (struct ptlrpc_request *)itp->d.lustre.it_data,
                           1, NULL);
        RETURN(rc);
}

static void ll_och_fill(struct obd_export *md_exp, struct ll_inode_info *lli,
                        struct lookup_intent *it, struct obd_client_handle *och)
{
        struct ptlrpc_request *req = it->d.lustre.it_data;
        struct mdt_body *body;

        LASSERT(och);

        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof(*body));
        LASSERT(body != NULL);                  /* reply already checked out */
        LASSERT_REPSWABBED(req, 1);             /* and swabbed in md_enqueue */

        memcpy(&och->och_fh, &body->handle, sizeof(body->handle));
        och->och_magic = OBD_CLIENT_HANDLE_MAGIC;
        lli->lli_io_epoch = body->io_epoch;

        md_set_open_replay_data(md_exp, och, it->d.lustre.it_data);
}

int ll_local_open(struct file *file, struct lookup_intent *it,
                  struct ll_file_data *fd)
{
        struct inode *inode = file->f_dentry->d_inode;
        ENTRY;

        LASSERT(!LUSTRE_FPRIVATE(file));

        LASSERT(fd != NULL);

        ll_och_fill(ll_i2sbi(inode)->ll_md_exp,
                    ll_i2info(inode), it, &fd->fd_mds_och);

        LUSTRE_FPRIVATE(file) = fd;
        ll_readahead_init(inode, &fd->fd_ras);

        RETURN(0);
}

/* Open a file, and (for the very first open) create objects on the OSTs at
 * this time.  If opened with O_LOV_DELAY_CREATE, then we don't do the object
 * creation or open until ll_lov_setstripe() ioctl is called.  We grab
 * lli_open_sem to ensure no other process will create objects, send the
 * stripe MD to the MDS, or try to destroy the objects if that fails.
 *
 * If we already have the stripe MD locally then we don't request it in
 * md_open(), by passing a lmm_size = 0.
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
        struct lookup_intent *it, oit = { .it_op = IT_OPEN,
                                          .it_flags = file->f_flags };
        struct lov_stripe_md *lsm;
        struct ptlrpc_request *req;
        struct ll_file_data *fd;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), flags %o\n", inode->i_ino,
               inode->i_generation, inode, file->f_flags);

        it = file->f_it;

        fd = ll_file_data_get();
        if (fd == NULL)
                RETURN(-ENOMEM);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry) {
                LUSTRE_FPRIVATE(file) = fd;
                RETURN(0);
        }

        if (!it || !it->d.lustre.it_disposition) {
                struct ll_sb_info *sbi = ll_i2sbi(inode);

                /* Convert f_flags into access mode. We cannot use file->f_mode,
                 * because everything but O_ACCMODE mask was stripped from
                 * there */
                if ((oit.it_flags + 1) & O_ACCMODE)
                        oit.it_flags++;
                if (oit.it_flags & O_TRUNC)
                        oit.it_flags |= FMODE_WRITE;

                if (oit.it_flags & O_CREAT)
                        oit.it_flags |= MDS_OPEN_OWNEROVERRIDE;

                /* We do not want O_EXCL here, presumably we opened the file
                 * already? XXX - NFS implications? */
                oit.it_flags &= ~O_EXCL;

                it = &oit;
                rc = ll_intent_file_open(file, NULL, 0, it);
                if (rc) {
                        ll_file_data_put(fd);
                        GOTO(out, rc);
                }

                md_set_lock_data(sbi->ll_md_exp, &it->d.lustre.it_lock_handle,
                                 file->f_dentry->d_inode);
        }

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_OPEN);
        rc = it_open_error(DISP_OPEN_OPEN, it);
        /* md_intent_lock() didn't get a request ref if there was an open
         * error, so don't do cleanup on the request here (bug 3430) */
        if (rc) {
                ll_file_data_put(fd);
                RETURN(rc);
        }

        rc = ll_local_open(file, it, fd);
        req = it->d.lustre.it_data;
        LASSERTF(rc == 0, "rc = %d\n", rc);
        CDEBUG(D_INFO, "opening ino = %lu file = %p has open req = %p, type = %x, "
                       "transno = "LPU64", handle = "LPX64"\n",
                       inode->i_ino, file, req, req->rq_type,
                       req->rq_transno, fd->fd_mds_och.och_fh.cookie);

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

static int ll_lock_to_stripe_offset(struct inode *inode, struct ldlm_lock *lock)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_export *exp = ll_i2dtexp(inode);
        struct {
                char name[16];
                struct ldlm_lock *lock;
                struct lov_stripe_md *lsm;
        } key = { .name = "lock_to_stripe", .lock = lock, .lsm = lsm };
        __u32 stripe, vallen = sizeof(stripe);
        int rc;
        ENTRY;

        if (lsm->lsm_stripe_count == 1)
                GOTO(check, stripe = 0);

        /* get our offset in the lov */
        rc = obd_get_info(exp, sizeof(key), &key, &vallen, &stripe);
        if (rc != 0) {
                CERROR("obd_get_info: rc = %d\n", rc);
                RETURN(rc);
        }
        LASSERT(stripe < lsm->lsm_stripe_count);

check:
        if (lsm->lsm_oinfo[stripe].loi_id != lock->l_resource->lr_name.name[0]||
            lsm->lsm_oinfo[stripe].loi_gr != lock->l_resource->lr_name.name[1]){
                LDLM_ERROR(lock, "resource doesn't match object "LPU64"/"LPU64,
                           lsm->lsm_oinfo[stripe].loi_id,
                           lsm->lsm_oinfo[stripe].loi_gr);
                RETURN(-ELDLM_NO_LOCK_DATA);
        }

        RETURN(stripe);
}

/* Flush the page cache for an extent as its canceled.  When we're on an LOV,
 * we get a lock cancellation for each stripe, so we have to map the obd's
 * region back onto the stripes in the file that it held.
 *
 * No one can dirty the extent until we've finished our work and they can
 * enqueue another lock.  The DLM protects us from ll_file_read/write here,
 * but other kernel actors could have pages locked.
 *
 * Called with the DLM lock held. */
void ll_pgcache_remove_extent(struct inode *inode, struct lov_stripe_md *lsm,
                              struct ldlm_lock *lock, __u32 stripe)
{
        ldlm_policy_data_t tmpex;
        unsigned long start, end, count, skip, i, j;
        struct page *page;
        int rc, rc2, discard = lock->l_flags & LDLM_FL_DISCARD_DATA;
        struct lustre_handle lockh;
        ENTRY;

        memcpy(&tmpex, &lock->l_policy_data, sizeof(tmpex));
        CDEBUG(D_INODE|D_PAGE, "inode %lu(%p) ["LPU64"->"LPU64"] size: %llu\n",
               inode->i_ino, inode, tmpex.l_extent.start, tmpex.l_extent.end,
               inode->i_size);

        /* our locks are page granular thanks to osc_enqueue, we invalidate the
         * whole page. */
        LASSERT((tmpex.l_extent.start & ~PAGE_CACHE_MASK) == 0);
        LASSERT(((tmpex.l_extent.end + 1) & ~PAGE_CACHE_MASK) == 0);

        count = ~0;
        skip = 0;
        start = tmpex.l_extent.start >> PAGE_CACHE_SHIFT;
        end = tmpex.l_extent.end >> PAGE_CACHE_SHIFT;
        if (lsm->lsm_stripe_count > 1) {
                count = lsm->lsm_stripe_size >> PAGE_CACHE_SHIFT;
                skip = (lsm->lsm_stripe_count - 1) * count;
                start += start/count * skip + stripe * count;
                if (end != ~0)
                        end += end/count * skip + stripe * count;
        }
        if (end < tmpex.l_extent.end >> PAGE_CACHE_SHIFT)
                end = ~0;

        i = inode->i_size ? (inode->i_size - 1) >> PAGE_CACHE_SHIFT : 0;
        if (i < end)
                end = i;

        CDEBUG(D_INODE|D_PAGE, "walking page indices start: %lu j: %lu "
               "count: %lu skip: %lu end: %lu%s\n", start, start % count,
               count, skip, end, discard ? " (DISCARDING)" : "");

        /* walk through the vmas on the inode and tear down mmaped pages that
         * intersect with the lock.  this stops immediately if there are no
         * mmap()ed regions of the file.  This is not efficient at all and
         * should be short lived. We'll associate mmap()ed pages with the lock
         * and will be able to find them directly */
        for (i = start; i <= end; i += (j + skip)) {
                j = min(count - (i % count), end - i + 1);
                LASSERT(j > 0);
                LASSERT(inode->i_mapping);
                if (ll_teardown_mmaps(inode->i_mapping,
                                      (__u64)i << PAGE_CACHE_SHIFT,
                                      ((__u64)(i+j) << PAGE_CACHE_SHIFT) - 1) )
                        break;
        }

        /* this is the simplistic implementation of page eviction at
         * cancelation.  It is careful to get races with other page
         * lockers handled correctly.  fixes from bug 20 will make it
         * more efficient by associating locks with pages and with
         * batching writeback under the lock explicitly. */
        for (i = start, j = start % count; i <= end;
             j++, i++, tmpex.l_extent.start += PAGE_CACHE_SIZE) {
                if (j == count) {
                        CDEBUG(D_PAGE, "skip index %lu to %lu\n", i, i + skip);
                        i += skip;
                        j = 0;
                        if (i > end)
                                break;
                }
                LASSERTF(tmpex.l_extent.start< lock->l_policy_data.l_extent.end,
                         LPU64" >= "LPU64" start %lu i %lu end %lu\n",
                         tmpex.l_extent.start, lock->l_policy_data.l_extent.end,
                         start, i, end);

                if (!mapping_has_pages(inode->i_mapping)) {
                        CDEBUG(D_INODE|D_PAGE, "nothing left\n");
                        break;
                }

                cond_resched();

                page = find_get_page(inode->i_mapping, i);
                if (page == NULL)
                        continue;
                LL_CDEBUG_PAGE(D_PAGE, page, "lock page idx %lu ext "LPU64"\n",
                               i, tmpex.l_extent.start);
                lock_page(page);

                /* page->mapping to check with racing against teardown */
                if (!discard && clear_page_dirty_for_io(page)) {
                        rc = ll_call_writepage(inode, page);
                        if (rc != 0)
                                CERROR("writepage of page %p failed: %d\n",
                                       page, rc);
                        /* either waiting for io to complete or reacquiring
                         * the lock that the failed writepage released */
                        lock_page(page);
                }

                tmpex.l_extent.end = tmpex.l_extent.start + PAGE_CACHE_SIZE - 1;
                /* check to see if another DLM lock covers this page */
                rc2 = ldlm_lock_match(lock->l_resource->lr_namespace,
                                      LDLM_FL_BLOCK_GRANTED|LDLM_FL_CBPENDING |
                                      LDLM_FL_TEST_LOCK,
                                      &lock->l_resource->lr_name, LDLM_EXTENT,
                                      &tmpex, LCK_PR | LCK_PW, &lockh);
                if (rc2 == 0 && page->mapping != NULL) {
                        struct ll_async_page *llap = llap_cast_private(page);
                        // checking again to account for writeback's lock_page()
                        LL_CDEBUG_PAGE(D_PAGE, page, "truncating\n");
                        if (llap)
                                ll_ra_accounting(llap, inode->i_mapping);
                        ll_truncate_complete_page(page);
                }
                unlock_page(page);
                page_cache_release(page);
        }
        LASSERTF(tmpex.l_extent.start <=
                 (lock->l_policy_data.l_extent.end == ~0ULL ? ~0ULL :
                  lock->l_policy_data.l_extent.end + 1),
                 "loop too long "LPU64" > "LPU64" start %lu i %lu end %lu\n",
                 tmpex.l_extent.start, lock->l_policy_data.l_extent.end,
                 start, i, end);
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
                struct inode *inode;
                struct ll_inode_info *lli;
                struct lov_stripe_md *lsm;
                int stripe;
                __u64 kms;

                /* This lock wasn't granted, don't try to evict pages */
                if (lock->l_req_mode != lock->l_granted_mode)
                        RETURN(0);

                inode = ll_inode_from_lock(lock);
                if (inode == NULL)
                        RETURN(0);
                lli = ll_i2info(inode);
                if (lli == NULL)
                        goto iput;
                if (lli->lli_smd == NULL)
                        goto iput;
                lsm = lli->lli_smd;

                stripe = ll_lock_to_stripe_offset(inode, lock);
                if (stripe < 0)
                        goto iput;

                ll_pgcache_remove_extent(inode, lsm, lock, stripe);

                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                lov_stripe_lock(lsm);
                kms = ldlm_extent_shift_kms(lock,
                                            lsm->lsm_oinfo[stripe].loi_kms);

                if (lsm->lsm_oinfo[stripe].loi_kms != kms)
                        LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                                   lsm->lsm_oinfo[stripe].loi_kms, kms);
                lsm->lsm_oinfo[stripe].loi_kms = kms;
                lov_stripe_unlock(lsm);
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                //ll_try_done_writing(inode);
        iput:
                iput(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

#if 0
int ll_async_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        /* XXX ALLOCATE - 160 bytes */
        struct inode *inode = ll_inode_from_lock(lock);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle lockh = { 0 };
        struct ost_lvb *lvb;
        int stripe;
        ENTRY;

        if (flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                     LDLM_FL_BLOCK_CONV)) {
                LBUG(); /* not expecting any blocked async locks yet */
                LDLM_DEBUG(lock, "client-side async enqueue returned a blocked "
                           "lock, returning");
                ldlm_lock_dump(D_OTHER, lock, 0);
                ldlm_reprocess_all(lock->l_resource);
                RETURN(0);
        }

        LDLM_DEBUG(lock, "client-side async enqueue: granted/glimpsed");

        stripe = ll_lock_to_stripe_offset(inode, lock);
        if (stripe < 0)
                goto iput;

        if (lock->l_lvb_len) {
                struct lov_stripe_md *lsm = lli->lli_smd;
                __u64 kms;
                lvb = lock->l_lvb_data;
                lsm->lsm_oinfo[stripe].loi_rss = lvb->lvb_size;

                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                LOCK_INODE_MUTEX(inode);
                kms = MAX(lsm->lsm_oinfo[stripe].loi_kms, lvb->lvb_size);
                kms = ldlm_extent_shift_kms(NULL, kms);
                if (lsm->lsm_oinfo[stripe].loi_kms != kms)
                        LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                                   lsm->lsm_oinfo[stripe].loi_kms, kms);
                lsm->lsm_oinfo[stripe].loi_kms = kms;
                UNLOCK_INODE_MUTEX(inode);
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        }

iput:
        iput(inode);
        wake_up(&lock->l_waitq);

        ldlm_lock2handle(lock, &lockh);
        ldlm_lock_decref(&lockh, LCK_PR);
        RETURN(0);
}
#endif

static int ll_glimpse_callback(struct ldlm_lock *lock, void *reqp)
{
        struct ptlrpc_request *req = reqp;
        struct inode *inode = ll_inode_from_lock(lock);
        struct ll_inode_info *lli;
        struct lov_stripe_md *lsm;
        struct ost_lvb *lvb;
        int rc, size = sizeof(*lvb), stripe;
        ENTRY;

        if (inode == NULL)
                GOTO(out, rc = -ELDLM_NO_LOCK_DATA);
        lli = ll_i2info(inode);
        if (lli == NULL)
                GOTO(iput, rc = -ELDLM_NO_LOCK_DATA);
        lsm = lli->lli_smd;
        if (lsm == NULL)
                GOTO(iput, rc = -ELDLM_NO_LOCK_DATA);

        /* First, find out which stripe index this lock corresponds to. */
        stripe = ll_lock_to_stripe_offset(inode, lock);
        if (stripe < 0)
                GOTO(iput, rc = -ELDLM_NO_LOCK_DATA);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc) {
                CERROR("lustre_pack_reply: %d\n", rc);
                GOTO(iput, rc);
        }

        lvb = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*lvb));
        lvb->lvb_size = lli->lli_smd->lsm_oinfo[stripe].loi_kms;
        lvb->lvb_mtime = LTIME_S(inode->i_mtime);
        lvb->lvb_atime = LTIME_S(inode->i_atime);
        lvb->lvb_ctime = LTIME_S(inode->i_ctime);

        LDLM_DEBUG(lock, "i_size: %llu -> stripe number %u -> kms "LPU64
                   " atime "LPU64", mtime "LPU64", ctime "LPU64,
                   inode->i_size, stripe, lvb->lvb_size, lvb->lvb_mtime,
                   lvb->lvb_atime, lvb->lvb_ctime);
        GOTO(iput, 0);
 iput:
        iput(inode);

 out:
        /* These errors are normal races, so we don't want to fill the console
         * with messages by calling ptlrpc_error() */
        if (rc == -ELDLM_NO_LOCK_DATA)
                lustre_pack_reply(req, 0, NULL, NULL);

        req->rq_status = rc;
        return rc;
}

/* NB: obd_merge_lvb will prefer locally cached writes if they extend the
 * file (because it prefers KMS over RSS when larger) */
int ll_glimpse_size(struct inode *inode, int ast_flags)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };
        struct lustre_handle lockh = { 0 };
        struct ost_lvb lvb;
        int rc;
        ENTRY;

        CDEBUG(D_DLMTRACE, "Glimpsing inode %lu\n", inode->i_ino);

        ast_flags |= LDLM_FL_HAS_INTENT;

        /* NOTE: this looks like DLM lock request, but it may not be one. Due
         *       to LDLM_FL_HAS_INTENT flag, this is glimpse request, that
         *       won't revoke any conflicting DLM locks held. Instead,
         *       ll_glimpse_callback() will be called on each client
         *       holding a DLM lock against this file, and resulting size
         *       will be returned for each stripe. DLM lock on [0, EOF] is
         *       acquired only if there were no conflicting locks. */
        rc = obd_enqueue(sbi->ll_dt_exp, lli->lli_smd, LDLM_EXTENT, &policy,
                         LCK_PR, &ast_flags, ll_extent_lock_callback,
                         ldlm_completion_ast, ll_glimpse_callback, inode,
                         sizeof(struct ost_lvb), lustre_swab_ost_lvb, &lockh);
        if (rc == -ENOENT)
                RETURN(rc);
        if (rc != 0) {
                CERROR("obd_enqueue returned rc %d, returning -EIO\n", rc);
                RETURN(rc > 0 ? -EIO : rc);
        }

        ll_inode_size_lock(inode, 1);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(sbi->ll_dt_exp, lli->lli_smd, &lvb, 0);
        inode->i_size = lvb.lvb_size;
        inode->i_blocks = lvb.lvb_blocks;
        LTIME_S(inode->i_mtime) = lvb.lvb_mtime;
        LTIME_S(inode->i_atime) = lvb.lvb_atime;
        LTIME_S(inode->i_ctime) = lvb.lvb_ctime;
        ll_inode_size_unlock(inode, 1);

        CDEBUG(D_DLMTRACE, "glimpse: size: %llu, blocks: %lu\n",
               inode->i_size, inode->i_blocks);

        obd_cancel(sbi->ll_dt_exp, lli->lli_smd, LCK_PR, &lockh);

        RETURN(rc);
}

int ll_extent_lock(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm, int mode,
                   ldlm_policy_data_t *policy, struct lustre_handle *lockh,
                   int ast_flags)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ost_lvb lvb;
        int rc;
        ENTRY;

        LASSERT(!lustre_handle_is_used(lockh));
        LASSERT(lsm != NULL);

        /* don't drop the mmapped file to LRU */
        if (mapping_mapped(inode->i_mapping))
                ast_flags |= LDLM_FL_NO_LRU;

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        CDEBUG(D_DLMTRACE, "Locking inode %lu, start "LPU64" end "LPU64"\n",
               inode->i_ino, policy->l_extent.start, policy->l_extent.end);

        rc = obd_enqueue(sbi->ll_dt_exp, lsm, LDLM_EXTENT, policy, mode,
                         &ast_flags, ll_extent_lock_callback,
                         ldlm_completion_ast, ll_glimpse_callback, inode,
                         sizeof(struct ost_lvb), lustre_swab_ost_lvb, lockh);
        if (rc > 0)
                rc = -EIO;

        ll_inode_size_lock(inode, 1);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(sbi->ll_dt_exp, lsm, &lvb, 0);

        if (policy->l_extent.start == 0 &&
            policy->l_extent.end == OBD_OBJECT_EOF) {
                /* vmtruncate()->ll_truncate() first sets the i_size and then
                 * the kms under both a DLM lock and the
                 * ll_inode_size_lock().  If we don't get the
                 * ll_inode_size_lock() here we can match the DLM lock and
                 * reset i_size from the kms before the truncating path has
                 * updated the kms.  generic_file_write can then trust the
                 * stale i_size when doing appending writes and effectively
                 * cancel the result of the truncate.  Getting the
                 * ll_inode_size_lock() after the enqueue maintains the DLM
                 * -> ll_inode_size_lock() acquiring order. */
                inode->i_size = lvb.lvb_size;
        }

        if (rc == 0) {
                LTIME_S(inode->i_mtime) = lvb.lvb_mtime;
                LTIME_S(inode->i_atime) = lvb.lvb_atime;
                LTIME_S(inode->i_ctime) = lvb.lvb_ctime;
        }
        ll_inode_size_unlock(inode, 1);

        RETURN(rc);
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

        rc = obd_cancel(sbi->ll_dt_exp, lsm, mode, lockh);

        RETURN(rc);
}

static ssize_t ll_file_read(struct file *file, char *buf, size_t count,
                            loff_t *ppos)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_lock_tree tree;
        struct ll_lock_tree_node *node;
        struct ost_lvb lvb;
        struct ll_ra_read bead;
        int rc;
        ssize_t retval;
        __u64 kms;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size="LPSZ",offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, count, *ppos);

        /* "If nbyte is 0, read() will return 0 and have no other results."
         *                      -- Single Unix Spec */
        if (count == 0)
                RETURN(0);

        lprocfs_counter_add(ll_i2sbi(inode)->ll_stats, LPROC_LL_READ_BYTES,
                            count);

        if (!lsm) {
                /* Read on file with no objects should return zero-filled
                 * buffers up to file size (we can get non-zero sizes with
                 * mknod + truncate, then opening file for read. This is a
                 * common pattern in NFS case, it seems). Bug 6243 */
                int notzeroed;
                /* Since there are no objects on OSTs, we have nothing to get
                 * lock on and so we are forced to access inode->i_size
                 * unguarded */

                /* Read beyond end of file */
                if (*ppos >= inode->i_size)
                        RETURN(0);

                if (count > inode->i_size - *ppos)
                        count = inode->i_size - *ppos;
                /* Make sure to correctly adjust the file pos pointer for
                 * EFAULT case */
                notzeroed = clear_user(buf, count);
                count -= notzeroed;
                *ppos += count;
                if (!count)
                        RETURN(-EFAULT);
                RETURN(count);
        }

        node = ll_node_from_inode(inode, *ppos, *ppos + count - 1, LCK_PR);
        tree.lt_fd = LUSTRE_FPRIVATE(file);
        rc = ll_tree_lock(&tree, node, buf, count,
                          file->f_flags & O_NONBLOCK ? LDLM_FL_BLOCK_NOWAIT :0);
        if (rc != 0)
                RETURN(rc);

        ll_inode_size_lock(inode, 1);
        /*
         * Consistency guarantees: following possibilities exist for the
         * relation between region being read and real file size at this
         * moment:
         *
         *  (A): the region is completely inside of the file;
         *
         *  (B-x): x bytes of region are inside of the file, the rest is
         *  outside;
         *
         *  (C): the region is completely outside of the file.
         *
         * This classification is stable under DLM lock acquired by
         * ll_tree_lock() above, because to change class, other client has to
         * take DLM lock conflicting with our lock. Also, any updates to
         * ->i_size by other threads on this client are serialized by
         * ll_inode_size_lock(). This guarantees that short reads are handled
         * correctly in the face of concurrent writes and truncates.
         */
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(ll_i2sbi(inode)->ll_dt_exp, lsm, &lvb, 1);
        kms = lvb.lvb_size;
        if (*ppos + count - 1 > kms) {
                /* A glimpse is necessary to determine whether we return a
                 * short read (B) or some zeroes at the end of the buffer (C) */
                ll_inode_size_unlock(inode, 1);
                retval = ll_glimpse_size(inode, LDLM_FL_BLOCK_GRANTED);
                if (retval)
                        goto out;
        } else {
                /* region is within kms and, hence, within real file size (A) */
                inode->i_size = kms;
                ll_inode_size_unlock(inode, 1);
        }

        CDEBUG(D_INFO, "Read ino %lu, "LPSZ" bytes, offset %lld, i_size %llu\n",
               inode->i_ino, count, *ppos, inode->i_size);

        /* turn off the kernel's read-ahead */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        file->f_ramax = 0;
#else
        file->f_ra.ra_pages = 0;
#endif
        bead.lrr_start = *ppos >> CFS_PAGE_SHIFT;
        bead.lrr_count = (count + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
        ll_ra_read_in(file, &bead);
        /* BUG: 5972 */
        file_accessed(file);
        retval = generic_file_read(file, buf, count, ppos);
        ll_ra_read_ex(file, &bead);

 out:
        ll_tree_unlock(&tree);
        RETURN(retval);
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t ll_file_write(struct file *file, const char *buf, size_t count,
                             loff_t *ppos)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_lock_tree tree;
        struct ll_lock_tree_node *node;
        loff_t maxbytes = ll_file_maxbytes(inode);
        ssize_t retval;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size="LPSZ",offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, count, *ppos);

        SIGNAL_MASK_ASSERT(); /* XXX BUG 1511 */

        /* POSIX, but surprised the VFS doesn't check this already */
        if (count == 0)
                RETURN(0);

        /* If file was opened for LL_IOC_LOV_SETSTRIPE but the ioctl wasn't
         * called on the file, don't fail the below assertion (bug 2388). */
        if (file->f_flags & O_LOV_DELAY_CREATE &&
            ll_i2info(inode)->lli_smd == NULL)
                RETURN(-EBADF);

        LASSERT(ll_i2info(inode)->lli_smd != NULL);

        if (file->f_flags & O_APPEND)
                node = ll_node_from_inode(inode, 0, OBD_OBJECT_EOF, LCK_PW);
        else
                node = ll_node_from_inode(inode, *ppos, *ppos  + count - 1,
                                          LCK_PW);

        if (IS_ERR(node))
                RETURN(PTR_ERR(node));

        tree.lt_fd = LUSTRE_FPRIVATE(file);
        rc = ll_tree_lock(&tree, node, buf, count,
                          file->f_flags & O_NONBLOCK ? LDLM_FL_BLOCK_NOWAIT :0);
        if (rc != 0)
                RETURN(rc);

        /* this is ok, g_f_w will overwrite this under i_mutex if it races
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

        /* generic_file_write handles O_APPEND after getting i_mutex */
        retval = generic_file_write(file, buf, count, ppos);

out:
        ll_tree_unlock(&tree);
        lprocfs_counter_add(ll_i2sbi(inode)->ll_stats, LPROC_LL_WRITE_BYTES,
                            retval > 0 ? retval : 0);
        RETURN(retval);
}

/*
 * Send file content (through pagecache) somewhere with helper
 */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static ssize_t ll_file_sendfile(struct file *in_file, loff_t *ppos,size_t count,
                                read_actor_t actor, void *target)
{
        struct inode *inode = in_file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_lock_tree tree;
        struct ll_lock_tree_node *node;
        struct ost_lvb lvb;
        struct ll_ra_read bead;
        int rc;
        ssize_t retval;
        __u64 kms;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size="LPSZ",offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, count, *ppos);

        /* "If nbyte is 0, read() will return 0 and have no other results."
         *                      -- Single Unix Spec */
        if (count == 0)
                RETURN(0);

        lprocfs_counter_add(ll_i2sbi(inode)->ll_stats, LPROC_LL_READ_BYTES,
                            count);

        /* File with no objects, nothing to lock */
        if (!lsm)
                RETURN(generic_file_sendfile(in_file, ppos, count, actor, target));

        node = ll_node_from_inode(inode, *ppos, *ppos + count - 1, LCK_PR);
        tree.lt_fd = LUSTRE_FPRIVATE(in_file);
        rc = ll_tree_lock(&tree, node, NULL, count,
                          in_file->f_flags & O_NONBLOCK?LDLM_FL_BLOCK_NOWAIT:0);
        if (rc != 0)
                RETURN(rc);

        ll_inode_size_lock(inode, 1);
        /*
         * Consistency guarantees: following possibilities exist for the
         * relation between region being read and real file size at this
         * moment:
         *
         *  (A): the region is completely inside of the file;
         *
         *  (B-x): x bytes of region are inside of the file, the rest is
         *  outside;
         *
         *  (C): the region is completely outside of the file.
         *
         * This classification is stable under DLM lock acquired by
         * ll_tree_lock() above, because to change class, other client has to
         * take DLM lock conflicting with our lock. Also, any updates to
         * ->i_size by other threads on this client are serialized by
         * ll_inode_size_lock(). This guarantees that short reads are handled
         * correctly in the face of concurrent writes and truncates.
         */
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(ll_i2sbi(inode)->ll_dt_exp, lsm, &lvb, 1);
        kms = lvb.lvb_size;
        if (*ppos + count - 1 > kms) {
                /* A glimpse is necessary to determine whether we return a
                 * short read (B) or some zeroes at the end of the buffer (C) */
                ll_inode_size_unlock(inode, 1);
                retval = ll_glimpse_size(inode, LDLM_FL_BLOCK_GRANTED);
                if (retval)
                        goto out;
        } else {
                /* region is within kms and, hence, within real file size (A) */
                inode->i_size = kms;
                ll_inode_size_unlock(inode, 1);
        }

        CDEBUG(D_INFO, "Send ino %lu, "LPSZ" bytes, offset %lld, i_size %llu\n",
               inode->i_ino, count, *ppos, inode->i_size);

        /* turn off the kernel's read-ahead */
        in_file->f_ra.ra_pages = 0;

        bead.lrr_start = *ppos >> CFS_PAGE_SHIFT;
        bead.lrr_count = (count + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
        ll_ra_read_in(in_file, &bead);
        /* BUG: 5972 */
        file_accessed(in_file);
        retval = generic_file_sendfile(in_file, ppos, count, actor, target);
        ll_ra_read_ex(in_file, &bead);

 out:
        ll_tree_unlock(&tree);
        RETURN(retval);
}
#endif

static int ll_lov_recreate_obj(struct inode *inode, struct file *file,
                               unsigned long arg)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_export *exp = ll_i2dtexp(inode);
        struct ll_recreate_obj ucreatp;
        struct obd_trans_info oti = { 0 };
        struct obdo *oa = NULL;
        int lsm_size;
        int rc = 0;
        struct lov_stripe_md *lsm, *lsm2;
        ENTRY;

        if (!capable (CAP_SYS_ADMIN))
                RETURN(-EPERM);

        rc = copy_from_user(&ucreatp, (struct ll_recreate_obj *)arg,
                            sizeof(struct ll_recreate_obj));
        if (rc) {
                RETURN(-EFAULT);
        }
        oa = obdo_alloc();
        if (oa == NULL)
                RETURN(-ENOMEM);

        down(&lli->lli_open_sem);
        lsm = lli->lli_smd;
        if (lsm == NULL)
                GOTO(out, rc = -ENOENT);
        lsm_size = sizeof(*lsm) + (sizeof(struct lov_oinfo) *
                   (lsm->lsm_stripe_count));

        OBD_ALLOC(lsm2, lsm_size);
        if (lsm2 == NULL)
                GOTO(out, rc = -ENOMEM);

        oa->o_id = ucreatp.lrc_id;
        oa->o_nlink = ucreatp.lrc_ost_idx;
        oa->o_flags |= OBD_FL_RECREATE_OBJS;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLFLAGS;
        obdo_from_inode(oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                        OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        oti.oti_objid = NULL;
        memcpy(lsm2, lsm, lsm_size);
        rc = obd_create(exp, oa, &lsm2, &oti);

        OBD_FREE(lsm2, lsm_size);
        GOTO(out, rc);
out:
        up(&lli->lli_open_sem);
        obdo_free(oa);
        return rc;
}

static int ll_lov_setstripe_ea_info(struct inode *inode, struct file *file,
                                    int flags, struct lov_user_md *lum,
                                    int lum_size)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct file *f = NULL;
        struct obd_export *dt_exp = ll_i2dtexp(inode);
        struct obd_export *md_exp = ll_i2mdexp(inode);
        struct lov_stripe_md *lsm;
        struct lookup_intent oit = {.it_op = IT_OPEN, .it_flags = flags};
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        int rc = 0;
        struct lustre_md md;
        ENTRY;

        down(&lli->lli_open_sem);
        lsm = lli->lli_smd;
        if (lsm) {
                up(&lli->lli_open_sem);
                CDEBUG(D_IOCTL, "stripe already exists for ino %lu\n",
                       inode->i_ino);
                RETURN(-EEXIST);
        }

        fd = ll_file_data_get();
        if (fd == NULL)
                GOTO(out, -ENOMEM);

        f = get_empty_filp();
        if (!f)
                GOTO(out, -ENOMEM);

        f->f_dentry = dget(file->f_dentry);
        f->f_vfsmnt = mntget(file->f_vfsmnt);

        rc = ll_intent_file_open(f, lum, lum_size, &oit);
        if (rc)
                GOTO(out, rc);
        if (it_disposition(&oit, DISP_LOOKUP_NEG))
                GOTO(out, -ENOENT);
        req = oit.d.lustre.it_data;
        rc = oit.d.lustre.it_status;

        if (rc < 0)
                GOTO(out, rc);

        rc = md_get_lustre_md(md_exp, req, 1, dt_exp, &md);
        if (rc)
                GOTO(out, rc);
        ll_update_inode(f->f_dentry->d_inode, &md);

        rc = ll_local_open(f, &oit, fd);
        if (rc)
                GOTO(out, rc);
        fd = NULL;
        ll_intent_release(&oit);

        rc = ll_file_release(f->f_dentry->d_inode, f);

 out:
        if (f)
                fput(f);
        ll_file_data_put(fd);
        up(&lli->lli_open_sem);
        if (req != NULL)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int ll_lov_setea(struct inode *inode, struct file *file,
                            unsigned long arg)
{
        int flags = MDS_OPEN_HAS_OBJS | FMODE_WRITE;
        struct lov_user_md  *lump;
        int lum_size = sizeof(struct lov_user_md) +
                       sizeof(struct lov_user_ost_data);
        int rc;
        ENTRY;

        if (!capable (CAP_SYS_ADMIN))
                RETURN(-EPERM);

        OBD_ALLOC(lump, lum_size);
        if (lump == NULL) {
                RETURN(-ENOMEM);
        }
        rc = copy_from_user(lump, (struct lov_user_md  *)arg, lum_size);
        if (rc) {
                OBD_FREE(lump, lum_size);
                RETURN(-EFAULT);
        }

        rc = ll_lov_setstripe_ea_info(inode, file, flags, lump, lum_size);

        OBD_FREE(lump, lum_size);
        RETURN(rc);
}

static int ll_lov_setstripe(struct inode *inode, struct file *file,
                            unsigned long arg)
{
        struct lov_user_md lum, *lump = (struct lov_user_md *)arg;
        int rc;
        int flags = FMODE_WRITE;
        ENTRY;

        /* Bug 1152: copy properly when this is no longer true */
        LASSERT(sizeof(lum) == sizeof(*lump));
        LASSERT(sizeof(lum.lmm_objects[0]) == sizeof(lump->lmm_objects[0]));
        rc = copy_from_user(&lum, lump, sizeof(lum));
        if (rc)
                RETURN(-EFAULT);

        rc = ll_lov_setstripe_ea_info(inode, file, flags, &lum, sizeof(lum));
        if (rc == 0) {
                 put_user(0, &lump->lmm_stripe_count);
                 rc = obd_iocontrol(LL_IOC_LOV_GETSTRIPE, ll_i2dtexp(inode),
                                    0, ll_i2info(inode)->lli_smd, lump);
        }
        RETURN(rc);
}

static int ll_lov_getstripe(struct inode *inode, unsigned long arg)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;

        if (!lsm)
                RETURN(-ENODATA);

        return obd_iocontrol(LL_IOC_LOV_GETSTRIPE, ll_i2dtexp(inode), 0, lsm,
                            (void *)arg);
}

static int ll_get_grouplock(struct inode *inode, struct file *file,
                            unsigned long arg)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        ldlm_policy_data_t policy = { .l_extent = { .start = 0,
                                                    .end = OBD_OBJECT_EOF}};
        struct lustre_handle lockh = { 0 };
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        int flags = 0, rc;
        ENTRY;

        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                RETURN(-EINVAL);
        }

        policy.l_extent.gid = arg;
        if (file->f_flags & O_NONBLOCK)
                flags = LDLM_FL_BLOCK_NOWAIT;

        rc = ll_extent_lock(fd, inode, lsm, LCK_GROUP, &policy, &lockh, flags);
        if (rc)
                RETURN(rc);

        fd->fd_flags |= LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK;
        fd->fd_gid = arg;
        memcpy(&fd->fd_cwlockh, &lockh, sizeof(lockh));

        RETURN(0);
}

static int ll_put_grouplock(struct inode *inode, struct file *file,
                            unsigned long arg)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        int rc;
        ENTRY;

        if (!(fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
                /* Ugh, it's already unlocked. */
                RETURN(-EINVAL);
        }

        if (fd->fd_gid != arg) /* Ugh? Unlocking with different gid? */
                RETURN(-EINVAL);

        fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);

        rc = ll_extent_unlock(fd, inode, lsm, LCK_GROUP, &fd->fd_cwlockh);
        if (rc)
                RETURN(rc);

        fd->fd_gid = 0;
        memset(&fd->fd_cwlockh, 0, sizeof(fd->fd_cwlockh));

        RETURN(0);
}

static int join_sanity_check(struct inode *head, struct inode *tail)
{
        ENTRY;
        if ((ll_i2sbi(head)->ll_flags & LL_SBI_JOIN) == 0) {
                CERROR("server do not support join \n");
                RETURN(-EINVAL);
        }
        if (!S_ISREG(tail->i_mode) || !S_ISREG(head->i_mode)) {
                CERROR("tail ino %lu and ino head %lu must be regular\n",
                       head->i_ino, tail->i_ino);
                RETURN(-EINVAL);
        }
        if (head->i_ino == tail->i_ino) {
                CERROR("file %lu can not be joined to itself \n", head->i_ino);
                RETURN(-EINVAL);
        }
        if (head->i_size % JOIN_FILE_ALIGN) {
                CERROR("hsize" LPU64 " must be times of 64K\n",
                        head->i_size);
                RETURN(-EINVAL);
        }
        RETURN(0);
}

static int join_file(struct inode *head_inode, struct file *head_filp,
                     struct file *tail_filp)
{
        struct inode *tail_inode, *tail_parent;
        struct dentry *tail_dentry = tail_filp->f_dentry;
        struct lookup_intent oit = {.it_op = IT_OPEN,
                                   .it_flags = head_filp->f_flags|O_JOIN_FILE};
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        struct lustre_handle lockh;
        struct md_op_data *op_data;
        __u32  hsize = head_inode->i_size >> 32;
        __u32  tsize = head_inode->i_size;
        struct file *f;
        int    rc;
        ENTRY;

        tail_dentry = tail_filp->f_dentry;
        tail_inode = tail_dentry->d_inode;
        tail_parent = tail_dentry->d_parent->d_inode;

        fd = ll_file_data_get();
        if (fd == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL) {
                ll_file_data_put(fd);
                RETURN(-ENOMEM);
        }

        f = get_empty_filp();
        if (f == NULL)
                GOTO(out, rc = -ENOMEM);

        f->f_dentry = dget(head_filp->f_dentry);
        f->f_vfsmnt = mntget(head_filp->f_vfsmnt);

        ll_prepare_md_op_data(op_data, head_inode, tail_parent,
                              tail_dentry->d_name.name,
                              tail_dentry->d_name.len, 0);

        rc = md_enqueue(ll_i2mdexp(head_inode), LDLM_IBITS, &oit, LCK_PW,
                        op_data, &lockh, &tsize, 0, ldlm_completion_ast,
                        ll_md_blocking_ast, &hsize, 0);

        if (rc < 0)
                GOTO(out, rc);

        req = oit.d.lustre.it_data;
        rc = oit.d.lustre.it_status;

        if (rc < 0)
                GOTO(out, rc);

        rc = ll_local_open(f, &oit, fd);
        LASSERTF(rc == 0, "rc = %d\n", rc);

        fd = NULL;
        ll_intent_release(&oit);

        rc = ll_file_release(f->f_dentry->d_inode, f);
out:
        if (op_data)
                OBD_FREE_PTR(op_data);
        if (f)
                fput(f);
        ll_file_data_put(fd);
        ptlrpc_req_finished(req);
        RETURN(rc);
}

static int ll_file_join(struct inode *head, struct file *filp,
                        char *filename_tail)
{
        struct inode *tail = NULL, *first = NULL, *second = NULL;
        struct dentry *tail_dentry;
        struct file *tail_filp, *first_filp, *second_filp;
        struct ll_lock_tree first_tree, second_tree;
        struct ll_lock_tree_node *first_node, *second_node;
        struct ll_inode_info *hlli = ll_i2info(head), *tlli;
        int rc = 0, cleanup_phase = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:head=%lu/%u(%p) tail %s\n",
               head->i_ino, head->i_generation, head, filename_tail);

        tail_filp = filp_open(filename_tail, O_WRONLY, 0644);
        if (IS_ERR(tail_filp)) {
                CERROR("Can not open tail file %s", filename_tail);
                rc = PTR_ERR(tail_filp);
                GOTO(cleanup, rc);
        }
        tail = igrab(tail_filp->f_dentry->d_inode);

        tlli = ll_i2info(tail);
        tail_dentry = tail_filp->f_dentry;
        LASSERT(tail_dentry);
        cleanup_phase = 1;

        /*reorder the inode for lock sequence*/
        first = head->i_ino > tail->i_ino ? head : tail;
        second = head->i_ino > tail->i_ino ? tail : head;
        first_filp = head->i_ino > tail->i_ino ? filp : tail_filp;
        second_filp = head->i_ino > tail->i_ino ? tail_filp : filp;

        CDEBUG(D_INFO, "reorder object from %lu:%lu to %lu:%lu \n",
               head->i_ino, tail->i_ino, first->i_ino, second->i_ino);
        first_node = ll_node_from_inode(first, 0, OBD_OBJECT_EOF, LCK_EX);
        if (IS_ERR(first_node)){
                rc = PTR_ERR(first_node);
                GOTO(cleanup, rc);
        }
        first_tree.lt_fd = first_filp->private_data;
        rc = ll_tree_lock(&first_tree, first_node, NULL, 0, 0);
        if (rc != 0)
                GOTO(cleanup, rc);
        cleanup_phase = 2;

        second_node = ll_node_from_inode(second, 0, OBD_OBJECT_EOF, LCK_EX);
        if (IS_ERR(second_node)){
                rc = PTR_ERR(second_node);
                GOTO(cleanup, rc);
        }
        second_tree.lt_fd = second_filp->private_data;
        rc = ll_tree_lock(&second_tree, second_node, NULL, 0, 0);
        if (rc != 0)
                GOTO(cleanup, rc);
        cleanup_phase = 3;

        rc = join_sanity_check(head, tail);
        if (rc)
                GOTO(cleanup, rc);

        rc = join_file(head, filp, tail_filp);
        if (rc)
                GOTO(cleanup, rc);
cleanup:
        switch (cleanup_phase) {
        case 3:
                ll_tree_unlock(&second_tree);
                obd_cancel_unused(ll_i2dtexp(second),
                                  ll_i2info(second)->lli_smd, 0, NULL);
        case 2:
                ll_tree_unlock(&first_tree);
                obd_cancel_unused(ll_i2dtexp(first),
                                  ll_i2info(first)->lli_smd, 0, NULL);
        case 1:
                filp_close(tail_filp, 0);
                if (tail)
                        iput(tail);
                if (head && rc == 0) {
                        obd_free_memmd(ll_i2sbi(head)->ll_dt_exp,
                                       &hlli->lli_smd);
                        hlli->lli_smd = NULL;
                }
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        RETURN(rc);
}

int ll_release_openhandle(struct dentry *dentry, struct lookup_intent *it)
{
        struct inode *inode = dentry->d_inode;
        struct obd_client_handle *och;
        int rc;
        ENTRY;

        LASSERT(inode);

        /* Root ? Do nothing. */
        if (dentry->d_inode->i_sb->s_root == dentry)
                RETURN(0);

        /* No open handle to close? Move away */
        if (!it_disposition(it, DISP_OPEN_OPEN))
                RETURN(0);

        OBD_ALLOC(och, sizeof(*och));
        if (!och)
                GOTO(out, rc = -ENOMEM);

        ll_och_fill(ll_i2sbi(inode)->ll_md_exp,
                    ll_i2info(inode), it, och);

        rc = ll_close_inode_openhandle(ll_i2sbi(inode)->ll_md_exp,
                                       inode, och);

        OBD_FREE(och, sizeof(*och));
 out:
        /* this one is in place of ll_file_open */
        ptlrpc_req_finished(it->d.lustre.it_data);
        RETURN(rc);
}

int ll_file_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                  unsigned long arg)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        int flags;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),cmd=%x\n", inode->i_ino,
               inode->i_generation, inode, cmd);

        /* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
        if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
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

                if (cmd == LL_IOC_SETFLAGS) {
                        if ((flags & LL_FILE_IGNORE_LOCK) &&
                            !(file->f_flags & O_DIRECT)) {
                                CERROR("%s: unable to disable locking on "
                                       "non-O_DIRECT file\n", current->comm);
                                RETURN(-EINVAL);
                        }

                        fd->fd_flags |= flags;
                } else {
                        fd->fd_flags &= ~flags;
                }
                RETURN(0);
        case LL_IOC_LOV_SETSTRIPE:
                RETURN(ll_lov_setstripe(inode, file, arg));
        case LL_IOC_LOV_SETEA:
                RETURN(ll_lov_setea(inode, file, arg));
        case LL_IOC_LOV_GETSTRIPE:
                RETURN(ll_lov_getstripe(inode, arg));
        case LL_IOC_RECREATE_OBJ:
                RETURN(ll_lov_recreate_obj(inode, file, arg));
        case EXT3_IOC_GETFLAGS:
        case EXT3_IOC_SETFLAGS:
                RETURN(ll_iocontrol(inode, file, cmd, arg));
        case EXT3_IOC_GETVERSION_OLD:
        case EXT3_IOC_GETVERSION:
                RETURN(put_user(inode->i_generation, (int *)arg));
        case LL_IOC_JOIN: {
                char *ftail;
                int rc;

                ftail = getname((const char *)arg);
                if (IS_ERR(ftail))
                        RETURN(PTR_ERR(ftail));
                rc = ll_file_join(inode, file, ftail);
                putname(ftail);
                RETURN(rc);
        }
        case LL_IOC_GROUP_LOCK:
                RETURN(ll_get_grouplock(inode, file, arg));
        case LL_IOC_GROUP_UNLOCK:
                RETURN(ll_put_grouplock(inode, file, arg));
        case LL_IOC_OBD_STATFS:
                RETURN(ll_obd_statfs(inode, (void *)arg));

        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT3_IOC_SETVERSION_OLD:
        case EXT3_IOC_SETVERSION:
        */
        default:
                RETURN(obd_iocontrol(cmd, ll_i2dtexp(inode), 0, NULL,
                                     (void *)arg));
        }
}

loff_t ll_file_seek(struct file *file, loff_t offset, int origin)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        loff_t retval;
        ENTRY;
        retval = offset + ((origin == 2) ? inode->i_size :
                           (origin == 1) ? file->f_pos : 0);
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), to=%Lu=%#Lx(%s)\n",
               inode->i_ino, inode->i_generation, inode, retval, retval,
               origin == 2 ? "SEEK_END": origin == 1 ? "SEEK_CUR" : "SEEK_SET");

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_LLSEEK);
        if (origin == 2) { /* SEEK_END */
                int nonblock = 0, rc;

                if (file->f_flags & O_NONBLOCK)
                        nonblock = LDLM_FL_BLOCK_NOWAIT;

                if (lsm != NULL) {
                        rc = ll_glimpse_size(inode, nonblock);
                        if (rc != 0)
                                RETURN(rc);
                }

                ll_inode_size_lock(inode, 0);
                offset += inode->i_size;
                ll_inode_size_unlock(inode, 0);
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

        RETURN(retval);
}

int ll_fsync(struct file *file, struct dentry *dentry, int data)
{
        struct inode *inode = dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ptlrpc_request *req;
        int rc, err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_FSYNC);

        /* fsync's caller has already called _fdata{sync,write}, we want
         * that IO to finish before calling the osc and mdc sync methods */
        rc = filemap_fdatawait(inode->i_mapping);

        /* catch async errors that were recorded back when async writeback
         * failed for pages in this mapping. */
        err = lli->lli_async_rc;
        lli->lli_async_rc = 0;
        if (rc == 0)
                rc = err;
        if (lsm) {
                err = lov_test_and_clear_async_rc(lsm);
                if (rc == 0)
                        rc = err;
        }

        err = md_sync(ll_i2sbi(inode)->ll_md_exp,
                      ll_inode2fid(inode), &req);
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

                err = obd_sync(ll_i2sbi(inode)->ll_dt_exp, oa, lsm,
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
                { .name = { fid_seq(ll_inode2fid(inode)),
                            fid_oid(ll_inode2fid(inode)),
                            fid_ver(ll_inode2fid(inode)),
                            LDLM_FLOCK} };
        struct lustre_handle lockh = {0};
        ldlm_policy_data_t flock;
        ldlm_mode_t mode = 0;
        int flags = 0;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu file_lock=%p\n",
               inode->i_ino, file_lock);

        flock.l_flock.pid = file_lock->fl_pid;
        flock.l_flock.start = file_lock->fl_start;
        flock.l_flock.end = file_lock->fl_end;

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
#ifdef F_SETLKW64
        case F_SETLKW64:
#endif
                flags = 0;
                break;
        case F_SETLK:
#ifdef F_SETLK64
        case F_SETLK64:
#endif
                flags = LDLM_FL_BLOCK_NOWAIT;
                break;
        case F_GETLK:
#ifdef F_GETLK64
        case F_GETLK64:
#endif
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
               "start="LPU64", end="LPU64"\n", inode->i_ino, flock.l_flock.pid,
               flags, mode, flock.l_flock.start, flock.l_flock.end);

        obddev = sbi->ll_md_exp->exp_obd;
        rc = ldlm_cli_enqueue(sbi->ll_md_exp, NULL, obddev->obd_namespace,
                              res_id, LDLM_FLOCK, &flock, mode, &flags,
                              NULL, ldlm_flock_completion_ast, NULL, file_lock,
                              NULL, 0, NULL, &lockh);
        RETURN(rc);
}

int ll_have_md_lock(struct inode *inode, __u64 bits)
{
        struct lustre_handle lockh;
        ldlm_policy_data_t policy = { .l_inodebits = {bits}};
        struct lu_fid *fid;
        int flags;
        ENTRY;

        if (!inode)
               RETURN(0);

        fid = &ll_i2info(inode)->lli_fid;
        CDEBUG(D_INFO, "trying to match res "DFID3"\n", PFID3(fid));

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
        if (md_lock_match(ll_i2mdexp(inode), flags, fid, LDLM_IBITS, &policy, 
                                LCK_CR|LCK_CW|LCK_PR, &lockh)) {
                RETURN(1);
        }

        RETURN(0);
}

int ll_inode_revalidate_it(struct dentry *dentry, struct lookup_intent *it)
{
        struct lookup_intent oit = { .it_op = IT_GETATTR };
        struct inode *inode = dentry->d_inode;
        struct ptlrpc_request *req = NULL;
        struct md_op_data *op_data;
        struct ll_inode_info *lli;
        struct ll_sb_info *sbi;
        int rc;
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }
        sbi = ll_i2sbi(inode);
        lli = ll_i2info(inode);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),name=%s\n",
               inode->i_ino, inode->i_generation, inode, dentry->d_name.name);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,5,0))
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_REVALIDATE);
#endif

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);

        ll_prepare_md_op_data(op_data, inode, inode, NULL, 0, 0);

        rc = md_intent_lock(sbi->ll_md_exp, op_data, NULL, 0, &oit, 0,
                            &req, ll_md_blocking_ast, 0);
        OBD_FREE_PTR(op_data);

        if (rc < 0)
                GOTO(out, rc);

        rc = ll_revalidate_it_finish(req, 1, &oit, dentry);
        if (rc)
                GOTO(out, rc);
        
        if (!dentry->d_inode->i_nlink) {
                spin_lock(&dcache_lock);
                ll_drop_dentry(dentry);
                spin_unlock(&dcache_lock);
        }
        
        ll_lookup_finish_locks(&oit, dentry);

        /* object is allocated, validate size */
        if (lli->lli_smd) {
                /* ll_glimpse_size will prefer locally cached writes if they
                 * extend the file */
                rc = ll_glimpse_size(inode, 0);
        }
        EXIT;
out:
        if (req)
                ptlrpc_req_finished(req);
        return rc;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
int ll_getattr_it(struct vfsmount *mnt, struct dentry *de,
                  struct lookup_intent *it, struct kstat *stat)
{
        struct inode *inode = de->d_inode;
        int res = 0;

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
        stat->blksize = inode->i_blksize;

        ll_inode_size_lock(inode, 0);
        stat->size = inode->i_size;
        stat->blocks = inode->i_blocks;
        ll_inode_size_unlock(inode, 0);

        return 0;
}
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat)
{
        struct lookup_intent it = { .it_op = IT_GETATTR };

        return ll_getattr_it(mnt, de, &it, stat);
}
#endif

static
int lustre_check_acl(struct inode *inode, int mask)
{
#ifdef CONFIG_FS_POSIX_ACL
        struct ll_inode_info *lli = ll_i2info(inode);
        struct posix_acl *acl;
        int rc;
        ENTRY;

        spin_lock(&lli->lli_lock);
        acl = posix_acl_dup(lli->lli_posix_acl);
        spin_unlock(&lli->lli_lock);

        if (!acl)
                RETURN(-EAGAIN);

        rc = posix_acl_permission(inode, acl, mask);
        posix_acl_release(acl);

        RETURN(rc);
#else
        return -EAGAIN;
#endif
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10))
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), mask %o\n",
               inode->i_ino, inode->i_generation, inode, mask);
        return generic_permission(inode, mask, lustre_check_acl);
}
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
#else
int ll_inode_permission(struct inode *inode, int mask)
#endif
{
        int mode = inode->i_mode;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), mask %o\n",
               inode->i_ino, inode->i_generation, inode, mask);

        if ((mask & MAY_WRITE) && IS_RDONLY(inode) &&
            (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
                return -EROFS;
        if ((mask & MAY_WRITE) && IS_IMMUTABLE(inode))
                return -EACCES;
        if (current->fsuid == inode->i_uid) {
                mode >>= 6;
        } else if (1) {
                if (((mode >> 3) & mask & S_IRWXO) != mask)
                        goto check_groups;
                rc = lustre_check_acl(inode, mask);
                if (rc == -EAGAIN)
                        goto check_groups;
                if (rc == -EACCES)
                        goto check_capabilities;
                return rc;
        } else {
check_groups:
                if (in_group_p(inode->i_gid))
                        mode >>= 3;
        }
        if ((mode & mask & S_IRWXO) == mask)
                return 0;

check_capabilities:
        if (!(mask & MAY_EXEC) ||
            (inode->i_mode & S_IXUGO) || S_ISDIR(inode->i_mode))
                if (capable(CAP_DAC_OVERRIDE))
                        return 0;

        if (capable(CAP_DAC_READ_SEARCH) && ((mask == MAY_READ) ||
            (S_ISDIR(inode->i_mode) && !(mask & MAY_WRITE))))
                return 0;
        return -EACCES;
}
#endif

struct file_operations ll_file_operations = {
        .read           = ll_file_read,
        .write          = ll_file_write,
        .ioctl          = ll_file_ioctl,
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        .sendfile       = ll_file_sendfile,
#endif
        .fsync          = ll_fsync,
        /* .lock           = ll_file_flock */
};

struct file_operations ll_file_operations_flock = {
        .read           = ll_file_read,
        .write          = ll_file_write,
        .ioctl          = ll_file_ioctl,
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        .sendfile       = ll_file_sendfile,
#endif
        .fsync          = ll_fsync,
        .lock           = ll_file_flock
};


struct inode_operations ll_file_inode_operations = {
        .setattr_raw    = ll_setattr_raw,
        .setattr        = ll_setattr,
        .truncate       = ll_truncate,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        .getattr_it     = ll_getattr_it,
#else
        .revalidate_it  = ll_inode_revalidate_it,
#endif
        .permission     = ll_inode_permission,
        .setxattr       = ll_setxattr,
        .getxattr       = ll_getxattr,
        .listxattr      = ll_listxattr,
        .removexattr    = ll_removexattr,
};

