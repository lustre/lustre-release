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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/lustre_compat25.h>
#endif

#include "llite_internal.h"

static int ll_mdc_close(struct lustre_handle *mdc_conn, struct inode *inode,
                        struct file *file)
{
        struct ll_file_data *fd = file->private_data;
        struct ptlrpc_request *req = NULL;
        unsigned long flags;
        struct obd_import *imp;
        int rc;
        ENTRY;

        /* Complete the open request and remove it from replay list */
        rc = mdc_close(&ll_i2sbi(inode)->ll_mdc_conn, inode->i_ino,
                       inode->i_mode, &fd->fd_mds_och.och_fh, &req);
        if (rc)
                CERROR("inode %lu close failed: rc = %d\n", inode->i_ino, rc);

        imp = fd->fd_mds_och.och_req->rq_import;
        LASSERT(imp != NULL);
        spin_lock_irqsave(&imp->imp_lock, flags);

        DEBUG_REQ(D_HA, fd->fd_mds_och.och_req, "matched open req %p",
                  fd->fd_mds_och.och_req);

        /* We held on to the request for replay until we saw a close for that
         * file.  Now that we've closed it, it gets replayed on the basis of
         * its transno only. */
        spin_lock (&fd->fd_mds_och.och_req->rq_lock);
        fd->fd_mds_och.och_req->rq_replay = 0;
        spin_unlock (&fd->fd_mds_och.och_req->rq_lock);

        if (fd->fd_mds_och.och_req->rq_transno) {
                /* This open created a file, so it needs replay as a
                 * normal transaction now.  Our reference to it now
                 * effectively owned by the imp_replay_list, and it'll
                 * be committed just like other transno-having
                 * requests from here on out. */

                /* We now retain this close request, so that it is
                 * replayed if the open is replayed.  We duplicate the
                 * transno, so that we get freed at the right time,
                 * and rely on the difference in xid to keep
                 * everything ordered correctly.
                 *
                 * But! If this close was already given a transno
                 * (because it caused real unlinking of an
                 * open-unlinked file, f.e.), then we'll be ordered on
                 * the basis of that and we don't need to do anything
                 * magical here. */
                if (!req->rq_transno) {
                        req->rq_transno = fd->fd_mds_och.och_req->rq_transno;
                        ptlrpc_retain_replayable_request(req, imp);
                }
                spin_unlock_irqrestore(&imp->imp_lock, flags);

                /* Should we free_committed now? we always free before
                 * replay, so it's probably a wash.  We could check to
                 * see if the fd_req should already be committed, in
                 * which case we can avoid the whole retain_replayable
                 * dance. */
        } else {
                /* No transno means that we can just drop our ref. */
                spin_unlock_irqrestore(&imp->imp_lock, flags);
        }
        ptlrpc_req_finished(fd->fd_mds_och.och_req);

        /* Do this after the fd_req->rq_transno check, because we don't want
         * to bounce off zero references. */
        ptlrpc_req_finished(req);
        fd->fd_mds_och.och_fh.cookie = DEAD_HANDLE_MAGIC;
        file->private_data = NULL;
        OBD_SLAB_FREE(fd, ll_file_data_slab, sizeof *fd);

        RETURN(-abs(rc));
}

/* While this returns an error code, fput() the caller does not, so we need
 * to make every effort to clean up all of our state here.  Also, applications
 * rarely check close errors and even if an error is returned they will not
 * re-try the close call.
 */
int ll_file_release(struct inode *inode, struct file *file)
{
        struct ll_file_data *fd;
        struct obdo oa;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        int rc = 0, rc2;

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry)
                RETURN(0);

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_RELEASE);
        fd = (struct ll_file_data *)file->private_data;
        if (!fd) /* no process opened the file after an mcreate */
                RETURN(0);

        /* we might not be able to get a valid handle on this file
         * again so we really want to flush our write cache.. */
        if (S_ISREG(inode->i_mode) && lsm) {
                write_inode_now(inode, 0);
                obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                            OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                memcpy(obdo_handle(&oa), &fd->fd_ost_och, FD_OSTDATA_SIZE);
                oa.o_valid |= OBD_MD_FLHANDLE;

                rc = obd_close(&sbi->ll_osc_conn, &oa, lsm, NULL);
                if (rc)
                        CERROR("inode %lu object close failed: rc %d\n",
                               inode->i_ino, rc);
        }

        rc2 = ll_mdc_close(&sbi->ll_mdc_conn, inode, file);
        if (rc2 && !rc)
                rc = rc2;

        RETURN(rc);
}

static int ll_local_open(struct file *file, struct lookup_intent *it)
{
        struct ptlrpc_request *req = it->it_data;
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

        memset(fd, 0, sizeof(*fd));

        memcpy(&fd->fd_mds_och.och_fh, &body->handle, sizeof(body->handle));
        fd->fd_mds_och.och_req = it->it_data;
        file->private_data = fd;

        RETURN(0);
}

static int ll_osc_open(struct lustre_handle *conn, struct inode *inode,
                       struct file *file, struct lov_stripe_md *lsm)
{
        struct ll_file_data *fd = file->private_data;
        struct obdo *oa;
        int rc;
        ENTRY;

        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);
        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = S_IFREG;
        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, inode, OBD_MD_FLTYPE);
        rc = obd_open(conn, oa, lsm, NULL, &fd->fd_ost_och);
        if (rc)
                GOTO(out, rc);

        file->f_flags &= ~O_LOV_DELAY_CREATE;
        obdo_refresh_inode(inode, oa, (OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ |
                                       OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                       OBD_MD_FLCTIME));
        EXIT;
out:
        obdo_free(oa);
        return rc;
}

/* Caller must hold lli_open_sem to protect lli->lli_smd from changing and
 * duplicate objects from being created.  We only install lsm to lli_smd if
 * the mdc open was successful (hence stored stripe MD on MDS), otherwise
 * other nodes could try to create different objects for the same file.
 */
static int ll_create_obj(struct lustre_handle *conn, struct inode *inode,
                         struct file *file, struct lov_stripe_md *lsm)
{
        struct ptlrpc_request *req = NULL;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_mds_md *lmm = NULL;
        struct obdo *oa;
        struct iattr iattr;
        struct mdc_op_data op_data;
        struct obd_trans_info oti = { 0 };
        int rc, err, lmm_size = 0;
        ENTRY;

        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);

        LASSERT(S_ISREG(inode->i_mode));
        oa->o_mode = S_IFREG | 0600;
        oa->o_id = inode->i_ino;
        oa->o_generation = inode->i_generation;
        /* Keep these 0 for now, because chown/chgrp does not change the
         * ownership on the OST, and we don't want to allow BA OST NFS
         * users to access these objects by mistake. */
        oa->o_uid = 0;
        oa->o_gid = 0;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGENER | OBD_MD_FLTYPE |
                OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID;
#ifdef ENABLE_ORPHANS
        oa->o_valid |= OBD_MD_FLCOOKIE;
#endif

        obdo_from_inode(oa, inode, OBD_MD_FLTYPE|OBD_MD_FLATIME|OBD_MD_FLMTIME|
                        OBD_MD_FLCTIME | (inode->i_size ? OBD_MD_FLSIZE : 0));

        rc = obd_create(conn, oa, &lsm, &oti);
        if (rc) {
                CERROR("error creating objects for inode %lu: rc = %d\n",
                       inode->i_ino, rc);
                if (rc > 0) {
                        CERROR("obd_create returned invalid rc %d\n", rc);
                        rc = -EIO;
                }
                GOTO(out_oa, rc);
        }
        obdo_refresh_inode(inode, oa, OBD_MD_FLBLKSZ);

        LASSERT(lsm && lsm->lsm_object_id);
        rc = obd_packmd(conn, &lmm, lsm);
        if (rc < 0)
                GOTO(out_destroy, rc);

        lmm_size = rc;

        /* Save the stripe MD with this file on the MDS */
        memset(&iattr, 0, sizeof(iattr));
        iattr.ia_valid = ATTR_FROM_OPEN;

        ll_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);

#if 0
#warning FIXME: next line is for debugging purposes only
        obd_log_cancel(&ll_i2sbi(inode)->ll_osc_conn, lsm, oti.oti_numcookies,
                       oti.oti_logcookies, OBD_LLOG_FL_SENDNOW);
#endif

        rc = mdc_setattr(&ll_i2sbi(inode)->ll_mdc_conn, &op_data, &iattr,
                         lmm, lmm_size, oti.oti_logcookies,
                         oti.oti_numcookies * sizeof(oti.oti_onecookie), &req);
        ptlrpc_req_finished(req);

        obd_free_diskmd(conn, &lmm);

        /* If we couldn't complete mdc_open() and store the stripe MD on the
         * MDS, we need to destroy the objects now or they will be leaked.
         */
        if (rc) {
                CERROR("error: storing stripe MD for %lu: rc %d\n",
                       inode->i_ino, rc);
                GOTO(out_destroy, rc);
        }
        lli->lli_smd = lsm;
        lli->lli_maxbytes = lsm->lsm_maxbytes;

        EXIT;
out_oa:
        oti_free_cookies(&oti);
        obdo_free(oa);
        return rc;

out_destroy:
        oa->o_id = lsm->lsm_object_id;
        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, inode, OBD_MD_FLTYPE);
#if 0
        err = obd_log_cancel(conn, lsm, oti.oti_numcookies, oti.oti_logcookies,
                             OBD_LLOG_FL_SENDNOW);
        if (err)
                CERROR("error cancelling inode %lu log cookies: rc %d\n",
                       inode->i_ino, err);
#endif
        err = obd_destroy(conn, oa, lsm, NULL);
        obd_free_memmd(conn, &lsm);
        if (err)
                CERROR("error uncreating inode %lu objects: rc %d\n",
                       inode->i_ino, err);
        goto out_oa;
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
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle *conn = ll_i2obdconn(inode);
        struct lookup_intent *it;
        struct lov_stripe_md *lsm;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry)
                RETURN(0);

        it = file->f_it;
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_OPEN);

        rc = ll_it_open_error(DISP_OPEN_OPEN, it);
        if (rc)
                RETURN(rc);

        rc = ll_local_open(file, it);
        if (rc)
                LBUG();

        mdc_set_open_replay_data(&((struct ll_file_data *)
                                   file->private_data)->fd_mds_och);
        if (!S_ISREG(inode->i_mode))
                RETURN(0);

        lsm = lli->lli_smd;
        if (lsm == NULL) {
                if (file->f_flags & O_LOV_DELAY_CREATE ||
                    !(file->f_mode & FMODE_WRITE)) {
                        CDEBUG(D_INODE, "delaying object creation\n");
                        RETURN(0);
                }
                down(&lli->lli_open_sem);
                if (!lli->lli_smd) {
                        rc = ll_create_obj(conn, inode, file, NULL);
                        up(&lli->lli_open_sem);
                        if (rc)
                                GOTO(out_close, rc);
                } else {
                        CERROR("warning: stripe already set on ino %lu\n",
                               inode->i_ino);
                        up(&lli->lli_open_sem);
                }
                lsm = lli->lli_smd;
        }

        rc = ll_osc_open(conn, inode, file, lsm);
        if (rc)
                GOTO(out_close, rc);
        RETURN(0);

 out_close:
        ll_mdc_close(&sbi->ll_mdc_conn, inode, file);
        return rc;
}

/*
 * really does the getattr on the inode and updates its fields
 */
int ll_inode_getattr(struct inode *inode, struct lov_stripe_md *lsm,
                     void *ostdata)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ptlrpc_request_set *set;
        struct obdo oa;
        int bef, aft;
        unsigned long before, after;
        int rc;
        ENTRY;

        LASSERT(lsm);
        LASSERT(sbi);
        LASSERT(lli);

        memset(&oa, 0, sizeof oa);
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ | OBD_MD_FLMTIME |
                OBD_MD_FLCTIME;

        if (ostdata != NULL) {
                memcpy(obdo_handle(&oa), ostdata, FD_OSTDATA_SIZE);
                oa.o_valid |= OBD_MD_FLHANDLE;
        }

        /* getattr can race with writeback.  we don't want to trust a getattr
         * that doesn't include the writeback of our farthest cached pages
         * that it raced with. */
        /* Now that the OSC knows the cached-page status, it can and should be
         * adjusting its getattr results to include the maximum cached offset
         * for its stripe(s). */
        do {
                bef = obd_last_dirty_offset(ll_i2obdconn(inode), lli->lli_smd,
                                            &before);
#if 0
                rc = obd_getattr(&sbi->ll_osc_conn, &oa, lsm);
#else
                set = ptlrpc_prep_set ();
                if (set == NULL) {
                        CERROR ("ENOMEM allocing request set\n");
                        rc = -ENOMEM;
                } else {
                        rc = obd_getattr_async(&sbi->ll_osc_conn, &oa, lsm, set);
                        if (rc == 0)
                                rc = ptlrpc_set_wait (set);
                        ptlrpc_set_destroy (set);
                }
#endif
                if (rc)
                        RETURN(rc);

                aft = obd_last_dirty_offset(ll_i2obdconn(inode), lli->lli_smd,
                                            &after);
                CDEBUG(D_INODE, " %d,%lu -> %d,%lu\n", bef, before, aft, after);
        } while (bef == 0 &&
                 (aft != 0 || after < before) &&
                 oa.o_size < ((u64)before + 1) << PAGE_CACHE_SHIFT);

        obdo_refresh_inode(inode, &oa, (OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ |
                                        OBD_MD_FLMTIME | OBD_MD_FLCTIME));
        if (inode->i_blksize < PAGE_CACHE_SIZE)
                inode->i_blksize = PAGE_CACHE_SIZE;

        /* make sure getattr doesn't return a size that causes writeback
         * to forget about cached writes */
        if ((aft == 0) && oa.o_size < ((u64)after + 1) << PAGE_CACHE_SHIFT) {
                CDEBUG(D_INODE, "cached at %lu, keeping %llu i_size instead "
                                "of oa "LPU64"\n", after, inode->i_size,
                                oa.o_size);
                RETURN(0);
        }

        obdo_to_inode(inode, &oa, OBD_MD_FLSIZE);

        CDEBUG(D_INODE, "objid "LPX64" size %Lu/%Lu blksize %lu\n",
               lsm->lsm_object_id, inode->i_size, inode->i_size,
               inode->i_blksize);
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

#if 0
static void ll_update_atime(struct inode *inode)
{
        if (IS_RDONLY(inode)) return;

        /* update atime, but don't explicitly write it out just this change */
        inode->i_atime = CURRENT_TIME;
}
#endif

/*
 * flush the page cache for an extent as its canceled.  when we're on an
 * lov we get a lock cancelation for each of the obd locks under the lov
 * so we have to map the obd's region back onto the stripes in the file
 * that it held.
 *
 * no one can dirty the extent until we've finished our work and they
 * can enqueue another lock.
 *
 * XXX this could be asking the inode's dirty tree for info
 */
void ll_pgcache_remove_extent(struct inode *inode, struct lov_stripe_md *lsm,
                              struct ldlm_lock *lock)
{
        struct ldlm_extent *extent = &lock->l_extent;
        unsigned long start, end, count, skip, i, j;
        struct page *page;
        int ret;
        ENTRY;

        CDEBUG(D_INODE, "obdo %lu inode %p ["LPU64"->"LPU64"] size: %llu\n",
               inode->i_ino, inode, extent->start, extent->end, inode->i_size);

        start = extent->start >> PAGE_CACHE_SHIFT;
        count = ~0;
        skip = 0;
        end = (extent->end >> PAGE_CACHE_SHIFT) + 1;
        if ((end << PAGE_CACHE_SHIFT) < extent->end)
                end = ~0;
        if (lsm->lsm_stripe_count > 1) {
                struct {
                        char name[16];
                        struct ldlm_lock *lock;
                        struct lov_stripe_md *lsm;
                } key = { .name = "lock_to_stripe", .lock = lock, .lsm = lsm };
                __u32 stripe;
                __u32 vallen = sizeof(stripe);
                int rc;

                /* get our offset in the lov */
                rc = obd_get_info(ll_i2obdconn(inode), sizeof(key),
                                  &key, &vallen, &stripe);
                if (rc != 0) {
                        CERROR("obd_get_info: rc = %d\n", rc);
                        LBUG();
                }
                LASSERT(stripe < lsm->lsm_stripe_count);

                count = lsm->lsm_stripe_size >> PAGE_CACHE_SHIFT;
                skip = (lsm->lsm_stripe_count - 1) * count;
                start += (start/count * skip) + (stripe * count);
                if (end != ~0)
                        end += (end/count * skip) + (stripe * count);
        }

        i = (inode->i_size + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
        if (end >= i)
                clear_bit(LLI_F_HAVE_SIZE_LOCK, &(ll_i2info(inode)->lli_flags));
        if (i < end)
                end = i;

        CDEBUG(D_INODE, "start: %lu j: %lu count: %lu skip: %lu end: %lu\n",
               start, start % count, count, skip, end);

        /* start writeback on dirty pages in the extent when its PW */
        for (i = start, j = start % count;
             lock->l_granted_mode == LCK_PW && i < end; j++, i++) {
                if (j == count) {
                        i += skip;
                        j = 0;
                }
                /* its unlikely, but give us a chance to bail when we're out */
                ll_pgcache_lock(inode->i_mapping);
                if (list_empty(&inode->i_mapping->dirty_pages)) {
                        CDEBUG(D_INODE, "dirty list empty\n");
                        ll_pgcache_unlock(inode->i_mapping);
                        break;
                }
                ll_pgcache_unlock(inode->i_mapping);

                if (need_resched())
                        schedule();

                page = find_get_page(inode->i_mapping, i);
                if (page == NULL)
                        continue;
                if (!PageDirty(page) || TryLockPage(page)) {
                        page_cache_release(page);
                        continue;
                }
                if (PageDirty(page)) {
                        CDEBUG(D_INODE, "writing page %p\n", page);
                        ll_pgcache_lock(inode->i_mapping);
                        list_del(&page->list);
                        list_add(&page->list, &inode->i_mapping->locked_pages);
                        ll_pgcache_unlock(inode->i_mapping);

                        /* this writepage might write out pages outside
                         * this extent, but that's ok, the pages are only
                         * still dirty because a lock still covers them */
                        ClearPageDirty(page);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        ret = inode->i_mapping->a_ops->writepage(page);
#else
                        ret = inode->i_mapping->a_ops->writepage(page, NULL);
#endif
                        if (ret != 0)
                                unlock_page(page);
                } else {
                        unlock_page(page);
                }
                page_cache_release(page);

        }

        /* our locks are page granular thanks to osc_enqueue, we invalidate the
         * whole page. */
        LASSERT((extent->start & ~PAGE_CACHE_MASK) == 0);
        LASSERT(((extent->end+1) & ~PAGE_CACHE_MASK) == 0);
        for (i = start, j = start % count ; i < end ; j++, i++) {
                if (j == count) {
                        i += skip;
                        j = 0;
                }
                ll_pgcache_lock(inode->i_mapping);
                if (list_empty(&inode->i_mapping->dirty_pages) &&
                     list_empty(&inode->i_mapping->clean_pages) &&
                     list_empty(&inode->i_mapping->locked_pages)) {
                        CDEBUG(D_INODE, "nothing left\n");
                        ll_pgcache_unlock(inode->i_mapping);
                        break;
                }
                ll_pgcache_unlock(inode->i_mapping);
                if (need_resched())
                        schedule();
                page = find_get_page(inode->i_mapping, i);
                if (page == NULL)
                        continue;
                CDEBUG(D_INODE, "dropping page %p at %lu\n", page, page->index);
                lock_page(page);
                if (page->mapping) /* might have raced */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        truncate_complete_page(page);
#else
                        truncate_complete_page(page->mapping, page);
#endif
                unlock_page(page);
                page_cache_release(page);
        }
        EXIT;
}

static int ll_extent_lock_callback(struct ldlm_lock *lock,
                                   struct ldlm_lock_desc *new, void *data,
                                   int flag)
{
        struct inode *inode = data;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle lockh = { 0 };
        int rc;
        ENTRY;

        if ((unsigned long)inode < 0x1000) {
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
        case LDLM_CB_CANCELING:
                /* FIXME: we could be given 'canceling intents' so that we
                 * could know to write-back or simply throw away the pages
                 * based on if the cancel comes from a desire to, say,
                 * read or truncate.. */
                if ((unsigned long)lli->lli_smd < 0x1000) {
                        /* note that lli is part of the inode itself, so it
                         * is valid if as checked the inode pointer above. */
                        CERROR("inode %lu, sb %p, lli %p, lli_smd %p\n",
                               inode->i_ino, inode->i_sb, lli, lli->lli_smd);
                        LDLM_ERROR(lock, "cancel lock on bad inode %p", inode);
                        LBUG();
                }

                ll_pgcache_remove_extent(inode, lli->lli_smd, lock);
                break;
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
                   struct lustre_handle *lockh)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc, flags = 0;
        ENTRY;

        LASSERT(lockh->cookie == 0);

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        CDEBUG(D_DLMTRACE, "Locking inode %lu, start "LPU64" end "LPU64"\n",
               inode->i_ino, extent->start, extent->end);

        rc = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT, extent,
                         sizeof(extent), mode, &flags, ll_extent_lock_callback,
                         inode, lockh);

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
        struct ldlm_extent size_lock;
        struct lustre_handle match_lockh = {0};
        int flags, rc, matched;
        ENTRY;

        rc = ll_extent_lock_no_validate(fd, inode, lsm, mode, extent, lockh);
        if (rc != ELDLM_OK)
                RETURN(rc);

        if (test_bit(LLI_F_HAVE_SIZE_LOCK, &lli->lli_flags))
                RETURN(0);

        rc = ll_inode_getattr(inode, lsm, fd ? &fd->fd_ost_och : NULL);
        if (rc) {
                ll_extent_unlock(fd, inode, lsm, mode, lockh);
                RETURN(rc);
        }

        size_lock.start = inode->i_size;
        size_lock.end = OBD_OBJECT_EOF;

        /* XXX I bet we should be checking the lock ignore flags.. */
        flags = LDLM_FL_CBPENDING | LDLM_FL_BLOCK_GRANTED | LDLM_FL_MATCH_DATA;
        matched = obd_match(&ll_i2sbi(inode)->ll_osc_conn, lsm, LDLM_EXTENT,
                            &size_lock, sizeof(size_lock), LCK_PR, &flags,
                            inode, &match_lockh);

        /* hey, alright, we hold a size lock that covers the size we
         * just found, its not going to change for a while.. */
        if (matched == 1) {
                set_bit(LLI_F_HAVE_SIZE_LOCK, &lli->lli_flags);
                obd_cancel(&ll_i2sbi(inode)->ll_osc_conn, lsm, LCK_PR,
                           &match_lockh);
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

        rc = obd_cancel(&sbi->ll_osc_conn, lsm, mode, lockh);

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
        struct ll_read_extent rextent;
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
        rextent.re_extent.start = *ppos;
        rextent.re_extent.end = OBD_OBJECT_EOF;

        err = ll_extent_lock(fd, inode, lsm, LCK_PR, &rextent.re_extent,&lockh);
        if (err != ELDLM_OK)
                RETURN(-ENOLCK);

        /* XXX tell ll_readpage what pages have a PR lock.. */
        rextent.re_task = current;
        spin_lock(&lli->lli_read_extent_lock);
        list_add(&rextent.re_lli_item, &lli->lli_read_extents);
        spin_unlock(&lli->lli_read_extent_lock);

        CDEBUG(D_INFO, "Reading inode %lu, "LPSZ" bytes, offset %Ld\n",
               inode->i_ino, count, *ppos);
        retval = generic_file_read(filp, buf, count, ppos);

        spin_lock(&lli->lli_read_extent_lock);
        list_del(&rextent.re_lli_item);
        spin_unlock(&lli->lli_read_extent_lock);

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
        /*
         * sleep doing some writeback work of this mount's dirty data
         * if the VM thinks we're low on memory.. other dirtying code
         * paths should think about doing this, too, but they should be
         * careful not to hold locked pages while they do so.  like
         * ll_prepare_write.  *cough*
         */
        ll_check_dirty(inode->i_sb);

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
                                                 &extent, &lockh);
        if (err != ELDLM_OK)
                RETURN(-ENOLCK);

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
        struct lustre_handle *conn = ll_i2obdconn(inode);
        struct lov_stripe_md *lsm;
        int rc;
        ENTRY;

        down(&lli->lli_open_sem);
        lsm = lli->lli_smd;
        if (lsm) {
                up(&lli->lli_open_sem);
                CDEBUG(D_IOCTL, "stripe already exists for ino %lu\n",
                       inode->i_ino);
                /* If we haven't already done the open, do so now */
                if (file->f_flags & O_LOV_DELAY_CREATE) {
                        int rc2 = ll_osc_open(conn, inode, file, lsm);
                        if (rc2)
                                RETURN(rc2);
                }

                RETURN(-EEXIST);
        }

        rc = obd_iocontrol(LL_IOC_LOV_SETSTRIPE, conn, 0, &lsm, (void *)arg);
        if (rc) {
                up(&lli->lli_open_sem);
                RETURN(rc);
        }
        rc = ll_create_obj(conn, inode, file, lsm);
        up(&lli->lli_open_sem);

        if (rc) {
                obd_free_memmd(conn, &lsm);
                RETURN(rc);
        }
        rc = ll_osc_open(conn, inode, file, lli->lli_smd);
        RETURN(rc);
}

static int ll_lov_getstripe(struct inode *inode, unsigned long arg)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct lustre_handle *conn = ll_i2obdconn(inode);

        if (!lsm)
                RETURN(-ENODATA);

        return obd_iocontrol(LL_IOC_LOV_GETSTRIPE, conn, 0, lsm, (void *)arg);
}

int ll_file_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                  unsigned long arg)
{
        struct ll_file_data *fd = file->private_data;
        struct lustre_handle *conn;
        int flags;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),cmd=%u\n", inode->i_ino,
               inode->i_generation, inode, cmd);

        if (_IOC_TYPE(cmd) == 'T') /* tty ioctls */
                return -ENOTTY;

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
                        return -EFAULT;

                if (cmd == LL_IOC_SETFLAGS)
                        fd->fd_flags |= flags;
                else
                        fd->fd_flags &= ~flags;
                return 0;
        case LL_IOC_LOV_SETSTRIPE:
                return ll_lov_setstripe(inode, file, arg);
        case LL_IOC_LOV_GETSTRIPE:
                return ll_lov_getstripe(inode, arg);

        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT2_IOC_GETFLAGS:
        case EXT2_IOC_SETFLAGS:
        case EXT2_IOC_GETVERSION_OLD:
        case EXT2_IOC_GETVERSION_NEW:
        case EXT2_IOC_SETVERSION_OLD:
        case EXT2_IOC_SETVERSION_NEW:
        */
        default:
                conn = ll_i2obdconn(inode);
                return obd_iocontrol(cmd, conn, 0, NULL, (void *)arg);
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
                        RETURN(-ENOLCK);

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
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_FSYNC);
        /*
         * filemap_fdata{sync,wait} are also called at PW lock cancelation so
         * we know that they can only find data to writeback here if we are
         * still holding the PW lock that covered the dirty pages.  XXX we
         * should probably get a reference on it, though, just to be clear.
         */
        rc = filemap_fdatasync(inode->i_mapping);
        if (rc == 0)
                rc = filemap_fdatawait(inode->i_mapping);

        RETURN(rc);
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

        /* this is very tricky.  it is unsafe to call ll_have_md_lock
           when we have a referenced lock: because it may cause an RPC
           below when the lock is marked CB_PENDING.  That RPC may not
           go out because someone else may be in another RPC waiting for
           that lock*/
        if (!(it && it->it_lock_mode) && !ll_have_md_lock(dentry)) {
                struct lustre_md md;
                struct ptlrpc_request *req = NULL;
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                struct ll_fid fid;
                unsigned long valid = 0;
                int rc;
                int ealen = 0;

                if (S_ISREG(inode->i_mode)) {
                        ealen = obd_size_diskmd(&sbi->ll_osc_conn, NULL);
                        valid |= OBD_MD_FLEASIZE;
                }
                ll_inode2fid(&fid, inode);
                rc = mdc_getattr(&sbi->ll_mdc_conn, &fid, valid, ealen, &req);
                if (rc) {
                        CERROR("failure %d inode %lu\n", rc, inode->i_ino);
                        RETURN(-abs(rc));
                }
                rc = mdc_req2lustre_md(req, 0, &sbi->ll_osc_conn, &md);

                /* XXX Too paranoid? */
                if ((md.body->valid ^ valid) & OBD_MD_FLEASIZE)
                        CERROR("Asked for %s eadata but got %s\n",
                               (valid & OBD_MD_FLEASIZE) ? "some" : "no",
                               (md.body->valid & OBD_MD_FLEASIZE) ? "some":
                               "none");
                if (rc) {
                        ptlrpc_req_finished(req);
                        RETURN(rc);
                }

                ll_update_inode(inode, md.body, md.lsm);
                if (md.lsm != NULL && ll_i2info(inode)->lli_smd != md.lsm)
                        obd_free_memmd(&sbi->ll_osc_conn, &md.lsm);

                ptlrpc_req_finished(req);
        }

        lsm = ll_i2info(inode)->lli_smd;
        if (!lsm)       /* object not yet allocated, don't validate size */
                RETURN(0);

        /*
         * unfortunately stat comes in through revalidate and we don't
         * differentiate this use from initial instantiation.  we're
         * also being wildly conservative and flushing write caches
         * so that stat really returns the proper size.
         */
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
                      struct lookup_intent *it, 
                      struct kstat *stat)
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
};

struct inode_operations ll_file_inode_operations = {
        setattr_raw:    ll_setattr_raw,
        setattr:    ll_setattr,
        truncate:   ll_truncate,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        getattr_it: ll_getattr,
#else
        revalidate_it: ll_inode_revalidate_it,
#endif
};

struct inode_operations ll_special_inode_operations = {
        setattr_raw:    ll_setattr_raw,
        setattr:    ll_setattr,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        getattr_it:    ll_getattr,
#else
        revalidate_it: ll_inode_revalidate_it,
#endif
};
