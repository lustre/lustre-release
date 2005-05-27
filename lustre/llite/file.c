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
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/lustre_acl.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/lustre_compat25.h>
#endif
#include "llite_internal.h"
#include <linux/obd_lov.h>

int ll_md_och_close(struct obd_export *md_exp, struct inode *inode,
                    struct obd_client_handle *och)
{
        struct ptlrpc_request *req = NULL;
        struct obdo *obdo = NULL;
        struct obd_device *obd;
        int rc;
        ENTRY;

        obd = class_exp2obd(md_exp);
        if (obd == NULL) {
                CERROR("Invalid MDC connection handle "LPX64"\n",
                       md_exp->exp_handle.h_cookie);
                EXIT;
                return 0;
        }

        /*
         * here we check if this is forced umount. If so this is called on
         * canceling "open lock" and we do not call md_close() in this case , as
         * it will not successful, as import is already deactivated.
         */
        if (obd->obd_no_recov)
                GOTO(out, rc = 0);

        /* closing opened file */
        obdo = obdo_alloc();
        if (obdo == NULL)
                RETURN(-ENOMEM);

        obdo->o_id = inode->i_ino;
        obdo->o_valid = OBD_MD_FLID;
        obdo_from_inode(obdo, inode, (OBD_MD_FLTYPE | OBD_MD_FLMODE |
                                      OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                      OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                      OBD_MD_FLCTIME));
        if (0 /* ll_is_inode_dirty(inode) */) {
                obdo->o_flags = MDS_BFLAG_UNCOMMITTED_WRITES;
                obdo->o_valid |= OBD_MD_FLFLAGS;
        }
        obdo->o_fid = id_fid(&ll_i2info(inode)->lli_id);
        obdo->o_mds = id_group(&ll_i2info(inode)->lli_id);
        rc = md_close(md_exp, obdo, och, &req);
        obdo_free(obdo);

        if (rc == EAGAIN) {
                /*
                 * we are the last writer, so the MDS has instructed us to get
                 * the file size and any write cookies, then close again.
                 */

                //ll_queue_done_writing(inode);
                rc = 0;
        } else if (rc) {
                CERROR("inode %lu mdc close failed: rc = %d\n",
                       (unsigned long)inode->i_ino, rc);
        }

        ptlrpc_req_finished(req);
        EXIT;
out:
        mdc_clear_open_replay_data(md_exp, och);
        och->och_fh.cookie = DEAD_HANDLE_MAGIC;
        OBD_FREE(och, sizeof *och);
        return rc;
}

int ll_md_real_close(struct obd_export *md_exp,
                     struct inode *inode, int flags)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_client_handle **och_p;
        struct obd_client_handle *och;
        __u64 *och_usecount;
        int rc = 0;
        ENTRY;

        if (flags & FMODE_WRITE) {
                och_p = &lli->lli_mds_write_och;
                och_usecount = &lli->lli_open_fd_write_count;
        } else if (flags & FMODE_EXEC) {
                och_p = &lli->lli_mds_exec_och;
                och_usecount = &lli->lli_open_fd_exec_count;
         } else {
                och_p = &lli->lli_mds_read_och;
                och_usecount = &lli->lli_open_fd_read_count;
        }

        down(&lli->lli_och_sem);
        if (*och_usecount) { /* There are still users of this handle, so
                                skip freeing it. */
                up(&lli->lli_och_sem);
                RETURN(0);
        }
        och = *och_p;

        *och_p = NULL;
        up(&lli->lli_och_sem);

        /*
         * there might be a race and somebody have freed this och
         * already. Another way to have this twice called is if file closing
         * will fail due to netwok problems and on umount lock will be canceled
         * and this will be called from block_ast callack.
        */
        if (och && och->och_fh.cookie != DEAD_HANDLE_MAGIC)
                rc = ll_md_och_close(md_exp, inode, och);
        
        RETURN(rc);
}

int ll_md_close(struct obd_export *md_exp, struct inode *inode,
                struct file *file)
{
        struct ll_file_data *fd = file->private_data;
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        ENTRY;

        /* clear group lock, if present */
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);
                rc = ll_extent_unlock(fd, inode, lsm, LCK_GROUP,
                                      &fd->fd_cwlockh);
        }

        /* Let's see if we have good enough OPEN lock on the file and if
           we can skip talking to MDS */
        if (file->f_dentry->d_inode) {
                int lockmode;
                struct obd_device *obddev;
                struct lustre_handle lockh;
                int flags = LDLM_FL_BLOCK_GRANTED;
                struct ldlm_res_id file_res_id = {.name = {id_fid(&lli->lli_id), 
						           id_group(&lli->lli_id)}};
                ldlm_policy_data_t policy = {.l_inodebits={MDS_INODELOCK_OPEN}};

                down(&lli->lli_och_sem);
                if (fd->fd_omode & FMODE_WRITE) {
                        lockmode = LCK_CW;
                        LASSERT(lli->lli_open_fd_write_count);
                        lli->lli_open_fd_write_count--;
                } else if (fd->fd_omode & FMODE_EXEC) {
                        lockmode = LCK_PR;
                        LASSERT(lli->lli_open_fd_exec_count);
                        lli->lli_open_fd_exec_count--;
                } else {
                        lockmode = LCK_CR;
                        LASSERT(lli->lli_open_fd_read_count);
                        lli->lli_open_fd_read_count--;
                }
                up(&lli->lli_och_sem);
                
                obddev = md_get_real_obd(md_exp, &lli->lli_id);
                if (!ldlm_lock_match(obddev->obd_namespace, flags, &file_res_id,
                                     LDLM_IBITS, &policy, lockmode, &lockh))
                {
                        rc = ll_md_real_close(md_exp, file->f_dentry->d_inode,
                                              fd->fd_omode);
                } else {
                        ldlm_lock_decref(&lockh, lockmode);
                }
        }

        file->private_data = NULL;
        OBD_SLAB_FREE(fd, ll_file_data_slab, sizeof(*fd));
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
        CDEBUG(D_VFSTRACE, "VFS Op:inode="DLID4"(%p)\n",
               OLID4(&ll_i2info(inode)->lli_id), inode);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry)
                RETURN(0);

        lprocfs_counter_incr(sbi->ll_stats, LPROC_LL_RELEASE);
        fd = (struct ll_file_data *)file->private_data;
        LASSERT(fd != NULL);

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
        struct mdc_op_data *op_data;
        int rc;

        if (!parent)
                RETURN(-ENOENT);

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        ll_prepare_mdc_data(op_data, parent->d_inode, NULL,
                            name, len, O_RDWR);

        rc = md_enqueue(sbi->ll_md_exp, LDLM_IBITS, itp, LCK_PR, op_data,
                        &lockh, lmm, lmmsize, ldlm_completion_ast,
                        ll_mdc_blocking_ast, NULL);
        OBD_FREE(op_data, sizeof(*op_data));
        if (rc == 0) {
                if (LUSTRE_IT(itp)->it_lock_mode)
                        memcpy(&LUSTRE_IT(itp)->it_lock_handle,
                               &lockh, sizeof(lockh));

        } else if (rc < 0) {
                CERROR("lock enqueue: err: %d\n", rc);
        }
        RETURN(rc);
}

void ll_och_fill(struct inode *inode, struct lookup_intent *it,
                 struct obd_client_handle *och)
{
        struct ptlrpc_request *req = LUSTRE_IT(it)->it_data;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct mds_body *body;
        LASSERT(och);

        body = lustre_msg_buf (req->rq_repmsg, 1, sizeof (*body));
        LASSERT (body != NULL);          /* reply already checked out */
        LASSERT_REPSWABBED (req, 1);     /* and swabbed down */

        memcpy(&och->och_fh, &body->handle, sizeof(body->handle));
        och->och_magic = OBD_CLIENT_HANDLE_MAGIC;
        lli->lli_io_epoch = body->io_epoch;
        mdc_set_open_replay_data(ll_i2mdexp(inode), och, 
				 LUSTRE_IT(it)->it_data);
}

int ll_local_open(struct file *file, struct lookup_intent *it,
                  struct obd_client_handle *och)
{
        struct ll_file_data *fd;
        ENTRY;

        if (och)
                ll_och_fill(file->f_dentry->d_inode, it, och);

        LASSERTF(file->private_data == NULL, "file %.*s/%.*s ino %lu/%u (%o)\n",
                 file->f_dentry->d_name.len, file->f_dentry->d_name.name,
                 file->f_dentry->d_parent->d_name.len,
                 file->f_dentry->d_parent->d_name.name,
                 file->f_dentry->d_inode->i_ino,
                 file->f_dentry->d_inode->i_generation,
                 file->f_dentry->d_inode->i_mode);

        OBD_SLAB_ALLOC(fd, ll_file_data_slab, SLAB_KERNEL, sizeof *fd);
        
        /* We can't handle this well without reorganizing ll_file_open and
         * ll_md_close(), so don't even try right now. */
        LASSERT(fd != NULL);

        file->private_data = fd;
        ll_readahead_init(file->f_dentry->d_inode, &fd->fd_ras);
        fd->fd_omode = it->it_flags;
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
        struct lookup_intent *it, oit = { .it_op = IT_OPEN,
                                          .it_flags = file->f_flags };
        struct lov_stripe_md *lsm;
        struct ptlrpc_request *req;
        int rc = 0;
        struct obd_client_handle **och_p;
        __u64 *och_usecount;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), flags %o\n",
               inode->i_ino, inode->i_generation, inode, file->f_flags);

        /* don't do anything for / */
        if (inode->i_sb->s_root == file->f_dentry)
                RETURN(0);

        if ((file->f_flags+1) & O_ACCMODE)
                oit.it_flags++;
        if (file->f_flags & O_TRUNC)
                oit.it_flags |= 2;

        it = file->f_it;

        /*
         * sometimes LUSTRE_IT(it) may not be allocated like opening file by
         * dentry_open() from GNS stuff.
         */
        if (!it || !LUSTRE_IT(it)) {
                it = &oit;
                rc = ll_intent_alloc(it);
                if (rc)
                        GOTO(out, rc);
        }

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_OPEN);
        
        /*
         * mdc_intent_lock() didn't get a request ref if there was an open
         * error, so don't do cleanup on the * request here (bug 3430)
         */
        if (LUSTRE_IT(it)->it_disposition) {
    		rc = it_open_error(DISP_OPEN_OPEN, it);
    		if (rc)
            		RETURN(rc);
	}

        /* Let's see if we have file open on MDS already. */
        if (it->it_flags & FMODE_WRITE) {
                och_p = &lli->lli_mds_write_och;
                och_usecount = &lli->lli_open_fd_write_count;
        } else if (it->it_flags & FMODE_EXEC) {
                och_p = &lli->lli_mds_exec_och;
                och_usecount = &lli->lli_open_fd_exec_count;
        } else {
                och_p = &lli->lli_mds_read_och;
                och_usecount = &lli->lli_open_fd_read_count;
        }

        down(&lli->lli_och_sem);
        if (*och_p) { /* Open handle is present */
                if (LUSTRE_IT(it)->it_disposition) {
                        struct obd_client_handle *och;
                        /* Well, there's extra open request that we do not need,
                           let's close it somehow*/
                        OBD_ALLOC(och, sizeof (struct obd_client_handle));
                        if (!och) {
                                up(&lli->lli_och_sem);
                                RETURN(-ENOMEM);
                        }

                        ll_och_fill(inode, it, och);
                        /* ll_md_och_close() will free och */
                        ll_md_och_close(ll_i2mdexp(inode), inode, och);
                }
                (*och_usecount)++;
                        
                rc = ll_local_open(file, it, NULL);
                if (rc)
                        LBUG();
        } else {
                LASSERT(*och_usecount == 0);
                OBD_ALLOC(*och_p, sizeof (struct obd_client_handle));
                if (!*och_p)
                        GOTO(out, rc = -ENOMEM);
                (*och_usecount)++;

                if (!it || !LUSTRE_IT(it) || !LUSTRE_IT(it)->it_disposition) {
                        /*
                         * we are going to replace intent here, and that may
                         * possibly change access mode (FMODE_EXEC can only be
                         * set in intent), but I hope it never happens (I was
                         * not able to trigger it yet at least) -- green
                         */
                        
                        /* FIXME: FMODE_EXEC is not covered by O_ACCMODE! */
                        LASSERT(!(it->it_flags & FMODE_EXEC));
                        LASSERTF((it->it_flags & O_ACCMODE) ==
                                 (oit.it_flags & O_ACCMODE), "Changing intent "
                                 "flags %x to incompatible %x\n", it->it_flags,
                                 oit.it_flags);
                        it = &oit;
                        rc = ll_intent_file_open(file, NULL, 0, it);
                        if (rc)
                                GOTO(out, rc);
                        rc = it_open_error(DISP_OPEN_OPEN, it);
                        if (rc)
                                GOTO(out_och_free, rc);

                        mdc_set_lock_data(NULL, &LUSTRE_IT(it)->it_lock_handle,
                                          file->f_dentry->d_inode);
                }
                lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_OPEN);
                rc = ll_local_open(file, it, *och_p);
                LASSERTF(rc == 0, "rc = %d\n", rc);
        }
        up(&lli->lli_och_sem);
        
        /*
         * must do this outside lli_och_sem lock to prevent deadlock where
         * different kind of OPEN lock for this same inode gets cancelled by
         * ldlm_cancel_lru
         */

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
        req = LUSTRE_IT(it)->it_data;
        ll_intent_drop_lock(it);
        ll_intent_release(it);
        ptlrpc_req_finished(req);
        if (rc == 0) {
                ll_open_complete(inode);
        } else {
out_och_free:
                if (*och_p) {
                        OBD_FREE(*och_p, sizeof (struct obd_client_handle));
                        *och_p = NULL; /* OBD_FREE writes some magic there */
                        (*och_usecount)--;
                }
                up(&lli->lli_och_sem);
        }
                
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
        oa->o_gr = lsm->lsm_object_gr;
        oa->o_mode = S_IFREG;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ | OBD_MD_FLMTIME |
                OBD_MD_FLCTIME | OBD_MD_FLGROUP;

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
        EXIT;
check:
        if (lsm->lsm_oinfo[stripe].loi_id != lock->l_resource->lr_name.name[0]||
            lsm->lsm_oinfo[stripe].loi_gr != lock->l_resource->lr_name.name[2]){
                LDLM_ERROR(lock, "resource doesn't match object "LPU64"/"LPU64
                           " inode=%lu/%u (%p)\n",
                           lsm->lsm_oinfo[stripe].loi_id,
                           lsm->lsm_oinfo[stripe].loi_gr,
                           inode->i_ino, inode->i_generation, inode);
                return -ELDLM_NO_LOCK_DATA;
        }

        return stripe;
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
                if (ll_teardown_mmaps(inode->i_mapping, i << PAGE_CACHE_SHIFT,
                                      ((i+j) << PAGE_CACHE_SHIFT) - 1) )
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
                        // checking again to account for writeback's lock_page()
                        LL_CDEBUG_PAGE(D_PAGE, page, "truncating\n");
                        ll_ra_accounting(page, inode->i_mapping);
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
                __u32 stripe;
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
                down(&lli->lli_size_sem);
                kms = ldlm_extent_shift_kms(lock,
                                            lsm->lsm_oinfo[stripe].loi_kms);
		
                if (lsm->lsm_oinfo[stripe].loi_kms != kms)
                        LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                                   lsm->lsm_oinfo[stripe].loi_kms, kms);
                lsm->lsm_oinfo[stripe].loi_kms = kms;
                up(&lli->lli_size_sem);
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
        __u32 stripe;
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
                down(&inode->i_sem);
                kms = MAX(lsm->lsm_oinfo[stripe].loi_kms, lvb->lvb_size);
                kms = ldlm_extent_shift_kms(NULL, kms);
                if (lsm->lsm_oinfo[stripe].loi_kms != kms)
                        LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                                   lsm->lsm_oinfo[stripe].loi_kms, kms);
                lsm->lsm_oinfo[stripe].loi_kms = kms;
                up(&inode->i_sem);
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
        struct ost_lvb *lvb;
        struct lov_stripe_md *lsm;
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

        LDLM_DEBUG(lock, "i_size: %llu -> stripe number %u -> kms "LPU64,
                   inode->i_size, stripe, lvb->lvb_size);
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

__u64 lov_merge_size(struct lov_stripe_md *lsm, int kms);
__u64 lov_merge_blocks(struct lov_stripe_md *lsm);
__u64 lov_merge_mtime(struct lov_stripe_md *lsm, __u64 current_time);

/* NB: lov_merge_size will prefer locally cached writes if they extend the
 * file (because it prefers KMS over RSS when larger) */
int ll_glimpse_size(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };
        struct lustre_handle lockh = { 0 };
        int rc, flags = LDLM_FL_HAS_INTENT;
        ENTRY;

        CDEBUG(D_DLMTRACE, "Glimpsing inode %lu\n", inode->i_ino);

        rc = obd_enqueue(sbi->ll_dt_exp, lli->lli_smd, LDLM_EXTENT, &policy,
                         LCK_PR, &flags, ll_extent_lock_callback,
                         ldlm_completion_ast, ll_glimpse_callback, inode,
                         sizeof(struct ost_lvb), lustre_swab_ost_lvb, &lockh);
        if (rc == -ENOENT)
                RETURN(rc);

        if (rc != 0) {
                CERROR("obd_enqueue returned rc %d, returning -EIO\n", rc);
                RETURN(rc > 0 ? -EIO : rc);
        }

        down(&lli->lli_size_sem);
        inode->i_size = lov_merge_size(lli->lli_smd, 0);
        inode->i_blocks = lov_merge_blocks(lli->lli_smd);
        up(&lli->lli_size_sem);

        LTIME_S(inode->i_mtime) = lov_merge_mtime(lli->lli_smd,
                                                  LTIME_S(inode->i_mtime));

        CDEBUG(D_DLMTRACE, "glimpse: size: "LPU64", blocks: "LPU64"\n",
               (__u64)inode->i_size, (__u64)inode->i_blocks);
        
        obd_cancel(sbi->ll_dt_exp, lli->lli_smd, LCK_PR, &lockh);
        RETURN(rc);
}

void ll_stime_record(struct ll_sb_info *sbi, struct timeval *start,
                    struct obd_service_time *stime)
{
        struct timeval stop;
        do_gettimeofday(&stop);
                                                                                                                                                                                                     
        spin_lock(&sbi->ll_lock);
        lprocfs_stime_record(stime, &stop, start);
        spin_unlock(&sbi->ll_lock);
}

int ll_extent_lock(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm, int mode,
                   ldlm_policy_data_t *policy, struct lustre_handle *lockh,
                   int ast_flags, struct obd_service_time *stime)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct timeval start;
        int rc;
        ENTRY;

        LASSERT(lockh->cookie == 0);

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        CDEBUG(D_DLMTRACE, "Locking inode %lu, start "LPU64" end "LPU64"\n",
               inode->i_ino, policy->l_extent.start, policy->l_extent.end);

        do_gettimeofday(&start);
        rc = obd_enqueue(sbi->ll_dt_exp, lsm, LDLM_EXTENT, policy, mode,
                         &ast_flags, ll_extent_lock_callback,
                         ldlm_completion_ast, ll_glimpse_callback, inode,
                         sizeof(struct ost_lvb), lustre_swab_ost_lvb, lockh);
        if (rc > 0)
                rc = -EIO;
        
        ll_stime_record(sbi, &start, stime);

        if (policy->l_extent.start == 0 &&
            policy->l_extent.end == OBD_OBJECT_EOF) {
                /* vmtruncate()->ll_truncate() first sets the i_size and then
                 * the kms under both a DLM lock and the i_sem.  If we don't
                 * get the i_sem here we can match the DLM lock and reset
                 * i_size from the kms before the truncating path has updated
                 * the kms.  generic_file_write can then trust the stale i_size
                 * when doing appending writes and effectively cancel the
                 * result of the truncate.  Getting the i_sem after the enqueue
                 * maintains the DLM -> i_sem acquiry order. */
                down(&lli->lli_size_sem);
                inode->i_size = lov_merge_size(lsm, 1);
                up(&lli->lli_size_sem);
        }
        
        if (rc == 0) {
                LTIME_S(inode->i_mtime) =
                        lov_merge_mtime(lsm, LTIME_S(inode->i_mtime));
        }

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

        if (!lsm)
                RETURN(0);

        node = ll_node_from_inode(inode, *ppos, *ppos  + count - 1,
                                  LCK_PR);

        tree.lt_fd = file->private_data;

        rc = ll_tree_lock(&tree, node, inode, buf, count,
                          file->f_flags & O_NONBLOCK ? LDLM_FL_BLOCK_NOWAIT :0);
        if (rc != 0)
                RETURN(rc);

        down(&lli->lli_size_sem);
        kms = lov_merge_size(lsm, 1);
        if (*ppos + count - 1 > kms) {
                /* A glimpse is necessary to determine whether we return a short
                 * read or some zeroes at the end of the buffer */
                up(&lli->lli_size_sem);
                retval = ll_glimpse_size(inode);
                if (retval)
                        goto out;
        } else {
                inode->i_size = kms;
                up(&lli->lli_size_sem);
        }

        CDEBUG(D_INFO, "Read ino %lu, "LPSZ" bytes, offset %lld, i_size %llu\n",
               inode->i_ino, count, *ppos, inode->i_size);

        /* turn off the kernel's read-ahead */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        file->f_ramax = 0;
#else
        file->f_ra.ra_pages = 0;
#endif
        retval = generic_file_read(file, buf, count, ppos);

 out:
        ll_tree_unlock(&tree, inode);
        RETURN(retval);
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t ll_file_write(struct file *file, const char *buf,
                             size_t count, loff_t *ppos)
{
        struct inode *inode = file->f_dentry->d_inode;
        loff_t maxbytes = ll_file_maxbytes(inode);
        struct ll_lock_tree tree;
        struct ll_lock_tree_node *node;
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

        tree.lt_fd = file->private_data;

        rc = ll_tree_lock(&tree, node, inode, buf, count,
                          file->f_flags & O_NONBLOCK ? LDLM_FL_BLOCK_NOWAIT :0);
        if (rc != 0)
                RETURN(rc);

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
        EXIT;
out:
        ll_tree_unlock(&tree, inode);
        /* serialize with mmap/munmap/mremap */
        lprocfs_counter_add(ll_i2sbi(inode)->ll_stats, LPROC_LL_WRITE_BYTES,
                            retval > 0 ? retval : 0);
        return retval;
}

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
        oa->o_gr = ucreatp.lrc_group;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLFLAGS;
        oa->o_flags |= OBD_FL_RECREATE_OBJS;
        obdo_from_inode(oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                        OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        oti.oti_objid = NULL;
        memcpy(lsm2, lsm, lsm_size);
        rc = obd_create(exp, oa, NULL, 0, &lsm2, &oti);

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
        struct file *f;
        struct obd_export *exp = ll_i2dtexp(inode);
        struct lov_stripe_md *lsm;
        struct lookup_intent oit = {.it_op = IT_OPEN, .it_flags = flags};
        struct ptlrpc_request *req = NULL;
        int rc = 0;
        struct lustre_md md;
        struct obd_client_handle *och;
        ENTRY;

        
        if ((file->f_flags+1) & O_ACCMODE)
                oit.it_flags++;
        if (file->f_flags & O_TRUNC)
                oit.it_flags |= 2;

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
        f->f_flags = flags;

        rc = ll_intent_alloc(&oit);
        if (rc)
                GOTO(out, rc);

        rc = ll_intent_file_open(f, lum, lum_size, &oit);
        if (rc)
                GOTO(out, rc);
        if (it_disposition(&oit, DISP_LOOKUP_NEG))
                GOTO(out, -ENOENT);
        
        req = LUSTRE_IT(&oit)->it_data;
        rc = LUSTRE_IT(&oit)->it_status;

        if (rc < 0)
                GOTO(out, rc);

        rc = mdc_req2lustre_md(ll_i2mdexp(inode), req, 1, exp, &md);
        if (rc)
                GOTO(out, rc);
        ll_update_inode(f->f_dentry->d_inode, &md);

        OBD_ALLOC(och, sizeof(struct obd_client_handle));
        rc = ll_local_open(f, &oit, och);
        if (rc) { /* Actually ll_local_open cannot fail! */
                GOTO(out, rc);
        }
        if (LUSTRE_IT(&oit)->it_lock_mode) {
                ldlm_lock_decref_and_cancel((struct lustre_handle *)
                                            &LUSTRE_IT(&oit)->it_lock_handle,
                                            LUSTRE_IT(&oit)->it_lock_mode);
                LUSTRE_IT(&oit)->it_lock_mode = 0;
        }

        ll_intent_release(&oit);

        /* ll_file_release will decrease the count, but won't free anything
           because we have at least one more reference coming from actual open
         */
        down(&lli->lli_och_sem);
        lli->lli_open_fd_write_count++;
        up(&lli->lli_och_sem);
        rc = ll_file_release(f->f_dentry->d_inode, f);
        
        /* Now also destroy our supplemental och */
        ll_md_och_close(ll_i2mdexp(inode), f->f_dentry->d_inode, och);
        EXIT;
 out:
        ll_intent_release(&oit);
        if (f)
                put_filp(f);
        up(&lli->lli_open_sem);
        if (req != NULL)
                ptlrpc_req_finished(req);
        return rc;
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
        struct ll_file_data *fd = file->private_data;
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

        rc = ll_extent_lock(fd, inode, lsm, LCK_GROUP, &policy, &lockh, flags,
                            &ll_i2sbi(inode)->ll_grouplock_stime);
        if (rc != 0)
                RETURN(rc);

        fd->fd_flags |= LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK;
        fd->fd_gid = arg;
        memcpy(&fd->fd_cwlockh, &lockh, sizeof(lockh));

        RETURN(0);
}

static int ll_put_grouplock(struct inode *inode, struct file *file,
                         unsigned long arg)
{
        struct ll_file_data *fd = file->private_data;
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

int ll_file_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                  unsigned long arg)
{
        struct ll_file_data *fd = file->private_data;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
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
        case LL_IOC_LOV_SETEA:
                RETURN(ll_lov_setea(inode, file, arg));
        case IOC_MDC_SHOWFID: {
                struct lustre_id *idp = (struct lustre_id *)arg;
                struct lustre_id id;
                char *filename;
                int rc;

                filename = getname((const char *)arg);
                if (IS_ERR(filename))
                        RETURN(PTR_ERR(filename));

                ll_inode2id(&id, inode);

                rc = ll_get_fid(sbi->ll_md_exp, &id, filename, &id);
                if (rc < 0)
                        GOTO(out_filename, rc);

                rc = copy_to_user(idp, &id, sizeof(*idp));
                if (rc)
                        GOTO(out_filename, rc = -EFAULT);

                EXIT;
        out_filename:
                putname(filename);
                return rc;
        }
        case LL_IOC_LOV_GETSTRIPE:
                RETURN(ll_lov_getstripe(inode, arg));
        case LL_IOC_RECREATE_OBJ:
                RETURN(ll_lov_recreate_obj(inode, file, arg));
        case EXT3_IOC_GETFLAGS:
        case EXT3_IOC_SETFLAGS:
                RETURN( ll_iocontrol(inode, file, cmd, arg) );
        case LL_IOC_GROUP_LOCK:
                RETURN(ll_get_grouplock(inode, file, arg));
        case LL_IOC_GROUP_UNLOCK:
                RETURN(ll_put_grouplock(inode, file, arg));
        case EXT3_IOC_GETVERSION_OLD:
        case EXT3_IOC_GETVERSION:
                return put_user(inode->i_generation, (int *) arg);
        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT2_IOC_GETVERSION_OLD:
        case EXT2_IOC_GETVERSION_NEW:
        case EXT2_IOC_SETVERSION_OLD:
        case EXT2_IOC_SETVERSION_NEW:
        case EXT3_IOC_SETVERSION_OLD:
        case EXT3_IOC_SETVERSION:
        */
        default:
                RETURN( obd_iocontrol(cmd, ll_i2dtexp(inode), 0, NULL,
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
                ldlm_policy_data_t policy = { .l_extent = {0, OBD_OBJECT_EOF }};
                struct ll_inode_info *lli = ll_i2info(inode);
                int nonblock = 0, rc;

                if (file->f_flags & O_NONBLOCK)
                        nonblock = LDLM_FL_BLOCK_NOWAIT;

                rc = ll_extent_lock(fd, inode, lsm, LCK_PR, &policy, &lockh,
                                    nonblock, &ll_i2sbi(inode)->ll_seek_stime);
                if (rc != 0)
                        RETURN(rc);

                down(&lli->lli_size_sem);
                offset += inode->i_size;
                up(&lli->lli_size_sem);
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
        struct lustre_id id;
        struct ptlrpc_request *req;
        int rc, err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_FSYNC);

        /* fsync's caller has already called _fdata{sync,write}, we want
         * that IO to finish before calling the osc and mdc sync methods */
        rc = filemap_fdatawait(inode->i_mapping);

        ll_inode2id(&id, inode);
        err = md_sync(ll_i2sbi(inode)->ll_md_exp, &id, &req);
        if (!rc)
                rc = err;
        if (!err)
                ptlrpc_req_finished(req);

        if (data && lsm) {
                struct obdo *oa = obdo_alloc();

                if (!oa)
                        RETURN(rc ? rc : -ENOMEM);

                oa->o_id = lsm->lsm_object_id;
                oa->o_gr = lsm->lsm_object_gr;
                oa->o_valid = OBD_MD_FLID;
                obdo_from_inode(oa, inode, (OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                            OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                                            OBD_MD_FLGROUP));

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
        struct ll_inode_info *li = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct obd_device *obddev;
        struct ldlm_res_id res_id =
                { .name = {id_fid(&li->lli_id), id_group(&li->lli_id), LDLM_FLOCK} };
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

        CDEBUG(D_DLMTRACE, "inode=%lu, pid="LPU64", flags=%#x, mode=%u, "
               "start="LPU64", end="LPU64"\n", inode->i_ino, flock.l_flock.pid,
               flags, mode, flock.l_flock.start, flock.l_flock.end);

        obddev = md_get_real_obd(sbi->ll_md_exp, &li->lli_id);
        rc = ldlm_cli_enqueue(obddev->obd_self_export, NULL,
                              obddev->obd_namespace,
                              res_id, LDLM_FLOCK, &flock, mode, &flags,
                              NULL, ldlm_flock_completion_ast, NULL, file_lock,
                              NULL, 0, NULL, &lockh);
        RETURN(rc);
}

int ll_inode_revalidate_it(struct dentry *dentry)
{
        struct lookup_intent oit = { .it_op = IT_GETATTR };
        struct inode *inode = dentry->d_inode;
        struct ptlrpc_request *req = NULL;
        struct ll_inode_info *lli;
        struct lov_stripe_md *lsm;
        struct ll_sb_info *sbi;
        struct lustre_id id;
        int rc;
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }
        
        sbi = ll_i2sbi(inode);
        
        ll_inode2id(&id, inode);
        lli = ll_i2info(inode);
        LASSERT(id_fid(&id) != 0);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), name=%s(%p)\n",
               inode->i_ino, inode->i_generation, inode, dentry->d_name.name,
               dentry);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,5,0))
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_REVALIDATE);
#endif

        rc = ll_intent_alloc(&oit);
        if (rc)
                RETURN(-ENOMEM);

        rc = md_intent_lock(sbi->ll_md_exp, &id, NULL, 0, NULL, 0, &id,
                            &oit, 0, &req, ll_mdc_blocking_ast);
        if (rc < 0)
                GOTO(out, rc);

        rc = revalidate_it_finish(req, 1, &oit, dentry);
        if (rc) {
                GOTO(out, rc);
        }

        ll_lookup_finish_locks(&oit, dentry);

        lsm = lli->lli_smd;
        if (lsm == NULL) /* object not yet allocated, don't validate size */
                GOTO(out, rc = 0);

        /*
         * ll_glimpse_size() will prefer locally cached writes if they extend
         * the file.
         */
        rc = ll_glimpse_size(inode);
        EXIT;
out:
        ll_intent_release(&oit);
        if (req)
                ptlrpc_req_finished(req);
        return rc;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat)
{
        int res = 0;
        struct inode *inode = de->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);

        res = ll_inode_revalidate_it(de);
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_GETATTR);

        if (res)
                return res;

        stat->ino = inode->i_ino;
        stat->mode = inode->i_mode;
        stat->nlink = inode->i_nlink;
        stat->uid = inode->i_uid;
        stat->gid = inode->i_gid;
        stat->atime = inode->i_atime;
        stat->mtime = inode->i_mtime;
        stat->ctime = inode->i_ctime;
        stat->blksize = inode->i_blksize;

        down(&lli->lli_size_sem);
        stat->size = inode->i_size;
        stat->blocks = inode->i_blocks;
        up(&lli->lli_size_sem);
        
        stat->rdev = kdev_t_to_nr(inode->i_rdev);
        stat->dev = id_group(&ll_i2info(inode)->lli_id);
        return 0;
}
#endif

static
int ll_setxattr_internal(struct inode *inode, const char *name,
                         const void *value, size_t size, int flags, 
                         __u64 valid)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data op_data;
        struct iattr attr;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", inode->i_ino);
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_SETXATTR);

        memset(&attr, 0x0, sizeof(attr));
        attr.ia_valid |= valid;
        attr.ia_attr_flags = flags;

        ll_prepare_mdc_data(&op_data, inode, NULL, NULL, 0, 0);

        rc = md_setattr(sbi->ll_md_exp, &op_data, &attr,
                        (void*) name, strnlen(name, XATTR_NAME_MAX)+1, 
                        (void*) value, size, &request);
        if (rc) {
                CERROR("md_setattr fails: rc = %d\n", rc);
                GOTO(out, rc);
        }

 out:
        ptlrpc_req_finished(request);
        RETURN(rc);
}

int ll_setxattr(struct dentry *dentry, const char *name, const void *value,
                size_t size, int flags)
{
        int rc, error;
        struct posix_acl *acl;
        struct ll_inode_info *lli;
        ENTRY;

        rc = ll_setxattr_internal(dentry->d_inode, name, value, size, 
                                  flags, ATTR_EA);
        
        /* update inode's acl info */
        if (rc == 0 && strcmp(name, XATTR_NAME_ACL_ACCESS) == 0) {
                if (value) {
                        acl = posix_acl_from_xattr(value, size);
                        if (IS_ERR(acl)) {
                                CERROR("convert from xattr to acl error: %ld",
                                        PTR_ERR(acl));
                                GOTO(out, rc);
                        } else if (acl) {
                                error = posix_acl_valid(acl);
                                if (error) {
                                        CERROR("acl valid error: %d", error);
                                        posix_acl_release(acl);
                                        GOTO(out, rc);
                                }
                        }
                } else {
                        acl = NULL;
                }
                                        
                lli = ll_i2info(dentry->d_inode);
                spin_lock(&lli->lli_lock);
                if (lli->lli_acl_access != NULL)
                        posix_acl_release(lli->lli_acl_access);
                lli->lli_acl_access = acl;
                spin_unlock(&lli->lli_lock);
        }
        EXIT;
out:
        return(rc);
}

int ll_removexattr(struct dentry *dentry, const char *name)
{
        return ll_setxattr_internal(dentry->d_inode, name, NULL, 0, 0,
                                    ATTR_EA_RM);
}

static
int ll_getxattr_internal(struct inode *inode, const char *name, int namelen,
                         void *value, size_t size, __u64 valid)
{
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_id id;
        struct mds_body *body;
        void *ea_data; 
        int rc, ea_size;
        ENTRY;

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_GETXATTR);

        ll_inode2id(&id, inode);
        rc = md_getattr(sbi->ll_md_exp, &id, valid, name, namelen,
                         size, &request);
        if (rc) {
                if (rc != -ENODATA && rc != -EOPNOTSUPP)
                        CERROR("md_getattr fails: rc = %d\n", rc);
                GOTO(out, rc);
        }

        body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));
        LASSERT(body != NULL);
        LASSERT_REPSWABBED(request, 0);

        ea_size = body->eadatasize;
        LASSERT(ea_size <= request->rq_repmsg->buflens[0]);

        if (size == 0) 
                GOTO(out, rc = ea_size);

        ea_data = lustre_msg_buf(request->rq_repmsg, 1, ea_size);
        LASSERT(ea_data != NULL);
        LASSERT_REPSWABBED(request, 1);

        if (value)
                memcpy(value, ea_data, ea_size);
        rc = ea_size;
 out:
        ptlrpc_req_finished(request);
        RETURN(rc);
}

int ll_getxattr(struct dentry *dentry, const char *name, void *value,
                size_t size)
{
        return ll_getxattr_internal(dentry->d_inode, name, strlen(name) + 1, 
                                    value, size, OBD_MD_FLEA);
}

int ll_listxattr(struct dentry *dentry, char *list, size_t size)
{
        return ll_getxattr_internal(dentry->d_inode, NULL, 0, list, size,
                                    OBD_MD_FLEALIST);
}

/*
 * XXX We could choose not to check DLM lock. Leave the decision
 * to remote acl handling.
 */
static int
lustre_check_acl(struct inode *inode, int mask)
{
        struct lookup_intent it = { .it_op = IT_GETATTR };
        struct dentry de = { .d_inode = inode };
        struct ll_sb_info *sbi;
        struct lustre_id id;
        struct ptlrpc_request *req = NULL;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct posix_acl *acl;
        int rc;
        ENTRY;

        sbi = ll_i2sbi(inode);
        ll_inode2id(&id, inode);

        if (ll_intent_alloc(&it))
                return -EACCES;

        rc = md_intent_lock(sbi->ll_md_exp, &id, NULL, 0, NULL, 0, &id,
                            &it, 0, &req, ll_mdc_blocking_ast);
        if (rc < 0) {
                ll_intent_free(&it);
                GOTO(out, rc);
        }

        rc = revalidate_it_finish(req, 1, &it, &de);
        if (rc) {
                ll_intent_release(&it);
                GOTO(out, rc);
        }

        ll_lookup_finish_locks(&it, &de);
        ll_intent_free(&it);

        spin_lock(&lli->lli_lock);
        acl = posix_acl_dup(ll_i2info(inode)->lli_acl_access);
        spin_unlock(&lli->lli_lock);

        if (!acl)
                GOTO(out, rc = -EAGAIN);

        rc = posix_acl_permission(inode, acl, mask);
        posix_acl_release(acl);

out:
        if (req)
                ptlrpc_req_finished(req);

        RETURN(rc);
}

int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
        return generic_permission(inode, mask, lustre_check_acl);
}

struct file_operations ll_file_operations = {
        .read           = ll_file_read,
        .write          = ll_file_write,
        .ioctl          = ll_file_ioctl,
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        .sendfile       = generic_file_sendfile,
#endif
        .fsync          = ll_fsync,
        .lock           = ll_file_flock
};

struct inode_operations ll_file_inode_operations = {
        .setattr        = ll_setattr,
        .truncate       = ll_truncate,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        .getattr        = ll_getattr,
#else
        .revalidate_it  = ll_inode_revalidate_it,
#endif
        .setxattr       = ll_setxattr,
        .getxattr       = ll_getxattr,
        .listxattr      = ll_listxattr,
        .removexattr    = ll_removexattr,
        .permission     = ll_inode_permission,
};

