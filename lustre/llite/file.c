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
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/file.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <lustre_dlm.h>
#include <lustre_lite.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include "llite_internal.h"
#include <lustre/ll_fiemap.h>

/* also used by llite/special.c:ll_special_open() */
struct ll_file_data *ll_file_data_get(void)
{
	struct ll_file_data *fd;

	OBD_SLAB_ALLOC_PTR(fd, ll_file_data_slab);
	fd->fd_write_failed = false;
	return fd;
}

static void ll_file_data_put(struct ll_file_data *fd)
{
        if (fd != NULL)
                OBD_SLAB_FREE_PTR(fd, ll_file_data_slab);
}

static int ll_close_inode_openhandle(struct inode *inode,
                                     struct obd_client_handle *och)
{
        struct ptlrpc_request *req = NULL;
        struct obd_device *obd;
        struct obdo *oa;
        struct mdc_op_data data = { { 0 } };
        obd_flag valid;
        int rc;
        ENTRY;

        obd = class_exp2obd(ll_i2mdcexp(inode));
        if (obd == NULL) {
                CERROR("Invalid MDC connection handle "LPX64"\n",
                       ll_i2mdcexp(inode)->exp_handle.h_cookie);
                GOTO(out, rc = 0);
        }

        /*
         * here we check if this is forced umount. If so this is called on
         * canceling "open lock" and we do not call mdc_close() in this case, as
         * it will not be successful, as import is already deactivated.
         */
        if (obd->obd_force)
                GOTO(out, rc = 0);

        OBDO_ALLOC(oa);
        if (!oa)
                RETURN(-ENOMEM); // XXX We leak openhandle and request here.

        oa->o_id = inode->i_ino;
        oa->o_valid = OBD_MD_FLID;
        valid = OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLATIME |
                OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        if (S_ISREG(inode->i_mode))
                valid |=  OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        obdo_from_inode(oa, inode, valid);
        if (ll_is_inode_dirty(inode)) {
                oa->o_flags = MDS_BFLAG_UNCOMMITTED_WRITES;
                oa->o_valid |= OBD_MD_FLFLAGS;
        }
        ll_inode2fid(&data.fid1, inode);
        rc = mdc_close(ll_i2mdcexp(inode), &data, oa, och, &req);
        if (rc == EAGAIN) {
                /* We are the last writer, so the MDS has instructed us to get
                 * the file size and any write cookies, then close again. */
                ll_queue_done_writing(inode);
                rc = 0;
        } else if (rc) {
                CERROR("inode %lu mdc close failed: rc = %d\n",
                       inode->i_ino, rc);
        }

        OBDO_FREE(oa);

        if (rc == 0) {
                rc = ll_objects_destroy(req, inode);
                if (rc)
                        CERROR("inode %lu ll_objects destroy: rc = %d\n",
                               inode->i_ino, rc);
        }

        ptlrpc_req_finished(req); /* This is close request */
        EXIT;
out:
        mdc_clear_open_replay_data(och);

        return rc;
}

int ll_mdc_real_close(struct inode *inode, int flags)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        struct obd_client_handle **och_p;
        struct obd_client_handle *och;
        __u64 *och_usecount;

        ENTRY;

        if (flags & FMODE_WRITE) {
                och_p = &lli->lli_mds_write_och;
                och_usecount = &lli->lli_open_fd_write_count;
        } else if (flags & FMODE_EXEC) {
                och_p = &lli->lli_mds_exec_och;
                och_usecount = &lli->lli_open_fd_exec_count;
         } else {
                LASSERT(flags & FMODE_READ);
                och_p = &lli->lli_mds_read_och;
                och_usecount = &lli->lli_open_fd_read_count;
        }

        down(&lli->lli_och_sem);
        if (*och_usecount) { /* There are still users of this handle, so
                                skip freeing it. */
                up(&lli->lli_och_sem);
                RETURN(0);
        }
        och=*och_p;
        *och_p = NULL;
        up(&lli->lli_och_sem);

        if (och) { /* There might be a race and somebody have freed this och
                      already */
                rc = ll_close_inode_openhandle(inode, och);
                och->och_fh.cookie = DEAD_HANDLE_MAGIC;
                OBD_FREE(och, sizeof *och);
        }

        RETURN(rc);
}

int ll_mdc_close(struct obd_export *mdc_exp, struct inode *inode,
                        struct file *file)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        ENTRY;

        /* clear group lock, if present */
        if (unlikely(fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
                struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);
                rc = ll_extent_unlock(fd, inode, lsm, LCK_GROUP,
                                      &fd->fd_cwlockh);
        }

        /* Let's see if we have good enough OPEN lock on the file and if
           we can skip talking to MDS */
        if (file->f_dentry->d_inode) { /* Can this ever be false? */
                int lockmode;
                int flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_TEST_LOCK;
                struct lustre_handle lockh;
                struct inode *inode = file->f_dentry->d_inode;
                struct ldlm_res_id file_res_id;

                ldlm_policy_data_t policy = {.l_inodebits={MDS_INODELOCK_OPEN}};
                fid_build_reg_res_name(ll_inode_lu_fid(inode), &file_res_id);

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

                if (!ldlm_lock_match(mdc_exp->exp_obd->obd_namespace, flags,
                                     &file_res_id, LDLM_IBITS, &policy,lockmode,
                                     &lockh)) {
                        rc = ll_mdc_real_close(file->f_dentry->d_inode,
                                                fd->fd_omode);
                }
        } else {
                CERROR("Releasing a file %p with negative dentry %p. Name %s",
                       file, file->f_dentry, file->f_dentry->d_name.name);
        }

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

        if (inode->i_sb->s_root != file->f_dentry)
                ll_stats_ops_tally(sbi, LPROC_LL_RELEASE, 1);
        fd = LUSTRE_FPRIVATE(file);
        LASSERT(fd != NULL);

        /* The last ref on @file, maybe not the the owner pid of statahead.
         * Different processes can open the same dir, "ll_opendir_key" means:
         * it is me that should stop the statahead thread. */
        if (lli->lli_opendir_key == fd && lli->lli_opendir_pid != 0)
                ll_stop_statahead(inode, lli->lli_opendir_key);

        if (inode->i_sb->s_root == file->f_dentry) {
                LUSTRE_FPRIVATE(file) = NULL;
                ll_file_data_put(fd);
                RETURN(0);
        }

        if (lsm)
                lov_test_and_clear_async_rc(lsm);
        lli->lli_async_rc = 0;

        rc = ll_mdc_close(sbi->ll_mdc_exp, inode, file);

        if (OBD_FAIL_TIMEOUT_MS(OBD_FAIL_PTLRPC_DUMP_LOG, obd_fail_val))
                libcfs_debug_dumplog();

        RETURN(rc);
}

static int ll_intent_file_open(struct file *file, void *lmm,
                               int lmmsize, struct lookup_intent *itp)
{
        struct ll_sb_info *sbi = ll_i2sbi(file->f_dentry->d_inode);
        struct mdc_op_data data = { { 0 } };
        struct dentry *parent = file->f_dentry->d_parent;
        const char *name = file->f_dentry->d_name.name;
        const int len = file->f_dentry->d_name.len;
        struct inode *inode = file->f_dentry->d_inode;
        struct ptlrpc_request *req;
        int rc;
        ENTRY;

        if (!parent)
                RETURN(-ENOENT);

        ll_prepare_mdc_op_data(&data, parent->d_inode, inode,
                               name, len, O_RDWR, NULL);

        /* Usually we come here only for NFSD, and we want open lock.
           But we can also get here with pre 2.6.15 patchless kernels, and in
           that case that lock is also ok */
        /* We can also get here if there was cached open handle in revalidate_it
         * but it disappeared while we were getting from there to ll_file_open.
         * But this means this file was closed and immediatelly opened which
         * makes a good candidate for using OPEN lock */
        /* If lmmsize & lmm are not 0, we are just setting stripe info
         * parameters. No need for the open lock */
        if (!lmm && !lmmsize)
                itp->it_flags |= MDS_OPEN_LOCK;

        rc = mdc_intent_lock(sbi->ll_mdc_exp, &data, lmm, lmmsize, itp,
                              0 /*unused */, &req, ll_mdc_blocking_ast, 0);
        if (rc == -ESTALE) {
                /* reason for keep own exit path - don`t flood log
                * with messages with -ESTALE errors.
                */
                if (!it_disposition(itp, DISP_OPEN_OPEN) ||
                     it_open_error(DISP_OPEN_OPEN, itp))
                        GOTO(out, rc);
                ll_release_openhandle(file->f_dentry, itp);
                GOTO(out, rc);
        }

        if (it_disposition(itp, DISP_LOOKUP_NEG))
                GOTO(out, rc = -ENOENT);

        if (rc != 0 || it_open_error(DISP_OPEN_OPEN, itp)) {
                rc = rc ? rc : it_open_error(DISP_OPEN_OPEN, itp);
                CDEBUG(D_VFSTRACE, "lock enqueue: err: %d\n", rc);
                GOTO(out, rc);
        }

        rc = ll_prep_inode(sbi->ll_osc_exp, &file->f_dentry->d_inode,
                           req, DLM_REPLY_REC_OFF, NULL);
        if (itp->d.lustre.it_lock_mode)
                mdc_set_lock_data(&itp->d.lustre.it_lock_handle,
                                  inode, NULL);

out:
        ptlrpc_req_finished(itp->d.lustre.it_data);
        it_clear_disposition(itp, DISP_ENQ_COMPLETE);
        ll_intent_drop_lock(itp);

        RETURN(rc);
}


static void ll_och_fill(struct ll_inode_info *lli, struct lookup_intent *it,
                        struct obd_client_handle *och)
{
        struct ptlrpc_request *req = it->d.lustre.it_data;
        struct mds_body *body;

        LASSERT(och);

        body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));
        LASSERT(body != NULL);                  /* reply already checked out */
        /* and swabbed in mdc_enqueue */
        LASSERT(lustre_rep_swabbed(req, DLM_REPLY_REC_OFF));

        memcpy(&och->och_fh, &body->handle, sizeof(body->handle));
        och->och_magic = OBD_CLIENT_HANDLE_MAGIC;
        lli->lli_io_epoch = body->io_epoch;

        mdc_set_open_replay_data(och, it->d.lustre.it_data);
}

int ll_local_open(struct file *file, struct lookup_intent *it,
                  struct ll_file_data *fd, struct obd_client_handle *och)
{
        ENTRY;

        LASSERT(!LUSTRE_FPRIVATE(file));

        LASSERT(fd != NULL);

        if (och)
                ll_och_fill(ll_i2info(file->f_dentry->d_inode), it, och);
        LUSTRE_FPRIVATE(file) = fd;
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
        struct obd_client_handle **och_p = NULL;
        __u64 *och_usecount = NULL;
        struct ll_file_data *fd;
        int rc = 0, opendir_set = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), flags %o\n", inode->i_ino,
               inode->i_generation, inode, file->f_flags);

#ifdef HAVE_VFS_INTENT_PATCHES
        it = file->f_it;
#else
        it = file->private_data; /* XXX: compat macro */
        file->private_data = NULL; /* prevent ll_local_open assertion */
#endif

        fd = ll_file_data_get();
        if (fd == NULL)
                GOTO(out_och_free, rc = -ENOMEM);

        if (S_ISDIR(inode->i_mode)) {
                spin_lock(&lli->lli_lock);
                if (lli->lli_opendir_key == NULL && lli->lli_opendir_pid == 0) {
                        LASSERT(lli->lli_sai == NULL);
                        lli->lli_opendir_key = fd;
                        lli->lli_opendir_pid = cfs_curproc_pid();
                        opendir_set = 1;
                }
                spin_unlock(&lli->lli_lock);
        }

        if (inode->i_sb->s_root == file->f_dentry) {
                LUSTRE_FPRIVATE(file) = fd;
                RETURN(0);
        }

        if (!it || !it->d.lustre.it_disposition) {
                /* Convert f_flags into access mode. We cannot use file->f_mode,
                 * because everything but O_ACCMODE mask was stripped from it */
                if ((oit.it_flags + 1) & O_ACCMODE)
                        oit.it_flags++;
                if (file->f_flags & O_TRUNC)
                        oit.it_flags |= FMODE_WRITE;

                /* kernel only call f_op->open in dentry_open.  filp_open calls
                 * dentry_open after call to open_namei that checks permissions.
                 * Only nfsd_open call dentry_open directly without checking
                 * permissions and because of that this code below is safe. */
                if (oit.it_flags & (FMODE_WRITE | FMODE_READ))
                        oit.it_flags |= MDS_OPEN_OWNEROVERRIDE;

                /* We do not want O_EXCL here, presumably we opened the file
                 * already? XXX - NFS implications? */
                oit.it_flags &= ~O_EXCL;

                /* bug20584, if "it_flags" contains O_CREAT, the file will be
                 * created if necessary, then "IT_CREAT" should be set to keep
                 * consistent with it */
                if (oit.it_flags & O_CREAT)
                        oit.it_op |= IT_CREAT;

                it = &oit;
        }

        if (ll_i2sbi(inode)->ll_direct_io_default &&
            !S_ISDIR(inode->i_mode) &&
            !(it->it_flags & FMODE_EXEC))
                file->f_flags |= O_DIRECT;

restart:
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

        LASSERTF(it->it_flags != 0, "it %p dist %d \n", it,
                 it->d.lustre.it_disposition);

        down(&lli->lli_och_sem);
        if (*och_p) { /* Open handle is present */
                if (it_disposition(it, DISP_OPEN_OPEN)) {
                        /* Well, there's extra open request that we do not need,
                           let's close it somehow. This will decref request. */
                        rc = it_open_error(DISP_OPEN_OPEN, it);
                        if (rc) {
                                up(&lli->lli_och_sem);
                                GOTO(out_openerr, rc);
                        }
                        ll_release_openhandle(file->f_dentry, it);
                        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats,
                                             LPROC_LL_OPEN);
                }
                (*och_usecount)++;

                rc = ll_local_open(file, it, fd, NULL);

                LASSERTF(rc == 0, "rc = %d\n", rc);
        } else {
                LASSERT(*och_usecount == 0);
                if (!it->d.lustre.it_disposition) {
                        /* We cannot just request lock handle now, new ELC code
                           means that one of other OPEN locks for this file
                           could be cancelled, and since blocking ast handler
                           would attempt to grab och_sem as well, that would
                           result in a deadlock */
                        up(&lli->lli_och_sem);
                        it->it_create_mode |= M_CHECK_STALE;
                        rc = ll_intent_file_open(file, NULL, 0, it);
                        it->it_create_mode &= ~M_CHECK_STALE;
                        if (rc)
                                GOTO(out_openerr, rc);

                        goto restart;
                }

                OBD_ALLOC(*och_p, sizeof (struct obd_client_handle));
                if (!*och_p)
                        GOTO(out_och_free, rc = -ENOMEM);

                (*och_usecount)++;

                /* mdc_intent_lock() didn't get a request ref if there was an
                 * open error, so don't do cleanup on the request here
                 * (bug 3430) */
                /* XXX (green): Should not we bail out on any error here, not
                 * just open error? */
                rc = it_open_error(DISP_OPEN_OPEN, it);
                if (rc)
                        GOTO(out_och_free, rc);

                LASSERT(it_disposition(it, DISP_ENQ_OPEN_REF));

                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_OPEN, 1);
                rc = ll_local_open(file, it, fd, *och_p);
                LASSERTF(rc == 0, "rc = %d\n", rc);
        }
        up(&lli->lli_och_sem);
        fd = NULL;

        /* Must do this outside lli_och_sem lock to prevent deadlock where
           different kind of OPEN lock for this same inode gets cancelled
           by ldlm_cancel_lru */
        if (!S_ISREG(inode->i_mode))
                GOTO(out_och_free, rc);

        lsm = lli->lli_smd;
        if (lsm == NULL) {
                if (file->f_flags & O_LOV_DELAY_CREATE ||
                    !(file->f_mode & FMODE_WRITE)) {
                        CDEBUG(D_INODE, "object creation was delayed\n");
                        GOTO(out_och_free, rc);
                }
        }
        file->f_flags &= ~O_LOV_DELAY_CREATE;
        GOTO(out_och_free, rc);

out_och_free:
        if (it && it_disposition(it, DISP_ENQ_OPEN_REF)) {
                ptlrpc_req_finished(it->d.lustre.it_data);
                it_clear_disposition(it, DISP_ENQ_OPEN_REF);
        }

        if (rc == 0) {
                ll_open_complete(inode);
        } else {
                if (och_p && *och_p) {
                        OBD_FREE(*och_p, sizeof (struct obd_client_handle));
                        *och_p = NULL; /* OBD_FREE writes some magic there */
                        (*och_usecount)--;
                }
                up(&lli->lli_och_sem);
out_openerr:
                if (opendir_set != 0)
                        ll_stop_statahead(inode, lli->lli_opendir_key);
                if (fd != NULL)
                        ll_file_data_put(fd);
        }

        return rc;
}

/* Fills the obdo with the attributes for the inode defined by lsm */
int ll_lsm_getattr(struct obd_export *exp, struct lov_stripe_md *lsm,
                   struct obdo *oa)
{
        struct ptlrpc_request_set *set;
        struct obd_info oinfo = { { { 0 } } };
        int rc;
        ENTRY;

        LASSERT(lsm != NULL);

        memset(oa, 0, sizeof *oa);
        oinfo.oi_md = lsm;
        oinfo.oi_oa = oa;
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
                rc = obd_getattr_async(exp, &oinfo, set);
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

static int ll_lock_to_stripe_offset(struct inode *inode, struct ldlm_lock *lock)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_export *exp = ll_i2obdexp(inode);
        struct {
                char name[16];
                struct ldlm_lock *lock;
        } key = { .name = KEY_LOCK_TO_STRIPE, .lock = lock };
        __u32 stripe, vallen = sizeof(stripe);
        struct lov_oinfo *loinfo;
        int rc;
        ENTRY;

        if (lsm->lsm_stripe_count == 1)
                GOTO(check, stripe = 0);

        /* get our offset in the lov */
        rc = obd_get_info(exp, sizeof(key), &key, &vallen, &stripe, lsm);
        if (rc != 0) {
                CERROR("obd_get_info: rc = %d\n", rc);
                RETURN(rc);
        }
        LASSERT(stripe < lsm->lsm_stripe_count);

check:
        loinfo = lsm->lsm_oinfo[stripe];
        if (!osc_res_name_eq(loinfo->loi_id, loinfo->loi_gr,
                            &lock->l_resource->lr_name)) {
                LDLM_ERROR(lock, "resource doesn't match object "LPU64"/"LPU64,
                           loinfo->loi_id, loinfo->loi_gr);
                RETURN(-ELDLM_NO_LOCK_DATA);
        }

        RETURN(stripe);
}

/* Get extra page reference to ensure it is not going away */
void ll_pin_extent_cb(void *data)
{
        struct page *page = data;

        page_cache_get(page);

        return;
}
/* Flush the page from page cache for an extent as its canceled.
 * Page to remove is delivered as @data.
 *
 * No one can dirty the extent until we've finished our work and they cannot
 * enqueue another lock.  The DLM protects us from ll_file_read/write here,
 * but other kernel actors could have pages locked.
 *
 * If @discard is set, there is no need to write the page if it is dirty.
 *
 * Called with the DLM lock held. */
int ll_page_removal_cb(void *data, int discard)
{
        int rc;
        struct page *page = data;
        struct address_space *mapping;

        ENTRY;

        /* We have page reference already from ll_pin_page */
        lock_page(page);

        /* Already truncated by somebody */
        if (!page->mapping)
                GOTO(out, rc = 0);

        mapping = page->mapping;

        ll_teardown_mmaps(mapping,
                          (__u64)page->index << PAGE_CACHE_SHIFT,
                          ((__u64)page->index<<PAGE_CACHE_SHIFT)|
                                                              ~PAGE_CACHE_MASK);
        LL_CDEBUG_PAGE(D_PAGE, page, "removing page\n");
        if (!discard && PageWriteback(page))
                wait_on_page_writeback(page);

        if (!discard && clear_page_dirty_for_io(page)) {
                rc = ll_call_writepage(page->mapping->host, page);
                /* either waiting for io to complete or reacquiring
                 * the lock that the failed writepage released */
                lock_page(page);
                wait_on_page_writeback(page);
                if (rc < 0) {
                        CERROR("writepage inode %lu(%p) of page %p "
                               "failed: %d\n", mapping->host->i_ino,
                               mapping->host, page, rc);
                        if (rc == -ENOSPC)
                                set_bit(AS_ENOSPC, &mapping->flags);
                        else
                                set_bit(AS_EIO, &mapping->flags);
                }
        }
        if (page->mapping != NULL) {
                struct ll_async_page *llap = llap_cast_private(page);
                // checking again to account for writeback's lock_page()
                LL_CDEBUG_PAGE(D_PAGE, page, "truncating\n");
                if (llap)
                        ll_ra_accounting(llap, page->mapping);
                truncate_complete_page(page->mapping, page);
        }
        EXIT;
out:
        LASSERT(!PageWriteback(page));
        unlock_page(page);
        page_cache_release(page);

        return 0;
}

int ll_extent_lock_cancel_cb(struct ldlm_lock *lock, struct ldlm_lock_desc *new,
                             void *data, int flag)
{
        struct inode *inode;
        struct ll_inode_info *lli;
        struct lov_stripe_md *lsm;
        int stripe;
        __u64 kms;

        ENTRY;

        if ((unsigned long)data > 0 && (unsigned long)data < 0x1000) {
                LDLM_ERROR(lock, "cancelling lock with bad data %p", data);
                LBUG();
        }

        inode = ll_inode_from_lock(lock);
        if (inode == NULL)
                RETURN(0);
        lli = ll_i2info(inode);
        if (lli == NULL)
                GOTO(iput, 0);
        if (lli->lli_smd == NULL)
                GOTO(iput, 0);
        lsm = lli->lli_smd;

        stripe = ll_lock_to_stripe_offset(inode, lock);
        if (stripe < 0)
                GOTO(iput, 0);

        lov_stripe_lock(lsm);
        lock_res_and_lock(lock);
        kms = ldlm_extent_shift_kms(lock,
                                    lsm->lsm_oinfo[stripe]->loi_kms);

        if (lsm->lsm_oinfo[stripe]->loi_kms != kms)
                LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                           lsm->lsm_oinfo[stripe]->loi_kms, kms);
        lsm->lsm_oinfo[stripe]->loi_kms = kms;
        unlock_res_and_lock(lock);
        lov_stripe_unlock(lsm);
        ll_try_done_writing(inode);
        EXIT;
iput:
        iput(inode);

        return 0;
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

                lock_res_and_lock(lock);
                ll_inode_size_lock(inode, 1);
                kms = MAX(lsm->lsm_oinfo[stripe].loi_kms, lvb->lvb_size);
                kms = ldlm_extent_shift_kms(NULL, kms);
                if (lsm->lsm_oinfo[stripe].loi_kms != kms)
                        LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                                   lsm->lsm_oinfo[stripe].loi_kms, kms);
                lsm->lsm_oinfo[stripe].loi_kms = kms;
                ll_inode_size_unlock(inode, 1);
                unlock_res_and_lock(lock);
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
        int rc, stripe;
        int size[2] = { sizeof(struct ptlrpc_body), sizeof(*lvb) };
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

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(iput, rc);

        lvb = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*lvb));
        lvb->lvb_size = lli->lli_smd->lsm_oinfo[stripe]->loi_kms;
        lvb->lvb_mtime = LTIME_S(inode->i_mtime);
        lvb->lvb_atime = LTIME_S(inode->i_atime);
        lvb->lvb_ctime = LTIME_S(inode->i_ctime);

        LDLM_DEBUG(lock, "i_size: %llu -> stripe number %u -> kms "LPU64
                   " atime "LPU64", mtime "LPU64", ctime "LPU64,
                   i_size_read(inode), stripe, lvb->lvb_size, lvb->lvb_atime,
                   lvb->lvb_mtime, lvb->lvb_ctime);
 iput:
        iput(inode);

 out:
        /* These errors are normal races, so we don't want to fill the console
         * with messages by calling ptlrpc_error() */
        if (rc == -ELDLM_NO_LOCK_DATA)
                lustre_pack_reply(req, 1, NULL, NULL);

        req->rq_status = rc;
        return rc;
}

int ll_glimpse_ioctl(struct ll_sb_info *sbi, struct lov_stripe_md *lsm,
                     lstat_t *st)
{
        struct lustre_handle lockh = { 0 };
        struct ldlm_enqueue_info einfo = { 0 };
        struct obd_info oinfo = { { { 0 } } };
        struct ost_lvb lvb;
        int rc;

        ENTRY;

        einfo.ei_type = LDLM_EXTENT;
        einfo.ei_mode = LCK_PR;
        einfo.ei_cb_bl = osc_extent_blocking_cb;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = ll_glimpse_callback;
        einfo.ei_cbdata = NULL;

        oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;
        oinfo.oi_lockh = &lockh;
        oinfo.oi_md = lsm;
        oinfo.oi_flags = LDLM_FL_HAS_INTENT;

        rc = obd_enqueue_rqset(sbi->ll_osc_exp, &oinfo, &einfo);
        if (rc == -ENOENT)
                RETURN(rc);
        if (rc != 0) {
                CERROR("obd_enqueue returned rc %d, "
                       "returning -EIO\n", rc);
                RETURN(rc > 0 ? -EIO : rc);
        }

        lov_stripe_lock(lsm);
        memset(&lvb, 0, sizeof(lvb));
        obd_merge_lvb(sbi->ll_osc_exp, lsm, &lvb, 0);
        st->st_size = lvb.lvb_size;
        st->st_blocks = lvb.lvb_blocks;
        st->st_mtime = lvb.lvb_mtime;
        st->st_atime = lvb.lvb_atime;
        st->st_ctime = lvb.lvb_ctime;
        lov_stripe_unlock(lsm);

        RETURN(rc);
}

/* NB: obd_merge_lvb will prefer locally cached writes if they extend the
 * file (because it prefers KMS over RSS when larger) */
int ll_glimpse_size(struct inode *inode, int ast_flags)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_handle lockh = { 0 };
        struct ldlm_enqueue_info einfo = { 0 };
        struct obd_info oinfo = { { { 0 } } };
        struct ost_lvb lvb;
        int rc;
        ENTRY;

        CDEBUG(D_DLMTRACE, "Glimpsing inode %lu\n", inode->i_ino);

        if (!lli->lli_smd) {
                CDEBUG(D_DLMTRACE, "No objects for inode %lu\n", inode->i_ino);
                RETURN(0);
        }

        /* NOTE: this looks like DLM lock request, but it may not be one. Due
         *       to LDLM_FL_HAS_INTENT flag, this is glimpse request, that
         *       won't revoke any conflicting DLM locks held. Instead,
         *       ll_glimpse_callback() will be called on each client
         *       holding a DLM lock against this file, and resulting size
         *       will be returned for each stripe. DLM lock on [0, EOF] is
         *       acquired only if there were no conflicting locks. */
        einfo.ei_type = LDLM_EXTENT;
        einfo.ei_mode = LCK_PR;
        einfo.ei_cb_bl = osc_extent_blocking_cb;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = ll_glimpse_callback;
        einfo.ei_cbdata = inode;

        oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;
        oinfo.oi_lockh = &lockh;
        oinfo.oi_md = lli->lli_smd;
        oinfo.oi_flags = ast_flags | LDLM_FL_HAS_INTENT;

        rc = obd_enqueue_rqset(sbi->ll_osc_exp, &oinfo, &einfo);
        if (rc == -ENOENT)
                RETURN(rc);
        if (rc != 0) {
                CERROR("obd_enqueue returned rc %d, returning -EIO\n", rc);
                RETURN(rc > 0 ? -EIO : rc);
        }

        ll_inode_size_lock(inode, 1);
        inode_init_lvb(inode, &lvb);
        /* merge timestamps the most recently obtained from mds with
           timestamps obtained from osts */
        lvb.lvb_atime = lli->lli_lvb.lvb_atime;
        lvb.lvb_mtime = lli->lli_lvb.lvb_mtime;
        lvb.lvb_ctime = lli->lli_lvb.lvb_ctime;
        rc = obd_merge_lvb(sbi->ll_osc_exp, lli->lli_smd, &lvb, 0);
        i_size_write(inode, lvb.lvb_size);
        inode->i_blocks = lvb.lvb_blocks;
        LTIME_S(inode->i_mtime) = lvb.lvb_mtime;
        LTIME_S(inode->i_atime) = lvb.lvb_atime;
        LTIME_S(inode->i_ctime) = lvb.lvb_ctime;
        ll_inode_size_unlock(inode, 1);

        CDEBUG(D_DLMTRACE, "glimpse: size: %llu, blocks: %llu\n",
               i_size_read(inode), (long long)inode->i_blocks);

        RETURN(rc);
}

int ll_extent_lock(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm, int mode,
                   ldlm_policy_data_t *policy, struct lustre_handle *lockh,
                   int ast_flags)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ost_lvb lvb;
        struct ldlm_enqueue_info einfo = { 0 };
        struct obd_info oinfo = { { { 0 } } };
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

        einfo.ei_type = LDLM_EXTENT;
        einfo.ei_mode = mode;
        einfo.ei_cb_bl = osc_extent_blocking_cb;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = ll_glimpse_callback;
        einfo.ei_cbdata = inode;

        oinfo.oi_policy = *policy;
        oinfo.oi_lockh = lockh;
        oinfo.oi_md = lsm;
        oinfo.oi_flags = ast_flags;

        rc = obd_enqueue(sbi->ll_osc_exp, &oinfo, &einfo, NULL);
        *policy = oinfo.oi_policy;
        if (rc > 0)
                rc = -EIO;

        ll_inode_size_lock(inode, 1);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(sbi->ll_osc_exp, lsm, &lvb, 1);

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
                i_size_write(inode, lvb.lvb_size);
                CDEBUG(D_INODE, "inode=%lu, updating i_size %llu\n",
                       inode->i_ino, i_size_read(inode));
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

        rc = obd_cancel(sbi->ll_osc_exp, lsm, mode, lockh, 0, 0);

        RETURN(rc);
}

static void ll_set_file_contended(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        lli->lli_contention_time = cfs_time_current();
        set_bit(LLI_F_CONTENDED, &lli->lli_flags);
}

void ll_clear_file_contended(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        clear_bit(LLI_F_CONTENDED, &lli->lli_flags);
}

static int ll_is_file_contended(struct file *file)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        ENTRY;

        if (!(sbi->ll_lco.lco_flags & OBD_CONNECT_SRVLOCK)) {
                CDEBUG(D_INFO, "the server does not support SRVLOCK feature,"
                       " osc connect flags = 0x"LPX64"\n",
                       sbi->ll_lco.lco_flags);
                RETURN(0);
        }

        if (fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK))
                RETURN(0);

        /* The semantics here is a bit complicated due to compatibility.
         * The user may be aware of per-file LL_FILE_LOCKED_DIRECTIO,
         * but not of per-client lockless_direct_io, so the file bit takes
         * precedence if it is set. If the file bit is not set, we use
         * lockless I/O unless per-client lockless_direct_io is set to zero.
         */
        CLASSERT(SBI_DEFAULT_LOCKLESS_DIRECT_IO == 1);
        if ((file->f_flags & O_DIRECT) &&
            !(fd && (fd->fd_flags & LL_FILE_LOCKED_DIRECTIO)) &&
            sbi->ll_lockless_direct_io)
                RETURN(1);

        /* server-side locking for cached I/O with LL_FILE_LOCKLESS_IO */
        if (!(file->f_flags & O_DIRECT) &&
            fd && fd->fd_flags & LL_FILE_LOCKLESS_IO)
                RETURN(1);

        if (test_bit(LLI_F_CONTENDED, &lli->lli_flags)) {
                cfs_time_t cur_time = cfs_time_current();
                cfs_time_t retry_time;

                retry_time = cfs_time_add(
                        lli->lli_contention_time,
                        cfs_time_seconds(sbi->ll_contention_time));
                if (cfs_time_after(cur_time, retry_time)) {
                        ll_clear_file_contended(inode);
                        RETURN(0);
                }
                RETURN(1);
        }
        RETURN(0);
}

static int ll_file_get_tree_lock_iov(struct ll_lock_tree *tree,
                                     struct file *file, const struct iovec *iov,
                                     unsigned long nr_segs,
                                     obd_off start, obd_off end, int rw)
{
        int append;
        int tree_locked = 0;
        int rc;
        struct inode * inode = file->f_dentry->d_inode;
        ENTRY;

        append = (rw == OBD_BRW_WRITE) && (file->f_flags & O_APPEND);

        if (append || !ll_is_file_contended(file)) {
                struct ll_lock_tree_node *node;
                int ast_flags;

                ast_flags = append ? 0 : LDLM_FL_DENY_ON_CONTENTION;
                if (file->f_flags & O_NONBLOCK)
                        ast_flags |= LDLM_FL_BLOCK_NOWAIT;
                node = ll_node_from_inode(inode, start, end,
                                          (rw == OBD_BRW_WRITE) ? LCK_PW : LCK_PR);
                if (IS_ERR(node)) {
                        rc = PTR_ERR(node);
                        GOTO(out, rc);
                }
                tree->lt_fd = LUSTRE_FPRIVATE(file);
                rc = ll_tree_lock_iov(tree, node, iov, nr_segs, ast_flags);
                if (rc == 0)
                        tree_locked = 1;
                else if (rc == -EUSERS)
                        ll_set_file_contended(inode);
                else
                        GOTO(out, rc);
        }
        RETURN(tree_locked);
out:
        return rc;
}

/* XXX: exact copy from kernel code (__generic_file_aio_write_nolock from rhel4)
 */
static size_t ll_file_get_iov_count(const struct iovec *iov,
                                     unsigned long *nr_segs)
{
        size_t count = 0;
        unsigned long seg;

        for (seg = 0; seg < *nr_segs; seg++) {
                const struct iovec *iv = &iov[seg];

                /*
                 * If any segment has a negative length, or the cumulative
                 * length ever wraps negative then return -EINVAL.
                 */
                count += iv->iov_len;
                if (unlikely((ssize_t)(count|iv->iov_len) < 0))
                        return -EINVAL;
                if (access_ok(VERIFY_WRITE, iv->iov_base, iv->iov_len))
                        continue;
                if (seg == 0)
                        return -EFAULT;
                *nr_segs = seg;
                count -= iv->iov_len;   /* This segment is no good */
                break;
        }
        return count;
}

static int iov_copy_update(unsigned long *nr_segs, const struct iovec **iov_out,
                           unsigned long *nrsegs_copy,
                           struct iovec *iov_copy, size_t *offset,
                           size_t size)
{
        int i;
        const struct iovec *iov = *iov_out;
        for (i = 0; i < *nr_segs;
             i++) {
                const struct iovec *iv = &iov[i];
                struct iovec *ivc = &iov_copy[i];
                *ivc = *iv;
                if (i == 0) {
                        ivc->iov_len -= *offset;
                        ivc->iov_base += *offset;
                }
                if (ivc->iov_len >= size) {
                        ivc->iov_len = size;
                        if (i == 0)
                                *offset += size;
                        else
                                *offset = size;
                        break;
                }
                size -= ivc->iov_len;
        }
        *iov_out += i;
        *nr_segs -= i;
        *nrsegs_copy = i + 1;

        return 0;
}

static int ll_get_short_lock(struct page *page, int rw, obd_off start,
                             obd_off end, struct lustre_handle *lockh)
{
        struct ll_async_page *llap;
        struct obd_export *exp;
        struct inode *inode = page->mapping->host;

        ENTRY;

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                RETURN(0);

        llap = llap_cast_private(page);
        if (llap == NULL)
                RETURN(0);

        RETURN(obd_get_lock(exp, ll_i2info(inode)->lli_smd,
                            &llap->llap_cookie, rw, start, end, lockh,
                            OBD_FAST_LOCK));
}

static void ll_release_short_lock(struct inode *inode, obd_off end,
                                  struct lustre_handle *lockh, int rw)
{
        struct obd_export *exp;
        int rc;

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                return;

        rc = obd_cancel(exp, ll_i2info(inode)->lli_smd,
                        rw = OBD_BRW_READ ? LCK_PR : LCK_PW, lockh,
                        OBD_FAST_LOCK, end);
        if (rc < 0)
                CERROR("unlock failed (%d)\n", rc);
}

static inline int ll_file_get_fast_lock(struct file *file,
                                        obd_off ppos, obd_off end,
                                        const struct iovec *iov,
                                        unsigned long nr_segs,
                                        struct lustre_handle *lockh,
                                        int rw)
{
        int rc = 0, seg;
        struct page *page;

        ENTRY;

        /* we would like this read request to be lockfree */
        for (seg = 0; seg < nr_segs; seg++) {
                const struct iovec *iv = &iov[seg];
                if (ll_region_mapped((unsigned long)iv->iov_base, iv->iov_len))
                        GOTO(out, rc);
        }

        page = find_lock_page(file->f_dentry->d_inode->i_mapping,
                              ppos >> CFS_PAGE_SHIFT);
        if (page) {
                if (ll_get_short_lock(page, rw, ppos, end, lockh))
                        rc = 1;

                unlock_page(page);
                page_cache_release(page);
        }

out:
        RETURN(rc);
}

static inline void ll_file_put_fast_lock(struct inode *inode, obd_off end,
                                         struct lustre_handle *lockh, int rw)
{
        ll_release_short_lock(inode, end, lockh, rw);
}

static inline int ll_file_get_lock(struct file *file, obd_off ppos,
                                   obd_off end, const struct iovec *iov,
                                   unsigned long nr_segs,
                                   struct lustre_handle *lockh,
                                   struct ll_lock_tree *tree, int rw)
{
        int rc;

        ENTRY;

        if (ll_file_get_fast_lock(file, ppos, end, iov, nr_segs, lockh, rw))
                RETURN(LL_LOCK_STYLE_FASTLOCK);

        rc = ll_file_get_tree_lock_iov(tree, file, iov, nr_segs,
                                       ppos, end, rw);
        /* rc: 1 for tree lock, 0 for no lock, <0 for error */
        switch (rc) {
        case 1:
                RETURN(LL_LOCK_STYLE_TREELOCK);
        case 0:
                RETURN(LL_LOCK_STYLE_NOLOCK);
        }

        /* an error happened if we reached this point, rc = -errno here */
        RETURN(rc);
}

static inline void ll_file_put_lock(struct inode *inode, obd_off end,
                                    enum ll_lock_style lock_style,
                                    struct lustre_handle *lockh,
                                    struct ll_lock_tree *tree, int rw)

{
        switch (lock_style) {
        case LL_LOCK_STYLE_TREELOCK:
                ll_tree_unlock(tree);
                break;
        case LL_LOCK_STYLE_FASTLOCK:
                ll_file_put_fast_lock(inode, end, lockh, rw);
                break;
        default:
                CERROR("invalid locking style (%d)\n", lock_style);
        }
}

#ifdef HAVE_FILE_READV
static ssize_t ll_file_readv(struct file *file, const struct iovec *iov,
                              unsigned long nr_segs, loff_t *ppos)
{
#else
static ssize_t ll_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
                                unsigned long nr_segs, loff_t pos)
{
        struct file *file = iocb->ki_filp;
        loff_t *ppos = &iocb->ki_pos;
#endif
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_thread_data ltd = { 0 };
        struct ost_lvb lvb;
        struct ll_ra_read bead;
        int ra = 0;
        obd_off end;
        ssize_t retval, chunk, sum = 0;
        struct iovec *iov_copy = NULL;
        unsigned long nrsegs_copy, nrsegs_orig = 0;
        size_t count, iov_offset = 0;
        __u64 kms;
        ENTRY;

        count = ll_file_get_iov_count(iov, &nr_segs);
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size=%lu,offset=%lld\n",
               inode->i_ino, inode->i_generation, inode, (unsigned long)count,
               *ppos);
        /* "If nbyte is 0, read() will return 0 and have no other results."
         *                      -- Single Unix Spec */
        if (count == 0)
                RETURN(0);

        ll_stats_ops_tally(sbi, LPROC_LL_READ_BYTES, count);

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
                if (*ppos >= i_size_read(inode))
                        RETURN(0);

                if (count > i_size_read(inode) - *ppos)
                        count = i_size_read(inode) - *ppos;
                /* Make sure to correctly adjust the file pos pointer for
                 * EFAULT case */
                for (nrsegs_copy = 0; nrsegs_copy < nr_segs; nrsegs_copy++) {
                        const struct iovec *iv = &iov[nrsegs_copy];

                        if (count < iv->iov_len)
                                chunk = count;
                        else
                                chunk = iv->iov_len;
                        notzeroed = clear_user(iv->iov_base, chunk);
                        sum += (chunk - notzeroed);
                        count -= (chunk - notzeroed);
                        if (notzeroed || !count)
                                break;
                }
                *ppos += sum;
                if (!sum)
                        RETURN(-EFAULT);
                RETURN(sum);
        }

        ltd.ltd_magic = LTD_MAGIC;
        ll_td_set(&ltd);
repeat:
        memset(&ltd, 0, sizeof(ltd));
        ltd.ltd_magic = LTD_MAGIC;
        if (sbi->ll_max_rw_chunk != 0 && !(file->f_flags & O_DIRECT)) {
                /* first, let's know the end of the current stripe */
                end = *ppos;
                obd_extent_calc(sbi->ll_osc_exp, lsm, OBD_CALC_STRIPE_END,&end);

                /* correct, the end is beyond the request */
                if (end > *ppos + count - 1)
                        end = *ppos + count - 1;

                /* and chunk shouldn't be too large even if striping is wide */
                if (end - *ppos > sbi->ll_max_rw_chunk)
                        end = *ppos + sbi->ll_max_rw_chunk - 1;

                chunk = end - *ppos + 1;
                if ((count == chunk) && (iov_offset == 0)) {
                        if (iov_copy)
                                OBD_FREE(iov_copy, sizeof(*iov) * nrsegs_orig);

                        iov_copy = (struct iovec *)iov;
                        nrsegs_copy = nr_segs;
                } else {
                        if (!iov_copy) {
                                nrsegs_orig = nr_segs;
                                OBD_ALLOC(iov_copy, sizeof(*iov) * nr_segs);
                                if (!iov_copy)
                                        GOTO(out, retval = -ENOMEM);
                        }

                        iov_copy_update(&nr_segs, &iov, &nrsegs_copy, iov_copy,
                                        &iov_offset, chunk);
                }
        } else {
                end = *ppos + count - 1;
                iov_copy = (struct iovec *)iov;
                nrsegs_copy = nr_segs;
        }

        down_read(&lli->lli_truncate_rwsem); /* Bug 18233 */

        ltd.lock_style = ll_file_get_lock(file, (obd_off)(*ppos), end,
                                          iov_copy, nrsegs_copy,
                                          &ltd.u.lockh, &ltd.u.tree,
                                          OBD_BRW_READ);
        if (ltd.lock_style < 0 || ltd.lock_style == LL_LOCK_STYLE_NOLOCK)
                up_read(&lli->lli_truncate_rwsem);
        if (ltd.lock_style < 0)
                GOTO(out, retval = ltd.lock_style);

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
        obd_merge_lvb(ll_i2sbi(inode)->ll_osc_exp, lsm, &lvb, 1);
        kms = lvb.lvb_size;
        if (*ppos + count - 1 > kms) {
                /* A glimpse is necessary to determine whether we return a
                 * short read (B) or some zeroes at the end of the buffer (C) */
                ll_inode_size_unlock(inode, 1);
                retval = ll_glimpse_size(inode, LDLM_FL_BLOCK_GRANTED);
                if (retval) {
                        if (ltd.lock_style != LL_LOCK_STYLE_NOLOCK) {
                                ll_file_put_lock(inode, end, ltd.lock_style,
                                                 &ltd.u.lockh, &ltd.u.tree,
                                                 OBD_BRW_READ);
                                up_read(&lli->lli_truncate_rwsem);
                        }
                        goto out;
                } else {
                        /* If objective page index exceed the end-of-file page
                         * index, return directly. Do not expect kernel will
                         * check such case correctly. linux-2.6.18-128.1.1 miss
                         * to do that. --bug 17336 */
                        loff_t size = i_size_read(inode);
                        unsigned long cur_index = *ppos >> CFS_PAGE_SHIFT;

                        if ((size == 0 && cur_index != 0) ||
                            (((size - 1) >> CFS_PAGE_SHIFT) < cur_index)) {
                                if (ltd.lock_style != LL_LOCK_STYLE_NOLOCK) {

                                        ll_file_put_lock(inode, end,
                                                         ltd.lock_style,
                                                         &ltd.u.lockh,
                                                         &ltd.u.tree,
                                                         OBD_BRW_READ);
                                        up_read(&lli->lli_truncate_rwsem);
                                }
                                goto out;
                        }
                }
        } else {
                /* region is within kms and, hence, within real file size (A).
                 * We need to increase i_size to cover the read region so that
                 * generic_file_read() will do its job, but that doesn't mean
                 * the kms size is _correct_, it is only the _minimum_ size.
                 * If someone does a stat they will get the correct size which
                 * will always be >= the kms value here.  b=11081 */
                if (i_size_read(inode) < kms)
                        i_size_write(inode, kms);
                ll_inode_size_unlock(inode, 1);
        }

        chunk = end - *ppos + 1;
        CDEBUG(D_INODE,"Read ino %lu, %ld bytes, offset %lld, i_size %llu\n",
               inode->i_ino, (long)chunk, *ppos, i_size_read(inode));

        /* turn off the kernel's read-ahead */
        if (ltd.lock_style != LL_LOCK_STYLE_NOLOCK) {
                struct ost_lvb *xtimes;
                /* read under locks
                 *
                 * 1. update inode's atime as long as concurrent stat
                 * (via ll_glimpse_size) might bring out-of-date ones
                 *
                 * 2. update lsm so that next stat (via
                 * ll_glimpse_size) could get correct values in lsm */
                OBD_ALLOC_PTR(xtimes);
                if (NULL == xtimes) {
                        ll_file_put_lock(inode, end, ltd.lock_style,
                                         &ltd.u.lockh, &ltd.u.tree,
                                         OBD_BRW_READ);
                        up_read(&lli->lli_truncate_rwsem);
                        GOTO(out, retval = -ENOMEM);
                }

                lov_stripe_lock(lsm);
                LTIME_S(inode->i_atime) = LTIME_S(CURRENT_TIME);
                xtimes->lvb_atime = LTIME_S(inode->i_atime);
                obd_update_lvb(sbi->ll_osc_exp, lsm, xtimes,
                               OBD_MD_FLATIME);
                lov_stripe_unlock(lsm);
                OBD_FREE_PTR(xtimes);

                file->f_ra.ra_pages = 0;
                /* initialize read-ahead window once per syscall */
                if (ra == 0) {
                        ra = 1;
                        ll_ra_read_init(file, &bead, *ppos, count);
                }

                /* BUG: 5972 */
                file_accessed(file);
#ifdef HAVE_FILE_READV
                retval = generic_file_readv(file, iov_copy, nrsegs_copy, ppos);
#else
                retval = generic_file_aio_read(iocb, iov_copy, nrsegs_copy,
                                               *ppos);
#endif
                ll_file_put_lock(inode, end, ltd.lock_style, &ltd.u.lockh,
                                 &ltd.u.tree, OBD_BRW_READ);
                up_read(&lli->lli_truncate_rwsem);
        } else {
                file_accessed(file);
                retval = ll_direct_IO(READ, file, iov_copy, *ppos, nr_segs, 0);
                if (retval > 0) {
                        lprocfs_counter_add(sbi->ll_stats,
                                            LPROC_LL_LOCKLESS_READ,
                                            (long)retval);
                        *ppos += retval;
                }
        }
        ll_rw_stats_tally(sbi, current->pid, file, count, 0);
        if (retval > 0) {
                count -= retval;
                sum += retval;
                if (retval == chunk && count > 0)
                        goto repeat;
        }

 out:
        ll_td_set(NULL);
        if (ra != 0)
                ll_ra_read_ex(file, &bead);
        retval = (sum > 0) ? sum : retval;

        if (iov_copy && iov_copy != iov)
                OBD_FREE(iov_copy, sizeof(*iov) * nrsegs_orig);

        RETURN(retval);
}

static ssize_t ll_file_read(struct file *file, char *buf, size_t count,
                            loff_t *ppos)
{
        struct iovec local_iov = { .iov_base = (void __user *)buf,
                                   .iov_len = count };
#ifdef HAVE_FILE_READV
        return ll_file_readv(file, &local_iov, 1, ppos);
#else
        struct kiocb kiocb;
        ssize_t ret;

        init_sync_kiocb(&kiocb, file);
        kiocb.ki_pos = *ppos;
        kiocb.ki_left = count;

        ret = ll_file_aio_read(&kiocb, &local_iov, 1, kiocb.ki_pos);
        *ppos = kiocb.ki_pos;
        return ret;
#endif
}

/* iov_shorten from linux kernel */
static unsigned long ll_iov_shorten(struct iovec *iov,
                                    unsigned long nr_segs,
                                    size_t to)
{
        unsigned long seg = 0;
        size_t len = 0;

        while (seg < nr_segs) {
                seg++;
                if (len + iov->iov_len >= to) {
                        iov->iov_len = to - len;
                        break;
                }
                len += iov->iov_len;
                iov++;
        }
        return seg;
}

/* 2.6.22 and 2.6.27 export this as generic_segment_checks */
static int ll_generic_segment_checks(const struct iovec *iov,
                                     unsigned long *nr_segs,
                                     size_t *count,
                                     int access_flags)
{
        unsigned long   seg;
        size_t cnt = 0;
        for (seg = 0; seg < *nr_segs; seg++) {
                const struct iovec *iv = &iov[seg];

                /*
                 * If any segment has a negative length, or the cumulative
                 * length ever wraps negative then return -EINVAL.
                 */
                cnt += iv->iov_len;
                if (unlikely((ssize_t)(cnt|iv->iov_len) < 0))
                        return -EINVAL;
                if (access_ok(access_flags, iv->iov_base, iv->iov_len))
                        continue;
                if (seg == 0)
                        return -EFAULT;
                *nr_segs = seg;
                cnt -= iv->iov_len;  /* This segment is no good */
                break;
        }
        *count = cnt;
        return 0;
}

/*
 * Write to a file (through the page cache).
 */
#ifdef HAVE_FILE_WRITEV
static ssize_t ll_file_writev(struct file *file, const struct iovec *iov,
                              unsigned long nr_segs, loff_t *ppos)
{
#else /* AIO stuff */
static ssize_t ll_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
                                 unsigned long nr_segs, loff_t pos)
{
        struct file *file = iocb->ki_filp;
        loff_t *ppos = &iocb->ki_pos;
#endif
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ll_thread_data ltd = { 0 };
        loff_t maxbytes = ll_file_maxbytes(inode);
        loff_t lock_start, lock_end, end;
        ssize_t retval, chunk, sum = 0;
        int tree_locked;
        struct iovec *iov_copy = NULL;
        unsigned long nrsegs_copy, nrsegs_orig = 0;
        size_t count, iov_offset = 0;
        int got_write_sem = 0;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        ENTRY;

        count = ll_file_get_iov_count(iov, &nr_segs);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size=%lu,offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, (unsigned long)count,
               *ppos);

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

        /* signal(7) specifies that write(2) and writev(2) should be restarted */
        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK)) {
                got_write_sem = 1;
                if (down_interruptible(&ll_i2info(inode)->lli_write_sem))
                        RETURN(-ERESTARTSYS);
        }

        ltd.ltd_magic = LTD_MAGIC;
        ll_td_set(&ltd);
repeat:
        memset(&ltd, 0, sizeof(ltd));
        ltd.ltd_magic = LTD_MAGIC;

        chunk = 0; /* just to fix gcc's warning */
        end = *ppos + count - 1;

        if (file->f_flags & O_APPEND) {
                lock_start = 0;
                lock_end = OBD_OBJECT_EOF;
                iov_copy = (struct iovec *)iov;
                nrsegs_copy = nr_segs;
        } else if (sbi->ll_max_rw_chunk != 0 && !(file->f_flags & O_DIRECT)) {
                /* first, let's know the end of the current stripe */
                end = *ppos;
                obd_extent_calc(sbi->ll_osc_exp, lsm, OBD_CALC_STRIPE_END,
                                (obd_off *)&end);

                /* correct, the end is beyond the request */
                if (end > *ppos + count - 1)
                        end = *ppos + count - 1;

                /* and chunk shouldn't be too large even if striping is wide */
                if (end - *ppos > sbi->ll_max_rw_chunk)
                        end = *ppos + sbi->ll_max_rw_chunk - 1;
                lock_start = *ppos;
                lock_end = end;
                chunk = end - *ppos + 1;
                if ((count == chunk) && (iov_offset == 0)) {
                        if (iov_copy)
                                OBD_FREE(iov_copy, sizeof(*iov) * nrsegs_orig);

                        iov_copy = (struct iovec *)iov;
                        nrsegs_copy = nr_segs;
                } else {
                        if (!iov_copy) {
                                nrsegs_orig = nr_segs;
                                OBD_ALLOC(iov_copy, sizeof(*iov) * nr_segs);
                                if (!iov_copy)
                                        GOTO(out, retval = -ENOMEM);
                        }
                        iov_copy_update(&nr_segs, &iov, &nrsegs_copy, iov_copy,
                                        &iov_offset, chunk);
                }
        } else {
                lock_start = *ppos;
                lock_end = end;
                iov_copy = (struct iovec *)iov;
                nrsegs_copy = nr_segs;
        }

        tree_locked = ll_file_get_tree_lock_iov(&ltd.u.tree, file, iov_copy,
                                                nrsegs_copy,
                                                (obd_off)lock_start,
                                                (obd_off)lock_end,
                                                OBD_BRW_WRITE);
        if (tree_locked < 0)
                GOTO(out, retval = tree_locked);

        /* This is ok, g_f_w will overwrite this under i_sem if it races
         * with a local truncate, it just makes our maxbyte checking easier.
         * The i_size value gets updated in ll_extent_lock() as a consequence
         * of the [0,EOF] extent lock we requested above. */
        if (file->f_flags & O_APPEND) {
                *ppos = i_size_read(inode);
                end = *ppos + count - 1;
        }

        if (*ppos >= maxbytes) {
                send_sig(SIGXFSZ, current, 0);
                GOTO(out_unlock, retval = -EFBIG);
        }
        if (end > maxbytes - 1)
                end = maxbytes - 1;

        /* generic_file_write handles O_APPEND after getting i_mutex */
        chunk = end - *ppos + 1;
        CDEBUG(D_INFO, "Writing inode %lu, %ld bytes, offset %Lu\n",
               inode->i_ino, (long)chunk, *ppos);
        if (tree_locked) {
                struct ost_lvb *xtimes;
                /* write under locks
                 *
                 * 1. update inode's mtime and ctime as long as
                 * concurrent stat (via ll_glimpse_size) might bring
                 * out-of-date ones
                 *
                 * 2. update lsm so that next stat (via
                 * ll_glimpse_size) could get correct values in lsm */
                OBD_ALLOC_PTR(xtimes);
                if (NULL == xtimes)
                        GOTO(out_unlock, retval = -ENOMEM);

                lov_stripe_lock(lsm);
                LTIME_S(inode->i_mtime) = LTIME_S(CURRENT_TIME);
                LTIME_S(inode->i_ctime) = LTIME_S(CURRENT_TIME);
                xtimes->lvb_mtime = LTIME_S(inode->i_mtime);
                xtimes->lvb_ctime = LTIME_S(inode->i_ctime);
                obd_update_lvb(sbi->ll_osc_exp, lsm, xtimes,
                               OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                lov_stripe_unlock(lsm);
                OBD_FREE_PTR(xtimes);

                ltd.lock_style = LL_LOCK_STYLE_TREELOCK;

#ifdef HAVE_FILE_WRITEV
                retval = generic_file_writev(file, iov_copy, nrsegs_copy, ppos);
#else
                retval = generic_file_aio_write(iocb, iov_copy, nrsegs_copy,
                                                *ppos);
#endif
        } else {
                size_t ocount, ncount;

                retval = ll_generic_segment_checks(iov_copy, &nrsegs_copy,
                                                   &ocount, VERIFY_READ);
                if (retval)
                        GOTO(out, retval);

                ncount = ocount;

                retval = generic_write_checks(file, ppos, &ncount, 0);
                if (retval)
                        GOTO(out, retval);

                if (unlikely(ocount != ncount)) {
                        /* we are allowed to modify the original iov too */
                        nrsegs_copy = ll_iov_shorten(iov_copy, nrsegs_copy,
                                                     ncount);
                        chunk = 0; /* no repetition after the short write */
                }

                retval = ll_remove_suid(file, file->f_vfsmnt);
                if (retval)
                        GOTO(out, retval);

                ll_update_time(file);
                retval = ll_direct_IO(WRITE, file, iov_copy, *ppos, nr_segs, 0);
                if (retval > 0) {
                        lprocfs_counter_add(sbi->ll_stats,
                                            LPROC_LL_LOCKLESS_WRITE,
                                            (long)retval);
                        *ppos += retval;
                }
        }
        ll_rw_stats_tally(ll_i2sbi(inode), current->pid, file, chunk, 1);

out_unlock:
        if (tree_locked)
                ll_tree_unlock(&ltd.u.tree);

out:
        if (retval > 0) {
                count -= retval;
                sum += retval;
                if (retval == chunk && count > 0)
                        goto repeat;
        }

        if (got_write_sem)
                up(&ll_i2info(inode)->lli_write_sem);

        ll_td_set(NULL);
        if (iov_copy && iov_copy != iov)
                OBD_FREE(iov_copy, sizeof(*iov) * nrsegs_orig);

        retval = (sum > 0) ? sum : retval;
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_WRITE_BYTES,
                           retval > 0 ? retval : 0);
	if (retval < 0)
		fd->fd_write_failed = true;
	else
		fd->fd_write_failed = false;
        RETURN(retval);
}

static ssize_t ll_file_write(struct file *file, const char *buf, size_t count,
                             loff_t *ppos)
{
        struct iovec local_iov = { .iov_base = (void __user *)buf,
                                   .iov_len = count };

#ifdef HAVE_FILE_WRITEV
        return ll_file_writev(file, &local_iov, 1, ppos);
#else
        struct kiocb kiocb;
        ssize_t ret;

        init_sync_kiocb(&kiocb, file);
        kiocb.ki_pos = *ppos;
        kiocb.ki_left = count;

        ret = ll_file_aio_write(&kiocb, &local_iov, 1, kiocb.ki_pos);
        *ppos = kiocb.ki_pos;

        return ret;
#endif
}

#ifdef HAVE_KERNEL_SENDFILE
/*
 * Send file content (through pagecache) somewhere with helper
 */
static ssize_t ll_file_sendfile(struct file *in_file, loff_t *ppos,
                                size_t count, read_actor_t actor, void *target)
{
        struct inode *inode = in_file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_lock_tree tree;
        struct ll_lock_tree_node *node;
        struct ost_lvb lvb;
        struct ll_ra_read bead;
        ssize_t rc;
        __u64 kms;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size=%lu,offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, (unsigned long)count,
               *ppos);

        /* "If nbyte is 0, read() will return 0 and have no other results."
         *                      -- Single Unix Spec */
        if (count == 0)
                RETURN(0);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_READ_BYTES, count);
        /* turn off the kernel's read-ahead */
        in_file->f_ra.ra_pages = 0;

        /* File with no objects, nothing to lock */
        if (!lsm) {
                rc = generic_file_sendfile(in_file, ppos, count, actor, target);
                RETURN(rc);
        }

        node = ll_node_from_inode(inode, *ppos, *ppos + count - 1, LCK_PR);
        if (IS_ERR(node))
                RETURN(PTR_ERR(node));

        tree.lt_fd = LUSTRE_FPRIVATE(in_file);
        rc = ll_tree_lock(&tree, node, NULL, count,
                          in_file->f_flags & O_NONBLOCK?LDLM_FL_BLOCK_NOWAIT:0);
        if (rc != 0)
                RETURN(rc);

        ll_clear_file_contended(inode);
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
        obd_merge_lvb(ll_i2sbi(inode)->ll_osc_exp, lsm, &lvb, 1);
        kms = lvb.lvb_size;
        if (*ppos + count - 1 > kms) {
                /* A glimpse is necessary to determine whether we return a
                 * short read (B) or some zeroes at the end of the buffer (C) */
                ll_inode_size_unlock(inode, 1);
                rc = ll_glimpse_size(inode, LDLM_FL_BLOCK_GRANTED);
                if (rc)
                        goto out;
        } else {
                /* region is within kms and, hence, within real file size (A) */
                i_size_write(inode, kms);
                ll_inode_size_unlock(inode, 1);
        }

        CDEBUG(D_INFO, "Send ino %lu, %lu bytes, offset %lld, i_size %llu\n",
               inode->i_ino, (unsigned long)count, *ppos, i_size_read(inode));

        ll_ra_read_init(in_file, &bead, *ppos, count);
        /* BUG: 5972 */
        file_accessed(in_file);
        rc = generic_file_sendfile(in_file, ppos, count, actor, target);
        ll_ra_read_ex(in_file, &bead);

 out:
        ll_tree_unlock(&tree);
        RETURN(rc);
}
#endif

/* change based on
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=f0930fffa99e7fe0a0c4b6c7d9a244dc88288c27
 */
#ifdef HAVE_KERNEL_SPLICE_READ
static ssize_t ll_file_splice_read(struct file *in_file, loff_t *ppos,
                                   struct pipe_inode_info *pipe, size_t count,
                                   unsigned int flags)
{
        struct inode *inode = in_file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_lock_tree tree;
        struct ll_lock_tree_node *node;
        struct ost_lvb lvb;
        struct ll_ra_read bead;
        ssize_t rc;
        __u64 kms;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size=%lu,offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, (unsigned long)count,
               *ppos);

        /* "If nbyte is 0, read() will return 0 and have no other results."
         *                      -- Single Unix Spec */
        if (count == 0)
                RETURN(0);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_READ_BYTES, count);
        /* turn off the kernel's read-ahead */
        in_file->f_ra.ra_pages = 0;

        /* File with no objects, nothing to lock */
        if (!lsm) {
                rc = generic_file_splice_read(in_file, ppos, pipe, count, flags);
                RETURN(rc);
        }

        node = ll_node_from_inode(inode, *ppos, *ppos + count - 1, LCK_PR);
        if (IS_ERR(node))
                RETURN(PTR_ERR(node));

        tree.lt_fd = LUSTRE_FPRIVATE(in_file);
        rc = ll_tree_lock(&tree, node, NULL, count,
                          in_file->f_flags & O_NONBLOCK?LDLM_FL_BLOCK_NOWAIT:0);
        if (rc != 0)
                RETURN(rc);

        ll_clear_file_contended(inode);
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
        obd_merge_lvb(ll_i2sbi(inode)->ll_osc_exp, lsm, &lvb, 1);
        kms = lvb.lvb_size;
        if (*ppos + count - 1 > kms) {
                /* A glimpse is necessary to determine whether we return a
                 * short read (B) or some zeroes at the end of the buffer (C) */
                ll_inode_size_unlock(inode, 1);
                rc = ll_glimpse_size(inode, LDLM_FL_BLOCK_GRANTED);
                if (rc)
                        goto out;
        } else {
                /* region is within kms and, hence, within real file size (A) */
                i_size_write(inode, kms);
                ll_inode_size_unlock(inode, 1);
        }

        CDEBUG(D_INFO, "Send ino %lu, %lu bytes, offset %lld, i_size %llu\n",
               inode->i_ino, (unsigned long)count, *ppos, i_size_read(inode));

        ll_ra_read_init(in_file, &bead, *ppos, count);
        /* BUG: 5972 */
        file_accessed(in_file);
        rc = generic_file_splice_read(in_file, ppos, pipe, count, flags);
        ll_ra_read_ex(in_file, &bead);

 out:
        ll_tree_unlock(&tree);
        RETURN(rc);
}
#endif

static int ll_lov_recreate(struct inode *inode, obd_id id, obd_gr gr,
                           obd_count ost_idx)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_export *exp = ll_i2obdexp(inode);
        struct obd_trans_info oti = { 0 };
        struct obdo *oa = NULL;
        int lsm_size;
        int rc = 0;
        struct lov_stripe_md *lsm, *lsm2;
        ENTRY;

        OBDO_ALLOC(oa);
        if (oa == NULL)
                RETURN(-ENOMEM);

        down(&lli->lli_size_sem);
        lsm = lli->lli_smd;
        if (lsm == NULL)
                GOTO(out, rc = -ENOENT);
        lsm_size = sizeof(*lsm) + (sizeof(struct lov_oinfo) *
                   (lsm->lsm_stripe_count));

        OBD_ALLOC(lsm2, lsm_size);
        if (lsm2 == NULL)
                GOTO(out, rc = -ENOMEM);

        oa->o_id = id;
        oa->o_gr = gr;
        oa->o_nlink = ost_idx;
        oa->o_flags |= OBD_FL_RECREATE_OBJS;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLFLAGS;
        obdo_from_inode(oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                        OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        memcpy(lsm2, lsm, lsm_size);
        rc = obd_create(exp, oa, &lsm2, &oti);

        OBD_FREE(lsm2, lsm_size);
        GOTO(out, rc);
out:
        up(&lli->lli_size_sem);
        OBDO_FREE(oa);
        return rc;
}

static int ll_lov_recreate_obj(struct inode *inode, unsigned long arg)
{
        struct ll_recreate_obj ucreat;
        ENTRY;

        if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                RETURN(-EPERM);

        if (copy_from_user(&ucreat, (struct ll_recreate_obj *)arg,
                           sizeof(struct ll_recreate_obj)))
                RETURN(-EFAULT);

        RETURN(ll_lov_recreate(inode, ucreat.lrc_id, 0,
                               ucreat.lrc_ost_idx));
}

static int ll_lov_recreate_fid(struct inode *inode, unsigned long arg)
{
        struct lu_fid fid;
        obd_id id;
        obd_count ost_idx;
        ENTRY;

        if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                RETURN(-EPERM);

        if (copy_from_user(&fid, (struct lu_fid *)arg,
                           sizeof(struct lu_fid)))
                RETURN(-EFAULT);

        id = fid_oid(&fid) | ((fid_seq(&fid) & 0xffff) << 32);
        ost_idx = (fid_seq(&fid) >> 16) & 0xffff;
        RETURN(ll_lov_recreate(inode, id, 0, ost_idx));
}        

int ll_lov_setstripe_ea_info(struct inode *inode, struct file *file,
                                    int flags, struct lov_user_md *lum,
                                    int lum_size)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm;
        struct lookup_intent oit = {.it_op = IT_OPEN, .it_flags = flags};
        int rc = 0;
        ENTRY;

        down(&lli->lli_size_sem);
        lsm = lli->lli_smd;
        if (lsm) {
                up(&lli->lli_size_sem);
                CDEBUG(D_IOCTL, "stripe already exists for ino %lu\n",
                       inode->i_ino);
                RETURN(-EEXIST);
        }

        rc = ll_intent_file_open(file, lum, lum_size, &oit);
        if (rc)
                GOTO(out, rc);
        rc = oit.d.lustre.it_status;
        if (rc < 0)
                GOTO(out_req_free, rc);

        ll_release_openhandle(file->f_dentry, &oit);

 out:
        up(&lli->lli_size_sem);
        ll_intent_release(&oit);
        RETURN(rc);
out_req_free:
        ptlrpc_req_finished((struct ptlrpc_request *) oit.d.lustre.it_data);
        goto out;
}

int ll_lov_getstripe_ea_info(struct inode *inode, const char *filename,
                             struct lov_mds_md **lmmp, int *lmm_size,
                             struct ptlrpc_request **request)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_fid  fid;
        struct mds_body  *body;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *req = NULL;
        int rc, lmmsize;

        ll_inode2fid(&fid, inode);

        rc = ll_get_max_mdsize(sbi, &lmmsize);
        if (rc)
                RETURN(rc);

        rc = mdc_getattr_name(sbi->ll_mdc_exp, &fid,
                        filename, strlen(filename) + 1,
                        OBD_MD_FLEASIZE | OBD_MD_FLDIREA,
                        lmmsize, &req);
        if (rc < 0) {
                CDEBUG(D_INFO, "mdc_getattr_name failed "
                                "on %s: rc %d\n", filename, rc);
                GOTO(out, rc);
        }

        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                        sizeof(*body));
        LASSERT(body != NULL); /* checked by mdc_getattr_name */
        /* swabbed by mdc_getattr_name */
        LASSERT(lustre_rep_swabbed(req, REPLY_REC_OFF));

        lmmsize = body->eadatasize;

        if (!(body->valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
                        lmmsize == 0) {
                GOTO(out, rc = -ENODATA);
        }

        lmm = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1,
                        lmmsize);
        LASSERT(lmm != NULL);
        LASSERT(lustre_rep_swabbed(req, REPLY_REC_OFF + 1));

        if ((lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V1)) &&
            (lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V3)) &&
            (lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_JOIN))) {
                GOTO(out, rc = -EPROTO);
        }
        /*
         * This is coming from the MDS, so is probably in
         * little endian.  We convert it to host endian before
         * passing it to userspace.
         */
        if (LOV_MAGIC != cpu_to_le32(LOV_MAGIC)) {
                /* if function called for directory - we should
                 * avoid swab not existent lsm objects */
                if ((lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V1)) ||
                    (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3))) {
                        lustre_swab_lov_user_md((struct lov_user_md*)lmm);
                        if (S_ISREG(body->mode))
                                lustre_swab_lov_user_md_objects(
                                                (struct lov_user_md*)lmm);
                } else if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_JOIN)) {
                        lustre_swab_lov_user_md_join((struct lov_user_md_join *)lmm);
                }
        }

        if (lmm->lmm_magic == LOV_MAGIC_JOIN) {
                struct lov_stripe_md *lsm;
                struct lov_user_md_join *lmj;
                int lmj_size, i, aindex = 0;

                rc = obd_unpackmd(sbi->ll_osc_exp, &lsm, lmm, lmmsize);
                if (rc < 0)
                        GOTO(out, rc = -ENOMEM);
                rc = obd_checkmd(sbi->ll_osc_exp, sbi->ll_mdc_exp, lsm);
                if (rc)
                        GOTO(out_free_memmd, rc);

                lmj_size = sizeof(struct lov_user_md_join) +
                        lsm->lsm_stripe_count *
                        sizeof(struct lov_user_ost_data_join);
                OBD_ALLOC(lmj, lmj_size);
                if (!lmj)
                        GOTO(out_free_memmd, rc = -ENOMEM);

                memcpy(lmj, lmm, sizeof(struct lov_user_md_join));
                for (i = 0; i < lsm->lsm_stripe_count; i++) {
                        struct lov_extent *lex =
                                &lsm->lsm_array->lai_ext_array[aindex];

                        if (lex->le_loi_idx + lex->le_stripe_count <= i)
                                aindex ++;
                        CDEBUG(D_INFO, "aindex %d i %d l_extent_start "
                                        LPU64" len %d\n", aindex, i,
                                        lex->le_start, (int)lex->le_len);
                        lmj->lmm_objects[i].l_extent_start =
                                lex->le_start;

                        if ((int)lex->le_len == -1)
                                lmj->lmm_objects[i].l_extent_end = -1;
                        else
                                lmj->lmm_objects[i].l_extent_end =
                                        lex->le_start + lex->le_len;
                        lmj->lmm_objects[i].l_object_id =
                                lsm->lsm_oinfo[i]->loi_id;
                        lmj->lmm_objects[i].l_object_gr =
                                lsm->lsm_oinfo[i]->loi_gr;
                        lmj->lmm_objects[i].l_ost_gen =
                                lsm->lsm_oinfo[i]->loi_ost_gen;
                        lmj->lmm_objects[i].l_ost_idx =
                                lsm->lsm_oinfo[i]->loi_ost_idx;
                }
                lmm = (struct lov_mds_md *)lmj;
                lmmsize = lmj_size;
out_free_memmd:
                obd_free_memmd(sbi->ll_osc_exp, &lsm);
        }
out:
        *lmmp = lmm;
        *lmm_size = lmmsize;
        *request = req;
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

        if (!cfs_capable(CFS_CAP_SYS_ADMIN))
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
        struct lov_user_md_v3 lumv3;
        struct lov_user_md_v1 *lumv1 = (struct lov_user_md_v1 *)&lumv3;
        struct lov_user_md_v1 *lumv1p = (struct lov_user_md_v1 *)arg;
        struct lov_user_md_v3 *lumv3p = (struct lov_user_md_v3 *)arg;
        int lum_size;
        int rc;
        int flags = FMODE_WRITE;
        ENTRY;

        /* first try with v1 which is smaller than v3 */
        lum_size = sizeof(struct lov_user_md_v1);
        rc = copy_from_user(lumv1, lumv1p, lum_size);
        if (rc)
                RETURN(-EFAULT);

        if (lumv1->lmm_magic == LOV_USER_MAGIC_V3) {
                lum_size = sizeof(struct lov_user_md_v3);
                rc = copy_from_user(&lumv3, lumv3p, lum_size);
                if (rc)
                        RETURN(-EFAULT);
        }

        rc = ll_lov_setstripe_ea_info(inode, file, flags, lumv1, lum_size);
        if (rc == 0) {
                 put_user(0, &lumv1p->lmm_stripe_count);
                 rc = obd_iocontrol(LL_IOC_LOV_GETSTRIPE, ll_i2obdexp(inode),
                                    0, ll_i2info(inode)->lli_smd,
                                    (void *)arg);
        }
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

#if LUSTRE_FIX >= 50
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
        if (i_size_read(head) % JOIN_FILE_ALIGN) {
                CERROR("hsize %llu must be times of 64K\n", i_size_read(head));
                RETURN(-EINVAL);
        }
        RETURN(0);
}

static int join_file(struct inode *head_inode, struct file *head_filp,
                     struct file *tail_filp)
{
        struct dentry *tail_dentry = tail_filp->f_dentry;
        struct lookup_intent oit = {.it_op = IT_OPEN,
                                    .it_flags = head_filp->f_flags,
                                    .it_create_mode = M_JOIN_FILE};
        struct ldlm_enqueue_info einfo = { LDLM_IBITS, LCK_PW,
                ll_mdc_blocking_ast, ldlm_completion_ast, NULL, NULL };

        struct lustre_handle lockh;
        struct mdc_op_data *op_data;
        int    rc;
        loff_t data;
        ENTRY;

        tail_dentry = tail_filp->f_dentry;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL) {
                RETURN(-ENOMEM);
        }

        data = i_size_read(head_inode);
        ll_prepare_mdc_op_data(op_data, head_inode,
                               tail_dentry->d_parent->d_inode,
                               tail_dentry->d_name.name,
                               tail_dentry->d_name.len, 0, &data);
        rc = mdc_enqueue(ll_i2mdcexp(head_inode), &einfo, &oit,
                         op_data, &lockh, NULL, 0, 0);

        if (rc < 0)
                GOTO(out, rc);

        rc = oit.d.lustre.it_status;

        if (rc < 0 || it_open_error(DISP_OPEN_OPEN, &oit)) {
                rc = rc ? rc : it_open_error(DISP_OPEN_OPEN, &oit);
                ptlrpc_req_finished((struct ptlrpc_request *)
                                    oit.d.lustre.it_data);
                GOTO(out, rc);
        }

        if (oit.d.lustre.it_lock_mode) { /* If we got lock - release it right
                                           * away */
                ldlm_lock_decref(&lockh, oit.d.lustre.it_lock_mode);
                oit.d.lustre.it_lock_mode = 0;
        }
        ptlrpc_req_finished((struct ptlrpc_request *) oit.d.lustre.it_data);
        it_clear_disposition(&oit, DISP_ENQ_COMPLETE);
        ll_release_openhandle(head_filp->f_dentry, &oit);
out:
        if (op_data)
                OBD_FREE_PTR(op_data);
        ll_intent_release(&oit);
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
        struct ll_inode_info *hlli = ll_i2info(head);
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
                obd_cancel_unused(ll_i2obdexp(second),
                                  ll_i2info(second)->lli_smd, 0, NULL);
        case 2:
                ll_tree_unlock(&first_tree);
                obd_cancel_unused(ll_i2obdexp(first),
                                  ll_i2info(first)->lli_smd, 0, NULL);
        case 1:
                filp_close(tail_filp, 0);
                if (tail)
                        iput(tail);
                if (head && rc == 0) {
                        obd_free_memmd(ll_i2sbi(head)->ll_osc_exp,
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
#endif  /* LUSTRE_FIX >= 50 */

/**
 * Close inode open handle
 *
 * \param dentry [in]     dentry which contains the inode
 * \param it     [in,out] intent which contains open info and result
 *
 * \retval 0     success
 * \retval <0    failure
 */
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

        LASSERT(it_open_error(DISP_OPEN_OPEN, it) == 0);

        OBD_ALLOC(och, sizeof(*och));
        if (!och)
                GOTO(out, rc = -ENOMEM);

        ll_och_fill(ll_i2info(inode), it, och);

        rc = ll_close_inode_openhandle(inode, och);

        OBD_FREE(och, sizeof(*och));
 out:
        /* this one is in place of ll_file_open */
        if (it_disposition(it, DISP_ENQ_OPEN_REF)) {
                ptlrpc_req_finished(it->d.lustre.it_data);
                it_clear_disposition(it, DISP_ENQ_OPEN_REF);
        }
        RETURN(rc);
}

int ll_do_fiemap(struct inode *inode, struct ll_user_fiemap *fiemap,
              int num_bytes)
{
        struct obd_export *exp = ll_i2obdexp(inode);
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ll_fiemap_info_key fm_key = { .name = KEY_FIEMAP, };
        int vallen = num_bytes;
        int rc;
        ENTRY;

        /* Checks for fiemap flags */
        if (fiemap->fm_flags & ~LUSTRE_FIEMAP_FLAGS_COMPAT) {
                fiemap->fm_flags &= ~LUSTRE_FIEMAP_FLAGS_COMPAT;
                return -EBADR;
        }

        /* Check for FIEMAP_FLAG_SYNC */
        if (fiemap->fm_flags & FIEMAP_FLAG_SYNC) {
                rc = filemap_fdatawrite(inode->i_mapping);
                if (rc)
                        return rc;
        }

        /* If the stripe_count > 1 and the application does not understand
         * DEVICE_ORDER flag, then it cannot interpret the extents correctly.
         */
        if (lsm->lsm_stripe_count > 1 &&
            !(fiemap->fm_flags & FIEMAP_FLAG_DEVICE_ORDER))
                return -EOPNOTSUPP;

        fm_key.oa.o_id = lsm->lsm_object_id;
        fm_key.oa.o_valid = OBD_MD_FLID;

        obdo_from_inode(&fm_key.oa, inode, OBD_MD_FLFID | OBD_MD_FLSIZE);

        /* If filesize is 0, then there would be no objects for mapping */
        if (fm_key.oa.o_size == 0) {
                fiemap->fm_mapped_extents = 0;
                RETURN(0);
        }

        memcpy(&fm_key.fiemap, fiemap, sizeof(*fiemap));

        rc = obd_get_info(exp, sizeof(fm_key), &fm_key, &vallen, fiemap, lsm);
        if (rc)
                CERROR("obd_get_info failed: rc = %d\n", rc);

        RETURN(rc);
}

static int ll_ioctl_fiemap(struct inode *inode, unsigned long arg)
{
        struct ll_user_fiemap *fiemap_s;
        size_t num_bytes, ret_bytes;
        unsigned int extent_count;
        int rc = 0;

        /* Get the extent count so we can calculate the size of
         * required fiemap buffer */
        if (get_user(extent_count,
            &((struct ll_user_fiemap __user *)arg)->fm_extent_count))
                RETURN(-EFAULT);
        num_bytes = sizeof(*fiemap_s) + (extent_count *
                                         sizeof(struct ll_fiemap_extent));

        OBD_VMALLOC(fiemap_s, num_bytes);
        if (fiemap_s == NULL)
                RETURN(-ENOMEM);

        /* get the fiemap value */
        if (copy_from_user(fiemap_s,(struct ll_user_fiemap __user *)arg,
                           sizeof(*fiemap_s)))
                GOTO(error, rc = -EFAULT);

        /* If fm_extent_count is non-zero, read the first extent since
         * it is used to calculate end_offset and device from previous
         * fiemap call. */
        if (extent_count) {
                if (copy_from_user(&fiemap_s->fm_extents[0],
                    (char __user *)arg + sizeof(*fiemap_s),
                    sizeof(struct ll_fiemap_extent)))
                        GOTO(error, rc = -EFAULT);
        }

        rc = ll_do_fiemap(inode, fiemap_s, num_bytes);
        if (rc)
                GOTO(error, rc);

        ret_bytes = sizeof(struct ll_user_fiemap);

        if (extent_count != 0)
                ret_bytes += (fiemap_s->fm_mapped_extents *
                                 sizeof(struct ll_fiemap_extent));

        if (copy_to_user((void *)arg, fiemap_s, ret_bytes))
                rc = -EFAULT;

error:
        OBD_VFREE(fiemap_s, num_bytes);
        RETURN(rc);
}

#ifdef HAVE_UNLOCKED_IOCTL
long ll_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        struct inode *inode = file->f_dentry->d_inode;
#else
int ll_file_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                  unsigned long arg)
{
#endif
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        int flags;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),cmd=%x\n", inode->i_ino,
               inode->i_generation, inode, cmd);
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_IOCTL, 1);

        /* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
        if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
                RETURN(-ENOTTY);

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
                RETURN(ll_lov_recreate_obj(inode, arg));
        case LL_IOC_RECREATE_FID:
                RETURN(ll_lov_recreate_fid(inode, arg));
        case FSFILT_IOC_FIEMAP:
                RETURN(ll_ioctl_fiemap(inode, arg));
        case FSFILT_IOC_GETFLAGS:
        case FSFILT_IOC_SETFLAGS:
                RETURN(ll_iocontrol(inode, file, cmd, arg));
        case FSFILT_IOC_GETVERSION_OLD:
        case FSFILT_IOC_GETVERSION:
                RETURN(put_user(inode->i_generation, (int *)arg));
        case LL_IOC_JOIN: {
#if LUSTRE_FIX >= 50
                /* Allow file join in beta builds to allow debuggging */
                char *ftail;
                int rc;

                ftail = getname((const char *)arg);
                if (IS_ERR(ftail))
                        RETURN(PTR_ERR(ftail));
                rc = ll_file_join(inode, file, ftail);
                putname(ftail);
                RETURN(rc);
#else
                CWARN("file join is not supported in this version of Lustre\n");
                RETURN(-ENOTTY);
#endif
        }
        case LL_IOC_GROUP_LOCK:
                RETURN(ll_get_grouplock(inode, file, arg));
        case LL_IOC_GROUP_UNLOCK:
                RETURN(ll_put_grouplock(inode, file, arg));
        case IOC_OBD_STATFS:
                RETURN(ll_obd_statfs(inode, (void *)arg));
        case OBD_IOC_GETNAME_OLD:
        case OBD_IOC_GETNAME: {
                struct obd_device *obd =
                        class_exp2obd(ll_i2sbi(inode)->ll_osc_exp);
                if (!obd)
                        RETURN(-EFAULT);
                if (copy_to_user((void *)arg, obd->obd_name,
                                strlen(obd->obd_name) + 1))
                        RETURN (-EFAULT);
                RETURN(0);
        }
        case LL_IOC_PATH2FID: {
                if (copy_to_user((void *)arg, ll_inode_lu_fid(inode),
                                 sizeof(struct lu_fid)))
                        RETURN(-EFAULT);

                RETURN(0);
        }

        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT3_IOC_SETVERSION_OLD:
        case EXT3_IOC_SETVERSION:
        */
        default: {
                int err;

                if (LLIOC_STOP ==
                    ll_iocontrol_call(inode, file, cmd, arg, &err))
                        RETURN(err);

                RETURN(obd_iocontrol(cmd, ll_i2obdexp(inode), 0, NULL,
                                     (void *)arg));
        }
        }
}

loff_t ll_file_seek(struct file *file, loff_t offset, int origin)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        loff_t retval;
        ENTRY;
        retval = offset + ((origin == 2) ? i_size_read(inode) :
                           (origin == 1) ? file->f_pos : 0);
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), to=%Lu=%#Lx(%s)\n",
               inode->i_ino, inode->i_generation, inode, retval, retval,
               origin == 2 ? "SEEK_END": origin == 1 ? "SEEK_CUR" : "SEEK_SET");
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LLSEEK, 1);

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
                offset += i_size_read(inode);
                ll_inode_size_unlock(inode, 0);
        } else if (origin == 1) { /* SEEK_CUR */
                offset += file->f_pos;
        }

        retval = -EINVAL;
        if (offset >= 0 && offset <= ll_file_maxbytes(inode)) {
                if (offset != file->f_pos) {
                        file->f_pos = offset;
                        file->f_version = 0;
                }
                retval = offset;
        }

        RETURN(retval);
}

#ifdef HAVE_FLUSH_OWNER_ID
int ll_flush(struct file *file, fl_owner_t id)
#else
int ll_flush(struct file *file)
#endif
{
	struct inode *inode = file->f_dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lov_stripe_md *lsm = lli->lli_smd;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	int rc, err;

	/* catch async errors that were recorded back when async writeback
	 * failed for pages in this mapping. */
	rc = lli->lli_async_rc;
	lli->lli_async_rc = 0;
	if (lsm) {
		err = lov_test_and_clear_async_rc(lsm);
		if (rc == 0)
			rc = err;
	}

	/* The application has been told write failure already.
	 * Do not report failure again. */
	if (fd->fd_write_failed)
		return 0;
	return rc ? -EIO : 0;
}

int ll_fsync(struct file *file, struct dentry *dentry, int data)
{
        struct inode *inode = dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_fid fid;
        struct ptlrpc_request *req;
        int rc, err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FSYNC, 1);

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

        ll_inode2fid(&fid, inode);
        err = mdc_sync(ll_i2sbi(inode)->ll_mdc_exp, &fid, &req);
        if (!rc)
                rc = err;
        if (!err)
                ptlrpc_req_finished(req);

        if (data && lsm) {
                struct obd_info *oinfo;
		struct ll_file_data *fd = LUSTRE_FPRIVATE(file);

                OBD_ALLOC_PTR(oinfo);
                if (!oinfo)
                        RETURN(rc ? rc : -ENOMEM);
                OBDO_ALLOC(oinfo->oi_oa);
                if (!oinfo->oi_oa) {
                        OBD_FREE_PTR(oinfo);
                        RETURN(rc ? rc : -ENOMEM);
                }
                oinfo->oi_oa->o_id = lsm->lsm_object_id;
                oinfo->oi_oa->o_gr = lsm->lsm_object_gr;
                oinfo->oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
                obdo_from_inode(oinfo->oi_oa, inode,
                                OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                oinfo->oi_md = lsm;
                err = obd_sync_rqset(ll_i2sbi(inode)->ll_osc_exp, oinfo,
                                     0, OBD_OBJECT_EOF);
                if (!rc)
                        rc = err;
                OBDO_FREE(oinfo->oi_oa);
                OBD_FREE_PTR(oinfo);
		if (rc < 0)
			fd->fd_write_failed = true;
		else
			fd->fd_write_failed = false;
        }

        RETURN(rc);
}

int ll_file_flock(struct file *file, int cmd, struct file_lock *file_lock)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lu_fid *fid = ll_inode_lu_fid(inode);
        struct ldlm_res_id res_id =
                    { .name = { fid_seq(fid),
                                fid_oid(fid),
                                fid_ver(fid),
                                LDLM_FLOCK} };
        struct ldlm_enqueue_info einfo = { LDLM_FLOCK, 0, NULL,
                ldlm_flock_completion_ast, NULL, file_lock };
        struct lustre_handle lockh = {0};
        ldlm_policy_data_t flock;
        int flags = 0;
        int rc, rc2 = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu file_lock=%p\n",
               inode->i_ino, file_lock);
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FLOCK, 1);

        if (fid_is_igif(fid)) {
                /* If this is an IGIF inode, we need to keep the 1.6-style
                 * flock mapping for compatibility.  If it is a proper FID
                 * then we know any other client accessing it must also be
                 * accessing it as a FID and can use the CMD-style flock. */
                res_id.name[2] = LDLM_FLOCK;
                res_id.name[3] = 0;
        }

        if (file_lock->fl_flags & FL_FLOCK) {
                LASSERT((cmd == F_SETLKW) || (cmd == F_SETLK));
                /* set missing params for flock() calls */
                file_lock->fl_end = OFFSET_MAX;
                file_lock->fl_pid = current->tgid;
        }
        flock.l_flock.pid = file_lock->fl_pid;
        flock.l_flock.start = file_lock->fl_start;
        flock.l_flock.end = file_lock->fl_end;

        switch (file_lock->fl_type) {
        case F_RDLCK:
                einfo.ei_mode = LCK_PR;
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
                einfo.ei_mode = LCK_NL;
                break;
        case F_WRLCK:
                einfo.ei_mode = LCK_PW;
                break;
        default:
                CERROR("unknown fcntl lock type: %d\n", file_lock->fl_type);
                RETURN (-EINVAL);
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
                file_lock->fl_type = einfo.ei_mode;
                break;
        default:
                CERROR("unknown fcntl lock command: %d\n", cmd);
                RETURN (-EINVAL);
        }

        CDEBUG(D_DLMTRACE, "inode=%lu, pid=%u, flags=%#x, mode=%u, "
               "start="LPU64", end="LPU64"\n", inode->i_ino, flock.l_flock.pid,
               flags, einfo.ei_mode, flock.l_flock.start, flock.l_flock.end);

        rc = ldlm_cli_enqueue(sbi->ll_mdc_exp, NULL, &einfo, res_id,
                              &flock, &flags, NULL, 0, NULL, &lockh, 0);
        if ((file_lock->fl_flags & FL_FLOCK) &&
            (rc == 0 || file_lock->fl_type == F_UNLCK))
                rc2 = ll_flock_lock_file_wait(file, file_lock, (cmd == F_SETLKW));
#ifdef HAVE_F_OP_FLOCK
        if ((file_lock->fl_flags & FL_POSIX) &&
            (rc == 0 || file_lock->fl_type == F_UNLCK) &&
            !(flags & LDLM_FL_TEST_LOCK))
                rc2 = posix_lock_file_wait(file, file_lock);
#endif

        RETURN(rc ? rc : rc2);
}

int ll_file_noflock(struct file *file, int cmd, struct file_lock *file_lock)
{
        ENTRY;

        RETURN(-ENOSYS);
}

int ll_have_md_lock(struct inode *inode, __u64 bits, ldlm_mode_t l_req_mode)
{
        struct lustre_handle lockh;
        struct ldlm_res_id res_id;
        struct obd_device *obddev;
        ldlm_policy_data_t policy = { .l_inodebits = {bits}};
        ldlm_mode_t mode = (l_req_mode == LCK_MINMODE) ?
                                (LCK_CR|LCK_CW|LCK_PR|LCK_PW) : l_req_mode;
        int flags;
        ENTRY;

        if (!inode)
               RETURN(0);

        obddev = ll_i2mdcexp(inode)->exp_obd;
        fid_build_reg_res_name(ll_inode_lu_fid(inode), &res_id);

        CDEBUG(D_INFO, "trying to match res "LPU64":"LPU64":"LPU64" mode %s\n",
                res_id.name[0],
                res_id.name[1],
                res_id.name[2],
                ldlm_lockname[mode]);

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
        if (ldlm_lock_match(obddev->obd_namespace, flags, &res_id, LDLM_IBITS,
                            &policy, mode, &lockh)) {
                RETURN(1);
        }

        RETURN(0);
}

static int ll_inode_revalidate_fini(struct inode *inode, int rc) {
        if (rc == -ENOENT) { /* Already unlinked. Just update nlink
                              * and return success */
                inode->i_nlink = 0;
                /* This path cannot be hit for regular files unless in
                 * case of obscure races, so no need to to validate
                 * size. */
                if (!S_ISREG(inode->i_mode) &&
                    !S_ISDIR(inode->i_mode))
                        return 0;
        }

        if (rc) {
                CERROR("failure %d inode %lu\n", rc, inode->i_ino);
                return -abs(rc);

        }

        return 0;
}

int __ll_inode_revalidate_it(struct dentry *dentry, struct lookup_intent *it,
                             __u64 ibits)
{
        struct inode *inode = dentry->d_inode;
        struct ptlrpc_request *req = NULL;
        struct obd_export *exp;
        int rc = 0;
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),name=%s\n",
               inode->i_ino, inode->i_generation, inode, dentry->d_name.name);

        exp = ll_i2mdcexp(inode);

        if (exp->exp_connect_flags & OBD_CONNECT_ATTRFID) {
                struct lookup_intent oit = { .it_op = IT_GETATTR };
                struct mdc_op_data op_data = { { 0 } };

                /* Call getattr by fid, so do not provide name at all. */
                ll_prepare_mdc_op_data(&op_data, dentry->d_parent->d_inode,
                                       dentry->d_inode, NULL, 0, 0, NULL);
                oit.it_create_mode |= M_CHECK_STALE;
                rc = mdc_intent_lock(exp, &op_data, NULL, 0,
                                     /* we are not interested in name
                                        based lookup */
                                     &oit, 0, &req,
                                     ll_mdc_blocking_ast, 0);
                oit.it_create_mode &= ~M_CHECK_STALE;
                if (rc < 0) {
                        rc = ll_inode_revalidate_fini(inode, rc);
                        GOTO (out, rc);
                }

                rc = revalidate_it_finish(req, DLM_REPLY_REC_OFF, &oit, dentry);
                if (rc != 0) {
                        ll_intent_release(&oit);
                        GOTO(out, rc);
                }

                /* Unlinked? Unhash dentry, so it is not picked up later by
                   do_lookup() -> ll_revalidate_it(). We cannot use d_drop
                   here to preserve get_cwd functionality on 2.6.
                   Bug 10503 */
                if (!dentry->d_inode->i_nlink) {
                        spin_lock(&ll_lookup_lock);
                        spin_lock(&dcache_lock);
                        ll_drop_dentry(dentry);
                        spin_unlock(&dcache_lock);
                        spin_unlock(&ll_lookup_lock);
                }

                ll_lookup_finish_locks(&oit, dentry);
        } else if (!ll_have_md_lock(dentry->d_inode, ibits, LCK_MINMODE)) {
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                struct ll_fid fid;
                obd_valid valid = OBD_MD_FLGETATTR;
                int ealen = 0;

                if (S_ISREG(inode->i_mode)) {
                        rc = ll_get_max_mdsize(sbi, &ealen);
                        if (rc)
                                RETURN(rc);
                        valid |= OBD_MD_FLEASIZE | OBD_MD_FLMODEASIZE;
                }
                ll_inode2fid(&fid, inode);
                rc = mdc_getattr(sbi->ll_mdc_exp, &fid, valid, ealen, &req);
                if (rc) {
                        rc = ll_inode_revalidate_fini(inode, rc);
                        RETURN(rc);
                }

                rc = ll_prep_inode(sbi->ll_osc_exp, &inode, req, REPLY_REC_OFF,
                                   NULL);
        }

out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int ll_inode_revalidate_it(struct dentry *dentry, struct lookup_intent *it)
{
        struct inode *inode = dentry->d_inode;
        int rc;
        ENTRY;

        rc = __ll_inode_revalidate_it(dentry, it, MDS_INODELOCK_UPDATE |
                                                  MDS_INODELOCK_LOOKUP);

        /* if object not yet allocated, don't validate size */
        if (rc == 0 && ll_i2info(inode)->lli_smd == NULL) {
                LTIME_S(inode->i_atime) = ll_i2info(inode)->lli_lvb.lvb_atime;
                LTIME_S(inode->i_mtime) = ll_i2info(inode)->lli_lvb.lvb_mtime;
                LTIME_S(inode->i_ctime) = ll_i2info(inode)->lli_lvb.lvb_ctime;
                RETURN(0);
        }

        /* ll_glimpse_size will prefer locally cached writes if they extend
         * the file */

        if (rc == 0)
                rc = ll_glimpse_size(inode, 0);

        RETURN(rc);
}

int ll_getattr_it(struct vfsmount *mnt, struct dentry *de,
                  struct lookup_intent *it, struct kstat *stat)
{
        struct inode *inode = de->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ll_inode_info *lli = ll_i2info(inode);
        int res = 0;

        res = ll_inode_revalidate_it(de, it);
        ll_stats_ops_tally(sbi, LPROC_LL_GETATTR, 1);

        if (res)
                return res;

        stat->dev = inode->i_sb->s_dev;
        if (ll_need_32bit_api(sbi))
                stat->ino = ll_fid_build_ino((struct ll_fid *)&lli->lli_fid, 1);
        else
                stat->ino = inode->i_ino;
        stat->mode = inode->i_mode;
        stat->nlink = inode->i_nlink;
        stat->uid = inode->i_uid;
        stat->gid = inode->i_gid;
        stat->rdev = kdev_t_to_nr(inode->i_rdev);
        stat->atime = inode->i_atime;
        stat->mtime = inode->i_mtime;
        stat->ctime = inode->i_ctime;
#ifdef HAVE_INODE_BLKSIZE
        stat->blksize = inode->i_blksize;
#else
        stat->blksize = 1<<inode->i_blkbits;
#endif

        ll_inode_size_lock(inode, 0);
        stat->size = i_size_read(inode);
        stat->blocks = inode->i_blocks;
        ll_inode_size_unlock(inode, 0);

        return 0;
}
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat)
{
        struct lookup_intent it = { .it_op = IT_GETATTR };

        return ll_getattr_it(mnt, de, &it, stat);
}

#ifdef HAVE_LINUX_FIEMAP_H
int ll_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
                __u64 start, __u64 len)
{
        int rc;
        size_t num_bytes;
        struct ll_user_fiemap *fiemap;
        unsigned int extent_count = fieinfo->fi_extents_max;

        num_bytes = sizeof(*fiemap) + (extent_count *
                                       sizeof(struct ll_fiemap_extent));
        OBD_VMALLOC(fiemap, num_bytes);

        if (fiemap == NULL)
                RETURN(-ENOMEM);

        fiemap->fm_flags = fieinfo->fi_flags;
        fiemap->fm_extent_count = fieinfo->fi_extents_max;
        fiemap->fm_start = start;
        fiemap->fm_length = len;
        memcpy(&fiemap->fm_extents[0], fieinfo->fi_extents_start,
               sizeof(struct ll_fiemap_extent));

        rc = ll_do_fiemap(inode, fiemap, num_bytes);

        fieinfo->fi_flags = fiemap->fm_flags;
        fieinfo->fi_extents_mapped = fiemap->fm_mapped_extents;
        memcpy(fieinfo->fi_extents_start, &fiemap->fm_extents[0],
               fiemap->fm_mapped_extents * sizeof(struct ll_fiemap_extent));

        OBD_VFREE(fiemap, num_bytes);
        return rc;
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
#ifndef HAVE_INODE_PERMISION_2ARGS
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
#else
int ll_inode_permission(struct inode *inode, int mask)
#endif
{
        int rc = 0;
        ENTRY;

       /* as root inode are NOT getting validated in lookup operation,
        * need to do it before permission check. */

        if (inode == inode->i_sb->s_root->d_inode) {
                struct lookup_intent it = { .it_op = IT_LOOKUP };

                rc = __ll_inode_revalidate_it(inode->i_sb->s_root, &it,
                                              MDS_INODELOCK_LOOKUP);
                if (rc)
                        RETURN(rc);
        }

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), inode mode %x mask %o\n",
               inode->i_ino, inode->i_generation, inode, inode->i_mode, mask);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_INODE_PERM, 1);
        rc = generic_permission(inode, mask, lustre_check_acl);

        RETURN(rc);
}
#else
#ifndef HAVE_INODE_PERMISION_2ARGS
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
#else
int ll_inode_permission(struct inode *inode, int mask)
#endif
{
        int mode = inode->i_mode;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), mask %o\n",
               inode->i_ino, inode->i_generation, inode, mask);
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_INODE_PERM, 1);

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
                if (cfs_capable(CFS_CAP_DAC_OVERRIDE))
                        return 0;

        if (cfs_capable(CFS_CAP_DAC_READ_SEARCH) && ((mask == MAY_READ) ||
            (S_ISDIR(inode->i_mode) && !(mask & MAY_WRITE))))
                return 0;

        return -EACCES;
}
#endif

/* -o localflock - only provides locally consistent flock locks */
struct file_operations ll_file_operations = {
        .read           = ll_file_read,
#ifdef HAVE_FILE_READV
        .readv          = ll_file_readv,
#else
        .aio_read       = ll_file_aio_read,
#endif
        .write          = ll_file_write,
#ifdef HAVE_FILE_WRITEV
        .writev         = ll_file_writev,
#else
        .aio_write      = ll_file_aio_write,
#endif
#ifdef HAVE_UNLOCKED_IOCTL
        .unlocked_ioctl = ll_file_ioctl,
#else
        .ioctl          = ll_file_ioctl,
#endif
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#ifdef HAVE_KERNEL_SPLICE_READ
        .splice_read    = ll_file_splice_read,
#endif
#ifdef HAVE_KERNEL_SENDFILE
        .sendfile       = ll_file_sendfile,
#endif
        .fsync          = ll_fsync,
        .flush          = ll_flush
};

struct file_operations ll_file_operations_flock = {
        .read           = ll_file_read,
#ifdef HAVE_FILE_READV
        .readv          = ll_file_readv,
#else
        .aio_read       = ll_file_aio_read,
#endif
        .write          = ll_file_write,
#ifdef HAVE_FILE_WRITEV
        .writev         = ll_file_writev,
#else
        .aio_write      = ll_file_aio_write,
#endif
#ifdef HAVE_UNLOCKED_IOCTL
        .unlocked_ioctl = ll_file_ioctl,
#else
        .ioctl          = ll_file_ioctl,
#endif
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#ifdef HAVE_KERNEL_SPLICE_READ
        .splice_read    = ll_file_splice_read,
#endif
#ifdef HAVE_KERNEL_SENDFILE
        .sendfile       = ll_file_sendfile,
#endif
        .fsync          = ll_fsync,
        .flush          = ll_flush,
#ifdef HAVE_F_OP_FLOCK
        .flock          = ll_file_flock,
#endif
        .lock           = ll_file_flock
};

/* These are for -o noflock - to return ENOSYS on flock calls */
struct file_operations ll_file_operations_noflock = {
        .read           = ll_file_read,
#ifdef HAVE_FILE_READV
        .readv          = ll_file_readv,
#else
        .aio_read       = ll_file_aio_read,
#endif
        .write          = ll_file_write,
#ifdef HAVE_FILE_WRITEV
        .writev         = ll_file_writev,
#else
        .aio_write      = ll_file_aio_write,
#endif
#ifdef HAVE_UNLOCKED_IOCTL
        .unlocked_ioctl = ll_file_ioctl,
#else
        .ioctl          = ll_file_ioctl,
#endif
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#ifdef HAVE_KERNEL_SPLICE_READ
        .splice_read    = ll_file_splice_read,
#endif
#ifdef HAVE_KERNEL_SENDFILE
        .sendfile       = ll_file_sendfile,
#endif
        .fsync          = ll_fsync,
        .flush          = ll_flush,
#ifdef HAVE_F_OP_FLOCK
        .flock          = ll_file_noflock,
#endif
        .lock           = ll_file_noflock
};

struct inode_operations ll_file_inode_operations = {
#ifdef HAVE_VFS_INTENT_PATCHES
        .setattr_raw    = ll_setattr_raw,
#endif
        .setattr        = ll_setattr,
        .truncate       = ll_truncate,
        .getattr        = ll_getattr,
        .permission     = ll_inode_permission,
        .setxattr       = ll_setxattr,
        .getxattr       = ll_getxattr,
        .listxattr      = ll_listxattr,
        .removexattr    = ll_removexattr,
#ifdef  HAVE_LINUX_FIEMAP_H
        .fiemap         = ll_fiemap,
#endif
};

/* dynamic ioctl number support routins */
static struct llioc_ctl_data {
        struct rw_semaphore ioc_sem;
        struct list_head    ioc_head;
} llioc = {
        __RWSEM_INITIALIZER(llioc.ioc_sem),
        CFS_LIST_HEAD_INIT(llioc.ioc_head)
};


struct llioc_data {
        struct list_head        iocd_list;
        unsigned int            iocd_size;
        llioc_callback_t        iocd_cb;
        unsigned int            iocd_count;
        unsigned int            iocd_cmd[0];
};

void *ll_iocontrol_register(llioc_callback_t cb, int count, unsigned int *cmd)
{
        unsigned int size;
        struct llioc_data *in_data = NULL;
        ENTRY;

        if (cb == NULL || cmd == NULL ||
            count > LLIOC_MAX_CMD || count < 0)
                RETURN(NULL);

        size = sizeof(*in_data) + count * sizeof(unsigned int);
        OBD_ALLOC(in_data, size);
        if (in_data == NULL)
                RETURN(NULL);

        memset(in_data, 0, sizeof(*in_data));
        in_data->iocd_size = size;
        in_data->iocd_cb = cb;
        in_data->iocd_count = count;
        memcpy(in_data->iocd_cmd, cmd, sizeof(unsigned int) * count);

        down_write(&llioc.ioc_sem);
        list_add_tail(&in_data->iocd_list, &llioc.ioc_head);
        up_write(&llioc.ioc_sem);

        RETURN(in_data);
}

void ll_iocontrol_unregister(void *magic)
{
        struct llioc_data *tmp;

        if (magic == NULL)
                return;

        down_write(&llioc.ioc_sem);
        list_for_each_entry(tmp, &llioc.ioc_head, iocd_list) {
                if (tmp == magic) {
                        unsigned int size = tmp->iocd_size;

                        list_del(&tmp->iocd_list);
                        up_write(&llioc.ioc_sem);

                        OBD_FREE(tmp, size);
                        return;
                }
        }
        up_write(&llioc.ioc_sem);

        CWARN("didn't find iocontrol register block with magic: %p\n", magic);
}

EXPORT_SYMBOL(ll_iocontrol_register);
EXPORT_SYMBOL(ll_iocontrol_unregister);

enum llioc_iter ll_iocontrol_call(struct inode *inode, struct file *file,
                        unsigned int cmd, unsigned long arg, int *rcp)
{
        enum llioc_iter ret = LLIOC_CONT;
        struct llioc_data *data;
        int rc = -EINVAL, i;

        down_read(&llioc.ioc_sem);
        list_for_each_entry(data, &llioc.ioc_head, iocd_list) {
                for (i = 0; i < data->iocd_count; i++) {
                        if (cmd != data->iocd_cmd[i])
                                continue;

                        ret = data->iocd_cb(inode, file, cmd, arg, data, &rc);
                        break;
                }

                if (ret == LLIOC_STOP)
                        break;
        }
        up_read(&llioc.ioc_sem);

        if (rcp)
                *rcp = rc;
        return ret;
}
