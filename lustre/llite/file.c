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
 * lustre/llite/file.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <lustre_dlm.h>
#include <lustre_lite.h>
#include <lustre_mdc.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include "llite_internal.h"
#include <lustre/ll_fiemap.h>

#include "cl_object.h"

struct ll_file_data *ll_file_data_get(void)
{
        struct ll_file_data *fd;

        OBD_SLAB_ALLOC_PTR_GFP(fd, ll_file_data_slab, CFS_ALLOC_IO);
        return fd;
}

static void ll_file_data_put(struct ll_file_data *fd)
{
        if (fd != NULL)
                OBD_SLAB_FREE_PTR(fd, ll_file_data_slab);
}

void ll_pack_inode2opdata(struct inode *inode, struct md_op_data *op_data,
                          struct lustre_handle *fh)
{
        op_data->op_fid1 = ll_i2info(inode)->lli_fid;
        op_data->op_attr.ia_mode = inode->i_mode;
        op_data->op_attr.ia_atime = inode->i_atime;
        op_data->op_attr.ia_mtime = inode->i_mtime;
        op_data->op_attr.ia_ctime = inode->i_ctime;
        op_data->op_attr.ia_size = i_size_read(inode);
        op_data->op_attr_blocks = inode->i_blocks;
        ((struct ll_iattr *)&op_data->op_attr)->ia_attr_flags =
                                        ll_inode_to_ext_flags(inode->i_flags);
        op_data->op_ioepoch = ll_i2info(inode)->lli_ioepoch;
        if (fh)
                op_data->op_handle = *fh;
        op_data->op_capa1 = ll_mdscapa_get(inode);
}

/**
 * Closes the IO epoch and packs all the attributes into @op_data for
 * the CLOSE rpc.
 */
static void ll_prepare_close(struct inode *inode, struct md_op_data *op_data,
                             struct obd_client_handle *och)
{
        ENTRY;

        op_data->op_attr.ia_valid = ATTR_MODE | ATTR_ATIME_SET |
                                 ATTR_MTIME_SET | ATTR_CTIME_SET;

        if (!(och->och_flags & FMODE_WRITE))
                goto out;

        if (!exp_connect_som(ll_i2mdexp(inode)) || !S_ISREG(inode->i_mode))
                op_data->op_attr.ia_valid |= ATTR_SIZE | ATTR_BLOCKS;
        else
                ll_ioepoch_close(inode, op_data, &och, 0);

out:
        ll_pack_inode2opdata(inode, op_data, &och->och_fh);
        ll_prep_md_op_data(op_data, inode, NULL, NULL,
                           0, 0, LUSTRE_OPC_ANY, NULL);
        EXIT;
}

static int ll_close_inode_openhandle(struct obd_export *md_exp,
                                     struct inode *inode,
                                     struct obd_client_handle *och)
{
        struct obd_export *exp = ll_i2mdexp(inode);
        struct md_op_data *op_data;
        struct ptlrpc_request *req = NULL;
        struct obd_device *obd = class_exp2obd(exp);
        int epoch_close = 1;
        int rc;
        ENTRY;

        if (obd == NULL) {
                /*
                 * XXX: in case of LMV, is this correct to access
                 * ->exp_handle?
                 */
                CERROR("Invalid MDC connection handle "LPX64"\n",
                       ll_i2mdexp(inode)->exp_handle.h_cookie);
                GOTO(out, rc = 0);
        }

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                GOTO(out, rc = -ENOMEM); // XXX We leak openhandle and request here.

        ll_prepare_close(inode, op_data, och);
        epoch_close = (op_data->op_flags & MF_EPOCH_CLOSE);
        rc = md_close(md_exp, op_data, och->och_mod, &req);
        if (rc == -EAGAIN) {
                /* This close must have the epoch closed. */
                LASSERT(epoch_close);
                /* MDS has instructed us to obtain Size-on-MDS attribute from
                 * OSTs and send setattr to back to MDS. */
                rc = ll_som_update(inode, op_data);
                if (rc) {
                        CERROR("inode %lu mdc Size-on-MDS update failed: "
                               "rc = %d\n", inode->i_ino, rc);
                        rc = 0;
                }
        } else if (rc) {
                CERROR("inode %lu mdc close failed: rc = %d\n",
                       inode->i_ino, rc);
        }
        ll_finish_md_op_data(op_data);

        if (rc == 0) {
                rc = ll_objects_destroy(req, inode);
                if (rc)
                        CERROR("inode %lu ll_objects destroy: rc = %d\n",
                               inode->i_ino, rc);
        }

        EXIT;
out:

        if (exp_connect_som(exp) && !epoch_close &&
            S_ISREG(inode->i_mode) && (och->och_flags & FMODE_WRITE)) {
                ll_queue_done_writing(inode, LLIF_DONE_WRITING);
        } else {
                md_clear_open_replay_data(md_exp, och);
                /* Free @och if it is not waiting for DONE_WRITING. */
                och->och_fh.cookie = DEAD_HANDLE_MAGIC;
                OBD_FREE_PTR(och);
        }
        if (req) /* This is close request */
                ptlrpc_req_finished(req);
        return rc;
}

int ll_md_real_close(struct inode *inode, int flags)
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
                LASSERT(flags & FMODE_READ);
                och_p = &lli->lli_mds_read_och;
                och_usecount = &lli->lli_open_fd_read_count;
        }

        cfs_down(&lli->lli_och_sem);
        if (*och_usecount) { /* There are still users of this handle, so
                                skip freeing it. */
                cfs_up(&lli->lli_och_sem);
                RETURN(0);
        }
        och=*och_p;
        *och_p = NULL;
        cfs_up(&lli->lli_och_sem);

        if (och) { /* There might be a race and somebody have freed this och
                      already */
                rc = ll_close_inode_openhandle(ll_i2sbi(inode)->ll_md_exp,
                                               inode, och);
        }

        RETURN(rc);
}

int ll_md_close(struct obd_export *md_exp, struct inode *inode,
                struct file *file)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        ENTRY;

        /* clear group lock, if present */
        if (unlikely(fd->fd_flags & LL_FILE_GROUP_LOCKED))
                ll_put_grouplock(inode, file, fd->fd_grouplock.cg_gid);

        /* Let's see if we have good enough OPEN lock on the file and if
           we can skip talking to MDS */
        if (file->f_dentry->d_inode) { /* Can this ever be false? */
                int lockmode;
                int flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_TEST_LOCK;
                struct lustre_handle lockh;
                struct inode *inode = file->f_dentry->d_inode;
                ldlm_policy_data_t policy = {.l_inodebits={MDS_INODELOCK_OPEN}};

                cfs_down(&lli->lli_och_sem);
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
                cfs_up(&lli->lli_och_sem);

                if (!md_lock_match(md_exp, flags, ll_inode2fid(inode),
                                   LDLM_IBITS, &policy, lockmode,
                                   &lockh)) {
                        rc = ll_md_real_close(file->f_dentry->d_inode,
                                              fd->fd_omode);
                }
        } else {
                CERROR("Releasing a file %p with negative dentry %p. Name %s",
                       file, file->f_dentry, file->f_dentry->d_name.name);
        }

        LUSTRE_FPRIVATE(file) = NULL;
        ll_file_data_put(fd);
        ll_capa_close(inode);

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

#ifdef CONFIG_FS_POSIX_ACL
        if (sbi->ll_flags & LL_SBI_RMT_CLIENT &&
            inode == inode->i_sb->s_root->d_inode) {
                struct ll_file_data *fd = LUSTRE_FPRIVATE(file);

                LASSERT(fd != NULL);
                if (unlikely(fd->fd_flags & LL_FILE_RMTACL)) {
                        fd->fd_flags &= ~LL_FILE_RMTACL;
                        rct_del(&sbi->ll_rct, cfs_curproc_pid());
                        et_search_free(&sbi->ll_et, cfs_curproc_pid());
                }
        }
#endif

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

        rc = ll_md_close(sbi->ll_md_exp, inode, file);

        if (CFS_FAIL_TIMEOUT_MS(OBD_FAIL_PTLRPC_DUMP_LOG, cfs_fail_val))
                libcfs_debug_dumplog();

        RETURN(rc);
}

static int ll_intent_file_open(struct file *file, void *lmm,
                               int lmmsize, struct lookup_intent *itp)
{
        struct ll_sb_info *sbi = ll_i2sbi(file->f_dentry->d_inode);
        struct dentry *parent = file->f_dentry->d_parent;
        const char *name = file->f_dentry->d_name.name;
        const int len = file->f_dentry->d_name.len;
        struct md_op_data *op_data;
        struct ptlrpc_request *req;
        int rc;
        ENTRY;

        if (!parent)
                RETURN(-ENOENT);

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

        op_data  = ll_prep_md_op_data(NULL, parent->d_inode,
                                      file->f_dentry->d_inode, name, len,
                                      O_RDWR, LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        rc = md_intent_lock(sbi->ll_md_exp, op_data, lmm, lmmsize, itp,
                            0 /*unused */, &req, ll_md_blocking_ast, 0);
        ll_finish_md_op_data(op_data);
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

        if (rc != 0 || it_open_error(DISP_OPEN_OPEN, itp)) {
                rc = rc ? rc : it_open_error(DISP_OPEN_OPEN, itp);
                CDEBUG(D_VFSTRACE, "lock enqueue: err: %d\n", rc);
                GOTO(out, rc);
        }

        rc = ll_prep_inode(&file->f_dentry->d_inode, req, NULL);
        if (!rc && itp->d.lustre.it_lock_mode)
                md_set_lock_data(sbi->ll_md_exp,
                                 &itp->d.lustre.it_lock_handle,
                                 file->f_dentry->d_inode, NULL);

out:
        ptlrpc_req_finished(itp->d.lustre.it_data);
        it_clear_disposition(itp, DISP_ENQ_COMPLETE);
        ll_intent_drop_lock(itp);

        RETURN(rc);
}

/**
 * Assign an obtained @ioepoch to client's inode. No lock is needed, MDS does
 * not believe attributes if a few ioepoch holders exist. Attributes for
 * previous ioepoch if new one is opened are also skipped by MDS.
 */
void ll_ioepoch_open(struct ll_inode_info *lli, __u64 ioepoch)
{
        if (ioepoch && lli->lli_ioepoch != ioepoch) {
                lli->lli_ioepoch = ioepoch;
                CDEBUG(D_INODE, "Epoch "LPU64" opened on "DFID"\n",
                       ioepoch, PFID(&lli->lli_fid));
        }
}

static int ll_och_fill(struct obd_export *md_exp, struct ll_inode_info *lli,
                       struct lookup_intent *it, struct obd_client_handle *och)
{
        struct ptlrpc_request *req = it->d.lustre.it_data;
        struct mdt_body *body;

        LASSERT(och);

        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);                      /* reply already checked out */

        memcpy(&och->och_fh, &body->handle, sizeof(body->handle));
        och->och_magic = OBD_CLIENT_HANDLE_MAGIC;
        och->och_fid = lli->lli_fid;
        och->och_flags = it->it_flags;
        ll_ioepoch_open(lli, body->ioepoch);

        return md_set_open_replay_data(md_exp, och, req);
}

int ll_local_open(struct file *file, struct lookup_intent *it,
                  struct ll_file_data *fd, struct obd_client_handle *och)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        LASSERT(!LUSTRE_FPRIVATE(file));

        LASSERT(fd != NULL);

        if (och) {
                struct ptlrpc_request *req = it->d.lustre.it_data;
                struct mdt_body *body;
                int rc;

                rc = ll_och_fill(ll_i2sbi(inode)->ll_md_exp, lli, it, och);
                if (rc)
                        RETURN(rc);

                body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
                if ((it->it_flags & FMODE_WRITE) &&
                    (body->valid & OBD_MD_FLSIZE))
                        CDEBUG(D_INODE, "Epoch "LPU64" opened on "DFID"\n",
                               lli->lli_ioepoch, PFID(&lli->lli_fid));
        }

        LUSTRE_FPRIVATE(file) = fd;
        ll_readahead_init(inode, &fd->fd_ras);
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
        struct ptlrpc_request *req = NULL;
        struct obd_client_handle **och_p;
        __u64 *och_usecount;
        struct ll_file_data *fd;
        int rc = 0, opendir_set = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), flags %o\n", inode->i_ino,
               inode->i_generation, inode, file->f_flags);

        it = file->private_data; /* XXX: compat macro */
        file->private_data = NULL; /* prevent ll_local_open assertion */

        fd = ll_file_data_get();
        if (fd == NULL)
                RETURN(-ENOMEM);

        fd->fd_file = file;
        if (S_ISDIR(inode->i_mode)) {
                cfs_spin_lock(&lli->lli_sa_lock);
                if (lli->lli_opendir_key == NULL && lli->lli_opendir_pid == 0) {
                        LASSERT(lli->lli_sai == NULL);
                        lli->lli_opendir_key = fd;
                        lli->lli_opendir_pid = cfs_curproc_pid();
                        opendir_set = 1;
                }
                cfs_spin_unlock(&lli->lli_sa_lock);
        }

        if (inode->i_sb->s_root == file->f_dentry) {
                LUSTRE_FPRIVATE(file) = fd;
                RETURN(0);
        }

        if (!it || !it->d.lustre.it_disposition) {
                /* Convert f_flags into access mode. We cannot use file->f_mode,
                 * because everything but O_ACCMODE mask was stripped from
                 * there */
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

        cfs_down(&lli->lli_och_sem);
        if (*och_p) { /* Open handle is present */
                if (it_disposition(it, DISP_OPEN_OPEN)) {
                        /* Well, there's extra open request that we do not need,
                           let's close it somehow. This will decref request. */
                        rc = it_open_error(DISP_OPEN_OPEN, it);
                        if (rc) {
                                cfs_up(&lli->lli_och_sem);
                                ll_file_data_put(fd);
                                GOTO(out_openerr, rc);
                        }
                        ll_release_openhandle(file->f_dentry, it);
                        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats,
                                             LPROC_LL_OPEN);
                }
                (*och_usecount)++;

                rc = ll_local_open(file, it, fd, NULL);
                if (rc) {
                        (*och_usecount)--;
                        cfs_up(&lli->lli_och_sem);
                        ll_file_data_put(fd);
                        GOTO(out_openerr, rc);
                }
        } else {
                LASSERT(*och_usecount == 0);
                if (!it->d.lustre.it_disposition) {
                        /* We cannot just request lock handle now, new ELC code
                           means that one of other OPEN locks for this file
                           could be cancelled, and since blocking ast handler
                           would attempt to grab och_sem as well, that would
                           result in a deadlock */
                        cfs_up(&lli->lli_och_sem);
                        it->it_create_mode |= M_CHECK_STALE;
                        rc = ll_intent_file_open(file, NULL, 0, it);
                        it->it_create_mode &= ~M_CHECK_STALE;
                        if (rc) {
                                ll_file_data_put(fd);
                                GOTO(out_openerr, rc);
                        }

                        /* Got some error? Release the request */
                        if (it->d.lustre.it_status < 0) {
                                req = it->d.lustre.it_data;
                                ptlrpc_req_finished(req);
                        }
                        goto restart;
                }
                OBD_ALLOC(*och_p, sizeof (struct obd_client_handle));
                if (!*och_p) {
                        ll_file_data_put(fd);
                        GOTO(out_och_free, rc = -ENOMEM);
                }
                (*och_usecount)++;
                req = it->d.lustre.it_data;

                /* md_intent_lock() didn't get a request ref if there was an
                 * open error, so don't do cleanup on the request here
                 * (bug 3430) */
                /* XXX (green): Should not we bail out on any error here, not
                 * just open error? */
                rc = it_open_error(DISP_OPEN_OPEN, it);
                if (rc) {
                        ll_file_data_put(fd);
                        GOTO(out_och_free, rc);
                }

                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_OPEN, 1);
                rc = ll_local_open(file, it, fd, *och_p);
                if (rc) {
                        ll_file_data_put(fd);
                        GOTO(out_och_free, rc);
                }
        }
        cfs_up(&lli->lli_och_sem);

        /* Must do this outside lli_och_sem lock to prevent deadlock where
           different kind of OPEN lock for this same inode gets cancelled
           by ldlm_cancel_lru */
        if (!S_ISREG(inode->i_mode))
                GOTO(out, rc);

        ll_capa_open(inode);

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
        ptlrpc_req_finished(req);
        if (req)
                it_clear_disposition(it, DISP_ENQ_OPEN_REF);
out_och_free:
        if (rc) {
                if (*och_p) {
                        OBD_FREE(*och_p, sizeof (struct obd_client_handle));
                        *och_p = NULL; /* OBD_FREE writes some magic there */
                        (*och_usecount)--;
                }
                cfs_up(&lli->lli_och_sem);
out_openerr:
                if (opendir_set != 0)
                        ll_stop_statahead(inode, lli->lli_opendir_key);
        }

        return rc;
}

/* Fills the obdo with the attributes for the lsm */
static int ll_lsm_getattr(struct lov_stripe_md *lsm, struct obd_export *exp,
                          struct obd_capa *capa, struct obdo *obdo,
                          __u64 ioepoch, int sync)
{
        struct ptlrpc_request_set *set;
        struct obd_info            oinfo = { { { 0 } } };
        int                        rc;

        ENTRY;

        LASSERT(lsm != NULL);

        oinfo.oi_md = lsm;
        oinfo.oi_oa = obdo;
        oinfo.oi_oa->o_id = lsm->lsm_object_id;
        oinfo.oi_oa->o_seq = lsm->lsm_object_seq;
        oinfo.oi_oa->o_mode = S_IFREG;
        oinfo.oi_oa->o_ioepoch = ioepoch;
        oinfo.oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE |
                               OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                               OBD_MD_FLBLKSZ | OBD_MD_FLATIME |
                               OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                               OBD_MD_FLGROUP | OBD_MD_FLEPOCH;
        oinfo.oi_capa = capa;
        if (sync) {
                oinfo.oi_oa->o_valid |= OBD_MD_FLFLAGS;
                oinfo.oi_oa->o_flags |= OBD_FL_SRVLOCK;
        }

        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR("can't allocate ptlrpc set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_getattr_async(exp, &oinfo, set);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                ptlrpc_set_destroy(set);
        }
        if (rc == 0)
                oinfo.oi_oa->o_valid &= (OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ |
                                         OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                         OBD_MD_FLCTIME | OBD_MD_FLSIZE);
        RETURN(rc);
}

/**
  * Performs the getattr on the inode and updates its fields.
  * If @sync != 0, perform the getattr under the server-side lock.
  */
int ll_inode_getattr(struct inode *inode, struct obdo *obdo,
                     __u64 ioepoch, int sync)
{
        struct ll_inode_info *lli  = ll_i2info(inode);
        struct obd_capa      *capa = ll_mdscapa_get(inode);
        int rc;
        ENTRY;

        rc = ll_lsm_getattr(lli->lli_smd, ll_i2dtexp(inode),
                            capa, obdo, ioepoch, sync);
        capa_put(capa);
        if (rc == 0) {
                obdo_refresh_inode(inode, obdo, obdo->o_valid);
                CDEBUG(D_INODE,
                       "objid "LPX64" size %Lu, blocks %llu, blksize %lu\n",
                       lli->lli_smd->lsm_object_id, i_size_read(inode),
                       (unsigned long long)inode->i_blocks,
                       (unsigned long)ll_inode_blksize(inode));
        }
        RETURN(rc);
}

int ll_merge_lvb(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ost_lvb lvb;
        int rc;

        ENTRY;

        ll_inode_size_lock(inode, 1);
        inode_init_lvb(inode, &lvb);

        /* merge timestamps the most resently obtained from mds with
           timestamps obtained from osts */
        lvb.lvb_atime = lli->lli_lvb.lvb_atime;
        lvb.lvb_mtime = lli->lli_lvb.lvb_mtime;
        lvb.lvb_ctime = lli->lli_lvb.lvb_ctime;
        rc = obd_merge_lvb(sbi->ll_dt_exp, lli->lli_smd, &lvb, 0);
        cl_isize_write_nolock(inode, lvb.lvb_size);

        CDEBUG(D_VFSTRACE, DFID" updating i_size "LPU64"\n",
               PFID(&lli->lli_fid), lvb.lvb_size);
        inode->i_blocks = lvb.lvb_blocks;

        LTIME_S(inode->i_mtime) = lvb.lvb_mtime;
        LTIME_S(inode->i_atime) = lvb.lvb_atime;
        LTIME_S(inode->i_ctime) = lvb.lvb_ctime;
        ll_inode_size_unlock(inode, 1);

        RETURN(rc);
}

int ll_glimpse_ioctl(struct ll_sb_info *sbi, struct lov_stripe_md *lsm,
                     lstat_t *st)
{
        struct obdo obdo = { 0 };
        int rc;

        rc = ll_lsm_getattr(lsm, sbi->ll_dt_exp, NULL, &obdo, 0, 0);
        if (rc == 0) {
                st->st_size   = obdo.o_size;
                st->st_blocks = obdo.o_blocks;
                st->st_mtime  = obdo.o_mtime;
                st->st_atime  = obdo.o_atime;
                st->st_ctime  = obdo.o_ctime;
        }
        return rc;
}

void ll_io_init(struct cl_io *io, const struct file *file, int write)
{
        struct inode *inode = file->f_dentry->d_inode;

        io->u.ci_rw.crw_nonblock = file->f_flags & O_NONBLOCK;
        if (write)
                io->u.ci_wr.wr_append = !!(file->f_flags & O_APPEND);
        io->ci_obj     = ll_i2info(inode)->lli_clob;
        io->ci_lockreq = CILR_MAYBE;
        if (ll_file_nolock(file)) {
                io->ci_lockreq = CILR_NEVER;
                io->ci_no_srvlock = 1;
        } else if (file->f_flags & O_APPEND) {
                io->ci_lockreq = CILR_MANDATORY;
        }
}

static ssize_t ll_file_io_generic(const struct lu_env *env,
                struct vvp_io_args *args, struct file *file,
                enum cl_io_type iot, loff_t *ppos, size_t count)
{
        struct ll_inode_info *lli = ll_i2info(file->f_dentry->d_inode);
        struct cl_io         *io;
        ssize_t               result;
        ENTRY;

        io = ccc_env_thread_io(env);
        ll_io_init(io, file, iot == CIT_WRITE);

        if (cl_io_rw_init(env, io, iot, *ppos, count) == 0) {
                struct vvp_io *vio = vvp_env_io(env);
                struct ccc_io *cio = ccc_env_io(env);
                int write_sem_locked = 0;

                cio->cui_fd  = LUSTRE_FPRIVATE(file);
                vio->cui_io_subtype = args->via_io_subtype;

                switch (vio->cui_io_subtype) {
                case IO_NORMAL:
                        cio->cui_iov = args->u.normal.via_iov;
                        cio->cui_nrsegs = args->u.normal.via_nrsegs;
                        cio->cui_tot_nrsegs = cio->cui_nrsegs;
#ifndef HAVE_FILE_WRITEV
                        cio->cui_iocb = args->u.normal.via_iocb;
#endif
                        if ((iot == CIT_WRITE) &&
                            !(cio->cui_fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
                                if(cfs_down_interruptible(&lli->lli_write_sem))
                                        GOTO(out, result = -ERESTARTSYS);
                                write_sem_locked = 1;
                        } else if (iot == CIT_READ) {
                                cfs_down_read(&lli->lli_trunc_sem);
                        }
                        break;
                case IO_SENDFILE:
                        vio->u.sendfile.cui_actor = args->u.sendfile.via_actor;
                        vio->u.sendfile.cui_target = args->u.sendfile.via_target;
                        break;
                case IO_SPLICE:
                        vio->u.splice.cui_pipe = args->u.splice.via_pipe;
                        vio->u.splice.cui_flags = args->u.splice.via_flags;
                        break;
                default:
                        CERROR("Unknow IO type - %u\n", vio->cui_io_subtype);
                        LBUG();
                }
                result = cl_io_loop(env, io);
                if (write_sem_locked)
                        cfs_up(&lli->lli_write_sem);
                else if (args->via_io_subtype == IO_NORMAL && iot == CIT_READ)
                        cfs_up_read(&lli->lli_trunc_sem);
        } else {
                /* cl_io_rw_init() handled IO */
                result = io->ci_result;
        }

        if (io->ci_nob > 0) {
                result = io->ci_nob;
                *ppos = io->u.ci_wr.wr.crw_pos;
        }
        GOTO(out, result);
out:
        cl_io_fini(env, io);
        if (iot == CIT_WRITE)
                lli->lli_write_rc = result < 0 ? : 0;
        return result;
}


/*
 * XXX: exact copy from kernel code (__generic_file_aio_write_nolock)
 */
static int ll_file_get_iov_count(const struct iovec *iov,
                                 unsigned long *nr_segs, size_t *count)
{
        size_t cnt = 0;
        unsigned long seg;

        for (seg = 0; seg < *nr_segs; seg++) {
                const struct iovec *iv = &iov[seg];

                /*
                 * If any segment has a negative length, or the cumulative
                 * length ever wraps negative then return -EINVAL.
                 */
                cnt += iv->iov_len;
                if (unlikely((ssize_t)(cnt|iv->iov_len) < 0))
                        return -EINVAL;
                if (access_ok(VERIFY_READ, iv->iov_base, iv->iov_len))
                        continue;
                if (seg == 0)
                        return -EFAULT;
                *nr_segs = seg;
                cnt -= iv->iov_len;   /* This segment is no good */
                break;
        }
        *count = cnt;
        return 0;
}

#ifdef HAVE_FILE_READV
static ssize_t ll_file_readv(struct file *file, const struct iovec *iov,
                              unsigned long nr_segs, loff_t *ppos)
{
        struct lu_env      *env;
        struct vvp_io_args *args;
        size_t              count;
        ssize_t             result;
        int                 refcheck;
        ENTRY;

        result = ll_file_get_iov_count(iov, &nr_segs, &count);
        if (result)
                RETURN(result);

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        args = vvp_env_args(env, IO_NORMAL);
        args->u.normal.via_iov = (struct iovec *)iov;
        args->u.normal.via_nrsegs = nr_segs;

        result = ll_file_io_generic(env, args, file, CIT_READ, ppos, count);
        cl_env_put(env, &refcheck);
        RETURN(result);
}

static ssize_t ll_file_read(struct file *file, char *buf, size_t count,
                            loff_t *ppos)
{
        struct lu_env *env;
        struct iovec  *local_iov;
        ssize_t        result;
        int            refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        local_iov = &vvp_env_info(env)->vti_local_iov;
        local_iov->iov_base = (void __user *)buf;
        local_iov->iov_len = count;
        result = ll_file_readv(file, local_iov, 1, ppos);
        cl_env_put(env, &refcheck);
        RETURN(result);
}

#else
static ssize_t ll_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
                                unsigned long nr_segs, loff_t pos)
{
        struct lu_env      *env;
        struct vvp_io_args *args;
        size_t              count;
        ssize_t             result;
        int                 refcheck;
        ENTRY;

        result = ll_file_get_iov_count(iov, &nr_segs, &count);
        if (result)
                RETURN(result);

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        args = vvp_env_args(env, IO_NORMAL);
        args->u.normal.via_iov = (struct iovec *)iov;
        args->u.normal.via_nrsegs = nr_segs;
        args->u.normal.via_iocb = iocb;

        result = ll_file_io_generic(env, args, iocb->ki_filp, CIT_READ,
                                    &iocb->ki_pos, count);
        cl_env_put(env, &refcheck);
        RETURN(result);
}

static ssize_t ll_file_read(struct file *file, char *buf, size_t count,
                            loff_t *ppos)
{
        struct lu_env *env;
        struct iovec  *local_iov;
        struct kiocb  *kiocb;
        ssize_t        result;
        int            refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        local_iov = &vvp_env_info(env)->vti_local_iov;
        kiocb = &vvp_env_info(env)->vti_kiocb;
        local_iov->iov_base = (void __user *)buf;
        local_iov->iov_len = count;
        init_sync_kiocb(kiocb, file);
        kiocb->ki_pos = *ppos;
        kiocb->ki_left = count;

        result = ll_file_aio_read(kiocb, local_iov, 1, kiocb->ki_pos);
        *ppos = kiocb->ki_pos;

        cl_env_put(env, &refcheck);
        RETURN(result);
}
#endif

/*
 * Write to a file (through the page cache).
 */
#ifdef HAVE_FILE_WRITEV
static ssize_t ll_file_writev(struct file *file, const struct iovec *iov,
                              unsigned long nr_segs, loff_t *ppos)
{
        struct lu_env      *env;
        struct vvp_io_args *args;
        size_t              count;
        ssize_t             result;
        int                 refcheck;
        ENTRY;

        result = ll_file_get_iov_count(iov, &nr_segs, &count);
        if (result)
                RETURN(result);

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        args = vvp_env_args(env, IO_NORMAL);
        args->u.normal.via_iov = (struct iovec *)iov;
        args->u.normal.via_nrsegs = nr_segs;

        result = ll_file_io_generic(env, args, file, CIT_WRITE, ppos, count);
        cl_env_put(env, &refcheck);
        RETURN(result);
}

static ssize_t ll_file_write(struct file *file, const char *buf, size_t count,
                             loff_t *ppos)
{
        struct lu_env    *env;
        struct iovec     *local_iov;
        ssize_t           result;
        int               refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        local_iov = &vvp_env_info(env)->vti_local_iov;
        local_iov->iov_base = (void __user *)buf;
        local_iov->iov_len = count;

        result = ll_file_writev(file, local_iov, 1, ppos);
        cl_env_put(env, &refcheck);
        RETURN(result);
}

#else /* AIO stuff */
static ssize_t ll_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
                                 unsigned long nr_segs, loff_t pos)
{
        struct lu_env      *env;
        struct vvp_io_args *args;
        size_t              count;
        ssize_t             result;
        int                 refcheck;
        ENTRY;

        result = ll_file_get_iov_count(iov, &nr_segs, &count);
        if (result)
                RETURN(result);

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        args = vvp_env_args(env, IO_NORMAL);
        args->u.normal.via_iov = (struct iovec *)iov;
        args->u.normal.via_nrsegs = nr_segs;
        args->u.normal.via_iocb = iocb;

        result = ll_file_io_generic(env, args, iocb->ki_filp, CIT_WRITE,
                                  &iocb->ki_pos, count);
        cl_env_put(env, &refcheck);
        RETURN(result);
}

static ssize_t ll_file_write(struct file *file, const char *buf, size_t count,
                             loff_t *ppos)
{
        struct lu_env *env;
        struct iovec  *local_iov;
        struct kiocb  *kiocb;
        ssize_t        result;
        int            refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        local_iov = &vvp_env_info(env)->vti_local_iov;
        kiocb = &vvp_env_info(env)->vti_kiocb;
        local_iov->iov_base = (void __user *)buf;
        local_iov->iov_len = count;
        init_sync_kiocb(kiocb, file);
        kiocb->ki_pos = *ppos;
        kiocb->ki_left = count;

        result = ll_file_aio_write(kiocb, local_iov, 1, kiocb->ki_pos);
        *ppos = kiocb->ki_pos;

        cl_env_put(env, &refcheck);
        RETURN(result);
}
#endif


#ifdef HAVE_KERNEL_SENDFILE
/*
 * Send file content (through pagecache) somewhere with helper
 */
static ssize_t ll_file_sendfile(struct file *in_file, loff_t *ppos,size_t count,
                                read_actor_t actor, void *target)
{
        struct lu_env      *env;
        struct vvp_io_args *args;
        ssize_t             result;
        int                 refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        args = vvp_env_args(env, IO_SENDFILE);
        args->u.sendfile.via_target = target;
        args->u.sendfile.via_actor = actor;

        result = ll_file_io_generic(env, args, in_file, CIT_READ, ppos, count);
        cl_env_put(env, &refcheck);
        RETURN(result);
}
#endif

#ifdef HAVE_KERNEL_SPLICE_READ
/*
 * Send file content (through pagecache) somewhere with helper
 */
static ssize_t ll_file_splice_read(struct file *in_file, loff_t *ppos,
                                   struct pipe_inode_info *pipe, size_t count,
                                   unsigned int flags)
{
        struct lu_env      *env;
        struct vvp_io_args *args;
        ssize_t             result;
        int                 refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        args = vvp_env_args(env, IO_SPLICE);
        args->u.splice.via_pipe = pipe;
        args->u.splice.via_flags = flags;

        result = ll_file_io_generic(env, args, in_file, CIT_READ, ppos, count);
        cl_env_put(env, &refcheck);
        RETURN(result);
}
#endif

static int ll_lov_recreate(struct inode *inode, obd_id id, obd_seq seq,
                           obd_count ost_idx)
{
        struct obd_export *exp = ll_i2dtexp(inode);
        struct obd_trans_info oti = { 0 };
        struct obdo *oa = NULL;
        int lsm_size;
        int rc = 0;
        struct lov_stripe_md *lsm, *lsm2;
        ENTRY;

        OBDO_ALLOC(oa);
        if (oa == NULL)
                RETURN(-ENOMEM);

        ll_inode_size_lock(inode, 0);
        lsm = ll_i2info(inode)->lli_smd;
        if (lsm == NULL)
                GOTO(out, rc = -ENOENT);
        lsm_size = sizeof(*lsm) + (sizeof(struct lov_oinfo) *
                   (lsm->lsm_stripe_count));

        OBD_ALLOC_LARGE(lsm2, lsm_size);
        if (lsm2 == NULL)
                GOTO(out, rc = -ENOMEM);

        oa->o_id = id;
        oa->o_seq = seq;
        oa->o_nlink = ost_idx;
        oa->o_flags |= OBD_FL_RECREATE_OBJS;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
        obdo_from_inode(oa, inode, &ll_i2info(inode)->lli_fid, OBD_MD_FLTYPE |
                        OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME);
        memcpy(lsm2, lsm, lsm_size);
        rc = obd_create(exp, oa, &lsm2, &oti);

        OBD_FREE_LARGE(lsm2, lsm_size);
        GOTO(out, rc);
out:
        ll_inode_size_unlock(inode, 0);
        OBDO_FREE(oa);
        return rc;
}

static int ll_lov_recreate_obj(struct inode *inode, unsigned long arg)
{
        struct ll_recreate_obj ucreat;
        ENTRY;

        if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                RETURN(-EPERM);

        if (cfs_copy_from_user(&ucreat, (struct ll_recreate_obj *)arg,
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

        if (cfs_copy_from_user(&fid, (struct lu_fid *)arg,
                               sizeof(struct lu_fid)))
                RETURN(-EFAULT);

        id = fid_oid(&fid) | ((fid_seq(&fid) & 0xffff) << 32);
        ost_idx = (fid_seq(&fid) >> 16) & 0xffff;
        RETURN(ll_lov_recreate(inode, id, 0, ost_idx));
}

int ll_lov_setstripe_ea_info(struct inode *inode, struct file *file,
                             int flags, struct lov_user_md *lum, int lum_size)
{
        struct lov_stripe_md *lsm;
        struct lookup_intent oit = {.it_op = IT_OPEN, .it_flags = flags};
        int rc = 0;
        ENTRY;

        ll_inode_size_lock(inode, 0);
        lsm = ll_i2info(inode)->lli_smd;
        if (lsm) {
                ll_inode_size_unlock(inode, 0);
                CDEBUG(D_IOCTL, "stripe already exists for ino %lu\n",
                       inode->i_ino);
                RETURN(-EEXIST);
        }

        rc = ll_intent_file_open(file, lum, lum_size, &oit);
        if (rc)
                GOTO(out, rc);
        if (it_disposition(&oit, DISP_LOOKUP_NEG))
                GOTO(out_req_free, rc = -ENOENT);
        rc = oit.d.lustre.it_status;
        if (rc < 0)
                GOTO(out_req_free, rc);

        ll_release_openhandle(file->f_dentry, &oit);

 out:
        ll_inode_size_unlock(inode, 0);
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
        struct mdt_body  *body;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *req = NULL;
        struct md_op_data *op_data;
        int rc, lmmsize;

        rc = ll_get_max_mdsize(sbi, &lmmsize);
        if (rc)
                RETURN(rc);

        op_data = ll_prep_md_op_data(NULL, inode, NULL, filename,
                                     strlen(filename), lmmsize,
                                     LUSTRE_OPC_ANY, NULL);
        if (op_data == NULL)
                RETURN(-ENOMEM);

        op_data->op_valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;
        rc = md_getattr_name(sbi->ll_md_exp, op_data, &req);
        ll_finish_md_op_data(op_data);
        if (rc < 0) {
                CDEBUG(D_INFO, "md_getattr_name failed "
                       "on %s: rc %d\n", filename, rc);
                GOTO(out, rc);
        }

        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL); /* checked by mdc_getattr_name */

        lmmsize = body->eadatasize;

        if (!(body->valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
                        lmmsize == 0) {
                GOTO(out, rc = -ENODATA);
        }

        lmm = req_capsule_server_sized_get(&req->rq_pill, &RMF_MDT_MD, lmmsize);
        LASSERT(lmm != NULL);

        if ((lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V1)) &&
            (lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V3))) {
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
                if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V1)) {
                        lustre_swab_lov_user_md_v1((struct lov_user_md_v1 *)lmm);
                        if (S_ISREG(body->mode))
                                lustre_swab_lov_user_md_objects(
                                 ((struct lov_user_md_v1 *)lmm)->lmm_objects,
                                 ((struct lov_user_md_v1 *)lmm)->lmm_stripe_count);
                } else if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)) {
                        lustre_swab_lov_user_md_v3((struct lov_user_md_v3 *)lmm);
                        if (S_ISREG(body->mode))
                                lustre_swab_lov_user_md_objects(
                                 ((struct lov_user_md_v3 *)lmm)->lmm_objects,
                                 ((struct lov_user_md_v3 *)lmm)->lmm_stripe_count);
                }
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

        OBD_ALLOC_LARGE(lump, lum_size);
        if (lump == NULL) {
                RETURN(-ENOMEM);
        }
        if (cfs_copy_from_user(lump, (struct lov_user_md  *)arg, lum_size)) {
                OBD_FREE_LARGE(lump, lum_size);
                RETURN(-EFAULT);
        }

        rc = ll_lov_setstripe_ea_info(inode, file, flags, lump, lum_size);

        OBD_FREE_LARGE(lump, lum_size);
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
        if (cfs_copy_from_user(lumv1, lumv1p, lum_size))
                RETURN(-EFAULT);

        if (lumv1->lmm_magic == LOV_USER_MAGIC_V3) {
                lum_size = sizeof(struct lov_user_md_v3);
                if (cfs_copy_from_user(&lumv3, lumv3p, lum_size))
                        RETURN(-EFAULT);
        }

        rc = ll_lov_setstripe_ea_info(inode, file, flags, lumv1, lum_size);
        if (rc == 0) {
                 put_user(0, &lumv1p->lmm_stripe_count);
                 rc = obd_iocontrol(LL_IOC_LOV_GETSTRIPE, ll_i2dtexp(inode),
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

        return obd_iocontrol(LL_IOC_LOV_GETSTRIPE, ll_i2dtexp(inode), 0, lsm,
                            (void *)arg);
}

int ll_get_grouplock(struct inode *inode, struct file *file, unsigned long arg)
{
        struct ll_inode_info   *lli = ll_i2info(inode);
        struct ll_file_data    *fd = LUSTRE_FPRIVATE(file);
        struct ccc_grouplock    grouplock;
        int                     rc;
        ENTRY;

        if (ll_file_nolock(file))
                RETURN(-EOPNOTSUPP);

        cfs_spin_lock(&lli->lli_lock);
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                CWARN("group lock already existed with gid %lu\n",
                       fd->fd_grouplock.cg_gid);
                cfs_spin_unlock(&lli->lli_lock);
                RETURN(-EINVAL);
        }
        LASSERT(fd->fd_grouplock.cg_lock == NULL);
        cfs_spin_unlock(&lli->lli_lock);

        rc = cl_get_grouplock(cl_i2info(inode)->lli_clob,
                              arg, (file->f_flags & O_NONBLOCK), &grouplock);
        if (rc)
                RETURN(rc);

        cfs_spin_lock(&lli->lli_lock);
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                cfs_spin_unlock(&lli->lli_lock);
                CERROR("another thread just won the race\n");
                cl_put_grouplock(&grouplock);
                RETURN(-EINVAL);
        }

        fd->fd_flags |= LL_FILE_GROUP_LOCKED;
        fd->fd_grouplock = grouplock;
        cfs_spin_unlock(&lli->lli_lock);

        CDEBUG(D_INFO, "group lock %lu obtained\n", arg);
        RETURN(0);
}

int ll_put_grouplock(struct inode *inode, struct file *file, unsigned long arg)
{
        struct ll_inode_info   *lli = ll_i2info(inode);
        struct ll_file_data    *fd = LUSTRE_FPRIVATE(file);
        struct ccc_grouplock    grouplock;
        ENTRY;

        cfs_spin_lock(&lli->lli_lock);
        if (!(fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
                cfs_spin_unlock(&lli->lli_lock);
                CWARN("no group lock held\n");
                RETURN(-EINVAL);
        }
        LASSERT(fd->fd_grouplock.cg_lock != NULL);

        if (fd->fd_grouplock.cg_gid != arg) {
                CWARN("group lock %lu doesn't match current id %lu\n",
                       arg, fd->fd_grouplock.cg_gid);
                cfs_spin_unlock(&lli->lli_lock);
                RETURN(-EINVAL);
        }

        grouplock = fd->fd_grouplock;
        memset(&fd->fd_grouplock, 0, sizeof(fd->fd_grouplock));
        fd->fd_flags &= ~LL_FILE_GROUP_LOCKED;
        cfs_spin_unlock(&lli->lli_lock);

        cl_put_grouplock(&grouplock);
        CDEBUG(D_INFO, "group lock %lu released\n", arg);
        RETURN(0);
}

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

        ll_och_fill(ll_i2sbi(inode)->ll_md_exp,
                    ll_i2info(inode), it, och);

        rc = ll_close_inode_openhandle(ll_i2sbi(inode)->ll_md_exp,
                                       inode, och);
 out:
        /* this one is in place of ll_file_open */
        if (it_disposition(it, DISP_ENQ_OPEN_REF))
                ptlrpc_req_finished(it->d.lustre.it_data);
        it_clear_disposition(it, DISP_ENQ_OPEN_REF);
        RETURN(rc);
}

/**
 * Get size for inode for which FIEMAP mapping is requested.
 * Make the FIEMAP get_info call and returns the result.
 */
int ll_do_fiemap(struct inode *inode, struct ll_user_fiemap *fiemap,
              int num_bytes)
{
        struct obd_export *exp = ll_i2dtexp(inode);
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
        fm_key.oa.o_seq = lsm->lsm_object_seq;
        fm_key.oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

        obdo_from_inode(&fm_key.oa, inode, &ll_i2info(inode)->lli_fid,
                        OBD_MD_FLSIZE);
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

int ll_fid2path(struct obd_export *exp, void *arg)
{
        struct getinfo_fid2path *gfout, *gfin;
        int outsize, rc;
        ENTRY;

        /* Need to get the buflen */
        OBD_ALLOC_PTR(gfin);
        if (gfin == NULL)
                RETURN(-ENOMEM);
        if (cfs_copy_from_user(gfin, arg, sizeof(*gfin))) {
                OBD_FREE_PTR(gfin);
                RETURN(-EFAULT);
        }

        outsize = sizeof(*gfout) + gfin->gf_pathlen;
        OBD_ALLOC(gfout, outsize);
        if (gfout == NULL) {
                OBD_FREE_PTR(gfin);
                RETURN(-ENOMEM);
        }
        memcpy(gfout, gfin, sizeof(*gfout));
        OBD_FREE_PTR(gfin);

        /* Call mdc_iocontrol */
        rc = obd_iocontrol(OBD_IOC_FID2PATH, exp, outsize, gfout, NULL);
        if (rc)
                GOTO(gf_free, rc);
        if (cfs_copy_to_user(arg, gfout, outsize))
                rc = -EFAULT;

gf_free:
        OBD_FREE(gfout, outsize);
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

        OBD_ALLOC_LARGE(fiemap_s, num_bytes);
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
        OBD_FREE_LARGE(fiemap_s, num_bytes);
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
        case LL_IOC_GROUP_LOCK:
                RETURN(ll_get_grouplock(inode, file, arg));
        case LL_IOC_GROUP_UNLOCK:
                RETURN(ll_put_grouplock(inode, file, arg));
        case IOC_OBD_STATFS:
                RETURN(ll_obd_statfs(inode, (void *)arg));

        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case FSFILT_IOC_SETVERSION_OLD:
        case FSFILT_IOC_SETVERSION:
        */
        case LL_IOC_FLUSHCTX:
                RETURN(ll_flush_ctx(inode));
        case LL_IOC_PATH2FID: {
                if (cfs_copy_to_user((void *)arg, ll_inode2fid(inode),
                                     sizeof(struct lu_fid)))
                        RETURN(-EFAULT);

                RETURN(0);
        }
        case OBD_IOC_FID2PATH:
                RETURN(ll_fid2path(ll_i2mdexp(inode), (void *)arg));

        case LL_IOC_GET_MDTIDX: {
                int mdtidx;

                mdtidx = ll_get_mdt_idx(inode);
                if (mdtidx < 0)
                        RETURN(mdtidx);

                if (put_user((int)mdtidx, (int*)arg))
                        RETURN(-EFAULT);

                RETURN(0);
        }

        default: {
                int err;

                if (LLIOC_STOP ==
                    ll_iocontrol_call(inode, file, cmd, arg, &err))
                        RETURN(err);

                RETURN(obd_iocontrol(cmd, ll_i2dtexp(inode), 0, NULL,
                                     (void *)arg));
        }
        }
}

loff_t ll_file_seek(struct file *file, loff_t offset, int origin)
{
        struct inode *inode = file->f_dentry->d_inode;
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

                rc = cl_glimpse_size(inode);
                if (rc != 0)
                        RETURN(rc);

                offset += i_size_read(inode);
        } else if (origin == 1) { /* SEEK_CUR */
                offset += file->f_pos;
        }

        retval = -EINVAL;
        if (offset >= 0 && offset <= ll_file_maxbytes(inode)) {
                if (offset != file->f_pos) {
                        file->f_pos = offset;
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
        int rc, err;

        /* the application should know write failure already. */
        if (lli->lli_write_rc)
                return 0;

        /* catch async errors that were recorded back when async writeback
         * failed for pages in this mapping. */
        rc = lli->lli_async_rc;
        lli->lli_async_rc = 0;
        if (lsm) {
                err = lov_test_and_clear_async_rc(lsm);
                if (rc == 0)
                        rc = err;
        }

        return rc ? -EIO : 0;
}

int ll_fsync(struct file *file, struct dentry *dentry, int data)
{
        struct inode *inode = dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ptlrpc_request *req;
        struct obd_capa *oc;
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

        oc = ll_mdscapa_get(inode);
        err = md_sync(ll_i2sbi(inode)->ll_md_exp, ll_inode2fid(inode), oc,
                      &req);
        capa_put(oc);
        if (!rc)
                rc = err;
        if (!err)
                ptlrpc_req_finished(req);

        if (data && lsm) {
                struct obd_info *oinfo;

                OBD_ALLOC_PTR(oinfo);
                if (!oinfo)
                        RETURN(rc ? rc : -ENOMEM);
                OBDO_ALLOC(oinfo->oi_oa);
                if (!oinfo->oi_oa) {
                        OBD_FREE_PTR(oinfo);
                        RETURN(rc ? rc : -ENOMEM);
                }
                oinfo->oi_oa->o_id = lsm->lsm_object_id;
                oinfo->oi_oa->o_seq = lsm->lsm_object_seq;
                oinfo->oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
                obdo_from_inode(oinfo->oi_oa, inode, &ll_i2info(inode)->lli_fid,
                                OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                                OBD_MD_FLGROUP);
                oinfo->oi_md = lsm;
                oinfo->oi_capa = ll_osscapa_get(inode, CAPA_OPC_OSS_WRITE);
                err = obd_sync_rqset(ll_i2sbi(inode)->ll_dt_exp, oinfo, 0,
                                     OBD_OBJECT_EOF);
                capa_put(oinfo->oi_capa);
                if (!rc)
                        rc = err;
                OBDO_FREE(oinfo->oi_oa);
                OBD_FREE_PTR(oinfo);
                lli->lli_write_rc = err < 0 ? : 0;
        }

        RETURN(rc);
}

int ll_file_flock(struct file *file, int cmd, struct file_lock *file_lock)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ldlm_enqueue_info einfo = { .ei_type = LDLM_FLOCK,
                                           .ei_cb_cp =ldlm_flock_completion_ast,
                                           .ei_cbdata = file_lock };
        struct md_op_data *op_data;
        struct lustre_handle lockh = {0};
        ldlm_policy_data_t flock = {{0}};
        int flags = 0;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu file_lock=%p\n",
               inode->i_ino, file_lock);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FLOCK, 1);

        if (file_lock->fl_flags & FL_FLOCK) {
                LASSERT((cmd == F_SETLKW) || (cmd == F_SETLK));
                /* flocks are whole-file locks */
                flock.l_flock.end = OFFSET_MAX;
                /* For flocks owner is determined by the local file desctiptor*/
                flock.l_flock.owner = (unsigned long)file_lock->fl_file;
        } else if (file_lock->fl_flags & FL_POSIX) {
                flock.l_flock.owner = (unsigned long)file_lock->fl_owner;
                flock.l_flock.start = file_lock->fl_start;
                flock.l_flock.end = file_lock->fl_end;
        } else {
                RETURN(-EINVAL);
        }
        flock.l_flock.pid = file_lock->fl_pid;

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

        op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
                                     LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        CDEBUG(D_DLMTRACE, "inode=%lu, pid=%u, flags=%#x, mode=%u, "
               "start="LPU64", end="LPU64"\n", inode->i_ino, flock.l_flock.pid,
               flags, einfo.ei_mode, flock.l_flock.start, flock.l_flock.end);

        rc = md_enqueue(sbi->ll_md_exp, &einfo, NULL,
                        op_data, &lockh, &flock, 0, NULL /* req */, flags);

        ll_finish_md_op_data(op_data);

        if ((file_lock->fl_flags & FL_FLOCK) &&
            (rc == 0 || file_lock->fl_type == F_UNLCK))
                ll_flock_lock_file_wait(file, file_lock, (cmd == F_SETLKW));
#ifdef HAVE_F_OP_FLOCK
        if ((file_lock->fl_flags & FL_POSIX) &&
            (rc == 0 || file_lock->fl_type == F_UNLCK) &&
            !(flags & LDLM_FL_TEST_LOCK))
                posix_lock_file_wait(file, file_lock);
#endif

        RETURN(rc);
}

int ll_file_noflock(struct file *file, int cmd, struct file_lock *file_lock)
{
        ENTRY;

        RETURN(-ENOSYS);
}

int ll_have_md_lock(struct inode *inode, __u64 bits,  ldlm_mode_t l_req_mode)
{
        struct lustre_handle lockh;
        ldlm_policy_data_t policy = { .l_inodebits = {bits}};
        ldlm_mode_t mode = (l_req_mode == LCK_MINMODE) ?
                                (LCK_CR|LCK_CW|LCK_PR|LCK_PW) : l_req_mode;
        struct lu_fid *fid;
        int flags;
        ENTRY;

        if (!inode)
               RETURN(0);

        fid = &ll_i2info(inode)->lli_fid;
        CDEBUG(D_INFO, "trying to match res "DFID" mode %s\n", PFID(fid),
               ldlm_lockname[mode]);

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
        if (md_lock_match(ll_i2mdexp(inode), flags, fid, LDLM_IBITS, &policy,
                          mode, &lockh)) {
                RETURN(1);
        }
        RETURN(0);
}

ldlm_mode_t ll_take_md_lock(struct inode *inode, __u64 bits,
                            struct lustre_handle *lockh)
{
        ldlm_policy_data_t policy = { .l_inodebits = {bits}};
        struct lu_fid *fid;
        ldlm_mode_t rc;
        int flags;
        ENTRY;

        fid = &ll_i2info(inode)->lli_fid;
        CDEBUG(D_INFO, "trying to match res "DFID"\n", PFID(fid));

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING;
        rc = md_lock_match(ll_i2mdexp(inode), flags, fid, LDLM_IBITS, &policy,
                           LCK_CR|LCK_CW|LCK_PR|LCK_PW, lockh);
        RETURN(rc);
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
        struct ll_sb_info *sbi;
        struct obd_export *exp;
        int rc = 0;
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }
        sbi = ll_i2sbi(inode);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),name=%s\n",
               inode->i_ino, inode->i_generation, inode, dentry->d_name.name);

        exp = ll_i2mdexp(inode);

        /* XXX: Enable OBD_CONNECT_ATTRFID to reduce unnecessary getattr RPC.
         *      But under CMD case, it caused some lock issues, should be fixed
         *      with new CMD ibits lock. See bug 12718 */
        if (exp->exp_connect_flags & OBD_CONNECT_ATTRFID) {
                struct lookup_intent oit = { .it_op = IT_GETATTR };
                struct md_op_data *op_data;

                if (ibits == MDS_INODELOCK_LOOKUP)
                        oit.it_op = IT_LOOKUP;

                /* Call getattr by fid, so do not provide name at all. */
                op_data = ll_prep_md_op_data(NULL, dentry->d_parent->d_inode,
                                             dentry->d_inode, NULL, 0, 0,
                                             LUSTRE_OPC_ANY, NULL);
                if (IS_ERR(op_data))
                        RETURN(PTR_ERR(op_data));

                oit.it_create_mode |= M_CHECK_STALE;
                rc = md_intent_lock(exp, op_data, NULL, 0,
                                    /* we are not interested in name
                                       based lookup */
                                    &oit, 0, &req,
                                    ll_md_blocking_ast, 0);
                ll_finish_md_op_data(op_data);
                oit.it_create_mode &= ~M_CHECK_STALE;
                if (rc < 0) {
                        rc = ll_inode_revalidate_fini(inode, rc);
                        GOTO (out, rc);
                }

                rc = ll_revalidate_it_finish(req, &oit, dentry);
                if (rc != 0) {
                        ll_intent_release(&oit);
                        GOTO(out, rc);
                }

                /* Unlinked? Unhash dentry, so it is not picked up later by
                   do_lookup() -> ll_revalidate_it(). We cannot use d_drop
                   here to preserve get_cwd functionality on 2.6.
                   Bug 10503 */
                if (!dentry->d_inode->i_nlink) {
                        cfs_spin_lock(&ll_lookup_lock);
                        spin_lock(&dcache_lock);
                        ll_drop_dentry(dentry);
                        spin_unlock(&dcache_lock);
                        cfs_spin_unlock(&ll_lookup_lock);
                }

                ll_lookup_finish_locks(&oit, dentry);
        } else if (!ll_have_md_lock(dentry->d_inode, ibits, LCK_MINMODE)) {
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                obd_valid valid = OBD_MD_FLGETATTR;
                struct md_op_data *op_data;
                int ealen = 0;

                if (S_ISREG(inode->i_mode)) {
                        rc = ll_get_max_mdsize(sbi, &ealen);
                        if (rc)
                                RETURN(rc);
                        valid |= OBD_MD_FLEASIZE | OBD_MD_FLMODEASIZE;
                }

                op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL,
                                             0, ealen, LUSTRE_OPC_ANY,
                                             NULL);
                if (op_data == NULL)
                        RETURN(-ENOMEM);

                op_data->op_valid = valid;
                /* Once OBD_CONNECT_ATTRFID is not supported, we can't find one
                 * capa for this inode. Because we only keep capas of dirs
                 * fresh. */
                rc = md_getattr(sbi->ll_md_exp, op_data, &req);
                ll_finish_md_op_data(op_data);
                if (rc) {
                        rc = ll_inode_revalidate_fini(inode, rc);
                        RETURN(rc);
                }

                rc = ll_prep_inode(&inode, req, NULL);
        }
out:
        ptlrpc_req_finished(req);
        return rc;
}

int ll_inode_revalidate_it(struct dentry *dentry, struct lookup_intent *it,
                           __u64 ibits)
{
        struct inode *inode = dentry->d_inode;
        int rc;
        ENTRY;

        rc = __ll_inode_revalidate_it(dentry, it, ibits);

        /* if object not yet allocated, don't validate size */
        if (rc == 0 && ll_i2info(dentry->d_inode)->lli_smd == NULL) {
                LTIME_S(inode->i_atime) = ll_i2info(inode)->lli_lvb.lvb_atime;
                LTIME_S(inode->i_mtime) = ll_i2info(inode)->lli_lvb.lvb_mtime;
                LTIME_S(inode->i_ctime) = ll_i2info(inode)->lli_lvb.lvb_ctime;
                RETURN(0);
        }

        /* cl_glimpse_size will prefer locally cached writes if they extend
         * the file */

        if (rc == 0)
                rc = cl_glimpse_size(inode);

        RETURN(rc);
}

int ll_getattr_it(struct vfsmount *mnt, struct dentry *de,
                  struct lookup_intent *it, struct kstat *stat)
{
        struct inode *inode = de->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        int res = 0;

        res = ll_inode_revalidate_it(de, it, MDS_INODELOCK_UPDATE |
                                             MDS_INODELOCK_LOOKUP);
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETATTR, 1);

        if (res)
                return res;

        stat->dev = inode->i_sb->s_dev;
        if (ll_need_32bit_api(ll_i2sbi(inode)))
                stat->ino = cl_fid_build_ino32(&lli->lli_fid);
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
        stat->blksize = 1 << inode->i_blkbits;
#endif

        stat->size = i_size_read(inode);
        stat->blocks = inode->i_blocks;

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
        OBD_ALLOC_LARGE(fiemap, num_bytes);

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

        OBD_FREE_LARGE(fiemap, num_bytes);
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

        cfs_spin_lock(&lli->lli_lock);
        acl = posix_acl_dup(lli->lli_posix_acl);
        cfs_spin_unlock(&lli->lli_lock);

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

        if (ll_i2sbi(inode)->ll_flags & LL_SBI_RMT_CLIENT)
                return lustre_check_remote_perm(inode, mask);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_INODE_PERM, 1);
        rc = generic_permission(inode, mask, lustre_check_acl);

        RETURN(rc);
}
#else
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
        int mode = inode->i_mode;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), mask %o\n",
               inode->i_ino, inode->i_generation, inode, mask);

        if (ll_i2sbi(inode)->ll_flags & LL_SBI_RMT_CLIENT)
                return lustre_check_remote_perm(inode, mask);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_INODE_PERM, 1);

        if ((mask & MAY_WRITE) && IS_RDONLY(inode) &&
            (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
                return -EROFS;
        if ((mask & MAY_WRITE) && IS_IMMUTABLE(inode))
                return -EACCES;
        if (cfs_curproc_fsuid() == inode->i_uid) {
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
                if (cfs_curproc_is_in_groups(inode->i_gid))
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

#ifdef HAVE_FILE_READV
#define READ_METHOD readv
#define READ_FUNCTION ll_file_readv
#define WRITE_METHOD writev
#define WRITE_FUNCTION ll_file_writev
#else
#define READ_METHOD aio_read
#define READ_FUNCTION ll_file_aio_read
#define WRITE_METHOD aio_write
#define WRITE_FUNCTION ll_file_aio_write
#endif

/* -o localflock - only provides locally consistent flock locks */
struct file_operations ll_file_operations = {
        .read           = ll_file_read,
        .READ_METHOD    = READ_FUNCTION,
        .write          = ll_file_write,
        .WRITE_METHOD   = WRITE_FUNCTION,
#ifdef HAVE_UNLOCKED_IOCTL
        .unlocked_ioctl = ll_file_ioctl,
#else
        .ioctl          = ll_file_ioctl,
#endif
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#ifdef HAVE_KERNEL_SENDFILE
        .sendfile       = ll_file_sendfile,
#endif
#ifdef HAVE_KERNEL_SPLICE_READ
        .splice_read    = ll_file_splice_read,
#endif
        .fsync          = ll_fsync,
        .flush          = ll_flush
};

struct file_operations ll_file_operations_flock = {
        .read           = ll_file_read,
        .READ_METHOD    = READ_FUNCTION,
        .write          = ll_file_write,
        .WRITE_METHOD   = WRITE_FUNCTION,
#ifdef HAVE_UNLOCKED_IOCTL
        .unlocked_ioctl = ll_file_ioctl,
#else
        .ioctl          = ll_file_ioctl,
#endif
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#ifdef HAVE_KERNEL_SENDFILE
        .sendfile       = ll_file_sendfile,
#endif
#ifdef HAVE_KERNEL_SPLICE_READ
        .splice_read    = ll_file_splice_read,
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
        .READ_METHOD    = READ_FUNCTION,
        .write          = ll_file_write,
        .WRITE_METHOD   = WRITE_FUNCTION,
#ifdef HAVE_UNLOCKED_IOCTL
        .unlocked_ioctl = ll_file_ioctl,
#else
        .ioctl          = ll_file_ioctl,
#endif
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
#ifdef HAVE_KERNEL_SENDFILE
        .sendfile       = ll_file_sendfile,
#endif
#ifdef HAVE_KERNEL_SPLICE_READ
        .splice_read    = ll_file_splice_read,
#endif
        .fsync          = ll_fsync,
        .flush          = ll_flush,
#ifdef HAVE_F_OP_FLOCK
        .flock          = ll_file_noflock,
#endif
        .lock           = ll_file_noflock
};

struct inode_operations ll_file_inode_operations = {
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
        cfs_rw_semaphore_t      ioc_sem;
        cfs_list_t              ioc_head;
} llioc = {
        __RWSEM_INITIALIZER(llioc.ioc_sem),
        CFS_LIST_HEAD_INIT(llioc.ioc_head)
};


struct llioc_data {
        cfs_list_t              iocd_list;
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

        cfs_down_write(&llioc.ioc_sem);
        cfs_list_add_tail(&in_data->iocd_list, &llioc.ioc_head);
        cfs_up_write(&llioc.ioc_sem);

        RETURN(in_data);
}

void ll_iocontrol_unregister(void *magic)
{
        struct llioc_data *tmp;

        if (magic == NULL)
                return;

        cfs_down_write(&llioc.ioc_sem);
        cfs_list_for_each_entry(tmp, &llioc.ioc_head, iocd_list) {
                if (tmp == magic) {
                        unsigned int size = tmp->iocd_size;

                        cfs_list_del(&tmp->iocd_list);
                        cfs_up_write(&llioc.ioc_sem);

                        OBD_FREE(tmp, size);
                        return;
                }
        }
        cfs_up_write(&llioc.ioc_sem);

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

        cfs_down_read(&llioc.ioc_sem);
        cfs_list_for_each_entry(data, &llioc.ioc_head, iocd_list) {
                for (i = 0; i < data->iocd_count; i++) {
                        if (cmd != data->iocd_cmd[i])
                                continue;

                        ret = data->iocd_cb(inode, file, cmd, arg, data, &rc);
                        break;
                }

                if (ret == LLIOC_STOP)
                        break;
        }
        cfs_up_read(&llioc.ioc_sem);

        if (rcp)
                *rcp = rc;
        return ret;
}
