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
#include "llite_internal.h"

/* also used by llite/special.c:ll_special_open() */
struct ll_file_data *ll_file_data_get(void)
{
        struct ll_file_data *fd;

        OBD_SLAB_ALLOC_PTR(fd, ll_file_data_slab);
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
        ((struct ll_iattr *)&op_data->op_attr)->ia_attr_flags = inode->i_flags;
        op_data->op_ioepoch = ll_i2info(inode)->lli_ioepoch;
        memcpy(&op_data->op_handle, fh, sizeof(op_data->op_handle));
        op_data->op_capa1 = ll_mdscapa_get(inode);
}

static void ll_prepare_close(struct inode *inode, struct md_op_data *op_data,
                             struct obd_client_handle *och)
{
        ENTRY;

        op_data->op_attr.ia_valid = ATTR_MODE | ATTR_ATIME_SET |
                                 ATTR_MTIME_SET | ATTR_CTIME_SET;

        if (!(och->och_flags & FMODE_WRITE))
                goto out;

        if (!(ll_i2mdexp(inode)->exp_connect_flags & OBD_CONNECT_SOM) ||
            !S_ISREG(inode->i_mode))
                op_data->op_attr.ia_valid |= ATTR_SIZE | ATTR_BLOCKS;
        else
                ll_epoch_close(inode, op_data, &och, 0);

out:
        ll_pack_inode2opdata(inode, op_data, &och->och_fh);
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
        int seq_end = 0, rc;
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

        /*
         * here we check if this is forced umount. If so this is called on
         * canceling "open lock" and we do not call md_close() in this case, as
         * it will not be successful, as import is already deactivated.
         */
        if (obd->obd_force)
                GOTO(out, rc = 0);

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                GOTO(out, rc = -ENOMEM); // XXX We leak openhandle and request here.

        ll_prepare_close(inode, op_data, och);
        epoch_close = (op_data->op_flags & MF_EPOCH_CLOSE);
        rc = md_close(md_exp, op_data, och->och_mod, &req);
        if (rc != -EAGAIN)
                seq_end = 1;

        if (rc == -EAGAIN) {
                /* This close must have the epoch closed. */
                LASSERT(exp->exp_connect_flags & OBD_CONNECT_SOM);
                LASSERT(epoch_close);
                /* MDS has instructed us to obtain Size-on-MDS attribute from
                 * OSTs and send setattr to back to MDS. */
                rc = ll_sizeonmds_update(inode, och->och_mod,
                                         &och->och_fh, op_data->op_ioepoch);
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
      
        if ((exp->exp_connect_flags & OBD_CONNECT_SOM) && !epoch_close &&
            S_ISREG(inode->i_mode) && (och->och_flags & FMODE_WRITE)) {
                ll_queue_done_writing(inode, LLIF_DONE_WRITING);
        } else {
                if (seq_end)
                        ptlrpc_close_replay_seq(req);
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
        if (lli->lli_opendir_key == fd)
                ll_stop_statahead(inode, fd);

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
                GOTO(out_stale, rc);
        }

        if (rc != 0 || it_open_error(DISP_OPEN_OPEN, itp)) {
                rc = rc ? rc : it_open_error(DISP_OPEN_OPEN, itp);
                CDEBUG(D_VFSTRACE, "lock enqueue: err: %d\n", rc);
                GOTO(out, rc);
        }

        if (itp->d.lustre.it_lock_mode)
                md_set_lock_data(sbi->ll_md_exp,
                                 &itp->d.lustre.it_lock_handle, 
                                 file->f_dentry->d_inode);

        rc = ll_prep_inode(&file->f_dentry->d_inode, req, NULL);
out:
        ptlrpc_req_finished(itp->d.lustre.it_data);

out_stale:
        it_clear_disposition(itp, DISP_ENQ_COMPLETE);
        ll_intent_drop_lock(itp);

        RETURN(rc);
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
        lli->lli_ioepoch = body->ioepoch;

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

#ifdef HAVE_VFS_INTENT_PATCHES
        it = file->f_it;
#else
        it = file->private_data; /* XXX: compat macro */
        file->private_data = NULL; /* prevent ll_local_open assertion */
#endif

        fd = ll_file_data_get();
        if (fd == NULL)
                RETURN(-ENOMEM);

        if (S_ISDIR(inode->i_mode)) {
                spin_lock(&lli->lli_lock);
                /* "lli->lli_opendir_pid != 0" means someone has set it.
                 * "lli->lli_sai != NULL" means the previous statahead has not
                 *                        been cleanup. */ 
                if (lli->lli_opendir_pid == 0 && lli->lli_sai == NULL) {
                        opendir_set = 1;
                        lli->lli_opendir_pid = cfs_curproc_pid();
                        lli->lli_opendir_key = fd;
                } else if (unlikely(lli->lli_opendir_pid == cfs_curproc_pid())) {
                        /* Two cases for this:
                         * (1) The same process open such directory many times.
                         * (2) The old process opened the directory, and exited
                         *     before its children processes. Then new process
                         *     with the same pid opens such directory before the
                         *     old process's children processes exit.
                         * Change the owner to the latest one. */
                        opendir_set = 2;
                        lli->lli_opendir_key = fd;
                }
                spin_unlock(&lli->lli_lock);
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
                if (oit.it_flags & FMODE_WRITE)
                        oit.it_flags |= MDS_OPEN_OWNEROVERRIDE;

                /* We do not want O_EXCL here, presumably we opened the file
                 * already? XXX - NFS implications? */
                oit.it_flags &= ~O_EXCL;

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
        
        down(&lli->lli_och_sem);
        if (*och_p) { /* Open handle is present */
                if (it_disposition(it, DISP_OPEN_OPEN)) {
                        /* Well, there's extra open request that we do not need,
                           let's close it somehow. This will decref request. */
                        rc = it_open_error(DISP_OPEN_OPEN, it);
                        if (rc) {
                                ll_file_data_put(fd);
                                GOTO(out_och_free, rc);
                        }       
                        ll_release_openhandle(file->f_dentry, it);
                        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, 
                                             LPROC_LL_OPEN);
                }
                (*och_usecount)++;

                rc = ll_local_open(file, it, fd, NULL);
                if (rc) {
                        up(&lli->lli_och_sem);
                        ll_file_data_put(fd);
                        RETURN(rc);
                }
        } else {
                LASSERT(*och_usecount == 0);
                if (!it->d.lustre.it_disposition) {
                        /* We cannot just request lock handle now, new ELC code
                           means that one of other OPEN locks for this file
                           could be cancelled, and since blocking ast handler
                           would attempt to grab och_sem as well, that would
                           result in a deadlock */
                        up(&lli->lli_och_sem);
                        it->it_flags |= O_CHECK_STALE;
                        rc = ll_intent_file_open(file, NULL, 0, it);
                        it->it_flags &= ~O_CHECK_STALE;
                        if (rc) {
                                ll_file_data_put(fd);
                                GOTO(out_openerr, rc);
                        }

                        /* Got some error? Release the request */
                        if (it->d.lustre.it_status < 0) {
                                req = it->d.lustre.it_data;
                                ptlrpc_req_finished(req);
                        }
                        md_set_lock_data(ll_i2sbi(inode)->ll_md_exp,
                                         &it->d.lustre.it_lock_handle,
                                         file->f_dentry->d_inode);
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
                        up(&lli->lli_och_sem);
                        ll_file_data_put(fd);
                        GOTO(out_och_free, rc);
                }
        }
        up(&lli->lli_och_sem);

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
                up(&lli->lli_och_sem);
out_openerr:
                if (opendir_set == 1) {
                        lli->lli_opendir_key = NULL;
                        lli->lli_opendir_pid = 0;
                } else if (unlikely(opendir_set == 2)) {
                        ll_stop_statahead(inode, fd);
                }
        }

        return rc;
}

/* Fills the obdo with the attributes for the inode defined by lsm */
int ll_inode_getattr(struct inode *inode, struct obdo *obdo)
{
        struct ptlrpc_request_set *set;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;

        struct obd_info oinfo = { { { 0 } } };
        int rc;
        ENTRY;

        LASSERT(lsm != NULL);

        oinfo.oi_md = lsm;
        oinfo.oi_oa = obdo;
        oinfo.oi_oa->o_id = lsm->lsm_object_id;
        oinfo.oi_oa->o_gr = lsm->lsm_object_gr;
        oinfo.oi_oa->o_mode = S_IFREG;
        oinfo.oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE |
                               OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                               OBD_MD_FLBLKSZ | OBD_MD_FLATIME |
                               OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                               OBD_MD_FLGROUP;
        oinfo.oi_capa = ll_mdscapa_get(inode);

        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR("can't allocate ptlrpc set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_getattr_async(ll_i2dtexp(inode), &oinfo, set);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                ptlrpc_set_destroy(set);
        }
        capa_put(oinfo.oi_capa);
        if (rc)
                RETURN(rc);

        oinfo.oi_oa->o_valid &= (OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ |
                                 OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                 OBD_MD_FLCTIME | OBD_MD_FLSIZE);

        obdo_refresh_inode(inode, oinfo.oi_oa, oinfo.oi_oa->o_valid);
        CDEBUG(D_INODE, "objid "LPX64" size %Lu, blocks %llu, blksize %lu\n",
               lli->lli_smd->lsm_object_id, i_size_read(inode),
               (unsigned long long)inode->i_blocks,
               (unsigned long)ll_inode_blksize(inode));
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
        if (lsm->lsm_oinfo[stripe]->loi_id != lock->l_resource->lr_name.name[0]||
            lsm->lsm_oinfo[stripe]->loi_gr != lock->l_resource->lr_name.name[2]){
                LDLM_ERROR(lock, "resource doesn't match object "LPU64"/"LPU64,
                           lsm->lsm_oinfo[stripe]->loi_id,
                           lsm->lsm_oinfo[stripe]->loi_gr);
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
        struct address_space *mapping = inode->i_mapping;

        ENTRY;
        tmpex = lock->l_policy_data;
        CDEBUG(D_INODE|D_PAGE, "inode %lu(%p) ["LPU64"->"LPU64"] size: %llu\n",
               inode->i_ino, inode, tmpex.l_extent.start, tmpex.l_extent.end,
               i_size_read(inode));

        /* our locks are page granular thanks to osc_enqueue, we invalidate the
         * whole page. */
        if ((tmpex.l_extent.start & ~CFS_PAGE_MASK) != 0 ||
            ((tmpex.l_extent.end + 1) & ~CFS_PAGE_MASK) != 0)
                LDLM_ERROR(lock, "lock not aligned on PAGE_SIZE %lu",
                           CFS_PAGE_SIZE);
        LASSERT((tmpex.l_extent.start & ~CFS_PAGE_MASK) == 0);
        LASSERT(((tmpex.l_extent.end + 1) & ~CFS_PAGE_MASK) == 0);

        count = ~0;
        skip = 0;
        start = tmpex.l_extent.start >> CFS_PAGE_SHIFT;
        end = tmpex.l_extent.end >> CFS_PAGE_SHIFT;
        if (lsm->lsm_stripe_count > 1) {
                count = lsm->lsm_stripe_size >> CFS_PAGE_SHIFT;
                skip = (lsm->lsm_stripe_count - 1) * count;
                start += start/count * skip + stripe * count;
                if (end != ~0)
                        end += end/count * skip + stripe * count;
        }
        if (end < tmpex.l_extent.end >> CFS_PAGE_SHIFT)
                end = ~0;

        i = i_size_read(inode) ? (__u64)(i_size_read(inode) - 1) >>
            CFS_PAGE_SHIFT : 0;
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
                LASSERT(mapping);
                if (ll_teardown_mmaps(mapping,
                                      (__u64)i << CFS_PAGE_SHIFT,
                                      ((__u64)(i+j) << CFS_PAGE_SHIFT) - 1) )
                        break;
        }

        /* this is the simplistic implementation of page eviction at
         * cancelation.  It is careful to get races with other page
         * lockers handled correctly.  fixes from bug 20 will make it
         * more efficient by associating locks with pages and with
         * batching writeback under the lock explicitly. */
        for (i = start, j = start % count; i <= end;
             j++, i++, tmpex.l_extent.start += CFS_PAGE_SIZE) {
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

                if (!mapping_has_pages(mapping)) {
                        CDEBUG(D_INODE|D_PAGE, "nothing left\n");
                        break;
                }

                cond_resched();

                page = find_lock_page(mapping, i);
                if (page == NULL)
                        continue;
                LL_CDEBUG_PAGE(D_PAGE, page, "lock page idx %lu ext "LPU64"\n",
                               i, tmpex.l_extent.start);
                if (!discard && PageWriteback(page))
                        wait_on_page_writeback(page);

                /* page->mapping to check with racing against teardown */
                if (!discard && clear_page_dirty_for_io(page)) {
                        rc = ll_call_writepage(inode, page);
                        /* either waiting for io to complete or reacquiring
                         * the lock that the failed writepage released */
                        lock_page(page);
                        wait_on_page_writeback(page);
                        if (rc < 0) {
                                CERROR("writepage inode %lu(%p) of page %p "
                                       "failed: %d\n", inode->i_ino, inode,
                                       page, rc);
                                if (rc == -ENOSPC)
                                        set_bit(AS_ENOSPC, &mapping->flags);
                                else
                                        set_bit(AS_EIO, &mapping->flags);
                        }
                }

                tmpex.l_extent.end = tmpex.l_extent.start + CFS_PAGE_SIZE - 1;
                /* check to see if another DLM lock covers this page b=2765 */
                rc2 = ldlm_lock_match(lock->l_resource->lr_namespace,
                                      LDLM_FL_BLOCK_GRANTED|LDLM_FL_CBPENDING |
                                      LDLM_FL_TEST_LOCK,
                                      &lock->l_resource->lr_name, LDLM_EXTENT,
                                      &tmpex, LCK_PR | LCK_PW, &lockh);

                if (rc2 <= 0 && page->mapping != NULL) {
                        struct ll_async_page *llap = llap_cast_private(page);
                        /* checking again to account for writeback's
                         * lock_page() */
                        LL_CDEBUG_PAGE(D_PAGE, page, "truncating\n");
                        if (llap)
                                ll_ra_accounting(llap, mapping);
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

        req_capsule_extend(&req->rq_pill, &RQF_LDLM_GL_CALLBACK);
        req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
                             sizeof(*lvb));
        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc) {
                CERROR("lustre_pack_reply: %d\n", rc);
                GOTO(iput, rc);
        }

        lvb = req_capsule_server_get(&req->rq_pill, &RMF_DLM_LVB);
        lvb->lvb_size = lli->lli_smd->lsm_oinfo[stripe]->loi_kms;
        lvb->lvb_mtime = LTIME_S(inode->i_mtime);
        lvb->lvb_atime = LTIME_S(inode->i_atime);
        lvb->lvb_ctime = LTIME_S(inode->i_ctime);

        LDLM_DEBUG(lock, "i_size: %llu -> stripe number %u -> kms "LPU64
                   " atime "LPU64", mtime "LPU64", ctime "LPU64,
                   i_size_read(inode), stripe, lvb->lvb_size, lvb->lvb_mtime,
                   lvb->lvb_atime, lvb->lvb_ctime);
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

static int ll_merge_lvb(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ost_lvb lvb;
        int rc;

        ENTRY;

        ll_inode_size_lock(inode, 1);
        inode_init_lvb(inode, &lvb);
        rc = obd_merge_lvb(sbi->ll_dt_exp, lli->lli_smd, &lvb, 0);
        i_size_write(inode, lvb.lvb_size);
        inode->i_blocks = lvb.lvb_blocks;

        LTIME_S(inode->i_mtime) = lvb.lvb_mtime;
        LTIME_S(inode->i_atime) = lvb.lvb_atime;
        LTIME_S(inode->i_ctime) = lvb.lvb_ctime;
        ll_inode_size_unlock(inode, 1);

        RETURN(rc);
}

int ll_local_size(struct inode *inode)
{
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_handle lockh = { 0 };
        int flags = 0;
        int rc;
        ENTRY;

        if (lli->lli_smd->lsm_stripe_count == 0)
                RETURN(0);

        rc = obd_match(sbi->ll_dt_exp, lli->lli_smd, LDLM_EXTENT,
                       &policy, LCK_PR, &flags, inode, &lockh);
        if (rc < 0)
                RETURN(rc);
        else if (rc == 0)
                RETURN(-ENODATA);

        rc = ll_merge_lvb(inode);
        obd_cancel(sbi->ll_dt_exp, lli->lli_smd, LCK_PR, &lockh);
        RETURN(rc);
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
        einfo.ei_cb_bl = ll_extent_lock_callback;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = ll_glimpse_callback;
        einfo.ei_cbdata = NULL;

        oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;
        oinfo.oi_lockh = &lockh;
        oinfo.oi_md = lsm;
        oinfo.oi_flags = LDLM_FL_HAS_INTENT;

        rc = obd_enqueue_rqset(sbi->ll_dt_exp, &oinfo, &einfo);
        if (rc == -ENOENT)
                RETURN(rc);
        if (rc != 0) {
                CERROR("obd_enqueue returned rc %d, "
                       "returning -EIO\n", rc);
                RETURN(rc > 0 ? -EIO : rc);
        }

        lov_stripe_lock(lsm);
        memset(&lvb, 0, sizeof(lvb));
        obd_merge_lvb(sbi->ll_dt_exp, lsm, &lvb, 0);
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
        int rc;
        ENTRY;

        if (lli->lli_flags & LLIF_MDS_SIZE_LOCK)
                RETURN(0);

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
        einfo.ei_cb_bl = ll_extent_lock_callback;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = ll_glimpse_callback;
        einfo.ei_cbdata = inode;

        oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;
        oinfo.oi_lockh = &lockh;
        oinfo.oi_md = lli->lli_smd;
        oinfo.oi_flags = ast_flags | LDLM_FL_HAS_INTENT;

        rc = obd_enqueue_rqset(sbi->ll_dt_exp, &oinfo, &einfo);
        if (rc == -ENOENT)
                RETURN(rc);
        if (rc != 0) {
                CERROR("obd_enqueue returned rc %d, returning -EIO\n", rc);
                RETURN(rc > 0 ? -EIO : rc);
        }

        rc = ll_merge_lvb(inode);

        CDEBUG(D_DLMTRACE, "glimpse: size: %llu, blocks: %llu\n",
               i_size_read(inode), (unsigned long long)inode->i_blocks);

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
        einfo.ei_cb_bl = ll_extent_lock_callback;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = ll_glimpse_callback;
        einfo.ei_cbdata = inode;

        oinfo.oi_policy = *policy;
        oinfo.oi_lockh = lockh;
        oinfo.oi_md = lsm;
        oinfo.oi_flags = ast_flags;

        rc = obd_enqueue(sbi->ll_dt_exp, &oinfo, &einfo, NULL);
        *policy = oinfo.oi_policy;
        if (rc > 0)
                rc = -EIO;

        ll_inode_size_lock(inode, 1);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(sbi->ll_dt_exp, lsm, &lvb, 1);

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

        rc = obd_cancel(sbi->ll_dt_exp, lsm, mode, lockh);

        RETURN(rc);
}

static void ll_set_file_contended(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        cfs_time_t now = cfs_time_current();

        spin_lock(&lli->lli_lock);
        lli->lli_contention_time = now;
        lli->lli_flags |= LLIF_CONTENDED;
        spin_unlock(&lli->lli_lock);
}

void ll_clear_file_contended(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        spin_lock(&lli->lli_lock);
        lli->lli_flags &= ~LLIF_CONTENDED;
        spin_unlock(&lli->lli_lock);
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
                RETURN(1);
        if (lli->lli_flags & LLIF_CONTENDED) {
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

static int ll_file_get_tree_lock(struct ll_lock_tree *tree, struct file *file,
                                 const char *buf, size_t count,
                                 loff_t start, loff_t end, int rw)
{
        int append;
        int tree_locked = 0;
        int rc;
        struct inode * inode = file->f_dentry->d_inode;
        ENTRY;

        append = (rw == WRITE) && (file->f_flags & O_APPEND);

        if (append || !ll_is_file_contended(file)) {
                struct ll_lock_tree_node *node;
                int ast_flags;

                ast_flags = append ? 0 : LDLM_FL_DENY_ON_CONTENTION;
                if (file->f_flags & O_NONBLOCK)
                        ast_flags |= LDLM_FL_BLOCK_NOWAIT;
                node = ll_node_from_inode(inode, start, end,
                                          (rw == WRITE) ? LCK_PW : LCK_PR);
                if (IS_ERR(node)) {
                        rc = PTR_ERR(node);
                        GOTO(out, rc);
                }
                tree->lt_fd = LUSTRE_FPRIVATE(file);
                rc = ll_tree_lock(tree, node, buf, count, ast_flags);
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

static ssize_t ll_file_read(struct file *file, char *buf, size_t count,
                            loff_t *ppos)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_lock_tree tree;
        struct ost_lvb lvb;
        struct ll_ra_read bead;
        int ra = 0;
        loff_t end;
        ssize_t retval, chunk, sum = 0;
        int tree_locked;

        __u64 kms;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),size="LPSZ",offset=%Ld\n",
               inode->i_ino, inode->i_generation, inode, count, *ppos);
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
                notzeroed = clear_user(buf, count);
                count -= notzeroed;
                *ppos += count;
                if (!count)
                        RETURN(-EFAULT);
                RETURN(count);
        }
repeat:
        if (sbi->ll_max_rw_chunk != 0) {
                /* first, let's know the end of the current stripe */
                end = *ppos;
                obd_extent_calc(sbi->ll_dt_exp, lsm, OBD_CALC_STRIPE_END, 
                                (obd_off *)&end);

                /* correct, the end is beyond the request */
                if (end > *ppos + count - 1)
                        end = *ppos + count - 1;

                /* and chunk shouldn't be too large even if striping is wide */
                if (end - *ppos > sbi->ll_max_rw_chunk)
                        end = *ppos + sbi->ll_max_rw_chunk - 1;
        } else {
                end = *ppos + count - 1;
        }

        tree_locked = ll_file_get_tree_lock(&tree, file, buf,
                                            count, *ppos, end, READ);
        if (tree_locked < 0)
                GOTO(out, retval = tree_locked);

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
        obd_merge_lvb(sbi->ll_dt_exp, lsm, &lvb, 1);
        kms = lvb.lvb_size;
        if (*ppos + count - 1 > kms) {
                /* A glimpse is necessary to determine whether we return a
                 * short read (B) or some zeroes at the end of the buffer (C) */
                ll_inode_size_unlock(inode, 1);
                retval = ll_glimpse_size(inode, LDLM_FL_BLOCK_GRANTED);
                if (retval) {
                        if (tree_locked)
                                ll_tree_unlock(&tree);
                        goto out;
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
        CDEBUG(D_INODE, "Read ino %lu, "LPSZ" bytes, offset %lld, i_size %llu\n",
               inode->i_ino, chunk, *ppos, i_size_read(inode));

        if (tree_locked) {
                /* turn off the kernel's read-ahead */
                file->f_ra.ra_pages = 0;

                /* initialize read-ahead window once per syscall */
                if (ra == 0) {
                        ra = 1;
                        bead.lrr_start = *ppos >> CFS_PAGE_SHIFT;
                        bead.lrr_count = (count + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
                        ll_ra_read_in(file, &bead);
                }

                /* BUG: 5972 */
                file_accessed(file);
                retval = generic_file_read(file, buf, chunk, ppos);
                ll_tree_unlock(&tree);
        } else {
                retval = ll_file_lockless_io(file, buf, chunk, ppos, READ);
        }

        ll_rw_stats_tally(sbi, current->pid, file, chunk, 0);

        if (retval > 0) {
                buf += retval;
                count -= retval;
                sum += retval;
                if (retval == chunk && count > 0)
                        goto repeat;
        }

 out:
        if (ra != 0)
                ll_ra_read_ex(file, &bead);
        retval = (sum > 0) ? sum : retval;
        RETURN(retval);
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t ll_file_write(struct file *file, const char *buf, size_t count,
                             loff_t *ppos)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ll_lock_tree tree;
        loff_t maxbytes = ll_file_maxbytes(inode);
        loff_t lock_start, lock_end, end;
        ssize_t retval, chunk, sum = 0;
        int tree_locked;
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

        down(&ll_i2info(inode)->lli_write_sem);

repeat:
        chunk = 0; /* just to fix gcc's warning */
        end = *ppos + count - 1;

        if (file->f_flags & O_APPEND) {
                lock_start = 0;
                lock_end = OBD_OBJECT_EOF;
        } else if (sbi->ll_max_rw_chunk != 0) {
                /* first, let's know the end of the current stripe */
                end = *ppos;
                obd_extent_calc(sbi->ll_dt_exp, lsm, OBD_CALC_STRIPE_END,
                                (obd_off *)&end);

                /* correct, the end is beyond the request */
                if (end > *ppos + count - 1)
                        end = *ppos + count - 1;

                /* and chunk shouldn't be too large even if striping is wide */
                if (end - *ppos > sbi->ll_max_rw_chunk)
                        end = *ppos + sbi->ll_max_rw_chunk - 1;
                lock_start = *ppos;
                lock_end = end;
        } else {
                lock_start = *ppos;
                lock_end = *ppos + count - 1;
        }

        tree_locked = ll_file_get_tree_lock(&tree, file, buf, count,
                                            lock_start, lock_end, WRITE);
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
        CDEBUG(D_INFO, "Writing inode %lu, "LPSZ" bytes, offset %Lu\n",
               inode->i_ino, chunk, *ppos);
        if (tree_locked)
                retval = generic_file_write(file, buf, chunk, ppos);
        else
                retval = ll_file_lockless_io(file, (char*)buf, chunk,
                                             ppos, WRITE);
        ll_rw_stats_tally(ll_i2sbi(inode), current->pid, file, chunk, 1);

out_unlock:
        if (tree_locked)
                ll_tree_unlock(&tree);

out:
        if (retval > 0) {
                buf += retval;
                count -= retval;
                sum += retval;
                if (retval == chunk && count > 0)
                        goto repeat;
        }

        up(&ll_i2info(inode)->lli_write_sem);

        retval = (sum > 0) ? sum : retval;
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_WRITE_BYTES,
                           retval > 0 ? retval : 0);
        RETURN(retval);
}

/*
 * Send file content (through pagecache) somewhere with helper
 */
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

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_READ_BYTES, count);
        /* turn off the kernel's read-ahead */
        in_file->f_ra.ra_pages = 0;

        /* File with no objects, nothing to lock */
        if (!lsm)
                RETURN(generic_file_sendfile(in_file, ppos, count, actor, target));

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
                i_size_write(inode, kms);
                ll_inode_size_unlock(inode, 1);
        }

        CDEBUG(D_INFO, "Send ino %lu, "LPSZ" bytes, offset %lld, i_size %llu\n",
               inode->i_ino, count, *ppos, i_size_read(inode));

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

        oa->o_id = ucreatp.lrc_id;
        oa->o_gr = ucreatp.lrc_group;
        oa->o_nlink = ucreatp.lrc_ost_idx;
        oa->o_flags |= OBD_FL_RECREATE_OBJS;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
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

int ll_lov_setstripe_ea_info(struct inode *inode, struct file *file,
                             int flags, struct lov_user_md *lum, int lum_size)
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
        if (it_disposition(&oit, DISP_LOOKUP_NEG))
                GOTO(out_req_free, rc = -ENOENT);
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
        struct mdt_body  *body;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *req = NULL;
        struct obd_capa *oc;
        int rc, lmmsize;

        rc = ll_get_max_mdsize(sbi, &lmmsize);
        if (rc)
                RETURN(rc);

        oc = ll_mdscapa_get(inode);
        rc = md_getattr_name(sbi->ll_md_exp, ll_inode2fid(inode),
                             oc, filename, strlen(filename) + 1,
                             OBD_MD_FLEASIZE | OBD_MD_FLDIREA, lmmsize,
                             ll_i2suppgid(inode), &req);
        capa_put(oc);
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

        /*
         * This is coming from the MDS, so is probably in
         * little endian.  We convert it to host endian before
         * passing it to userspace.
         */
        if (lmm->lmm_magic == __swab32(LOV_MAGIC)) {
                lustre_swab_lov_user_md((struct lov_user_md *)lmm);
                lustre_swab_lov_user_md_objects((struct lov_user_md *)lmm);
        } else if (lmm->lmm_magic == __swab32(LOV_MAGIC_JOIN)) {
                lustre_swab_lov_user_md_join((struct lov_user_md_join *)lmm);
        }

        if (lmm->lmm_magic == LOV_MAGIC_JOIN) {
                struct lov_stripe_md *lsm;
                struct lov_user_md_join *lmj;
                int lmj_size, i, aindex = 0;

                rc = obd_unpackmd(sbi->ll_dt_exp, &lsm, lmm, lmmsize);
                if (rc < 0)
                        GOTO(out, rc = -ENOMEM);
                rc = obd_checkmd(sbi->ll_dt_exp, sbi->ll_md_exp, lsm);
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
                obd_free_memmd(sbi->ll_dt_exp, &lsm);
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
                                   .it_flags = head_filp->f_flags|O_JOIN_FILE};
        struct ldlm_enqueue_info einfo = { LDLM_IBITS, LCK_CW,
                ll_md_blocking_ast, ldlm_completion_ast, NULL, NULL };

        struct lustre_handle lockh;
        struct md_op_data *op_data;
        int    rc;
        loff_t data;
        ENTRY;

        tail_dentry = tail_filp->f_dentry;

        data = i_size_read(head_inode);
        op_data = ll_prep_md_op_data(NULL, head_inode,
                                     tail_dentry->d_parent->d_inode,
                                     tail_dentry->d_name.name,
                                     tail_dentry->d_name.len, 0,
                                     LUSTRE_OPC_ANY, &data);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        rc = md_enqueue(ll_i2mdexp(head_inode), &einfo, &oit, 
                         op_data, &lockh, NULL, 0, 0);

        ll_finish_md_op_data(op_data);
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
        ll_release_openhandle(head_filp->f_dentry, &oit);
out:
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
        ptlrpc_req_finished(it->d.lustre.it_data);
        it_clear_disposition(it, DISP_ENQ_OPEN_REF);
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
        case IOC_OBD_STATFS:
                RETURN(ll_obd_statfs(inode, (void *)arg));

        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT3_IOC_SETVERSION_OLD:
        case EXT3_IOC_SETVERSION:
        */
        case LL_IOC_FLUSHCTX:
                RETURN(ll_flush_ctx(inode));
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
                struct obdo *oa;
                
                OBDO_ALLOC(oa);
                if (!oa)
                        RETURN(rc ? rc : -ENOMEM);

                oa->o_id = lsm->lsm_object_id;
                oa->o_gr = lsm->lsm_object_gr;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
                obdo_from_inode(oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                           OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                                           OBD_MD_FLGROUP);

                oc = ll_osscapa_get(inode, CAPA_OPC_OSS_WRITE);
                err = obd_sync(ll_i2sbi(inode)->ll_dt_exp, oa, lsm,
                               0, OBD_OBJECT_EOF, oc);
                capa_put(oc);
                if (!rc)
                        rc = err;
                OBDO_FREE(oa);
        }

        RETURN(rc);
}

int ll_file_flock(struct file *file, int cmd, struct file_lock *file_lock)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ldlm_res_id res_id =
                { .name = { fid_seq(ll_inode2fid(inode)),
                            fid_oid(ll_inode2fid(inode)),
                            fid_ver(ll_inode2fid(inode)),
                            LDLM_FLOCK} };
        struct ldlm_enqueue_info einfo = { LDLM_FLOCK, 0, NULL,
                ldlm_flock_completion_ast, NULL, file_lock };
        struct lustre_handle lockh = {0};
        ldlm_policy_data_t flock;
        int flags = 0;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu file_lock=%p\n",
               inode->i_ino, file_lock);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FLOCK, 1);
 
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
                file_lock->fl_type = einfo.ei_mode;
                break;
        default:
                CERROR("unknown fcntl lock command: %d\n", cmd);
                LBUG();
        }

        CDEBUG(D_DLMTRACE, "inode=%lu, pid=%u, flags=%#x, mode=%u, "
               "start="LPU64", end="LPU64"\n", inode->i_ino, flock.l_flock.pid,
               flags, einfo.ei_mode, flock.l_flock.start, flock.l_flock.end);

        rc = ldlm_cli_enqueue(sbi->ll_md_exp, NULL, &einfo, &res_id,
                              &flock, &flags, NULL, 0, NULL, &lockh, 0);
        if ((file_lock->fl_flags & FL_FLOCK) && (rc == 0))
                ll_flock_lock_file_wait(file, file_lock, (cmd == F_SETLKW));
#ifdef HAVE_F_OP_FLOCK
        if ((file_lock->fl_flags & FL_POSIX) && (rc == 0) &&
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
        CDEBUG(D_INFO, "trying to match res "DFID"\n", PFID(fid));

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
        if (md_lock_match(ll_i2mdexp(inode), flags, fid, LDLM_IBITS, &policy,
                          LCK_CR|LCK_CW|LCK_PR|LCK_PW, &lockh)) {
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

int ll_inode_revalidate_it(struct dentry *dentry, struct lookup_intent *it)
{
        struct inode *inode = dentry->d_inode;
        struct ptlrpc_request *req = NULL;
        struct ll_sb_info *sbi;
        struct obd_export *exp;
        int rc;
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }
        sbi = ll_i2sbi(inode);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),name=%s\n",
               inode->i_ino, inode->i_generation, inode, dentry->d_name.name);

        exp = ll_i2mdexp(inode);

        if (exp->exp_connect_flags & OBD_CONNECT_ATTRFID) {
                struct lookup_intent oit = { .it_op = IT_GETATTR };
                struct md_op_data *op_data;

                /* Call getattr by fid, so do not provide name at all. */
                op_data = ll_prep_md_op_data(NULL, dentry->d_parent->d_inode,
                                             dentry->d_inode, NULL, 0, 0,
                                             LUSTRE_OPC_ANY, NULL);
                if (IS_ERR(op_data))
                        RETURN(PTR_ERR(op_data));

                oit.it_flags |= O_CHECK_STALE;
                rc = md_intent_lock(exp, op_data, NULL, 0,
                                    /* we are not interested in name
                                       based lookup */
                                    &oit, 0, &req,
                                    ll_md_blocking_ast, 0);
                ll_finish_md_op_data(op_data);
                oit.it_flags &= ~O_CHECK_STALE;
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
                        spin_lock(&dcache_lock);
                        ll_drop_dentry(dentry);
                        spin_unlock(&dcache_lock);
                }

                ll_lookup_finish_locks(&oit, dentry);
        } else if (!ll_have_md_lock(dentry->d_inode, MDS_INODELOCK_UPDATE |
                                                     MDS_INODELOCK_LOOKUP)) {
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                obd_valid valid = OBD_MD_FLGETATTR;
                struct obd_capa *oc;
                int ealen = 0;

                if (S_ISREG(inode->i_mode)) {
                        rc = ll_get_max_mdsize(sbi, &ealen);
                        if (rc)
                                RETURN(rc);
                        valid |= OBD_MD_FLEASIZE | OBD_MD_FLMODEASIZE;
                }
                /* Once OBD_CONNECT_ATTRFID is not supported, we can't find one
                 * capa for this inode. Because we only keep capas of dirs
                 * fresh. */
                oc = ll_mdscapa_get(inode);
                rc = md_getattr(sbi->ll_md_exp, ll_inode2fid(inode), oc, valid,
                                ealen, &req);
                capa_put(oc);
                if (rc) {
                        rc = ll_inode_revalidate_fini(inode, rc);
                        RETURN(rc);
                }

                rc = ll_prep_inode(&inode, req, NULL);
                if (rc)
                        GOTO(out, rc);
        }

        /* if object not yet allocated, don't validate size */
        if (ll_i2info(inode)->lli_smd == NULL)
                GOTO(out, rc = 0);

        /* ll_glimpse_size will prefer locally cached writes if they extend
         * the file */
        rc = ll_glimpse_size(inode, 0);
        EXIT;
out:
        ptlrpc_req_finished(req);
        return rc;
}

int ll_getattr_it(struct vfsmount *mnt, struct dentry *de,
                  struct lookup_intent *it, struct kstat *stat)
{
        struct inode *inode = de->d_inode;
        int res = 0;

        res = ll_inode_revalidate_it(de, it);
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETATTR, 1);

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
#ifdef HAVE_INODE_BLKSIZE
        stat->blksize = inode->i_blksize;
#else
        stat->blksize = 1 << inode->i_blkbits;
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
        if (ll_i2sbi(inode)->ll_flags & LL_SBI_RMT_CLIENT)
                return lustre_check_remote_perm(inode, mask);
        
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_INODE_PERM, 1);
        return generic_permission(inode, mask, lustre_check_acl);
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

/* -o localflock - only provides locally consistent flock locks */
struct file_operations ll_file_operations = {
        .read           = ll_file_read,
        .write          = ll_file_write,
        .ioctl          = ll_file_ioctl,
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
        .sendfile       = ll_file_sendfile,
        .fsync          = ll_fsync,
};

struct file_operations ll_file_operations_flock = {
        .read           = ll_file_read,
        .write          = ll_file_write,
        .ioctl          = ll_file_ioctl,
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
        .sendfile       = ll_file_sendfile,
        .fsync          = ll_fsync,
#ifdef HAVE_F_OP_FLOCK
        .flock          = ll_file_flock,
#endif
        .lock           = ll_file_flock
};

/* These are for -o noflock - to return ENOSYS on flock calls */
struct file_operations ll_file_operations_noflock = {
        .read           = ll_file_read,
        .write          = ll_file_write,
        .ioctl          = ll_file_ioctl,
        .open           = ll_file_open,
        .release        = ll_file_release,
        .mmap           = ll_file_mmap,
        .llseek         = ll_file_seek,
        .sendfile       = ll_file_sendfile,
        .fsync          = ll_fsync,
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
