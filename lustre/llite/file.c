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

int ll_inode_setattr(struct inode *inode, struct iattr *attr, int do_trunc);
extern int ll_setattr(struct dentry *de, struct iattr *attr);

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
                       inode->i_mode, &fd->fd_mdshandle, &req);
        if (rc)
                CERROR("inode %lu close failed: rc = %d\n", inode->i_ino, rc);

        imp = fd->fd_req->rq_import;
        LASSERT(imp != NULL);
        spin_lock_irqsave(&imp->imp_lock, flags);

        DEBUG_REQ(D_HA, fd->fd_req, "matched open req %p", fd->fd_req);

        /* We held on to the request for replay until we saw a close for that
         * file.  Now that we've closed it, it gets replayed on the basis of
         * its transno only. */
        fd->fd_req->rq_flags &= ~PTL_RPC_FL_REPLAY;

        if (fd->fd_req->rq_transno) {
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
                        req->rq_transno = fd->fd_req->rq_transno;
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
        ptlrpc_req_finished(fd->fd_req);

        /* Do this after the fd_req->rq_transno check, because we don't want
         * to bounce off zero references. */
        ptlrpc_req_finished(req);
        fd->fd_mdshandle.cookie = DEAD_HANDLE_MAGIC;
        file->private_data = NULL;
        kmem_cache_free(ll_file_data_slab, fd);

        RETURN(-abs(rc));
}

/* While this returns an error code, fput() the caller does not, so we need
 * to make every effort to clean up all of our state here.  Also, applications
 * rarely check close errors and even if an error is returned they will not
 * re-try the close call.
 */
static int ll_file_release(struct inode *inode, struct file *file)
{
        struct ll_file_data *fd;
        struct obdo oa;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        int rc = 0, rc2;

        ENTRY;

        fd = (struct ll_file_data *)file->private_data;
        if (!fd) /* no process opened the file after an mcreate */
                RETURN(rc = 0);

        /* we might not be able to get a valid handle on this file
         * again so we really want to flush our write cache.. */
        filemap_fdatasync(inode->i_mapping);
        filemap_fdatawait(inode->i_mapping);

        if (lsm != NULL) {
                memset(&oa, 0, sizeof(oa));
                oa.o_id = lsm->lsm_object_id;
                oa.o_mode = S_IFREG;
                oa.o_valid = OBD_MD_FLTYPE | OBD_MD_FLID;

                memcpy(&oa.o_inline, fd->fd_ostdata, FD_OSTDATA_SIZE);
                oa.o_valid |= OBD_MD_FLHANDLE;

                rc = obd_close(&sbi->ll_osc_conn, &oa, lsm, NULL);
                if (rc)
                        CERROR("inode %lu object close failed: rc = %d\n",
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
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
        ENTRY;

        LASSERT(!file->private_data);

        fd = kmem_cache_alloc(ll_file_data_slab, SLAB_KERNEL);
        /* We can't handle this well without reorganizing ll_file_open and
         * ll_mdc_close, so don't even try right now. */
        LASSERT(fd != NULL);

        memset(fd, 0, sizeof(*fd));

        memcpy(&fd->fd_mdshandle, &body->handle, sizeof(body->handle));
        fd->fd_req = it->it_data;
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
        oa->o_valid = (OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLBLOCKS |
                       OBD_MD_FLMTIME | OBD_MD_FLCTIME);
        rc = obd_open(conn, oa, lsm, NULL);
        if (rc)
                GOTO(out, rc);

        file->f_flags &= ~O_LOV_DELAY_CREATE;
        obdo_to_inode(inode, oa, OBD_MD_FLBLOCKS | OBD_MD_FLMTIME |
                      OBD_MD_FLCTIME);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                memcpy(fd->fd_ostdata, obdo_handle(oa), FD_OSTDATA_SIZE);

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
        int rc, err, lmm_size = 0;;
        ENTRY;

        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);

        oa->o_mode = S_IFREG | 0600;
        oa->o_id = inode->i_ino;
        /* Keep these 0 for now, because chown/chgrp does not change the
         * ownership on the OST, and we don't want to allow BA OST NFS
         * users to access these objects by mistake.
         */
        oa->o_uid = 0;
        oa->o_gid = 0;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE |
                OBD_MD_FLUID | OBD_MD_FLGID;

        rc = obd_create(conn, oa, &lsm, NULL);
        if (rc) {
                CERROR("error creating objects for inode %lu: rc = %d\n",
                       inode->i_ino, rc);
                if (rc > 0) {
                        CERROR("obd_create returned invalid rc %d\n", rc);
                        rc = -EIO;
                }
                GOTO(out_oa, rc);
        }

        LASSERT(lsm && lsm->lsm_object_id);
        rc = obd_packmd(conn, &lmm, lsm);
        if (rc < 0)
                GOTO(out_destroy, rc);

        lmm_size = rc;

        /* Save the stripe MD with this file on the MDS */
        memset(&iattr, 0, sizeof(iattr));
        iattr.ia_valid = ATTR_FROM_OPEN;
        rc = mdc_setattr(&ll_i2sbi(inode)->ll_mdc_conn, inode, &iattr,
                         lmm, lmm_size, &req);
        ptlrpc_req_finished(req);

        obd_free_wiremd(conn, &lmm);

        /* If we couldn't complete mdc_open() and store the stripe MD on the
         * MDS, we need to destroy the objects now or they will be leaked.
         */
        if (rc) {
                CERROR("error: storing stripe MD for %lu: rc %d\n",
                       inode->i_ino, rc);
                GOTO(out_destroy, rc);
        }
        lli->lli_smd = lsm;

        EXIT;
out_oa:
        obdo_free(oa);
        return rc;

out_destroy:
        obdo_from_inode(oa, inode, OBD_MD_FLTYPE);
        oa->o_id = lsm->lsm_object_id;
        oa->o_valid |= OBD_MD_FLID;
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
extern int ll_it_open_error(int phase, struct lookup_intent *it);

static int ll_file_open(struct inode *inode, struct file *file)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle *conn = ll_i2obdconn(inode);
        struct lookup_intent *it;
        struct lov_stripe_md *lsm;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        LL_GET_INTENT(file->f_dentry, it);
        rc = ll_it_open_error(IT_OPEN_OPEN, it);
        if (rc)
                RETURN(rc);

        rc = ll_local_open(file, it);
        if (rc)
                LBUG();

        mdc_set_open_replay_data((struct ll_file_data *)file->private_data);

        lsm = lli->lli_smd;
        if (lsm == NULL) {
                if (file->f_flags & O_LOV_DELAY_CREATE) {
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
                     char *ostdata)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct obdo oa;
        int rc;
        ENTRY;

        LASSERT(lsm);
        LASSERT(sbi);

        memset(&oa, 0, sizeof oa);
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS | OBD_MD_FLMTIME | OBD_MD_FLCTIME;

        if (ostdata != NULL) {
                memcpy(&oa.o_inline, ostdata, FD_OSTDATA_SIZE);
                oa.o_valid |= OBD_MD_FLHANDLE;
        }

        rc = obd_getattr(&sbi->ll_osc_conn, &oa, lsm);
        if (rc)
                RETURN(rc);

        obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                           OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        CDEBUG(D_INODE, "objid "LPX64" size %Lu/%Lu\n", lsm->lsm_object_id,
               inode->i_size, inode->i_size);
        RETURN(0);
}

/*
 * we've acquired a lock and need to see if we should perform a getattr
 * to update the file size that may have been updated by others that had
 * their locks canceled.
 */
static int ll_size_validate(struct inode *inode, struct lov_stripe_md *lsm,
                            char *ostdata, struct ldlm_extent *extent)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        ENTRY;

        if (test_bit(LLI_F_DID_GETATTR, &lli->lli_flags))
                RETURN(0);

        down(&lli->lli_getattr_sem);

        if (!test_bit(LLI_F_DID_GETATTR, &lli->lli_flags)) {
                rc = ll_inode_getattr(inode, lsm, ostdata);
                if ( rc == 0 ) 
                        set_bit(LLI_F_DID_GETATTR, &lli->lli_flags);
        }

        up(&lli->lli_getattr_sem);
        RETURN(rc);
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

        LASSERT(lockh->addr == 0 && lockh->cookie == 0);

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        CDEBUG(D_INFO, "Locking inode %lu, start "LPU64" end "LPU64"\n",
               inode->i_ino, extent->start, extent->end);

        rc = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT, extent,
                         sizeof(extent), mode, &flags, ll_lock_callback,
                         inode, sizeof(*inode), lockh);

        RETURN(rc);
}
/*
 * this grabs a lock and manually implements behaviour that makes it look
 * like the OST is returning the file size with each lock acquisition
 */
int ll_extent_lock(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm,
                   int mode, struct ldlm_extent *extent,
                   struct lustre_handle *lockh)
{
        int rc;
        ENTRY;

        rc = ll_extent_lock_no_validate(fd, inode, lsm, mode, extent, lockh);

        if (rc == ELDLM_OK) {
                rc = ll_size_validate(inode, lsm, fd ? fd->fd_ostdata : NULL,
                        extent);
                if ( rc != 0 ) {
                        ll_extent_unlock(fd, inode, lsm, mode, lockh);
                        rc = ELDLM_GETATTR_ERROR;
                }
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

        rc = obd_cancel(&sbi->ll_osc_conn, lsm, mode, lockh);

        RETURN(rc);
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

static void ll_update_atime(struct inode *inode)
{
#ifdef USE_ATIME
        struct iattr attr;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        attr.ia_atime = CURRENT_TIME;
#else
        attr.ia_atime = CURRENT_TIME.tv_sec;
#endif
        attr.ia_valid = ATTR_ATIME;

        if (inode->i_atime == attr.ia_atime) return;
        if (IS_RDONLY(inode)) return;
        if (IS_NOATIME(inode)) return;

        /* ll_inode_setattr() sets inode->i_atime from attr.ia_atime */
        ll_inode_setattr(inode, &attr, 0);
#else
        /* update atime, but don't explicitly write it out just this change */
        inode->i_atime = CURRENT_TIME;
#endif
}

int ll_lock_callback(struct ldlm_lock *lock, struct ldlm_lock_desc *new,
                     void *data, int flag)
{
        struct inode *inode = data;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle lockh = { 0, 0 };
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op\n");

        if (inode == NULL)
                LBUG();

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
                CDEBUG(D_INODE, "invalidating obdo/inode %lu\n", inode->i_ino);
                filemap_fdatasync(inode->i_mapping);
                filemap_fdatawait(inode->i_mapping);
                clear_bit(LLI_F_DID_GETATTR, &lli->lli_flags);
                truncate_inode_pages(inode->i_mapping, 0);
                break;
        default:
                LBUG();
        }

        RETURN(0);
}

static ssize_t ll_file_read(struct file *filp, char *buf, size_t count,
                            loff_t *ppos)
{
        struct ll_file_data *fd = filp->private_data;
        struct inode *inode = filp->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct lustre_handle lockh = { 0, 0 };
        struct ll_read_extent rextent;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op\n");

        /* "If nbyte is 0, read() will return 0 and have no other results."
         *                      -- Single Unix Spec */
        if (count == 0)
                RETURN(0);

        rextent.re_extent.start = *ppos;
        rextent.re_extent.end = *ppos + count - 1;

        err = ll_extent_lock(fd, inode, lsm, 
                             LCK_PR, &rextent.re_extent, &lockh);
        if (err != ELDLM_OK && err != ELDLM_LOCK_MATCHED) {
                retval = -ENOLCK;
                RETURN(retval);
        }

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

        if (retval > 0)
                ll_update_atime(inode);

        /* XXX errors? */
        ll_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
        RETURN(retval);
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t
ll_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
        struct ll_file_data *fd = file->private_data;
        struct inode *inode = file->f_dentry->d_inode;
        struct lustre_handle lockh = { 0, 0 };
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ldlm_extent extent;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;

        /* POSIX, but surprised the VFS doesn't check this already */
        if (count == 0)
                RETURN(0);

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        if (!S_ISBLK(inode->i_mode) && file->f_flags & O_APPEND) {
                extent.start = 0;
                extent.end = OBD_OBJECT_EOF;
        } else  {
                extent.start = *ppos;
                extent.end = *ppos + count - 1;
        }

        err = ll_extent_lock(fd, inode, lsm, LCK_PW, &extent, &lockh);
        if (err != ELDLM_OK && err != ELDLM_LOCK_MATCHED) {
                retval = -ENOLCK;
                RETURN(retval);
        }

        if (!S_ISBLK(inode->i_mode) && file->f_flags & O_APPEND)
                *ppos = inode->i_size;

        CDEBUG(D_INFO, "Writing inode %lu, "LPSZ" bytes, offset %Lu\n",
               inode->i_ino, count, *ppos);

        retval = generic_file_write(file, buf, count, ppos);

        /* XXX errors? */
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
                CERROR("stripe already set for ino %lu\n", inode->i_ino);
                /* If we haven't already done the open, do so now */
                if (file->f_flags & O_LOV_DELAY_CREATE) {
                        int rc2 = ll_osc_open(conn, inode, file, lsm);
                        if (rc2)
                                RETURN(rc2);
                }

                RETURN(-EALREADY);
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

        CDEBUG(D_VFSTRACE, "VFS Op\n");

        if ((cmd & 0xffffff00) == ((int)'T') << 8) /* tty ioctls */
                return -ENOTTY;

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
        struct lustre_handle lockh = {0, 0};
        loff_t retval;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        if (origin == 2) { /* SEEK_END */
                ldlm_error_t err;
                struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                err = ll_extent_lock(fd, inode, lsm, LCK_PR, &extent, &lockh);
                if (err != ELDLM_OK && err != ELDLM_LOCK_MATCHED) {
                        retval = -ENOLCK;
                        RETURN(retval);
                }

                offset += inode->i_size;
        } else if (origin == 1) { /* SEEK_CUR */
                offset += file->f_pos;
        }

        retval = -EINVAL;
        if (offset >= 0 && offset <= inode->i_sb->s_maxbytes) {
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
        int ret;
        ENTRY;

        /*
         * filemap_fdata{sync,wait} are also called at PW lock cancelation so
         * we know that they can only find data to writeback here if we are
         * still holding the PW lock that covered the dirty pages.  XXX we
         * should probably get a reference on it, though, just to be clear.
         */
        ret = filemap_fdatasync(dentry->d_inode->i_mapping);
        if ( ret == 0 )
                ret = filemap_fdatawait(dentry->d_inode->i_mapping);

        RETURN(ret);
}

int ll_inode_revalidate(struct dentry *dentry)
{
        struct inode *inode = dentry->d_inode;
        struct lov_stripe_md *lsm;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }

        /* this is very tricky.  it is unsafe to call ll_have_md_lock
           when we have a referenced lock: because it may cause an RPC
           below when the lock is marked CB_PENDING.  That RPC may not
           go out because someone else may be in another RPC waiting for
           that lock*/
        if (!(dentry->d_it && dentry->d_it->it_lock_mode) &&
            !ll_have_md_lock(dentry)) {
                struct ptlrpc_request *req = NULL;
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                struct mds_body *body;
                unsigned long valid = 0;
                int datalen = 0, rc;

                /* Why don't we update all valid MDS fields here, if we're
                 * doing an RPC anyways?  -phil */
                if (S_ISREG(inode->i_mode)) {
                        datalen = obd_size_wiremd(&sbi->ll_osc_conn, NULL);
                        valid |= OBD_MD_FLEASIZE;
                }
                rc = mdc_getattr(&sbi->ll_mdc_conn, inode->i_ino,
                                 inode->i_mode, valid, datalen, &req);
                if (rc) {
                        CERROR("failure %d inode %lu\n", rc, inode->i_ino);
                        ptlrpc_req_finished(req);
                        RETURN(-abs(rc));
                }

                body = lustre_msg_buf(req->rq_repmsg, 0);

                if (S_ISREG(inode->i_mode) &&
                    body->valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) {
                        CERROR("MDS sent back size for regular file\n");
                        body->valid &= ~(OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);
                }

                if (body->valid & OBD_MD_FLEASIZE)
                        ll_update_inode(inode, body,
                                        lustre_msg_buf(req->rq_repmsg, 1));
                else
                        ll_update_inode(inode, body, NULL);
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
                struct lustre_handle lockh = {0, 0};
                ldlm_error_t err;

                err = ll_extent_lock(NULL, inode, lsm, LCK_PR, &extent, &lockh);
                if (err != ELDLM_OK && err != ELDLM_LOCK_MATCHED )
                        RETURN(-abs(err)); /* XXX can't be right */

                ll_extent_unlock(NULL, inode, lsm, LCK_PR, &lockh);
        }
        RETURN(0);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int ll_getattr(struct vfsmount *mnt, struct dentry *de,
                      struct kstat *stat)
{
        int res = 0;
        struct inode *inode = de->d_inode;

        res = ll_inode_revalidate(de);
        if (res)
                return res;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        stat->dev = inode->i_dev;
#endif
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
        getattr: ll_getattr,
#else
        revalidate: ll_inode_revalidate,
#endif
};

struct inode_operations ll_special_inode_operations = {
        setattr_raw:    ll_setattr_raw,
        setattr:    ll_setattr,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        getattr:    ll_getattr,
#else
        revalidate: ll_inode_revalidate,
#endif
};
