/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/ext2/file.c
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *      (jj@sunsite.ms.mff.cuni.cz)
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_dlm.h>
#include <linux/lustre_lite.h>
#include <linux/obd_lov.h>      /* for lov_mds_md_size() in lov_setstripe() */
#include <linux/random.h>

int ll_inode_setattr(struct inode *inode, struct iattr *attr, int do_trunc);
extern int ll_setattr(struct dentry *de, struct iattr *attr);

static int ll_mdc_open(struct lustre_handle *mdc_conn, struct inode *inode,
                       struct file *file, struct lov_mds_md *lmm, int lmm_size)
{
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        int rc;
        ENTRY;

        LASSERT(!file->private_data);

        fd = kmem_cache_alloc(ll_file_data_slab, SLAB_KERNEL);
        if (!fd)
                RETURN(-ENOMEM);

        memset(fd, 0, sizeof(*fd));
        fd->fd_mdshandle.addr = (__u64)(unsigned long)file;
        get_random_bytes(&fd->fd_mdshandle.cookie,
                         sizeof(fd->fd_mdshandle.cookie));

        rc = mdc_open(mdc_conn, inode->i_ino, S_IFREG | inode->i_mode,
                      file->f_flags, lmm, lmm_size, &fd->fd_mdshandle, &req);

        /* This is the "reply" refcount. */
        ptlrpc_req_finished(req);

        if (rc)
                GOTO(out_fd, rc);

        fd->fd_req = req;
        file->private_data = fd;

        if (!fd->fd_mdshandle.addr ||
            fd->fd_mdshandle.addr == (__u64)(unsigned long)file) {
                CERROR("hmm, mdc_open didn't assign fd_mdshandle?\n");
                /* XXX handle this how, abort or is it non-fatal? */
        }

        file->f_flags &= ~O_LOV_DELAY_CREATE;
        RETURN(0);

out_fd:
        fd->fd_mdshandle.cookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(ll_file_data_slab, fd);

        return -abs(rc);
}

static int ll_mdc_close(struct lustre_handle *mdc_conn, struct inode *inode,
                        struct file *file)
{
        struct ll_file_data *fd = file->private_data;
        struct ptlrpc_request *req = NULL;
        unsigned long flags;
        struct obd_import *imp = fd->fd_req->rq_import;
        int rc;

        /* Complete the open request and remove it from replay list */
        DEBUG_REQ(D_HA, fd->fd_req, "matched open req %p", fd->fd_req);
        rc = mdc_close(&ll_i2sbi(inode)->ll_mdc_conn, inode->i_ino,
                       inode->i_mode, &fd->fd_mdshandle, &req);

        if (rc)
                CERROR("inode %lu close failed: rc = %d\n", inode->i_ino, rc);
        ptlrpc_req_finished(req);

        spin_lock_irqsave(&imp->imp_lock, flags);
        if (fd->fd_req->rq_transno) {
                /* This caused an EA to be written, need to replay as a normal
                 * transaction now.  Our reference is now effectively owned
                 * by the imp_replay_list, and we'll be committed just like
                 * other transno-having requests now.
                 */
                fd->fd_req->rq_flags &= ~PTL_RPC_FL_REPLAY;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
        } else {
                /* No transno means that we can just drop our ref. */
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                ptlrpc_req_finished(fd->fd_req);
        }
        fd->fd_mdshandle.cookie = DEAD_HANDLE_MAGIC;
        file->private_data = NULL;
        kmem_cache_free(ll_file_data_slab, fd);

        return -abs(rc);
}

static int ll_osc_open(struct lustre_handle *conn, struct inode *inode,
                       struct file *file, struct lov_stripe_md *lsm)
{
        struct ll_file_data *fd;
        struct obdo *oa;
        int rc;
        ENTRY;

        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);
        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = S_IFREG;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS;
        rc = obd_open(conn, oa, lsm);
        if (rc)
                GOTO(out, rc);

        obdo_to_inode(inode, oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

        fd = file->private_data;
        obd_oa2handle(&fd->fd_osthandle, oa);

        atomic_inc(&ll_i2info(inode)->lli_open_count);
out:
        obdo_free(oa);
        RETURN(rc);
}

/* Caller must hold lli_open_sem to protect lli->lli_smd from changing and
 * duplicate objects from being created.  We only install lsm to lli_smd if
 * the mdc open was successful (hence stored stripe MD on MDS), otherwise
 * other nodes could try to create different objects for the same file.
 */
static int ll_create_open_obj(struct lustre_handle *conn, struct inode *inode,
                              struct file *file, struct lov_stripe_md *lsm)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_mds_md *lmm = NULL;
        int lmm_size = 0;
        struct obdo *oa;
        int rc, err;
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

        rc = obd_create(conn, oa, &lsm);
        if (rc) {
                CERROR("error creating objects for inode %lu: rc = %d\n",
                       inode->i_ino, rc);
                GOTO(out_oa, rc);
        }

        LASSERT(lsm && lsm->lsm_object_id);
        rc = obd_packmd(conn, &lmm, lsm);
        if (rc < 0)
                GOTO(out_destroy, rc);

        lmm_size = rc;

        rc = ll_mdc_open(&ll_i2sbi(inode)->ll_mdc_conn,inode,file,lmm,lmm_size);

        obd_free_wiremd(conn, &lmm);

        /* If we couldn't complete mdc_open() and store the stripe MD on the
         * MDS, we need to destroy the objects now or they will be leaked.
         */
        if (rc) {
                CERROR("error MDS opening %lu with delayed create: rc %d\n",
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
        err = obd_destroy(conn, oa, lsm);
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
 * If we already have the stripe MD locally, we don't request it in
 * mdc_open() by passing a lmm_size = 0.
 *
 * It is up to the application to ensure no other processes open this file
 * in the O_LOV_DELAY_CREATE case, or the default striping pattern will be
 * used.  We might be able to avoid races of that sort by getting lli_open_sem
 * before returning in the O_LOV_DELAY_CREATE case and dropping it here
 * or in ll_file_release(), but I'm not sure that is desirable/necessary.
 */
static int ll_file_open(struct inode *inode, struct file *file)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle *conn = ll_i2obdconn(inode);
        struct lov_stripe_md *lsm;
        int rc = 0;
        ENTRY;

        lsm = lli->lli_smd;
        if (lsm == NULL) {
                if (file->f_flags & O_LOV_DELAY_CREATE) {
                        CDEBUG(D_INODE, "delaying object creation\n");
                        RETURN(0);
                }

                down(&lli->lli_open_sem);
                if (!lli->lli_smd) {
                        rc = ll_create_open_obj(conn, inode, file, NULL);
                        up(&lli->lli_open_sem);
                } else {
                        CERROR("stripe already set on ino %lu\n", inode->i_ino);
                        up(&lli->lli_open_sem);
                        rc = ll_mdc_open(&sbi->ll_mdc_conn, inode, file,NULL,0);
                }
                lsm = lli->lli_smd;
        } else
                rc = ll_mdc_open(&sbi->ll_mdc_conn, inode, file, NULL, 0);

        if (rc)
                RETURN(rc);

        rc = ll_osc_open(conn, inode, file, lsm);
        if (rc)
                GOTO(out_close, rc);
        RETURN(0);
out_close:
        ll_mdc_close(&sbi->ll_mdc_conn, inode, file);
        return rc;
}

int ll_size_lock(struct inode *inode, struct lov_stripe_md *lsm, obd_off start,
                 int mode, struct lustre_handle *lockh)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ldlm_extent extent;
        int rc, flags = 0;
        ENTRY;

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if (sbi->ll_flags & LL_SBI_NOLCK)
                RETURN(0);

        extent.start = start;
        extent.end = OBD_OBJECT_EOF;

        rc = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT, &extent,
                         sizeof(extent), mode, &flags, ll_lock_callback,
                         inode, sizeof(*inode), lockh);
        RETURN(rc);
}

int ll_size_unlock(struct inode *inode, struct lov_stripe_md *lsm, int mode,
                   struct lustre_handle *lockh)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc;
        ENTRY;

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if (sbi->ll_flags & LL_SBI_NOLCK)
                RETURN(0);

        rc = obd_cancel(&sbi->ll_osc_conn, lsm, mode, lockh);
        if (rc != ELDLM_OK) {
                CERROR("lock cancel: %d\n", rc);
                LBUG();
        }

        RETURN(rc);
}

int ll_file_size(struct inode *inode, struct lov_stripe_md *lsm)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        //struct lustre_handle lockh = { 0, 0 };
        struct obdo oa;
        //int err;
        int rc;
        ENTRY;

        LASSERT(lsm);
        LASSERT(sbi);

        /* XXX do not yet need size lock - OST size always correct (sync write)
        rc = ll_size_lock(inode, lsm, 0, LCK_PR, &lockh);
        if (rc != ELDLM_OK) {
                CERROR("lock enqueue: %d\n", rc);
                RETURN(rc);
        }
        */

        memset(&oa, 0, sizeof oa);
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLID|OBD_MD_FLTYPE|OBD_MD_FLSIZE|OBD_MD_FLBLOCKS;
        rc = obd_getattr(&sbi->ll_osc_conn, &oa, lsm);
        if (!rc) {
                obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);
                CDEBUG(D_INODE, LPX64" size %Lu/%Lu\n",
                       lsm->lsm_object_id, inode->i_size, inode->i_size);
        }
        /* XXX do not need size lock, because OST size always correct (sync write)
        err = ll_size_unlock(inode, lsm, LCK_PR, &lockh);
        if (err != ELDLM_OK) {
                CERROR("lock cancel: %d\n", err);
                if (!rc)
                        rc = err;
        }
        */
        RETURN(rc);
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
        int rc, rc2;

        ENTRY;

        fd = (struct ll_file_data *)file->private_data;
        if (!fd) /* no process opened the file after an mcreate */
                RETURN(rc = 0);

        memset(&oa, 0, sizeof(oa));
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLTYPE | OBD_MD_FLID;
        obd_handle2oa(&oa, &fd->fd_osthandle);
        rc = obd_close(&sbi->ll_osc_conn, &oa, lsm);
        if (rc)
                CERROR("inode %lu object close failed: rc = %d\n",
                       inode->i_ino, rc);

        rc2 = ll_mdc_close(&sbi->ll_mdc_conn, inode, file);
        if (rc2 && !rc)
                rc = rc2;

        if (atomic_dec_and_test(&lli->lli_open_count)) {
                CDEBUG(D_INFO, "last close, cancelling unused locks\n");
                rc2 = obd_cancel_unused(&sbi->ll_osc_conn, lsm, 0);
                if (rc2 && !rc) {
                        rc = rc2;
                        CERROR("obd_cancel_unused: %d\n", rc);
                }
        } else
                CDEBUG(D_INFO, "not last close, not cancelling unused locks\n");

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
        struct iattr attr;

        attr.ia_atime = CURRENT_TIME;
        attr.ia_valid = ATTR_ATIME;

        if (inode->i_atime == attr.ia_atime) return;
        if (IS_RDONLY(inode)) return;
        if (IS_NOATIME(inode)) return;

        /* ll_inode_setattr() sets inode->i_atime from attr.ia_atime */
        ll_inode_setattr(inode, &attr, 0);
}

int ll_lock_callback(struct ldlm_lock *lock, struct ldlm_lock_desc *new,
                     void *data, __u32 data_len, int flag)
{
        struct inode *inode = data;
        struct lustre_handle lockh = { 0, 0 };
        int rc;
        ENTRY;

        if (data_len != sizeof(struct inode))
                LBUG();

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
                CDEBUG(D_INODE, "invalidating obdo/inode %lu\n", inode->i_ino);
                /* FIXME: do something better than throwing away everything */
                //down(&inode->i_sem);
                ll_invalidate_inode_pages(inode);
                //up(&inode->i_sem);
                break;
        default:
                LBUG();
        }

        RETURN(0);
}

static ssize_t ll_file_read(struct file *filp, char *buf, size_t count,
                            loff_t *ppos)
{
        struct ll_file_data *fd = (struct ll_file_data *)filp->private_data;
        struct inode *inode = filp->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_handle lockh = { 0, 0 };
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        int flags = 0;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;

        /* If we don't refresh the file size, generic_file_read may not even
         * call us */
        retval = ll_file_size(inode, lsm);
        if (retval < 0) {
                CERROR("ll_file_size: "LPSZ"\n", retval);
                RETURN(retval);
        }

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK) &&
            !(sbi->ll_flags & LL_SBI_NOLCK)) {
                struct ldlm_extent extent;
                extent.start = *ppos;
                extent.end = *ppos + count;
                CDEBUG(D_INFO, "Locking inode %lu, start "LPU64" end "LPU64"\n",
                       inode->i_ino, extent.start, extent.end);

                err = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT,
                                  &extent, sizeof(extent), LCK_PR, &flags,
                                  ll_lock_callback, inode, sizeof(*inode),
                                  &lockh);
                if (err != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", err);
                        RETURN(err);
                }
        }

        CDEBUG(D_INFO, "Reading inode %lu, "LPSZ" bytes, offset %Ld\n",
               inode->i_ino, count, *ppos);
        retval = generic_file_read(filp, buf, count, ppos);

        if (retval > 0)
                ll_update_atime(inode);

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK) &&
            !(sbi->ll_flags & LL_SBI_NOLCK)) {
                err = obd_cancel(&sbi->ll_osc_conn, lsm, LCK_PR, &lockh);
                if (err != ELDLM_OK) {
                        CERROR("lock cancel: err: %d\n", err);
                        retval = err;
                }
        }

        RETURN(retval);
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t
ll_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
        struct ll_file_data *fd = (struct ll_file_data *)file->private_data;
        struct inode *inode = file->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_handle lockh = { 0, 0 }, eof_lockh = { 0, 0 };
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        int flags = 0;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;

        if (!S_ISBLK(inode->i_mode) && file->f_flags & O_APPEND) {
                struct obdo *oa;

                oa = obdo_alloc();
                if (!oa)
                        RETURN(-ENOMEM);

                err = ll_size_lock(inode, lsm, 0, LCK_PW, &eof_lockh);
                if (err) {
                        obdo_free(oa);
                        RETURN(err);
                }

                oa->o_id = lsm->lsm_object_id;
                oa->o_mode = inode->i_mode;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                        OBD_MD_FLBLOCKS;
                obd_handle2oa(oa, &fd->fd_osthandle);
                retval = obd_getattr(&sbi->ll_osc_conn, oa, lsm);
                if (retval) {
                        obdo_free(oa);
                        GOTO(out_eof, retval);
                }

                *ppos = oa->o_size;
                obdo_to_inode(inode, oa, oa->o_valid);
                obdo_free(oa);
        }

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK) &&
            !(sbi->ll_flags & LL_SBI_NOLCK)) {
                struct ldlm_extent extent;
                extent.start = *ppos;
                extent.end = *ppos + count;
                CDEBUG(D_INFO, "Locking inode %lu, start "LPU64" end "LPU64"\n",
                       inode->i_ino, extent.start, extent.end);

                err = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT,
                                  &extent, sizeof(extent), LCK_PW, &flags,
                                  ll_lock_callback, inode, sizeof(*inode),
                                  &lockh);
                if (err != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", err);
                        GOTO(out_eof, retval = err);
                }
        }

        CDEBUG(D_INFO, "Writing inode %lu, "LPSZ" bytes, offset %Lu\n",
               inode->i_ino, count, *ppos);

        retval = generic_file_write(file, buf, count, ppos);

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK) ||
            sbi->ll_flags & LL_SBI_NOLCK) {
                err = obd_cancel(&sbi->ll_osc_conn, lsm, LCK_PW, &lockh);
                if (err != ELDLM_OK) {
                        CERROR("lock cancel: err: %d\n", err);
                        GOTO(out_eof, retval = err);
                }
        }

        EXIT;
 out_eof:
        if (!S_ISBLK(inode->i_mode) && file->f_flags & O_APPEND) {
                err = ll_size_unlock(inode, lsm, LCK_PW, &eof_lockh);
                if (err && !retval)
                        retval = err;
        }

        return retval;
}

static int ll_lov_setstripe(struct inode *inode, struct file *file,
                            unsigned long arg)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle *conn;
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
                        int rc2 = ll_file_open(inode, file);
                        if (rc2)
                                RETURN(rc2);
                }

                RETURN(-EALREADY);
        }

        conn = ll_i2obdconn(inode);

        rc = obd_iocontrol(LL_IOC_LOV_SETSTRIPE, conn, 0, &lsm, (void *)arg);
        if (!rc)
                rc = ll_create_open_obj(conn, inode, file, lsm);
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
        struct ll_file_data *fd = (struct ll_file_data *)file->private_data;
        struct lustre_handle *conn;
        int flags;

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
        long long retval;
        ENTRY;

        switch (origin) {
        case 2: {
                struct ll_inode_info *lli = ll_i2info(inode);

                retval = ll_file_size(inode, lli->lli_smd);
                if (retval)
                        RETURN(retval);

                offset += inode->i_size;
                break;
        }
        case 1:
                offset += file->f_pos;
        }
        retval = -EINVAL;
        if (offset >= 0 && offset <= inode->i_sb->s_maxbytes) {
                if (offset != file->f_pos) {
                        file->f_pos = offset;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        file->f_reada = 0;
#endif
                        file->f_version = ++event;
                }
                retval = offset;
        }
        RETURN(retval);
}

/* XXX this does not need to do anything for data, it _does_ need to
   call setattr */
int ll_fsync(struct file *file, struct dentry *dentry, int data)
{
        return 0;
}

static int ll_inode_revalidate(struct dentry *dentry)
{
        struct inode *inode = dentry->d_inode;
        struct lov_stripe_md *lsm;
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }

        if (!ll_have_md_lock(dentry)) {
                struct ptlrpc_request *req = NULL;
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                struct mds_body *body;
                unsigned long valid = 0;
                int datalen = 0;
                int rc;

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
                ll_update_inode(inode, body);
                ptlrpc_req_finished(req);
        }

        lsm = ll_i2info(inode)->lli_smd;
        if (!lsm)       /* object not yet allocated, don't validate size */
                RETURN(0);

        RETURN(ll_file_size(inode, lsm));
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int ll_getattr(struct vfsmount *mnt, struct dentry *de,
                      struct kstat *stat)
{
        return ll_inode_revalidate(de);
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
        fsync:          NULL
};

struct inode_operations ll_file_inode_operations = {
        setattr:    ll_setattr,
        truncate:   ll_truncate,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        getattr: ll_getattr,
#else
        revalidate: ll_inode_revalidate,
#endif
};
