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

int ll_create_objects(struct super_block *sb, obd_id id, uid_t uid, gid_t gid,
                      struct lov_stripe_md **lsmp)
{
        struct obdo *oa;
        int rc;
        ENTRY;

        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);

        oa->o_mode = S_IFREG | 0600;
        oa->o_id = id;
        oa->o_uid = uid;
        oa->o_gid = gid;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE |
                OBD_MD_FLUID | OBD_MD_FLGID;
        rc = obd_create(ll_s2obdconn(sb), oa, lsmp);
        obdo_free(oa);

        if (!rc)
                LASSERT(*lsmp && (*lsmp)->lsm_object_id);
        RETURN(rc);
}

static int ll_file_open(struct inode *inode, struct file *file)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_handle *conn = ll_i2obdconn(inode);
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        struct obdo *oa;
        struct lov_stripe_md *lsm;
        struct lov_mds_md *lmm = NULL;
        int lmm_size = 0;
        int rc = 0;
        ENTRY;

        LASSERT(!file->private_data);

        lsm = lli->lli_smd;

        /*  delayed create of object (intent created inode) */
        /*  XXX object needs to be cleaned up if mdc_open fails */
        /*  XXX error handling appropriate here? */
        if (lsm == NULL) {
                if (file->f_flags & O_LOV_DELAY_CREATE) {
                        CDEBUG(D_INODE, "delaying object creation\n");
                        RETURN(0);
                }
                down(&lli->lli_open_sem);
                /* Check to see if we lost the race */
                if (!lli->lli_smd)
                        rc = ll_create_objects(inode->i_sb, inode->i_ino, 0, 0,
                                               &lli->lli_smd);
                up(&lli->lli_open_sem);
                if (rc)
                        RETURN(rc);

                lsm = lli->lli_smd;
        }

        /* XXX We should only send this to MDS if we just created these
         *     objects, except we also need to handle the user-stripe case.
         */
        rc = obd_packmd(conn, &lmm, lli->lli_smd);
        if (rc < 0)
                GOTO(out, rc);

        lmm_size = rc;

        fd = kmem_cache_alloc(ll_file_data_slab, SLAB_KERNEL);
        if (!fd) {
                if (lmm)
                        obd_free_wiremd(conn, &lmm);
                GOTO(out, rc = -ENOMEM);
        }
        memset(fd, 0, sizeof(*fd));

        fd->fd_mdshandle.addr = (__u64)(unsigned long)file;
        get_random_bytes(&fd->fd_mdshandle.cookie,
                         sizeof(fd->fd_mdshandle.cookie));
        rc = mdc_open(&sbi->ll_mdc_conn, inode->i_ino, S_IFREG | inode->i_mode,
                      file->f_flags, lmm, lmm_size, &fd->fd_mdshandle, &req);
        if (lmm)
                obd_free_wiremd(conn, &lmm);
        fd->fd_req = req;

        /* This is the "reply" refcount. */
        ptlrpc_req_finished(req);
        if (rc)
                GOTO(out_req, -abs(rc));
        if (!fd->fd_mdshandle.addr ||
            fd->fd_mdshandle.addr == (__u64)(unsigned long)file) {
                CERROR("hmm, mdc_open didn't assign fd_mdshandle?\n");
                /* XXX handle this how, abort or is it non-fatal? */
        }

        oa = obdo_alloc();
        if (!oa)
                GOTO(out_mdc, rc = -EINVAL);

        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = S_IFREG;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS;
        rc = obd_open(ll_i2obdconn(inode), oa, lsm);
        obdo_to_inode(inode, oa, oa->o_valid & (OBD_MD_FLSIZE|OBD_MD_FLBLOCKS));

        obd_oa2handle(&fd->fd_osthandle, oa);
        obdo_free(oa);

        if (rc)
                GOTO(out_mdc, rc = -abs(rc));

        atomic_inc(&lli->lli_open_count);

        file->private_data = fd;

        RETURN(0);
out_mdc:
        mdc_close(&sbi->ll_mdc_conn, inode->i_ino,
                  S_IFREG, &fd->fd_mdshandle, &req);
out_req:
        ptlrpc_req_finished(req); /* once for reply */
        ptlrpc_req_finished(req); /* once for an early "commit" */
//out_fd:
        fd->fd_mdshandle.cookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(ll_file_data_slab, fd);
out:
        return rc;
}

int ll_size_lock(struct inode *inode, struct lov_stripe_md *lsm, obd_off start,
                 int mode, struct lustre_handle **lockhs_p)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ldlm_extent extent;
        struct lustre_handle *lockhs = NULL;
        int rc, flags = 0, stripe_count;
        ENTRY;

        if (sbi->ll_flags & LL_SBI_NOLCK) {
                *lockhs_p = NULL;
                RETURN(0);
        }

        stripe_count = lsm->lsm_stripe_count;
        if (!stripe_count)
                stripe_count = 1;

        OBD_ALLOC(lockhs, stripe_count * sizeof(*lockhs));
        if (lockhs == NULL)
                RETURN(-ENOMEM);

        extent.start = start;
        extent.end = OBD_OBJECT_EOF;

        rc = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT, &extent,
                         sizeof(extent), mode, &flags, ll_lock_callback,
                         inode, sizeof(*inode), lockhs);
        if (rc != ELDLM_OK) {
                CERROR("lock enqueue: %d\n", rc);
                OBD_FREE(lockhs, stripe_count * sizeof(*lockhs));
        } else
                *lockhs_p = lockhs;
        RETURN(rc);
}

int ll_size_unlock(struct inode *inode, struct lov_stripe_md *lsm, int mode,
                   struct lustre_handle *lockhs)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc, stripe_count;
        ENTRY;

        if (sbi->ll_flags & LL_SBI_NOLCK)
                RETURN(0);

        if (lockhs == NULL) {
                LBUG();
                RETURN(-EINVAL);
        }

        rc = obd_cancel(&sbi->ll_osc_conn, lsm, mode, lockhs);
        if (rc != ELDLM_OK) {
                CERROR("lock cancel: %d\n", rc);
                LBUG();
        }

        stripe_count = lsm->lsm_stripe_count;
        if (!stripe_count)
                stripe_count = 1;

        OBD_FREE(lockhs, stripe_count * sizeof(*lockhs));
        RETURN(rc);
}

int ll_file_size(struct inode *inode, struct lov_stripe_md *lsm)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_handle *lockhs;
        struct obdo oa;
        int err, rc;
        ENTRY;

        LASSERT(lsm);
        LASSERT(sbi);

        rc = ll_size_lock(inode, lsm, 0, LCK_PR, &lockhs);
        if (rc != ELDLM_OK) {
                CERROR("lock enqueue: %d\n", rc);
                RETURN(rc);
        }

        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLID|OBD_MD_FLTYPE|OBD_MD_FLSIZE|OBD_MD_FLBLOCKS;
        rc = obd_getattr(&sbi->ll_osc_conn, &oa, lsm);
        if (!rc)
                obdo_to_inode(inode, &oa,
                              oa.o_valid & ~(OBD_MD_FLTYPE | OBD_MD_FLMODE));

        err = ll_size_unlock(inode, lsm, LCK_PR, lockhs);
        if (err != ELDLM_OK) {
                CERROR("lock cancel: %d\n", err);
                LBUG();
        }
        RETURN(rc);
}

static int ll_file_release(struct inode *inode, struct file *file)
{
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        struct obdo oa;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        int rc, rc2;

        ENTRY;

        fd = (struct ll_file_data *)file->private_data;
        if (!fd) {
                LASSERT(file->f_flags & O_LOV_DELAY_CREATE);
                GOTO(out, rc = 0);
        }

        memset(&oa, 0, sizeof(oa));
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLTYPE | OBD_MD_FLID;
        obd_handle2oa(&oa, &fd->fd_osthandle);
        rc = obd_close(ll_i2obdconn(inode), &oa, lsm);
        if (rc)
                GOTO(out_mdc, rc = -abs(rc));

#if 0
#error "This should only be done on the node that already has the EOF lock"
#error "and only in the case where the file size actually changed.  For now"
#error "we don't care about the size on the MDS, since we never use it (the"
#error "OST always has the authoritative size and we don't even use the MDS."
        /* If this fails and we goto out_fd, the file size on the MDS is out of
         * date.  Is that a big deal? */
        if (file->f_mode & FMODE_WRITE) {
                struct lustre_handle *lockhs;

                rc = ll_size_lock(inode, lsm, 0, LCK_PR, &lockhs);
                if (rc)
                        GOTO(out_mdc, -abs(rc));

                oa.o_id = lsm->lsm_object_id;
                oa.o_mode = S_IFREG;
                oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                        OBD_MD_FLBLOCKS;
                rc = obd_getattr(&sbi->ll_osc_conn, &oa, lsm);
                if (!rc) {
                        struct iattr attr;
                        attr.ia_valid = (ATTR_MTIME | ATTR_CTIME | ATTR_ATIME |
                                         ATTR_SIZE);
                        attr.ia_mtime = inode->i_mtime;
                        attr.ia_ctime = inode->i_ctime;
                        attr.ia_atime = inode->i_atime;
                        attr.ia_size = oa.o_size;

                        inode->i_blocks = oa.o_blocks;

                        /* XXX: this introduces a small race that we should
                         * evaluate */
                        rc = ll_inode_setattr(inode, &attr, 0);
                }
                rc2 = ll_size_unlock(inode, lli->lli_smd, LCK_PR, lockhs);
                if (rc2) {
                        CERROR("lock cancel: %d\n", rc);
                        LBUG();
                        if (!rc)
                                rc = rc2;
                }
        }
#endif

out_mdc:
        rc2 = mdc_close(&sbi->ll_mdc_conn, inode->i_ino,
                        S_IFREG, &fd->fd_mdshandle, &req);
        ptlrpc_req_finished(req);
        if (rc2) {
                if (!rc)
                        rc = -abs(rc2);
                GOTO(out_fd, rc);
        }
        DEBUG_REQ(D_HA, fd->fd_req, "matched open for this close: ");
        ptlrpc_req_finished(fd->fd_req);

        if (atomic_dec_and_test(&lli->lli_open_count)) {
                CDEBUG(D_INFO, "last close, cancelling unused locks\n");
                rc = obd_cancel_unused(ll_i2obdconn(inode), lsm, 0);
                if (rc)
                        CERROR("obd_cancel_unused: %d\n", rc);
        } else {
                CDEBUG(D_INFO, "not last close, not cancelling unused locks\n");
        }

        EXIT;

out_fd:
        fd->fd_mdshandle.cookie = DEAD_HANDLE_MAGIC;
        file->private_data = NULL;
        kmem_cache_free(ll_file_data_slab, fd);
out:
        return rc;
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
        struct lustre_handle lockh;
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
        struct lustre_handle *lockhs = NULL;
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        int flags = 0;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;

        /* If we don't refresh the file size, generic_file_read may not even
         * call us */
        retval = ll_file_size(inode, lsm);
        if (retval < 0) {
                CERROR("ll_file_size: %d\n", retval);
                RETURN(retval);
        }

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK) &&
            !(sbi->ll_flags & LL_SBI_NOLCK)) {
                struct ldlm_extent extent;
                OBD_ALLOC(lockhs, lsm->lsm_stripe_count * sizeof(*lockhs));
                if (!lockhs)
                        RETURN(-ENOMEM);

                extent.start = *ppos;
                extent.end = *ppos + count;
                CDEBUG(D_INFO, "Locking inode %lu, start "LPU64" end "LPU64"\n",
                       inode->i_ino, extent.start, extent.end);

                err = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT,
                                  &extent, sizeof(extent), LCK_PR, &flags,
                                  ll_lock_callback, inode, sizeof(*inode),
                                  lockhs);
                if (err != ELDLM_OK) {
                        OBD_FREE(lockhs, lsm->lsm_stripe_count*sizeof(*lockhs));
                        CERROR("lock enqueue: err: %d\n", err);
                        RETURN(err);
                }
        }

        CDEBUG(D_INFO, "Reading inode %lu, %d bytes, offset %Ld\n",
               inode->i_ino, count, *ppos);
        retval = generic_file_read(filp, buf, count, ppos);

        if (retval > 0)
                ll_update_atime(inode);

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK) &&
            !(sbi->ll_flags & LL_SBI_NOLCK)) {
                err = obd_cancel(&sbi->ll_osc_conn, lsm, LCK_PR, lockhs);
                if (err != ELDLM_OK) {
                        CERROR("lock cancel: err: %d\n", err);
                        retval = err;
                }
        }

        if (lockhs)
                OBD_FREE(lockhs, lsm->lsm_stripe_count * sizeof(*lockhs));
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
        struct lustre_handle *lockhs = NULL, *eof_lockhs = NULL;
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

                err = ll_size_lock(inode, lsm, 0, LCK_PW, &eof_lockhs);
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
                OBD_ALLOC(lockhs, lsm->lsm_stripe_count * sizeof(*lockhs));
                if (!lockhs)
                        GOTO(out_eof, retval = -ENOMEM);
                extent.start = *ppos;
                extent.end = *ppos + count;
                CDEBUG(D_INFO, "Locking inode %lu, start "LPU64" end "LPU64"\n",
                       inode->i_ino, extent.start, extent.end);

                err = obd_enqueue(&sbi->ll_osc_conn, lsm, NULL, LDLM_EXTENT,
                                  &extent, sizeof(extent), LCK_PW, &flags,
                                  ll_lock_callback, inode, sizeof(*inode),
                                  lockhs);
                if (err != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", err);
                        GOTO(out_free, retval = err);
                }
        }

        CDEBUG(D_INFO, "Writing inode %lu, %ld bytes, offset "LPD64"\n",
               inode->i_ino, (long)count, *ppos);

        retval = generic_file_write(file, buf, count, ppos);

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK) ||
            sbi->ll_flags & LL_SBI_NOLCK) {
                err = obd_cancel(&sbi->ll_osc_conn, lsm, LCK_PW, lockhs);
                if (err != ELDLM_OK) {
                        CERROR("lock cancel: err: %d\n", err);
                        GOTO(out_free, retval = err);
                }
        }

        EXIT;
 out_free:
        if (lockhs)
                OBD_FREE(lockhs, lsm->lsm_stripe_count * sizeof(*lockhs));

 out_eof:
        if (!S_ISBLK(inode->i_mode) && file->f_flags & O_APPEND) {
                err = ll_size_unlock(inode, lsm, LCK_PW, eof_lockhs);
                if (err && !retval)
                        retval = err;
        }

        return retval;
}

/* Retrieve object striping information.
 *
 * @arg is a pointer to a user struct with one or more of the fields set to
 * indicate the application preference: lmm_stripe_count, lmm_stripe_size,
 * lmm_stripe_offset, and lmm_stripe_pattern.  lmm_magic must be LOV_MAGIC.
 */
static int ll_lov_setstripe(struct inode *inode, struct file *file,
                            unsigned long arg)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_mds_md *lmm = NULL, *lmmu = (void *)arg;
        struct lustre_handle *conn = ll_i2obdconn(inode);
        int rc;

        rc = obd_alloc_wiremd(conn, &lmm);
        if (rc < 0)
                RETURN(rc);

        rc = copy_from_user(lmm, lmmu, sizeof(*lmm));
        if (rc)
                GOTO(out_free, rc = -EFAULT);

        if (lmm->lmm_magic != LOV_MAGIC) {
                CERROR("bad LOV magic %X\n", lmm->lmm_magic);
                GOTO(out_free, rc = -EINVAL);
        }

        down(&lli->lli_open_sem);
        if (lli->lli_smd) {
                CERROR("striping data already set for %lu\n", inode->i_ino);
                GOTO(out_lov_up, rc = -EPERM);
        }
        rc = obd_unpackmd(conn, &lli->lli_smd, lmm);
        if (rc < 0) {
                CERROR("error setting LOV striping on %lu: rc = %d\n",
                       inode->i_ino, rc);
                GOTO(out_lov_up, rc);
        }

        rc = ll_create_objects(inode->i_sb, inode->i_ino, 0, 0, &lli->lli_smd);
        if (rc) {
                obd_free_memmd(conn, &lli->lli_smd);
        } else {
                file->f_flags &= ~O_LOV_DELAY_CREATE;
                rc = ll_file_open(inode, file);
        }
out_lov_up:
        up(&lli->lli_open_sem);
out_free:
        obd_free_wiremd(conn, &lmm);
        return rc;
}

/* Retrieve object striping information.
 *
 * @arg is a pointer to a user struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_MAGIC.
 */
static int ll_lov_getstripe(struct inode *inode, unsigned long arg)
{
        struct lov_mds_md lmm, *lmmu = (void *)arg, *lmmk = NULL;
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct lustre_handle *conn = ll_i2obdconn(inode);
        int ost_count, rc, lmm_size;

        if (!lsm)
                RETURN(-ENODATA);

        rc = copy_from_user(&lmm, lmmu, sizeof(lmm));
        if (rc)
                RETURN(-EFAULT);

        if (lmm.lmm_magic != LOV_MAGIC)
                RETURN(-EINVAL);

        if (lsm->lsm_stripe_count == 0)
                ost_count = 1;
        else {
                struct obd_device *obd = class_conn2obd(conn);
                struct lov_obd *lov = &obd->u.lov;
                ost_count = lov->desc.ld_tgt_count;
        }

        /* XXX we _could_ check if indices > user lmm_ost_count are zero */
        if (lmm.lmm_ost_count < ost_count)
                RETURN(-EOVERFLOW);

        rc = obd_packmd(conn, &lmmk, lsm);
        if (rc < 0)
                RETURN(rc);

        lmm_size = rc;

        /* LOV STACKING layering violation to make LOV/OSC return same data */
        if (lsm->lsm_stripe_count == 0) {
                struct lov_object_id *loi;

                loi = (void *)lmmu + offsetof(typeof(*lmmu), lmm_objects);
                rc = copy_to_user(loi, &lsm->lsm_object_id, sizeof(*loi));
                if (rc) {
                        lmm_size = 0;
                        rc = -EFAULT;
                } else {
                        lmmk->lmm_magic = LOV_MAGIC;
                        lmmk->lmm_ost_count = lmmk->lmm_stripe_count = 1;
                }
        }

        if (lmm_size && copy_to_user(lmmu, lmmk, lmm_size))
                rc = -EFAULT;

        obd_free_wiremd(conn, &lmmk);

        RETURN(rc);
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
        
        if (! ll_have_md_lock(dentry)) { 
                struct ptlrpc_request *req;
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
                struct mds_body *body; 
                int rc, datalen, valid; 

                if (S_ISREG(inode->i_mode)) {
                        datalen = obd_size_wiremd(&sbi->ll_osc_conn, NULL);
                        valid |= OBD_MD_FLEASIZE;
                }
                rc = mdc_getattr(&sbi->ll_mdc_conn, 
                                 inode->i_ino, 
                                 inode->i_mode, valid,
                                 datalen, &req);
                if (rc) {
                        CERROR("failure %d inode "LPX64"\n", rc, inode->i_ino);
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
