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

int ll_inode_setattr(struct inode *inode, struct iattr *attr, int do_trunc);
extern int ll_setattr(struct dentry *de, struct iattr *attr);

static int ll_file_open(struct inode *inode, struct file *file)
{
        int rc;
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        struct obdo *oa = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        if (file->private_data)
                LBUG();

        /*  delayed create of object (intent created inode) */
        /*  XXX object needs to be cleaned up if mdc_open fails */
        /*  XXX error handling appropriate here? */
        if (lli->lli_obdo == NULL) {
                struct inode * inode = file->f_dentry->d_inode;

                oa = lli->lli_obdo = obdo_alloc();
                oa->o_valid = OBD_MD_FLMODE;
                oa->o_mode = S_IFREG | 0600;
                rc = obd_create(ll_i2obdconn(inode), oa);
                if (rc)
                        RETURN(rc);
                lli->lli_flags &= ~OBD_FL_CREATEONOPEN;
        }

        fd = kmem_cache_alloc(ll_file_data_slab, SLAB_KERNEL);
        if (!fd)
                GOTO(out, rc = -ENOMEM);
        memset(fd, 0, sizeof(*fd));

        rc = mdc_open(&sbi->ll_mdc_conn, inode->i_ino, S_IFREG | inode->i_mode,
                      file->f_flags,
                      oa, (__u64)(unsigned long)file, &fd->fd_mdshandle, &req);
        fd->fd_req = req;
        ptlrpc_req_finished(req);
        if (rc)
                GOTO(out_req, -abs(rc));
        if (!fd->fd_mdshandle) {
                CERROR("mdc_open didn't assign fd_mdshandle\n");
                /* XXX handle this how, abort or is it non-fatal? */
        }
        if (!fd->fd_mdshandle)
                CERROR("mdc_open didn't assign fd_mdshandle\n");

        oa = lli->lli_obdo;
        if (oa == NULL) {
                LBUG();
                GOTO(out_mdc, rc = -EINVAL);
        }

        rc = obd_open(ll_i2obdconn(inode), oa);
        if (rc)
                GOTO(out_mdc, rc = -abs(rc));

        file->private_data = fd;

        EXIT;

        return 0;
out_mdc:
        mdc_close(&sbi->ll_mdc_conn, inode->i_ino,
                  S_IFREG, fd->fd_mdshandle, &req);
out_req:
        ptlrpc_free_req(req);
//out_fd:
        kmem_cache_free(ll_file_data_slab, fd);
        file->private_data = NULL;
out:
        return rc;
}

static int ll_file_release(struct inode *inode, struct file *file)
{
        int rc;
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        struct obdo *oa;
        struct ll_sb_info *sbi = ll_i2sbi(inode);

        ENTRY;

        fd = (struct ll_file_data *)file->private_data;
        if (!fd || !fd->fd_mdshandle) {
                LBUG();
                GOTO(out, rc = -EINVAL);
        }

        oa = ll_i2info(inode)->lli_obdo;
        if (oa == NULL) {
                LBUG();
                GOTO(out_fd, rc = -ENOENT);
        }
        rc = obd_close(ll_i2obdconn(inode), oa);
        if (rc)
                GOTO(out_fd, abs(rc));

        if (file->f_mode & FMODE_WRITE) {
                struct iattr attr;
                attr.ia_valid = ATTR_MTIME | ATTR_CTIME | ATTR_ATIME | ATTR_SIZE;
                attr.ia_mtime = inode->i_mtime;
                attr.ia_ctime = inode->i_ctime;
                attr.ia_atime = inode->i_atime;
                attr.ia_size = inode->i_size;

                /* XXX: this introduces a small race that we should evaluate */
                rc = ll_inode_setattr(inode, &attr, 0);
                if (rc) {
                        CERROR("failed - %d.\n", rc);
                        rc = -EIO; /* XXX - GOTO(out)? -phil */
                }
        }

        rc = mdc_close(&sbi->ll_mdc_conn, inode->i_ino,
                       S_IFREG, fd->fd_mdshandle, &req);
        ptlrpc_req_finished(req);
        if (rc) {
                if (rc > 0)
                        rc = -rc;
                GOTO(out, rc);
        }
        ptlrpc_free_req(fd->fd_req);

        EXIT;

out_fd:
        kmem_cache_free(ll_file_data_slab, fd);
        file->private_data = NULL;
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

static int ll_lock_callback(struct ldlm_lock *lock, struct ldlm_lock *new,
                            void *data, __u32 data_len,
                            struct ptlrpc_request **reqp)
{
        struct inode *inode = lock->l_data;
        struct lustre_handle lockh;
        ENTRY;

        if (new == NULL) {
                /* Completion AST.  Do nothing. */
                RETURN(0);
        }

        if (data_len != sizeof(struct inode))
                LBUG();

        /* FIXME: do something better than throwing away everything */
        if (inode == NULL)
                LBUG();
        down(&inode->i_sem);
        CDEBUG(D_INODE, "invalidating obdo/inode %ld\n", inode->i_ino);
        invalidate_inode_pages(inode);
        up(&inode->i_sem);

        ldlm_lock2handle(lock, &lockh);
        if (ldlm_cli_cancel(lock->l_client, &lockh) < 0)
                LBUG();
        RETURN(0);
}

static ssize_t ll_file_read(struct file *filp, char *buf, size_t count,
                            loff_t *ppos)
{
        struct ll_file_data *fd = (struct ll_file_data *)filp->private_data;
        struct inode *inode = filp->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ldlm_extent extent;
        struct lustre_handle lockh;
        __u64 res_id[RES_NAME_SIZE] = {inode->i_ino};
        int flags = 0;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK)) {
                extent.start = *ppos;
                extent.end = *ppos + count;
                CDEBUG(D_INFO, "Locking inode %ld, start %Lu end %Lu\n",
                       inode->i_ino, extent.start, extent.end);

                err = obd_enqueue(&sbi->ll_osc_conn, NULL, res_id, LDLM_EXTENT,
                                  &extent, sizeof(extent), LCK_PR, &flags,
                                  ll_lock_callback, inode, sizeof(*inode),
                                  &lockh);
                if (err != ELDLM_OK)
                        CERROR("lock enqueue: err: %d\n", err);
                ldlm_lock_dump((void *)(unsigned long)lockh.addr);
        }

        CDEBUG(D_INFO, "Reading inode %ld, %d bytes, offset %Ld\n",
               inode->i_ino, count, *ppos);
        retval = generic_file_read(filp, buf, count, ppos);

        if (retval > 0)
                ll_update_atime(inode);

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK)) {
                err = obd_cancel(&sbi->ll_osc_conn, LCK_PR, &lockh);
                if (err != ELDLM_OK)
                        CERROR("lock cancel: err: %d\n", err);
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
        struct ldlm_extent extent;
        struct lustre_handle lockh;
        __u64 res_id[RES_NAME_SIZE] = {inode->i_ino};
        int flags = 0;
        ldlm_error_t err;
        ssize_t retval;
        ENTRY;

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK)) {
                /* FIXME: this should check whether O_APPEND is set and adjust
                 * extent.start accordingly */
                extent.start = *ppos;
                extent.end = *ppos + count;
                CDEBUG(D_INFO, "Locking inode %ld, start %Lu end %Lu\n",
                       inode->i_ino, extent.start, extent.end);

                err = obd_enqueue(&sbi->ll_osc_conn, NULL, res_id, LDLM_EXTENT,
                                  &extent, sizeof(extent), LCK_PW, &flags,
                                  ll_lock_callback, inode, sizeof(*inode),
                                  &lockh);
                if (err != ELDLM_OK)
                        CERROR("lock enqueue: err: %d\n", err);
                ldlm_lock_dump((void *)(unsigned long)lockh.addr);
        }

        CDEBUG(D_INFO, "Writing inode %ld, %ld bytes, offset %Ld\n",
               inode->i_ino, (long)count, *ppos);

        retval = generic_file_write(file, buf, count, ppos);

        if (!(fd->fd_flags & LL_FILE_IGNORE_LOCK)) {
                err = obd_cancel(&sbi->ll_osc_conn, LCK_PW, &lockh);
                if (err != ELDLM_OK)
                        CERROR("lock cancel: err: %d\n", err);
        }

        RETURN(retval);
}

int ll_file_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                  unsigned long arg)
{
        struct ll_file_data *fd = (struct ll_file_data *)file->private_data;
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
                return -ENOTTY;
        }
}

/* XXX this does not need to do anything for data, it _does_ need to
   call setattr */
int ll_fsync(struct file *file, struct dentry *dentry, int data)
{
        return 0;
}

struct file_operations ll_file_operations = {
        read:           ll_file_read,
        write:          ll_file_write,
        ioctl:          ll_file_ioctl,
        open:           ll_file_open,
        release:        ll_file_release,
        mmap:           generic_file_mmap,
        fsync:          NULL
};

struct inode_operations ll_file_inode_operations = {
        truncate: ll_truncate,
        setattr: ll_setattr
};
