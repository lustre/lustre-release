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
extern inline struct obdo * ll_oa_from_inode(struct inode *inode,
                                             unsigned long valid);

static int ll_file_open(struct inode *inode, struct file *file)
{
        int rc;
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        struct obdo *oa;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ENTRY;

        if (file->private_data)
                LBUG();

        fd = kmem_cache_alloc(ll_file_data_slab, SLAB_KERNEL);
        if (!fd)
                GOTO(out, rc = -ENOMEM);
        memset(fd, 0, sizeof(*fd));

        rc = mdc_open(&sbi->ll_mds_client, sbi->ll_mds_conn, inode->i_ino,
                      S_IFREG, file->f_flags, &fd->fd_mdshandle, &req);
        fd->fd_req = req;
        ptlrpc_req_finished(req);
        if (rc) {
                if (rc > 0) 
                        rc = -rc;
                GOTO(out, rc);
        }
        if (!fd->fd_mdshandle)
                CERROR("mdc_open didn't assign fd_mdshandle\n");
        

        oa = ll_oa_from_inode(inode, (OBD_MD_FLMODE | OBD_MD_FLID));
        if (oa == NULL)
                LBUG();
        rc = obd_open(ll_i2obdconn(inode), oa);
        obdo_free(oa);
        if (rc) {
                /* XXX: Need to do mdc_close here! */
                GOTO(out, rc = abs(rc));
        }

        file->private_data = fd;

        EXIT;
 out:
        if (rc && fd) {
                kmem_cache_free(ll_file_data_slab, fd);
                file->private_data = NULL;
        }

        return rc;
}

static int ll_file_release(struct inode *inode, struct file *file)
{
        int rc;
        struct ptlrpc_request *req = NULL;
        struct ll_file_data *fd;
        struct obdo *oa;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct iattr iattr;

        ENTRY;

        fd = (struct ll_file_data *)file->private_data;
        if (!fd || !fd->fd_mdshandle) {
                LBUG();
                GOTO(out, rc = -EINVAL);
        }

        oa = ll_oa_from_inode(inode, (OBD_MD_FLMODE | OBD_MD_FLID));
        if (oa == NULL)
                LBUG();
        rc = obd_close(ll_i2obdconn(inode), oa);
        obdo_free(oa);
        if (rc)
                GOTO(out, abs(rc));

        iattr.ia_valid = ATTR_SIZE;
        iattr.ia_size = inode->i_size;
        rc = ll_inode_setattr(inode, &iattr, 0);
        if (rc) {
                CERROR("failed - %d.\n", rc);
                rc = -EIO; /* XXX - GOTO(out)? -phil */
        }

        rc = mdc_close(&sbi->ll_mds_client, sbi->ll_mds_conn, inode->i_ino,
                       S_IFREG, fd->fd_mdshandle, &req);
        ptlrpc_req_finished(req);
        if (rc) { 
                if (rc > 0) 
                        rc = -rc;
                GOTO(out, rc);
        }
        ptlrpc_free_req(fd->fd_req);

        EXIT; 

 out:
        if (!rc && fd) {
                kmem_cache_free(ll_file_data_slab, fd);
                file->private_data = NULL;
        }
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

static ssize_t ll_file_read(struct file *filp, char *buf, size_t count,
                            loff_t *ppos)
{
        struct inode *inode = filp->f_dentry->d_inode;
#if 0
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ldlm_extent extent;
        struct ldlm_handle lockh;
        __u64 res_id[RES_NAME_SIZE] = {inode->i_ino};
        int flags = 0;
        ldlm_error_t err;
#endif
        ssize_t retval;
        ENTRY;

#if 0
        extent.start = *ppos;
        extent.end = *ppos + count;
        CDEBUG(D_INFO, "Locking inode %ld, start %Lu end %Lu\n",
               inode->i_ino, extent.start, extent.end);

        err = obd_enqueue(&sbi->ll_conn, sbi->ll_namespace, NULL, res_id,
                          LDLM_EXTENT, &extent, LCK_PR, &flags, inode,
                          sizeof(*inode), &lockh);
        if (err != ELDLM_OK)
                CERROR("lock enqueue: err: %d\n", err);
        ldlm_lock_dump((void *)(unsigned long)lockh.addr);
#endif

        CDEBUG(D_INFO, "Reading inode %ld, %d bytes, offset %Ld\n",
               inode->i_ino, count, *ppos);
        retval = generic_file_read(filp, buf, count, ppos);
        if (retval > 0) {
                struct iattr attr;
                attr.ia_valid = ATTR_ATIME;
                attr.ia_atime = CURRENT_TIME;
                ll_setattr(filp->f_dentry, &attr);
        }

#if 0
        err = obd_cancel(&sbi->ll_conn, LCK_PR, &lockh);
        if (err != ELDLM_OK)
                CERROR("lock cancel: err: %d\n", err);
#endif

        RETURN(retval);
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t
ll_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
        struct inode *inode = file->f_dentry->d_inode;
#if 0
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ldlm_extent extent;
        struct ldlm_handle lockh;
        __u64 res_id[RES_NAME_SIZE] = {inode->i_ino};
        int flags = 0;
        ldlm_error_t err;
#endif
        ssize_t retval;
        ENTRY;

#if 0
        extent.start = *ppos;
        extent.end = *ppos + count;
        CDEBUG(D_INFO, "Locking inode %ld, start %Lu end %Lu\n",
               inode->i_ino, extent.start, extent.end);

        err = obd_enqueue(&sbi->ll_conn, sbi->ll_namespace, NULL, res_id,
                          LDLM_EXTENT, &extent, LCK_PW, &flags, inode,
                          sizeof(*inode), &lockh);
        if (err != ELDLM_OK)
                CERROR("lock enqueue: err: %d\n", err);
        ldlm_lock_dump((void *)(unsigned long)lockh.addr);
#endif

        CDEBUG(D_INFO, "Writing inode %ld, %ld bytes, offset %Ld\n",
               inode->i_ino, (long)count, *ppos);

        retval = generic_file_write(file, buf, count, ppos);

        /* update mtime/ctime/atime here, NOT size */
        if (retval > 0) {
                struct iattr attr;
                attr.ia_valid = ATTR_MTIME | ATTR_CTIME | ATTR_ATIME;
                attr.ia_mtime = attr.ia_ctime = attr.ia_atime =
                        CURRENT_TIME;
                ll_setattr(file->f_dentry, &attr);
        }

#if 0
        err = obd_cancel(&sbi->ll_conn, LCK_PW, &lockh);
        if (err != ELDLM_OK)
                CERROR("lock cancel: err: %d\n", err);
#endif

        RETURN(retval);
}

/* XXX this does not need to do anything for data, it _does_ need to
   call setattr */
int ll_fsync(struct file *file, struct dentry *dentry, int data)
{
        return 0;
}

struct file_operations ll_file_operations = {
        read: ll_file_read,
        write: ll_file_write,
        open: ll_file_open,
        release: ll_file_release,
        mmap: generic_file_mmap,
        fsync: NULL
};

struct inode_operations ll_file_inode_operations = {
        truncate: ll_truncate,
        setattr: ll_setattr
};
