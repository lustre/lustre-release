/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lib/simple.c
 *
 * Copyright (C) 2002  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 * and Andreas Dilger <adilger@clusterfs.com>
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/lustre_mds.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>

#if 1
/* Debugging check only needed during development */
#define ASSERT_NOT_KERNEL_CTXT(msg) do { if (segment_eq(get_fs(), get_ds())) { \
                                        CERROR(msg); LBUG(); } } while(0)
#define ASSERT_KERNEL_CTXT(msg) do { if (!segment_eq(get_fs(), get_ds())) { \
                                        CERROR(msg); LBUG(); } } while(0)
#else
#define ASSERT_NOT_KERNEL_CTXT(msg) do {} while(0)
#define ASSERT_KERNEL_CTXT(msg) do {} while(0)
#endif

/* push / pop to root of obd store */
void push_ctxt(struct obd_run_ctxt *save, struct obd_run_ctxt *new)
{
        //ASSERT_NOT_KERNEL_CTXT("already in kernel context!\n");
        save->fs = get_fs();
        save->pwd = dget(current->fs->pwd);
        save->pwdmnt = mntget(current->fs->pwdmnt);

        set_fs(new->fs);
        set_fs_pwd(current->fs, new->pwdmnt, new->pwd);
}

void pop_ctxt(struct obd_run_ctxt *saved)
{
        ASSERT_KERNEL_CTXT( "popping non-kernel context!\n");
        set_fs(saved->fs);
        set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);

        dput(saved->pwd);
        mntput(saved->pwdmnt);
}

/* utility to make a directory */
struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err;
        ENTRY;

        ASSERT_KERNEL_CTXT("kernel doing I/O outside kernel context\n");
        CDEBUG(D_INODE, "creating directory %*s\n", strlen(name), name);
        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                RETURN(dchild);

        if (dchild->d_inode) {
		if (!S_ISDIR(dchild->d_inode->i_mode))
			GOTO(out, err = -ENOTDIR);

                RETURN(dchild);
	}

        err = vfs_mkdir(dir->d_inode, dchild, mode);
        EXIT;
out:
        if (err) {
                dput(dchild);
                RETURN(ERR_PTR(err));
        }

        RETURN(dchild);
}

/*
 * Read a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fread(struct file *file, char *str, int len, loff_t *off)
{
        ASSERT_KERNEL_CTXT("kernel doing I/O outside kernel context\n");
        if (!file || !file->f_op || !file->f_op->read || !off)
                RETURN(-ENOSYS);

        return file->f_op->read(file, str, len, off);
}

/*
 * Write a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fwrite(struct file *file, const char *str, int len, loff_t *off)
{
        ASSERT_KERNEL_CTXT("kernel doing I/O outside kernel context\n");
        if (!file || !file->f_op || !off)
                RETURN(-ENOSYS);

        if (!file->f_op->write)
                RETURN(-EROFS);

        return file->f_op->write(file, str, len, off);
}

/*
 * Sync a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fsync(struct file *file)
{
        ASSERT_KERNEL_CTXT("kernel doing I/O outside kernel context\n");
	if (!file || !file->f_op || !file->f_op->fsync)
		RETURN(-ENOSYS);

	return file->f_op->fsync(file, file->f_dentry, 0);
}
