/*
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


/* push / pop to root of obd store */
void push_ctxt(struct obd_run_ctxt *save, struct obd_run_ctxt *new)
{ 
        save->fs = get_fs();
        save->pwd = dget(current->fs->pwd);
        save->pwdmnt = mntget(current->fs->pwdmnt);

        set_fs(new->fs);
        set_fs_pwd(current->fs, new->pwdmnt, new->pwd);
}

void pop_ctxt(struct obd_run_ctxt *saved)
{
        set_fs(saved->fs);
        set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);

        dput(saved->pwd);
        mntput(saved->pwdmnt);
}

/* utility to make a directory */
int simple_mkdir(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err;
        ENTRY;

        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                RETURN(PTR_ERR(dchild));

        if (dchild->d_inode) {
		if (!S_ISDIR(dchild->d_inode->i_mode))
			GOTO(out, err = -ENOTDIR);

                GOTO(out, err = -EEXIST);
	}

        err = vfs_mkdir(dir->d_inode, dchild, mode);
out:
        l_dput(dchild);

        RETURN(err);
}

int lustre_fread(struct file *file, char *str, int len, loff_t *off)
{
	if (!file || !file->f_op || !file->f_op->read || !off)
		RETURN(-ENOSYS);

	return file->f_op->read(file, str, len, off);
}

int lustre_fwrite(struct file *file, const char *str, int len, loff_t *off)
{
	if (!file || !file->f_op || !off)
		RETURN(-ENOSYS);

	if (!file->f_op->write)
		RETURN(-EROFS);

	return file->f_op->write(file, str, len, off);
}

int lustre_fsync(struct file *file)
{
	if (!file || !file->f_op || !file->f_op->fsync)
		RETURN(-ENOSYS);

	return file->f_op->fsync(file, file->f_dentry, 0);
}
