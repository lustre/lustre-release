/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *  Author: Peter Braam <braam@clusterfs.com>
 *  Aurhot: Andreas Dilger <adilger@clusterfs.com>
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

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/obd.h>
#include <linux/lustre_lib.h>

/* Debugging check only needed during development */
#ifdef OBD_CTXT_DEBUG
# define ASSERT_CTXT_MAGIC(magic) LASSERT((magic) == OBD_RUN_CTXT_MAGIC)
# define ASSERT_NOT_KERNEL_CTXT(msg) LASSERT(!segment_eq(get_fs(), get_ds()))
# define ASSERT_KERNEL_CTXT(msg) LASSERT(segment_eq(get_fs(), get_ds()))
#else
# define ASSERT_CTXT_MAGIC(magic) do {} while(0)
# define ASSERT_NOT_KERNEL_CTXT(msg) do {} while(0)
# define ASSERT_KERNEL_CTXT(msg) do {} while(0)
#endif

/* push / pop to root of obd store */
void push_ctxt(struct obd_run_ctxt *save, struct obd_run_ctxt *new_ctx,
               struct obd_ucred *uc)
{
        //ASSERT_NOT_KERNEL_CTXT("already in kernel context!\n");
        ASSERT_CTXT_MAGIC(new_ctx->magic);
        OBD_SET_CTXT_MAGIC(save);

        /*
        CDEBUG(D_INFO,
               "= push %p->%p = cur fs %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               save, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */

        save->fs = get_fs();
        LASSERT(atomic_read(&current->fs->pwd->d_count));
        LASSERT(atomic_read(&new_ctx->pwd->d_count));
        save->pwd = dget(current->fs->pwd);
        save->pwdmnt = mntget(current->fs->pwdmnt);

        LASSERT(save->pwd);
        LASSERT(save->pwdmnt);
        LASSERT(new_ctx->pwd);
        LASSERT(new_ctx->pwdmnt);

        if (uc) {
                save->fsuid = current->fsuid;
                save->fsgid = current->fsgid;
                save->cap = current->cap_effective;

                current->fsuid = uc->ouc_fsuid;
                current->fsgid = uc->ouc_fsgid;
                current->cap_effective = uc->ouc_cap;
                if (uc->ouc_suppgid1 != -1)
                        current->groups[current->ngroups++] = uc->ouc_suppgid1;
                if (uc->ouc_suppgid2 != -1)
                        current->groups[current->ngroups++] = uc->ouc_suppgid2;
        }
        set_fs(new_ctx->fs);
        set_fs_pwd(current->fs, new_ctx->pwdmnt, new_ctx->pwd);

        /*
        CDEBUG(D_INFO,
               "= push %p->%p = cur fs %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               new_ctx, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */
}
EXPORT_SYMBOL(push_ctxt);

void pop_ctxt(struct obd_run_ctxt *saved, struct obd_run_ctxt *new_ctx,
              struct obd_ucred *uc)
{
        //printk("pc0");
        ASSERT_CTXT_MAGIC(saved->magic);
        //printk("pc1");
        ASSERT_KERNEL_CTXT("popping non-kernel context!\n");

        /*
        CDEBUG(D_INFO,
               " = pop  %p==%p = cur %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               new_ctx, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */

        LASSERT(current->fs->pwd == new_ctx->pwd);
        LASSERT(current->fs->pwdmnt == new_ctx->pwdmnt);

        set_fs(saved->fs);
        set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);

        dput(saved->pwd);
        mntput(saved->pwdmnt);
        if (uc) {
                current->fsuid = saved->fsuid;
                current->fsgid = saved->fsgid;
                current->cap_effective = saved->cap;

                if (uc->ouc_suppgid1 != -1)
                        current->ngroups--;
                if (uc->ouc_suppgid2 != -1)
                        current->ngroups--;
        }

        /*
        CDEBUG(D_INFO,
               "= pop  %p->%p = cur fs %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               saved, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */
}
EXPORT_SYMBOL(pop_ctxt);

/* utility to make a file */
struct dentry *simple_mknod(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        ASSERT_KERNEL_CTXT("kernel doing mknod outside kernel context\n");
        CDEBUG(D_INODE, "creating file %*s\n", (int)strlen(name), name);

        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                if (!S_ISREG(dchild->d_inode->i_mode))
                        GOTO(out_err, err = -EEXIST);

                GOTO(out_up, dchild);
        }

        err = vfs_create(dir->d_inode, dchild, (mode & ~S_IFMT) | S_IFREG);
        if (err)
                GOTO(out_err, err);

        RETURN(dchild);

out_err:
        dput(dchild);
        dchild = ERR_PTR(err);
out_up:
        return dchild;
}
EXPORT_SYMBOL(simple_mknod);

/* utility to make a directory */
struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        ASSERT_KERNEL_CTXT("kernel doing mkdir outside kernel context\n");
        CDEBUG(D_INODE, "creating directory %*s\n", (int)strlen(name), name);
        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                if (!S_ISDIR(dchild->d_inode->i_mode))
                        GOTO(out_err, err = -ENOTDIR);

                GOTO(out_up, dchild);
        }

        err = vfs_mkdir(dir->d_inode, dchild, mode);
        if (err)
                GOTO(out_err, err);

        RETURN(dchild);

out_err:
        dput(dchild);
        dchild = ERR_PTR(err);
out_up:
        return dchild;
}
EXPORT_SYMBOL(simple_mkdir);

/*
 * Read a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fread(struct file *file, void *buf, int len, loff_t *off)
{
        ASSERT_KERNEL_CTXT("kernel doing read outside kernel context\n");
        if (!file || !file->f_op || !file->f_op->read || !off)
                RETURN(-ENOSYS);

        return file->f_op->read(file, buf, len, off);
}
EXPORT_SYMBOL(lustre_fread);

/*
 * Write a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fwrite(struct file *file, const void *buf, int len, loff_t *off)
{
        ENTRY;
        ASSERT_KERNEL_CTXT("kernel doing write outside kernel context\n");
        if (!file)
                RETURN(-ENOENT);
        if (!file->f_op)
                RETURN(-ENOSYS);
        if (!off)
                RETURN(-EINVAL);

        if (!file->f_op->write)
                RETURN(-EROFS);

        RETURN(file->f_op->write(file, buf, len, off));
}
EXPORT_SYMBOL(lustre_fwrite);

/*
 * Sync a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fsync(struct file *file)
{
        ENTRY;
        ASSERT_KERNEL_CTXT("kernel doing sync outside kernel context\n");
        if (!file || !file->f_op || !file->f_op->fsync)
                RETURN(-ENOSYS);

        RETURN(file->f_op->fsync(file, file->f_dentry, 0));
}
EXPORT_SYMBOL(lustre_fsync);
