/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/lvfs_linux.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/version.h>
#include <libcfs/kp30.h>
#include <lustre_fsfilt.h>
#include <obd.h>
#include <obd_class.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/lustre_compat25.h>
#include <lvfs.h>
#include "lvfs_internal.h"

#include <obd.h>
#include <lustre_lib.h>
#include <lustre_quota.h>

atomic_t obd_memory;
int obd_memmax;

/* Debugging check only needed during development */
#ifdef OBD_CTXT_DEBUG
# define ASSERT_CTXT_MAGIC(magic) LASSERT((magic) == OBD_RUN_CTXT_MAGIC)
# define ASSERT_NOT_KERNEL_CTXT(msg) LASSERTF(!segment_eq(get_fs(), get_ds()),\
                                              msg)
# define ASSERT_KERNEL_CTXT(msg) LASSERTF(segment_eq(get_fs(), get_ds()), msg)
#else
# define ASSERT_CTXT_MAGIC(magic) do {} while(0)
# define ASSERT_NOT_KERNEL_CTXT(msg) do {} while(0)
# define ASSERT_KERNEL_CTXT(msg) do {} while(0)
#endif

static void push_group_info(struct lvfs_run_ctxt *save,
                            struct group_info *ginfo)
{
        if (!ginfo) {
                save->ngroups = current_ngroups;
                current_ngroups = 0;
        } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
                task_lock(current);
                save->group_info = current->group_info;
                current->group_info = ginfo;
                task_unlock(current);
#else
                LASSERT(ginfo->ngroups <= NGROUPS);
                LASSERT(current->ngroups <= NGROUPS_SMALL);
                /* save old */
                save->group_info.ngroups = current->ngroups;
                if (current->ngroups)
                        memcpy(save->group_info.small_block, current->groups,
                               current->ngroups * sizeof(gid_t));
                /* push new */
                current->ngroups = ginfo->ngroups;
                if (ginfo->ngroups)
                        memcpy(current->groups, ginfo->small_block,
                               current->ngroups * sizeof(gid_t));
#endif
        }
}

static void pop_group_info(struct lvfs_run_ctxt *save,
                           struct group_info *ginfo)
{
        if (!ginfo) {
                current_ngroups = save->ngroups;
        } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
                task_lock(current);
                current->group_info = save->group_info;
                task_unlock(current);
#else
                current->ngroups = save->group_info.ngroups;
                if (current->ngroups)
                        memcpy(current->groups, save->group_info.small_block,
                               current->ngroups * sizeof(gid_t));
#endif
        }
}

/* push / pop to root of obd store */
void push_ctxt(struct lvfs_run_ctxt *save, struct lvfs_run_ctxt *new_ctx,
               struct lvfs_ucred *uc)
{
        //ASSERT_NOT_KERNEL_CTXT("already in kernel context!\n");
        ASSERT_CTXT_MAGIC(new_ctx->magic);
        OBD_SET_CTXT_MAGIC(save);

        /*
        CDEBUG(D_INFO,
               "= push %p->%p = cur fs %p pwd %p:d%d:i%d (%.*s), pwdmnt %p:%d\n",
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
        save->luc.luc_umask = current->fs->umask;
        save->ngroups = current->group_info->ngroups;

        LASSERT(save->pwd);
        LASSERT(save->pwdmnt);
        LASSERT(new_ctx->pwd);
        LASSERT(new_ctx->pwdmnt);

        if (uc) {
                save->luc.luc_uid = current->uid;
                save->luc.luc_gid = current->gid;
                save->luc.luc_fsuid = current->fsuid;
                save->luc.luc_fsgid = current->fsgid;
                save->luc.luc_cap = current->cap_effective;

                current->uid = uc->luc_uid;
                current->gid = uc->luc_gid;
                current->fsuid = uc->luc_fsuid;
                current->fsgid = uc->luc_fsgid;
                current->cap_effective = uc->luc_cap;

                push_group_info(save,
                                uc->luc_ginfo ?:
                                uc->luc_identity ? uc->luc_identity->mi_ginfo :
                                                   NULL);
        }
        current->fs->umask = 0; /* umask already applied on client */
        set_fs(new_ctx->fs);
        ll_set_fs_pwd(current->fs, new_ctx->pwdmnt, new_ctx->pwd);

        /*
        CDEBUG(D_INFO,
               "= push %p->%p = cur fs %p pwd %p:d%d:i%d (%.*s), pwdmnt %p:%d\n",
               new_ctx, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */
}
EXPORT_SYMBOL(push_ctxt);

void pop_ctxt(struct lvfs_run_ctxt *saved, struct lvfs_run_ctxt *new_ctx,
              struct lvfs_ucred *uc)
{
        //printk("pc0");
        ASSERT_CTXT_MAGIC(saved->magic);
        //printk("pc1");
        ASSERT_KERNEL_CTXT("popping non-kernel context!\n");

        /*
        CDEBUG(D_INFO,
               " = pop  %p==%p = cur %p pwd %p:d%d:i%d (%.*s), pwdmnt %p:%d\n",
               new_ctx, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */

        LASSERTF(current->fs->pwd == new_ctx->pwd, "%p != %p\n",
                 current->fs->pwd, new_ctx->pwd);
        LASSERTF(current->fs->pwdmnt == new_ctx->pwdmnt, "%p != %p\n",
                 current->fs->pwdmnt, new_ctx->pwdmnt);

        set_fs(saved->fs);
        ll_set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);

        dput(saved->pwd);
        mntput(saved->pwdmnt);
        current->fs->umask = saved->luc.luc_umask;
        if (uc) {
                current->uid = saved->luc.luc_uid;
                current->gid = saved->luc.luc_gid;
                current->fsuid = saved->luc.luc_fsuid;
                current->fsgid = saved->luc.luc_fsgid;
                current->cap_effective = saved->luc.luc_cap;
                pop_group_info(saved,
                               uc->luc_ginfo ?:
                               uc->luc_identity ? uc->luc_identity->mi_ginfo :
                                                  NULL);
        }

        /*
        CDEBUG(D_INFO,
               "= pop  %p->%p = cur fs %p pwd %p:d%d:i%d (%.*s), pwdmnt %p:%d\n",
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
struct dentry *simple_mknod(struct dentry *dir, char *name, int mode, int fix)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        // ASSERT_KERNEL_CTXT("kernel doing mknod outside kernel context\n");
        CDEBUG(D_INODE, "creating file %.*s\n", (int)strlen(name), name);

        dchild = ll_lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                int old_mode = dchild->d_inode->i_mode;
                if (!S_ISREG(old_mode))
                        GOTO(out_err, err = -EEXIST);

                /* Fixup file permissions if necessary */
                if (fix && (old_mode & S_IALLUGO) != (mode & S_IALLUGO)) {
                        CWARN("fixing permissions on %s from %o to %o\n",
                              name, old_mode, mode);
                        dchild->d_inode->i_mode = (mode & S_IALLUGO) |
                                                  (old_mode & ~S_IALLUGO);
                        mark_inode_dirty(dchild->d_inode);
                }
                GOTO(out_up, dchild);
        }

        err = ll_vfs_create(dir->d_inode, dchild, (mode & ~S_IFMT) | S_IFREG,
                            NULL);
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
struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode, int fix)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        // ASSERT_KERNEL_CTXT("kernel doing mkdir outside kernel context\n");
        CDEBUG(D_INODE, "creating directory %.*s\n", (int)strlen(name), name);
        dchild = ll_lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                int old_mode = dchild->d_inode->i_mode;
                if (!S_ISDIR(old_mode)) {
                        CERROR("found %s (%lu/%u) is mode %o\n", name,
                               dchild->d_inode->i_ino,
                               dchild->d_inode->i_generation, old_mode);
                        GOTO(out_err, err = -ENOTDIR);
                }

                /* Fixup directory permissions if necessary */
                if (fix && (old_mode & S_IALLUGO) != (mode & S_IALLUGO)) {
                        CDEBUG(D_CONFIG, 
                               "fixing permissions on %s from %o to %o\n",
                               name, old_mode, mode);
                        dchild->d_inode->i_mode = (mode & S_IALLUGO) |
                                                  (old_mode & ~S_IALLUGO);
                        mark_inode_dirty(dchild->d_inode);
                }
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

struct l_file *l_dentry_open(struct lvfs_run_ctxt *ctxt, struct l_dentry *de,
                             int flags)
{
        mntget(ctxt->pwdmnt);
        return dentry_open(de, ctxt->pwdmnt, flags);
}
EXPORT_SYMBOL(l_dentry_open);

static int l_filldir(void *__buf, const char *name, int namlen, loff_t offset,
                     ino_t ino, unsigned int d_type)
{
        struct l_linux_dirent *dirent;
        struct l_readdir_callback *buf = (struct l_readdir_callback *)__buf;

        dirent = buf->lrc_dirent;
        if (dirent)
               dirent->lld_off = offset;

        OBD_ALLOC(dirent, sizeof(*dirent));

        if (!dirent)
                return -ENOMEM;

        list_add_tail(&dirent->lld_list, buf->lrc_list);

        buf->lrc_dirent = dirent;
        dirent->lld_ino = ino;
        LASSERT(sizeof(dirent->lld_name) >= namlen + 1);
        memcpy(dirent->lld_name, name, namlen);

        return 0;
}

long l_readdir(struct file *file, struct list_head *dentry_list)
{
        struct l_linux_dirent *lastdirent;
        struct l_readdir_callback buf;
        int error;

        buf.lrc_dirent = NULL;
        buf.lrc_list = dentry_list;

        error = vfs_readdir(file, l_filldir, &buf);
        if (error < 0)
                return error;

        lastdirent = buf.lrc_dirent;
        if (lastdirent)
                lastdirent->lld_off = file->f_pos;

        return 0;
}
EXPORT_SYMBOL(l_readdir);
EXPORT_SYMBOL(obd_memory);
EXPORT_SYMBOL(obd_memmax);

#ifdef LUSTRE_KERNEL_VERSION
#ifdef HAVE_OLD_DEV_SET_RDONLY
void dev_set_rdonly(lvfs_sbdev_type dev, int no_write);
void dev_clear_rdonly(int no_write);
int dev_check_rdonly(lvfs_sbdev_type dev);
#elif !defined(HAVE_CLEAR_RDONLY_ON_PUT)
void dev_set_rdonly(lvfs_sbdev_type dev);
void dev_clear_rdonly(lvfs_sbdev_type dev);
int dev_check_rdonly(lvfs_sbdev_type dev);
#endif

void lvfs_set_rdonly(lvfs_sbdev_type dev)
{
        CDEBUG(D_IOCTL | D_HA, "set dev %lx rdonly\n", (long)dev);
        lvfs_sbdev_sync(dev);
#ifdef HAVE_OLD_DEV_SET_RDONLY
        dev_set_rdonly(dev, 2);
#else
        dev_set_rdonly(dev);
#endif
}

int lvfs_check_rdonly(lvfs_sbdev_type dev)
{
        return dev_check_rdonly(dev);
}

void lvfs_clear_rdonly(lvfs_sbdev_type dev)
{
#ifndef HAVE_CLEAR_RDONLY_ON_PUT
        CDEBUG(D_IOCTL | D_HA, "unset dev %lx rdonly\n", (long)dev);
        if (lvfs_check_rdonly(dev)) {
                lvfs_sbdev_sync(dev);
#ifdef HAVE_OLD_DEV_SET_RDONLY
                dev_clear_rdonly(2);
#else
                dev_clear_rdonly(dev);
#endif
        }
#else
        CDEBUG(D_IOCTL | D_HA, "(will unset dev %lx rdonly on put)\n",
               (long)dev);
#endif
}
EXPORT_SYMBOL(lvfs_set_rdonly);
EXPORT_SYMBOL(lvfs_check_rdonly);
EXPORT_SYMBOL(lvfs_clear_rdonly);
#endif

int lvfs_check_io_health(struct obd_device *obd, struct file *file)
{
        char *write_page = NULL;
        loff_t offset = 0;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(write_page, PAGE_SIZE);
        if (!write_page)
                RETURN(-ENOMEM);

        rc = fsfilt_write_record(obd, file, write_page, PAGE_SIZE, &offset, 1);

        OBD_FREE(write_page, PAGE_SIZE);

        CDEBUG(D_INFO, "write 1 page synchronously for checking io rc %d\n",rc);
        RETURN(rc);
}
EXPORT_SYMBOL(lvfs_check_io_health);

static int __init lvfs_linux_init(void)
{
        RETURN(0);
}

static void __exit lvfs_linux_exit(void)
{
        int leaked;
        ENTRY;

        leaked = atomic_read(&obd_memory);
        CDEBUG(leaked ? D_ERROR : D_INFO,
               "obd mem max: %d leaked: %d\n", obd_memmax, leaked);

        EXIT;
        return;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre VFS Filesystem Helper v0.1");
MODULE_LICENSE("GPL");

module_init(lvfs_linux_init);
module_exit(lvfs_linux_exit);
