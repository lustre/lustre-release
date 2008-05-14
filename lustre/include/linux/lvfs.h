/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 *
 * lustre VFS/process permission interface
 */

#ifndef __LINUX_LVFS_H__
#define __LINUX_LVFS_H__

#ifndef __LVFS_H__
#error Do not #include this file directly. #include <lvfs.h> instead
#endif

#if defined __KERNEL__
#include <linux/lustre_compat25.h>
#include <linux/lvfs_linux.h>
#else
struct group_info { /* unused */ };
#include <liblustre.h>
#endif

#define LLOG_LVFS

/* simple.c */

struct lvfs_ucred {
        __u32                   luc_uid;
        __u32                   luc_gid;
        __u32                   luc_fsuid;
        __u32                   luc_fsgid;
        __u32                   luc_cap;
        __u32                   luc_umask;
	struct group_info      *luc_ginfo;
	struct md_identity     *luc_identity;
};

struct lvfs_callback_ops {
        struct dentry *(*l_fid2dentry)(__u64 id_ino, __u32 gen, __u64 gr, void *data);
};

#define OBD_RUN_CTXT_MAGIC      0xC0FFEEAA
#define OBD_CTXT_DEBUG          /* development-only debugging */
struct lvfs_run_ctxt {
        struct vfsmount         *pwdmnt;
        struct dentry           *pwd;
        mm_segment_t             fs;
        struct lvfs_ucred        luc;
        int                      ngroups;
        struct lvfs_callback_ops cb_ops;
        struct group_info       *group_info;
#ifdef OBD_CTXT_DEBUG
        __u32                    magic;
#endif
};

#ifdef OBD_CTXT_DEBUG
#define OBD_SET_CTXT_MAGIC(ctxt) (ctxt)->magic = OBD_RUN_CTXT_MAGIC
#else
#define OBD_SET_CTXT_MAGIC(ctxt) do {} while(0)
#endif

#ifdef __KERNEL__

struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode, int fix);
struct dentry *simple_mknod(struct dentry *dir, char *name, int mode, int fix);
int lustre_rename(struct dentry *dir, char *oldname, char *newname);
int lustre_fread(struct file *file, void *buf, int len, loff_t *off);
int lustre_fwrite(struct file *file, const void *buf, int len, loff_t *off);
int lustre_fsync(struct file *file);
long l_readdir(struct file * file, struct list_head *dentry_list);

static inline void l_dput(struct dentry *de)
{
        if (!de || IS_ERR(de))
                return;
        //shrink_dcache_parent(de);
        LASSERT(atomic_read(&de->d_count) > 0);
        dput(de);
}

/* We need to hold the inode semaphore over the dcache lookup itself, or we
 * run the risk of entering the filesystem lookup path concurrently on SMP
 * systems, and instantiating two inodes for the same entry.  We still
 * protect against concurrent addition/removal races with the DLM locking.
 */
static inline struct dentry *ll_lookup_one_len(const char *fid_name,
                                               struct dentry *dparent,
                                               int fid_namelen)
{
        struct dentry *dchild;

        LOCK_INODE_MUTEX(dparent->d_inode);
        dchild = lookup_one_len(fid_name, dparent, fid_namelen);
        UNLOCK_INODE_MUTEX(dparent->d_inode);

        if (IS_ERR(dchild) || dchild->d_inode == NULL)
                return dchild;

        if (is_bad_inode(dchild->d_inode)) {
                CERROR("bad inode returned %lu/%u\n",
                       dchild->d_inode->i_ino, dchild->d_inode->i_generation);
                dput(dchild);
                dchild = ERR_PTR(-ENOENT);
        }
        return dchild;
}

static inline void ll_sleep(int t)
{
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(t * HZ);
        set_current_state(TASK_RUNNING);
}
#endif

#endif
