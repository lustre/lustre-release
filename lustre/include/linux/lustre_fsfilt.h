/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <info@clusterfs.com>
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
 * Filesystem interface helper.
 *
 */

#ifndef _LUSTRE_FSFILT_H
#define _LUSTRE_FSFILT_H

#ifdef __KERNEL__

#include <linux/obd.h>
#include <linux/fs.h>

typedef void (*fsfilt_cb_t)(struct obd_device *obd, __u64 last_rcvd, int error);

struct fsfilt_objinfo {
        struct dentry *fso_dentry;
        int fso_bufcnt;
};

struct fsfilt_operations {
        struct list_head fs_list;
        struct module *fs_owner;
        char   *fs_type;
        void   *(* fs_start)(struct inode *inode, int op);
        void   *(* fs_brw_start)(int objcount, struct fsfilt_objinfo *fso,
                                 int niocount, struct niobuf_remote *nb);
        int     (* fs_commit)(struct inode *inode, void *handle);
        int     (* fs_setattr)(struct dentry *dentry, void *handle,
                               struct iattr *iattr);
        int     (* fs_set_md)(struct inode *inode, void *handle, void *md,
                              int size);
        int     (* fs_get_md)(struct inode *inode, void *md, int size);
        ssize_t (* fs_readpage)(struct file *file, char *buf, size_t count,
                                loff_t *offset);
        int     (* fs_journal_data)(struct file *file);
        int     (* fs_set_last_rcvd)(struct obd_device *obd, __u64 last_rcvd,
                                     void *handle, fsfilt_cb_t cb_func);
        int     (* fs_statfs)(struct super_block *sb, struct obd_statfs *osfs);
        int     (* fs_prep_san_write)(struct inode *inode, long *blocks,
                                      int nblocks, loff_t newsize);
};

extern int fsfilt_register_ops(struct fsfilt_operations *fs_ops);
extern void fsfilt_unregister_ops(struct fsfilt_operations *fs_ops);
extern struct fsfilt_operations *fsfilt_get_ops(char *type);
extern void fsfilt_put_ops(struct fsfilt_operations *fs_ops);

#define FSFILT_OP_UNLINK         1
#define FSFILT_OP_RMDIR          2
#define FSFILT_OP_RENAME         3
#define FSFILT_OP_CREATE         4
#define FSFILT_OP_MKDIR          5
#define FSFILT_OP_SYMLINK        6
#define FSFILT_OP_MKNOD          7
#define FSFILT_OP_SETATTR        8
#define FSFILT_OP_LINK           9

static inline void *fsfilt_start(struct obd_device *obd,
                                 struct inode *inode, int op)
{
        return obd->obd_fsops->fs_start(inode, op);
}

static inline void *fsfilt_brw_start(struct obd_device *obd, int objcount,
                                     struct fsfilt_objinfo *fso, int niocount,
                                     struct niobuf_remote *nb)
{
        return obd->obd_fsops->fs_brw_start(objcount, fso, niocount, nb);
}

static inline int fsfilt_commit(struct obd_device *obd, struct inode *inode,
                                void *handle)
{
        return obd->obd_fsops->fs_commit(inode, handle);
}

static inline int fsfilt_setattr(struct obd_device *obd, struct dentry *dentry,
                                 void *handle, struct iattr *iattr)
{
        int rc;
        /*
         * NOTE: we probably don't need to take i_sem here when changing
         *       ATTR_SIZE because the MDS never needs to truncate a file.
         *       The ext2/ext3 code never truncates a directory, and files
         *       stored on the MDS are entirely sparse (no data blocks).
         *       If we do need to get it, we can do it here.
         */
        lock_kernel();
        rc = obd->obd_fsops->fs_setattr(dentry, handle, iattr);
        unlock_kernel();

        return rc;
}

static inline int fsfilt_set_md(struct obd_device *obd, struct inode *inode,
                                void *handle, void *md, int size)
{
        return obd->obd_fsops->fs_set_md(inode, handle, md, size);
}

static inline int fsfilt_get_md(struct obd_device *obd, struct inode *inode,
                                void *md, int size)
{
        return obd->obd_fsops->fs_get_md(inode, md, size);
}

static inline ssize_t fsfilt_readpage(struct obd_device *obd,
                                      struct file *file, char *buf,
                                      size_t count, loff_t *offset)
{
        return obd->obd_fsops->fs_readpage(file, buf, count, offset);
}

static inline int fsfilt_journal_data(struct obd_device *obd, struct file *file)
{
        return obd->obd_fsops->fs_journal_data(file);
}

static inline int fsfilt_set_last_rcvd(struct obd_device *obd, __u64 last_rcvd,
                                       void *handle, fsfilt_cb_t cb_func)
{
        return obd->obd_fsops->fs_set_last_rcvd(obd, last_rcvd,handle,cb_func);
}

static inline int fsfilt_statfs(struct obd_device *obd, struct super_block *fs,
                                struct obd_statfs *osfs)
{
        return obd->obd_fsops->fs_statfs(fs, osfs);
}

static inline int fs_prep_san_write(struct obd_device *obd,
                                    struct inode *inode,
                                    long *blocks,
                                    int nblocks,
                                    loff_t newsize)
{
        return obd->obd_fsops->fs_prep_san_write(inode, blocks,
                                                 nblocks, newsize);
}
#endif /* __KERNEL__ */

#endif
