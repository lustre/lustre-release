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
#include <linux/obd_class.h>

typedef void (*fsfilt_cb_t)(struct obd_device *obd, __u64 last_rcvd,
                            void *data, int error);

struct fsfilt_objinfo {
        struct dentry *fso_dentry;
        int fso_bufcnt;
};

struct fsfilt_operations {
        struct list_head fs_list;
        struct module *fs_owner;
        char   *fs_type;
        void   *(* fs_start)(struct inode *inode, int op, void *desc_private,
                             int logs);
        void   *(* fs_brw_start)(int objcount, struct fsfilt_objinfo *fso,
                                 int niocount, struct niobuf_local *nb,
                                 void *desc_private, int logs);
        int     (* fs_commit)(struct inode *inode, void *handle,int force_sync);
        int     (* fs_commit_async)(struct inode *inode, void *handle,
                                        void **wait_handle);
        int     (* fs_commit_wait)(struct inode *inode, void *handle);
        int     (* fs_setattr)(struct dentry *dentry, void *handle,
                               struct iattr *iattr, int do_trunc);
        int     (* fs_iocontrol)(struct inode *inode, struct file *file,
                                 unsigned int cmd, unsigned long arg);
        int     (* fs_set_md)(struct inode *inode, void *handle, void *md,
                              int size);
        int     (* fs_get_md)(struct inode *inode, void *md, int size);
        ssize_t (* fs_readpage)(struct file *file, char *buf, size_t count,
                                loff_t *offset);
        int     (* fs_add_journal_cb)(struct obd_device *obd, __u64 last_rcvd,
                                      void *handle, fsfilt_cb_t cb_func,
                                      void *cb_data);
        int     (* fs_statfs)(struct super_block *sb, struct obd_statfs *osfs);
        int     (* fs_sync)(struct super_block *sb);
        int     (* fs_map_inode_page)(struct inode *inode, struct page *page,
                                      unsigned long *blocks, int *created,
                                      int create);
        int     (* fs_prep_san_write)(struct inode *inode, long *blocks,
                                      int nblocks, loff_t newsize);
        int     (* fs_write_record)(struct file *, void *, int size, loff_t *,
                                    int force_sync);
        int     (* fs_read_record)(struct file *, void *, int size, loff_t *);
        int     (* fs_setup)(struct super_block *sb);
        int     (* fs_get_op_len)(int, struct fsfilt_objinfo *, int);
};

extern int fsfilt_register_ops(struct fsfilt_operations *fs_ops);
extern void fsfilt_unregister_ops(struct fsfilt_operations *fs_ops);
extern struct fsfilt_operations *fsfilt_get_ops(const char *type);
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
#define FSFILT_OP_CANCEL_UNLINK 10

struct obd_handle {
        void *orh_filt_handle;
        int orh_reserve;
};

/* very similar to obd_statfs(), but caller already holds obd_osfs_lock */
static inline int fsfilt_statfs(struct obd_device *obd, struct super_block *sb,
                                unsigned long max_age)
{
        int rc = 0;

        CDEBUG(D_SUPER, "osfs %lu, max_age %lu\n", obd->obd_osfs_age, max_age);
        if (time_before(obd->obd_osfs_age, max_age)) {
                rc = obd->obd_fsops->fs_statfs(sb, &obd->obd_osfs);
                if (rc == 0) /* N.B. statfs can't really fail */
                        obd->obd_osfs_age = jiffies;
        } else {
                CDEBUG(D_SUPER, "using cached obd_statfs data\n");
        }

        return rc;
}

static inline int fsfilt_reserve(struct obd_device *obd, struct super_block *sb,
                                 int reserve, struct obd_handle **h)
{
        struct obd_handle *handle;

        OBD_ALLOC(handle, sizeof(*handle));
        if (!handle)
                return -ENOMEM;

        /* Perform space reservation if needed */
        if (reserve) {
                spin_lock(&obd->obd_osfs_lock);
                obd->obd_reserve_freespace_estimated -= reserve;
                if (obd->obd_reserve_freespace_estimated < 0) {
                        int rc = fsfilt_statfs(obd, sb, jiffies - 1);
                        if (rc) {
                                CERROR("statfs failed during reservation\n");
                                spin_unlock(&obd->obd_osfs_lock);
                                OBD_FREE(handle, sizeof(*handle));
                                return rc;
                        }
                        /* Some filesystems (e.g. reiserfs) report more space
                         * available compared to what is really available
                         * (reiserfs reserves 1996K for itself).
                         */
                        obd->obd_reserve_freespace_estimated =
                                obd->obd_osfs.os_bfree-obd->obd_reserve_space;
                        if (obd->obd_reserve_freespace_estimated < reserve) {
                                spin_unlock(&obd->obd_osfs_lock);
                                OBD_FREE(handle, sizeof(*handle));
                                return -ENOSPC;
                        }
                        obd->obd_reserve_freespace_estimated -= reserve;
                }
                obd->obd_reserve_space += reserve;
                handle->orh_reserve = reserve;
                spin_unlock(&obd->obd_osfs_lock);
        }
        *h = handle;
        return 0;
}

static inline void fsfilt_release(struct obd_device *obd,
                                  struct obd_handle *handle)
{
        struct obd_handle *h = handle;

        spin_lock(&obd->obd_osfs_lock);
        obd->obd_reserve_space -= h->orh_reserve;
        LASSERT(obd->obd_reserve_space >= 0);
        spin_unlock(&obd->obd_osfs_lock);

        OBD_FREE(h, sizeof(*h));
}

static inline void *fsfilt_start_log(struct obd_device *obd,
                                     struct inode *inode, int op,
                                     struct obd_trans_info *oti, int logs)
{
        unsigned long now = jiffies;
        struct obd_handle *parent_handle = oti ? oti->oti_handle : NULL, *h;
        int reserve = 0;
        int rc;

        if (obd->obd_fsops->fs_get_op_len)
                reserve = obd->obd_fsops->fs_get_op_len(op, NULL, logs);

        rc = fsfilt_reserve(obd, inode->i_sb, reserve, &h);
        if (rc)
                return ERR_PTR(rc);

        h->orh_filt_handle = obd->obd_fsops->fs_start(inode, op, parent_handle,
                                                      logs);
        CDEBUG(D_HA, "started handle %p (%p)\n", h->orh_filt_handle,
               parent_handle);
        if (IS_ERR(h->orh_filt_handle)) {
                rc = PTR_ERR(h->orh_filt_handle);
                fsfilt_release(obd, h);
                RETURN(ERR_PTR(rc));
        }

        if (oti != NULL) {
                if (parent_handle == NULL) {
                        oti->oti_handle = h;
                } else if (h->orh_filt_handle != parent_handle) {
                        CERROR("mismatch: parent %p, handle %p, oti %p\n",
                               parent_handle->orh_filt_handle,
                               h->orh_filt_handle, oti);
                        LBUG();
                }
        }
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);
        return h;
}

static inline void *fsfilt_start(struct obd_device *obd,
                                        struct inode *inode, int op,
                                        struct obd_trans_info *oti)
{
        return fsfilt_start_log(obd, inode, op, oti, 0);
}

static inline void *fsfilt_brw_start_log(struct obd_device *obd,
                                         int objcount,
                                         struct fsfilt_objinfo *fso,
                                         int niocount, struct niobuf_local *nb,
                                         struct obd_trans_info *oti, int logs)
{
        unsigned long now = jiffies;
        struct obd_handle *parent_handle = oti ? oti->oti_handle : NULL, *h;
        int reserve = 0;
        int rc;

        if (obd->obd_fsops->fs_get_op_len)
                reserve = obd->obd_fsops->fs_get_op_len(objcount, fso, logs);

        rc = fsfilt_reserve(obd, fso->fso_dentry->d_inode->i_sb, reserve, &h);
        if (rc)
                return ERR_PTR(rc);

        h->orh_filt_handle = obd->obd_fsops->fs_brw_start(objcount, fso,
                                                          niocount, nb,
                                                          parent_handle, logs);
        CDEBUG(D_HA, "started handle %p (%p)\n", h->orh_filt_handle,
                                                 parent_handle);

        if (oti != NULL) {
                if (parent_handle == NULL) {
                        oti->oti_handle = h;
                } else if (h->orh_filt_handle !=
                           parent_handle->orh_filt_handle) {
                        CERROR("mismatch: parent %p, handle %p, oti %p\n",
                               parent_handle->orh_filt_handle,
                               h->orh_filt_handle, oti);
                        LBUG();
                }
        }
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);

        return h;
}

static inline void *fsfilt_brw_start(struct obd_device *obd, int objcount,
                                     struct fsfilt_objinfo *fso, int niocount,
                                     struct niobuf_local *nb,
                                     struct obd_trans_info *oti)
{
        return fsfilt_brw_start_log(obd, objcount, fso, niocount, nb, oti, 0);
}

static inline int fsfilt_commit(struct obd_device *obd, struct inode *inode,
                                void *handle, int force_sync)
{
        unsigned long now = jiffies;
        struct obd_handle *h = handle;
        int rc;

        rc = obd->obd_fsops->fs_commit(inode, h->orh_filt_handle, force_sync);
        CDEBUG(D_HA, "committing handle %p\n", h->orh_filt_handle);

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);

        fsfilt_release(obd, h);

        return rc;
}

static inline int fsfilt_commit_async(struct obd_device *obd,
                                      struct inode *inode, void *handle,
                                      void **wait_handle)
{
        unsigned long now = jiffies;
        struct obd_handle *h = handle;
        int rc;

        rc = obd->obd_fsops->fs_commit_async(inode, h->orh_filt_handle,
                                             wait_handle);

        CDEBUG(D_HA, "committing handle %p (async)\n", *wait_handle);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);

        fsfilt_release(obd, h);

        return rc;
}

static inline int fsfilt_commit_wait(struct obd_device *obd,
                                     struct inode *inode, void *handle)
{
        unsigned long now = jiffies;
        int rc = obd->obd_fsops->fs_commit_wait(inode, handle);
        CDEBUG(D_HA, "waiting for completion %p\n", handle);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);
        return rc;
}

static inline int fsfilt_setattr(struct obd_device *obd, struct dentry *dentry,
                                 void *handle, struct iattr *iattr,int do_trunc)
{
        unsigned long now = jiffies;
        struct obd_handle *h = handle;
        int rc;
        rc = obd->obd_fsops->fs_setattr(dentry, h->orh_filt_handle, iattr, do_trunc);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long setattr time %lus\n", (jiffies - now) / HZ);
        return rc;
}

static inline int fsfilt_iocontrol(struct obd_device *obd, struct inode *inode,
                                   struct file *file, unsigned int cmd,
                                   unsigned long arg)
{
        return obd->obd_fsops->fs_iocontrol(inode, file, cmd, arg);
}

static inline int fsfilt_set_md(struct obd_device *obd, struct inode *inode,
                                void *handle, void *md, int size)
{
        struct obd_handle *h = handle;
        return obd->obd_fsops->fs_set_md(inode, h->orh_filt_handle, md, size);
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

static inline int fsfilt_add_journal_cb(struct obd_device *obd, __u64 last_rcvd,
                                        void *handle, fsfilt_cb_t cb_func,
                                        void *cb_data)
{
        struct obd_handle *h = handle;
        return obd->obd_fsops->fs_add_journal_cb(obd, last_rcvd,
                                                 h->orh_filt_handle, cb_func,
                                                 cb_data);
}

static inline int fsfilt_sync(struct obd_device *obd, struct super_block *sb)
{
        return obd->obd_fsops->fs_sync(sb);
}

static inline int fsfilt_map_inode_page(struct obd_device *obd,
                                        struct inode *inode, struct page *page,
                                        unsigned long *blocks, int *created,
                                        int create)
{
        return obd->obd_fsops->fs_map_inode_page(inode, page, blocks, created,
                                                 create);
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

static inline int fsfilt_read_record(struct obd_device *obd, struct file *file,
                                     void *buf, loff_t size, loff_t *offs)
{
        return obd->obd_fsops->fs_read_record(file, buf, size, offs);
}

static inline int fsfilt_write_record(struct obd_device *obd, struct file *file,
                                      void *buf, loff_t size, loff_t *offs,
                                      int force_sync)
{
        return obd->obd_fsops->fs_write_record(file, buf, size,offs,force_sync);
}

static inline int fsfilt_setup(struct obd_device *obd, struct super_block *fs)
{
        if (obd->obd_fsops->fs_setup)
                return obd->obd_fsops->fs_setup(fs);
        return 0;
}

#endif /* __KERNEL__ */

#endif
