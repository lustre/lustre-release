/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/linux/lustre_fsfilt.h
 *
 * Filesystem interface helper.
 */

#ifndef _LINUX_LUSTRE_FSFILT_H
#define _LINUX_LUSTRE_FSFILT_H

#ifndef _LUSTRE_FSFILT_H
#error Do not #include this file directly. #include <lustre_fsfilt.h> instead
#endif

#ifdef __KERNEL__

#include <obd.h>
#include <obd_class.h>

typedef void (*fsfilt_cb_t)(struct obd_device *obd, __u64 last_rcvd,
                            void *data, int error);

struct fsfilt_objinfo {
        struct dentry *fso_dentry;
        int fso_bufcnt;
};

struct fsfilt_fid {
        __u32 ino;
        __u32 gen;
};

struct lustre_dquot;
struct fsfilt_operations {
        cfs_list_t fs_list;
        cfs_module_t *fs_owner;
        char   *fs_type;
        char   *(* fs_getlabel)(struct super_block *sb);
        int     (* fs_setlabel)(struct super_block *sb, char *label);
        char   *(* fs_uuid)(struct super_block *sb);
        void   *(* fs_start)(struct inode *inode, int op, void *desc_private,
                             int logs);
        void   *(* fs_brw_start)(int objcount, struct fsfilt_objinfo *fso,
                                 int niocount, struct niobuf_local *nb,
                                 void *desc_private, int logs);
        int     (* fs_extend)(struct inode *inode, unsigned nblocks, void *h);
        int     (* fs_commit)(struct inode *inode, void *handle,int force_sync);
        int     (* fs_commit_async)(struct inode *inode, void *handle,
                                        void **wait_handle);
        int     (* fs_commit_wait)(struct inode *inode, void *handle);
        int     (* fs_setattr)(struct dentry *dentry, void *handle,
                               struct iattr *iattr, int do_trunc);
        int     (* fs_iocontrol)(struct inode *inode, struct file *file,
                                 unsigned int cmd, unsigned long arg);
        int     (* fs_set_md)(struct inode *inode, void *handle, void *md,
                              int size, const char *name);
        int     (* fs_get_md)(struct inode *inode, void *md, int size,
                              const char *name);
        /*
         * this method is needed to make IO operation fsfilt nature depend.
         *
         * This operation maybe synchronous or asynchronous.
         *
         * Return convention: positive number of bytes written (synchronously)
         * on success. Negative errno value on failure. Zero if asynchronous
         * IO was submitted successfully.
         *
         */
        int     (* fs_send_bio)(int rw, struct inode *inode,struct kiobuf *bio);
        ssize_t (* fs_readpage)(struct file *file, char *buf, size_t count,
                                loff_t *offset);
        int     (* fs_add_journal_cb)(struct obd_device *obd, __u64 last_rcvd,
                                      void *handle, fsfilt_cb_t cb_func,
                                      void *cb_data);
        int     (* fs_statfs)(struct super_block *sb, struct obd_statfs *osfs);
        int     (* fs_sync)(struct super_block *sb);
        int     (* fs_map_inode_pages)(struct inode *inode, struct page **page,
                                       int pages, unsigned long *blocks,
                                       int *created, int create,
                                       cfs_mutex_t *sem);
        int     (* fs_write_record)(struct file *, void *, int size, loff_t *,
                                    int force_sync);
        int     (* fs_read_record)(struct file *, void *, int size, loff_t *);
        int     (* fs_setup)(struct super_block *sb);
        int     (* fs_get_op_len)(int, struct fsfilt_objinfo *, int);
        int     (* fs_quotacheck)(struct super_block *sb,
                                  struct obd_quotactl *oqctl);
        __u64   (* fs_get_version) (struct inode *inode);
        __u64   (* fs_set_version) (struct inode *inode, __u64 new_version);
        int     (* fs_quotactl)(struct super_block *sb,
                                struct obd_quotactl *oqctl);
        int     (* fs_quotainfo)(struct lustre_quota_info *lqi, int type,
                                 int cmd);
        int     (* fs_qids)(struct file *file, struct inode *inode, int type,
                            cfs_list_t *list);
        int     (* fs_get_mblk)(struct super_block *sb, int *count,
                                struct inode *inode, int frags);
        int     (* fs_dquot)(struct lustre_dquot *dquot, int cmd);
        lvfs_sbdev_type (* fs_journal_sbdev)(struct super_block *sb);
        struct dentry  *(* fs_fid2dentry)(struct vfsmount *mnt,
                                          struct fsfilt_fid *fid,
                                          int ignore_gen);
};

extern int fsfilt_register_ops(struct fsfilt_operations *fs_ops);
extern void fsfilt_unregister_ops(struct fsfilt_operations *fs_ops);
extern struct fsfilt_operations *fsfilt_get_ops(const char *type);
extern void fsfilt_put_ops(struct fsfilt_operations *fs_ops);

static inline char *fsfilt_get_label(struct obd_device *obd,
                                     struct super_block *sb)
{
        if (obd->obd_fsops->fs_getlabel == NULL)
                return NULL;
        if (obd->obd_fsops->fs_getlabel(sb)[0] == '\0')
                return NULL;

        return obd->obd_fsops->fs_getlabel(sb);
}

static inline int fsfilt_set_label(struct obd_device *obd,
                                   struct super_block *sb, char *label)
{
        if (obd->obd_fsops->fs_setlabel == NULL)
                return -ENOSYS;
        return (obd->obd_fsops->fs_setlabel(sb, label));
}

static inline __u8 *fsfilt_uuid(struct obd_device *obd, struct super_block *sb)
{
        if (obd->obd_fsops->fs_uuid == NULL)
                return NULL;

        return obd->obd_fsops->fs_uuid(sb);
}

static inline lvfs_sbdev_type fsfilt_journal_sbdev(struct obd_device *obd,
                                                   struct super_block *sb)
{
        if (obd && obd->obd_fsops && obd->obd_fsops->fs_journal_sbdev)
                return obd->obd_fsops->fs_journal_sbdev(sb);
        return (lvfs_sbdev_type)0;
}

#define FSFILT_OP_UNLINK                1
#define FSFILT_OP_RMDIR                 2
#define FSFILT_OP_RENAME                3
#define FSFILT_OP_CREATE                4
#define FSFILT_OP_MKDIR                 5
#define FSFILT_OP_SYMLINK               6
#define FSFILT_OP_MKNOD                 7
#define FSFILT_OP_SETATTR               8
#define FSFILT_OP_LINK                  9
#define FSFILT_OP_CANCEL_UNLINK         10
#define FSFILT_OP_NOOP                  15
#define FSFILT_OP_UNLINK_PARTIAL_CHILD  21
#define FSFILT_OP_UNLINK_PARTIAL_PARENT 22
#define FSFILT_OP_CREATE_PARTIAL_CHILD  23

#define __fsfilt_check_slow(obd, start, msg)                              \
do {                                                                      \
        if (cfs_time_before(jiffies, start + 15 * CFS_HZ))                \
                break;                                                    \
        else if (cfs_time_before(jiffies, start + 30 * CFS_HZ))           \
                CDEBUG(D_VFSTRACE, "%s: slow %s %lus\n", obd->obd_name,   \
                       msg, (jiffies-start) / CFS_HZ);                    \
        else if (cfs_time_before(jiffies, start + DISK_TIMEOUT * CFS_HZ)) \
                CWARN("%s: slow %s %lus\n", obd->obd_name, msg,           \
                      (jiffies - start) / CFS_HZ);                        \
        else                                                              \
                CERROR("%s: slow %s %lus\n", obd->obd_name, msg,          \
                       (jiffies - start) / CFS_HZ);                       \
} while (0)

#define fsfilt_check_slow(obd, start, msg)              \
do {                                                    \
        __fsfilt_check_slow(obd, start, msg);           \
        start = jiffies;                                \
} while (0)

static inline void *fsfilt_start_log(struct obd_device *obd,
                                     struct inode *inode, int op,
                                     struct obd_trans_info *oti, int logs)
{
        unsigned long now = jiffies;
        void *parent_handle = oti ? oti->oti_handle : NULL;
        void *handle;

        handle = obd->obd_fsops->fs_start(inode, op, parent_handle, logs);
        CDEBUG(D_INFO, "started handle %p (%p)\n", handle, parent_handle);

        if (oti != NULL) {
                if (parent_handle == NULL) {
                        oti->oti_handle = handle;
                } else if (handle != parent_handle) {
                        CERROR("mismatch: parent %p, handle %p, oti %p\n",
                               parent_handle, handle, oti);
                        LBUG();
                }
        }
        fsfilt_check_slow(obd, now, "journal start");
        return handle;
}

static inline void *fsfilt_start(struct obd_device *obd, struct inode *inode,
                                 int op, struct obd_trans_info *oti)
{
        return fsfilt_start_log(obd, inode, op, oti, 0);
}

static inline void *fsfilt_brw_start_log(struct obd_device *obd, int objcount,
                                         struct fsfilt_objinfo *fso,
                                         int niocount, struct niobuf_local *nb,
                                         struct obd_trans_info *oti, int logs)
{
        unsigned long now = jiffies;
        void *parent_handle = oti ? oti->oti_handle : NULL;
        void *handle;

        handle = obd->obd_fsops->fs_brw_start(objcount, fso, niocount, nb,
                                              parent_handle, logs);
        CDEBUG(D_INFO, "started handle %p (%p)\n", handle, parent_handle);

        if (oti != NULL) {
                if (parent_handle == NULL) {
                        oti->oti_handle = handle;
                } else if (handle != parent_handle) {
                        CERROR("mismatch: parent %p, handle %p, oti %p\n",
                               parent_handle, handle, oti);
                        LBUG();
                }
        }
        fsfilt_check_slow(obd, now, "journal start");

        return handle;
}

static inline void *fsfilt_brw_start(struct obd_device *obd, int objcount,
                                     struct fsfilt_objinfo *fso, int niocount,
                                     struct niobuf_local *nb,
                                     struct obd_trans_info *oti)
{
        return fsfilt_brw_start_log(obd, objcount, fso, niocount, nb, oti, 0);
}

static inline int fsfilt_extend(struct obd_device *obd, struct inode *inode,
                                unsigned int nblocks, void *handle)
{
        unsigned long now = jiffies;
        int rc = obd->obd_fsops->fs_extend(inode, nblocks, handle);
        CDEBUG(D_INFO, "extending handle %p with %u blocks\n", handle, nblocks);

        fsfilt_check_slow(obd, now, "journal extend");

        return rc;
}

static inline int fsfilt_commit(struct obd_device *obd, struct inode *inode,
                                void *handle, int force_sync)
{
        unsigned long now = jiffies;
        int rc = obd->obd_fsops->fs_commit(inode, handle, force_sync);
        CDEBUG(D_INFO, "committing handle %p\n", handle);

        fsfilt_check_slow(obd, now, "journal start");

        return rc;
}

static inline int fsfilt_commit_async(struct obd_device *obd,
                                      struct inode *inode, void *handle,
                                      void **wait_handle)
{
        unsigned long now = jiffies;
        int rc = obd->obd_fsops->fs_commit_async(inode, handle, wait_handle);

        CDEBUG(D_INFO, "committing handle %p (async)\n", *wait_handle);
        fsfilt_check_slow(obd, now, "journal start");

        return rc;
}

static inline int fsfilt_commit_wait(struct obd_device *obd,
                                     struct inode *inode, void *handle)
{
        unsigned long now = jiffies;
        int rc = obd->obd_fsops->fs_commit_wait(inode, handle);
        CDEBUG(D_INFO, "waiting for completion %p\n", handle);
        fsfilt_check_slow(obd, now, "journal start");
        return rc;
}

static inline int fsfilt_setattr(struct obd_device *obd, struct dentry *dentry,
                                 void *handle, struct iattr *iattr,int do_trunc)
{
        unsigned long now = jiffies;
        int rc;
        rc = obd->obd_fsops->fs_setattr(dentry, handle, iattr, do_trunc);
        fsfilt_check_slow(obd, now, "setattr");
        return rc;
}

static inline int fsfilt_iocontrol(struct obd_device *obd, struct dentry *dentry,
                                   unsigned int cmd, unsigned long arg)
{
        struct file *dummy_file = NULL;
        int ret;

        OBD_ALLOC_PTR(dummy_file);
        if (!dummy_file)
                return(-ENOMEM);

        dummy_file->f_dentry = dentry;
        dummy_file->f_vfsmnt = obd->u.obt.obt_vfsmnt;

        ret = obd->obd_fsops->fs_iocontrol(dentry->d_inode, dummy_file, cmd,
                                           arg);

        OBD_FREE_PTR(dummy_file);
        return ret;
}

static inline int fsfilt_set_md(struct obd_device *obd, struct inode *inode,
                                void *handle, void *md, int size,
                                const char *name)
{
        return obd->obd_fsops->fs_set_md(inode, handle, md, size, name);
}

static inline int fsfilt_get_md(struct obd_device *obd, struct inode *inode,
                                void *md, int size, const char *name)
{
        return obd->obd_fsops->fs_get_md(inode, md, size, name);
}

static inline int fsfilt_send_bio(int rw, struct obd_device *obd,
                                  struct inode *inode, void *bio)
{
        LASSERTF(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ, "%x\n", rw);

        if (rw == OBD_BRW_READ)
                return obd->obd_fsops->fs_send_bio(READ, inode, bio);
        return obd->obd_fsops->fs_send_bio(WRITE, inode, bio);
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
        return obd->obd_fsops->fs_add_journal_cb(obd, last_rcvd,
                                                 handle, cb_func, cb_data);
}

/* very similar to obd_statfs(), but caller already holds obd_osfs_lock */
static inline int fsfilt_statfs(struct obd_device *obd, struct super_block *sb,
                                __u64 max_age)
{
        int rc = 0;

        CDEBUG(D_SUPER, "osfs "LPU64", max_age "LPU64"\n",
                obd->obd_osfs_age, max_age);
        if (cfs_time_before_64(obd->obd_osfs_age, max_age)) {
                rc = obd->obd_fsops->fs_statfs(sb, &obd->obd_osfs);
                if (rc == 0) /* N.B. statfs can't really fail */
                        obd->obd_osfs_age = cfs_time_current_64();
        } else {
                CDEBUG(D_SUPER, "using cached obd_statfs data\n");
        }

        return rc;
}

static inline int fsfilt_sync(struct obd_device *obd, struct super_block *sb)
{
        return obd->obd_fsops->fs_sync(sb);
}

static inline int fsfilt_quotacheck(struct obd_device *obd,
                                    struct super_block *sb,
                                    struct obd_quotactl *oqctl)
{
        if (obd->obd_fsops->fs_quotacheck)
                return obd->obd_fsops->fs_quotacheck(sb, oqctl);
        return -ENOTSUPP;
}

static inline int fsfilt_quotactl(struct obd_device *obd,
                                  struct super_block *sb,
                                  struct obd_quotactl *oqctl)
{
        if (obd->obd_fsops->fs_quotactl)
                return obd->obd_fsops->fs_quotactl(sb, oqctl);
        return -ENOTSUPP;
}

static inline int fsfilt_quotainfo(struct obd_device *obd,
                                   struct lustre_quota_info *lqi,
                                   int type, int cmd)
{
        if (obd->obd_fsops->fs_quotainfo)
                return obd->obd_fsops->fs_quotainfo(lqi, type, cmd);
        return -ENOTSUPP;
}

static inline int fsfilt_qids(struct obd_device *obd, struct file *file,
                              struct inode *inode, int type,
                              cfs_list_t *list)
{
        if (obd->obd_fsops->fs_qids)
                return obd->obd_fsops->fs_qids(file, inode, type, list);
        return -ENOTSUPP;
}

static inline int fsfilt_dquot(struct obd_device *obd,
                               struct lustre_dquot *dquot, int cmd)
{
        if (obd->obd_fsops->fs_dquot)
                return obd->obd_fsops->fs_dquot(dquot, cmd);
        return -ENOTSUPP;
}

static inline int fsfilt_get_mblk(struct obd_device *obd,
                                  struct super_block *sb, int *count,
                                  struct inode *inode, int frags)
{
        if (obd->obd_fsops->fs_get_mblk)
                return obd->obd_fsops->fs_get_mblk(sb, count, inode, frags);
        return -ENOTSUPP;
}

static inline int fsfilt_map_inode_pages(struct obd_device *obd,
                                         struct inode *inode,
                                         struct page **page, int pages,
                                         unsigned long *blocks, int *created,
                                         int create, cfs_mutex_t *mutex)
{
        return obd->obd_fsops->fs_map_inode_pages(inode, page, pages, blocks,
                                                  created, create, mutex);
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

static inline __u64 fsfilt_set_version(struct obd_device *obd,
                                      struct inode *inode, __u64 new_version)
{
        if (obd->obd_fsops->fs_set_version)
                return obd->obd_fsops->fs_set_version(inode, new_version);
        return -EOPNOTSUPP;
}

static inline __u64 fsfilt_get_version(struct obd_device *obd,
                                       struct inode *inode)
{
        if (obd->obd_fsops->fs_get_version)
                return obd->obd_fsops->fs_get_version(inode);
        return -EOPNOTSUPP;
}

static inline struct dentry *fsfilt_fid2dentry(struct obd_device *obd,
                                               struct vfsmount *mnt,
                                               struct fsfilt_fid *fid,
                                               int ignore_gen)
{
        if (obd->obd_fsops->fs_fid2dentry)
                return obd->obd_fsops->fs_fid2dentry(mnt, fid, ignore_gen);
        return ERR_PTR(-EOPNOTSUPP);
}

#endif /* __KERNEL__ */

#endif
