/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2004 Cluster File Systems, Inc. <info@clusterfs.com>
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
#include <linux/lustre_log.h>
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
        int     (* fs_commit)(struct super_block *sb, struct inode *inode, 
                              void *handle,int force_sync);
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

        /* this method is needed to make IO operation fsfilt nature depend. */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        int     (* fs_send_bio)(struct inode *inode, struct bio *bio);
#else
        int     (* fs_send_bio)(struct inode *inode, struct kiobuf *bio);
#endif

        /* methods for getting page from backing fs and putting page there
         * during IO. Used on OST. */
        int (* fs_putpage)(struct inode *inode, struct page *page);
        struct page *(* fs_getpage)(struct inode *inode, long int index);

        ssize_t (* fs_readpage)(struct file *file, char *buf, size_t count,
                                loff_t *offset);
        int     (* fs_add_journal_cb)(struct obd_device *obd, struct super_block *sb,
                                      __u64 last_rcvd, void *handle, fsfilt_cb_t cb_func,
                                      void *cb_data);
        int     (* fs_statfs)(struct super_block *sb, struct obd_statfs *osfs);
        int     (* fs_sync)(struct super_block *sb);
        int     (* fs_map_inode_pages)(struct inode *inode, struct page **page,
                                       int pages, unsigned long *blocks,
                                       int *created, int create,
                                       struct semaphore *sem);
        int     (* fs_prep_san_write)(struct inode *inode, long *blocks,
                                      int nblocks, loff_t newsize);
        int     (* fs_write_record)(struct file *, void *, int size, loff_t *,
                                    int force_sync);
        int     (* fs_read_record)(struct file *, void *, int size, loff_t *);
        int     (* fs_setup)(struct obd_device *, struct super_block *);
        
        int     (* fs_post_setup)(struct obd_device *obd, struct vfsmount *mnt);
        int     (* fs_post_cleanup)(struct obd_device *obd, struct vfsmount *mnt);
        int     (* fs_get_reint_log_ctxt)(struct super_block *sb, 
                                          struct llog_ctxt **ctxt);
        int     (* fs_set_kml_flags)(struct inode *inode);
        int     (* fs_clear_kml_flags)(struct inode *inode);
        int     (* fs_set_ost_flags)(struct super_block *sb);
        int     (* fs_set_mds_flags)(struct super_block *sb);
        int     (* fs_precreate_rec)(struct dentry *dentry, int *num, 
                                     struct obdo *oa);
        int     (* fs_set_xattr)(struct inode *inode, void *handle, char *name,
                                 void *buffer, int buffer_size);
        int     (* fs_get_xattr)(struct inode *inode, char *name,
                                 void *buffer, int buffer_size); 
        
        int     (* fs_init_extents_ea)(struct inode *inode); 
        int     (* fs_insert_extents_ea)(struct inode *inode, unsigned long from, 
                                         unsigned long num); 
        int     (* fs_write_extents)(struct dentry *dentry, 
                                     unsigned long offset, unsigned long blks);
        int     (* fs_remove_extents_ea)(struct inode *inode, unsigned long from, 
                                         unsigned long num); 
        int     (* fs_get_ino_write_extents)(struct super_block *sb, ino_t ino, 
                                             char **pbuf, int *size);
        int     (* fs_free_write_extents)(struct super_block *sb, ino_t ino, 
                                          char *pbuf, int size);
        int     (* fs_get_inode_write_extents)(struct inode *inode, char **pbuf, 
                                               int *size);
        int     (* fs_get_write_extents_num)(struct inode *inode, int* size);

        int     (* fs_get_op_len)(int, struct fsfilt_objinfo *, int);
        int     (* fs_add_dir_entry)(struct obd_device *, struct dentry *,
                                     char *, int, unsigned long, unsigned long,
                                     unsigned);
        int     (* fs_del_dir_entry)(struct obd_device *, struct dentry *);
        /*snap operations*/
        int     (* fs_is_redirector)(struct inode *inode);
        int     (* fs_is_indirect)(struct inode *inode);
        
        struct inode * (* fs_create_indirect)(struct inode *pri, int index,
                                              unsigned int gen, struct inode *parent,
                                              int del);
        struct inode * (* fs_get_indirect)(struct inode *pri, int *table,
                                          int slot);
        ino_t   (* fs_get_indirect_ino)(struct inode *pri, int index);
        int     (* fs_destroy_indirect)(struct inode *pri, int index,
                                        struct inode *next_ind);
        int     (* fs_restore_indirect)(struct inode *pri, int index);
        int     (* fs_iterate)(struct super_block *sb,
                              int (*repeat)(struct inode *inode, void *priv),
                              struct inode **start, void *priv, int flag);
        int     (* fs_copy_block)(struct inode *dst, struct inode *src, int blk);
        int     (* fs_set_indirect)(struct inode *pri, int index,
                                    ino_t ind_ino, ino_t parent_ino);
        int     (* fs_snap_feature)(struct super_block *sb, int feature, int op);
        int     (* fs_set_snap_info)(struct super_block *sb, struct inode *inode, 
                                     void* key, __u32 keylen, void *val, 
                                     __u32 *vallen); 
        int     (* fs_get_snap_info)(struct super_block *sb, struct inode *inode,
                                     void* key, __u32 keylen, void *val, 
                                     __u32 *vallen); 
        int     (* fs_set_snap_item)(struct super_block *sb, char *name);
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
#define FSFILT_OP_NOOP          15

/* XXX BUG 3188 -- must return to one set of opcodes */
#define KML_UNLINK              0x11
#define KML_RMDIR               0x12
#define KML_RENAME              0x13
#define KML_CREATE              0x14
#define KML_MKDIR               0x15
#define KML_SYMLINK             0x16
#define KML_MKNOD               0x17
#define KML_LINK                0x19

#define CACHE_UNLINK            0x21
#define CACHE_RMDIR             0x22
#define CACHE_RENAME            0x23
#define CACHE_CREATE            0x24
#define CACHE_MKDIR             0x25
#define CACHE_SYMLINK           0x26
#define CACHE_MKNOD             0x27
#define CACHE_LINK              0x29
#define CACHE_NOOP              0x2f

#define KML_CACHE_UNLINK        0x31
#define KML_CACHE_RMDIR         0x32
#define KML_CACHE_RENAME        0x33
#define KML_CACHE_CREATE        0x34
#define KML_CACHE_MKDIR         0x35
#define KML_CACHE_SYMLINK       0x36
#define KML_CACHE_MKNOD         0x37
#define KML_CACHE_LINK          0x39
#define KML_CACHE_NOOP          0x3f

/*for fsfilt set md ea*/
#define LMV_EA  1
#define LOV_EA  0

static inline void *
fsfilt_start_ops(struct fsfilt_operations *ops, struct inode *inode,
                 int op, struct obd_trans_info *oti, int logs)
{
        unsigned long now = jiffies;
        void *parent_handle = oti ? oti->oti_handle : NULL;
        void *handle = ops->fs_start(inode, op, parent_handle, logs);
        CDEBUG(D_HA, "started handle %p (%p)\n", handle, parent_handle);

        if (oti != NULL) {
                if (parent_handle == NULL) {
                        oti->oti_handle = handle;
                } else if (handle != parent_handle) {
                        CERROR("mismatch: parent %p, handle %p, oti %p\n",
                               parent_handle, handle, oti);
                        LBUG();
                }
        }
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);
        return handle;
}

static inline void *
fsfilt_start_log(struct obd_device *obd, struct inode *inode,
                 int op, struct obd_trans_info *oti, int logs)
{
        return fsfilt_start_ops(obd->obd_fsops, inode, op, oti, logs);
}

static inline void *
fsfilt_start(struct obd_device *obd, struct inode *inode,
             int op, struct obd_trans_info *oti)
{
        return fsfilt_start_ops(obd->obd_fsops, inode, op, oti, 0);
}

static inline void *
llog_fsfilt_start(struct llog_ctxt *ctxt, struct inode *inode,
                  int op, struct obd_trans_info *oti)
{
        return fsfilt_start_ops(ctxt->loc_fsops, inode, op, oti, 1);
}

static inline int
fsfilt_commit_ops(struct fsfilt_operations *ops, struct super_block *sb,
                  struct inode *inode, void *handle, int force_sync)
{
        unsigned long now = jiffies;
        int rc = ops->fs_commit(sb, inode, handle, force_sync);
        CDEBUG(D_HA, "committing handle %p\n", handle);

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);

        return rc;
}

static inline int
fsfilt_commit(struct obd_device *obd, struct super_block *sb, 
              struct inode *inode, void *handle, int force_sync)
{
        return fsfilt_commit_ops(obd->obd_fsops, sb, inode, handle, force_sync);
}

static inline int
llog_fsfilt_commit(struct llog_ctxt *ctxt, struct inode *inode,
                   void *handle, int force_sync)
{
        return fsfilt_commit_ops(ctxt->loc_fsops, inode->i_sb, inode, handle, 
                                 force_sync);
}

static inline void *
fsfilt_brw_start_log(struct obd_device *obd, int objcount,
                     struct fsfilt_objinfo *fso, int niocount,
                     struct niobuf_local *nb, struct obd_trans_info *oti,
                     int logs)
{
        unsigned long now = jiffies;
        void *parent_handle = oti ? oti->oti_handle : NULL;
        void *handle = obd->obd_fsops->fs_brw_start(objcount, fso, niocount, nb,
                                                    parent_handle, logs);
        CDEBUG(D_HA, "started handle %p (%p)\n", handle, parent_handle);

        if (oti != NULL) {
                if (parent_handle == NULL) {
                        oti->oti_handle = handle;
                } else if (handle != parent_handle) {
                        CERROR("mismatch: parent %p, handle %p, oti %p\n",
                               parent_handle, handle, oti);
                        LBUG();
                }
        }
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);

        return handle;
}

static inline void *
fsfilt_brw_start(struct obd_device *obd, int objcount,
                 struct fsfilt_objinfo *fso, int niocount,
                 struct niobuf_local *nb, struct obd_trans_info *oti)
{
        return fsfilt_brw_start_log(obd, objcount, fso, niocount, nb, oti, 0);
}

static inline int
fsfilt_commit_async(struct obd_device *obd, struct inode *inode,
                    void *handle, void **wait_handle)
{
        unsigned long now = jiffies;
        int rc = obd->obd_fsops->fs_commit_async(inode, handle, wait_handle);

        CDEBUG(D_HA, "committing handle %p (async)\n", *wait_handle);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);

        return rc;
}

static inline int
fsfilt_commit_wait(struct obd_device *obd, struct inode *inode, void *handle)
{
        unsigned long now = jiffies;
        int rc = obd->obd_fsops->fs_commit_wait(inode, handle);
        CDEBUG(D_HA, "waiting for completion %p\n", handle);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long journal start time %lus\n", (jiffies - now) / HZ);
        return rc;
}

static inline int
fsfilt_setattr(struct obd_device *obd, struct dentry *dentry,
               void *handle, struct iattr *iattr, int do_trunc)
{
        unsigned long now = jiffies;
        int rc;
        rc = obd->obd_fsops->fs_setattr(dentry, handle, iattr, do_trunc);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long setattr time %lus\n", (jiffies - now) / HZ);
        return rc;
}

static inline int
fsfilt_iocontrol(struct obd_device *obd, struct inode *inode,
                 struct file *file, unsigned int cmd,
                 unsigned long arg)
{
        return obd->obd_fsops->fs_iocontrol(inode, file, cmd, arg);
}

static inline int fsfilt_setup(struct obd_device *obd,
                               struct super_block *fs)
{
        if (obd->obd_fsops->fs_setup)
                return obd->obd_fsops->fs_setup(obd, fs);
        return 0;
}
static inline int
fsfilt_set_md(struct obd_device *obd, struct inode *inode,
              void *handle, void *md, int size)
{
        return obd->obd_fsops->fs_set_md(inode, handle, md, size);
}

static inline int
fsfilt_get_md(struct obd_device *obd, struct inode *inode,
              void *md, int size)
{
        return obd->obd_fsops->fs_get_md(inode, md, size);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static inline int
fsfilt_send_bio(struct obd_device *obd, struct inode *inode,
                struct bio *bio)
#else
static inline int
fsfilt_send_bio(struct obd_device *obd, struct inode *inode,
                struct kiobuf *bio)
#endif
{
        return obd->obd_fsops->fs_send_bio(inode, bio);
}

static inline int
fsfilt_putpage(struct obd_device *obd, struct inode *inode,
               struct page *page)
{
        int rc = 0;
        struct filter_obd *filter;
        unsigned long now = jiffies;

        LASSERT(obd != NULL);
        LASSERT(inode != NULL);
        LASSERT(page != NULL);

        filter = &obd->u.filter;

        if (!obd->obd_fsops->fs_putpage)
                return -ENOSYS;

        CDEBUG(D_INFO, "putpage %lx\n", page->index);

        rc = obd->obd_fsops->fs_putpage(inode, page);

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long putpage time %lus\n", (jiffies - now) / HZ);

        return rc;
}

static inline struct page *
fsfilt_getpage(struct obd_device *obd, struct inode *inode,
               unsigned long index)
{
        struct page *page;
        unsigned long now = jiffies;

        LASSERT(obd != NULL);
        LASSERT(inode != NULL);

        if (!obd->obd_fsops->fs_getpage)
                return ERR_PTR(-ENOSYS);

        CDEBUG(D_INFO, "getpage %lx\n", index);

        page = obd->obd_fsops->fs_getpage(inode, index);

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("long getpage time %lus\n", (jiffies - now) / HZ);

        return page;
}

static inline ssize_t
fsfilt_readpage(struct obd_device *obd, struct file *file, char *buf,
                size_t count, loff_t *offset)
{
        return obd->obd_fsops->fs_readpage(file, buf, count, offset);
}

static inline int
fsfilt_add_journal_cb(struct obd_device *obd, struct super_block *sb,
                      __u64 last_rcvd, void *handle, fsfilt_cb_t cb_func,
                      void *cb_data)
{
        return obd->obd_fsops->fs_add_journal_cb(obd, sb, last_rcvd, handle,
                                                 cb_func, cb_data);
}

/* very similar to obd_statfs(), but caller already holds obd_osfs_lock */
static inline int
fsfilt_statfs(struct obd_device *obd, struct super_block *sb,
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

static inline int
fsfilt_sync(struct obd_device *obd, struct super_block *sb)
{
        return obd->obd_fsops->fs_sync(sb);
}

static inline int fsfilt_map_inode_pages(struct obd_device *obd,
                                         struct inode *inode,
                                         struct page **page, int pages,
                                         unsigned long *blocks, int *created,
                                         int create, struct semaphore *sem)
{
        return obd->obd_fsops->fs_map_inode_pages(inode, page, pages, blocks,
                                                  created, create, sem);
}

static inline int 
fsfilt_write_extents(struct obd_device *obd, struct dentry *dentry, 
                     unsigned long offset, unsigned long blks)
{
        if (obd->obd_fsops->fs_write_extents)
                return obd->obd_fsops->fs_write_extents(dentry, 
                                                        offset, blks);
        return 0;
}

static inline int
fs_prep_san_write(struct obd_device *obd, struct inode *inode,
                  long *blocks, int nblocks, loff_t newsize)
{
        return obd->obd_fsops->fs_prep_san_write(inode, blocks,
                                                 nblocks, newsize);
}

static inline int
fsfilt_read_record(struct obd_device *obd, struct file *file,
                   void *buf, loff_t size, loff_t *offs)
{
        return obd->obd_fsops->fs_read_record(file, buf, size, offs);
}

static inline int 
llog_fsfilt_read_record(struct llog_ctxt *ctxt, struct file *file, 
                        void *buf, loff_t size, loff_t *offs)
{
        return ctxt->loc_fsops->fs_read_record(file, buf, size, offs);
}

static inline int
fsfilt_write_record(struct obd_device *obd, struct file *file,
                    void *buf, loff_t size, loff_t *offs, int force_sync)
{
        return obd->obd_fsops->fs_write_record(file, buf, size, offs,
                                               force_sync);
}

static inline int
llog_fsfilt_write_record(struct llog_ctxt *ctxt, struct file *file,
                         void *buf, loff_t size, loff_t *offs,
                         int force_sync)
{
        return ctxt->loc_fsops->fs_write_record(file, buf, size, offs,
                                                force_sync);
}

static inline int 
fsfilt_set_kml_flags(struct obd_device *obd, struct inode *inode)
{
        if (obd->obd_fsops->fs_set_kml_flags)
                return obd->obd_fsops->fs_set_kml_flags(inode);
        return 0;
}

static inline int 
fsfilt_clear_kml_flags(struct obd_device *obd, struct inode *inode)
{
        if (obd->obd_fsops->fs_clear_kml_flags)
                return obd->obd_fsops->fs_clear_kml_flags(inode);
        return 0;
}
static inline int 
fsfilt_precreate_rec(struct obd_device *obd, struct dentry *dentry,
                     int *num, struct obdo *oa)
{
        if (obd->obd_fsops->fs_precreate_rec)
                return obd->obd_fsops->fs_precreate_rec(dentry, num, oa);
        return 0;
}

static inline int 
fsfilt_post_setup(struct obd_device *obd)
{
        if (obd->obd_fsops->fs_post_setup)
                return obd->obd_fsops->fs_post_setup(obd, 
                                obd->obd_lvfs_ctxt.pwdmnt);
        return 0;
}

static inline int 
fsfilt_post_cleanup(struct obd_device *obd)
{
        if (obd->obd_fsops->fs_post_cleanup)
                return obd->obd_fsops->fs_post_cleanup(obd, 
                                obd->obd_lvfs_ctxt.pwdmnt);
        return 0;
}

static inline int 
fsfilt_get_ino_write_extents(struct obd_device *obd, 
                             struct super_block *sb, 
                             int ino, char **buf, int *size)
{
        if (obd->obd_fsops->fs_get_ino_write_extents)
                return obd->obd_fsops->fs_get_ino_write_extents(sb, ino, 
                                                                buf, size);
        return 0;
}

static inline int 
fsfilt_free_write_extents(struct obd_device *obd, 
                          struct super_block *sb, 
                          int ino, char *buf, int size)
{
        if (obd->obd_fsops->fs_free_write_extents)
                return obd->obd_fsops->fs_free_write_extents(sb, ino, 
                                                             buf, size);
        return 0;
}

static inline int 
fsfilt_get_reint_log_ctxt(struct obd_device *obd,
                          struct super_block *sb, 
                          struct llog_ctxt **ctxt)
{
        if (obd->obd_fsops->fs_get_reint_log_ctxt)
                return obd->obd_fsops->fs_get_reint_log_ctxt(sb, ctxt);
        return 0;
}

static inline int 
fsfilt_set_ost_flags(struct obd_device *obd, struct super_block *sb) 
{
        if (obd->obd_fsops->fs_set_ost_flags)
                return obd->obd_fsops->fs_set_ost_flags(sb);
        return 0;
}

static inline int 
fsfilt_set_mds_flags(struct obd_device *obd, struct super_block *sb) 
{
        if (obd->obd_fsops->fs_set_mds_flags)
                return obd->obd_fsops->fs_set_mds_flags(sb);
        return 0;
}

static inline int 
fsfilt_add_dir_entry(struct obd_device *obd, struct dentry *dir,
                     char *name, int namelen, unsigned long ino,
                     unsigned long generation, unsigned mds)
{
        LASSERT(obd->obd_fsops->fs_add_dir_entry);
        return obd->obd_fsops->fs_add_dir_entry(obd, dir, name,
                                                namelen, ino, generation, mds);
}

static inline int 
fsfilt_del_dir_entry(struct obd_device *obd, struct dentry *dentry)
{
        LASSERT(obd->obd_fsops->fs_del_dir_entry);
        return obd->obd_fsops->fs_del_dir_entry(obd, dentry);
}

static inline int 
fsfilt_set_snap_item(struct obd_device *obd, struct super_block *sb,
                     char *name)
{
         if (obd->obd_fsops->fs_set_snap_item)
                return obd->obd_fsops->fs_set_snap_item(sb, name);
        return 0;
} 
#endif /* __KERNEL__ */

#endif
