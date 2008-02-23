/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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
 */

#ifndef _LINUX_COMPAT25_H
#define _LINUX_COMPAT25_H

#ifdef __KERNEL__

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5)
#error Sorry, Lustre requires at Linux kernel version 2.6.5 or later
#endif

#include <libcfs/linux/portals_compat25.h>

#include <linux/lustre_patchless_compat.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
struct ll_iattr {
        struct iattr    iattr;
        unsigned int    ia_attr_flags;
};
#else
#define ll_iattr iattr
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14) */

#ifndef HAVE_SET_FS_PWD
static inline void ll_set_fs_pwd(struct fs_struct *fs, struct vfsmount *mnt,
                struct dentry *dentry)
{
        struct dentry *old_pwd;
        struct vfsmount *old_pwdmnt;

        write_lock(&fs->lock);
        old_pwd = fs->pwd;
        old_pwdmnt = fs->pwdmnt;
        fs->pwdmnt = mntget(mnt);
        fs->pwd = dget(dentry);
        write_unlock(&fs->lock);

        if (old_pwd) {
                dput(old_pwd);
                mntput(old_pwdmnt);
        }
}
#else
#define ll_set_fs_pwd set_fs_pwd
#endif /* HAVE_SET_FS_PWD */

/*
 * set ATTR_BLOCKS to a high value to avoid any risk of collision with other
 * ATTR_* attributes (see bug 13828)
 */
#define ATTR_BLOCKS    (1 << 27)

#if HAVE_INODE_I_MUTEX
#define UNLOCK_INODE_MUTEX(inode) do {mutex_unlock(&(inode)->i_mutex); } while(0)
#define LOCK_INODE_MUTEX(inode) do {mutex_lock(&(inode)->i_mutex); } while(0)
#define TRYLOCK_INODE_MUTEX(inode) mutex_trylock(&(inode)->i_mutex)
#else
#define UNLOCK_INODE_MUTEX(inode) do {up(&(inode)->i_sem); } while(0)
#define LOCK_INODE_MUTEX(inode) do {down(&(inode)->i_sem); } while(0)
#define TRYLOCK_INODE_MUTEX(inode) (!down_trylock(&(inode)->i_sem))
#endif /* HAVE_INODE_I_MUTEX */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#define d_child d_u.d_child
#define d_rcu d_u.d_rcu
#endif

#ifdef HAVE_DQUOTOFF_MUTEX
#define UNLOCK_DQONOFF_MUTEX(dqopt) do {mutex_unlock(&(dqopt)->dqonoff_mutex); } while(0)
#define LOCK_DQONOFF_MUTEX(dqopt) do {mutex_lock(&(dqopt)->dqonoff_mutex); } while(0)
#else
#define UNLOCK_DQONOFF_MUTEX(dqopt) do {up(&(dqopt)->dqonoff_sem); } while(0)
#define LOCK_DQONOFF_MUTEX(dqopt) do {down(&(dqopt)->dqonoff_sem); } while(0)
#endif /* HAVE_DQUOTOFF_MUTEX */

#define current_ngroups current->group_info->ngroups
#define current_groups current->group_info->small_block

#ifndef page_private
#define page_private(page) ((page)->private)
#define set_page_private(page, v) ((page)->private = (v))
#endif

#ifndef HAVE_GFP_T
#define gfp_t int
#endif

#define lock_dentry(___dentry)          spin_lock(&(___dentry)->d_lock)
#define unlock_dentry(___dentry)        spin_unlock(&(___dentry)->d_lock)

#define ll_kernel_locked()      kernel_locked()

/*
 * OBD need working random driver, thus all our
 * initialization routines must be called after device
 * driver initialization
 */
#ifndef MODULE
#undef module_init
#define module_init(a)     late_initcall(a)
#endif

/* XXX our code should be using the 2.6 calls, not the other way around */
#define TryLockPage(page)               TestSetPageLocked(page)
#define Page_Uptodate(page)             PageUptodate(page)
#define ll_redirty_page(page)           set_page_dirty(page)

#define KDEVT_INIT(val)                 (val)

#define LTIME_S(time)                   (time.tv_sec)
#define ll_path_lookup                  path_lookup
#define ll_permission(inode,mask,nd)    permission(inode,mask,nd)

#define ll_pgcache_lock(mapping)          spin_lock(&mapping->page_lock)
#define ll_pgcache_unlock(mapping)        spin_unlock(&mapping->page_lock)
#define ll_call_writepage(inode, page)  \
                                (inode)->i_mapping->a_ops->writepage(page, NULL)
#define ll_invalidate_inode_pages(inode) \
                                invalidate_inode_pages((inode)->i_mapping)
#define ll_truncate_complete_page(page) \
                                truncate_complete_page(page->mapping, page)

#define ll_vfs_create(a,b,c,d)          vfs_create(a,b,c,d)
#define ll_dev_t                        dev_t
#define kdev_t                          dev_t
#define to_kdev_t(dev)                  (dev)
#define kdev_t_to_nr(dev)               (dev)
#define val_to_kdev(dev)                (dev)
#define ILOOKUP(sb, ino, test, data)    ilookup5(sb, ino, test, data);

#include <linux/writeback.h>

static inline int cleanup_group_info(void)
{
        struct group_info *ginfo;

        ginfo = groups_alloc(0);
        if (!ginfo)
                return -ENOMEM;

        set_current_groups(ginfo);
        put_group_info(ginfo);

        return 0;
}

#define __set_page_ll_data(page, llap) \
        do {       \
                page_cache_get(page); \
                SetPagePrivate(page); \
                set_page_private(page, (unsigned long)llap); \
        } while (0)
#define __clear_page_ll_data(page) \
        do {       \
                ClearPagePrivate(page); \
                set_page_private(page, 0); \
                page_cache_release(page); \
        } while(0)

#define kiobuf bio

#include <linux/proc_fs.h>

#if !defined(HAVE_D_REHASH_COND) && defined(HAVE___D_REHASH)
#define d_rehash_cond(dentry, lock) __d_rehash(dentry, lock)
extern void __d_rehash(struct dentry *dentry, int lock);
#endif

#if !defined(HAVE_D_MOVE_LOCKED) && defined(HAVE___D_MOVE)
#define d_move_locked(dentry, target) __d_move(dentry, target)
extern void __d_move(struct dentry *dentry, struct dentry *target);
#endif

#ifdef HAVE_CAN_SLEEP_ARG
#define ll_flock_lock_file_wait(file, lock, can_sleep) \
        flock_lock_file_wait(file, lock, can_sleep)
#else
#define ll_flock_lock_file_wait(file, lock, can_sleep) \
        flock_lock_file_wait(file, lock)
#endif

#define CheckWriteback(page, cmd) \
        (!(!PageWriteback(page) && cmd == OBD_BRW_WRITE))

#ifdef HAVE_PAGE_LIST
static inline int mapping_has_pages(struct address_space *mapping)
{
        int rc = 1;

        ll_pgcache_lock(mapping);
        if (list_empty(&mapping->dirty_pages) &&
            list_empty(&mapping->clean_pages) &&
            list_empty(&mapping->locked_pages)) {
                rc = 0;
        }
        ll_pgcache_unlock(mapping);

        return rc;
}
#else
static inline int mapping_has_pages(struct address_space *mapping)
{
        return mapping->nrpages > 0;
}
#endif

#ifdef HAVE_KIOBUF_KIO_BLOCKS
#define KIOBUF_GET_BLOCKS(k) ((k)->kio_blocks)
#else
#define KIOBUF_GET_BLOCKS(k) ((k)->blocks)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7))
#define ll_set_dflags(dentry, flags) do { dentry->d_vfs_flags |= flags; } while(0)
#define ll_vfs_symlink(dir, dentry, path, mode) vfs_symlink(dir, dentry, path)
#else
#define ll_set_dflags(dentry, flags) do { \
                spin_lock(&dentry->d_lock); \
                dentry->d_flags |= flags; \
                spin_unlock(&dentry->d_lock); \
        } while(0)
#define ll_vfs_symlink(dir, dentry, path, mode) vfs_symlink(dir, dentry, path, mode)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifdef HAVE_I_ALLOC_SEM
#define UP_WRITE_I_ALLOC_SEM(i)   do { up_write(&(i)->i_alloc_sem); } while (0)
#define DOWN_WRITE_I_ALLOC_SEM(i) do { down_write(&(i)->i_alloc_sem); } while(0)
#define LASSERT_I_ALLOC_SEM_WRITE_LOCKED(i) LASSERT(down_read_trylock(&(i)->i_alloc_sem) == 0)

#define UP_READ_I_ALLOC_SEM(i)    do { up_read(&(i)->i_alloc_sem); } while (0)
#define DOWN_READ_I_ALLOC_SEM(i)  do { down_read(&(i)->i_alloc_sem); } while (0)
#define LASSERT_I_ALLOC_SEM_READ_LOCKED(i) LASSERT(down_write_trylock(&(i)->i_alloc_sem) == 0)
#else
#define UP_READ_I_ALLOC_SEM(i)              do { } while (0)
#define DOWN_READ_I_ALLOC_SEM(i)            do { } while (0)
#define LASSERT_I_ALLOC_SEM_READ_LOCKED(i)  do { } while (0)

#define UP_WRITE_I_ALLOC_SEM(i)             do { } while (0)
#define DOWN_WRITE_I_ALLOC_SEM(i)           do { } while (0)
#define LASSERT_I_ALLOC_SEM_WRITE_LOCKED(i) do { } while (0)
#endif

#ifndef HAVE_GRAB_CACHE_PAGE_NOWAIT_GFP
#define grab_cache_page_nowait_gfp(x, y, z) grab_cache_page_nowait((x), (y))
#endif

#ifndef HAVE_FILEMAP_FDATAWRITE
#define filemap_fdatawrite(mapping)      filemap_fdatasync(mapping)
#endif

#ifdef HAVE_VFS_KERN_MOUNT
static inline 
struct vfsmount *
ll_kern_mount(const char *fstype, int flags, const char *name, void *data)
{
        struct file_system_type *type = get_fs_type(fstype);
        struct vfsmount *mnt;
        if (!type)
                return ERR_PTR(-ENODEV);
        mnt = vfs_kern_mount(type, flags, name, data);
        module_put(type->owner);
        return mnt;
}
#else
#define ll_kern_mount(fstype, flags, name, data) do_kern_mount((fstype), (flags), (name), (data))
#endif

#ifndef HAVE_GENERIC_FILE_READ
static inline
ssize_t
generic_file_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
        struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
        struct kiocb kiocb;
        ssize_t ret;

        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = *ppos;
        kiocb.ki_left = len;

        ret = generic_file_aio_read(&kiocb, &iov, 1, kiocb.ki_pos);
        *ppos = kiocb.ki_pos;
        return ret;
}
#endif

#ifndef HAVE_GENERIC_FILE_WRITE
static inline
ssize_t
generic_file_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
        struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
        struct kiocb kiocb;
        ssize_t ret;

        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = *ppos;
        kiocb.ki_left = len;

        ret = generic_file_aio_write(&kiocb, &iov, 1, kiocb.ki_pos);
        *ppos = kiocb.ki_pos;

        return ret;
}
#endif

#ifdef HAVE_STATFS_DENTRY_PARAM
#define ll_do_statfs(sb, sfs) (sb)->s_op->statfs((sb)->s_root, (sfs))
#else
#define ll_do_statfs(sb, sfs) (sb)->s_op->statfs((sb), (sfs))
#endif

/* task_struct */
#ifndef HAVE_TASK_PPTR
#define p_pptr parent
#endif

#ifndef HAVE_SB_TIME_GRAN
#ifndef HAVE_S_TIME_GRAN
#error Need s_time_gran patch!
#endif
static inline u32 get_sb_time_gran(struct super_block *sb)
{
        return sb->s_time_gran;
}
#endif

#ifdef HAVE_RW_TREE_LOCK
#define TREE_READ_LOCK_IRQ(mapping)	read_lock_irq(&(mapping)->tree_lock)
#define TREE_READ_UNLOCK_IRQ(mapping) read_unlock_irq(&(mapping)->tree_lock)
#else
#define TREE_READ_LOCK_IRQ(mapping) spin_lock_irq(&(mapping)->tree_lock)
#define TREE_READ_UNLOCK_IRQ(mapping) spin_unlock_irq(&(mapping)->tree_lock)
#endif

#ifdef HAVE_UNREGISTER_BLKDEV_RETURN_INT
#define ll_unregister_blkdev(a,b)       unregister_blkdev((a),(b))
#else
static inline 
int ll_unregister_blkdev(unsigned int dev, const char *name)
{
        unregister_blkdev(dev, name);
        return 0;
}
#endif

#ifdef HAVE_INVALIDATE_BDEV_2ARG
#define ll_invalidate_bdev(a,b)         invalidate_bdev((a),(b))
#else
#define ll_invalidate_bdev(a,b)         invalidate_bdev((a))
#endif

#ifdef HAVE_INODE_BLKSIZE
#define ll_inode_blksize(a)     (a)->i_blksize
#else
#define ll_inode_blksize(a)     (1<<(a)->i_blkbits)
#endif


#ifdef FS_ODD_RENAME
#define FS_RENAME_DOES_D_MOVE FS_ODD_RENAME
#endif

#endif /* __KERNEL__ */
#endif /* _COMPAT25_H */
