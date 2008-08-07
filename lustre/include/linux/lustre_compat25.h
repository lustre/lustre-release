/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _LINUX_COMPAT25_H
#define _LINUX_COMPAT25_H

#ifdef __KERNEL__

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) && LINUX_VERSION_CODE < KERNEL_VERSION(2,5,69)
#error sorry, lustre requires at least 2.5.69
#endif

#include <libcfs/linux/portals_compat25.h>

#include <linux/lustre_patchless_compat.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
struct ll_iattr_struct {
        struct iattr    iattr;
        unsigned int    ia_attr_flags;
};
#else
#define ll_iattr_struct iattr
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

#ifdef HAVE_INODE_I_MUTEX
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


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4)
#define NGROUPS_SMALL           NGROUPS
#define NGROUPS_PER_BLOCK       ((int)(EXEC_PAGESIZE / sizeof(gid_t)))

struct group_info {
        int        ngroups;
        atomic_t   usage;
        gid_t      small_block[NGROUPS_SMALL];
        int        nblocks;
        gid_t     *blocks[0];
};
#define current_ngroups current->ngroups
#define current_groups current->groups

struct group_info *groups_alloc(int gidsetsize);
void groups_free(struct group_info *ginfo);
#else /* >= 2.6.4 */

#define current_ngroups current->group_info->ngroups
#define current_groups current->group_info->small_block

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4) */

#ifndef page_private
#define page_private(page) ((page)->private)
#define set_page_private(page, v) ((page)->private = (v))
#endif

#ifndef HAVE_GFP_T
#define gfp_t int
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)

#define lock_dentry(___dentry)          spin_lock(&(___dentry)->d_lock)
#define unlock_dentry(___dentry)        spin_unlock(&(___dentry)->d_lock)

#define lock_24kernel()         do {} while (0)
#define unlock_24kernel()       do {} while (0)
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
        ((!PageWriteback(page) && (cmd & OBD_BRW_READ)) || \
         (PageWriteback(page) && (cmd & OBD_BRW_WRITE)))

#else /* 2.4.. */

#define ll_flock_lock_file_wait(file, lock, can_sleep) \
        do {} while(0)

#define lock_dentry(___dentry)
#define unlock_dentry(___dentry)

#define lock_24kernel()         lock_kernel()
#define unlock_24kernel()       unlock_kernel()
#define ll_kernel_locked()      (current->lock_depth >= 0)

/* 2.4 kernels have HZ=100 on i386/x86_64, this should be reasonably safe */
#define get_jiffies_64()        (__u64)jiffies

#ifdef HAVE_MM_INLINE
#include <linux/mm_inline.h>
#endif

#ifndef pgoff_t
#define pgoff_t unsigned long
#endif

#define ll_vfs_create(a,b,c,d)              vfs_create(a,b,c)
#define ll_permission(inode,mask,nd)        permission(inode,mask)
#define ILOOKUP(sb, ino, test, data)        ilookup4(sb, ino, test, data);
#define DCACHE_DISCONNECTED                 DCACHE_NFSD_DISCONNECTED
#define ll_dev_t                            int
#define old_encode_dev(dev)                 (dev)

/* 2.5 uses hlists for some things, like the d_hash.  we'll treat them
 * as 2.5 and let macros drop back.. */
#ifndef HLIST_HEAD /* until we get a kernel newer than l28 */
#define hlist_entry                     list_entry
#define hlist_head                      list_head
#define hlist_node                      list_head
#define HLIST_HEAD                      LIST_HEAD
#define INIT_HLIST_HEAD                 INIT_LIST_HEAD
#define hlist_del_init                  list_del_init
#define hlist_add_head                  list_add
#endif

#ifndef INIT_HLIST_NODE
#define INIT_HLIST_NODE(p)              ((p)->next = NULL, (p)->prev = NULL)
#endif

#ifndef hlist_for_each
#define hlist_for_each                  list_for_each
#endif

#ifndef hlist_for_each_safe
#define hlist_for_each_safe             list_for_each_safe
#endif

#define KDEVT_INIT(val)                 (val)
#define ext3_xattr_set_handle           ext3_xattr_set
#define try_module_get                  __MOD_INC_USE_COUNT
#define module_put                      __MOD_DEC_USE_COUNT
#define LTIME_S(time)                   (time)

#if !defined(CONFIG_RH_2_4_20) && !defined(cpu_online)
#define cpu_online(cpu)                 test_bit(cpu, &(cpu_online_map))
#endif

static inline int ll_path_lookup(const char *path, unsigned flags,
                                 struct nameidata *nd)
{
        int error = 0;
        if (path_init(path, flags, nd))
                error = path_walk(path, nd);
        return error;
}
#define ll_permission(inode,mask,nd)    permission(inode,mask)
typedef long sector_t;

#define ll_pgcache_lock(mapping)        spin_lock(&pagecache_lock)
#define ll_pgcache_unlock(mapping)      spin_unlock(&pagecache_lock)
#define ll_call_writepage(inode, page)  \
                               (inode)->i_mapping->a_ops->writepage(page)
#define ll_invalidate_inode_pages(inode) invalidate_inode_pages(inode)
#define ll_truncate_complete_page(page) truncate_complete_page(page)

static inline void clear_page_dirty(struct page *page)
{
        if (PageDirty(page))
                ClearPageDirty(page);
}

static inline int clear_page_dirty_for_io(struct page *page)
{
        struct address_space *mapping = page->mapping;

        if (page->mapping && PageDirty(page)) {
                ClearPageDirty(page);
                ll_pgcache_lock(mapping);
                list_del(&page->list);
                list_add(&page->list, &mapping->locked_pages);
                ll_pgcache_unlock(mapping);
                return 1;
        }
        return 0;
}

static inline void ll_redirty_page(struct page *page)
{
        SetPageDirty(page);
        ClearPageLaunder(page);
}

static inline void __d_drop(struct dentry *dentry)
{
        list_del_init(&dentry->d_hash);
}

static inline int cleanup_group_info(void)
{
        /* Get rid of unneeded supplementary groups */
        current->ngroups = 0;
        memset(current->groups, 0, sizeof(current->groups));
        return 0;
}

#ifndef HAVE_COND_RESCHED
static inline void cond_resched(void)
{
        if (unlikely(need_resched())) {
                set_current_state(TASK_RUNNING);
                schedule();
        }
}
#endif

/* to find proc_dir_entry from inode. 2.6 has native one -bzzz */
#ifndef HAVE_PDE
#define PDE(ii)         ((ii)->u.generic_ip)
#endif

#define __set_page_ll_data(page, llap) set_page_private(page, (unsigned long)llap)
#define __clear_page_ll_data(page) set_page_private(page, 0)
#define PageWriteback(page) 0
#define CheckWriteback(page, cmd) 1
#define set_page_writeback(page) do {} while (0)
#define end_page_writeback(page) do {} while (0)

static inline int mapping_mapped(struct address_space *mapping)
{
        if (mapping->i_mmap_shared)
                return 1;
        if (mapping->i_mmap)
                return 1;
        return 0;
}

#ifdef ZAP_PAGE_RANGE_VMA
#define ll_zap_page_range(vma, addr, len)  zap_page_range(vma, addr, len)
#else
#define ll_zap_page_range(vma, addr, len)  zap_page_range(vma->vm_mm, addr, len)
#endif

#ifndef HAVE_PAGE_MAPPED
/* Poor man's page_mapped. substract from page count, counts from
   buffers/pagecache and our own count (we are supposed to hold one reference).
   What is left are user mappings and also others who work with this page now,
   but there are supposedly none. */
static inline int page_mapped(struct page *page)
{
        return page_count(page) - !!page->mapping - !!page->buffers - 1;
}
#endif /* !HAVE_PAGE_MAPPED */

static inline void touch_atime(struct vfsmount *mnt, struct dentry *dentry)
{
        update_atime(dentry->d_inode);
}

static inline void file_accessed(struct file *file)
{
#ifdef O_NOATIME
        if (file->f_flags & O_NOATIME)
                return;
#endif
        touch_atime(file->f_vfsmnt, file->f_dentry);
}

#ifndef typecheck
/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})
#endif

#endif /* end of 2.4 compat macros */

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
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                       vfs_symlink(dir, dentry, path)
#else
#define ll_set_dflags(dentry, flags) do { \
                spin_lock(&dentry->d_lock); \
                dentry->d_flags |= flags; \
                spin_unlock(&dentry->d_lock); \
        } while(0)
#ifdef HAVE_SECURITY_PLUG
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                vfs_symlink(dir, dentry, mnt, path, mode)
#else
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                vfs_symlink(dir, dentry, path, mode)
#endif
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

#ifdef HAVE_STATFS_DENTRY_PARAM
#define ll_do_statfs(sb, sfs) (sb)->s_op->statfs((sb)->s_root, (sfs))
#else
#define ll_do_statfs(sb, sfs) (sb)->s_op->statfs((sb), (sfs))
#endif

/* task_struct */
#ifndef HAVE_TASK_PPTR
#define p_pptr parent
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

#ifdef HAVE_FS_RENAME_DOES_D_MOVE
#define LL_RENAME_DOES_D_MOVE	FS_RENAME_DOES_D_MOVE
#else
#define LL_RENAME_DOES_D_MOVE	FS_ODD_RENAME
#endif

#ifdef HAVE_SECURITY_PLUG
#define ll_remove_suid(inode,mnt)               remove_suid(inode,mnt)
#define ll_vfs_rmdir(dir,entry,mnt)             vfs_rmdir(dir,entry,mnt)
#define ll_vfs_mkdir(inode,dir,mnt,mode)        vfs_mkdir(inode,dir,mnt,mode)
#define ll_vfs_link(old,mnt,dir,new,mnt1)       vfs_link(old,mnt,dir,new,mnt1)
#define ll_vfs_unlink(inode,entry,mnt)          vfs_unlink(inode,entry,mnt)
#define ll_vfs_mknod(dir,entry,mnt,mode,dev)            \
                vfs_mknod(dir,entry,mnt,mode,dev)
#define ll_security_inode_unlink(dir,entry,mnt)         \
                security_inode_unlink(dir,entry,mnt)     
#define ll_vfs_rename(old,old_dir,mnt,new,new_dir,mnt1) \
                vfs_rename(old,old_dir,mnt,new,new_dir,mnt1)
#else
#define ll_remove_suid(inode,mnt)               remove_suid(inode)
#define ll_vfs_rmdir(dir,entry,mnt)             vfs_rmdir(dir,entry)
#define ll_vfs_mkdir(inode,dir,mnt,mode)        vfs_mkdir(inode,dir,mode)
#define ll_vfs_link(old,mnt,dir,new,mnt1)       vfs_link(old,dir,new)
#define ll_vfs_unlink(inode,entry,mnt)          vfs_unlink(inode,entry)
#define ll_vfs_mknod(dir,entry,mnt,mode,dev)    vfs_mknod(dir,entry,mode,dev)
#define ll_security_inode_unlink(dir,entry,mnt) security_inode_unlink(dir,entry)     
#define ll_vfs_rename(old,old_dir,mnt,new,new_dir,mnt1) \
                vfs_rename(old,old_dir,new,new_dir)
#endif

#endif /* __KERNEL__ */
#endif /* _COMPAT25_H */
