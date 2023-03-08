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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_COMPAT_H
#define _LUSTRE_COMPAT_H

#include <linux/aio.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/posix_acl_xattr.h>
#include <linux/bio.h>
#include <linux/xattr.h>
#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <libcfs/linux/linux-fs.h>
#include <obd_support.h>

#ifdef HAVE_4ARGS_VFS_SYMLINK
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                vfs_symlink(dir, dentry, path, mode)
#else
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                       vfs_symlink(dir, dentry, path)
#endif

#ifdef HAVE_BVEC_ITER
#define bio_idx(bio)			(bio->bi_iter.bi_idx)
#define bio_set_sector(bio, sector)	(bio->bi_iter.bi_sector = sector)
#define bvl_to_page(bvl)		(bvl->bv_page)
#else
#define bio_idx(bio)			(bio->bi_idx)
#define bio_set_sector(bio, sector)	(bio->bi_sector = sector)
#define bio_sectors(bio)		((bio)->bi_size >> 9)
#define bvl_to_page(bvl)		(bvl->bv_page)
#endif

#ifdef HAVE_BVEC_ITER
#define bio_start_sector(bio) (bio->bi_iter.bi_sector)
#else
#define bio_start_sector(bio) (bio->bi_sector)
#endif

#ifndef HAVE_DENTRY_D_CHILD
#define d_child			d_u.d_child
#endif

#ifdef HAVE_DENTRY_D_U_D_ALIAS
#define d_alias			d_u.d_alias
#endif

#ifndef HAVE_D_IN_LOOKUP
static inline int d_in_lookup(struct dentry *dentry)
{
	return false;
}
#endif

#ifndef HAVE_VM_FAULT_T
#define vm_fault_t int
#endif

#ifndef HAVE_FOP_ITERATE_SHARED
#define iterate_shared iterate
#endif

#ifdef HAVE_OLDSIZE_TRUNCATE_PAGECACHE
#define ll_truncate_pagecache(inode, size) truncate_pagecache(inode, 0, size)
#else
#define ll_truncate_pagecache(inode, size) truncate_pagecache(inode, size)
#endif

#ifdef HAVE_VFS_RENAME_5ARGS
#define ll_vfs_rename(a, b, c, d) vfs_rename(a, b, c, d, NULL)
#elif defined HAVE_VFS_RENAME_6ARGS
#define ll_vfs_rename(a, b, c, d) vfs_rename(a, b, c, d, NULL, 0)
#else
#define ll_vfs_rename(a, b, c, d) vfs_rename(a, b, c, d)
#endif

#ifdef HAVE_USER_NAMESPACE_ARG
#define vfs_unlink(ns, dir, de) vfs_unlink(ns, dir, de, NULL)
#elif defined HAVE_VFS_UNLINK_3ARGS
#define vfs_unlink(ns, dir, de) vfs_unlink(dir, de, NULL)
#else
#define vfs_unlink(ns, dir, de) vfs_unlink(dir, de)
#endif

static inline int ll_vfs_getattr(struct path *path, struct kstat *st,
				 u32 request_mask, unsigned int flags)
{
	int rc;

#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_INODEOPS_ENHANCED_GETATTR)
	rc = vfs_getattr(path, st, request_mask, flags);
#else
	rc = vfs_getattr(path, st);
#endif
	return rc;
}

#ifndef HAVE_D_IS_POSITIVE
static inline bool d_is_positive(const struct dentry *dentry)
{
	return dentry->d_inode != NULL;
}
#endif

#ifndef HAVE_INODE_LOCK
# define inode_lock(inode) mutex_lock(&(inode)->i_mutex)
# define inode_unlock(inode) mutex_unlock(&(inode)->i_mutex)
# define inode_trylock(inode) mutex_trylock(&(inode)->i_mutex)
#endif

/* Old kernels lacked both Xarray support and the page cache
 * using Xarrays. Our back ported Xarray support introduces
 * the real xa_is_value() but we need a wrapper as well for
 * the page cache interaction. Lets keep xa_is_value() separate
 * in old kernels for Xarray support and page cache handling.
 */
#ifndef HAVE_XARRAY_SUPPORT
static inline bool ll_xa_is_value(void *entry)
{
	return radix_tree_exceptional_entry(entry);
}
#else
#define ll_xa_is_value	xa_is_value
#endif

#ifndef HAVE_TRUNCATE_INODE_PAGES_FINAL
static inline void truncate_inode_pages_final(struct address_space *map)
{
	truncate_inode_pages(map, 0);
}
#endif

#ifndef HAVE_PTR_ERR_OR_ZERO
static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}
#endif

#ifdef HAVE_PID_NS_FOR_CHILDREN
# define ll_task_pid_ns(task) \
	 ((task)->nsproxy ? ((task)->nsproxy->pid_ns_for_children) : NULL)
#else
# define ll_task_pid_ns(task) \
	 ((task)->nsproxy ? ((task)->nsproxy->pid_ns) : NULL)
#endif

#ifdef HAVE_FULL_NAME_HASH_3ARGS
# define ll_full_name_hash(salt, name, len) full_name_hash(salt, name, len)
#else
# define ll_full_name_hash(salt, name, len) full_name_hash(name, len)
#endif

#ifdef HAVE_STRUCT_POSIX_ACL_XATTR
# define posix_acl_xattr_header struct posix_acl_xattr_header
# define posix_acl_xattr_entry  struct posix_acl_xattr_entry
# define GET_POSIX_ACL_XATTR_ENTRY(head) ((void *)((head) + 1))
#else
# define GET_POSIX_ACL_XATTR_ENTRY(head) ((head)->a_entries)
#endif

#ifdef HAVE_IOP_XATTR
#define ll_setxattr     generic_setxattr
#define ll_getxattr     generic_getxattr
#define ll_removexattr  generic_removexattr
#endif /* HAVE_IOP_XATTR */

#ifndef HAVE_POSIX_ACL_VALID_USER_NS
#define posix_acl_valid(a,b)		posix_acl_valid(b)
#endif

#ifdef HAVE_IOP_SET_ACL
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
#if !defined(HAVE_USER_NAMESPACE_ARG) && !defined(HAVE_POSIX_ACL_UPDATE_MODE)
static inline int posix_acl_update_mode(struct inode *inode, umode_t *mode_p,
			  struct posix_acl **acl)
{
	umode_t mode = inode->i_mode;
	int error;

	error = posix_acl_equiv_mode(*acl, &mode);
	if (error < 0)
		return error;
	if (error == 0)
		*acl = NULL;
	if (!in_group_p(inode->i_gid) &&
	    !capable_wrt_inode_uidgid(inode, CAP_FSETID))
		mode &= ~S_ISGID;
	*mode_p = mode;
	return 0;
}
#endif /* HAVE_POSIX_ACL_UPDATE_MODE */
#endif
#endif

#ifndef HAVE_IOV_ITER_TRUNCATE
static inline void iov_iter_truncate(struct iov_iter *i, u64 count)
{
	if (i->count > count)
		i->count = count;
}
#endif

/*
 * mount MS_* flags split from superblock SB_* flags
 * if the SB_* flags are not available use the MS_* flags
 */
#if !defined(SB_RDONLY) && defined(MS_RDONLY)
# define SB_RDONLY MS_RDONLY
#endif
#if !defined(SB_ACTIVE) && defined(MS_ACTIVE)
# define SB_ACTIVE MS_ACTIVE
#endif
#if !defined(SB_NOSEC) && defined(MS_NOSEC)
# define SB_NOSEC MS_NOSEC
#endif
#if !defined(SB_POSIXACL) && defined(MS_POSIXACL)
# define SB_POSIXACL MS_POSIXACL
#endif
#if !defined(SB_NODIRATIME) && defined(MS_NODIRATIME)
# define SB_NODIRATIME MS_NODIRATIME
#endif

#ifndef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
static inline void iov_iter_reexpand(struct iov_iter *i, size_t count)
{
	i->count = count;
}

static inline struct iovec iov_iter_iovec(const struct iov_iter *iter)
{
	return (struct iovec) {
		.iov_base = iter->iov->iov_base + iter->iov_offset,
		.iov_len = min(iter->count,
			       iter->iov->iov_len - iter->iov_offset),
	};
}

#define iov_for_each(iov, iter, start)					\
	for (iter = (start);						\
	     (iter).count && ((iov = iov_iter_iovec(&(iter))), 1);	\
	     iov_iter_advance(&(iter), (iov).iov_len))

static inline ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct iovec iov;
	struct iov_iter i;
	ssize_t bytes = 0;

	iov_for_each(iov, i, *iter) {
		ssize_t res;

		res = generic_file_aio_read(iocb, &iov, 1, iocb->ki_pos);
		if (res <= 0) {
			if (bytes == 0)
				bytes = res;
			break;
		}

		bytes += res;
		if (res < iov.iov_len)
			break;
	}

	if (bytes > 0)
		iov_iter_advance(iter, bytes);
	return bytes;
}

static inline ssize_t
__generic_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct iovec iov;
	struct iov_iter i;
	ssize_t bytes = 0;

	/* Since LLITE updates file size at the end of I/O in
	 * vvp_io_commit_write(), append write has to be done in atomic when
	 * there are multiple segments because otherwise each iteration to
	 * __generic_file_aio_write() will see original file size */
	if (unlikely(iocb->ki_filp->f_flags & O_APPEND && iter->nr_segs > 1)) {
		struct iovec *iov_copy;
		int count = 0;

		OBD_ALLOC_PTR_ARRAY(iov_copy, iter->nr_segs);
		if (!iov_copy)
			return -ENOMEM;

		iov_for_each(iov, i, *iter)
			iov_copy[count++] = iov;

		bytes = __generic_file_aio_write(iocb, iov_copy, count,
						 &iocb->ki_pos);
		OBD_FREE_PTR_ARRAY(iov_copy, iter->nr_segs);

		if (bytes > 0)
			iov_iter_advance(iter, bytes);
		return bytes;
	}

	iov_for_each(iov, i, *iter) {
		ssize_t res;

		res = __generic_file_aio_write(iocb, &iov, 1, &iocb->ki_pos);
		if (res <= 0) {
			if (bytes == 0)
				bytes = res;
			break;
		}

		bytes += res;
		if (res < iov.iov_len)
			break;
	}

	if (bytes > 0)
		iov_iter_advance(iter, bytes);
	return bytes;
}
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */

static inline void __user *get_vmf_address(struct vm_fault *vmf)
{
#ifdef HAVE_VM_FAULT_ADDRESS
	return (void __user *)vmf->address;
#else
	return vmf->virtual_address;
#endif
}

#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
# define ll_filemap_fault(vma, vmf) filemap_fault(vmf)
#else
# define ll_filemap_fault(vma, vmf) filemap_fault(vma, vmf)
#endif

#ifndef HAVE_CURRENT_TIME
static inline struct timespec current_time(struct inode *inode)
{
	return CURRENT_TIME;
}
#endif

#ifndef time_after32
/**
 * time_after32 - compare two 32-bit relative times
 * @a: the time which may be after @b
 * @b: the time which may be before @a
 *
 * Needed for kernels earlier than v4.14-rc1~134^2
 *
 * time_after32(a, b) returns true if the time @a is after time @b.
 * time_before32(b, a) returns true if the time @b is before time @a.
 *
 * Similar to time_after(), compare two 32-bit timestamps for relative
 * times.  This is useful for comparing 32-bit seconds values that can't
 * be converted to 64-bit values (e.g. due to disk format or wire protocol
 * issues) when it is known that the times are less than 68 years apart.
 */
#define time_after32(a, b)     ((s32)((u32)(b) - (u32)(a)) < 0)
#define time_before32(b, a)    time_after32(a, b)

#endif

#ifndef smp_store_mb
#define smp_store_mb(var, value)	set_mb(var, value)
#endif

#ifdef HAVE_PAGEVEC_INIT_ONE_PARAM
#define ll_pagevec_init(pvec, n) pagevec_init(pvec)
#else
#define ll_pagevec_init(pvec, n) pagevec_init(pvec, n)
#endif

#ifdef HAVE_D_COUNT
#  define ll_d_count(d)		d_count(d)
#else
#  define ll_d_count(d)		((d)->d_count)
#endif /* HAVE_D_COUNT */

#ifndef HAVE_IN_COMPAT_SYSCALL
#define in_compat_syscall	is_compat_task
#endif

#ifdef HAVE_I_PAGES
#define page_tree i_pages
#define ll_xa_lock_irqsave(lockp, flags) xa_lock_irqsave(lockp, flags)
#define ll_xa_unlock_irqrestore(lockp, flags) xa_unlock_irqrestore(lockp, flags)
#else
#define i_pages tree_lock
#define ll_xa_lock_irqsave(lockp, flags) spin_lock_irqsave(lockp, flags)
#define ll_xa_unlock_irqrestore(lockp, flags) spin_unlock_irqrestore(lockp, flags)
#endif

/* Linux commit v5.15-12273-gab2f9d2d3626
 *   mm: unexport {,un}lock_page_memcg
 *
 * Note that the functions are still defined or declared breaking
 * the simple approach of just defining the missing functions here
 */
#ifdef HAVE_LOCK_PAGE_MEMCG
#define vvp_lock_page_memcg(page)	lock_page_memcg((page))
#define vvp_unlock_page_memcg(page)	unlock_page_memcg((page))
#else
#define vvp_lock_page_memcg(page)
#define vvp_unlock_page_memcg(page)
#endif

#ifndef KMEM_CACHE_USERCOPY
#define kmem_cache_create_usercopy(name, size, align, flags, useroffset, \
				   usersize, ctor)			 \
	kmem_cache_create(name, size, align, flags, ctor)
#endif

#ifndef HAVE_LINUX_SELINUX_IS_ENABLED
#define selinux_is_enabled() 1
#endif

static inline int ll_vfs_getxattr(struct dentry *dentry, struct inode *inode,
				  const char *name,
				  void *value, size_t size)
{
#ifdef HAVE_USER_NAMESPACE_ARG
	return vfs_getxattr(&init_user_ns, dentry, name, value, size);
#elif defined(HAVE_VFS_SETXATTR)
	return __vfs_getxattr(dentry, inode, name, value, size);
#else
	if (unlikely(!inode->i_op->getxattr))
		return -ENODATA;

	return inode->i_op->getxattr(dentry, name, value, size);
#endif
}

static inline int ll_vfs_setxattr(struct dentry *dentry, struct inode *inode,
				  const char *name,
				  const void *value, size_t size, int flags)
{
#ifdef HAVE_USER_NAMESPACE_ARG
	return vfs_setxattr(&init_user_ns, dentry, name, value, size, flags);
#elif defined(HAVE_VFS_SETXATTR)
	return __vfs_setxattr(dentry, inode, name, value, size, flags);
#else
	if (unlikely(!inode->i_op->setxattr))
		return -EOPNOTSUPP;

	return inode->i_op->setxattr(dentry, name, value, size, flags);
#endif
}

static inline int ll_vfs_removexattr(struct dentry *dentry, struct inode *inode,
				     const char *name)
{
#ifdef HAVE_USER_NAMESPACE_ARG
	return vfs_removexattr(&init_user_ns, dentry, name);
#elif defined(HAVE_VFS_SETXATTR)
	return __vfs_removexattr(dentry, name);
#else
	if (unlikely(!inode->i_op->setxattr))
		return -EOPNOTSUPP;

	return inode->i_op->removexattr(dentry, name);
#endif
}

#ifndef FALLOC_FL_COLLAPSE_RANGE
#define FALLOC_FL_COLLAPSE_RANGE 0x08 /* remove a range of a file */
#endif

#ifndef FALLOC_FL_ZERO_RANGE
#define FALLOC_FL_ZERO_RANGE 0x10 /* convert range to zeros */
#endif

#ifndef FALLOC_FL_INSERT_RANGE
#define FALLOC_FL_INSERT_RANGE 0x20 /* insert space within file */
#endif

#ifndef raw_cpu_ptr
#define raw_cpu_ptr(p) __this_cpu_ptr(p)
#endif

#ifndef HAVE_IS_ROOT_INODE
static inline bool is_root_inode(struct inode *inode)
{
	return inode == inode->i_sb->s_root->d_inode;
}
#endif

#ifndef HAVE_REGISTER_SHRINKER_RET
#define register_shrinker(_s) (register_shrinker(_s), 0)
#endif

#ifndef fallthrough
# if defined(__GNUC__) && __GNUC__ >= 7
#  define fallthrough  __attribute__((fallthrough)) /* fallthrough */
# else
#  define fallthrough do {} while (0)  /* fallthrough */
# endif
#endif

static inline void ll_security_release_secctx(char *secdata, u32 seclen)
{
#ifdef HAVE_SEC_RELEASE_SECCTX_1ARG
	struct lsmcontext context = { };

	lsmcontext_init(&context, secdata, seclen, 0);
	return security_release_secctx(&context);
#else
	return security_release_secctx(secdata, seclen);
#endif
}

#ifndef HAVE_USER_NAMESPACE_ARG
#define posix_acl_update_mode(ns, inode, mode, acl) \
	posix_acl_update_mode(inode, mode, acl)
#define notify_change(ns, de, attr, inode)	notify_change(de, attr, inode)
#define inode_owner_or_capable(ns, inode)	inode_owner_or_capable(inode)
#define vfs_create(ns, dir, de, mode, ex)	vfs_create(dir, de, mode, ex)
#define vfs_mkdir(ns, dir, de, mode)		vfs_mkdir(dir, de, mode)
#define ll_set_acl(ns, inode, acl, type)	ll_set_acl(inode, acl, type)
#endif

/**
 * delete_from_page_cache is not exported anymore
 */
#ifdef HAVE_DELETE_FROM_PAGE_CACHE
#define cfs_delete_from_page_cache(page)	delete_from_page_cache((page))
#else
static inline void cfs_delete_from_page_cache(struct page *page)
{
	if (!page->mapping)
		return;
	LASSERT(PageLocked(page));
	get_page(page);
	unlock_page(page);
	/* on entry page is locked */
	if (S_ISREG(page->mapping->host->i_mode)) {
		generic_error_remove_page(page->mapping, page);
	} else {
		loff_t lstart = page->index << PAGE_SHIFT;
		loff_t lend = lstart + PAGE_SIZE - 1;

		truncate_inode_pages_range(page->mapping, lstart, lend);
	}
	lock_page(page);
	put_page(page);
}
#endif

#endif /* _LUSTRE_COMPAT_H */
