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
#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/pagevec.h>
#include <linux/workqueue.h>
#include <libcfs/linux/linux-fs.h>
#ifdef HAVE_XARRAY_SUPPORT
#include <linux/xarray.h>
#else
#include <libcfs/linux/xarray.h>
#endif
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

#ifdef HAVE_BI_BDEV
# define bio_get_dev(bio)	((bio)->bi_bdev)
# define bio_get_disk(bio)	(bio_get_dev(bio)->bd_disk)
# define bio_get_queue(bio)	bdev_get_queue(bio_get_dev(bio))

# ifndef HAVE_BIO_SET_DEV
#  define bio_set_dev(bio, bdev) (bio_get_dev(bio) = (bdev))
# endif
#else
# define bio_get_disk(bio)	((bio)->bi_disk)
# define bio_get_queue(bio)	(bio_get_disk(bio)->queue)
#endif

#ifndef HAVE_BI_OPF
#define bi_opf bi_rw
#endif

#ifndef SLAB_MEM_SPREAD
#define SLAB_MEM_SPREAD		0
#endif

#ifdef HAVE_STRUCT_FILE_LOCK_CORE
#define C_FLC_TYPE	c.flc_type
#define C_FLC_PID	c.flc_pid
#define C_FLC_FILE	c.flc_file
#define C_FLC_FLAGS	c.flc_flags
#define C_FLC_OWNER	c.flc_owner
#else
#define C_FLC_TYPE	fl_type
#define C_FLC_PID	fl_pid
#define C_FLC_FILE	fl_file
#define C_FLC_FLAGS	fl_flags
#define C_FLC_OWNER	fl_owner
#endif

static inline struct bio *cfs_bio_alloc(struct block_device *bdev,
					unsigned short nr_vecs,
					__u32 op, gfp_t gfp_mask)
{
	struct bio *bio;
#ifdef HAVE_BIO_ALLOC_WITH_BDEV
	bio = bio_alloc(bdev, nr_vecs, op, gfp_mask);
#else
	bio = bio_alloc(gfp_mask, nr_vecs);
	if (bio) {
		bio_set_dev(bio, bdev);
		bio->bi_opf = op;
	}
#endif /* HAVE_BIO_ALLOC_WITH_BDEV */
	return bio;
}

#ifndef HAVE_DENTRY_D_CHILD
#define d_child			d_u.d_child
#endif

#ifndef HAVE_D_IN_LOOKUP
static inline int d_in_lookup(struct dentry *dentry)
{
	return false;
}
#endif

#ifdef HAVE_DENTRY_D_CHILDREN
#define d_no_children(dentry)	(hlist_empty(&(dentry)->d_children))
#define d_for_each_child(child, dentry) \
	hlist_for_each_entry((child), &(dentry)->d_children, d_sib)
#else
#define d_no_children(dentry)	(list_empty(&(dentry)->d_subdirs))
#define d_for_each_child(child, dentry) \
	list_for_each_entry((child), &(dentry)->d_subdirs, d_child)
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

#ifndef HAVE_MNT_IDMAP_ARG
#define mnt_idmap	user_namespace
#define nop_mnt_idmap	init_user_ns
#endif

static inline int ll_vfs_getattr(struct path *path, struct kstat *st,
				 u32 request_mask, unsigned int flags)
{
	int rc;

#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_INODEOPS_ENHANCED_GETATTR)
#ifdef AT_GETATTR_NOSEC /* added in v6.7-rc1-1-g8a924db2d7b5 */
	if (flags & AT_GETATTR_NOSEC)
		rc = vfs_getattr_nosec(path, st, request_mask, flags);
	else
#endif /* AT_GETATTR_NOSEC */
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

#ifndef HAVE_PAGECACHE_GET_PAGE
#define pagecache_get_page(mapping, index, fp, gfp) \
	grab_cache_page_nowait(mapping, index)
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

/* Linux kernel version v5.0 commit fd9dc93e36231fb6d520e0edd467058fad4fd12d
 * ("XArray: Change xa_insert to return -EBUSY")
 * instead of -EEXIST
 */
static inline int __must_check ll_xa_insert(struct xarray *xa,
					    unsigned long index,
					    void *entry, gfp_t gpf)
{
	int rc = xa_insert(xa, index, entry, gpf);

	if (rc == -EEXIST)
		rc = -EBUSY;
	return rc;
}

#ifndef HAVE_TRUNCATE_INODE_PAGES_FINAL
static inline void truncate_inode_pages_final(struct address_space *map)
{
	truncate_inode_pages(map, 0);
}
#endif

#ifdef HAVE_U64_CAPABILITY
#define ll_capability_u32(kcap) \
	((kcap).val & 0xFFFFFFFF)
#define ll_set_capability_u32(kcap, val32) \
	((kcap)->val = ((kcap)->val & 0xffffffff00000000ull) | (val32))
#else
#define ll_capability_u32(kcap) \
	((kcap).cap[0])
#define ll_set_capability_u32(kcap, val32) \
	((kcap)->cap[0] = val32)
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
#define posix_acl_valid(a, b)		posix_acl_valid(b)
#endif

#ifdef HAVE_IOP_SET_ACL
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
#if !defined(HAVE_USER_NAMESPACE_ARG) && \
	!defined(HAVE_POSIX_ACL_UPDATE_MODE) && \
	!defined(HAVE_MNT_IDMAP_ARG)
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
#if !defined(SB_KERNMOUNT) && defined(MS_KERNMOUNT)
# define SB_KERNMOUNT MS_KERNMOUNT
#endif

#ifndef HAVE_IOV_ITER_IOVEC
static inline struct iovec iov_iter_iovec(const struct iov_iter *iter)
{
	return (struct iovec) {
		.iov_base = iter->__iov->iov_base + iter->iov_offset,
		.iov_len = min(iter->count,
			       iter->__iov->iov_len - iter->iov_offset),
	};
}
#endif

#ifndef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
static inline void iov_iter_reexpand(struct iov_iter *i, size_t count)
{
	i->count = count;
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
	 * __generic_file_aio_write() will see original file size
	 */
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
# define __ll_filemap_fault(vma, vmf) filemap_fault(vmf)
#else
# define __ll_filemap_fault(vma, vmf) filemap_fault(vma, vmf)
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

/* kernel version less than 4.2, smp_store_mb is not defined, use set_mb */
#ifndef smp_store_mb
#define smp_store_mb(var, value) set_mb(var, value) /* set full mem barrier */
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
#define ll_xa_unlock_irqrestore(lockp, flags) spin_unlock_irqrestore(lockp, \
								     flags)
#endif

#ifndef KMEM_CACHE_USERCOPY
#define kmem_cache_create_usercopy(name, size, align, flags, useroffset, \
				   usersize, ctor)			 \
	kmem_cache_create(name, size, align, flags, ctor)
#endif

static inline bool ll_security_xattr_wanted(struct inode *in)
{
#ifdef CONFIG_SECURITY
	return in->i_security && in->i_sb->s_security;
#else
	return false;
#endif
}

static inline int ll_vfs_getxattr(struct dentry *dentry, struct inode *inode,
				  const char *name,
				  void *value, size_t size)
{
#if defined(HAVE_MNT_IDMAP_ARG) || defined(HAVE_USER_NAMESPACE_ARG) || \
	defined(HAVE_VFS_SETXATTR)
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
#if defined(HAVE_MNT_IDMAP_ARG) || defined(HAVE_USER_NAMESPACE_ARG)
	return __vfs_setxattr(&nop_mnt_idmap, dentry, inode, name,
			    VFS_SETXATTR_VALUE(value), size, flags);
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
#if defined(HAVE_MNT_IDMAP_ARG) || defined(HAVE_USER_NAMESPACE_ARG)
	return __vfs_removexattr(&nop_mnt_idmap, dentry, name);
#elif defined(HAVE_VFS_SETXATTR)
	return __vfs_removexattr(dentry, name);
#else
	if (unlikely(!inode->i_op->setxattr))
		return -EOPNOTSUPP;

	return inode->i_op->removexattr(dentry, name);
#endif
}

/* until v3.19-rc5-3-gb4caecd48005 */
#ifndef BDI_CAP_MAP_COPY
#define BDI_CAP_MAP_COPY		0
#endif

/* from v4.1-rc2-56-g89e9b9e07a39, until v5.9-rc3-161-gf56753ac2a90 */
#ifndef BDI_CAP_CGROUP_WRITEBACK
#define BDI_CAP_CGROUP_WRITEBACK	0
#endif

/* from v5.9-rc3-161-gf56753ac2a90 */
#ifndef BDI_CAP_WRITEBACK
#define BDI_CAP_WRITEBACK		0
#endif

/* from v5.9-rc3-161-gf56753ac2a90 */
#ifndef BDI_CAP_WRITEBACK_ACCT
#define BDI_CAP_WRITEBACK_ACCT		0
#endif

#define LL_BDI_CAP_FLAGS	(BDI_CAP_CGROUP_WRITEBACK | BDI_CAP_MAP_COPY | \
				 BDI_CAP_WRITEBACK | BDI_CAP_WRITEBACK_ACCT)

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

#if defined(HAVE_DIRECTIO_ITER) || defined(HAVE_IOV_ITER_RW) || \
	defined(HAVE_DIRECTIO_2ARGS) || defined(HAVE_IOV_ITER_GET_PAGES_ALLOC2)
#define HAVE_DIO_ITER 1
#endif

#if !defined HAVE_IOV_ITER_GET_PAGES_ALLOC2 && defined HAVE_DIO_ITER
static inline ssize_t iov_iter_get_pages_alloc2(struct iov_iter *i,
						   struct page ***pages,
						   size_t maxsize,
						   size_t *start)
{
	ssize_t result = 0;

	/* iov_iter_get_pages_alloc is non advancing version of alloc2 */
	result = iov_iter_get_pages_alloc(i, pages, maxsize, start);
	if (result > 0 && user_backed_iter(i))
		iov_iter_advance(i, result);

	return result;
}
#endif

#ifdef HAVE_AOPS_MIGRATE_FOLIO
#define folio_migr	folio
#else
#define folio_migr	page
#define migrate_folio	migratepage
#endif

struct ll_shrinker_ops {
#ifdef HAVE_SHRINKER_COUNT
	unsigned long (*count_objects)(struct shrinker *,
				       struct shrink_control *sc);
	unsigned long (*scan_objects)(struct shrinker *,
				      struct shrink_control *sc);
#else
	int (*shrink)(struct shrinker *, struct shrink_control *sc);
#endif
	int seeks;	/* seeks to recreate an obj */
};

#ifndef HAVE_SHRINKER_ALLOC
static inline void shrinker_free(struct shrinker *shrinker)
{
	unregister_shrinker(shrinker);
	OBD_FREE_PTR(shrinker);
}
#endif

/* allocate and register a shrinker, return should be checked with IS_ERR() */
static inline struct shrinker *
ll_shrinker_create(struct ll_shrinker_ops *ops, unsigned int flags,
		   const char *fmt, ...)
{
	struct shrinker *shrinker;
	int rc = 0;

#if defined(HAVE_REGISTER_SHRINKER_FORMAT_NAMED) || defined(HAVE_SHRINKER_ALLOC)
	struct va_format vaf;
	va_list args;
#endif

#ifdef HAVE_SHRINKER_ALLOC
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	shrinker = shrinker_alloc(flags, "%pV", &vaf);
	va_end(args);
#else
	OBD_ALLOC_PTR(shrinker);
#endif
	if (!shrinker)
		return ERR_PTR(-ENOMEM);

#ifdef HAVE_SHRINKER_COUNT
	shrinker->count_objects = ops->count_objects;
	shrinker->scan_objects = ops->scan_objects;
#else
	shrinker->shrink = ops->shrink;
#endif
	shrinker->seeks = ops->seeks;

#ifdef HAVE_SHRINKER_ALLOC
	shrinker_register(shrinker);
#else
 #ifdef HAVE_REGISTER_SHRINKER_FORMAT_NAMED
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	rc = register_shrinker(shrinker, "%pV", &vaf);
	va_end(args);
 #elif defined(HAVE_REGISTER_SHRINKER_RET)
	rc = register_shrinker(shrinker);
 #else
	register_shrinker(shrinker);
 #endif
#endif
	if (rc) {
#ifdef HAVE_SHRINKER_ALLOC
		shrinker_free(shrinker);
#else
		OBD_FREE_PTR(shrinker);
#endif
		shrinker = ERR_PTR(rc);
	}
	return shrinker;
}

#ifndef fallthrough
# if defined(__GNUC__) && __GNUC__ >= 7
#  define fallthrough  __attribute__((fallthrough)) /* fallthrough */
# else
#  define fallthrough do {} while (0)  /* fallthrough */
# endif
#endif

#ifdef VERIFY_WRITE /* removed in kernel commit v4.20-10979-g96d4f267e40f */
#define ll_access_ok(ptr, len) access_ok(VERIFY_WRITE, ptr, len)
#else
#define ll_access_ok(ptr, len) access_ok(ptr, len)
#endif

#ifndef HAVE_WB_STAT_MOD
#define wb_stat_mod(wb, item, amount)	__add_wb_stat(wb, item, amount)
#endif

#ifdef HAVE_SEC_RELEASE_SECCTX_1ARG
#ifndef HAVE_LSMCONTEXT_INIT
/* Ubuntu 5.19 */
static inline void lsmcontext_init(struct lsmcontext *cp, char *context,
				   u32 size, int slot)
{
#ifdef HAVE_LSMCONTEXT_HAS_ID
	cp->id = slot;
#else
	cp->slot = slot;
#endif
	cp->context = context;
	cp->len = size;
}
#endif
#endif

static inline void ll_security_release_secctx(char *secdata, u32 seclen,
					      int slot)
{
#ifdef HAVE_SEC_RELEASE_SECCTX_1ARG
	struct lsmcontext context = { };

	lsmcontext_init(&context, secdata, seclen, slot);
	return security_release_secctx(&context);
#else
	return security_release_secctx(secdata, seclen);
#endif
}

#if !defined(HAVE_USER_NAMESPACE_ARG) && !defined(HAVE_MNT_IDMAP_ARG)
#define posix_acl_update_mode(ns, inode, mode, acl) \
	posix_acl_update_mode(inode, mode, acl)
#define notify_change(ns, de, attr, inode)	notify_change(de, attr, inode)
#define inode_owner_or_capable(ns, inode)	inode_owner_or_capable(inode)
#define vfs_create(ns, dir, de, mode, ex)	vfs_create(dir, de, mode, ex)
#define vfs_mkdir(ns, dir, de, mode)		vfs_mkdir(dir, de, mode)
#define ll_set_acl(ns, inode, acl, type)	ll_set_acl(inode, acl, type)
#endif

#ifndef HAVE_GENERIC_ERROR_REMOVE_FOLIO
#ifdef HAVE_FOLIO_BATCH
#define generic_folio			folio
#else
#define generic_folio			page
#define folio_page(page, n)		(page)
#define folio_nr_pages(page)		(1)
#define page_folio(page)		(page)
#endif
static inline int generic_error_remove_folio(struct address_space *mapping,
					     struct generic_folio *folio)
{
	int pg, npgs = folio_nr_pages(folio);
	int err = 0;

	for (pg = 0; pg < npgs; pg++) {
		err = generic_error_remove_page(mapping, folio_page(folio, pg));
		if (err)
			break;
	}
	return err;
}
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
		generic_error_remove_folio(page->mapping, page_folio(page));
	} else {
		loff_t lstart = page->index << PAGE_SHIFT;
		loff_t lend = lstart + PAGE_SIZE - 1;

		truncate_inode_pages_range(page->mapping, lstart, lend);
	}
	lock_page(page);
	put_page(page);
}
#endif

static inline struct page *ll_read_cache_page(struct address_space *mapping,
					      pgoff_t index, filler_t *filler,
					      void *data)
{
#ifdef HAVE_READ_CACHE_PAGE_WANTS_FILE
	struct file dummy_file;

	dummy_file.f_ra.ra_pages = 32; /* unused, modified on ra error */
	dummy_file.private_data = data;
	return read_cache_page(mapping, index, filler, &dummy_file);
#else
	return read_cache_page(mapping, index, filler, data);
#endif /* HAVE_READ_CACHE_PAGE_WANTS_FILE */
}

#if defined(HAVE_FOLIO_BATCH) && defined(HAVE_FILEMAP_GET_FOLIOS)
# define ll_folio_batch_init(batch, n)	folio_batch_init(batch)
# define ll_filemap_get_folios(m, s, e, fbatch) \
	 filemap_get_folios(m, &s, e, fbatch)
# define fbatch_at(fbatch, f)		((fbatch)->folios[(f)])
# define fbatch_at_npgs(fbatch, f)	folio_nr_pages((fbatch)->folios[(f)])
# define fbatch_at_pg(fbatch, f, pg)	folio_page((fbatch)->folios[(f)], (pg))
# define folio_batch_add_page(fbatch, page) \
	 folio_batch_add(fbatch, page_folio(page))
# ifndef HAVE_FOLIO_BATCH_REINIT
static inline void folio_batch_reinit(struct folio_batch *fbatch)
{
	fbatch->nr = 0;
}
# endif /* HAVE_FOLIO_BATCH_REINIT */

#else /* !HAVE_FOLIO_BATCH && !HAVE_FILEMAP_GET_FOLIOS */

# ifdef HAVE_PAGEVEC
#  define folio_batch			pagevec
# endif
# define folio_batch_init(pvec)		pagevec_init(pvec)
# define folio_batch_reinit(pvec)	pagevec_reinit(pvec)
# define folio_batch_count(pvec)	pagevec_count(pvec)
# define folio_batch_space(pvec)	pagevec_space(pvec)
# define folio_batch_add_page(pvec, page) \
	 pagevec_add(pvec, page)
# define folio_batch_release(pvec) \
	 pagevec_release(((struct pagevec *)pvec))
# ifdef HAVE_PAGEVEC_INIT_ONE_PARAM
#  define ll_folio_batch_init(pvec, n)	pagevec_init(pvec)
# else
#  define ll_folio_batch_init(pvec, n)	pagevec_init(pvec, n)
# endif
#ifdef HAVE_PAGEVEC_LOOKUP_THREE_PARAM
# define ll_filemap_get_folios(m, s, e, pvec) \
	 pagevec_lookup(pvec, m, &s)
#else
# define ll_filemap_get_folios(m, s, e, pvec) \
	 pagevec_lookup(pvec, m, s, PAGEVEC_SIZE)
#endif
# define fbatch_at(pvec, n)		((pvec)->pages[(n)])
# define fbatch_at_npgs(pvec, n)	1
# define fbatch_at_pg(pvec, n, pg)	((pvec)->pages[(n)])
#endif /* HAVE_FOLIO_BATCH && HAVE_FILEMAP_GET_FOLIOS */

#ifndef HAVE_FLUSH___WORKQUEUE
#define __flush_workqueue(wq)	flush_scheduled_work()
#endif

#ifdef HAVE_NSPROXY_COUNT_AS_REFCOUNT
#define nsproxy_dec(ns)		refcount_dec(&(ns)->count)
#else
#define nsproxy_dec(ns)		atomic_dec(&(ns)->count)
#endif

#ifndef HAVE_INODE_GET_CTIME
#define inode_get_ctime(i)		((i)->i_ctime)
#define inode_set_ctime_to_ts(i, ts)	((i)->i_ctime = ts)
#define inode_set_ctime_current(i) \
	inode_set_ctime_to_ts((i), current_time((i)))

static inline struct timespec64 inode_set_ctime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };

	return inode_set_ctime_to_ts(inode, ts);
}
#endif /* !HAVE_INODE_GET_CTIME */

#ifndef HAVE_INODE_GET_MTIME_SEC

#define inode_get_ctime_sec(i)		(inode_get_ctime((i)).tv_sec)

#define inode_get_atime(i)		((i)->i_atime)
#define inode_get_atime_sec(i)		((i)->i_atime.tv_sec)
#define inode_set_atime_to_ts(i, ts)	((i)->i_atime = ts)

static inline struct timespec64 inode_set_atime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };
	return inode_set_atime_to_ts(inode, ts);
}

#define inode_get_mtime(i)		((i)->i_mtime)
#define inode_get_mtime_sec(i)		((i)->i_mtime.tv_sec)
#define inode_set_mtime_to_ts(i, ts)	((i)->i_mtime = ts)

static inline struct timespec64 inode_set_mtime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };
	return inode_set_mtime_to_ts(inode, ts);
}
#endif  /* !HAVE_INODE_GET_MTIME_SEC */

#endif /* _LUSTRE_COMPAT_H */
