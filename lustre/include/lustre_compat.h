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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _LUSTRE_COMPAT_H
#define _LUSTRE_COMPAT_H

#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include <linux/xattr.h>

#include <libcfs/libcfs.h>
#include <lustre_patchless_compat.h>
#include <obd_support.h>

#ifdef HAVE_FS_STRUCT_RWLOCK
# define LOCK_FS_STRUCT(fs)	write_lock(&(fs)->lock)
# define UNLOCK_FS_STRUCT(fs)	write_unlock(&(fs)->lock)
#else
# define LOCK_FS_STRUCT(fs)	spin_lock(&(fs)->lock)
# define UNLOCK_FS_STRUCT(fs)	spin_unlock(&(fs)->lock)
#endif

#ifdef HAVE_FS_STRUCT_SEQCOUNT
# define WRITE_FS_SEQ_BEGIN(fs)	write_seqcount_begin(&(fs)->seq)
# define WRITE_FS_SEQ_END(fs)	write_seqcount_end(&(fs)->seq)
#else
# define WRITE_FS_SEQ_BEGIN(fs)
# define WRITE_FS_SEQ_END(fs)
#endif
static inline void ll_set_fs_pwd(struct fs_struct *fs, struct vfsmount *mnt,
                                 struct dentry *dentry)
{
	struct path path;
	struct path old_pwd;

	path.mnt = mnt;
	path.dentry = dentry;
	path_get(&path);
	LOCK_FS_STRUCT(fs);
	WRITE_FS_SEQ_BEGIN(fs);
	old_pwd = fs->pwd;
	fs->pwd = path;
	WRITE_FS_SEQ_END(fs);
	UNLOCK_FS_STRUCT(fs);

	if (old_pwd.dentry)
		path_put(&old_pwd);
}

/*
 * set ATTR_BLOCKS to a high value to avoid any risk of collision with other
 * ATTR_* attributes (see bug 13828)
 */
#define ATTR_BLOCKS    (1 << 27)

#define current_ngroups current_cred()->group_info->ngroups
#define current_groups current_cred()->group_info->small_block

/*
 * OBD need working random driver, thus all our
 * initialization routines must be called after device
 * driver initialization
 */
#ifndef MODULE
#undef module_init
#define module_init(a)     late_initcall(a)
#endif

#ifndef MODULE_ALIAS_FS
#define MODULE_ALIAS_FS(name)
#endif

#define LTIME_S(time)                   (time.tv_sec)

#ifdef HAVE_GENERIC_PERMISSION_2ARGS
# define ll_generic_permission(inode, mask, flags, check_acl) \
	 generic_permission(inode, mask)
#elif defined HAVE_GENERIC_PERMISSION_4ARGS
# define ll_generic_permission(inode, mask, flags, check_acl) \
	 generic_permission(inode, mask, flags, check_acl)
#else
# define ll_generic_permission(inode, mask, flags, check_acl) \
	 generic_permission(inode, mask, check_acl)
#endif

#ifdef HAVE_4ARGS_VFS_SYMLINK
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                vfs_symlink(dir, dentry, path, mode)
#else
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                       vfs_symlink(dir, dentry, path)
#endif

#if !defined(HAVE_FILE_LLSEEK_SIZE) || defined(HAVE_FILE_LLSEEK_SIZE_5ARGS)
#define ll_generic_file_llseek_size(file, offset, origin, maxbytes, eof) \
		generic_file_llseek_size(file, offset, origin, maxbytes, eof);
#else
#define ll_generic_file_llseek_size(file, offset, origin, maxbytes, eof) \
		generic_file_llseek_size(file, offset, origin, maxbytes);
#endif

#ifdef HAVE_INODE_DIO_WAIT
/* inode_dio_wait(i) use as-is for write lock */
# define inode_dio_write_done(i)	do {} while (0) /* for write unlock */
#else
# define inode_dio_wait(i)		down_write(&(i)->i_alloc_sem)
# define inode_dio_write_done(i)	up_write(&(i)->i_alloc_sem)
#endif

#ifndef FS_HAS_FIEMAP
#define FS_HAS_FIEMAP			(0)
#endif

#ifndef HAVE_SIMPLE_SETATTR
#define simple_setattr(dentry, ops) inode_setattr((dentry)->d_inode, ops)
#endif

#ifndef SLAB_DESTROY_BY_RCU
#define SLAB_DESTROY_BY_RCU 0
#endif

#ifndef HAVE_DQUOT_SUSPEND
# define ll_vfs_dq_init             vfs_dq_init
# define ll_vfs_dq_drop             vfs_dq_drop
# define ll_vfs_dq_transfer         vfs_dq_transfer
# define ll_vfs_dq_off(sb, remount) vfs_dq_off(sb, remount)
#else
# define ll_vfs_dq_init             dquot_initialize
# define ll_vfs_dq_drop             dquot_drop
# define ll_vfs_dq_transfer         dquot_transfer
# define ll_vfs_dq_off(sb, remount) dquot_suspend(sb, -1)
#endif

#ifndef HAVE_BLKDEV_GET_BY_DEV
# define blkdev_get_by_dev(dev, mode, holder) open_by_devnum(dev, mode)
#endif

#ifdef HAVE_BVEC_ITER
#define bio_idx(bio)			(bio->bi_iter.bi_idx)
#define bio_set_sector(bio, sector)	(bio->bi_iter.bi_sector = sector)
#define bvl_to_page(bvl)		(bvl->bv_page)
#else
#define bio_idx(bio)			(bio->bi_idx)
#define bio_set_sector(bio, sector)	(bio->bi_sector = sector)
#define bio_sectors(bio)		((bio)->bi_size >> 9)
#ifndef HAVE_BIO_END_SECTOR
#define bio_end_sector(bio)		(bio->bi_sector + bio_sectors(bio))
#endif
#define bvl_to_page(bvl)		(bvl->bv_page)
#endif

#ifndef HAVE_BLK_QUEUE_MAX_SEGMENTS
#define blk_queue_max_segments(rq, seg)                      \
        do { blk_queue_max_phys_segments(rq, seg);           \
             blk_queue_max_hw_segments(rq, seg); } while (0)
#else
#define queue_max_phys_segments(rq)       queue_max_segments(rq)
#define queue_max_hw_segments(rq)         queue_max_segments(rq)
#endif

#ifdef HAVE_BLK_PLUG
#define DECLARE_PLUG(plug)	struct blk_plug plug
#else /* !HAVE_BLK_PLUG */
#define DECLARE_PLUG(name)
#define blk_start_plug(plug)	do {} while (0)
#define blk_finish_plug(plug)	do {} while (0)
#endif

#ifdef HAVE_KMAP_ATOMIC_HAS_1ARG
#define ll_kmap_atomic(a, b)	kmap_atomic(a)
#define ll_kunmap_atomic(a, b)	kunmap_atomic(a)
#else
#define ll_kmap_atomic(a, b)	kmap_atomic(a, b)
#define ll_kunmap_atomic(a, b)	kunmap_atomic(a, b)
#endif

#ifndef HAVE_CLEAR_INODE
#define clear_inode(i)		end_writeback(i)
#endif

#ifndef HAVE_DENTRY_D_CHILD
#define d_child			d_u.d_child
#endif

#ifdef HAVE_DENTRY_D_U_D_ALIAS
#define d_alias			d_u.d_alias
#endif

#ifndef DATA_FOR_LLITE_IS_LIST
#define ll_d_hlist_node hlist_node
#define ll_d_hlist_empty(list) hlist_empty(list)
#define ll_d_hlist_entry(ptr, type, name) hlist_entry(ptr.first, type, name)
#define ll_d_hlist_for_each(tmp, i_dentry) hlist_for_each(tmp, i_dentry)
# ifdef HAVE_HLIST_FOR_EACH_3ARG
# define ll_d_hlist_for_each_entry(dentry, p, i_dentry) \
	p = NULL; hlist_for_each_entry(dentry, i_dentry, d_alias)
# else
# define ll_d_hlist_for_each_entry(dentry, p, i_dentry) \
	hlist_for_each_entry(dentry, p, i_dentry, d_alias)
# endif
#define DECLARE_LL_D_HLIST_NODE_PTR(name) struct ll_d_hlist_node *name
#else
#define ll_d_hlist_node list_head
#define ll_d_hlist_empty(list) list_empty(list)
#define ll_d_hlist_entry(ptr, type, name) list_entry(ptr.next, type, name)
#define ll_d_hlist_for_each(tmp, i_dentry) list_for_each(tmp, i_dentry)
#define ll_d_hlist_for_each_entry(dentry, p, i_dentry) \
	list_for_each_entry(dentry, i_dentry, d_alias)
#define DECLARE_LL_D_HLIST_NODE_PTR(name) /* nothing */
#endif /* !DATA_FOR_LLITE_IS_LIST */

#ifndef QUOTA_OK
# define QUOTA_OK 0
#endif
#ifndef NO_QUOTA
# define NO_QUOTA (-EDQUOT)
#endif

#ifndef SEEK_DATA
#define SEEK_DATA      3       /* seek to the next data */
#endif
#ifndef SEEK_HOLE
#define SEEK_HOLE      4       /* seek to the next hole */
#endif

#ifndef FMODE_UNSIGNED_OFFSET
#define FMODE_UNSIGNED_OFFSET	((__force fmode_t)0x2000)
#endif

#if !defined(_ASM_GENERIC_BITOPS_EXT2_NON_ATOMIC_H_) && !defined(ext2_set_bit)
# define ext2_set_bit             __test_and_set_bit_le
# define ext2_clear_bit           __test_and_clear_bit_le
# define ext2_test_bit            test_bit_le
# define ext2_find_first_zero_bit find_first_zero_bit_le
# define ext2_find_next_zero_bit  find_next_zero_bit_le
#endif

#ifdef ATTR_TIMES_SET
# define TIMES_SET_FLAGS (ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET)
#else
# define TIMES_SET_FLAGS (ATTR_MTIME_SET | ATTR_ATIME_SET)
#endif

#ifndef XATTR_NAME_POSIX_ACL_ACCESS
# define XATTR_NAME_POSIX_ACL_ACCESS POSIX_ACL_XATTR_ACCESS
#endif

#ifndef XATTR_NAME_POSIX_ACL_DEFAULT
# define XATTR_NAME_POSIX_ACL_DEFAULT POSIX_ACL_XATTR_DEFAULT
#endif

#ifndef HAVE_LM_XXX_LOCK_MANAGER_OPS
# define lm_compare_owner	fl_compare_owner
#endif

/*
 * After 3.1, kernel's nameidata.intent.open.flags is different
 * with lustre's lookup_intent.it_flags, as lustre's it_flags'
 * lower bits equal to FMODE_xxx while kernel doesn't transliterate
 * lower bits of nameidata.intent.open.flags to FMODE_xxx.
 * */
#include <linux/version.h>
static inline int ll_namei_to_lookup_intent_flag(int flag)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	flag = (flag & ~O_ACCMODE) | OPEN_FMODE(flag);
#endif
	return flag;
}

#include <linux/fs.h>
#ifndef HAVE_PROTECT_I_NLINK
static inline void set_nlink(struct inode *inode, unsigned int nlink)
{
	inode->i_nlink = nlink;
}
#endif

#ifdef HAVE_INODEOPS_USE_UMODE_T
# define ll_umode_t	umode_t
#else
# define ll_umode_t	int
#endif

#include <linux/dcache.h>
#ifndef HAVE_D_MAKE_ROOT
static inline struct dentry *d_make_root(struct inode *root)
{
	struct dentry *res = d_alloc_root(root);

	if (res == NULL && root)
		iput(root);

	return res;
}
#endif

#ifdef HAVE_DIRTY_INODE_HAS_FLAG
# define ll_dirty_inode(inode, flag)	(inode)->i_sb->s_op->dirty_inode((inode), flag)
#else
# define ll_dirty_inode(inode, flag)	(inode)->i_sb->s_op->dirty_inode((inode))
#endif

#ifdef HAVE_FILE_F_INODE
# define set_file_inode(file, inode)	(file)->f_inode = inode
#else
# define set_file_inode(file, inode)
#endif

#ifndef HAVE_FILE_INODE
static inline struct inode *file_inode(const struct file *file)
{
	return file->f_path.dentry->d_inode;
}
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

#ifdef HAVE_VFS_UNLINK_3ARGS
#define ll_vfs_unlink(a, b) vfs_unlink(a, b, NULL)
#else
#define ll_vfs_unlink(a, b) vfs_unlink(a, b)
#endif

#ifndef HAVE_INODE_LOCK
# define inode_lock(inode) mutex_lock(&(inode)->i_mutex)
# define inode_unlock(inode) mutex_unlock(&(inode)->i_mutex)
# define inode_trylock(inode) mutex_trylock(&(inode)->i_mutex)
#endif

#ifndef HAVE_RADIX_EXCEPTION_ENTRY
static inline int radix_tree_exceptional_entry(void *arg)
{
	return 0;
}
#endif

#ifndef HAVE_TRUNCATE_INODE_PAGES_FINAL
static inline void truncate_inode_pages_final(struct address_space *map)
{
	truncate_inode_pages(map, 0);
}
#endif

#ifndef SIZE_MAX
#define SIZE_MAX	(~(size_t)0)
#endif

#ifdef HAVE_SECURITY_IINITSEC_CALLBACK
# define ll_security_inode_init_security(inode, dir, name, value, len, \
					 initxattrs, dentry)	       \
	 security_inode_init_security(inode, dir, &((dentry)->d_name), \
				      initxattrs, dentry)
#elif defined HAVE_SECURITY_IINITSEC_QSTR
# define ll_security_inode_init_security(inode, dir, name, value, len, \
					 initxattrs, dentry)	       \
	 security_inode_init_security(inode, dir, &((dentry)->d_name), \
				      name, value, len)
#else /* !HAVE_SECURITY_IINITSEC_CALLBACK && !HAVE_SECURITY_IINITSEC_QSTR */
# define ll_security_inode_init_security(inode, dir, name, value, len, \
					 initxattrs, dentry)	       \
	 security_inode_init_security(inode, dir, name, value, len)
#endif

#ifndef bio_for_each_segment_all /* since kernel version 3.9 */
#ifdef HAVE_BVEC_ITER
#define bio_for_each_segment_all(bv, bio, it) \
	for (it = 0, bv = (bio)->bi_io_vec; it < (bio)->bi_vcnt; it++, bv++)
#else
#define bio_for_each_segment_all(bv, bio, it) bio_for_each_segment(bv, bio, it)
#endif
#endif

#ifdef HAVE_PID_NS_FOR_CHILDREN
# define ll_task_pid_ns(task)	((task)->nsproxy->pid_ns_for_children)
#else
# define ll_task_pid_ns(task)	((task)->nsproxy->pid_ns)
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
#ifdef HAVE_XATTR_HANDLER_FLAGS
#define ll_setxattr     generic_setxattr
#define ll_getxattr     generic_getxattr
#define ll_removexattr  generic_removexattr
#else
int ll_setxattr(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags);
ssize_t ll_getxattr(struct dentry *dentry, const char *name,
		    void *buf, size_t buf_size);
int ll_removexattr(struct dentry *dentry, const char *name);
#endif /* ! HAVE_XATTR_HANDLER_FLAGS */
#endif /* HAVE_IOP_XATTR */

#ifndef HAVE_VFS_SETXATTR
const struct xattr_handler *get_xattr_type(const char *name);

#ifdef HAVE_XATTR_HANDLER_FLAGS
static inline int
__vfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
	       const void *value, size_t size, int flags)
{
	const struct xattr_handler *handler;
	int rc;

	handler = get_xattr_type(name);
	if (!handler)
		return -ENXIO;

#if defined(HAVE_XATTR_HANDLER_INODE_PARAM)
	rc = handler->set(handler, dentry, inode, name, value, size,
			  XATTR_CREATE);
#elif defined(HAVE_XATTR_HANDLER_SIMPLIFIED)
	rc = handler->set(handler, dentry, name, value, size, XATTR_CREATE);
#else
	rc = handler->set(dentry, name, value, size, XATTR_CREATE,
			  handler->flags);
#endif /* !HAVE_XATTR_HANDLER_INODE_PARAM */
	return rc;
}
#else /* !HAVE_XATTR_HANDLER_FLAGS */
static inline int
__vfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
	       const void *value, size_t size, int flags)
{
	return ll_setxattr(dentry, name, value, size, flags);
}
#endif /* HAVE_XATTR_HANDLER_FLAGS */
#endif /* HAVE_VFS_SETXATTR */

#ifdef HAVE_IOP_SET_ACL
#ifdef CONFIG_FS_POSIX_ACL
#ifndef HAVE_POSIX_ACL_UPDATE_MODE
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

#ifndef HAVE_IS_SXID
static inline bool is_sxid(umode_t mode)
{
	return (mode & S_ISUID) || ((mode & S_ISGID) && (mode & S_IXGRP));
}
#endif

#ifndef IS_NOSEC
#define IS_NOSEC(inode)	(!is_sxid(inode->i_mode))
#endif

#ifndef MS_NOSEC
static inline void inode_has_no_xattr(struct inode *inode)
{
	return;
}
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

		OBD_ALLOC(iov_copy, sizeof(*iov_copy) * iter->nr_segs);
		if (!iov_copy)
			return -ENOMEM;

		iov_for_each(iov, i, *iter)
			iov_copy[count++] = iov;

		bytes = __generic_file_aio_write(iocb, iov_copy, count,
						 &iocb->ki_pos);
		OBD_FREE(iov_copy, sizeof(*iov_copy) * iter->nr_segs);

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

#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif

#endif /* _LUSTRE_COMPAT_H */
