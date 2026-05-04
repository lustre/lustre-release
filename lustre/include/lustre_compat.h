/* SPDX-License-Identifier: GPL-2.0 */

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
#include <lustre_compat/linux/fs.h>
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
#include <lustre_compat/linux/shrinker.h>
#include <lustre_compat/linux/xarray.h>
#include <lustre_compat/linux/folio.h>
#include <lustre_compat/linux/blkdev.h>
#include <lustre_compat/linux/posix_acl_xattr.h>
#include <obd_support.h>

#ifdef HAVE_4ARGS_VFS_SYMLINK
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
		       vfs_symlink(dir, dentry, path, mode)
#else
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
		       vfs_symlink(dir, dentry, path)
#endif

#ifdef HAVE_BVEC_ITER
#define bio_start_sector(bio) (bio->bi_iter.bi_sector)
#else
#define bio_start_sector(bio) (bio->bi_sector)
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

#ifdef HAVE_DENTRY_D_CHILDREN
#define d_no_children(dentry)	(hlist_empty(&(dentry)->d_children))
#define d_for_each_child(child, dentry) \
	hlist_for_each_entry((child), &(dentry)->d_children, d_sib)
#else
#define d_no_children(dentry)	(list_empty(&(dentry)->d_subdirs))
#define d_for_each_child(child, dentry) \
	list_for_each_entry((child), &(dentry)->d_subdirs, d_child)
#endif

#ifdef HAVE_USER_NAMESPACE_ARG
#define vfs_unlink(ns, dir, de) vfs_unlink(ns, dir, de, NULL)
#else
#define vfs_unlink(ns, dir, de) vfs_unlink(dir, de, NULL)
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

static inline bool ll_security_xattr_wanted(struct inode *in)
{
#ifdef CONFIG_SECURITY
	return in->i_security && in->i_sb->s_security;
#else
	return false;
#endif
}

static inline int ll_vfs_setxattr(struct dentry *dentry, struct inode *inode,
				  const char *name,
				  const void *value, size_t size, int flags)
{
#if defined(HAVE_MNT_IDMAP_ARG) || defined(HAVE_USER_NAMESPACE_ARG)
	return __vfs_setxattr(&nop_mnt_idmap, dentry, inode, name,
			      VFS_SETXATTR_VALUE(value), size, flags);
#else
	return __vfs_setxattr(dentry, inode, name, value, size, flags);
#endif
}

static inline int ll_vfs_removexattr(struct dentry *dentry, struct inode *inode,
				     const char *name)
{
#if defined(HAVE_MNT_IDMAP_ARG) || defined(HAVE_USER_NAMESPACE_ARG)
	return __vfs_removexattr(&nop_mnt_idmap, dentry, name);
#else
	return __vfs_removexattr(dentry, name);
#endif
}

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

#define LL_BDI_CAP_FLAGS	(BDI_CAP_CGROUP_WRITEBACK | \
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

#ifdef HAVE_AOPS_MIGRATE_FOLIO
#define folio_migr	folio
#else
#define folio_migr	page
#define migrate_folio	migratepage
#endif

static inline const char *shrinker_debugfs_path(struct shrinker *shrinker)
{
#ifndef CONFIG_SHRINKER_DEBUG
 #ifndef HAVE_SHRINKER_ALLOC
	struct ll_shrinker *s = container_of(shrinker, struct ll_shrinker,
					     ll_shrinker);
 #else
	struct ll_shrinker *s = shrinker->private_data;
 #endif
#else /* !CONFIG_SHRINKER_DEBUG */
	struct shrinker *s = shrinker;
#endif /* CONFIG_SHRINKER_DEBUG */

	return s->debugfs_entry->d_name.name;
}

#ifndef HAVE_WB_STAT_MOD
#define wb_stat_mod(wb, item, amount)	__add_wb_stat(wb, item, amount)
#endif

#ifdef HAVE_SEC_RELEASE_SECCTX_1ARG
#ifndef HAVE_LSMCONTEXT_INIT
/* Ubuntu 5.19 */
static inline void lsmcontext_init(struct lsm_context *cp, char *context,
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
	struct lsm_context context = { };

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
#define vfs_mkdir(ns, dir, de, mode)		vfs_mkdir(dir, de, mode)
#define ll_set_acl(ns, inode, acl, type)	ll_set_acl(inode, acl, type)
#endif

#ifdef HAVE_RADIX_TREE_REPLACE_SLOT_3ARGS
# define radix_tree_rcu	__rcu
#else /* !HAVE_RADIX_TREE_REPLACE_SLOT_3ARGS */
# define radix_tree_rcu
#endif /* HAVE_RADIX_TREE_REPLACE_SLOT_3ARGS */

#endif /* _LUSTRE_COMPAT_H */
