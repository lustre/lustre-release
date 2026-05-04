/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_FS_H__
#define __LIBCFS_LINUX_CFS_FS_H__

#include <linux/fs.h>
#include <linux/dcache.h>

#ifndef HAVE_D_MAKE_PERSISTENT
/*
 * Linux commit v6.18-rc5-9-gbacdf1d70bbe2 introduced d_make_persistent() and
 * d_make_discardable() so that filesystems can mark dentries as pinned without
 * leaking unbalanced dget()s. On older kernels we fall back to the equivalent
 * open-coded sequence: d_instantiate() (or d_add() for unhashed dentries) plus
 * an extra dget() to pin, and a matching dput() to unpin. Older kernels still
 * have kill_litter_super() available, which uses d_genocide() to drop these
 * extra references at unmount.
 */
static inline struct dentry *d_make_persistent(struct dentry *dentry,
					       struct inode *inode)
{
	if (d_unhashed(dentry))
		d_add(dentry, inode);
	else
		d_instantiate(dentry, inode);
	dget(dentry);
	return dentry;
}

static inline void d_make_discardable(struct dentry *dentry)
{
	dput(dentry);
}
#endif /* !HAVE_D_MAKE_PERSISTENT */

#ifndef S_DT_SHIFT
#define S_DT_SHIFT		12
#endif

#ifndef S_DT
#define S_DT(type)		(((type) & S_IFMT) >> S_DT_SHIFT)
#endif
#ifndef DTTOIF
#define DTTOIF(dirtype)		((dirtype) << S_DT_SHIFT)
#endif

#ifndef SB_I_CGROUPWB
#define SB_I_CGROUPWB   0
#endif

/* Really belongs in mnt_idmapping.h but it doesn't exist for
 * older kernels. mnt_idmapping.h is always included with fs.h.
 */
#ifndef HAVE_MNT_IDMAP_ARG
#define mnt_idmap       user_namespace
#define nop_mnt_idmap   init_user_ns
#endif

#if !defined(HAVE_VFS_CREATE_DELEGATE)
#if !defined(HAVE_USER_NAMESPACE_ARG) && !defined(HAVE_MNT_IDMAP_ARG)
#define vfs_create(ns, de, mode, di)	\
	vfs_create(d_inode((de)->d_parent), (de), (mode), !!(di))
#else
#define vfs_create(ns, de, mode, di) \
	vfs_create((ns), d_inode((de)->d_parent), (de), (mode), !!(di))
#endif
#endif /* HAVE_VFS_CREATE_DELEGATE */

#ifdef HAVE_VFS_MKDIR_DELEGATE
#define VFS_MKDIR_DELEGATE(id, inode, dentry, mode) \
	vfs_mkdir((id), (inode), (dentry), (mode), NULL)
#else
#define VFS_MKDIR_DELEGATE(id, inode, dentry, mode) \
	vfs_mkdir((id), (inode), (dentry), (mode))
#endif /* HAVE_VFS_MKDIR_DELEGATE */

#ifdef HAVE_IOPS_MKDIR_RETURNS_DENTRY
#define ll_vfs_mkdir(id, inode, dentry, mode)	\
	VFS_MKDIR_DELEGATE((id), (inode), (dentry), (mode))
#else
#define ll_vfs_mkdir(i, inode, dentry, mode) ({				\
	int rc = VFS_MKDIR_DELEGATE((i), (inode), (dentry), (mode));	\
	if (rc) {							\
		dput((dentry));						\
		dentry = ERR_PTR(rc);					\
	}								\
	(dentry);							\
})
#endif /* HAVE_IOPS_MKDIR_RETURNS_DENTRY */

#ifndef ATTR_CTIME_SET /* added in v6.17-rc7-14-gafc5b36e29 */
#define ATTR_CTIME_SET (1 << 28) /* safe for at least v4.18..v6.17 */
#endif

static inline int ll_vfs_getattr(struct path *path, struct kstat *st,
				 u32 request_mask, unsigned int flags)
{
#ifdef AT_GETATTR_NOSEC /* added in v6.7-rc1-1-g8a924db2d7b5 */
	if (flags & AT_GETATTR_NOSEC)
		return vfs_getattr_nosec(path, st, request_mask, flags);
#endif /* AT_GETATTR_NOSEC */

	return vfs_getattr(path, st, request_mask, flags);
}

#ifndef HAVE_INODE_JUST_DROP
static inline int inode_just_drop(struct inode *inode)
{
	return generic_delete_inode(inode);
}

static inline int inode_generic_drop(struct inode *inode)
{
	return generic_drop_inode(inode);
}
#endif

#ifndef HAVE_ILOOKUP5_NOWAIT_ISNEW
#define ilookup5_nowait(sb, hash, fn, data, isnew) \
	ilookup5_nowait((sb), (hash), (fn), (data))
#endif

#endif /* __LIBCFS_LINUX_CFS_FS_H__ */
