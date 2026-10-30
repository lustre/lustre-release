/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic library routines.
 */

#ifndef __LUSTRE_COMPAT_LINUX_XATTR_H__
#define __LUSTRE_COMPAT_LINUX_XATTR_H__

#include_next <linux/xattr.h>

#ifndef HAVE_USER_NAMESPACE_ARG
#define ll_xattr_set_common(hd, ns, de, inode, name, value, size, flags) \
	ll_xattr_set_common(hd, de, inode, name, value, size, flags)

#define ll_xattr_set(hd, ns, de, inode, name, value, size, flags) \
	ll_xattr_set(hd, de, inode, name, value, size, flags)
#endif

static inline int ll_vfs_setxattr(struct dentry *dentry, struct inode *inode,
				  const char *name,
				  const void *value, size_t size, int flags)
{
#if defined(HAVE_MNT_IDMAP_ARG)
	return __vfs_setxattr(&nop_mnt_idmap, dentry, inode, name,
			      VFS_SETXATTR_VALUE(value), size, flags);
#elif defined(HAVE_USER_NAMESPACE_ARG)
	return __vfs_setxattr(&init_user_ns, dentry, inode, name,
			      VFS_SETXATTR_VALUE(value), size, flags);
#else
	return __vfs_setxattr(dentry, inode, name, value, size, flags);
#endif
}

static inline int ll_vfs_removexattr(struct dentry *dentry, struct inode *inode,
				     const char *name)
{
#if defined(HAVE_MNT_IDMAP_ARG)
	return __vfs_removexattr(&nop_mnt_idmap, dentry, name);
#elif defined(HAVE_USER_NAMESPACE_ARG)
	return __vfs_removexattr(&init_user_ns, dentry, name);
#else
	return __vfs_removexattr(dentry, name);
#endif
}

#endif /* __LUSTRE_COMPAT_LINUX_XATTR_H__ */
