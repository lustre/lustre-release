/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_POSIX_ACL_XATTR_H__
#define __LIBCFS_LINUX_POSIX_ACL_XATTR_H__

#include_next <linux/posix_acl_xattr.h>

#ifndef HAVE_POSIX_ACL_TO_XATTR_ALLOC_BUFFER
static inline void *
compat_posix_acl_to_xattr(struct user_namespace *user_ns,
			  const struct posix_acl *acl,
			  size_t *sizep, gfp_t gfp)
{
	size_t acl_sz = posix_acl_xattr_size(acl->a_count);
	void *value = NULL;
	int rc;

	*sizep = acl_sz;
	if (acl_sz > 0)
		value = kmalloc(acl_sz, gfp);
	if (!value)
		return NULL;

	rc = posix_acl_to_xattr(user_ns, acl, value, acl_sz);
	if (rc < 0) {
		kfree(value);
		return NULL;
	}

	return value;
}
#define posix_acl_to_xattr(ns, acl, sz, gfp) \
	compat_posix_acl_to_xattr((ns), (acl), (sz), (gfp))
#endif

#endif /* __LIBCFS_LINUX_POSIX_ACL_XATTR_H__ */
