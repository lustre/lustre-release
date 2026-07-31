/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __COMPAT_SECURITY_H
#define __COMPAT_SECURITY_H

#include <linux/security.h>

#ifdef CONFIG_SECURITY
int compat_security_file_alloc(struct file *file);
void compat_security_file_free(struct file *file);

#ifndef COMPAT_BUILD
#define security_file_alloc(file)	compat_security_file_alloc(file)
#define security_file_free(file)	compat_security_file_free(file)
#endif

#endif

#ifndef XATTR_SELINUX_SUFFIX
# define XATTR_SELINUX_SUFFIX "selinux"
#endif

#ifndef XATTR_NAME_SELINUX
# define XATTR_NAME_SELINUX XATTR_SECURITY_PREFIX XATTR_SELINUX_SUFFIX
#endif

#ifdef HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX
#define HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG 1
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

#ifndef HAVE_SECURITY_INODE_LISTSECURITY_PTR_ARGS
/*
 * Linux commit v7.1-rc1-1-gf71ece9712b7 changed security_inode_listsecurity()
 * to update the buffer pointer and remaining size in place and to return
 * 0 or -errno instead of the copied length. A NULL buffer still requests
 * the needed size, subtracted from the remaining size.
 */
static inline int
compat_security_inode_listsecurity(struct inode *inode, char **buffer,
				   ssize_t *remaining_size)
{
	int len;

	len = security_inode_listsecurity(inode, *buffer,
					  *buffer ? *remaining_size : 0);
	if (len < 0)
		return len;
	if (*buffer) {
		if (len > *remaining_size)
			return -ERANGE;
		*buffer += len;
	}
	*remaining_size -= len;
	return 0;
}
#define security_inode_listsecurity compat_security_inode_listsecurity
#endif /* !HAVE_SECURITY_INODE_LISTSECURITY_PTR_ARGS */

#endif /* __COMPAT_SECURITY_H */
