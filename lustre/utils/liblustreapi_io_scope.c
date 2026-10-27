// SPDX-License-Identifier: LGPL-2.1+
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustreapi library for I/O scope
 */

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#include <lustre/lustreapi.h>
#include "lustreapi_internal.h"

/**
 * llapi_io_scope_set() - set I/O scope for @fd
 * @fd: file descriptor; non-FILE scopes need an O_DIRECT descriptor
 * @scope: I/O scope, see enum ll_io_scope
 *
 * A reserved scope returns -EOPNOTSUPP.
 *
 * Return:
 * * %0 on success.
 * * %-errno on failure.
 */
int llapi_io_scope_set(int fd, const struct ll_ioc_io_scope *scope)
{
	int rc;

	if (scope == NULL)
		return -EINVAL;

	rc = ioctl(fd, LL_IOC_SET_IO_SCOPE, scope);
	if (rc < 0)
		return -errno;
	return 0;
}

/**
 * llapi_io_scope_clear() - Clear the I/O scope for @fd
 * @fd: file descriptor
 *
 * Sets FILE scope via llapi_io_scope_set(), the same way
 * llapi_mirror_clear() passes id 0.
 *
 * Return:
 * * %0 on success.
 * * %-errno on failure.
 */
int llapi_io_scope_clear(int fd)
{
	struct ll_ioc_io_scope scope;

	memset(&scope, 0, sizeof(scope));
	return llapi_io_scope_set(fd, &scope);
}
