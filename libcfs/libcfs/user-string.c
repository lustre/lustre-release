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
 * Copyright (c) 2014 Intel Corporation.
 */
#ifndef __KERNEL__

#include <string.h>

/*
 * According manual of strlcpy() and strlcat() the functions should return
 * the total length of the string they tried to create. For strlcpy() that
 * means the length of src. For strlcat() that means the initial length of
 * dst plus the length of src. So, the function strnlen() cannot be used
 * otherwise the return value will be wrong.
 */
#ifndef HAVE_STRLCPY /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dst, src, len);
		dst[len] = '\0';
	}
	return ret;
}
#endif

#ifndef HAVE_STRLCAT /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t dsize = strlen(dst);
	size_t len = strlen(src);
	size_t ret = dsize + len;

	dst  += dsize;
	size -= dsize;
	if (len >= size)
		len = size-1;
	memcpy(dst, src, len);
	dst[len] = '\0';
	return ret;
}
#endif

#endif /* __KERNEL__ */
