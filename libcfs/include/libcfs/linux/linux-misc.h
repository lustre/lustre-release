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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_LINUX_MISC_H__
#define __LIBCFS_LINUX_MISC_H__

#ifdef HAVE_SYSCTL_CTLNAME
#define INIT_CTL_NAME	.ctl_name = CTL_UNNUMBERED,
#define INIT_STRATEGY	.strategy = &sysctl_intvec,
#else
#define INIT_CTL_NAME
#define INIT_STRATEGY
#endif

#ifndef HAVE_KSTRTOUL
static inline int kstrtoul(const char *s, unsigned int base, unsigned long *res)
{
	char *end = (char *)s;

	*res = simple_strtoul(s, &end, base);
	if (end - s == 0)
		return -EINVAL;
	return 0;
}
#endif /* !HAVE_KSTRTOUL */

#endif
