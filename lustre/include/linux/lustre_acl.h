/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lustre/include/lustre_idmap.h
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_LINUX_ACL_H
#define _LUSTRE_LINUX_ACL_H

#ifndef	_LUSTRE_ACL_H
#error	Shoud not include direectly. use #include <lustre_acl.h> instead
#endif

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/dcache.h>
# ifdef CONFIG_FS_POSIX_ACL
#  ifdef HAVE_XATTR_ACL
#   include <linux/xattr_acl.h>
#  endif /* HAVE_XATTR_ACL */
#  ifdef HAVE_LINUX_POSIX_ACL_XATTR_H
#   include <linux/posix_acl_xattr.h>
#  endif /* HAVE_LINUX_POSIX_ACL_XATTR_H */
# endif /* CONFIG_FS_POSIX_ACL */
#include <linux/lustre_intent.h>
/* XATTR_{REPLACE,CREATE} */
#include <linux/xattr.h>
#endif /* __KERNEL__ */

/* ACL */
#ifdef CONFIG_FS_POSIX_ACL
# ifdef HAVE_XATTR_ACL
#  define MDS_XATTR_NAME_ACL_ACCESS XATTR_NAME_ACL_ACCESS
#  define mds_xattr_acl_size(entry) xattr_acl_size(entry)
# else /* HAVE_XATTR_ACL */
#  ifdef HAVE_LINUX_POSIX_ACL_XATTR_H
#   define MDS_XATTR_NAME_ACL_ACCESS POSIX_ACL_XATTR_ACCESS
#   define mds_xattr_acl_size(entry) posix_acl_xattr_size(entry)
#  endif /* HAVE_LINUX_POSIX_ACL_XATTR_H */
# endif /* HAVE_XATTR_ACL */

# define LUSTRE_POSIX_ACL_MAX_ENTRIES   (32)

#ifdef __KERNEL__
# define LUSTRE_POSIX_ACL_MAX_SIZE   XATTR_ACL_SIZE
#else
# define LUSTRE_POSIX_ACL_MAX_SIZE   0
#endif

# else /* CONFIG_FS_POSIX_ACL */
# define LUSTRE_POSIX_ACL_MAX_SIZE      0
# endif /* CONFIG_FS_POSIX_ACL */

#endif /* _LUSTRE_LINUX_ACL_H */
