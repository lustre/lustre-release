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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_DARWIN_INTERNAL_H__
#define __LIBCFS_DARWIN_INTERNAL_H__

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

int cfs_sysctl_isvalid(void);
struct sysctl_oid *cfs_alloc_sysctl_node(struct sysctl_oid_list *parent, int nbr, int access,
		                         const char *name, int (*handler) SYSCTL_HANDLER_ARGS);
struct sysctl_oid *cfs_alloc_sysctl_int(struct sysctl_oid_list *parent, int n,
					const char *name, int *ptr, int val);
struct sysctl_oid * cfs_alloc_sysctl_long(struct sysctl_oid_list *parent, int nbr, int access,
		                          const char *name, int *ptr, int val);
struct sysctl_oid * cfs_alloc_sysctl_string(struct sysctl_oid_list *parent, int nbr, int access,
		                            const char *name, char *ptr, int len);
struct sysctl_oid * cfs_alloc_sysctl_struct(struct sysctl_oid_list *parent, int nbr, int access,
		                            const char *name, void *ptr, int size);

#endif
