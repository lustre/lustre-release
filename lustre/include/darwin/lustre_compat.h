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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __DARWIN_LUSTRE_COMPAT_H__
#define __DARWIN_LUSTRE_COMPAT_H__

#include <libcfs/libcfs.h>

#ifdef __KERNEL__

#ifndef HLIST_HEAD
#define hlist_entry                     list_entry
#define hlist_head                      list_head
#define hlist_node                      list_head
#define hlist_del_init                  list_del_init
#define hlist_add_head                  list_add
#define hlist_for_each_safe             list_for_each_safe

/* XXX */
#define LOOKUP_COBD 			4096

#endif

struct module;
static inline int try_module_get(struct module *module)
{
	return 1;
}

static inline void module_put(struct module *module)
{
}

#define THIS_MODULE                     NULL

static inline void lustre_daemonize_helper(void)
{
	return;
}

static inline int32_t ext2_set_bit(int nr, void *a)
{
	int32_t	old = test_bit(nr, a);
	set_bit(nr, a);
	return old;
}

static inline int32_t ext2_clear_bit(int nr, void *a)
{
	int32_t old = test_bit(nr, a);
	clear_bit(nr, a);
	return old;
}

struct nameidata;

#if !defined(__DARWIN8__)
static inline int ll_path_lookup(const char *path, unsigned int flags, struct nameidata *nd)
{
	int ret = 0;
	NDINIT(nd, LOOKUP, FOLLOW, UIO_SYSSPACE, (char *)path, current_proc());
	if (ret = namei(nd)){
		CERROR("ll_path_lookup fail!\n");
	}
	return ret;
}
#endif

#define ext2_test_bit	test_bit

#endif	/* __KERNEL__ */

#endif
