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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LUSTRE_HANDLES_H_
#define __LUSTRE_HANDLES_H_

/** \defgroup handles handles
 *
 * @{
 */

#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <libcfs/libcfs.h>

/* These handles are most easily used by having them appear at the very top of
 * whatever object that you want to make handles for.  ie:
 *
 * struct ldlm_lock {
 *         struct portals_handle handle;
 *         ...
 * };
 *
 * Now you're able to assign the results of cookie2handle directly to an
 * ldlm_lock.  If it's not at the top, you'll want to use container_of()
 * to compute the start of the structure based on the handle field. */
struct portals_handle {
	struct hlist_node		h_link;
	__u64				h_cookie;
	const char			*h_owner;
	refcount_t			h_ref;
	struct rcu_head			h_rcu;
};

/* handles.c */

/* Add a handle to the hash table */
void class_handle_hash(struct portals_handle *, const char *h_owner);
void class_handle_unhash(struct portals_handle *);
void *class_handle2object(u64 cookie, const char *h_owner);
int class_handle_init(void);
void class_handle_cleanup(void);

/** @} handles */

#endif
