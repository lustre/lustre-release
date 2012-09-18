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
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include "tracefile.h"

void libcfs_debug_dumpstack(cfs_task_t *tsk)
{
	return;
}

void libcfs_run_lbug_upcall(struct libcfs_debug_msg_data *msgdata)
{
}

void lbug_with_loc(struct libcfs_debug_msg_data *msgdata)
{
        libcfs_catastrophe = 1;
        CEMERG("LBUG: pid: %u thread: %#x\n",
	       (unsigned)cfs_curproc_pid(), (unsigned)current_thread());
        libcfs_debug_dumplog();
        libcfs_run_lbug_upcall(msgdata);
        while (1)
                cfs_schedule();

	/* panic("lbug_with_loc(%s, %s, %d)", file, func, line) */
}

#if ENTRY_NESTING_SUPPORT

static inline struct cfs_debug_data *__current_cdd(void)
{
	struct cfs_debug_data *cdd;

	cdd = (struct cfs_debug_data *)current_uthread()->uu_nlminfo;
	if (cdd != NULL &&
	    cdd->magic1 == CDD_MAGIC1 && cdd->magic2 == CDD_MAGIC2 &&
	    cdd->nesting_level < 1000)
		return cdd;
	else
		return NULL;
}

static inline void __current_cdd_set(struct cfs_debug_data *cdd)
{
	current_uthread()->uu_nlminfo = (void *)cdd;
}

void __entry_nesting(struct cfs_debug_data *child)
{
	struct cfs_debug_data *parent;

	parent = __current_cdd();
	if (parent != NULL) {
		child->parent        = parent;
		child->nesting_level = parent->nesting_level + 1;
	}
	__current_cdd_set(child);
}

void __exit_nesting(struct cfs_debug_data *child)
{
	__current_cdd_set(child->parent);
}

unsigned int __current_nesting_level(void)
{
	struct cfs_debug_data *cdd;

	cdd = __current_cdd();
	if (cdd != NULL)
		return cdd->nesting_level;
	else
		return 0;
}
/* ENTRY_NESTING_SUPPORT */
#endif
