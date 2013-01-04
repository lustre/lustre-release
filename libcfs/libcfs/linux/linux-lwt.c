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
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

#ifdef HAVE_LINUX_OOM_H
#include <linux/oom.h>
#else
#include <linux/mm.h>
#endif

int oom_get_adj(struct task_struct *task, int scope)
{
	int oom_adj;
#ifdef HAVE_OOMADJ_IN_SIG
	unsigned long flags;

	spin_lock_irqsave(&task->sighand->siglock, flags);
	oom_adj = task->signal->oom_adj;
	task->signal->oom_adj = scope;
	spin_unlock_irqrestore(&task->sighand->siglock, flags);

#else
	oom_adj = task->oomkilladj;
	task->oomkilladj = scope;
#endif
	return oom_adj;
}

int cfs_create_thread(int (*fn)(void *),
                      void *arg, unsigned long flags)
{
        void *orig_info = current->journal_info;
        int rc;
        int old_oom;

        old_oom = oom_get_adj(current, OOM_DISABLE);
        current->journal_info = NULL;
        rc = kernel_thread(fn, arg, flags);
        current->journal_info = orig_info;
        oom_get_adj(current, old_oom);

        return rc;
}
EXPORT_SYMBOL(cfs_create_thread);
