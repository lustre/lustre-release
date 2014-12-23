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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/ctype.h>
#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <linux/utsname.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd_support.h>
#include <lprocfs_status.h>
#include <obd_class.h>

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *obd_table_header;
#endif

static int
proc_set_timeout(struct ctl_table *table, int write, void __user *buffer,
		 size_t *lenp, loff_t *ppos)
{
        int rc;

	rc = proc_dointvec(table, write, buffer, lenp, ppos);
        if (ldlm_timeout >= obd_timeout)
                ldlm_timeout = max(obd_timeout / 3, 1U);
        return rc;
}

static int
proc_memory_alloc(struct ctl_table *table, int write, void __user *buffer,
		  size_t *lenp, loff_t *ppos)
{
        char buf[22];
        int len;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_memory_sum());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
	if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

static int
proc_pages_alloc(struct ctl_table *table, int write, void __user *buffer,
		 size_t *lenp, loff_t *ppos)
{
        char buf[22];
        int len;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_pages_sum());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
	if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

static int
proc_mem_max(struct ctl_table *table, int write, void __user *buffer,
	     size_t *lenp, loff_t *ppos)
{
        char buf[22];
        int len;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_memory_max());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
	if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

static int
proc_pages_max(struct ctl_table *table, int write, void __user *buffer,
	       size_t *lenp, loff_t *ppos)
{
        char buf[22];
        int len;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_pages_max());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
	if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

static int
proc_max_dirty_pages_in_mb(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	__u64 val;
	int rc = 0;

	if (!table->data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}
	if (write) {
		rc = lprocfs_write_frac_u64_helper(buffer, *lenp, &val,
					       1 << (20 - PAGE_CACHE_SHIFT));

		/* Don't allow them to let dirty pages exceed 90% of system
		 * memory and set a hard minimum of 4MB. */
		if (val > ((totalram_pages / 10) * 9)) {
			CERROR("Refusing to set max dirty pages to "LPU64", "
			       "which is more than 90%% of available RAM; "
			       "setting to %lu\n", val,
			       ((totalram_pages / 10) * 9));
			obd_max_dirty_pages = ((totalram_pages / 10) * 9);
		} else if (val < 4 << (20 - PAGE_CACHE_SHIFT)) {
			obd_max_dirty_pages = 4 << (20 - PAGE_CACHE_SHIFT);
		} else {
			obd_max_dirty_pages = val;
		}
	} else {
		char buf[21];
		int len;

		len = lprocfs_read_frac_helper(buf, sizeof(buf),
					       *(unsigned long *)table->data,
					       1 << (20 - PAGE_CACHE_SHIFT));
		if (len > *lenp)
			len = *lenp;
		buf[len] = '\0';
		if (copy_to_user(buffer, buf, len))
			return -EFAULT;
		*lenp = len;
	}
	*ppos += *lenp;
	return rc;
}

#ifdef RANDOM_FAIL_ALLOC
static int proc_alloc_fail_rate(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
        int rc          = 0;

        if (!table->data || !table->maxlen || !*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write) {
                rc = lprocfs_write_frac_helper(buffer, *lenp,
                                               (unsigned int*)table->data,
                                               OBD_ALLOC_FAIL_MULT);
        } else {
                char buf[21];
                int  len;

                len = lprocfs_read_frac_helper(buf, 21,
                                               *(unsigned int*)table->data,
                                               OBD_ALLOC_FAIL_MULT);
                if (len > *lenp)
                        len = *lenp;
                buf[len] = '\0';
		if (copy_to_user(buffer, buf, len))
                        return -EFAULT;
                *lenp = len;
        }
        *ppos += *lenp;
        return rc;
}
#endif

#ifdef CONFIG_SYSCTL
static struct ctl_table obd_table[] = {
	{
		INIT_CTL_NAME
		.procname	= "timeout",
		.data		= &obd_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_set_timeout
	},
	{
		INIT_CTL_NAME
		.procname	= "debug_peer_on_timeout",
		.data		= &obd_debug_peer_on_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "dump_on_timeout",
		.data		= &obd_dump_on_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "dump_on_eviction",
		.data		= &obd_dump_on_eviction,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "memused",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0444,
		.proc_handler	= &proc_memory_alloc
	},
	{
		INIT_CTL_NAME
		.procname	= "pagesused",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0444,
		.proc_handler	= &proc_pages_alloc
	},
	{
		INIT_CTL_NAME
		.procname	= "memused_max",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0444,
		.proc_handler	= &proc_mem_max
	},
	{
		INIT_CTL_NAME
		.procname	= "pagesused_max",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0444,
		.proc_handler	= &proc_pages_max
	},
	{
		INIT_CTL_NAME
		.procname	= "ldlm_timeout",
		.data		= &ldlm_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_set_timeout
	},
#ifdef RANDOM_FAIL_ALLOC
	{
		INIT_CTL_NAME
		.procname	= "alloc_fail_rate",
		.data		= &obd_alloc_fail_rate,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_alloc_fail_rate
	},
#endif
	{
		INIT_CTL_NAME
		.procname	= "max_dirty_mb",
		.data		= &obd_max_dirty_pages,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_max_dirty_pages_in_mb
	},
	{
		INIT_CTL_NAME
		.procname	= "bulk_timeout",
		.data		= &bulk_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "at_min",
		.data		= &at_min,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "at_max",
		.data		= &at_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "at_extra",
		.data		= &at_extra,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "at_early_margin",
		.data		= &at_early_margin,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "at_history",
		.data		= &at_history,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ 0 }
};

static struct ctl_table parent_table[] = {
	{
		INIT_CTL_NAME
		.procname	= "lustre",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0555,
		.child		= obd_table
	},
	{ 0 }
};
#endif

void obd_sysctl_init (void)
{
#ifdef CONFIG_SYSCTL
	if ( !obd_table_header )
		obd_table_header = register_sysctl_table(parent_table);
#endif
}

void obd_sysctl_clean (void)
{
#ifdef CONFIG_SYSCTL
	if ( obd_table_header )
		unregister_sysctl_table(obd_table_header);
	obd_table_header = NULL;
#endif
}
