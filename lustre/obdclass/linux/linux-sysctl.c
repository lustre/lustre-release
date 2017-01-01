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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
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

struct static_lustre_uintvalue_attr {
	struct {
		struct attribute attr;
		ssize_t (*show)(struct kobject *kobj, struct attribute *attr,
				char *buf);
		ssize_t (*store)(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t len);
	} u;
	int *value;
};

static ssize_t static_uintvalue_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct static_lustre_uintvalue_attr *lattr = (void *)attr;

	return sprintf(buf, "%d\n", *lattr->value);
}

static ssize_t static_uintvalue_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	struct static_lustre_uintvalue_attr *lattr  = (void *)attr;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	*lattr->value = val;

	return count;
}

#define LUSTRE_STATIC_UINT_ATTR(name, value) \
static struct static_lustre_uintvalue_attr lustre_sattr_##name =	\
					{__ATTR(name, 0644,		\
						static_uintvalue_show,	\
						static_uintvalue_store),\
						value }

LUSTRE_STATIC_UINT_ATTR(timeout, &obd_timeout);

#ifdef CONFIG_SYSCTL
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

	len = snprintf(buf, sizeof(buf), "%llu\n", obd_memory_sum());
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

	len = snprintf(buf, sizeof(buf), "%llu\n", obd_memory_max());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
	if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}
#endif /* CONFIG_SYSCTL */

static ssize_t max_dirty_mb_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	return sprintf(buf, "%lu\n",
		       obd_max_dirty_pages / (1 << (20 - PAGE_SHIFT)));
}

static ssize_t max_dirty_mb_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 10, &val);
	if (rc)
		return rc;

	val *= 1 << (20 - PAGE_SHIFT); /* convert to pages */

	if (val > ((totalram_pages / 10) * 9)) {
		/* Somebody wants to assign too much memory to dirty pages */
		return -EINVAL;
	}

	if (val < 4 << (20 - PAGE_SHIFT)) {
		/* Less than 4 Mb for dirty cache is also bad */
		return -EINVAL;
	}

	obd_max_dirty_pages = val;

	return count;
}
LUSTRE_RW_ATTR(max_dirty_mb);

LUSTRE_STATIC_UINT_ATTR(debug_peer_on_timeout, &obd_debug_peer_on_timeout);
LUSTRE_STATIC_UINT_ATTR(dump_on_timeout, &obd_dump_on_timeout);
LUSTRE_STATIC_UINT_ATTR(dump_on_eviction, &obd_dump_on_eviction);
LUSTRE_STATIC_UINT_ATTR(at_min, &at_min);
LUSTRE_STATIC_UINT_ATTR(at_max, &at_max);
LUSTRE_STATIC_UINT_ATTR(at_extra, &at_extra);
LUSTRE_STATIC_UINT_ATTR(at_early_margin, &at_early_margin);
LUSTRE_STATIC_UINT_ATTR(at_history, &at_history);

#ifdef HAVE_SERVER_SUPPORT
LUSTRE_STATIC_UINT_ATTR(ldlm_timeout, &ldlm_timeout);
#endif

#ifdef CONFIG_SYSCTL
static struct ctl_table obd_table[] = {
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
		.procname	= "memused_max",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0444,
		.proc_handler	= &proc_mem_max
	},
	{
		INIT_CTL_NAME
		.procname	= "bulk_timeout",
		.data		= &bulk_timeout,
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

static struct attribute *lustre_attrs[] = {
	&lustre_sattr_timeout.u.attr,
	&lustre_attr_max_dirty_mb.attr,
	&lustre_sattr_debug_peer_on_timeout.u.attr,
	&lustre_sattr_dump_on_timeout.u.attr,
	&lustre_sattr_dump_on_eviction.u.attr,
	&lustre_sattr_at_min.u.attr,
	&lustre_sattr_at_max.u.attr,
	&lustre_sattr_at_extra.u.attr,
	&lustre_sattr_at_early_margin.u.attr,
	&lustre_sattr_at_history.u.attr,
#ifdef HAVE_SERVER_SUPPORT
	&lustre_sattr_ldlm_timeout.u.attr,
#endif
	NULL,
};

static struct attribute_group lustre_attr_group = {
	.attrs = lustre_attrs,
};

int obd_sysctl_init(void)
{
#ifdef CONFIG_SYSCTL
	if ( !obd_table_header )
		obd_table_header = register_sysctl_table(parent_table);
#endif
	return sysfs_create_group(lustre_kobj, &lustre_attr_group);
}

void obd_sysctl_clean (void)
{
#ifdef CONFIG_SYSCTL
	if ( obd_table_header )
		unregister_sysctl_table(obd_table_header);
	obd_table_header = NULL;
#endif
}
