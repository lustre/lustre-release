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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <linux/uio.h>
#include <linux/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>

#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <asm/div64.h>

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <libcfs/libcfs_crypto.h>
#include <lnet/lib-lnet.h>
#include "tracefile.h"

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *lnet_table_header;
#endif

static DECLARE_RWSEM(ioctl_list_sem);
static LIST_HEAD(ioctl_list);

int libcfs_register_ioctl(struct libcfs_ioctl_handler *hand)
{
	int rc = 0;

	down_write(&ioctl_list_sem);
	if (!list_empty(&hand->item))
		rc = -EBUSY;
	else
		list_add_tail(&hand->item, &ioctl_list);
	up_write(&ioctl_list_sem);

	return rc;
}
EXPORT_SYMBOL(libcfs_register_ioctl);

int libcfs_deregister_ioctl(struct libcfs_ioctl_handler *hand)
{
	int rc = 0;

	down_write(&ioctl_list_sem);
	if (list_empty(&hand->item))
		rc = -ENOENT;
	else
		list_del_init(&hand->item);
	up_write(&ioctl_list_sem);

	return rc;
}
EXPORT_SYMBOL(libcfs_deregister_ioctl);

int libcfs_ioctl(unsigned long cmd, void __user *uparam)
{
	struct libcfs_ioctl_data *data = NULL;
	struct libcfs_ioctl_hdr  *hdr;
	int			  err;
	ENTRY;

	/* 'cmd' and permissions get checked in our arch-specific caller */
	err = libcfs_ioctl_getdata(&hdr, uparam);
	if (err != 0) {
		CDEBUG_LIMIT(D_ERROR,
			     "libcfs ioctl: data header error %d\n", err);
		RETURN(err);
	}

	if (hdr->ioc_version == LIBCFS_IOCTL_VERSION) {
		/* The libcfs_ioctl_data_adjust() function performs adjustment
		 * operations on the libcfs_ioctl_data structure to make
		 * it usable by the code.  This doesn't need to be called
		 * for new data structures added. */
		data = container_of(hdr, struct libcfs_ioctl_data, ioc_hdr);
		err = libcfs_ioctl_data_adjust(data);
		if (err != 0)
			GOTO(out, err);
	}

	CDEBUG(D_IOCTL, "libcfs ioctl cmd %lu\n", cmd);
	switch (cmd) {
	case IOC_LIBCFS_CLEAR_DEBUG:
		libcfs_debug_clear_buffer();
		break;
	case IOC_LIBCFS_MARK_DEBUG:
		if (data == NULL ||
		    data->ioc_inlbuf1 == NULL ||
		    data->ioc_inlbuf1[data->ioc_inllen1 - 1] != '\0')
			GOTO(out, err = -EINVAL);

		libcfs_debug_mark_buffer(data->ioc_inlbuf1);
		break;

	default: {
		struct libcfs_ioctl_handler *hand;

		err = -EINVAL;
		down_read(&ioctl_list_sem);
		list_for_each_entry(hand, &ioctl_list, item) {
			err = hand->handle_ioctl(cmd, hdr);
			if (err == -EINVAL)
				continue;

			if (err == 0) {
				if (copy_to_user(uparam, hdr, hdr->ioc_len))
					err = -EFAULT;
			}
			break;
		}
		up_read(&ioctl_list_sem);
		break; }
	}
out:
	LIBCFS_FREE(hdr, hdr->ioc_len);
	RETURN(err);
}

int
lprocfs_call_handler(void *data, int write, loff_t *ppos,
		     void __user *buffer, size_t *lenp,
		     int (*handler)(void *data, int write, loff_t pos,
				    void __user *buffer, int len))
{
	int rc = handler(data, write, *ppos, buffer, *lenp);

	if (rc < 0)
		return rc;

	if (write) {
		*ppos += *lenp;
	} else {
		*lenp = rc;
		*ppos += rc;
	}
	return 0;
}
EXPORT_SYMBOL(lprocfs_call_handler);

static int __proc_dobitmasks(void *data, int write,
			     loff_t pos, void __user *buffer, int nob)
{
	const int     tmpstrlen = 512;
	char         *tmpstr;
	int           rc;
	unsigned int *mask = data;
	int           is_subsys = (mask == &libcfs_subsystem_debug) ? 1 : 0;
	int           is_printk = (mask == &libcfs_printk) ? 1 : 0;

	rc = cfs_trace_allocate_string_buffer(&tmpstr, tmpstrlen);
	if (rc < 0)
		return rc;

	if (!write) {
		libcfs_debug_mask2str(tmpstr, tmpstrlen, *mask, is_subsys);
		rc = strlen(tmpstr);

		if (pos >= rc) {
			rc = 0;
		} else {
			rc = cfs_trace_copyout_string(buffer, nob,
						      tmpstr + pos, "\n");
		}
	} else {
		rc = cfs_trace_copyin_string(tmpstr, tmpstrlen, buffer, nob);
		if (rc < 0) {
			kfree(tmpstr);
			return rc;
		}

		rc = libcfs_debug_str2mask(mask, tmpstr, is_subsys);
		/* Always print LBUG/LASSERT to console, so keep this mask */
		if (is_printk)
			*mask |= D_EMERG;
	}

	kfree(tmpstr);
	return rc;
}

static int
proc_dobitmasks(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return lprocfs_call_handler(table->data, write, ppos, buffer, lenp,
				    __proc_dobitmasks);
}

static int min_watchdog_ratelimit;		/* disable ratelimiting */
static int max_watchdog_ratelimit = (24*60*60); /* limit to once per day */

static int __proc_dump_kernel(void *data, int write,
			      loff_t pos, void __user *buffer, int nob)
{
	if (!write)
		return 0;

	return cfs_trace_dump_debug_buffer_usrstr(buffer, nob);
}

static int
proc_dump_kernel(struct ctl_table *table, int write, void __user *buffer,
		 size_t *lenp, loff_t *ppos)
{
	return lprocfs_call_handler(table->data, write, ppos, buffer, lenp,
				    __proc_dump_kernel);
}

static int __proc_daemon_file(void *data, int write,
			      loff_t pos, void __user *buffer, int nob)
{
	if (!write) {
		int len = strlen(cfs_tracefile);

		if (pos >= len)
			return 0;

		return cfs_trace_copyout_string(buffer, nob,
						cfs_tracefile + pos, "\n");
	}

	return cfs_trace_daemon_command_usrstr(buffer, nob);
}

static int
proc_daemon_file(struct ctl_table *table, int write, void __user *buffer,
		 size_t *lenp, loff_t *ppos)
{
	return lprocfs_call_handler(table->data, write, ppos, buffer, lenp,
				    __proc_daemon_file);
}

static int __proc_debug_mb(void *data, int write,
			   loff_t pos, void __user *buffer, int nob)
{
	if (!write) {
		char tmpstr[32];
		int  len = snprintf(tmpstr, sizeof(tmpstr), "%d",
				    cfs_trace_get_debug_mb());

		if (pos >= len)
			return 0;

		return cfs_trace_copyout_string(buffer, nob, tmpstr + pos,
						"\n");
	}

	return cfs_trace_set_debug_mb_usrstr(buffer, nob);
}

static int
proc_debug_mb(struct ctl_table *table, int write, void __user *buffer,
	      size_t *lenp, loff_t *ppos)
{
	return lprocfs_call_handler(table->data, write, ppos, buffer, lenp,
				    __proc_debug_mb);
}

static int
proc_console_max_delay_cs(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int rc, max_delay_cs;
	struct ctl_table dummy = *table;
	cfs_duration_t d;

	dummy.data = &max_delay_cs;
	dummy.proc_handler = &proc_dointvec;

	if (!write) { /* read */
		max_delay_cs = cfs_duration_sec(libcfs_console_max_delay * 100);
		rc = proc_dointvec(&dummy, write, buffer, lenp, ppos);
		return rc;
	}

	/* write */
	max_delay_cs = 0;
	rc = proc_dointvec(&dummy, write, buffer, lenp, ppos);
	if (rc < 0)
		return rc;
	if (max_delay_cs <= 0)
		return -EINVAL;

	d = cfs_time_seconds(max_delay_cs) / 100;
	if (d == 0 || d < libcfs_console_min_delay)
		return -EINVAL;
	libcfs_console_max_delay = d;

	return rc;
}

static int
proc_console_min_delay_cs(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int rc, min_delay_cs;
	struct ctl_table dummy = *table;
	cfs_duration_t d;

	dummy.data = &min_delay_cs;
	dummy.proc_handler = &proc_dointvec;

	if (!write) { /* read */
		min_delay_cs = cfs_duration_sec(libcfs_console_min_delay * 100);
		rc = proc_dointvec(&dummy, write, buffer, lenp, ppos);
		return rc;
	}

	/* write */
	min_delay_cs = 0;
	rc = proc_dointvec(&dummy, write, buffer, lenp, ppos);
	if (rc < 0)
		return rc;
	if (min_delay_cs <= 0)
		return -EINVAL;

	d = cfs_time_seconds(min_delay_cs) / 100;
	if (d == 0 || d > libcfs_console_max_delay)
		return -EINVAL;
	libcfs_console_min_delay = d;

	return rc;
}

static int
proc_console_backoff(struct ctl_table *table, int write, void __user *buffer,
		     size_t *lenp, loff_t *ppos)
{
	int rc, backoff;
	struct ctl_table dummy = *table;

	dummy.data = &backoff;
	dummy.proc_handler = &proc_dointvec;

	if (!write) { /* read */
		backoff = libcfs_console_backoff;
		rc = proc_dointvec(&dummy, write, buffer, lenp, ppos);
		return rc;
	}

	/* write */
	backoff = 0;
	rc = proc_dointvec(&dummy, write, buffer, lenp, ppos);
	if (rc < 0)
		return rc;

	if (backoff <= 0)
		return -EINVAL;

	libcfs_console_backoff = backoff;

	return rc;
}

static int
libcfs_force_lbug(struct ctl_table *table, int write, void __user *buffer,
		  size_t *lenp, loff_t *ppos)
{
	if (write)
		LBUG();
	return 0;
}

static int
proc_fail_loc(struct ctl_table *table, int write, void __user *buffer,
	      size_t *lenp, loff_t *ppos)
{
	int rc;
	long old_fail_loc = cfs_fail_loc;

	rc = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (old_fail_loc != cfs_fail_loc)
		wake_up(&cfs_race_waitq);
	return rc;
}

static int __proc_cpt_table(void *data, int write,
			    loff_t pos, void __user *buffer, int nob)
{
	char *buf = NULL;
	int   len = 4096;
	int   rc  = 0;

	if (write)
		return -EPERM;

	LASSERT(cfs_cpt_table != NULL);

	while (1) {
		LIBCFS_ALLOC(buf, len);
		if (buf == NULL)
			return -ENOMEM;

		rc = cfs_cpt_table_print(cfs_cpt_table, buf, len);
		if (rc >= 0)
			break;

		if (rc == -EFBIG) {
			LIBCFS_FREE(buf, len);
			len <<= 1;
			continue;
		}
		goto out;
	}

	if (pos >= rc) {
		rc = 0;
		goto out;
	}

	rc = cfs_trace_copyout_string(buffer, nob, buf + pos, NULL);
out:
	if (buf != NULL)
		LIBCFS_FREE(buf, len);
	return rc;
}

static int
proc_cpt_table(struct ctl_table *table, int write, void __user *buffer,
	       size_t *lenp, loff_t *ppos)
{
	return lprocfs_call_handler(table->data, write, ppos, buffer, lenp,
				    __proc_cpt_table);
}

static int __proc_cpt_distance(void *data, int write,
			       loff_t pos, void __user *buffer, int nob)
{
	char *buf = NULL;
	int   len = 4096;
	int   rc  = 0;

	if (write)
		return -EPERM;

	LASSERT(cfs_cpt_table != NULL);

	while (1) {
		LIBCFS_ALLOC(buf, len);
		if (buf == NULL)
			return -ENOMEM;

		rc = cfs_cpt_distance_print(cfs_cpt_table, buf, len);
		if (rc >= 0)
			break;

		if (rc == -EFBIG) {
			LIBCFS_FREE(buf, len);
			len <<= 1;
			continue;
		}
		goto out;
	}

	if (pos >= rc) {
		rc = 0;
		goto out;
	}

	rc = cfs_trace_copyout_string(buffer, nob, buf + pos, NULL);
 out:
	if (buf != NULL)
		LIBCFS_FREE(buf, len);
	return rc;
}

static int
proc_cpt_distance(struct ctl_table *table, int write, void __user *buffer,
	       size_t *lenp, loff_t *ppos)
{
	return lprocfs_call_handler(table->data, write, ppos, buffer, lenp,
				     __proc_cpt_distance);
}

static struct ctl_table lnet_table[] = {
	/*
	 * NB No .strategy entries have been provided since sysctl(8) prefers
	 * to go via /proc for portability.
	 */
	{
		INIT_CTL_NAME
		.procname	= "debug",
		.data		= &libcfs_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dobitmasks,
	},
	{
		INIT_CTL_NAME
		.procname	= "subsystem_debug",
		.data		= &libcfs_subsystem_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dobitmasks,
	},
	{
		INIT_CTL_NAME
		.procname	= "printk",
		.data		= &libcfs_printk,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dobitmasks,
	},
	{
		INIT_CTL_NAME
		.procname	= "console_ratelimit",
		.data		= &libcfs_console_ratelimit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "console_max_delay_centisecs",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_console_max_delay_cs
	},
	{
		INIT_CTL_NAME
		.procname	= "console_min_delay_centisecs",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_console_min_delay_cs
	},
	{
		INIT_CTL_NAME
		.procname	= "console_backoff",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_console_backoff
	},
	{
		INIT_CTL_NAME
		.procname	= "debug_path",
		.data		= libcfs_debug_file_path_arr,
		.maxlen		= sizeof(libcfs_debug_file_path_arr),
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
	},
	{
		INIT_CTL_NAME
		.procname	= "cpu_partition_table",
		.maxlen		= 128,
		.mode		= 0444,
		.proc_handler	= &proc_cpt_table,
	},
	{
		INIT_CTL_NAME
		.procname	= "cpu_partition_distance",
		.maxlen		= 128,
		.mode		= 0444,
		.proc_handler	= &proc_cpt_distance,
	},
	{
		INIT_CTL_NAME
		.procname	= "debug_log_upcall",
		.data		= lnet_debug_log_upcall,
		.maxlen		= sizeof(lnet_debug_log_upcall),
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
	},
	{
		INIT_CTL_NAME
		.procname	= "lnet_memused",
		.data		= (int *)&libcfs_kmemory.counter,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
	},
	{
		INIT_CTL_NAME
		.procname	= "catastrophe",
		.data		= &libcfs_catastrophe,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
	},
	{
		INIT_CTL_NAME
		.procname	= "panic_on_lbug",
		.data		= &libcfs_panic_on_lbug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		INIT_CTL_NAME
		.procname	= "dump_kernel",
		.maxlen		= 256,
		.mode		= 0200,
		.proc_handler	= &proc_dump_kernel,
	},
	{
		INIT_CTL_NAME
		.procname	= "daemon_file",
		.mode		= 0644,
		.maxlen		= 256,
		.proc_handler	= &proc_daemon_file,
	},
	{
		INIT_CTL_NAME
		.procname	= "debug_mb",
		.mode		= 0644,
		.proc_handler	= &proc_debug_mb,
	},
	{
		INIT_CTL_NAME
		.procname	= "watchdog_ratelimit",
		.data		= &libcfs_watchdog_ratelimit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= &min_watchdog_ratelimit,
		.extra2		= &max_watchdog_ratelimit,
	},
	{
		INIT_CTL_NAME
		.procname	= "force_lbug",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0200,
		.proc_handler	= &libcfs_force_lbug
	},
	{
		INIT_CTL_NAME
		.procname	= "fail_loc",
		.data		= &cfs_fail_loc,
		.maxlen		= sizeof(cfs_fail_loc),
		.mode		= 0644,
		.proc_handler	= &proc_fail_loc
	},
	{
		INIT_CTL_NAME
		.procname	= "fail_val",
		.data		= &cfs_fail_val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "fail_err",
		.data		= &cfs_fail_err,
		.maxlen		= sizeof(cfs_fail_err),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
	}
};

#ifdef CONFIG_SYSCTL
static struct ctl_table top_table[] = {
	{
		INIT_CTL_NAME
		.procname       = "lnet",
		.mode           = 0555,
		.data           = NULL,
		.maxlen         = 0,
		.child          = lnet_table,
	},
	{ 0 }
};
#endif

static int insert_proc(void)
{
#ifdef CONFIG_SYSCTL
	if (lnet_table_header == NULL)
		lnet_table_header = register_sysctl_table(top_table);
#endif
	return 0;
}

static void remove_proc(void)
{
#ifdef CONFIG_SYSCTL
	if (lnet_table_header != NULL)
		unregister_sysctl_table(lnet_table_header);

	lnet_table_header = NULL;
#endif
}

static int __init libcfs_init(void)
{
	int rc;

	rc = libcfs_debug_init(5 * 1024 * 1024);
	if (rc < 0) {
		printk(KERN_ERR "LustreError: libcfs_debug_init: %d\n", rc);
		return (rc);
	}

	rc = cfs_cpu_init();
	if (rc != 0)
		goto cleanup_debug;

	rc = misc_register(&libcfs_dev);
	if (rc) {
		CERROR("misc_register: error %d\n", rc);
		goto cleanup_cpu;
	}

	rc = cfs_wi_startup();
	if (rc) {
		CERROR("initialize workitem: error %d\n", rc);
		goto cleanup_deregister;
	}

	/* max to 4 threads, should be enough for rehash */
	rc = min(cfs_cpt_weight(cfs_cpt_table, CFS_CPT_ANY), 4);
	rc = cfs_wi_sched_create("cfs_rh", cfs_cpt_table, CFS_CPT_ANY,
				 rc, &cfs_sched_rehash);
	if (rc != 0) {
		CERROR("Startup workitem scheduler: error: %d\n", rc);
		goto cleanup_deregister;
	}

	rc = cfs_crypto_register();
	if (rc) {
		CERROR("cfs_crypto_regster: error %d\n", rc);
		goto cleanup_wi;
	}


	rc = insert_proc();
	if (rc) {
		CERROR("insert_proc: error %d\n", rc);
		goto cleanup_crypto;
	}

	CDEBUG (D_OTHER, "portals setup OK\n");
	return 0;
cleanup_crypto:
	cfs_crypto_unregister();
cleanup_wi:
	cfs_wi_shutdown();
cleanup_deregister:
	misc_deregister(&libcfs_dev);
cleanup_cpu:
	cfs_cpu_fini();
cleanup_debug:
	libcfs_debug_cleanup();
	return rc;
}

static void __exit libcfs_exit(void)
{
	int rc;

	remove_proc();

	CDEBUG(D_MALLOC, "before Portals cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

	if (cfs_sched_rehash != NULL) {
		cfs_wi_sched_destroy(cfs_sched_rehash);
		cfs_sched_rehash = NULL;
	}

	cfs_crypto_unregister();
	cfs_wi_shutdown();

	misc_deregister(&libcfs_dev);

	cfs_cpu_fini();

	if (atomic_read(&libcfs_kmemory) != 0)
		CERROR("Portals memory leaked: %d bytes\n",
		       atomic_read(&libcfs_kmemory));

	rc = libcfs_debug_cleanup();
	if (rc)
		printk(KERN_ERR "LustreError: libcfs_debug_cleanup: %d\n",
		       rc);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre helper library");
MODULE_VERSION(LIBCFS_VERSION);
MODULE_LICENSE("GPL");

module_init(libcfs_init);
module_exit(libcfs_exit);
