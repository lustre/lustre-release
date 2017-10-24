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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/linux/linux-module.c
 *
 * Object Devices Class Driver
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <asm/ioctls.h>
#include <asm/poll.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/seq_file.h>
#include <linux/kobject.h>

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lnet/lnetctl.h>
#include <lprocfs_status.h>
#include <uapi/linux/lustre_ioctl.h>
#include <lustre_ver.h>

static int obd_ioctl_is_invalid(struct obd_ioctl_data *data)
{
	if (data->ioc_len > BIT(30)) {
		CERROR("OBD ioctl: ioc_len larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen1 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen1 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen2 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen2 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen3 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen3 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen4 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen4 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inlbuf1 && data->ioc_inllen1 == 0) {
		CERROR("OBD ioctl: inlbuf1 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf2 && data->ioc_inllen2 == 0) {
		CERROR("OBD ioctl: inlbuf2 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf3 && data->ioc_inllen3 == 0) {
		CERROR("OBD ioctl: inlbuf3 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf4 && data->ioc_inllen4 == 0) {
		CERROR("OBD ioctl: inlbuf4 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_pbuf1 && data->ioc_plen1 == 0) {
		CERROR("OBD ioctl: pbuf1 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_pbuf2 && data->ioc_plen2 == 0) {
		CERROR("OBD ioctl: pbuf2 pointer but 0 length\n");
		return 1;
	}

	if (!data->ioc_pbuf1 && data->ioc_plen1 != 0) {
		CERROR("OBD ioctl: plen1 set but NULL pointer\n");
		return 1;
	}

	if (!data->ioc_pbuf2 && data->ioc_plen2 != 0) {
		CERROR("OBD ioctl: plen2 set but NULL pointer\n");
		return 1;
	}

	if (obd_ioctl_packlen(data) > data->ioc_len) {
		CERROR("OBD ioctl: packlen exceeds ioc_len (%d > %d)\n",
		       obd_ioctl_packlen(data), data->ioc_len);
		return 1;
	}

	return 0;
}

/* buffer MUST be at least the size of obd_ioctl_hdr */
int obd_ioctl_getdata(char **buf, int *len, void __user *arg)
{
	struct obd_ioctl_hdr hdr;
	struct obd_ioctl_data *data;
	int offset = 0;
	ENTRY;

	if (copy_from_user(&hdr, arg, sizeof(hdr)))
		RETURN(-EFAULT);

        if (hdr.ioc_version != OBD_IOCTL_VERSION) {
                CERROR("Version mismatch kernel (%x) vs application (%x)\n",
                       OBD_IOCTL_VERSION, hdr.ioc_version);
                RETURN(-EINVAL);
        }

        if (hdr.ioc_len > OBD_MAX_IOCTL_BUFFER) {
                CERROR("User buffer len %d exceeds %d max buffer\n",
                       hdr.ioc_len, OBD_MAX_IOCTL_BUFFER);
                RETURN(-EINVAL);
        }

        if (hdr.ioc_len < sizeof(struct obd_ioctl_data)) {
                CERROR("User buffer too small for ioctl (%d)\n", hdr.ioc_len);
                RETURN(-EINVAL);
        }

        /* When there are lots of processes calling vmalloc on multi-core
         * system, the high lock contention will hurt performance badly,
         * obdfilter-survey is an example, which relies on ioctl. So we'd
         * better avoid vmalloc on ioctl path. LU-66 */
        OBD_ALLOC_LARGE(*buf, hdr.ioc_len);
        if (*buf == NULL) {
                CERROR("Cannot allocate control buffer of len %d\n",
                       hdr.ioc_len);
                RETURN(-EINVAL);
        }
        *len = hdr.ioc_len;
        data = (struct obd_ioctl_data *)*buf;

	if (copy_from_user(*buf, arg, hdr.ioc_len)) {
		OBD_FREE_LARGE(*buf, hdr.ioc_len);
		RETURN(-EFAULT);
	}

        if (obd_ioctl_is_invalid(data)) {
                CERROR("ioctl not correctly formatted\n");
                OBD_FREE_LARGE(*buf, hdr.ioc_len);
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1) {
                data->ioc_inlbuf1 = &data->ioc_bulk[0];
                offset += cfs_size_round(data->ioc_inllen1);
        }

        if (data->ioc_inllen2) {
                data->ioc_inlbuf2 = &data->ioc_bulk[0] + offset;
                offset += cfs_size_round(data->ioc_inllen2);
        }

        if (data->ioc_inllen3) {
                data->ioc_inlbuf3 = &data->ioc_bulk[0] + offset;
                offset += cfs_size_round(data->ioc_inllen3);
        }

	if (data->ioc_inllen4)
		data->ioc_inlbuf4 = &data->ioc_bulk[0] + offset;

	RETURN(0);
}
EXPORT_SYMBOL(obd_ioctl_getdata);

/*  opening /dev/obd */
static int obd_class_open(struct inode * inode, struct file * file)
{
	ENTRY;

	try_module_get(THIS_MODULE);
	RETURN(0);
}

/*  closing /dev/obd */
static int obd_class_release(struct inode * inode, struct file * file)
{
	ENTRY;

	module_put(THIS_MODULE);
	RETURN(0);
}

/* to control /dev/obd */
static long obd_class_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
        int err = 0;
        ENTRY;

        /* Allow non-root access for OBD_IOC_PING_TARGET - used by lfs check */
        if (!cfs_capable(CFS_CAP_SYS_ADMIN) && (cmd != OBD_IOC_PING_TARGET))
                RETURN(err = -EACCES);
        if ((cmd & 0xffffff00) == ((int)'T') << 8) /* ignore all tty ioctls */
                RETURN(err = -ENOTTY);

        err = class_handle_ioctl(cmd, (unsigned long)arg);

        RETURN(err);
}

/* declare character device */
static struct file_operations obd_psdev_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = obd_class_ioctl, /* unlocked_ioctl */
	.open           = obd_class_open,      /* open */
	.release        = obd_class_release,   /* release */
};

/* modules setup */
struct miscdevice obd_psdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= OBD_DEV_NAME,
	.fops	= &obd_psdev_fops,
};

static ssize_t version_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%s\n", LUSTRE_VERSION_STRING);
}

static ssize_t pinger_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
#ifdef ENABLE_PINGER
	const char *state = "on";
#else
	const char *state = "off";
#endif
	return sprintf(buf, "%s\n", state);
}

/**
 * Check all obd devices health
 *
 * \param kobj
 * \param buf [in]
 *
 * \retval number of characters printed if healthy
 */
static ssize_t
health_check_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	bool healthy = true;
	size_t len = 0;
	int i;

	if (libcfs_catastrophe) {
		len = sprintf(buf, "LBUG\n");
		healthy = false;
	}

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd;

		obd = class_num2obd(i);
		if (obd == NULL || !obd->obd_attached || !obd->obd_set_up)
			continue;

		LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
		if (obd->obd_stopping)
			continue;

		class_incref(obd, __FUNCTION__, current);
		read_unlock(&obd_dev_lock);

		if (obd_health_check(NULL, obd)) {
			len = sprintf(buf, "device %s reported unhealthy\n",
				      obd->obd_name);
			healthy = false;
		}
		class_decref(obd, __FUNCTION__, current);
		read_lock(&obd_dev_lock);
	}
	read_unlock(&obd_dev_lock);

	if (healthy)
		len = sprintf(buf, "healthy\n");
	else
		len = sprintf(buf, "NOT HEALTHY\n");

	return len;
}

static ssize_t jobid_var_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	int rc = 0;

	if (strlen(obd_jobid_var))
		rc = snprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_var);
	return rc;
}

static ssize_t jobid_var_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	if (!count || count > JOBSTATS_JOBID_VAR_MAX_LEN)
		return -EINVAL;

	memset(obd_jobid_var, 0, JOBSTATS_JOBID_VAR_MAX_LEN + 1);

	memcpy(obd_jobid_var, buffer, count);

	/* Trim the trailing '\n' if any */
	if (obd_jobid_var[count - 1] == '\n')
		obd_jobid_var[count - 1] = 0;

	return count;
}

static ssize_t jobid_name_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	int rc = 0;

	if (strlen(obd_jobid_node))
		rc = snprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_node);
	return rc;
}

static ssize_t jobid_name_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	if (!count || count > LUSTRE_JOBID_SIZE)
		return -EINVAL;

	/* clear previous value */
	memset(obd_jobid_node, 0, LUSTRE_JOBID_SIZE);

	memcpy(obd_jobid_node, buffer, count);

	/* Trim the trailing '\n' if any */
	if (obd_jobid_node[count - 1] == '\n') {
		/* Don't echo just a newline */
		if (count == 1)
			return -EINVAL;
		obd_jobid_node[count - 1] = 0;
	}

	return count;
}

/* Root for /sys/kernel/debug/lustre */
struct dentry *debugfs_lustre_root;
EXPORT_SYMBOL_GPL(debugfs_lustre_root);

#ifdef CONFIG_PROC_FS
/* Root for /proc/fs/lustre */
struct proc_dir_entry *proc_lustre_root = NULL;
EXPORT_SYMBOL(proc_lustre_root);
#else
#define lprocfs_base NULL
#endif /* CONFIG_PROC_FS */

LUSTRE_RO_ATTR(version);
LUSTRE_RO_ATTR(pinger);
LUSTRE_RO_ATTR(health_check);
LUSTRE_RW_ATTR(jobid_var);
LUSTRE_RW_ATTR(jobid_name);

static struct attribute *lustre_attrs[] = {
	&lustre_attr_version.attr,
	&lustre_attr_pinger.attr,
	&lustre_attr_health_check.attr,
	&lustre_attr_jobid_name.attr,
	&lustre_attr_jobid_var.attr,
	NULL,
};

static void *obd_device_list_seq_start(struct seq_file *p, loff_t *pos)
{
        if (*pos >= class_devno_max())
                return NULL;

        return pos;
}

static void obd_device_list_seq_stop(struct seq_file *p, void *v)
{
}

static void *obd_device_list_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        ++*pos;
        if (*pos >= class_devno_max())
                return NULL;

        return pos;
}

static int obd_device_list_seq_show(struct seq_file *p, void *v)
{
        loff_t index = *(loff_t *)v;
        struct obd_device *obd = class_num2obd((int)index);
        char *status;

        if (obd == NULL)
                return 0;

        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
        if (obd->obd_stopping)
                status = "ST";
        else if (obd->obd_inactive)
                status = "IN";
        else if (obd->obd_set_up)
                status = "UP";
        else if (obd->obd_attached)
                status = "AT";
        else
                status = "--";

	seq_printf(p, "%3d %s %s %s %s %d\n",
		   (int)index, status, obd->obd_type->typ_name,
		   obd->obd_name, obd->obd_uuid.uuid,
		   atomic_read(&obd->obd_refcount));
	return 0;
}

static const struct seq_operations obd_device_list_sops = {
        .start = obd_device_list_seq_start,
        .stop = obd_device_list_seq_stop,
        .next = obd_device_list_seq_next,
        .show = obd_device_list_seq_show,
};

static int obd_device_list_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc = seq_open(file, &obd_device_list_sops);

	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private;
	return 0;
}

static const struct file_operations obd_device_list_fops = {
        .owner   = THIS_MODULE,
        .open    = obd_device_list_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

struct kobject *lustre_kobj;
EXPORT_SYMBOL_GPL(lustre_kobj);

static struct attribute_group lustre_attr_group = {
	.attrs = lustre_attrs,
};

int class_procfs_init(void)
{
	struct proc_dir_entry *entry;
	struct dentry *file;
	int rc = -ENOMEM;
	ENTRY;

	lustre_kobj = kobject_create_and_add("lustre", fs_kobj);
	if (lustre_kobj == NULL)
		goto out;

	/* Create the files associated with this kobject */
	rc = sysfs_create_group(lustre_kobj, &lustre_attr_group);
	if (rc) {
		kobject_put(lustre_kobj);
		goto out;
	}

	rc = obd_sysctl_init();
	if (rc) {
		kobject_put(lustre_kobj);
		goto out;
	}

	debugfs_lustre_root = debugfs_create_dir("lustre", NULL);
	if (IS_ERR_OR_NULL(debugfs_lustre_root)) {
		rc = debugfs_lustre_root ? PTR_ERR(debugfs_lustre_root)
					 : -ENOMEM;
		debugfs_lustre_root = NULL;
		kobject_put(lustre_kobj);
		goto out;
	}

	file = debugfs_create_file("devices", 0444, debugfs_lustre_root, NULL,
				   &obd_device_list_fops);
	if (IS_ERR_OR_NULL(file)) {
		rc = file ? PTR_ERR(file) : -ENOMEM;
		kobject_put(lustre_kobj);
		goto out;
	}

	entry = lprocfs_register("fs/lustre", NULL, NULL, NULL);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CERROR("cannot create '/proc/fs/lustre': rc = %d\n", rc);
		kobject_put(lustre_kobj);
		goto out;
	}

	proc_lustre_root = entry;
out:
	RETURN(rc);
}

int class_procfs_clean(void)
{
	ENTRY;

	debugfs_remove_recursive(debugfs_lustre_root);

	debugfs_lustre_root = NULL;

	if (proc_lustre_root)
		lprocfs_remove(&proc_lustre_root);

	kobject_put(lustre_kobj);

	RETURN(0);
}
