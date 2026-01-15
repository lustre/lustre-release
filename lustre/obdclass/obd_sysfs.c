// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
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

#include <linux/lnet/lnet_crypto.h>
#include <lustre_compat/linux/timer.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <uapi/linux/lnet/lnetctl.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/lustre/lustre_ver.h>

bool obd_enable_health_write;
EXPORT_SYMBOL(obd_enable_health_write);

bool obd_enable_fname_encoding;
EXPORT_SYMBOL(obd_enable_fname_encoding);

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
	struct static_lustre_uintvalue_attr *lattr = (void *)attr;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	*lattr->value = val;

	return count;
}

#define LUSTRE_STATIC_UINT_ATTR(name, value)				\
static struct static_lustre_uintvalue_attr lustre_sattr_##name =	\
	{ __ATTR(name, 0644, static_uintvalue_show,			\
		 static_uintvalue_store), value }

LUSTRE_STATIC_UINT_ATTR(debug_peer_on_timeout, &obd_debug_peer_on_timeout);
LUSTRE_STATIC_UINT_ATTR(dump_on_timeout, &obd_dump_on_timeout);

static ssize_t at_min_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", at_min);
}

static ssize_t at_min_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	class_at_min_set(val);

	return count;
}
LUSTRE_RW_ATTR(at_min);

LUSTRE_STATIC_UINT_ATTR(at_max, &at_max);
LUSTRE_STATIC_UINT_ATTR(at_extra, &at_extra);
LUSTRE_STATIC_UINT_ATTR(at_early_margin, &at_early_margin);
LUSTRE_STATIC_UINT_ATTR(at_history, &at_history);
LUSTRE_STATIC_UINT_ATTR(at_unhealthy_factor, &at_unhealthy_factor);
LUSTRE_STATIC_UINT_ATTR(enable_stats_header, &obd_enable_stats_header);
LUSTRE_STATIC_UINT_ATTR(ping_interval, &ping_interval);

#ifdef CONFIG_LUSTRE_FS_SERVER
LUSTRE_STATIC_UINT_ATTR(ldlm_timeout, &ldlm_timeout);
LUSTRE_STATIC_UINT_ATTR(bulk_timeout, &bulk_timeout);

static ssize_t expected_clients_show(struct kobject *kobj,
				     struct attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", class_expected_clients_get());
}

static ssize_t expected_clients_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	rc = class_expected_clients_update(val, true);
	if (rc)
		return rc;

	return count;
}
LUSTRE_RW_ATTR(expected_clients);

/* Timer for auto-disabling allow_register after timeout */
static struct timer_list allow_register_timer;

static DEFINE_MUTEX(allow_register_mutex);

/* Set once the admin has explicitly touched allow_register, via module
 * param or lctl set_param, so class_allow_register_arm_default() knows
 * not to override that choice.
 */
static bool allow_register_user_set;

/* True until the one-time default window is armed, then false for the
 * rest of this module load. allow_register_mutex serializes callers so
 * a losing caller waits for the winner to finish arming, then rechecks
 * allow_register instead of racing past with a stale value.
 */
static bool allow_register_arm_pending = true;

/* Length of the automatic one-time registration window. */
#define ALLOW_REGISTER_DEFAULT_SECONDS (24 * 3600)

static void allow_register_timeout_handler(cfs_timer_cb_arg_t data)
{
	allow_register = 0;
	LCONSOLE_WARN("New MDT/OST registration window disabled. Use 'lctl set_param allow_register=<value>' to re-enable (default unit: hours).\n");
}

/**
 * class_allow_register_arm_default() - open the one-time default
 * registration window on first use
 * @fsname: name of the filesystem whose target registration triggered
 *	    the arming, printed in the console message so the admin can
 *	    see why the window opened
 *
 * Called for the first target of a filesystem unknown to the MGS.
 * Opens a one-time 24-hour window unless the admin already set
 * allow_register explicitly.
 *
 * allow_register_arm_pending is checked and cleared under
 * allow_register_mutex, so this runs at most once per module load.
 * Concurrent callers serialize on the mutex and recheck the state
 * after the winner finishes arming.
 *
 * An obdclass reload resets the default window and the one-shot.
 */
void class_allow_register_arm_default(const char *fsname)
{
	mutex_lock(&allow_register_mutex);
	if (!allow_register_arm_pending) {
		mutex_unlock(&allow_register_mutex);
		return;
	}
	allow_register_arm_pending = false;

	if (!allow_register_user_set) {
		timer_delete_sync(&allow_register_timer);
		allow_register = ALLOW_REGISTER_DEFAULT_SECONDS;
		mod_timer(&allow_register_timer,
			  jiffies + cfs_time_seconds(ALLOW_REGISTER_DEFAULT_SECONDS));
		LCONSOLE_WARN("%s: first target registration detected: opening a one-time 24-hour registration window. Use 'lctl set_param allow_register=0' to close it early, or 'lctl set_param -P allow_register=0' to lock down permanently.\n",
			      fsname);
	}
	mutex_unlock(&allow_register_mutex);
}
EXPORT_SYMBOL(class_allow_register_arm_default);

static ssize_t allow_register_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	unsigned long remaining;
	unsigned long expires;
	unsigned long now;
	unsigned long val;
	bool pending;

	mutex_lock(&allow_register_mutex);
	val = allow_register;
	pending = timer_pending(&allow_register_timer);
	expires = allow_register_timer.expires;
	now = jiffies;
	mutex_unlock(&allow_register_mutex);

	if (!val)
		return scnprintf(buf, PAGE_SIZE, "0\n");

	if (val == ALLOW_REGISTER_UNLIMITED)
		return scnprintf(buf, PAGE_SIZE, "unlimited\n");

	if (pending) {
		if (time_after(expires, now))
			remaining = (expires - now) / cfs_time_seconds(1);
		else
			remaining = 0;

		return scnprintf(buf, PAGE_SIZE, "%lus\n", remaining);
	}

	return scnprintf(buf, PAGE_SIZE, "0\n");
}

/**
 * class_allow_register_set() - parse and apply a new allow_register value
 * @buffer: NUL-terminated string: "unlimited", "0", or N[s|m|h]
 *
 * Shared by the sysfs store() callback and the mgs module's
 * "allow_register" boot-time module parameter, so both paths get
 * identical validation, locking, and timer arming.
 *
 * Return: 0 on success, negative errno on invalid input.
 */
int class_allow_register_set(const char *buffer)
{
	unsigned long val;
	unsigned long mult;
	const char *suffix;
	char buf[32];
	size_t len = 0;
	int rc;

	/* Check for "unlimited" keyword */
	if (sysfs_streq(buffer, "unlimited")) {
		mutex_lock(&allow_register_mutex);
		allow_register_user_set = true;
		timer_delete_sync(&allow_register_timer);
		if (allow_register != ALLOW_REGISTER_UNLIMITED) {
			allow_register = ALLOW_REGISTER_UNLIMITED;
			LCONSOLE_WARN("New target registration enabled indefinitely\n");
		}
		mutex_unlock(&allow_register_mutex);
		return 0;
	}

	while (len < sizeof(buf) - 1 && isdigit(buffer[len]))
		len++;

	if (len == 0 || len >= sizeof(buf) - 1)
		return -EINVAL;

	memcpy(buf, buffer, len);
	buf[len] = '\0';

	rc = kstrtoul(buf, 10, &val);
	if (rc)
		return rc;

	suffix = buffer + len;
	switch (*suffix) {
	case 's':
		mult = 1;
		suffix++;
		break;
	case 'm':
		mult = 60;
		suffix++;
		break;
	case 'h':
		mult = 3600;
		suffix++;
		break;
	default:
		/* no unit suffix: default unit is 1h */
		mult = 3600;
		break;
	}

	/* Only an optional trailing newline may follow digits or unit */
	if (*suffix == '\n')
		suffix++;
	if (*suffix != '\0')
		return -EINVAL;

	if (val > ULONG_MAX / mult)
		return -EINVAL;

	val *= mult;

	/*
	 * Reject timed windows at/above the unlimited sentinel (7d+1s).
	 * Larger values would be force-expired early by the wheel with no
	 * indication. Use "unlimited" for an open-ended window.
	 */
	if (val >= ALLOW_REGISTER_UNLIMITED) {
		LCONSOLE_WARN("allow_register=%lu exceeds maximum timed window of 7 days (604800s). Use 7 days or less (e.g. 168h) or 'unlimited'.\n",
			      val);
		return -EINVAL;
	}

	mutex_lock(&allow_register_mutex);
	allow_register_user_set = true;
	timer_delete_sync(&allow_register_timer);

	if (val == 0) {
		/* Registration disabled */
		if (allow_register != 0) {
			allow_register = 0;
			LCONSOLE_WARN("New target registration disabled\n");
		}
	} else {
		/* Enable registration with timeout (val = seconds) */
		allow_register = val;
		mod_timer(&allow_register_timer,
			  jiffies + cfs_time_seconds(val));
		LCONSOLE_WARN("Registration timeout window started: %lu seconds. New targets can be registered during this window.\n",
			      val);
	}
	mutex_unlock(&allow_register_mutex);

	return 0;
}
EXPORT_SYMBOL(class_allow_register_set);

static ssize_t allow_register_store(struct kobject *kobj,
				    struct attribute *attr, const char *buffer,
				    size_t count)
{
	int rc;

	rc = class_allow_register_set(buffer);
	if (rc)
		return rc;

	return count;
}
LUSTRE_ATTR(allow_register, 0644, allow_register_show, allow_register_store);
#endif

static ssize_t memused_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%llu\n", obd_memory_sum());
}
LUSTRE_RO_ATTR(memused);

static ssize_t memused_max_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	return sprintf(buf, "%llu\n", obd_memory_max());
}
LUSTRE_RO_ATTR(memused_max);

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

	if (val > ((totalram_pages() / 10) * 9)) {
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

#ifdef CONFIG_LUSTRE_FS_SERVER
static ssize_t no_transno_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buffer, size_t count)
{
	struct obd_device *obd;
	unsigned int idx;
	int rc;

	rc = kstrtouint(buffer, 10, &idx);
	if (rc)
		return rc;

	obd = class_num2obd(idx);
	if (!obd || !test_bit(OBDF_ATTACHED, obd->obd_flags)) {
		if (obd)
			CERROR("%s: not attached\n", obd->obd_name);
		return -ENODEV;
	}

	spin_lock(&obd->obd_dev_lock);
	set_bit(OBDF_NO_TRANSNO, obd->obd_flags);
	spin_unlock(&obd->obd_dev_lock);
	return count;
}
LUSTRE_WO_ATTR(no_transno);
#endif /* CONFIG_LUSTRE_FS_SERVER */

static ssize_t version_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%s\n", LUSTRE_VERSION_STRING);
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
	struct obd_device *obd = NULL;
	unsigned long dev_no = 0;
	bool healthy = true;
	size_t len = 0;

	if (libcfs_catastrophe)
		return sprintf(buf, "LBUG\n");

	obd_device_lock();
	obd_device_for_each_cond(dev_no, obd,
				 test_bit(OBDF_ATTACHED, obd->obd_flags) &&
				 test_bit(OBDF_SET_UP, obd->obd_flags) &&
				 !test_bit(OBDF_STOPPING, obd->obd_flags) &&
				 !test_bit(OBDF_READ_ONLY, obd->obd_flags)) {
		LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);

		class_incref(obd, __func__, current);
		obd_device_unlock();
		if (obd_health_check(NULL, obd)) {
			CERROR("%s: device reported unhealthy\n",
			       obd->obd_name);
			healthy = false;
		}
		obd_device_lock();
		class_decref(obd, __func__, current);

		if (!healthy)
			break;
	}
	obd_device_unlock();

	if (healthy)
		len = sprintf(buf, "healthy\n");
	else
		len = sprintf(buf, "NOT HEALTHY\n");

	return len;
}

#ifdef CONFIG_LUSTRE_FS_SERVER
static ssize_t enable_health_write_show(struct kobject *kobj,
					struct attribute *attr,
					char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 obd_enable_health_write);
}

static ssize_t enable_health_write_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t count)
{
	int rc = 0;

	rc = kstrtobool(buf, &obd_enable_health_write);
	if (rc)
		return rc;

	return count;
}
LUSTRE_RW_ATTR(enable_health_write);
#endif /* CONFIG_LUSTRE_FS_SERVER */

static ssize_t enable_fname_encoding_show(struct kobject *kobj,
					struct attribute *attr,
					char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 obd_enable_fname_encoding);
}

static ssize_t enable_fname_encoding_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t count)
{
	int rc = 0;

	rc = kstrtobool(buf, &obd_enable_fname_encoding);
	if (rc)
		return rc;

	return count;
}
LUSTRE_RW_ATTR(enable_fname_encoding);

static ssize_t jobid_var_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	int rc = 0;

	if (strlen(obd_jobid_var))
		rc = scnprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_var);
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

	if (strlen(obd_jobid_name))
		rc = scnprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_name);
	return rc;
}

static ssize_t jobid_name_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	if (!count || count > LUSTRE_JOBID_SIZE)
		return -EINVAL;

	if (strcmp(obd_jobid_var, JOBSTATS_NODELOCAL) != 0 &&
	    !strchr(buffer, '%')) {
		lustre_jobid_clear(buffer);
		return count;
	}

	/* clear previous value */
	memset(obd_jobid_name, 0, LUSTRE_JOBID_SIZE);

	memcpy(obd_jobid_name, buffer, count);

	/* Trim the trailing '\n' if any */
	if (obd_jobid_name[count - 1] == '\n') {
		/* Don't echo just a newline */
		if (count == 1)
			return -EINVAL;
		obd_jobid_name[count - 1] = 0;
	}

	return count;
}

static ssize_t jobid_this_session_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	char *jid;
	int ret = -ENOENT;

	rcu_read_lock();
	jid = jobid_current();
	if (jid)
		ret = scnprintf(buf, PAGE_SIZE, "%s\n", jid);
	rcu_read_unlock();
	return ret;
}

static ssize_t jobid_this_session_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	char *jobid;
	int len;
	int ret;

	if (!count || count > LUSTRE_JOBID_SIZE)
		return -EINVAL;

	jobid = kstrndup(buffer, count, GFP_KERNEL);
	if (!jobid)
		return -ENOMEM;
	len = strcspn(jobid, "\n ");
	jobid[len] = '\0';
	ret = jobid_set_current(jobid);
	kfree(jobid);

	return ret ?: count;
}

static ssize_t timeout_show(struct kobject *kobj,
			    struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%u\n", obd_timeout);
}

static ssize_t timeout_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buffer,
			     size_t count)
{
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;
	obd_timeout = val ?: 1U;
	ping_interval = max(obd_timeout / 4, 1U);

	return count;
}

static ssize_t debug_raw_pointers_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", get_debug_raw_pointers());
}

static ssize_t debug_raw_pointers_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buffer,
			     size_t count)
{
	bool initial = get_debug_raw_pointers();
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if ((initial && val) || (!initial && !val))
		return count;

	if (val) {
		rc = debug_format_buffer_alloc_buffers();
		if (rc)
			return rc;
	} else {
		debug_format_buffer_free_buffers();
	}
	set_debug_raw_pointers(val);

	return count;
}

static const char *const eviction_names[] = {
	"1",		/* DUMP_SUBS_OLD */
	"llite",	/* DUMP_PTLRPC_CONN */
	"ldlm",         /* DUMP_LDLM_LOCK */
	"stale",	/* DUMP_RECOVERY_STALE */
	"pinger"        /* DUMP_PINGER */
};

static inline const char *eviction_type2str(int type)
{
	if (type >= 0 && type < ARRAY_SIZE(eviction_names))
		return eviction_names[type];
	return NULL;
}

static ssize_t dump_on_eviction_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	size_t len;

	cfs_mask2str(buf, PAGE_SIZE, obd_dump_on_eviction, eviction_type2str,
		     ' ');
	len = strlen(buf);

	return len + scnprintf(buf + len, PAGE_SIZE - len, "\n");
}

static ssize_t both_on_eviction_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer,
				      size_t count, unsigned int *val)
{
	u64 fl = *val;
	u64 max_mask = (1 << (ARRAY_SIZE(eviction_names) + 1)) - 1;
	int rc;

	rc = kstrtou64(buffer, 0, &fl);
	/* check flags fits to str array */
	if (!rc && !(fl & ~max_mask)) {
		*val = fl;
		return count;
	}

	rc = cfs_str2mask(buffer, eviction_type2str, &fl, 0, max_mask, 0);

	if (!rc && fl != *val)
		*val = fl;

	return count;
}

static ssize_t dump_on_eviction_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer,
				      size_t count)
{
	return both_on_eviction_store(kobj, attr, buffer, count,
				      &obd_dump_on_eviction);
}

static ssize_t lbug_on_eviction_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	size_t len;

	cfs_mask2str(buf, PAGE_SIZE, obd_lbug_on_eviction, eviction_type2str,
		     ' ');
	len = strlen(buf);

	return len + scnprintf(buf + len, PAGE_SIZE - len, "\n");
}

static ssize_t lbug_on_eviction_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer,
				      size_t count)
{
	return both_on_eviction_store(kobj, attr, buffer, count,
				      &obd_lbug_on_eviction);
}


/* Root for /sys/kernel/debug/lustre */
struct dentry *debugfs_lustre_root;
EXPORT_SYMBOL_GPL(debugfs_lustre_root);

#ifdef CONFIG_PROC_FS
/* Root for /proc/fs/lustre */
struct proc_dir_entry *proc_lustre_root;
EXPORT_SYMBOL(proc_lustre_root);
#else
#define lprocfs_base NULL
#endif /* CONFIG_PROC_FS */

LUSTRE_RO_ATTR(version);
LUSTRE_RO_ATTR(health_check);
LUSTRE_RW_ATTR(jobid_var);
LUSTRE_RW_ATTR(jobid_name);
LUSTRE_RW_ATTR(jobid_this_session);
LUSTRE_RW_ATTR(timeout);
LUSTRE_RW_ATTR(debug_raw_pointers);
LUSTRE_RW_ATTR(dump_on_eviction);
LUSTRE_RW_ATTR(lbug_on_eviction);

static struct attribute *lustre_attrs[] = {
	&lustre_attr_version.attr,
	&lustre_sattr_enable_stats_header.u.attr,
	&lustre_attr_health_check.attr,
	&lustre_attr_jobid_name.attr,
	&lustre_attr_jobid_var.attr,
	&lustre_attr_jobid_this_session.attr,
	&lustre_attr_timeout.attr,
	&lustre_attr_debug_raw_pointers.attr,
	&lustre_attr_max_dirty_mb.attr,
	&lustre_sattr_debug_peer_on_timeout.u.attr,
	&lustre_sattr_dump_on_timeout.u.attr,
	&lustre_attr_dump_on_eviction.attr,
	&lustre_attr_at_min.attr,
	&lustre_sattr_at_max.u.attr,
	&lustre_sattr_at_extra.u.attr,
	&lustre_sattr_at_early_margin.u.attr,
	&lustre_sattr_at_history.u.attr,
	&lustre_sattr_at_unhealthy_factor.u.attr,
	&lustre_attr_memused_max.attr,
	&lustre_attr_memused.attr,
#ifdef CONFIG_LUSTRE_FS_SERVER
	&lustre_attr_allow_register.attr,
	&lustre_attr_enable_health_write.attr,
	&lustre_attr_expected_clients.attr,
	&lustre_attr_no_transno.attr,
	&lustre_sattr_bulk_timeout.u.attr,
	&lustre_sattr_ldlm_timeout.u.attr,
#endif
	&lustre_attr_enable_fname_encoding.attr,
	&lustre_attr_lbug_on_eviction.attr,
	&lustre_sattr_ping_interval.u.attr,
	NULL,
};

static void *obd_device_list_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_device *obd;
	unsigned long devno;

	devno = *pos;
	obd_device_lock();
	obd = obd_device_find(devno);

	if (!obd) {
		obd_device_unlock();
		return NULL;
	}

	*pos = devno;
	class_incref(obd, "obd_device_list_seq", obd);
	obd_device_unlock();

	return obd;
}

static void obd_device_list_seq_stop(struct seq_file *p, void *v)
{
	struct obd_device *obd = v;

	if (!obd)
		return;

	obd_device_lock();
	class_decref(obd, "obd_device_list_seq", obd);
	obd_device_unlock();
}

static void *obd_device_list_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_device *obd = v;
	unsigned long devno;

	obd_device_lock();
	class_decref(obd, "obd_device_list_seq", obd);
	devno = *pos;
	obd = obd_device_find_after(devno);

	if (!obd) {
		(*pos)++;
		obd_device_unlock();
		return NULL;
	}

	*pos = devno;
	class_incref(obd, "obd_device_list_seq", obd);
	obd_device_unlock();

	return obd;
}

static int obd_device_list_seq_show(struct seq_file *p, void *v)
{
	struct obd_device *obd = v;
	char *status;
	int dev_no;

	if (!obd)
		return 0;

	LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
	dev_no = obd->obd_minor;

	if (test_bit(OBDF_STOPPING, obd->obd_flags))
		status = "ST";
	else if (test_bit(OBDF_INACTIVE, obd->obd_flags))
		status = "IN";
	else if (test_bit(OBDF_SET_UP, obd->obd_flags))
		status = "UP";
	else if (test_bit(OBDF_ATTACHED, obd->obd_flags))
		status = "AT";
	else
		status = "--";

	seq_printf(p, "%3d %s %s %s %s %d\n",
		   dev_no, status, obd->obd_type->typ_name,
		   obd->obd_name, obd->obd_uuid.uuid,
		   kref_read(&obd->obd_refcount));

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

/* checksum_speed */
static void *checksum_speed_start(struct seq_file *p, loff_t *pos)
{
	return pos;
}

static void checksum_speed_stop(struct seq_file *p, void *v)
{
}

static void *checksum_speed_next(struct seq_file *p, void *v, loff_t *pos)
{
	++(*pos);
	if (*pos >= CFS_HASH_ALG_SPEED_MAX - 1)
		return NULL;

	return pos;
}

static int checksum_speed_show(struct seq_file *p, void *v)
{
	loff_t index = *(loff_t *)v;

	if (!index || index > CFS_HASH_ALG_SPEED_MAX - 1)
		return 0;

	seq_printf(p, "%s: %d\n", cfs_crypto_hash_name(index),
		   cfs_crypto_hash_speeds[index]);

	return 0;
}

static const struct seq_operations checksum_speed_sops = {
	.start = checksum_speed_start,
	.stop = checksum_speed_stop,
	.next = checksum_speed_next,
	.show = checksum_speed_show,
};

static int checksum_speed_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &checksum_speed_sops);

	if (rc)
		return rc;

	return 0;
}

static const struct file_operations checksum_speed_fops = {
	.owner   = THIS_MODULE,
	.open    = checksum_speed_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

struct kset *lustre_kset;
EXPORT_SYMBOL_GPL(lustre_kset);

static struct attribute_group lustre_attr_group = {
	.attrs = lustre_attrs,
};

static int allow_register_param_value(const char *param, char *val, size_t vsz)
{
	const char *eq, *name, *p, *end;
	size_t len;

	if (!param)
		return 0;

	eq = strchr(param, '=');
	if (!eq)
		return 0;

	name = eq;
	while (name > param && name[-1] != '.')
		name--;
	if (eq - name != strlen("allow_register") ||
	    strncmp(name, "allow_register", eq - name) != 0)
		return 0;

	p = eq + 1;
	while (*p == ' ' || *p == '\t')
		p++;

	len = strcspn(p, " \t\r\n");
	if (len == 0 || len >= vsz)
		return -EINVAL;

	end = p + len;
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (*end != '\0')
		return -EINVAL;

	memcpy(val, p, len);
	val[len] = '\0';
	return 1;
}

#ifdef CONFIG_LUSTRE_FS_SERVER
int class_allow_register_check_persist(const char *param, bool del)
{
	char val[16];
	int rc;

	if (del)
		return 0;

	rc = allow_register_param_value(param, val, sizeof(val));
	if (rc <= 0)
		return rc;
	if (strcmp(val, "0") == 0 || strcmp(val, "unlimited") == 0)
		return 0;
	return -EINVAL;
}
EXPORT_SYMBOL(class_allow_register_check_persist);
#endif /* CONFIG_LUSTRE_FS_SERVER */

ssize_t class_set_global(const char *param)
{
	const char *eq = strchr(param, '=');
	const char *value;
	size_t off;
	ssize_t count = -ENOENT;
	char val[16];
	int i, rc;

	if (!eq || eq == param)
		return -EINVAL;

	off = eq - param;
	value = eq + 1;

	/*
	 * allow_register from config: 0/unlimited as-is.
	 * bare 1 (old boolean "on") -> unlimited; reject timed values.
	 */
	rc = allow_register_param_value(param, val, sizeof(val));
	if (rc < 0)
		return rc;
	if (rc > 0) {
		if (strcmp(val, "1") == 0) {
			/* legacy boolean "on" */
			value = "unlimited";
		} else if (strcmp(val, "0") == 0 ||
			   strcmp(val, "unlimited") == 0) {
			value = val;
		} else {
			return -EINVAL;
		}
	}

	for (i = 0; lustre_attrs[i]; i++) {
		if (strlen(lustre_attrs[i]->name) == off &&
		    !strncmp(lustre_attrs[i]->name, param, off)) {
			count = lustre_attr_store(&lustre_kset->kobj,
						  lustre_attrs[i], value,
						  strlen(value));
			break;
		}
	}
	return count;
}

int __init class_procfs_init(void)
{
	struct proc_dir_entry *entry;
	int rc = -ENOMEM;

	ENTRY;

#ifdef CONFIG_LUSTRE_FS_SERVER
	timer_setup(&allow_register_timer, allow_register_timeout_handler, 0);
#endif

	lustre_kset = kset_create_and_add("lustre", NULL, fs_kobj);
	if (!lustre_kset)
		goto out;

	/* Create the files associated with this kobject */
	rc = sysfs_create_group(&lustre_kset->kobj, &lustre_attr_group);
	if (rc) {
		kset_unregister(lustre_kset);
		goto out;
	}

	rc = jobid_cache_init();
	if (rc) {
		kset_unregister(lustre_kset);
		goto out;
	}

	debugfs_lustre_root = debugfs_create_dir("lustre", NULL);

	debugfs_create_file("devices", 0444, debugfs_lustre_root, NULL,
			    &obd_device_list_fops);

	debugfs_create_file("checksum_speed", 0444, debugfs_lustre_root,
			    NULL, &checksum_speed_fops);

	entry = lprocfs_register("fs/lustre", NULL, NULL, NULL);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CERROR("cannot create '/proc/fs/lustre': rc = %d\n", rc);
		debugfs_remove_recursive(debugfs_lustre_root);
		kset_unregister(lustre_kset);
		goto out;
	}

	proc_lustre_root = entry;
out:
#ifdef CONFIG_LUSTRE_FS_SERVER
	if (rc)
		timer_delete_sync(&allow_register_timer);
#endif
	RETURN(rc);
}

int class_procfs_clean(void)
{
	ENTRY;

	debugfs_remove_recursive(debugfs_lustre_root);

	debugfs_lustre_root = NULL;
	jobid_cache_fini();

	if (proc_lustre_root)
		lprocfs_remove(&proc_lustre_root);

	sysfs_remove_group(&lustre_kset->kobj, &lustre_attr_group);

	kset_unregister(lustre_kset);

#ifdef CONFIG_LUSTRE_FS_SERVER
	timer_delete_sync(&allow_register_timer);
#endif

	RETURN(0);
}

/* filename encoding */
#define ENCODE_FN_LEN	BASE64URL_CHARS(sizeof(__u64)) + 2
#define FN_COUNT 64 /* must be power-of-two value */
const char *encode_fn_len(const char *fname, size_t namelen)
{
	static char fn_array[FN_COUNT][ENCODE_FN_LEN];
	static atomic_t fn_index;
	char *new_fn = NULL;
	char *tmp;
	int encode_len = ENCODE_FN_LEN;
	int rc;
	__u64 hash;

	CDEBUG(D_TRACE, "Process filename at %p\n", &fname);
	if (!fname || !namelen || !obd_enable_fname_encoding)
		return fname;
	if (unlikely(namelen > NAME_MAX))
		namelen = NAME_MAX;

	hash = lustre_hash_fnv_1a_64(fname, namelen);
	new_fn = fn_array[atomic_inc_return(&fn_index) & (FN_COUNT - 1)];
	tmp = new_fn;
	rc = gss_base64url_encode(&tmp, &encode_len, (__u8 *)&hash,
				  sizeof(hash));
	if (rc < 0) {
		if (encode_len == -1)
			CERROR("Encode buffer size(%d) is too small: rc = %d\n",
			       (int)ENCODE_FN_LEN, rc);
		else
			CERROR("Failed to encode name(%zu): rc = %d\n",
			       namelen, rc);
	}

	return new_fn;
}
EXPORT_SYMBOL(encode_fn_len);
