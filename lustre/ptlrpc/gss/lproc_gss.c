// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_SEC
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mutex.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lprocfs_status.h>
#include <lustre_sec.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"

static struct dentry *gss_debugfs_dir;

static struct kobject *gss_kobj;
static struct kobject *gss_kobj_lk;

/*
 * statistic of "out-of-sequence-window"
 */
static struct {
	spinlock_t	oos_lock;
	atomic_t	oos_cli_count;		/* client occurrence */
	int		oos_cli_behind;		/* client max seqs behind */
	atomic_t	oos_svc_replay[3];	/* server replay detected */
	atomic_t	oos_svc_pass[3];	/* server verified ok */
} gss_stat_oos = {
	.oos_cli_count	= ATOMIC_INIT(0),
	.oos_cli_behind	= 0,
	.oos_svc_replay	= { ATOMIC_INIT(0), },
	.oos_svc_pass	= { ATOMIC_INIT(0), },
};

void gss_stat_oos_record_cli(int behind)
{
	atomic_inc(&gss_stat_oos.oos_cli_count);

	spin_lock(&gss_stat_oos.oos_lock);
	if (behind > gss_stat_oos.oos_cli_behind)
		gss_stat_oos.oos_cli_behind = behind;
	spin_unlock(&gss_stat_oos.oos_lock);
}

void gss_stat_oos_record_svc(int phase, int replay)
{
	LASSERT(phase >= 0 && phase <= 2);

	if (replay)
		atomic_inc(&gss_stat_oos.oos_svc_replay[phase]);
	else
		atomic_inc(&gss_stat_oos.oos_svc_pass[phase]);
}

static int gss_proc_oos_seq_show(struct seq_file *m, void *v)
{
	seq_printf(m, "seqwin:		   %u\n"
		   "backwin:		%u\n"
		   "client fall behind seqwin\n"
		   "  occurrence:	%d\n"
		   "  max seq behind:	%d\n"
		   "server replay detected:\n"
		   "  phase 0:		%d\n"
		   "  phase 1:		%d\n"
		   "  phase 2:		%d\n"
		   "server verify ok:\n"
		   "  phase 2:		%d\n",
		   GSS_SEQ_WIN_MAIN,
		   GSS_SEQ_WIN_BACK,
		   atomic_read(&gss_stat_oos.oos_cli_count),
		   gss_stat_oos.oos_cli_behind,
		   atomic_read(&gss_stat_oos.oos_svc_replay[0]),
		   atomic_read(&gss_stat_oos.oos_svc_replay[1]),
		   atomic_read(&gss_stat_oos.oos_svc_replay[2]),
		   atomic_read(&gss_stat_oos.oos_svc_pass[2]));
	return 0;
}
LDEBUGFS_SEQ_FOPS_RO(gss_proc_oos);

static ssize_t init_channel_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t count)
{
	int rc;

	rc = gss_do_ctx_init_rpc((char *)buf, count);
	if (rc) {
		LASSERT(rc < 0);
		return rc;
	}
	return count;
}
LUSTRE_WO_ATTR(init_channel);

static int
sptlrpc_krb5_allow_old_client_csum_seq_show(struct seq_file *m,
					    void *data)
{
	seq_printf(m, "%u\n", krb5_allow_old_client_csum);
	return 0;
}

static ssize_t
sptlrpc_krb5_allow_old_client_csum_seq_write(struct file *file,
					     const char __user *buffer,
					     size_t count, loff_t *off)
{
	bool val;
	int rc;

	rc = kstrtobool_from_user(buffer, count, &val);
	if (rc)
		return rc;

	krb5_allow_old_client_csum = val;
	return count;
}
LDEBUGFS_SEQ_FOPS(sptlrpc_krb5_allow_old_client_csum);

#ifdef HAVE_GSS_KEYRING
static ssize_t gss_check_upcall_ns_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", gss_check_upcall_ns);
}

static ssize_t gss_check_upcall_ns_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t count)
{
	bool val;
	int rc;

	rc = kstrtobool(buf, &val);
	if (rc)
		return rc;

	gss_check_upcall_ns = val;
	return count;
}
LUSTRE_RW_ATTR(gss_check_upcall_ns);
#endif /* HAVE_GSS_KEYRING */

static int rsi_upcall_seq_show(struct seq_file *m,
			       void *data)
{
	down_read(&rsicache->uc_upcall_rwsem);
	seq_printf(m, "%s\n", rsicache->uc_upcall);
	up_read(&rsicache->uc_upcall_rwsem);

	return 0;
}

static ssize_t rsi_upcall_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	char *kbuf = NULL;
	int rc;

	OBD_ALLOC(kbuf, count + 1);
	if (kbuf == NULL)
		return -ENOMEM;

	if (copy_from_user(kbuf, buffer, count))
		GOTO(out, rc = -EFAULT);

	kbuf[count] = '\0';

	rc = upcall_cache_set_upcall(rsicache, kbuf, count, true);
	if (rc) {
		CERROR("%s: incorrect rsi upcall %s. Valid value for sptlrpc.gss.rsi_upcall is an executable pathname: rc = %d\n",
		       rsicache->uc_name, kbuf, rc);
		GOTO(out, rc);
	}

	CDEBUG(D_CONFIG, "%s: rsi upcall set to %s\n", rsicache->uc_name,
	       rsicache->uc_upcall);
	rc = count;

out:
	OBD_FREE(kbuf, count + 1);
	return rc;
}
LDEBUGFS_SEQ_FOPS(rsi_upcall);

static ssize_t ldebugfs_rsi_info_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count, void *data)
{
	struct rsi_downcall_data *param;
	int size = sizeof(*param), rc, checked = 0;

again:
	if (count < size) {
		CERROR("%s: invalid data count = %lu, size = %d\n",
		       rsicache->uc_name, (unsigned long)count, size);
		return -EINVAL;
	}

	OBD_ALLOC_LARGE(param, size);
	if (param == NULL)
		return -ENOMEM;

	if (copy_from_user(param, buffer, size)) {
		CERROR("%s: bad rsi data\n", rsicache->uc_name);
		GOTO(out, rc = -EFAULT);
	}

	if (checked == 0) {
		checked = 1;
		if (param->sid_magic != RSI_DOWNCALL_MAGIC) {
			CERROR("%s: rsi downcall bad params\n",
			       rsicache->uc_name);
			GOTO(out, rc = -EINVAL);
		}

		rc = param->sid_len; /* save sid_len */
		OBD_FREE_LARGE(param, size);
		size = offsetof(struct rsi_downcall_data, sid_val[rc]);
		goto again;
	}

	rc = upcall_cache_downcall(rsicache, param->sid_err,
				   param->sid_hash, param);

	/* The caller, i.e. the userspace process writing to rsi_info, only
	 * needs to know about invalid values. Other errors are processed
	 * directly in the kernel.
	 */
	if (rc != -EINVAL)
		rc = 0;

out:
	if (param != NULL)
		OBD_FREE_LARGE(param, size);

	return rc ? rc : count;
}
LDEBUGFS_FOPS_WR_ONLY(gss, rsi_info);

static int rsi_entry_expire_seq_show(struct seq_file *m,
				     void *data)
{
	seq_printf(m, "%lld\n", rsicache->uc_entry_expire);
	return 0;
}

static ssize_t rsi_entry_expire_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	time64_t val;
	int rc;

	rc = kstrtoll_from_user(buffer, count, 10, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -ERANGE;

	rsicache->uc_entry_expire = val;

	return count;
}
LDEBUGFS_SEQ_FOPS(rsi_entry_expire);

static int rsi_acquire_expire_seq_show(struct seq_file *m,
				       void *data)
{
	seq_printf(m, "%lld\n", rsicache->uc_acquire_expire);
	return 0;
}

static ssize_t rsi_acquire_expire_seq_write(struct file *file,
					    const char __user *buffer,
					    size_t count, loff_t *off)
{
	time64_t val;
	int rc;

	rc = kstrtoll_from_user(buffer, count, 10, &val);
	if (rc)
		return rc;

	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	rsicache->uc_acquire_expire = val;

	return count;
}
LDEBUGFS_SEQ_FOPS(rsi_acquire_expire);

static ssize_t ldebugfs_rsc_info_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count, void *data)
{
	struct rsc_downcall_data *param;
	int size = sizeof(*param), rc, checked = 0;
	struct gss_rsc rsc = { 0 }, *rscp = NULL;
	char *mesg, *handle_buf;

again:
	if (count < size) {
		CERROR("%s: invalid data count = %lu, size = %d\n",
		       rsccache->uc_name, (unsigned long)count, size);
		return -EINVAL;
	}

	OBD_ALLOC_LARGE(param, size);
	if (param == NULL)
		return -ENOMEM;

	if (copy_from_user(param, buffer, size)) {
		CERROR("%s: bad rsc data\n", rsccache->uc_name);
		GOTO(out, rc = -EFAULT);
	}

	if (checked == 0) {
		checked = 1;
		if (param->scd_magic != RSC_DOWNCALL_MAGIC) {
			CERROR("%s: rsc downcall bad params\n",
			       rsccache->uc_name);
			GOTO(out, rc = -EINVAL);
		}

		rc = param->scd_len; /* save scd_len */
		OBD_FREE_LARGE(param, size);
		size = offsetof(struct rsc_downcall_data, scd_val[rc]);
		goto again;
	}

	/* scd_val starts with handle.
	 * Use it to create cache entry.
	 */
	mesg = param->scd_val;
	gss_u32_read(&mesg, &rsc.sc_handle.len);
	if (!rsc.sc_handle.len) {
		rc = -EINVAL;
		goto out;
	}
	OBD_ALLOC_LARGE(handle_buf, rsc.sc_handle.len);
	if (!handle_buf) {
		rc = -ENOMEM;
		goto out;
	}
	memset(handle_buf, 0, rsc.sc_handle.len);
	mesg = param->scd_val;
	rc = gss_buffer_read(&mesg, handle_buf, rsc.sc_handle.len);
	if (rc < 0) {
		OBD_FREE_LARGE(handle_buf, rsc.sc_handle.len);
		rc = -EINVAL;
		goto out;
	}
	rsc.sc_handle.data = handle_buf;

	/* create cache entry on-the-fly */
	rscp = rsc_entry_get(rsccache, &rsc);
	__rsc_free(&rsc);

	if (IS_ERR_OR_NULL(rscp)) {
		if (IS_ERR(rscp))
			rc = PTR_ERR(rscp);
		else
			rc = -EINVAL;
		CERROR("%s: error in rsc_entry_get: rc = %d\n",
		       param->scd_mechname, rc);
		goto out;
	}

	/* now that entry has been created, downcall can be done,
	 * but we have to tell acquiring is in progress
	 */
	upcall_cache_update_entry(rsccache, rscp->sc_uc_entry,
				  0, UC_CACHE_ACQUIRING);
	rc = upcall_cache_downcall(rsccache, param->scd_err,
				   rscp->sc_uc_entry->ue_key, param);

out:
	if (!IS_ERR_OR_NULL(rscp))
		rsc_entry_put(rsccache, rscp);
	if (param)
		OBD_FREE_LARGE(param, size);

	return rc ? rc : count;
}
LDEBUGFS_FOPS_WR_ONLY(gss, rsc_info);

static struct ldebugfs_vars gss_debugfs_vars[] = {
	{ .name	=	"replays",
	  .fops	=	&gss_proc_oos_fops	},
	{ .name	=	"krb5_allow_old_client_csum",
	  .fops	=	&sptlrpc_krb5_allow_old_client_csum_fops },
	{ .name	=	"rsi_upcall",
	  .fops	=	&rsi_upcall_fops },
	{ .name =	"rsi_info",
	  .fops =	&gss_rsi_info_fops },
	{ .name	=	"rsi_entry_expire",
	  .fops	=	&rsi_entry_expire_fops },
	{ .name	=	"rsi_acquire_expire",
	  .fops	=	&rsi_acquire_expire_fops },
	{ .name =	"rsc_info",
	  .fops =	&gss_rsc_info_fops },
	{ NULL }
};

/*
 * for userspace helper lgss_keyring.
 *
 * debug_level: [0, 4], defined in utils/gss/lgss_utils.h
 */
static int gss_lk_debug_level = 1;

static ssize_t debug_level_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", gss_lk_debug_level);
}

static ssize_t debug_level_store(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int val;
	int rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val > 4)
		return -ERANGE;

	gss_lk_debug_level = val;

	return count;
}
LUSTRE_RW_ATTR(debug_level);

static struct attribute *gss_attrs[] = {
	&lustre_attr_init_channel.attr,
#ifdef HAVE_GSS_KEYRING
	&lustre_attr_gss_check_upcall_ns.attr,
#endif
	NULL
};

static struct attribute_group gss_attr_group = {
	.attrs = gss_attrs,
};

static struct attribute *gss_lk_attrs[] = {
	&lustre_attr_debug_level.attr,
	NULL
};

static struct attribute_group gss_lk_attr_group = {
	.attrs = gss_lk_attrs,
};

void gss_exit_tunables(void)
{
	if (gss_kobj_lk) {
		sysfs_remove_group(gss_kobj_lk, &gss_lk_attr_group);
		kobject_put(gss_kobj_lk);
	}

	if (gss_kobj) {
		sysfs_remove_group(gss_kobj, &gss_attr_group);
		kobject_put(gss_kobj);
	}

	debugfs_remove_recursive(gss_debugfs_dir);
	gss_debugfs_dir = NULL;
}

int gss_init_tunables(void)
{
	int rc;
	spin_lock_init(&gss_stat_oos.oos_lock);

	gss_debugfs_dir = debugfs_create_dir("gss", sptlrpc_debugfs_dir);
	ldebugfs_add_vars(gss_debugfs_dir, gss_debugfs_vars, NULL);

	gss_kobj = kobject_create_and_add("gss", sptlrpc_kobj);
	if (!gss_kobj)
		GOTO(out, rc = -ENOMEM);

	rc = sysfs_create_group(gss_kobj, &gss_attr_group);
	if (rc)
		GOTO(out, rc);

	gss_kobj_lk = kobject_create_and_add("lgss_keyring", gss_kobj);
	if (!gss_kobj_lk)
		GOTO(out, rc = -ENOMEM);

	rc = sysfs_create_group(gss_kobj_lk, &gss_lk_attr_group);
	if (rc)
		GOTO(out, rc);

	return 0;
out:
	gss_exit_tunables();
	return rc;
}
