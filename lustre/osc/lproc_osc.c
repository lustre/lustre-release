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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <asm/statfs.h>
#include <obd_cksum.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>
#include <lustre_osc.h>

#include "osc_internal.h"

static ssize_t active_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	int rc;

	with_imp_locked(obd, imp, rc)
		rc = sprintf(buf, "%d\n", !imp->imp_deactive);

	return rc;
}

static ssize_t active_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp, *imp0;
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	with_imp_locked(obd, imp0, rc)
		imp = class_import_get(imp0);
	if (rc)
		return rc;
	/* opposite senses */
	if (imp->imp_deactive == val)
		rc = ptlrpc_set_import_active(imp, val);
	else
		CDEBUG(D_CONFIG, "activate %u: ignoring repeat request\n",
		       (unsigned int)val);
	class_import_put(imp);

	return rc ?: count;
}
LUSTRE_RW_ATTR(active);

static ssize_t max_rpcs_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return  scnprintf(buf, PAGE_SIZE, "%u\n", cli->cl_max_rpcs_in_flight);
}

static ssize_t max_rpcs_in_flight_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	int adding, added, req_count;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val == 0 || val > OSC_MAX_RIF_MAX)
		return -ERANGE;

	adding = (int)val - cli->cl_max_rpcs_in_flight;
	req_count = atomic_read(&osc_pool_req_count);
	if (adding > 0 && req_count < osc_reqpool_maxreqcount) {
		/*
		 * There might be some race which will cause over-limit
		 * allocation, but it is fine.
		 */
		if (req_count + adding > osc_reqpool_maxreqcount)
			adding = osc_reqpool_maxreqcount - req_count;

		added = osc_rq_pool->prp_populate(osc_rq_pool, adding);
		atomic_add(added, &osc_pool_req_count);
	}

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_max_rpcs_in_flight = val;
	client_adjust_max_dirty(cli);
	spin_unlock(&cli->cl_loi_list_lock);

	return count;
}
LUSTRE_RW_ATTR(max_rpcs_in_flight);

static ssize_t max_dirty_mb_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			 PAGES_TO_MiB(cli->cl_dirty_max_pages));
}

static ssize_t max_dirty_mb_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buffer,
				  size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	unsigned long pages_number, max_dirty_mb;
	int rc;

	rc = kstrtoul(buffer, 10, &max_dirty_mb);
	if (rc)
		return rc;

	pages_number = MiB_TO_PAGES(max_dirty_mb);

	if (pages_number >= MiB_TO_PAGES(OSC_MAX_DIRTY_MB_MAX) ||
	    pages_number > cfs_totalram_pages() / 4) /* 1/4 of RAM */
		return -ERANGE;

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_dirty_max_pages = pages_number;
	osc_wake_cache_waiters(cli);
	spin_unlock(&cli->cl_loi_list_lock);

	return count;
}
LUSTRE_RW_ATTR(max_dirty_mb);

LUSTRE_ATTR(ost_conn_uuid, 0444, conn_uuid_show, NULL);
LUSTRE_RO_ATTR(conn_uuid);

LUSTRE_RW_ATTR(ping);

static int osc_cached_mb_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	int shift = 20 - PAGE_SHIFT;

	seq_printf(m, "used_mb: %ld\n"
		   "busy_cnt: %ld\n"
		   "reclaim: %llu\n",
		   (atomic_long_read(&cli->cl_lru_in_list) +
		    atomic_long_read(&cli->cl_lru_busy)) >> shift,
		    atomic_long_read(&cli->cl_lru_busy),
		   cli->cl_lru_reclaim);

	return 0;
}

/* shrink the number of caching pages to a specific number */
static ssize_t osc_cached_mb_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	u64 pages_number;
	const char *tmp;
	long rc;
	char kernbuf[128];

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	tmp = lprocfs_find_named_value(kernbuf, "used_mb:", &count);
	rc = sysfs_memparse(tmp, count, &pages_number, "MiB");
	if (rc < 0)
		return rc;

	pages_number >>= PAGE_SHIFT;

	rc = atomic_long_read(&cli->cl_lru_in_list) - pages_number;
	if (rc > 0) {
		struct lu_env *env;
		__u16 refcheck;

		env = cl_env_get(&refcheck);
		if (!IS_ERR(env)) {
			(void)osc_lru_shrink(env, cli, rc, true);
			cl_env_put(env, &refcheck);
		}
	}

	return count;
}

LPROC_SEQ_FOPS(osc_cached_mb);

static ssize_t cur_dirty_bytes_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			 cli->cl_dirty_pages << PAGE_SHIFT);
}
LUSTRE_RO_ATTR(cur_dirty_bytes);

static int osc_cur_grant_bytes_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;

	seq_printf(m, "%lu\n", cli->cl_avail_grant);
	return 0;
}

static ssize_t osc_cur_grant_bytes_seq_write(struct file *file,
					     const char __user *buffer,
					     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	struct obd_import *imp;
	char kernbuf[22] = "";
	u64 val;
	int rc;

	if (obd == NULL)
		return 0;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &val, "MiB");
	if (rc < 0)
		return rc;

	/* this is only for shrinking grant */
	if (val >= cli->cl_avail_grant)
		return 0;

	with_imp_locked(obd, imp, rc)
		if (imp->imp_state == LUSTRE_IMP_FULL)
			rc = osc_shrink_grant_to_target(cli, val);

	return rc ? rc : count;
}
LPROC_SEQ_FOPS(osc_cur_grant_bytes);

static ssize_t cur_lost_grant_bytes_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n", cli->cl_lost_grant);
}
LUSTRE_RO_ATTR(cur_lost_grant_bytes);

static ssize_t cur_dirty_grant_bytes_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n", cli->cl_dirty_grant);
}
LUSTRE_RO_ATTR(cur_dirty_grant_bytes);

static ssize_t grant_shrink_interval_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%lld\n", obd->u.cli.cl_grant_shrink_interval);
}

static ssize_t grant_shrink_interval_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer,
					   size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val == 0)
		return -ERANGE;

	obd->u.cli.cl_grant_shrink_interval = val;
	osc_update_next_shrink(&obd->u.cli);
	osc_schedule_grant_work();

	return count;
}
LUSTRE_RW_ATTR(grant_shrink_interval);

static ssize_t checksums_show(struct kobject *kobj,
			      struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", !!obd->u.cli.cl_checksum);
}

static ssize_t checksums_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buffer,
			       size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	obd->u.cli.cl_checksum = val;

	return count;
}
LUSTRE_RW_ATTR(checksums);

DECLARE_CKSUM_NAME;

static int osc_checksum_type_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	int i;

	if (obd == NULL)
		return 0;

	for (i = 0; i < ARRAY_SIZE(cksum_name); i++) {
		if ((BIT(i) & obd->u.cli.cl_supp_cksum_types) == 0)
			continue;
		if (obd->u.cli.cl_cksum_type == BIT(i))
			seq_printf(m, "[%s] ", cksum_name[i]);
		else
			seq_printf(m, "%s ", cksum_name[i]);
	}
	seq_puts(m, "\n");

	return 0;
}

static ssize_t osc_checksum_type_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	char kernbuf[10];
	int rc = -EINVAL;
	int i;

	if (obd == NULL)
		return 0;

	if (count > sizeof(kernbuf) - 1)
		return -EINVAL;
	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;

	if (count > 0 && kernbuf[count - 1] == '\n')
		kernbuf[count - 1] = '\0';
	else
		kernbuf[count] = '\0';

	for (i = 0; i < ARRAY_SIZE(cksum_name); i++) {
		if (strcmp(kernbuf, cksum_name[i]) == 0) {
			obd->u.cli.cl_preferred_cksum_type = BIT(i);
			if (obd->u.cli.cl_supp_cksum_types & BIT(i)) {
				obd->u.cli.cl_cksum_type = BIT(i);
				rc = count;
			} else {
				rc = -ENOTSUPP;
			}
			break;
		}
	}
	return rc;
}
LPROC_SEQ_FOPS(osc_checksum_type);

static ssize_t resend_count_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%u\n", atomic_read(&obd->u.cli.cl_resends));
}

static ssize_t resend_count_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buffer,
				  size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	atomic_set(&obd->u.cli.cl_resends, val);

	return count;
}
LUSTRE_RW_ATTR(resend_count);

static ssize_t checksum_dump_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", !!obd->u.cli.cl_checksum_dump);
}

static ssize_t checksum_dump_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	obd->u.cli.cl_checksum_dump = val;

	return count;
}
LUSTRE_RW_ATTR(checksum_dump);

static ssize_t contention_seconds_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct osc_device *od = obd2osc_dev(obd);

	return sprintf(buf, "%lld\n", od->od_contention_time);
}

static ssize_t contention_seconds_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct osc_device *od = obd2osc_dev(obd);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	od->od_contention_time = val;

	return count;
}
LUSTRE_RW_ATTR(contention_seconds);

static ssize_t lockless_truncate_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct osc_device *od = obd2osc_dev(obd);

	return sprintf(buf, "%u\n", od->od_lockless_truncate);
}

static ssize_t lockless_truncate_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer,
				       size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct osc_device *od = obd2osc_dev(obd);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	od->od_lockless_truncate = val;

	return count;
}
LUSTRE_RW_ATTR(lockless_truncate);

static ssize_t destroys_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%u\n",
		       atomic_read(&obd->u.cli.cl_destroy_in_flight));
}
LUSTRE_RO_ATTR(destroys_in_flight);

LPROC_SEQ_FOPS_RW_TYPE(osc, obd_max_pages_per_rpc);

LUSTRE_RW_ATTR(short_io_bytes);

#ifdef CONFIG_PROC_FS
static int osc_unstable_stats_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	long pages;
	int mb;

	pages = atomic_long_read(&cli->cl_unstable_count);
	mb    = (pages * PAGE_SIZE) >> 20;

	seq_printf(m, "unstable_pages: %20ld\n"
		   "unstable_mb:              %10d\n",
		   pages, mb);
	return 0;
}
LPROC_SEQ_FOPS_RO(osc_unstable_stats);

static ssize_t idle_timeout_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	int ret;

	with_imp_locked(obd, imp, ret)
		ret = sprintf(buf, "%u\n", imp->imp_idle_timeout);

	return ret;
}

static ssize_t idle_timeout_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	struct ptlrpc_request *req;
	unsigned int idle_debug = 0;
	unsigned int val;
	int rc;

	if (strncmp(buffer, "debug", 5) == 0) {
		idle_debug = D_CONSOLE;
	} else if (strncmp(buffer, "nodebug", 6) == 0) {
		idle_debug = D_HA;
	} else {
		rc = kstrtouint(buffer, 10, &val);
		if (rc)
			return rc;

		if (val > CONNECTION_SWITCH_MAX)
			return -ERANGE;
	}

	with_imp_locked(obd, imp, rc) {
		if (idle_debug) {
			imp->imp_idle_debug = idle_debug;
		} else {
			if (!val) {
				/* initiate the connection if it's in IDLE state */
				req = ptlrpc_request_alloc(imp,
							   &RQF_OST_STATFS);
				if (req != NULL)
					ptlrpc_req_finished(req);
			}
			imp->imp_idle_timeout = val;
		}
	}

	return count;
}
LUSTRE_RW_ATTR(idle_timeout);

static ssize_t idle_connect_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	struct ptlrpc_request *req;
	int rc;

	with_imp_locked(obd, imp, rc) {
		/* to initiate the connection if it's in IDLE state */
		req = ptlrpc_request_alloc(imp, &RQF_OST_STATFS);
		if (req)
			ptlrpc_req_finished(req);
		ptlrpc_pinger_force(imp);
	}

	return rc ?: count;
}
LUSTRE_WO_ATTR(idle_connect);

static ssize_t grant_shrink_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	ssize_t len;

	with_imp_locked(obd, imp, len)
		len = scnprintf(buf, PAGE_SIZE, "%d\n",
				!imp->imp_grant_shrink_disabled &&
				OCD_HAS_FLAG(&imp->imp_connect_data,
					     GRANT_SHRINK));

	return len;
}

static ssize_t grant_shrink_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	bool val;
	int rc;

	if (obd == NULL)
		return 0;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	with_imp_locked(obd, imp, rc) {
		spin_lock(&imp->imp_lock);
		imp->imp_grant_shrink_disabled = !val;
		spin_unlock(&imp->imp_lock);
	}

	return rc ?: count;
}
LUSTRE_RW_ATTR(grant_shrink);

LPROC_SEQ_FOPS_RO_TYPE(osc, connect_flags);
LPROC_SEQ_FOPS_RO_TYPE(osc, server_uuid);
LPROC_SEQ_FOPS_RO_TYPE(osc, timeouts);
LPROC_SEQ_FOPS_RO_TYPE(osc, state);

LPROC_SEQ_FOPS_RW_TYPE(osc, import);
LPROC_SEQ_FOPS_RW_TYPE(osc, pinger_recov);

struct lprocfs_vars lprocfs_osc_obd_vars[] = {
	{ .name	=	"connect_flags",
	  .fops	=	&osc_connect_flags_fops		},
	{ .name	=	"ost_server_uuid",
	  .fops	=	&osc_server_uuid_fops		},
	{ .name =	"max_pages_per_rpc",
	  .fops =	&osc_obd_max_pages_per_rpc_fops	},
	{ .name	=	"osc_cached_mb",
	  .fops	=	&osc_cached_mb_fops		},
	{ .name =	"cur_grant_bytes",
	  .fops =	&osc_cur_grant_bytes_fops	},
	{ .name	=	"checksum_type",
	  .fops	=	&osc_checksum_type_fops		},
	{ .name	=	"timeouts",
	  .fops	=	&osc_timeouts_fops		},
	{ .name	=	"import",
	  .fops	=	&osc_import_fops		},
	{ .name	=	"state",
	  .fops	=	&osc_state_fops			},
	{ .name	=	"pinger_recov",
	  .fops	=	&osc_pinger_recov_fops		},
	{ .name	=	"unstable_stats",
	  .fops	=	&osc_unstable_stats_fops	},
	{ NULL }
};

static int osc_rpc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct timespec64 now;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
	int i;

	ktime_get_real_ts64(&now);

	spin_lock(&cli->cl_loi_list_lock);

	seq_printf(seq, "snapshot_time:         %lld.%09lu (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);
	seq_printf(seq, "read RPCs in flight:  %d\n",
		   cli->cl_r_in_flight);
	seq_printf(seq, "write RPCs in flight: %d\n",
		   cli->cl_w_in_flight);
	seq_printf(seq, "pending write pages:  %d\n",
		   atomic_read(&cli->cl_pending_w_pages));
	seq_printf(seq, "pending read pages:   %d\n",
		   atomic_read(&cli->cl_pending_r_pages));

	seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
	seq_printf(seq, "pages per rpc         rpcs   %% cum %% |");
	seq_printf(seq, "       rpcs   %% cum %%\n");

	read_tot = lprocfs_oh_sum(&cli->cl_read_page_hist);
	write_tot = lprocfs_oh_sum(&cli->cl_write_page_hist);

	read_cum = 0;
	write_cum = 0;
	for (i = 0; i < OBD_HIST_MAX; i++) {
		unsigned long r = cli->cl_read_page_hist.oh_buckets[i];
		unsigned long w = cli->cl_write_page_hist.oh_buckets[i];

		read_cum += r;
		write_cum += w;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u   | %10lu %3u %3u\n",
			   1 << i, r, pct(r, read_tot),
			   pct(read_cum, read_tot), w,
			   pct(w, write_tot),
			   pct(write_cum, write_tot));
		if (read_cum == read_tot && write_cum == write_tot)
			break;
	}

	seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
	seq_printf(seq, "rpcs in flight        rpcs   %% cum %% |");
	seq_printf(seq, "       rpcs   %% cum %%\n");

	read_tot = lprocfs_oh_sum(&cli->cl_read_rpc_hist);
	write_tot = lprocfs_oh_sum(&cli->cl_write_rpc_hist);

        read_cum = 0;
        write_cum = 0;
        for (i = 1; i < OBD_HIST_MAX; i++) {
                unsigned long r = cli->cl_read_rpc_hist.oh_buckets[i];
                unsigned long w = cli->cl_write_rpc_hist.oh_buckets[i];
                read_cum += r;
                write_cum += w;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u   | %10lu %3u %3u\n",
			   i, r, pct(r, read_tot),
			   pct(read_cum, read_tot), w,
			   pct(w, write_tot),
			   pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "offset                rpcs   %% cum %% |");
        seq_printf(seq, "       rpcs   %% cum %%\n");

        read_tot = lprocfs_oh_sum(&cli->cl_read_offset_hist);
        write_tot = lprocfs_oh_sum(&cli->cl_write_offset_hist);

        read_cum = 0;
        write_cum = 0;
        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = cli->cl_read_offset_hist.oh_buckets[i];
                unsigned long w = cli->cl_write_offset_hist.oh_buckets[i];
                read_cum += r;
                write_cum += w;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u   | %10lu %3u %3u\n",
			   (i == 0) ? 0 : 1 << (i - 1),
			   r, pct(r, read_tot), pct(read_cum, read_tot),
			   w, pct(w, write_tot), pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

	spin_unlock(&cli->cl_loi_list_lock);

        return 0;
}

static ssize_t osc_rpc_stats_seq_write(struct file *file,
				       const char __user *buf,
                                       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;

	lprocfs_oh_clear(&cli->cl_read_rpc_hist);
	lprocfs_oh_clear(&cli->cl_write_rpc_hist);
	lprocfs_oh_clear(&cli->cl_read_page_hist);
	lprocfs_oh_clear(&cli->cl_write_page_hist);
	lprocfs_oh_clear(&cli->cl_read_offset_hist);
	lprocfs_oh_clear(&cli->cl_write_offset_hist);

	return len;
}
LPROC_SEQ_FOPS(osc_rpc_stats);

static int osc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct timespec64 now;
	struct obd_device *obd = seq->private;
	struct osc_stats *stats = &obd2osc_dev(obd)->od_stats;

	ktime_get_real_ts64(&now);

	seq_printf(seq, "snapshot_time:         %lld.%09lu (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);
	seq_printf(seq, "lockless_write_bytes\t\t%llu\n",
		   stats->os_lockless_writes);
	seq_printf(seq, "lockless_read_bytes\t\t%llu\n",
		   stats->os_lockless_reads);
	seq_printf(seq, "lockless_truncate\t\t%llu\n",
		   stats->os_lockless_truncates);
	return 0;
}

static ssize_t osc_stats_seq_write(struct file *file,
				   const char __user *buf,
                                   size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct osc_stats *stats = &obd2osc_dev(obd)->od_stats;

	memset(stats, 0, sizeof(*stats));
	return len;
}

LPROC_SEQ_FOPS(osc_stats);

int lprocfs_osc_attach_seqstat(struct obd_device *obd)
{
	int rc;

	rc = lprocfs_seq_create(obd->obd_proc_entry, "osc_stats", 0644,
				&osc_stats_fops, obd);
	if (rc == 0)
		rc = lprocfs_obd_seq_create(obd, "rpc_stats", 0644,
					    &osc_rpc_stats_fops, obd);

	return rc;
}
#endif /* CONFIG_PROC_FS */

static struct attribute *osc_attrs[] = {
	&lustre_attr_active.attr,
	&lustre_attr_checksums.attr,
	&lustre_attr_checksum_dump.attr,
	&lustre_attr_contention_seconds.attr,
	&lustre_attr_cur_dirty_bytes.attr,
	&lustre_attr_cur_lost_grant_bytes.attr,
	&lustre_attr_cur_dirty_grant_bytes.attr,
	&lustre_attr_destroys_in_flight.attr,
	&lustre_attr_grant_shrink_interval.attr,
	&lustre_attr_lockless_truncate.attr,
	&lustre_attr_max_dirty_mb.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_short_io_bytes.attr,
	&lustre_attr_resend_count.attr,
	&lustre_attr_ost_conn_uuid.attr,
	&lustre_attr_conn_uuid.attr,
	&lustre_attr_ping.attr,
	&lustre_attr_idle_timeout.attr,
	&lustre_attr_idle_connect.attr,
	&lustre_attr_grant_shrink.attr,
	NULL,
};

int osc_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_vars = lprocfs_osc_obd_vars;
	obd->obd_ktype.default_attrs = osc_attrs;
	rc = lprocfs_obd_setup(obd, false);
	if (rc)
		return rc;
#ifdef CONFIG_PROC_FS
	/* If the basic OSC proc tree construction succeeded then
	 * lets do the rest.
	 */
	rc = lprocfs_osc_attach_seqstat(obd);
	if (rc)
		goto obd_cleanup;

#endif /* CONFIG_PROC_FS */
	rc = sptlrpc_lprocfs_cliobd_attach(obd);
	if (rc)
		goto obd_cleanup;

	ptlrpc_lprocfs_register_obd(obd);
obd_cleanup:
	if (rc)
		lprocfs_obd_cleanup(obd);
	return rc;
}
