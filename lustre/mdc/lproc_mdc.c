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

#include <linux/vfs.h>
#include <obd_class.h>
#include <obd_cksum.h>
#include <lprocfs_status.h>
#include <lustre_osc.h>
#include <cl_object.h>
#include "mdc_internal.h"

static ssize_t active_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	ssize_t len;

	with_imp_locked(obd, imp, len)
		len = sprintf(buf, "%d\n", !imp->imp_deactive);
	return len;
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
		       val);
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
	ssize_t len;
	u32 max;

	max = obd_get_max_rpcs_in_flight(&obd->u.cli);
	len = sprintf(buf, "%u\n", max);

	return len;
}

static ssize_t max_rpcs_in_flight_store(struct kobject *kobj,
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

	rc = obd_set_max_rpcs_in_flight(&obd->u.cli, val);
	if (rc)
		count = rc;

	return count;
}
LUSTRE_RW_ATTR(max_rpcs_in_flight);

static ssize_t max_mod_rpcs_in_flight_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	u16 max;

	max = obd_get_max_mod_rpcs_in_flight(&obd->u.cli);
	return sprintf(buf, "%hu\n", max);
}

static ssize_t max_mod_rpcs_in_flight_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer,
					    size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	u16 val;
	int rc;

	rc = kstrtou16(buffer, 10, &val);
	if (rc)
		return rc;

	rc = obd_set_max_mod_rpcs_in_flight(&obd->u.cli, val);
	if (rc)
		count = rc;

	return count;
}
LUSTRE_RW_ATTR(max_mod_rpcs_in_flight);

static int mdc_max_dirty_mb_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;

	seq_printf(m, "%lu\n", PAGES_TO_MiB(cli->cl_dirty_max_pages));
	return 0;
}

static ssize_t mdc_max_dirty_mb_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	struct seq_file *sfl = file->private_data;
	struct obd_device *obd = sfl->private;
	struct client_obd *cli = &obd->u.cli;
	char kernbuf[22] = "";
	u64 pages_number;
	int rc;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &pages_number, "MiB");
	if (rc < 0)
		return rc;

	/* MB -> pages */
	pages_number = round_up(pages_number, 1024 * 1024) >> PAGE_SHIFT;
	if (pages_number <= 0 ||
	    pages_number >= MiB_TO_PAGES(OSC_MAX_DIRTY_MB_MAX) ||
	    pages_number > cfs_totalram_pages() / 4) /* 1/4 of RAM */
		return -ERANGE;

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_dirty_max_pages = pages_number;
	osc_wake_cache_waiters(cli);
	spin_unlock(&cli->cl_loi_list_lock);

	return count;
}
LPROC_SEQ_FOPS(mdc_max_dirty_mb);

DECLARE_CKSUM_NAME;

static int mdc_checksum_type_seq_show(struct seq_file *m, void *v)
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

static ssize_t mdc_checksum_type_seq_write(struct file *file,
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
		if (strcasecmp(kernbuf, cksum_name[i]) == 0) {
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
LPROC_SEQ_FOPS(mdc_checksum_type);

static ssize_t checksums_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
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

static ssize_t checksum_dump_show(struct kobject *kobj,
				  struct attribute *attr, char *buf)
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

LUSTRE_ATTR(mds_conn_uuid, 0444, conn_uuid_show, NULL);
LUSTRE_RO_ATTR(conn_uuid);

LUSTRE_RW_ATTR(ping);

static int mdc_cached_mb_seq_show(struct seq_file *m, void *v)
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
static ssize_t
mdc_cached_mb_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file *sfl = file->private_data;
	struct obd_device *obd = sfl->private;
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
LPROC_SEQ_FOPS(mdc_cached_mb);

static int mdc_unstable_stats_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	long pages;
	int mb;

	pages = atomic_long_read(&cli->cl_unstable_count);
	mb    = (pages * PAGE_SIZE) >> 20;

	seq_printf(m, "unstable_pages: %20ld\n"
		   "unstable_mb:              %10d\n", pages, mb);
	return 0;
}
LPROC_SEQ_FOPS_RO(mdc_unstable_stats);

static ssize_t mdc_rpc_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;

	lprocfs_oh_clear(&cli->cl_mod_rpcs_hist);

	lprocfs_oh_clear(&cli->cl_read_rpc_hist);
	lprocfs_oh_clear(&cli->cl_write_rpc_hist);
	lprocfs_oh_clear(&cli->cl_read_page_hist);
	lprocfs_oh_clear(&cli->cl_write_page_hist);
	lprocfs_oh_clear(&cli->cl_read_offset_hist);
	lprocfs_oh_clear(&cli->cl_write_offset_hist);
	cli->cl_mod_rpcs_init = ktime_get_real();

	return len;
}

static int mdc_rpc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
	int i;

	obd_mod_rpc_stats_seq_show(cli, seq);

	spin_lock(&cli->cl_loi_list_lock);

	seq_printf(seq, "\nread RPCs in flight:  %d\n",
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
			   i, r, pct(r, read_tot), pct(read_cum, read_tot), w,
			   pct(w, write_tot), pct(write_cum, write_tot));
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
LPROC_SEQ_FOPS(mdc_rpc_stats);

static int mdc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct osc_stats *stats = &obd2osc_dev(obd)->osc_stats;

	lprocfs_stats_header(seq, ktime_get_real(), stats->os_init, 25, ":",
			     true, "");
	seq_printf(seq, "lockless_write_bytes\t\t%llu\n",
		   stats->os_lockless_writes);
	seq_printf(seq, "lockless_read_bytes\t\t%llu\n",
		   stats->os_lockless_reads);
	return 0;
}

static ssize_t mdc_stats_seq_write(struct file *file,
				   const char __user *buf,
				   size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct osc_stats *stats = &obd2osc_dev(obd)->osc_stats;

	memset(stats, 0, sizeof(*stats));
	stats->os_init = ktime_get_real();

	return len;
}
LPROC_SEQ_FOPS(mdc_stats);

static int mdc_dom_min_repsize_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;

	seq_printf(m, "%u\n", obd->u.cli.cl_dom_min_inline_repsize);

	return 0;
}

static ssize_t mdc_dom_min_repsize_seq_write(struct file *file,
					     const char __user *buffer,
					     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	unsigned int val;
	int rc;

	rc = kstrtouint_from_user(buffer, count, 0, &val);
	if (rc)
		return rc;

	if (val > MDC_DOM_MAX_INLINE_REPSIZE)
		return -ERANGE;

	obd->u.cli.cl_dom_min_inline_repsize = val;
	return count;
}
LPROC_SEQ_FOPS(mdc_dom_min_repsize);

static int mdc_lsom_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;

	seq_printf(m, "%s\n", dev->u.cli.cl_lsom_update ? "On" : "Off");

	return 0;
}

static ssize_t mdc_lsom_seq_write(struct file *file,
				  const char __user *buffer,
				  size_t count, loff_t *off)
{
	struct obd_device *dev;
	bool val;
	int rc;

	dev =  ((struct seq_file *)file->private_data)->private;
	rc = kstrtobool_from_user(buffer, count, &val);
	if (rc)
		return rc;

	dev->u.cli.cl_lsom_update = val;
	return count;
}
LPROC_SEQ_FOPS(mdc_lsom);


LPROC_SEQ_FOPS_RO_TYPE(mdc, connect_flags);
LPROC_SEQ_FOPS_RO_TYPE(mdc, server_uuid);
LPROC_SEQ_FOPS_RO_TYPE(mdc, timeouts);
LPROC_SEQ_FOPS_RO_TYPE(mdc, state);
LPROC_SEQ_FOPS_RW_TYPE(mdc, obd_max_pages_per_rpc);
LPROC_SEQ_FOPS_RW_TYPE(mdc, import);
LPROC_SEQ_FOPS_RW_TYPE(mdc, pinger_recov);

struct lprocfs_vars lprocfs_mdc_obd_vars[] = {
	{ .name	=	"connect_flags",
	  .fops	=	&mdc_connect_flags_fops	},
	{ .name	=	"mds_server_uuid",
	  .fops	=	&mdc_server_uuid_fops	},
	{ .name =	"max_pages_per_rpc",
	  .fops =	&mdc_obd_max_pages_per_rpc_fops },
	{ .name =	"max_dirty_mb",
	  .fops =	&mdc_max_dirty_mb_fops		},
	{ .name	=	"mdc_cached_mb",
	  .fops	=	&mdc_cached_mb_fops		},
	{ .name	=	"checksum_type",
	  .fops	=	&mdc_checksum_type_fops		},
	{ .name	=	"timeouts",
	  .fops	=	&mdc_timeouts_fops		},
	{ .name	=	"import",
	  .fops	=	&mdc_import_fops		},
	{ .name	=	"state",
	  .fops	=	&mdc_state_fops			},
	{ .name	=	"pinger_recov",
	  .fops	=	&mdc_pinger_recov_fops		},
	{ .name	=	"rpc_stats",
	  .fops	=	&mdc_rpc_stats_fops		},
	{ .name	=	"unstable_stats",
	  .fops	=	&mdc_unstable_stats_fops	},
	{ .name	=	"mdc_stats",
	  .fops	=	&mdc_stats_fops			},
	{ .name	=	"mdc_dom_min_repsize",
	  .fops	=	&mdc_dom_min_repsize_fops	},
	{ .name =	"mdc_lsom",
	  .fops =	&mdc_lsom_fops			},
	{ NULL }
};

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

static struct attribute *mdc_attrs[] = {
	&lustre_attr_active.attr,
	&lustre_attr_checksums.attr,
	&lustre_attr_checksum_dump.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_max_mod_rpcs_in_flight.attr,
	&lustre_attr_mds_conn_uuid.attr,
	&lustre_attr_conn_uuid.attr,
	&lustre_attr_ping.attr,
	&lustre_attr_grant_shrink.attr,
	&lustre_attr_grant_shrink_interval.attr,
	&lustre_attr_cur_lost_grant_bytes.attr,
	&lustre_attr_cur_dirty_grant_bytes.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(mdc); /* creates mdc_groups */

int mdc_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_ktype.default_groups = KOBJ_ATTR_GROUPS(mdc);
	obd->obd_vars = lprocfs_mdc_obd_vars;

	rc = lprocfs_obd_setup(obd, false);
	if (rc)
		goto out_failed;
#ifdef CONFIG_PROC_FS
	rc = lprocfs_alloc_md_stats(obd, 0);
	if (rc) {
		lprocfs_obd_cleanup(obd);
		goto out_failed;
	}
#endif
	rc = sptlrpc_lprocfs_cliobd_attach(obd);
	if (rc) {
#ifdef CONFIG_PROC_FS
		lprocfs_free_md_stats(obd);
#endif
		lprocfs_obd_cleanup(obd);
		goto out_failed;
	}
	ptlrpc_lprocfs_register_obd(obd);

out_failed:
	return rc;
}
