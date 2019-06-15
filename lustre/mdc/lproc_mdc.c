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
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/vfs.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_osc.h>
#include <cl_object.h>
#include "mdc_internal.h"

static ssize_t active_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	ssize_t len;

	LPROCFS_CLIMP_CHECK(dev);
	len = sprintf(buf, "%d\n", !dev->u.cli.cl_import->imp_deactive);
	LPROCFS_CLIMP_EXIT(dev);
	return len;
}

static ssize_t active_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	/* opposite senses */
	if (dev->u.cli.cl_import->imp_deactive == val)
		rc = ptlrpc_set_import_active(dev->u.cli.cl_import, val);
	else
		CDEBUG(D_CONFIG, "activate %u: ignoring repeat request\n",
		       val);

	return count;
}
LUSTRE_RW_ATTR(active);

static ssize_t max_rpcs_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	ssize_t len;
	u32 max;

	max = obd_get_max_rpcs_in_flight(&dev->u.cli);
	len = sprintf(buf, "%u\n", max);

	return len;
}

static ssize_t max_rpcs_in_flight_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	rc = obd_set_max_rpcs_in_flight(&dev->u.cli, val);
	if (rc)
		count = rc;

	return count;
}
LUSTRE_RW_ATTR(max_rpcs_in_flight);

static ssize_t max_mod_rpcs_in_flight_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	u16 max;

	max = obd_get_max_mod_rpcs_in_flight(&dev->u.cli);
	return sprintf(buf, "%hu\n", max);
}

static ssize_t max_mod_rpcs_in_flight_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer,
					    size_t count)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	u16 val;
	int rc;

	rc = kstrtou16(buffer, 10, &val);
	if (rc)
		return rc;

	rc = obd_set_max_mod_rpcs_in_flight(&dev->u.cli, val);
	if (rc)
		count = rc;

	return count;
}
LUSTRE_RW_ATTR(max_mod_rpcs_in_flight);

static int mdc_max_dirty_mb_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct client_obd *cli = &dev->u.cli;
	unsigned long val;

	spin_lock(&cli->cl_loi_list_lock);
	val = PAGES_TO_MiB(cli->cl_dirty_max_pages);
	spin_unlock(&cli->cl_loi_list_lock);

	seq_printf(m, "%lu\n", val);
	return 0;
}

static ssize_t mdc_max_dirty_mb_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	struct seq_file *sfl = file->private_data;
	struct obd_device *dev = sfl->private;
	struct client_obd *cli = &dev->u.cli;
	s64 pages_number;
	int rc;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &pages_number, 'M');
	if (rc)
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
	time64_t val;
	int rc;

	rc = kstrtoll(buffer, 0, &val);
	if (rc)
		return rc;

	od->od_contention_time = val;

	return count;
}
LUSTRE_RW_ATTR(contention_seconds);

LUSTRE_ATTR(mds_conn_uuid, 0444, conn_uuid_show, NULL);
LUSTRE_RO_ATTR(conn_uuid);

LUSTRE_RW_ATTR(ping);

static int mdc_cached_mb_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct client_obd *cli = &dev->u.cli;
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
	struct obd_device *dev = sfl->private;
	struct client_obd *cli = &dev->u.cli;
	__s64 pages_number;
	long rc;
	char kernbuf[128];

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	buffer += lprocfs_find_named_value(kernbuf, "used_mb:", &count) -
		  kernbuf;
	rc = lprocfs_str_with_units_to_s64(buffer, count, &pages_number, 'M');
	if (rc)
		return rc;

	pages_number >>= PAGE_SHIFT;

	if (pages_number < 0)
		return -ERANGE;

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
	struct obd_device *dev = m->private;
	struct client_obd *cli = &dev->u.cli;
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
	struct obd_device *dev = seq->private;
	struct client_obd *cli = &dev->u.cli;

	lprocfs_oh_clear(&cli->cl_mod_rpcs_hist);

	lprocfs_oh_clear(&cli->cl_read_rpc_hist);
	lprocfs_oh_clear(&cli->cl_write_rpc_hist);
	lprocfs_oh_clear(&cli->cl_read_page_hist);
	lprocfs_oh_clear(&cli->cl_write_page_hist);
	lprocfs_oh_clear(&cli->cl_read_offset_hist);
	lprocfs_oh_clear(&cli->cl_write_offset_hist);

	return len;
}

static int mdc_rpc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *dev = seq->private;
	struct client_obd *cli = &dev->u.cli;
	unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
	int i;

	obd_mod_rpc_stats_seq_show(&dev->u.cli, seq);

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
	for (i = 0; i < OBD_HIST_MAX; i++) {
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
	struct timespec64 now;
	struct obd_device *dev = seq->private;
	struct osc_stats *stats = &obd2osc_dev(dev)->od_stats;

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

static ssize_t mdc_stats_seq_write(struct file *file,
				   const char __user *buf,
				   size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *dev = seq->private;
	struct osc_stats *stats = &obd2osc_dev(dev)->od_stats;

	memset(stats, 0, sizeof(*stats));
	return len;
}
LPROC_SEQ_FOPS(mdc_stats);

static int mdc_dom_min_repsize_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;

	seq_printf(m, "%u\n", dev->u.cli.cl_dom_min_inline_repsize);

	return 0;
}

static ssize_t mdc_dom_min_repsize_seq_write(struct file *file,
					     const char __user *buffer,
					     size_t count, loff_t *off)
{
	struct obd_device *dev;
	unsigned int val;
	int rc;

	dev =  ((struct seq_file *)file->private_data)->private;
	rc = kstrtouint_from_user(buffer, count, 0, &val);
	if (rc)
		return rc;

	if (val > MDC_DOM_MAX_INLINE_REPSIZE)
		return -ERANGE;

	dev->u.cli.cl_dom_min_inline_repsize = val;
	return count;
}
LPROC_SEQ_FOPS(mdc_dom_min_repsize);

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
	{ NULL }
};

static struct attribute *mdc_attrs[] = {
	&lustre_attr_active.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_max_mod_rpcs_in_flight.attr,
	&lustre_attr_contention_seconds.attr,
	&lustre_attr_mds_conn_uuid.attr,
	&lustre_attr_conn_uuid.attr,
	&lustre_attr_ping.attr,
	NULL,
};

int mdc_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_ktype.default_attrs = mdc_attrs;
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
