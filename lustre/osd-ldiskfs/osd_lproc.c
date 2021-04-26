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
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osd/osd_lproc.c
 *
 * Author: Mikhail Pershin <tappro@sun.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <lprocfs_status.h>

#include "osd_internal.h"

#ifdef CONFIG_PROC_FS

void osd_brw_stats_update(struct osd_device *osd, struct osd_iobuf *iobuf)
{
        struct brw_stats *s = &osd->od_brw_stats;
	sector_t	 *last_block = NULL;
        struct page     **pages = iobuf->dr_pages;
        struct page      *last_page = NULL;
        unsigned long     discont_pages = 0;
        unsigned long     discont_blocks = 0;
	sector_t	 *blocks = iobuf->dr_blocks;
        int               i, nr_pages = iobuf->dr_npages;
        int               blocks_per_page;
        int               rw = iobuf->dr_rw;

        if (unlikely(nr_pages == 0))
                return;

	blocks_per_page = PAGE_SIZE >> osd_sb(osd)->s_blocksize_bits;

        lprocfs_oh_tally_log2(&s->hist[BRW_R_PAGES+rw], nr_pages);

        while (nr_pages-- > 0) {
                if (last_page && (*pages)->index != (last_page->index + 1))
                        discont_pages++;
                last_page = *pages;
                pages++;
                for (i = 0; i < blocks_per_page; i++) {
                        if (last_block && *blocks != (*last_block + 1))
                                discont_blocks++;
                        last_block = blocks++;
                }
        }

        lprocfs_oh_tally(&s->hist[BRW_R_DISCONT_PAGES+rw], discont_pages);
        lprocfs_oh_tally(&s->hist[BRW_R_DISCONT_BLOCKS+rw], discont_blocks);
}

static void display_brw_stats(struct seq_file *seq, char *name, char *units,
        struct obd_histogram *read, struct obd_histogram *write, int scale)
{
        unsigned long read_tot, write_tot, r, w, read_cum = 0, write_cum = 0;
        int i;

        seq_printf(seq, "\n%26s read      |     write\n", " ");
        seq_printf(seq, "%-22s %-5s %% cum %% |  %-11s %% cum %%\n",
                   name, units, units);

        read_tot = lprocfs_oh_sum(read);
        write_tot = lprocfs_oh_sum(write);
        for (i = 0; i < OBD_HIST_MAX; i++) {
                r = read->oh_buckets[i];
                w = write->oh_buckets[i];
                read_cum += r;
                write_cum += w;
                if (read_cum == 0 && write_cum == 0)
                        continue;

                if (!scale)
                        seq_printf(seq, "%u", i);
                else if (i < 10)
                        seq_printf(seq, "%u", scale << i);
                else if (i < 20)
                        seq_printf(seq, "%uK", scale << (i-10));
                else
                        seq_printf(seq, "%uM", scale << (i-20));

		seq_printf(seq, ":\t\t%10lu %3u %3u   | %4lu %3u %3u\n",
                           r, pct(r, read_tot), pct(read_cum, read_tot),
                           w, pct(w, write_tot), pct(write_cum, write_tot));

                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }
}

static void brw_stats_show(struct seq_file *seq, struct brw_stats *brw_stats)
{
	struct timespec64 now;

	/* this sampling races with updates */
	ktime_get_real_ts64(&now);

	seq_printf(seq, "snapshot_time:         %lld.%09ld (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);

        display_brw_stats(seq, "pages per bulk r/w", "rpcs",
                          &brw_stats->hist[BRW_R_PAGES],
                          &brw_stats->hist[BRW_W_PAGES], 1);

        display_brw_stats(seq, "discontiguous pages", "rpcs",
                          &brw_stats->hist[BRW_R_DISCONT_PAGES],
                          &brw_stats->hist[BRW_W_DISCONT_PAGES], 0);

        display_brw_stats(seq, "discontiguous blocks", "rpcs",
                          &brw_stats->hist[BRW_R_DISCONT_BLOCKS],
                          &brw_stats->hist[BRW_W_DISCONT_BLOCKS], 0);

        display_brw_stats(seq, "disk fragmented I/Os", "ios",
                          &brw_stats->hist[BRW_R_DIO_FRAGS],
                          &brw_stats->hist[BRW_W_DIO_FRAGS], 0);

        display_brw_stats(seq, "disk I/Os in flight", "ios",
                          &brw_stats->hist[BRW_R_RPC_HIST],
                          &brw_stats->hist[BRW_W_RPC_HIST], 0);

	display_brw_stats(seq, "I/O time (1/1000s)", "ios",
			  &brw_stats->hist[BRW_R_IO_TIME],
			  &brw_stats->hist[BRW_W_IO_TIME], 1);

        display_brw_stats(seq, "disk I/O size", "ios",
                          &brw_stats->hist[BRW_R_DISK_IOSIZE],
                          &brw_stats->hist[BRW_W_DISK_IOSIZE], 1);
}

static int osd_brw_stats_seq_show(struct seq_file *seq, void *v)
{
        struct osd_device *osd = seq->private;

        brw_stats_show(seq, &osd->od_brw_stats);

        return 0;
}

static ssize_t osd_brw_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
        struct osd_device *osd = seq->private;
        int i;

        for (i = 0; i < BRW_LAST; i++)
                lprocfs_oh_clear(&osd->od_brw_stats.hist[i]);

        return len;
}

LPROC_SEQ_FOPS(osd_brw_stats);

static int osd_stats_init(struct osd_device *osd)
{
        int i, result;
        ENTRY;

        for (i = 0; i < BRW_LAST; i++)
		spin_lock_init(&osd->od_brw_stats.hist[i].oh_lock);

        osd->od_stats = lprocfs_alloc_stats(LPROC_OSD_LAST, 0);
        if (osd->od_stats != NULL) {
                result = lprocfs_register_stats(osd->od_proc_entry, "stats",
                                                osd->od_stats);
                if (result)
                        GOTO(out, result);

                lprocfs_counter_init(osd->od_stats, LPROC_OSD_GET_PAGE,
                                     LPROCFS_CNTR_AVGMINMAX|LPROCFS_CNTR_STDDEV,
                                     "get_page", "usec");
                lprocfs_counter_init(osd->od_stats, LPROC_OSD_NO_PAGE,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "get_page_failures", "num");
                lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_ACCESS,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "cache_access", "pages");
                lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_HIT,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "cache_hit", "pages");
                lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_MISS,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "cache_miss", "pages");
#if OSD_THANDLE_STATS
                lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_STARTING,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "thandle starting", "usec");
                lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_OPEN,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "thandle open", "usec");
                lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_CLOSING,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "thandle closing", "usec");
#endif
		result = lprocfs_seq_create(osd->od_proc_entry, "brw_stats",
					    0644, &osd_brw_stats_fops, osd);
        } else
                result = -ENOMEM;

out:
        RETURN(result);
}

static ssize_t fstype_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	return sprintf(buf, "ldiskfs\n");
}
LUSTRE_RO_ATTR(fstype);

static ssize_t mntdev_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%s\n", osd->od_mntdev);
}
LUSTRE_RO_ATTR(mntdev);

static ssize_t read_cache_enable_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%u\n", osd->od_read_cache);
}

static ssize_t read_cache_enable_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);
	bool val;
	int rc;

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	osd->od_read_cache = !!val;
	return count;
}
LUSTRE_RW_ATTR(read_cache_enable);

static ssize_t writethrough_cache_enable_show(struct kobject *kobj,
					      struct attribute *attr,
					      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%u\n", osd->od_writethrough_cache);
}

static ssize_t writethrough_cache_enable_store(struct kobject *kobj,
					       struct attribute *attr,
					       const char *buffer,
					       size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);
	bool val;
	int rc;

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	osd->od_writethrough_cache = !!val;
	return count;
}
LUSTRE_RW_ATTR(writethrough_cache_enable);

static ssize_t fallocate_zero_blocks_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	return scnprintf(buf, PAGE_SIZE, "%d\n", osd->od_fallocate_zero_blocks);
}

/*
 * Set how fallocate() interacts with the backing filesystem:
 * -1: fallocate is disabled and returns -EOPNOTSUPP
 *  0: fallocate allocates unwritten extents (like ext4)
 *  1: fallocate zeroes allocated extents on disk
 */
static ssize_t fallocate_zero_blocks_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);
	long val;
	int rc;

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	rc = kstrtol(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < -1 || val > 1)
		return -EINVAL;

	osd->od_fallocate_zero_blocks = val;
	return count;
}
LUSTRE_RW_ATTR(fallocate_zero_blocks);

ssize_t force_sync_store(struct kobject *kobj, struct attribute *attr,
			 const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);
	struct lu_env env;
	int rc;

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;

	rc = dt_sync(&env, dt);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}
LUSTRE_WO_ATTR(force_sync);

static ssize_t nonrotational_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%u\n", osd->od_nonrotational);
}

static ssize_t nonrotational_store(struct kobject *kobj,
				   struct attribute *attr, const char *buffer,
				   size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);
	bool val;
	int rc;

	LASSERT(osd);
	if (unlikely(!osd->od_mnt))
		return -EINPROGRESS;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	osd->od_nonrotational = val;
	return count;
}
LUSTRE_RW_ATTR(nonrotational);

static ssize_t pdo_show(struct kobject *kobj, struct attribute *attr,
			char *buf)
{
	return sprintf(buf, "%s\n", ldiskfs_pdo ? "ON" : "OFF");
}

static ssize_t pdo_store(struct kobject *kobj, struct attribute *attr,
			 const char *buffer, size_t count)
{
	bool pdo;
	int rc;

	rc = kstrtobool(buffer, &pdo);
	if (rc != 0)
		return rc;

	ldiskfs_pdo = pdo;

	return count;
}
LUSTRE_RW_ATTR(pdo);

static ssize_t auto_scrub_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%lld\n", dev->od_auto_scrub_interval);
}

static ssize_t auto_scrub_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	s64 val;
	int rc;

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	rc = kstrtoll(buffer, 0, &val);
	if (rc)
		return rc;

	dev->od_auto_scrub_interval = val;
	return count;
}
LUSTRE_RW_ATTR(auto_scrub);

static ssize_t full_scrub_ratio_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%llu\n", dev->od_full_scrub_ratio);
}

static ssize_t full_scrub_ratio_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	s64 val;
	int rc;

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	rc = kstrtoll(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -EINVAL;

	dev->od_full_scrub_ratio = val;
	return count;
}
LUSTRE_RW_ATTR(full_scrub_ratio);

static ssize_t full_scrub_threshold_rate_show(struct kobject *kobj,
					      struct attribute *attr,
					      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%llu (bad OI mappings/minute)\n",
		       dev->od_full_scrub_threshold_rate);
}

static ssize_t full_scrub_threshold_rate_store(struct kobject *kobj,
					       struct attribute *attr,
					       const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	u64 val;
	int rc;

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	rc = kstrtoull(buffer, 0, &val);
	if (rc != 0)
		return rc;

	dev->od_full_scrub_threshold_rate = val;
	return count;
}
LUSTRE_RW_ATTR(full_scrub_threshold_rate);

static ssize_t extent_bytes_allocation_show(struct kobject *kobj,
					    struct attribute *attr, char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	int i;
	unsigned int min = (unsigned int)(~0), cur;

	for_each_online_cpu(i) {
		cur = *per_cpu_ptr(dev->od_extent_bytes_percpu, i);
		if (cur < min)
			min = cur;
	}
	return snprintf(buf, PAGE_SIZE, "%u\n", min);
}
LUSTRE_RO_ATTR(extent_bytes_allocation);

static int ldiskfs_osd_oi_scrub_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *dev = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	osd_scrub_dump(m, dev);
	return 0;
}

LDEBUGFS_SEQ_FOPS_RO(ldiskfs_osd_oi_scrub);

static int ldiskfs_osd_readcache_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%llu\n", osd->od_readcache_max_filesize);
	return 0;
}

static ssize_t
ldiskfs_osd_readcache_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	char kernbuf[22] = "";
	u64 val;
	int rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &val, "B");
	if (rc < 0)
		return rc;

	osd->od_readcache_max_filesize = val > OSD_MAX_CACHE_SIZE ?
					 OSD_MAX_CACHE_SIZE : val;
	return count;
}

LDEBUGFS_SEQ_FOPS(ldiskfs_osd_readcache);

static int ldiskfs_osd_readcache_max_io_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%lu\n", osd->od_readcache_max_iosize >> 20);
	return 0;
}

static ssize_t
ldiskfs_osd_readcache_max_io_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	char kernbuf[22] = "";
	u64 val;
	int rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &val, "MiB");
	if (rc < 0)
		return rc;

	if (val > PTLRPC_MAX_BRW_SIZE)
		return -ERANGE;
	osd->od_readcache_max_iosize = val;
	return count;
}

LDEBUGFS_SEQ_FOPS(ldiskfs_osd_readcache_max_io);

static int ldiskfs_osd_writethrough_max_io_seq_show(struct seq_file *m,
						    void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%lu\n", osd->od_writethrough_max_iosize >> 20);
	return 0;
}

static ssize_t
ldiskfs_osd_writethrough_max_io_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	char kernbuf[22] = "";
	u64 val;
	int rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &val, "MiB");
	if (rc < 0)
		return rc;

	if (val > PTLRPC_MAX_BRW_SIZE)
		return -ERANGE;
	osd->od_writethrough_max_iosize = val;
	return count;
}

LDEBUGFS_SEQ_FOPS(ldiskfs_osd_writethrough_max_io);

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 52, 0)
static ssize_t index_in_idif_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%d\n", (int)(dev->od_index_in_idif));
}

static ssize_t index_in_idif_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	struct lu_target *tgt;
	struct lu_env env;
	bool val;
	int rc;

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (dev->od_index_in_idif) {
		if (val)
			return count;

		LCONSOLE_WARN("%s: OST-index in IDIF has been enabled, "
			      "it cannot be reverted back.\n", osd_name(dev));
		return -EPERM;
	}

	if (!val)
		return count;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		return rc;

	tgt = dev->od_dt_dev.dd_lu_dev.ld_site->ls_tgt;
	tgt->lut_lsd.lsd_feature_rocompat |= OBD_ROCOMPAT_IDX_IN_IDIF;
	rc = tgt_server_data_update(&env, tgt, 1);
	lu_env_fini(&env);
	if (rc < 0)
		return rc;

	LCONSOLE_INFO("%s: enable OST-index in IDIF successfully, "
		      "it cannot be reverted back.\n", osd_name(dev));

	dev->od_index_in_idif = 1;
	return count;
}
LUSTRE_RW_ATTR(index_in_idif);

int osd_register_proc_index_in_idif(struct osd_device *osd)
{
	struct dt_device *dt = &osd->od_dt_dev;

	return sysfs_create_file(&dt->dd_kobj, &lustre_attr_index_in_idif.attr);
}
#endif

static ssize_t index_backup_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	return sprintf(buf, "%d\n", dev->od_index_backup_policy);
}

ssize_t index_backup_store(struct kobject *kobj, struct attribute *attr,
			   const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					   dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	int val;
	int rc;

	LASSERT(dev);
	if (unlikely(!dev->od_mnt))
		return -EINPROGRESS;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	dev->od_index_backup_policy = val;
	return count;
}
LUSTRE_RW_ATTR(index_backup);

struct ldebugfs_vars ldebugfs_osd_obd_vars[] = {
	{ .name	=	"oi_scrub",
	  .fops	=	&ldiskfs_osd_oi_scrub_fops	},
	{ .name	=	"readcache_max_filesize",
	  .fops	=	&ldiskfs_osd_readcache_fops	},
	{ .name	=	"readcache_max_io_mb",
	  .fops	=	&ldiskfs_osd_readcache_max_io_fops	},
	{ .name	=	"writethrough_max_io_mb",
	  .fops	=	&ldiskfs_osd_writethrough_max_io_fops	},
	{ NULL }
};

static struct attribute *ldiskfs_attrs[] = {
	&lustre_attr_read_cache_enable.attr,
	&lustre_attr_writethrough_cache_enable.attr,
	&lustre_attr_fstype.attr,
	&lustre_attr_mntdev.attr,
	&lustre_attr_fallocate_zero_blocks.attr,
	&lustre_attr_force_sync.attr,
	&lustre_attr_nonrotational.attr,
	&lustre_attr_index_backup.attr,
	&lustre_attr_auto_scrub.attr,
	&lustre_attr_pdo.attr,
	&lustre_attr_full_scrub_ratio.attr,
	&lustre_attr_full_scrub_threshold_rate.attr,
	&lustre_attr_extent_bytes_allocation.attr,
	NULL,
};

int osd_procfs_init(struct osd_device *osd, const char *name)
{
	struct obd_type	*type;
	int rc;

	ENTRY;

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way
	 */
	type = class_search_type(LUSTRE_OSD_LDISKFS_NAME);

	LASSERT(name);
	LASSERT(type);

	CDEBUG(D_CONFIG, "%s: register osd-ldiskfs tunable parameters\n", name);

	/* put reference taken by class_search_type */
	kobject_put(&type->typ_kobj);

	osd->od_dt_dev.dd_ktype.default_attrs = ldiskfs_attrs;
	rc = dt_tunables_init(&osd->od_dt_dev, type, name,
			      ldebugfs_osd_obd_vars);
	if (rc) {
		CERROR("%s: cannot setup sysfs / debugfs entry: %d\n",
		       name, rc);
		GOTO(out, rc);
	}

	if (osd->od_proc_entry)
		RETURN(0);

	/* Find the type procroot and add the proc entry for this device */
	osd->od_proc_entry = lprocfs_register(name, type->typ_procroot,
					      NULL, &osd->od_dt_dev);
	if (IS_ERR(osd->od_proc_entry)) {
		rc = PTR_ERR(osd->od_proc_entry);
		CERROR("Error %d setting up lprocfs for %s\n",
		       rc, name);
		osd->od_proc_entry = NULL;
		GOTO(out, rc);
	}

	rc = osd_stats_init(osd);

	EXIT;
out:
	if (rc)
		osd_procfs_fini(osd);
	return rc;
}

int osd_procfs_fini(struct osd_device *osd)
{
	if (osd->od_stats)
		lprocfs_free_stats(&osd->od_stats);

	if (osd->od_proc_entry)
		lprocfs_remove(&osd->od_proc_entry);

	return dt_tunables_fini(&osd->od_dt_dev);
}
#endif
