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
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_lproc.c
 *
 * Author: Mikhail Pershin <tappro@sun.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>

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

#define pct(a, b) (b ? a * 100 / b : 0)

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

                seq_printf(seq, ":\t\t%10lu %3lu %3lu   | %4lu %3lu %3lu\n",
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
			  &brw_stats->hist[BRW_W_IO_TIME],
			  jiffies_to_msecs(1000) / MSEC_PER_SEC);

        display_brw_stats(seq, "disk I/O size", "ios",
                          &brw_stats->hist[BRW_R_DISK_IOSIZE],
                          &brw_stats->hist[BRW_W_DISK_IOSIZE], 1);
}

#undef pct

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

static int ldiskfs_osd_fstype_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	seq_puts(m, "ldiskfs\n");
	return 0;
}
LPROC_SEQ_FOPS_RO(ldiskfs_osd_fstype);

static int ldiskfs_osd_mntdev_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%s\n", osd->od_mntdev);
	return 0;
}
LPROC_SEQ_FOPS_RO(ldiskfs_osd_mntdev);

static int ldiskfs_osd_cache_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%u\n", osd->od_read_cache);
	return 0;
}

static ssize_t
ldiskfs_osd_cache_seq_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	int rc;
	__s64 val;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	osd->od_read_cache = !!val;
	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_cache);

static int ldiskfs_osd_wcache_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%u\n", osd->od_writethrough_cache);
	return 0;
}

static ssize_t
ldiskfs_osd_wcache_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	int rc;
	__s64 val;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	osd->od_writethrough_cache = !!val;
	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_wcache);

static ssize_t
lprocfs_osd_force_sync_seq_write(struct file *file, const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct dt_device  *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	struct lu_env	   env;
	int		   rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;
	rc = dt_sync(&env, dt);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}
LPROC_SEQ_FOPS_WO_TYPE(ldiskfs, osd_force_sync);

static int ldiskfs_osd_pdo_seq_show(struct seq_file *m, void *data)
{
	seq_printf(m, "%s\n", ldiskfs_pdo ? "ON" : "OFF");
	return 0;
}

static ssize_t
ldiskfs_osd_pdo_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	int rc;
	__s64 pdo;

	rc = lprocfs_str_to_s64(buffer, count, &pdo);
	if (rc != 0)
		return rc;

	ldiskfs_pdo = !!pdo;

	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_pdo);

static int ldiskfs_osd_auto_scrub_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *dev = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%d\n", !dev->od_noscrub);
	return 0;
}

static ssize_t
ldiskfs_osd_auto_scrub_seq_write(struct file *file, const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *dev = osd_dt_dev(dt);
	int rc;
	__s64 val;

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	dev->od_noscrub = !val;
	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_auto_scrub);

static int ldiskfs_osd_full_scrub_ratio_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *dev = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%llu\n", dev->od_full_scrub_ratio);
	return 0;
}

static ssize_t
ldiskfs_osd_full_scrub_ratio_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *dev = osd_dt_dev(dt);
	int rc;
	__s64 val;

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc != 0)
		return rc;

	if (val < 0)
		return -EINVAL;

	dev->od_full_scrub_ratio = val;
	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_full_scrub_ratio);

static int ldiskfs_osd_full_scrub_threshold_rate_seq_show(struct seq_file *m,
							  void *data)
{
	struct osd_device *dev = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%llu (bad OI mappings/minute)\n",
		   dev->od_full_scrub_threshold_rate);
	return 0;
}

static ssize_t
ldiskfs_osd_full_scrub_threshold_rate_seq_write(struct file *file,
						const char __user *buffer,
						size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *dev = osd_dt_dev(dt);
	int rc;
	__s64 val;

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc != 0)
		return rc;

	if (val < 0)
		return -EINVAL;

	dev->od_full_scrub_threshold_rate = val;
	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_full_scrub_threshold_rate);

static int
ldiskfs_osd_track_declares_assert_seq_show(struct seq_file *m, void *data)
{
	seq_printf(m, "%d\n", ldiskfs_track_declares_assert);
	return 0;
}

static ssize_t
ldiskfs_osd_track_declares_assert_seq_write(struct file *file,
						const char __user *buffer,
						size_t count, loff_t *off)
{
	__s64 track_declares_assert;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &track_declares_assert);
	if (rc != 0)
		return rc;

	ldiskfs_track_declares_assert = !!track_declares_assert;

	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_track_declares_assert);

static int ldiskfs_osd_oi_scrub_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *dev = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	return osd_scrub_dump(m, dev);
}
LPROC_SEQ_FOPS_RO(ldiskfs_osd_oi_scrub);

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
	__s64 val;
	int rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &val, '1');
	if (rc)
		return rc;
	if (val < 0)
		return -ERANGE;

	osd->od_readcache_max_filesize = val > OSD_MAX_CACHE_SIZE ?
					 OSD_MAX_CACHE_SIZE : val;
	return count;
}
LPROC_SEQ_FOPS(ldiskfs_osd_readcache);

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 52, 0)
static int ldiskfs_osd_index_in_idif_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *dev = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%d\n", (int)(dev->od_index_in_idif));
	return 0;
}

static ssize_t
ldiskfs_osd_index_in_idif_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	struct lu_env env;
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *dev = osd_dt_dev(dt);
	struct lu_target *tgt;
	__s64 val;
	int rc;

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc != 0)
		return rc;

	if (dev->od_index_in_idif) {
		if (val != 0)
			return count;

		LCONSOLE_WARN("%s: OST-index in IDIF has been enabled, "
			      "it cannot be reverted back.\n", osd_name(dev));
		return -EPERM;
	}

	if (val == 0)
		return count;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc != 0)
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
LPROC_SEQ_FOPS(ldiskfs_osd_index_in_idif);

int osd_register_proc_index_in_idif(struct osd_device *osd)
{
	struct proc_dir_entry *proc;

	proc = proc_create_data("index_in_idif", 0, osd->od_proc_entry,
				&ldiskfs_osd_index_in_idif_fops,
				&osd->od_dt_dev);
	if (proc == NULL)
		return -ENOMEM;

	return 0;
}
#endif

LPROC_SEQ_FOPS_RO_TYPE(ldiskfs, dt_blksize);
LPROC_SEQ_FOPS_RO_TYPE(ldiskfs, dt_kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(ldiskfs, dt_kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(ldiskfs, dt_kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(ldiskfs, dt_filestotal);
LPROC_SEQ_FOPS_RO_TYPE(ldiskfs, dt_filesfree);

struct lprocfs_vars lprocfs_osd_obd_vars[] = {
	{ .name	=	"blocksize",
	  .fops	=	&ldiskfs_dt_blksize_fops	},
	{ .name	=	"kbytestotal",
	  .fops	=	&ldiskfs_dt_kbytestotal_fops	},
	{ .name	=	"kbytesfree",
	  .fops	=	&ldiskfs_dt_kbytesfree_fops	},
	{ .name	=	"kbytesavail",
	  .fops	=	&ldiskfs_dt_kbytesavail_fops	},
	{ .name	=	"filestotal",
	  .fops	=	&ldiskfs_dt_filestotal_fops	},
	{ .name	=	"filesfree",
	  .fops	=	&ldiskfs_dt_filesfree_fops	},
	{ .name	=	"fstype",
	  .fops	=	&ldiskfs_osd_fstype_fops	},
	{ .name	=	"mntdev",
	  .fops	=	&ldiskfs_osd_mntdev_fops	},
	{ .name	=	"force_sync",
	  .fops	=	&ldiskfs_osd_force_sync_fops	},
	{ .name	=	"pdo",
	  .fops	=	&ldiskfs_osd_pdo_fops		},
	{ .name	=	"auto_scrub",
	  .fops	=	&ldiskfs_osd_auto_scrub_fops	},
	{ .name	=	"full_scrub_ratio",
	  .fops	=	&ldiskfs_osd_full_scrub_ratio_fops	},
	{ .name	=	"full_scrub_threshold_rate",
	  .fops	=	&ldiskfs_osd_full_scrub_threshold_rate_fops	},
	{ .name	=	"oi_scrub",
	  .fops	=	&ldiskfs_osd_oi_scrub_fops	},
	{ .name	=	"read_cache_enable",
	  .fops	=	&ldiskfs_osd_cache_fops		},
	{ .name	=	"writethrough_cache_enable",
	  .fops	=	&ldiskfs_osd_wcache_fops	},
	{ .name	=	"readcache_max_filesize",
	  .fops	=	&ldiskfs_osd_readcache_fops	},
	{ NULL }
};

struct lprocfs_vars lprocfs_osd_module_vars[] = {
	{ .name	=	"track_declares_assert",
	  .fops	=	&ldiskfs_osd_track_declares_assert_fops		},
	{ NULL }
};


int osd_procfs_init(struct osd_device *osd, const char *name)
{
	struct obd_type	*type;
	int		rc;
	ENTRY;

	if (osd->od_proc_entry)
		RETURN(0);

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way */
	type = class_search_type(LUSTRE_OSD_LDISKFS_NAME);

	LASSERT(name != NULL);
	LASSERT(type != NULL);

	/* Find the type procroot and add the proc entry for this device */
	osd->od_proc_entry = lprocfs_register(name, type->typ_procroot,
					      lprocfs_osd_obd_vars,
					      &osd->od_dt_dev);
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
	RETURN(0);
}
#endif
