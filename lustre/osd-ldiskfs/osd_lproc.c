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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_lproc.c
 *
 * Author: Mikhail Pershin <tappro@sun.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>

#include "osd_internal.h"

#ifdef LPROCFS

void osd_brw_stats_update(struct osd_device *osd, struct osd_iobuf *iobuf)
{
        struct brw_stats *s = &osd->od_brw_stats;
        unsigned long    *last_block = NULL;
        struct page     **pages = iobuf->dr_pages;
        struct page      *last_page = NULL;
        unsigned long     discont_pages = 0;
        unsigned long     discont_blocks = 0;
        unsigned long    *blocks = iobuf->dr_blocks;
        int               i, nr_pages = iobuf->dr_npages;
        int               blocks_per_page;
        int               rw = iobuf->dr_rw;

        if (unlikely(nr_pages == 0))
                return;

        blocks_per_page = CFS_PAGE_SIZE >> osd_sb(osd)->s_blocksize_bits;

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
        struct timeval now;

        /* this sampling races with updates */
        cfs_gettimeofday(&now);
        seq_printf(seq, "snapshot_time:         %lu.%lu (secs.usecs)\n",
                   now.tv_sec, now.tv_usec);

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
                          &brw_stats->hist[BRW_W_IO_TIME], 1000 / CFS_HZ);

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

static ssize_t osd_brw_stats_seq_write(struct file *file, const char *buf,
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

int osd_procfs_init(struct osd_device *osd, const char *name)
{
        struct lprocfs_static_vars lvars;
        struct obd_type     *type;
        int                  rc;
        ENTRY;

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way */
	type = class_search_type(LUSTRE_OSD_LDISKFS_NAME);

        LASSERT(name != NULL);
        LASSERT(type != NULL);

        /* Find the type procroot and add the proc entry for this device */
        lprocfs_osd_init_vars(&lvars);
        osd->od_proc_entry = lprocfs_register(name, type->typ_procroot,
                                              lvars.obd_vars, &osd->od_dt_dev);
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

        if (osd->od_proc_entry) {
                 lprocfs_remove(&osd->od_proc_entry);
                 osd->od_proc_entry = NULL;
        }
        RETURN(0);
}

static int lprocfs_osd_rd_fstype(char *page, char **start, off_t off, int count,
				 int *eof, void *data)
{
	struct osd_device *osd = osd_dt_dev(data);

        LASSERT(osd != NULL);
        return snprintf(page, count, "ldiskfs\n");
}

static int lprocfs_osd_rd_mntdev(char *page, char **start, off_t off, int count,
                                 int *eof, void *data)
{
        struct osd_device *osd = osd_dt_dev(data);

        LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
                return -EINPROGRESS;

	*eof = 1;

	return snprintf(page, count, "%s\n", osd->od_mntdev);
}

static int lprocfs_osd_rd_cache(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	struct osd_device *osd = osd_dt_dev(data);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	return snprintf(page, count, "%u\n", osd->od_read_cache);
}

static int lprocfs_osd_wr_cache(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	struct osd_device	*osd = osd_dt_dev(data);
	int			 val, rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	osd->od_read_cache = !!val;
	return count;
}

static int lprocfs_osd_rd_wcache(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	struct osd_device *osd = osd_dt_dev(data);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	return snprintf(page, count, "%u\n", osd->od_writethrough_cache);
}

static int lprocfs_osd_wr_wcache(struct file *file, const char *buffer,
				 unsigned long count, void *data)
{
	struct osd_device	*osd = osd_dt_dev(data);
	int			 val, rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	osd->od_writethrough_cache = !!val;
	return count;
}

static int lprocfs_osd_wr_force_sync(struct file *file, const char *buffer,
				     unsigned long count, void *data)
{
	struct osd_device	*osd = osd_dt_dev(data);
	struct dt_device	*dt = data;
	struct lu_env		 env;
	int			 rc;

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

static int lprocfs_osd_rd_pdo(char *page, char **start, off_t off, int count,
                              int *eof, void *data)
{
        *eof = 1;

        return snprintf(page, count, "%s\n", ldiskfs_pdo ? "ON" : "OFF");
}

static int lprocfs_osd_wr_pdo(struct file *file, const char *buffer,
                              unsigned long count, void *data)
{
        int     pdo;
        int     rc;

        rc = lprocfs_write_helper(buffer, count, &pdo);
        if (rc != 0)
                return rc;

        ldiskfs_pdo = !!pdo;

        return count;
}

static int lprocfs_osd_rd_auto_scrub(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	struct osd_device *dev = osd_dt_dev(data);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	*eof = 1;
	return snprintf(page, count, "%d\n", !dev->od_noscrub);
}

static int lprocfs_osd_wr_auto_scrub(struct file *file, const char *buffer,
				     unsigned long count, void *data)
{
	struct osd_device *dev = osd_dt_dev(data);
	int val, rc;

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	dev->od_noscrub = !val;
	return count;
}

static int lprocfs_osd_rd_track_declares_assert(char *page, char **start,
						off_t off, int count,
						int *eof, void *data)
{
	*eof = 1;

	return snprintf(page, count, "%d\n", ldiskfs_track_declares_assert);
}

static int lprocfs_osd_wr_track_declares_assert(struct file *file,
						const char *buffer,
						unsigned long count, void *data)
{
	int     track_declares_assert;
	int     rc;

	rc = lprocfs_write_helper(buffer, count, &track_declares_assert);
	if (rc != 0)
		return rc;

	ldiskfs_track_declares_assert = !!track_declares_assert;

	return count;
}

static int lprocfs_osd_rd_oi_scrub(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	struct osd_device *dev = osd_dt_dev(data);

	LASSERT(dev != NULL);
	if (unlikely(dev->od_mnt == NULL))
		return -EINPROGRESS;

	*eof = 1;
	return osd_scrub_dump(dev, page, count);
}

int lprocfs_osd_rd_readcache(char *page, char **start, off_t off, int count,
			     int *eof, void *data)
{
	struct osd_device	*osd = osd_dt_dev(data);
	int			 rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = snprintf(page, count, LPU64"\n", osd->od_readcache_max_filesize);
	return rc;
}

int lprocfs_osd_wr_readcache(struct file *file, const char *buffer,
			     unsigned long count, void *data)
{
	struct osd_device	*osd = osd_dt_dev(data);
	__u64			 val;
	int			 rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

	rc = lprocfs_write_u64_helper(buffer, count, &val);
	if (rc)
		return rc;

	osd->od_readcache_max_filesize = val > OSD_MAX_CACHE_SIZE ?
					 OSD_MAX_CACHE_SIZE : val;
	return count;
}

struct lprocfs_vars lprocfs_osd_obd_vars[] = {
	{ "blocksize",		lprocfs_dt_rd_blksize,	0, 0 },
	{ "kbytestotal",	lprocfs_dt_rd_kbytestotal,	0, 0 },
	{ "kbytesfree",		lprocfs_dt_rd_kbytesfree,	0, 0 },
	{ "kbytesavail",	lprocfs_dt_rd_kbytesavail,	0, 0 },
	{ "filestotal",		lprocfs_dt_rd_filestotal,	0, 0 },
	{ "filesfree",		lprocfs_dt_rd_filesfree,	0, 0 },
        { "fstype",          lprocfs_osd_rd_fstype,      0, 0 },
        { "mntdev",          lprocfs_osd_rd_mntdev,      0, 0 },
	{ "force_sync",      0, lprocfs_osd_wr_force_sync     },
        { "pdo",             lprocfs_osd_rd_pdo, lprocfs_osd_wr_pdo, 0 },
	{ "auto_scrub",      lprocfs_osd_rd_auto_scrub,
			     lprocfs_osd_wr_auto_scrub,  0 },
	{ "oi_scrub",	     lprocfs_osd_rd_oi_scrub,    0, 0 },
	{ "force_sync",		0, lprocfs_osd_wr_force_sync },
	{ "read_cache_enable",	lprocfs_osd_rd_cache, lprocfs_osd_wr_cache, 0 },
	{ "writethrough_cache_enable",	lprocfs_osd_rd_wcache,
					lprocfs_osd_wr_wcache, 0 },
	{ "readcache_max_filesize",	lprocfs_osd_rd_readcache,
					lprocfs_osd_wr_readcache, 0 },
	{ 0 }
};

struct lprocfs_vars lprocfs_osd_module_vars[] = {
        { "num_refs",        lprocfs_rd_numrefs,     0, 0 },
	{ "track_declares_assert",	lprocfs_osd_rd_track_declares_assert,
					lprocfs_osd_wr_track_declares_assert,
					0 },
        { 0 }
};

void lprocfs_osd_init_vars(struct lprocfs_static_vars *lvars)
{
        lvars->module_vars = lprocfs_osd_module_vars;
        lvars->obd_vars = lprocfs_osd_obd_vars;
}
#endif
