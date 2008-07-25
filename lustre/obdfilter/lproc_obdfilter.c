/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <lprocfs_status.h>
#include <obd.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#include "filter_internal.h"

#ifdef LPROCFS
static int lprocfs_filter_rd_groups(char *page, char **start, off_t off,
                                    int count, int *eof, void *data)
{
        *eof = 1;
        return snprintf(page, count, "%u\n", FILTER_GROUPS);
}

static int lprocfs_filter_rd_tot_dirty(char *page, char **start, off_t off,
                                       int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        *eof = 1;
        return snprintf(page, count, LPU64"\n", obd->u.filter.fo_tot_dirty);
}

static int lprocfs_filter_rd_tot_granted(char *page, char **start, off_t off,
                                         int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        *eof = 1;
        return snprintf(page, count, LPU64"\n", obd->u.filter.fo_tot_granted);
}

static int lprocfs_filter_rd_tot_pending(char *page, char **start, off_t off,
                                         int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        *eof = 1;
        return snprintf(page, count, LPU64"\n", obd->u.filter.fo_tot_pending);
}

static int lprocfs_filter_rd_mntdev(char *page, char **start, off_t off,
                                    int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        LASSERT(obd->u.filter.fo_vfsmnt->mnt_devname);
        *eof = 1;
        return snprintf(page, count, "%s\n",
                        obd->u.filter.fo_vfsmnt->mnt_devname);
}

static int lprocfs_filter_rd_last_id(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{
        struct obd_device *obd = data;

        if (obd == NULL)
                return 0;

        return snprintf(page, count, LPU64"\n",
                        filter_last_id(&obd->u.filter, 0));
}

int lprocfs_filter_rd_readcache(char *page, char **start, off_t off, int count,
                                int *eof, void *data)
{
        struct obd_device *obd = data;
        int rc;

        rc = snprintf(page, count, LPU64"\n",
                      obd->u.filter.fo_readcache_max_filesize);
        return rc;
}

int lprocfs_filter_wr_readcache(struct file *file, const char *buffer,
                                unsigned long count, void *data)
{
        struct obd_device *obd = data;
        __u64 val;
        int rc;

        rc = lprocfs_write_u64_helper(buffer, count, &val);
        if (rc)
                return rc;

        obd->u.filter.fo_readcache_max_filesize = val;
        return count;
}

int lprocfs_filter_rd_fmd_max_num(char *page, char **start, off_t off,
                                  int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        int rc;

        rc = snprintf(page, count, "%u\n", obd->u.filter.fo_fmd_max_num);
        return rc;
}

int lprocfs_filter_wr_fmd_max_num(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct obd_device *obd = data;
        int val;
        int rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val > 65536 || val < 1)
                return -EINVAL;

        obd->u.filter.fo_fmd_max_num = val;
        return count;
}

int lprocfs_filter_rd_fmd_max_age(char *page, char **start, off_t off,
                                  int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        int rc;

        rc = snprintf(page, count, "%u\n", obd->u.filter.fo_fmd_max_age / HZ);
        return rc;
}

int lprocfs_filter_wr_fmd_max_age(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct obd_device *obd = data;
        int val;
        int rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val > 65536 || val < 1)
                return -EINVAL;

        obd->u.filter.fo_fmd_max_age = val * HZ;
        return count;
}

static struct lprocfs_vars lprocfs_filter_obd_vars[] = {
        { "uuid",         lprocfs_rd_uuid,          0, 0 },
        { "blocksize",    lprocfs_rd_blksize,       0, 0 },
        { "kbytestotal",  lprocfs_rd_kbytestotal,   0, 0 },
        { "kbytesfree",   lprocfs_rd_kbytesfree,    0, 0 },
        { "kbytesavail",  lprocfs_rd_kbytesavail,   0, 0 },
        { "filestotal",   lprocfs_rd_filestotal,    0, 0 },
        { "filesfree",    lprocfs_rd_filesfree,     0, 0 },
        { "filegroups",   lprocfs_filter_rd_groups, 0, 0 },
        { "fstype",       lprocfs_rd_fstype,        0, 0 },
        { "mntdev",       lprocfs_filter_rd_mntdev, 0, 0 },
        { "last_id",      lprocfs_filter_rd_last_id,0, 0 },
        { "tot_dirty",    lprocfs_filter_rd_tot_dirty,   0, 0 },
        { "tot_pending",  lprocfs_filter_rd_tot_pending, 0, 0 },
        { "tot_granted",  lprocfs_filter_rd_tot_granted, 0, 0 },
        { "recovery_status", lprocfs_obd_rd_recovery_status, 0, 0 },
#ifdef CRAY_XT3
        { "recovery_maxtime", lprocfs_obd_rd_recovery_maxtime,
                              lprocfs_obd_wr_recovery_maxtime, 0},
#endif
        { "evict_client", 0, lprocfs_wr_evict_client, 0,
                                &lprocfs_evict_client_fops},
        { "num_exports",  lprocfs_rd_num_exports,   0, 0 },
        { "readcache_max_filesize",
                          lprocfs_filter_rd_readcache,
                          lprocfs_filter_wr_readcache, 0 },
#ifdef HAVE_QUOTA_SUPPORT
        { "quota_bunit_sz", lprocfs_quota_rd_bunit,
                            lprocfs_quota_wr_bunit, 0},
        { "quota_btune_sz", lprocfs_quota_rd_btune,
                            lprocfs_quota_wr_btune, 0},
        { "quota_iunit_sz", lprocfs_quota_rd_iunit,
                            lprocfs_quota_wr_iunit, 0},
        { "quota_itune_sz", lprocfs_quota_rd_itune,
                            lprocfs_quota_wr_itune, 0},
        { "quota_type",     lprocfs_quota_rd_type,
                            lprocfs_quota_wr_type, 0},
        { "quota_switch_seconds",  lprocfs_quota_rd_switch_seconds,
                                   lprocfs_quota_wr_switch_seconds, 0 },
#endif
        { "client_cache_count", lprocfs_filter_rd_fmd_max_num,
                          lprocfs_filter_wr_fmd_max_num, 0 },
        { "client_cache_seconds", lprocfs_filter_rd_fmd_max_age,
                          lprocfs_filter_wr_fmd_max_age, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_filter_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,       0, 0 },
        { 0 }
};

void filter_tally(struct obd_export *exp, struct page **pages, int nr_pages,
                  unsigned long *blocks, int blocks_per_page, int wr)
{
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct page *last_page = NULL;
        unsigned long *last_block = NULL;
        unsigned long discont_pages = 0;
        unsigned long discont_blocks = 0;
        int i;

        if (nr_pages == 0)
                return;

        lprocfs_oh_tally_log2(&filter->fo_filter_stats.hist[BRW_R_PAGES + wr],
                              nr_pages);
        lprocfs_oh_tally_log2(&fed->fed_brw_stats.hist[BRW_R_PAGES + wr],
                              nr_pages);
        if (exp->exp_nid_stats && exp->exp_nid_stats->nid_brw_stats)
                lprocfs_oh_tally_log2(&exp->exp_nid_stats->nid_brw_stats->hist[BRW_W_PAGES + wr],
                                      nr_pages);

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

        lprocfs_oh_tally(&filter->fo_filter_stats.hist[BRW_R_DISCONT_PAGES +wr],
                         discont_pages);
        lprocfs_oh_tally(&fed->fed_brw_stats.hist[BRW_R_DISCONT_PAGES + wr],
                         discont_pages);
        lprocfs_oh_tally(&filter->fo_filter_stats.hist[BRW_R_DISCONT_BLOCKS+wr],
                         discont_blocks);
        lprocfs_oh_tally(&fed->fed_brw_stats.hist[BRW_R_DISCONT_BLOCKS + wr],
                         discont_blocks);

        if (exp->exp_nid_stats && exp->exp_nid_stats->nid_brw_stats) {
                lprocfs_oh_tally_log2(&exp->exp_nid_stats->nid_brw_stats->hist[BRW_W_DISCONT_PAGES + wr],
                                      discont_pages);
                lprocfs_oh_tally_log2(&exp->exp_nid_stats->nid_brw_stats->hist[BRW_W_DISCONT_BLOCKS + wr],
                                      discont_blocks);
        }
}

#define pct(a,b) (b ? a * 100 / b : 0)

static void display_brw_stats(struct seq_file *seq, char *name, char *units,
        struct obd_histogram *read, struct obd_histogram *write, int log2)
{
        unsigned long read_tot, write_tot, r, w, read_cum = 0, write_cum = 0;
        int i;

        seq_printf(seq, "\n%26s read      |     write\n", " ");
        seq_printf(seq, "%-22s %-5s %% cum %% |  %-5s %% cum %%\n", 
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

                if (!log2) 
                        seq_printf(seq, "%u", i);
                else if (i < 10)
                        seq_printf(seq, "%u", 1<<i);
                else if (i < 20)
                        seq_printf(seq, "%uK", 1<<(i-10));
                else
                        seq_printf(seq, "%uM", 1<<(i-20));

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
        do_gettimeofday(&now);
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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        display_brw_stats(seq, "disk I/Os in flight", "ios",
                          &brw_stats->hist[BRW_R_RPC_HIST],
                          &brw_stats->hist[BRW_W_RPC_HIST], 0);

        {
                char title[24];
                sprintf(title, "I/O time (1/%ds)", HZ);
                display_brw_stats(seq, title, "ios",
                                  &brw_stats->hist[BRW_R_IO_TIME],
                                  &brw_stats->hist[BRW_W_IO_TIME], 1);
        }

        display_brw_stats(seq, "disk I/O size", "ios",
                          &brw_stats->hist[BRW_R_DISK_IOSIZE],
                          &brw_stats->hist[BRW_W_DISK_IOSIZE], 1);
#endif
}

#undef pct

static int filter_brw_stats_seq_show(struct seq_file *seq, void *v)
{
        struct obd_device *dev = seq->private;
        struct filter_obd *filter = &dev->u.filter;

        brw_stats_show(seq, &filter->fo_filter_stats);

        return 0;
}

static ssize_t filter_brw_stats_seq_write(struct file *file, const char *buf,
                                       size_t len, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct obd_device *dev = seq->private;
        struct filter_obd *filter = &dev->u.filter;
        int i;

        for (i = 0; i < BRW_LAST; i++)
                lprocfs_oh_clear(&filter->fo_filter_stats.hist[i]);

        return len;
}

LPROC_SEQ_FOPS(filter_brw_stats);

int lproc_filter_attach_seqstat(struct obd_device *dev)
{
        return lprocfs_obd_seq_create(dev, "brw_stats", 0444,
                                      &filter_brw_stats_fops, dev);
}

static int filter_per_export_stats_seq_show(struct seq_file *seq, void *v)
{
        struct filter_export_data *fed = seq->private;

        brw_stats_show(seq, &fed->fed_brw_stats);

        return 0;
}

static ssize_t filter_per_export_stats_seq_write(struct file *file,
                                       const char *buf, size_t len, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct filter_export_data *fed = seq->private;
        int i;

        for (i = 0; i < BRW_LAST; i++)
                lprocfs_oh_clear(&fed->fed_brw_stats.hist[i]);

        return len;
}

LPROC_SEQ_FOPS(filter_per_export_stats);

void lprocfs_filter_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_filter_module_vars;
    lvars->obd_vars     = lprocfs_filter_obd_vars;
}

static int filter_per_nid_stats_seq_show(struct seq_file *seq, void *v)
{
        nid_stat_t *tmp = seq->private;

        if (tmp->nid_brw_stats)
                brw_stats_show(seq, tmp->nid_brw_stats);

        return 0;
}

static ssize_t filter_per_nid_stats_seq_write(struct file *file,
                                              const char *buf, size_t len,
                                              loff_t *off)
{
        struct seq_file *seq = file->private_data;
        nid_stat_t *tmp = seq->private;
        int i;

        if (tmp->nid_brw_stats)
                for (i = 0; i < BRW_LAST; i++)
                        lprocfs_oh_clear(&tmp->nid_brw_stats->hist[i]);

        return len;
}

LPROC_SEQ_FOPS(filter_per_nid_stats);

#endif /* LPROCFS */
