/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
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

#ifdef HAVE_QUOTA_SUPPORT
static int lprocfs_filter_rd_bunit(char *page, char **start, off_t off, int count, 
                                   int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n", 
                        obd->u.obt.obt_qctxt.lqc_bunit_sz);
}

static int lprocfs_filter_rd_iunit(char *page, char **start, off_t off, int count, 
                                   int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n", 
                        obd->u.obt.obt_qctxt.lqc_iunit_sz);
}

static int lprocfs_filter_wr_bunit(struct file *file, const char *buffer,
                                   unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val % QUOTABLOCK_SIZE ||
            val <= obd->u.obt.obt_qctxt.lqc_btune_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_bunit_sz = val;
        return count;
}

static int lprocfs_filter_wr_iunit(struct file *file, const char *buffer,
                                   unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val <= obd->u.obt.obt_qctxt.lqc_itune_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_iunit_sz = val;
        return count;
}

static int lprocfs_filter_rd_btune(char *page, char **start, off_t off, int count, 
                                   int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n", 
                        obd->u.obt.obt_qctxt.lqc_btune_sz);
}

static int lprocfs_filter_rd_itune(char *page, char **start, off_t off, int count, 
                                   int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n", 
                        obd->u.obt.obt_qctxt.lqc_itune_sz);
}

static int lprocfs_filter_wr_btune(struct file *file, const char *buffer,
                                   unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;
        
        if (val <= QUOTABLOCK_SIZE * MIN_QLIMIT || val % QUOTABLOCK_SIZE || 
            val >= obd->u.obt.obt_qctxt.lqc_bunit_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_btune_sz = val;
        return count;
}

static int lprocfs_filter_wr_itune(struct file *file, const char *buffer,
                                   unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;
        
        if (val <= MIN_QLIMIT || 
            val >= obd->u.obt.obt_qctxt.lqc_iunit_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_itune_sz = val;
        return count;
}
#endif

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

static struct lprocfs_vars lprocfs_obd_vars[] = {
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
        { "evict_client", 0, lprocfs_wr_evict_client, 0 },
        { "num_exports",  lprocfs_rd_num_exports,   0, 0 },
        { "readcache_max_filesize",
                          lprocfs_filter_rd_readcache,
                          lprocfs_filter_wr_readcache, 0 },
#ifdef HAVE_QUOTA_SUPPORT
        { "quota_bunit_sz", lprocfs_filter_rd_bunit,
                            lprocfs_filter_wr_bunit, 0},
        { "quota_btune_sz", lprocfs_filter_rd_btune,
                            lprocfs_filter_wr_btune, 0},
        { "quota_iunit_sz", lprocfs_filter_rd_iunit,
                            lprocfs_filter_wr_iunit, 0},
        { "quota_itune_sz", lprocfs_filter_rd_itune,
                            lprocfs_filter_wr_itune, 0},
#endif
        { "client_cache_count", lprocfs_filter_rd_fmd_max_num,
                          lprocfs_filter_wr_fmd_max_num, 0 },
        { "client_cache_seconds", lprocfs_filter_rd_fmd_max_age,
                          lprocfs_filter_wr_fmd_max_age, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,       0, 0 },
        { 0 }
};

void filter_tally_write(struct filter_obd *filter, struct page **pages,
                     int nr_pages, unsigned long *blocks, int blocks_per_page)
{
        struct page *last_page = NULL;
        unsigned long *last_block = NULL;
        unsigned long discont_pages = 0;
        unsigned long discont_blocks = 0;
        int i;

        if (nr_pages == 0)
                return;

        lprocfs_oh_tally_log2(&filter->fo_w_pages, nr_pages);

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

        lprocfs_oh_tally(&filter->fo_w_discont_pages, discont_pages);
        lprocfs_oh_tally(&filter->fo_w_discont_blocks, discont_blocks);
}

void filter_tally_read(struct filter_obd *filter, struct niobuf_local *lnb,
                       int niocount)
{
        struct niobuf_local *end;
        struct page *last_page = NULL;
        unsigned long discont_pages = 0;
        unsigned long discont_blocks = 0;

        if (niocount == 0)
                return;

        for (end = lnb + niocount; lnb < end && lnb->page; lnb++) {
                struct page *page = lnb->page;
                if (last_page) {
                       if (page->index != (last_page->index + 1))
                                discont_pages++;
                        /* XXX not so smart for now */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        if ((page->buffers && last_page->buffers) &&
                            (page->buffers->b_blocknr !=
                             (last_page->buffers->b_blocknr + 1)))
                                discont_blocks++;
#else
#warning "port on 2.6 -bzzz"
#endif
                }
                last_page = page;
        }

        lprocfs_oh_tally_log2(&filter->fo_r_pages, niocount);
        lprocfs_oh_tally(&filter->fo_r_discont_pages, discont_pages);
        lprocfs_oh_tally(&filter->fo_r_discont_blocks, discont_blocks);
}

#define pct(a,b) (b ? a * 100 / b : 0)

static int filter_brw_stats_seq_show(struct seq_file *seq, void *v)
{
        struct timeval now;
        struct obd_device *dev = seq->private;
        struct filter_obd *filter = &dev->u.filter;
        unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
        int i;

        do_gettimeofday(&now);

        /* this sampling races with updates */

        seq_printf(seq, "snapshot_time:         %lu.%lu (secs.usecs)\n",
                   now.tv_sec, now.tv_usec);

        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "pages per brw         brws   %% cum %% |");
        seq_printf(seq, "       rpcs   %% cum %%\n");

        read_tot = lprocfs_oh_sum(&filter->fo_r_pages);
        write_tot = lprocfs_oh_sum(&filter->fo_w_pages);

        read_cum = 0;
        write_cum = 0;
        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = filter->fo_r_pages.oh_buckets[i];
                unsigned long w = filter->fo_w_pages.oh_buckets[i];
                read_cum += r;
                write_cum += w;
                seq_printf(seq, "%u:\t\t%10lu %3lu %3lu   | %10lu %3lu %3lu\n",
                                 1 << i, r, pct(r, read_tot),
                                 pct(read_cum, read_tot), w,
                                 pct(w, write_tot),
                                 pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "discont pages         rpcs   %% cum %% |");
        seq_printf(seq, "       rpcs   %% cum %%\n");

        read_tot = lprocfs_oh_sum(&filter->fo_r_discont_pages);
        write_tot = lprocfs_oh_sum(&filter->fo_w_discont_pages);

        read_cum = 0;
        write_cum = 0;

        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = filter->fo_r_discont_pages.oh_buckets[i];
                unsigned long w = filter->fo_w_discont_pages.oh_buckets[i];
                read_cum += r;
                write_cum += w;
                seq_printf(seq, "%u:\t\t%10lu %3lu %3lu   | %10lu %3lu %3lu\n",
                                 i, r, pct(r, read_tot),
                                 pct(read_cum, read_tot), w,
                                 pct(w, write_tot),
                                 pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "discont blocks        rpcs   %% cum %% |");
        seq_printf(seq, "       rpcs   %% cum %%\n");

        read_tot = lprocfs_oh_sum(&filter->fo_r_discont_blocks);
        write_tot = lprocfs_oh_sum(&filter->fo_w_discont_blocks);

        read_cum = 0;
        write_cum = 0;
        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = filter->fo_r_discont_blocks.oh_buckets[i];
                unsigned long w = filter->fo_w_discont_blocks.oh_buckets[i];
                read_cum += r;
                write_cum += w;
                seq_printf(seq, "%u:\t\t%10lu %3lu %3lu   | %10lu %3lu %3lu\n",
                                 i, r, pct(r, read_tot),
                                 pct(read_cum, read_tot), w,
                                 pct(w, write_tot),
                                 pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "dio frags             rpcs   %% cum %% |");
        seq_printf(seq, "       rpcs   %% cum %%\n");

        read_tot = lprocfs_oh_sum(&filter->fo_r_dio_frags);
        write_tot = lprocfs_oh_sum(&filter->fo_w_dio_frags);

        read_cum = 0;
        write_cum = 0;
        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = filter->fo_r_dio_frags.oh_buckets[i];
                unsigned long w = filter->fo_w_dio_frags.oh_buckets[i];
                read_cum += r;
                write_cum += w;
                seq_printf(seq, "%u:\t\t%10lu %3lu %3lu   | %10lu %3lu %3lu\n",
                                 i, r, pct(r, read_tot),
                                 pct(read_cum, read_tot), w,
                                 pct(w, write_tot),
                                 pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "disk ios in flight     ios   %% cum %% |");
        seq_printf(seq, "       rpcs   %% cum %%\n");

        read_tot = lprocfs_oh_sum(&filter->fo_read_rpc_hist);
        write_tot = lprocfs_oh_sum(&filter->fo_write_rpc_hist);

        read_cum = 0;
        write_cum = 0;
        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = filter->fo_read_rpc_hist.oh_buckets[i];
                unsigned long w = filter->fo_write_rpc_hist.oh_buckets[i];
                read_cum += r;
                write_cum += w;
                seq_printf(seq, "%u:\t\t%10lu %3lu %3lu   | %10lu %3lu %3lu\n",
                                 i, r, pct(r, read_tot),
                                 pct(read_cum, read_tot), w,
                                 pct(w, write_tot),
                                 pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "io time (1/%ds)     rpcs   %% cum %% |", HZ);
        seq_printf(seq, "       rpcs   %% cum %%\n");

        read_tot = lprocfs_oh_sum(&filter->fo_r_io_time);
        write_tot = lprocfs_oh_sum(&filter->fo_w_io_time);

        read_cum = 0;
        write_cum = 0;
        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = filter->fo_r_io_time.oh_buckets[i];
                unsigned long w = filter->fo_w_io_time.oh_buckets[i];
                read_cum += r;
                write_cum += w;
                seq_printf(seq, "%u:\t\t%10lu %3lu %3lu   | %10lu %3lu %3lu\n",
                                 1 << i, r, pct(r, read_tot),
                                 pct(read_cum, read_tot), w,
                                 pct(w, write_tot),
                                 pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }

        seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
        seq_printf(seq, "disk I/O size         count  %% cum %% |");
        seq_printf(seq, "       count  %% cum %%\n");

        read_tot = lprocfs_oh_sum(&filter->fo_r_disk_iosize);
        write_tot = lprocfs_oh_sum(&filter->fo_w_disk_iosize);

        read_cum = 0;
        write_cum = 0;
        for (i = 0; i < OBD_HIST_MAX; i++) {
                unsigned long r = filter->fo_r_disk_iosize.oh_buckets[i];
                unsigned long w = filter->fo_w_disk_iosize.oh_buckets[i];

                read_cum += r;
                write_cum += w;
                if (read_cum == 0 && write_cum == 0)
                        continue;

                if (i < 10)
                        seq_printf(seq, "%u", 1<<i);
                else if (i < 20)
                        seq_printf(seq, "%uK", 1<<(i-10));
                else
                        seq_printf(seq, "%uM", 1<<(i-20));

                seq_printf(seq, ":\t\t%10lu %3lu %3lu   | %10lu %3lu %3lu\n",
                           r, pct(r, read_tot), pct(read_cum, read_tot),
                           w, pct(w, write_tot), pct(write_cum, write_tot));
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }
#endif

        return 0;
}
#undef pct

static void *filter_brw_stats_seq_start(struct seq_file *p, loff_t *pos)
{
        if (*pos == 0)
                return (void *)1;
        return NULL;
}
static void *filter_brw_stats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        ++*pos;
        return NULL;
}
static void filter_brw_stats_seq_stop(struct seq_file *p, void *v)
{
}
struct seq_operations filter_brw_stats_seq_sops = {
        .start = filter_brw_stats_seq_start,
        .stop = filter_brw_stats_seq_stop,
        .next = filter_brw_stats_seq_next,
        .show = filter_brw_stats_seq_show,
};

static int filter_brw_stats_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file *seq;
        int rc;

        rc = seq_open(file, &filter_brw_stats_seq_sops);
        if (rc)
                return rc;
        seq = file->private_data;
        seq->private = dp->data;
        return 0;
}

static ssize_t filter_brw_stats_seq_write(struct file *file, const char *buf,
                                       size_t len, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct obd_device *dev = seq->private;
        struct filter_obd *filter = &dev->u.filter;

        lprocfs_oh_clear(&filter->fo_r_pages);
        lprocfs_oh_clear(&filter->fo_w_pages);
        lprocfs_oh_clear(&filter->fo_read_rpc_hist);
        lprocfs_oh_clear(&filter->fo_write_rpc_hist);
        lprocfs_oh_clear(&filter->fo_r_io_time);
        lprocfs_oh_clear(&filter->fo_w_io_time);
        lprocfs_oh_clear(&filter->fo_r_discont_pages);
        lprocfs_oh_clear(&filter->fo_w_discont_pages);
        lprocfs_oh_clear(&filter->fo_r_discont_blocks);
        lprocfs_oh_clear(&filter->fo_w_discont_blocks);
        lprocfs_oh_clear(&filter->fo_r_disk_iosize);
        lprocfs_oh_clear(&filter->fo_w_disk_iosize);
        lprocfs_oh_clear(&filter->fo_r_dio_frags);
        lprocfs_oh_clear(&filter->fo_w_dio_frags);

        return len;
}

struct file_operations filter_brw_stats_fops = {
        .owner   = THIS_MODULE,
        .open    = filter_brw_stats_seq_open,
        .read    = seq_read,
        .write   = filter_brw_stats_seq_write,
        .llseek  = seq_lseek,
        .release = seq_release,
};

int lproc_filter_attach_seqstat(struct obd_device *dev)
{
        return lprocfs_obd_seq_create(dev, "brw_stats", 0444,
                                      &filter_brw_stats_fops, dev);
}

LPROCFS_INIT_VARS(filter, lprocfs_module_vars, lprocfs_obd_vars)
#endif /* LPROCFS */
