/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#define DEBUG_SUBSYSTEM S_OST

#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>
#include <linux/seq_file.h>

#ifndef LPROCFS
static struct lprocfs_vars lprocfs_obd_vars[]  = { {0} };
static struct lprocfs_vars lprocfs_module_vars[] = { {0} };
#else
static struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",            lprocfs_rd_uuid,   0, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",       lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

#define PRINTF_STIME(stime) (unsigned long)(stime)->st_num,     \
        lprocfs_stime_avg_ms(stime), lprocfs_stime_avg_us(stime)

static int ost_stimes_seq_show(struct seq_file *seq, void *v)
{
        struct timeval now;
        struct obd_device *dev = seq->private;
        struct ost_obd *ost = &dev->u.ost;

        do_gettimeofday(&now);

        spin_lock(&ost->ost_lock);

        seq_printf(seq, "snapshot_time:         %lu.%lu (secs.usecs)\n",
                   now.tv_sec, now.tv_usec);

        seq_printf(seq, "\nread rpc service time: (rpcs, average ms)\n");
        seq_printf(seq, "\tprep\t%lu\t%lu.%04lu\n",
                        PRINTF_STIME(&ost->ost_stimes[0]));
        seq_printf(seq, "\tbulk\t%lu\t%lu.%04lu\n\n",
                        PRINTF_STIME(&ost->ost_stimes[1]));
        seq_printf(seq, "\tcommit\t%lu\t%lu.%04lu\n\n",
                        PRINTF_STIME(&ost->ost_stimes[2]));

        seq_printf(seq, "\nwrite rpc service time: (rpcs, average ms)\n");
        seq_printf(seq, "\tprep\t%lu\t%lu.%04lu\n",
                        PRINTF_STIME(&ost->ost_stimes[3]));
        seq_printf(seq, "\tbulk\t%lu\t%lu.%04lu\n\n",
                        PRINTF_STIME(&ost->ost_stimes[4]));
        seq_printf(seq, "\tcommit\t%lu\t%lu.%04lu\n\n",
                        PRINTF_STIME(&ost->ost_stimes[5]));

        spin_unlock(&ost->ost_lock);

        return 0;
}

static void *ost_stimes_seq_start(struct seq_file *p, loff_t *pos)
{
        if (*pos == 0)
                return (void *)1;
        return NULL;
}
static void *ost_stimes_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        ++*pos;
        return NULL;
}
static void ost_stimes_seq_stop(struct seq_file *p, void *v)
{
}
struct seq_operations ost_stimes_seq_sops = {
        .start = ost_stimes_seq_start,
        .stop = ost_stimes_seq_stop,
        .next = ost_stimes_seq_next,
        .show = ost_stimes_seq_show,
};

static int ost_stimes_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file *seq;
        int rc;

        rc = seq_open(file, &ost_stimes_seq_sops);
        if (rc)
                return rc;
        seq = file->private_data;
        seq->private = dp->data;
        return 0;
}

static ssize_t ost_stimes_seq_write(struct file *file, const char *buf,
                                       size_t len, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct obd_device *dev = seq->private;
        struct ost_obd *ost = &dev->u.ost;

        spin_lock(&ost->ost_lock);
        memset(&ost->ost_stimes, 0, sizeof(ost->ost_stimes));
        spin_unlock(&ost->ost_lock);

        return len;
}

struct file_operations ost_stimes_fops = {
        .owner   = THIS_MODULE,
        .open    = ost_stimes_seq_open,
        .read    = seq_read,
        .write   = ost_stimes_seq_write,
        .llseek  = seq_lseek,
        .release = seq_release,
};

#endif /* LPROCFS */
LPROCFS_INIT_VARS(ost, lprocfs_module_vars, lprocfs_obd_vars)
