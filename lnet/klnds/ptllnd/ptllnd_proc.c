/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */

#include "ptllnd.h"
#include <linux/seq_file.h>
#include <linux/lustre_compat25.h>

#define LNET_PTLLND_PROC_STATS   "sys/lnet/ptllnd_stats"

char* stats_name_table[] = {
        "kps_incoming_checksums_calculated",
        "kps_incoming_checksums_invalid",
        "kps_cleaning_caneled_peers",
        "kps_checking_buckets",
        "kps_too_many_peers",
        "kps_peers_created",
        "kps_no_credits",
        "kps_saving_last_credit",
        "kps_rx_allocated",
        "kps_rx_released",
        "kps_rx_allocation_failed",
        "kps_tx_allocated",
        "kps_tx_released",
        "kpt_tx_allocation_failed",
        "kps_recv_delayed",
        "kps_send_routing",
        "kps_send_target_is_router",
        "kpt_send_put",
        "kps_send_get",
        "kps_send_immd",
        "kps_send_reply",
};

typedef struct {
        loff_t   pssi_index;
} ptllnd_stats_seq_iterator_t;


int
ptllnd_stats_seq_seek (ptllnd_stats_seq_iterator_t *pssi, loff_t off)
{
        if( off < sizeof(kptllnd_stats) / sizeof(int) &&
            off < sizeof(stats_name_table) / sizeof(stats_name_table[0])){
                pssi->pssi_index = off;
                return 0;
        }
        return -ENOENT;
}

static void *
ptllnd_stats_seq_start (struct seq_file *s, loff_t *pos)
{
        ptllnd_stats_seq_iterator_t *pssi;
        int                         rc;

        LIBCFS_ALLOC(pssi, sizeof(*pssi));
        if (pssi == NULL)
                return NULL;

        pssi->pssi_index = 0;
        rc = ptllnd_stats_seq_seek(pssi, *pos);
        if (rc == 0)
                return pssi;

        LIBCFS_FREE(pssi, sizeof(*pssi));
        return NULL;
}

static void
ptllnd_stats_seq_stop (struct seq_file *s, void *iter)
{
        ptllnd_stats_seq_iterator_t  *pssi = iter;

        if (pssi != NULL)
                LIBCFS_FREE(pssi, sizeof(*pssi));
}

static void *
ptllnd_stats_seq_next (struct seq_file *s, void *iter, loff_t *pos)
{
        ptllnd_stats_seq_iterator_t *pssi = iter;
        int                         rc;
        loff_t                      next = *pos + 1;

        rc = ptllnd_stats_seq_seek(pssi, next);
        if (rc != 0) {
                LIBCFS_FREE(pssi, sizeof(*pssi));
                return NULL;
        }

        *pos = next;
        return pssi;
}

static int
ptllnd_stats_seq_show (struct seq_file *s, void *iter)
{
        ptllnd_stats_seq_iterator_t *pssi = iter;

        seq_printf(s,"%02d %-40s %d\n",
                (int)pssi->pssi_index,
                stats_name_table[pssi->pssi_index],
                ((int*)&kptllnd_stats)[pssi->pssi_index]);

        return 0;
}

static struct seq_operations ptllnd_stats_sops = {
        .start = ptllnd_stats_seq_start,
        .stop  = ptllnd_stats_seq_stop,
        .next  = ptllnd_stats_seq_next,
        .show  = ptllnd_stats_seq_show,
};

static int
ptllnd_stats_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *sf;
        int                    rc;

        rc = seq_open(file, &ptllnd_stats_sops);
        if (rc == 0) {
                sf = file->private_data;
                sf->private = dp->data;
        }

        return rc;
}

static struct file_operations ptllnd_stats_fops = {
        .owner   = THIS_MODULE,
        .open    = ptllnd_stats_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

void
kptllnd_proc_init(void)
{
        struct proc_dir_entry *stats;

        /* Initialize LNET_PTLLND_PROC_STATS */
        stats = create_proc_entry (LNET_PTLLND_PROC_STATS, 0644, NULL);
        if (stats == NULL) {
                CERROR("couldn't create proc entry %s\n", LNET_PTLLND_PROC_STATS);
                return;
        }

        stats->proc_fops = &ptllnd_stats_fops;
        stats->data = NULL;
}

void
kptllnd_proc_fini(void)
{
        remove_proc_entry(LNET_PTLLND_PROC_STATS, 0);
}
