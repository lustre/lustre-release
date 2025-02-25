// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Metadata Server (MDS) filesystem interface code
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <libcfs/linux/linux-fs.h>
#include "mdt_internal.h"

static const struct file_operations mdt_open_files_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= ldebugfs_mdt_open_files_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/**
 * Initialize MDT per-export statistics.
 *
 * This function sets up procfs entries for various MDT export counters. These
 * counters are for per-client statistics tracked on the server.
 *
 * \param[in] obd	OBD device
 * \param[in] exp	OBD export
 * \param[in] localdata	NID of client
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int mdt_export_stats_init(struct obd_device *obd, struct obd_export *exp,
			  void *localdata)
{
	struct lnet_nid *client_nid = localdata;
	char param[MAX_OBD_NAME * 4];
	struct nid_stat *stats;
	int rc;

	ENTRY;
	rc = lprocfs_exp_setup(exp, client_nid);

	if (rc != 0)
		/* Mask error for already created /proc entries */
		RETURN(rc == -EALREADY ? 0 : rc);

	stats = exp->exp_nid_stats;
	scnprintf(param, sizeof(param), "mdt.%s.exports.%s.stats",
		  obd->obd_name, libcfs_nidstr(client_nid));
	stats->nid_stats = ldebugfs_stats_alloc(LPROC_MDT_LAST, param,
						stats->nid_debugfs,
						LPROCFS_STATS_FLAG_NOPERCPU);
	if (!stats->nid_stats)
		RETURN(-ENOMEM);

	mdt_stats_counter_init(stats->nid_stats, 0, LPROCFS_CNTR_HISTOGRAM);

	rc = lprocfs_nid_ldlm_stats_init(stats);
	if (rc != 0)
		GOTO(out, rc);

	debugfs_create_file("open_files", 0444, stats->nid_debugfs, stats,
			    &mdt_open_files_seq_fops);
out:
	RETURN(rc);
}
