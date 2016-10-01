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
 * lustre/mdt/mdt_fs.c
 *
 * Lustre Metadata Server (MDS) filesystem interface code
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

static const struct file_operations mdt_open_files_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = lprocfs_mdt_open_files_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
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
	lnet_nid_t *client_nid = localdata;
	struct nid_stat *stats;
	int rc;
	ENTRY;

	LASSERT(!obd->obd_uses_nid_stats);

	rc = lprocfs_exp_setup(exp, client_nid);
	if (rc != 0)
		/* Mask error for already created /proc entries */
		RETURN(rc == -EALREADY ? 0 : rc);

	stats = exp->exp_nid_stats;
	stats->nid_stats = lprocfs_alloc_stats(LPROC_MDT_LAST,
						LPROCFS_STATS_FLAG_NOPERCPU);
	if (stats->nid_stats == NULL)
		RETURN(-ENOMEM);

	mdt_stats_counter_init(stats->nid_stats);

	rc = lprocfs_register_stats(stats->nid_proc, "stats", stats->nid_stats);
	if (rc != 0) {
		lprocfs_free_stats(&stats->nid_stats);
		GOTO(out, rc);
	}

	rc = lprocfs_nid_ldlm_stats_init(stats);
	if (rc != 0)
		GOTO(out, rc);

	rc = lprocfs_seq_create(stats->nid_proc, "open_files",
				0444, &mdt_open_files_seq_fops, stats);
	if (rc != 0) {
		CWARN("%s: error adding the open_files file: rc = %d\n",
			obd->obd_name, rc);
		GOTO(out, rc);
	}
out:
	RETURN(rc);
}
