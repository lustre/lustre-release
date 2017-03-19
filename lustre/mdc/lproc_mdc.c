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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <linux/vfs.h>
#include <obd_class.h>
#include <lprocfs_status.h>

#include "mdc_internal.h"

#ifdef CONFIG_PROC_FS
static int mdc_active_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;

	LPROCFS_CLIMP_CHECK(dev);
	seq_printf(m, "%d\n", !dev->u.cli.cl_import->imp_deactive);
	LPROCFS_CLIMP_EXIT(dev);
	return 0;
}

static ssize_t mdc_active_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	struct obd_device *dev;
	int rc;
	__s64 val;

	dev = ((struct seq_file *)file->private_data)->private;
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > 1)
		return -ERANGE;

	/* opposite senses */
	if (dev->u.cli.cl_import->imp_deactive == val)
		rc = ptlrpc_set_import_active(dev->u.cli.cl_import, val);
	else
		CDEBUG(D_CONFIG, "activate %llu: ignoring repeat request\n",
		       val);

	return count;
}
LPROC_SEQ_FOPS(mdc_active);

static int mdc_max_rpcs_in_flight_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	__u32 max;

	max = obd_get_max_rpcs_in_flight(&dev->u.cli);
	seq_printf(m, "%u\n", max);

	return 0;
}

static ssize_t mdc_max_rpcs_in_flight_seq_write(struct file *file,
						const char __user *buffer,
						size_t count, loff_t *off)
{
	struct obd_device *dev;
	__s64 val;
	int rc;

	dev = ((struct seq_file *)file->private_data)->private;
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0 || val > UINT_MAX)
		return -ERANGE;

	rc = obd_set_max_rpcs_in_flight(&dev->u.cli, val);
	if (rc)
		return rc;

	return count;
}
LPROC_SEQ_FOPS(mdc_max_rpcs_in_flight);

static int mdc_max_mod_rpcs_in_flight_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	__u16 max;

	max = obd_get_max_mod_rpcs_in_flight(&dev->u.cli);
	seq_printf(m, "%hu\n", max);

	return 0;
}

static ssize_t mdc_max_mod_rpcs_in_flight_seq_write(struct file *file,
						    const char __user *buffer,
						    size_t count, loff_t *off)
{
	struct obd_device *dev =
			((struct seq_file *)file->private_data)->private;
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0 || val > USHRT_MAX)
		return -ERANGE;

	rc = obd_set_max_mod_rpcs_in_flight(&dev->u.cli, val);
	if (rc)
		count = rc;

	return count;
}
LPROC_SEQ_FOPS(mdc_max_mod_rpcs_in_flight);

static int mdc_rpc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *dev = seq->private;

	return obd_mod_rpc_stats_seq_show(&dev->u.cli, seq);
}

static ssize_t mdc_rpc_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *dev = seq->private;
	struct client_obd *cli = &dev->u.cli;

	lprocfs_oh_clear(&cli->cl_mod_rpcs_hist);

	return len;
}
LPROC_SEQ_FOPS(mdc_rpc_stats);

LPROC_SEQ_FOPS_WO_TYPE(mdc, ping);

LPROC_SEQ_FOPS_RO_TYPE(mdc, uuid);
LPROC_SEQ_FOPS_RO_TYPE(mdc, connect_flags);
LPROC_SEQ_FOPS_RO_TYPE(mdc, blksize);
LPROC_SEQ_FOPS_RO_TYPE(mdc, kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(mdc, kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(mdc, kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(mdc, filestotal);
LPROC_SEQ_FOPS_RO_TYPE(mdc, filesfree);
LPROC_SEQ_FOPS_RO_TYPE(mdc, server_uuid);
LPROC_SEQ_FOPS_RO_TYPE(mdc, conn_uuid);
LPROC_SEQ_FOPS_RO_TYPE(mdc, timeouts);
LPROC_SEQ_FOPS_RO_TYPE(mdc, state);
LPROC_SEQ_FOPS_RW_TYPE(mdc, obd_max_pages_per_rpc);
LPROC_SEQ_FOPS_RW_TYPE(mdc, import);
LPROC_SEQ_FOPS_RW_TYPE(mdc, pinger_recov);

struct lprocfs_vars lprocfs_mdc_obd_vars[] = {
	{ .name	=	"uuid",
	  .fops	=	&mdc_uuid_fops		},
	{ .name	=	"ping",
	  .fops	=	&mdc_ping_fops,
	  .proc_mode =	0222			},
	{ .name	=	"connect_flags",
	  .fops	=	&mdc_connect_flags_fops	},
	{ .name	=	"blocksize",
	  .fops	=	&mdc_blksize_fops	},
	{ .name	=	"kbytestotal",
	  .fops	=	&mdc_kbytestotal_fops	},
	{ .name	=	"kbytesfree",
	  .fops	=	&mdc_kbytesfree_fops	},
	{ .name	=	"kbytesavail",
	  .fops	=	&mdc_kbytesavail_fops	},
	{ .name	=	"filestotal",
	  .fops	=	&mdc_filestotal_fops	},
	{ .name	=	"filesfree",
	  .fops	=	&mdc_filesfree_fops	},
	{ .name	=	"mds_server_uuid",
	  .fops	=	&mdc_server_uuid_fops	},
	{ .name	=	"mds_conn_uuid",
	  .fops	=	&mdc_conn_uuid_fops	},
	{ .name	=	"max_pages_per_rpc",
	  .fops	=	&mdc_obd_max_pages_per_rpc_fops	},
	{ .name	=	"max_rpcs_in_flight",
	  .fops	=	&mdc_max_rpcs_in_flight_fops	},
	{ .name	=	"max_mod_rpcs_in_flight",
	  .fops	=	&mdc_max_mod_rpcs_in_flight_fops	},
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
	{ .name	=	"active",
	  .fops	=	&mdc_active_fops		},
	{ NULL }
};
#endif /* CONFIG_PROC_FS */
