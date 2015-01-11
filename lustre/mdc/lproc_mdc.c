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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
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

static int mdc_max_rpcs_in_flight_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	__u32 max;
	int rc;

	max = obd_get_max_rpcs_in_flight(&dev->u.cli);
	rc = seq_printf(m, "%u\n", max);

	return rc;
}

static ssize_t mdc_max_rpcs_in_flight_seq_write(struct file *file,
						const char __user *buffer,
						size_t count,
						loff_t *off)
{
	struct obd_device *dev = ((struct seq_file *)file->private_data)->private;
	int val;
	int rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc == 0)
		rc = obd_set_max_rpcs_in_flight(&dev->u.cli, val);

	if (rc != 0)
		count = rc;

	return count;
}
LPROC_SEQ_FOPS(mdc_max_rpcs_in_flight);

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

static int mdc_obd_max_pages_per_rpc_seq_show(struct seq_file *m, void *v)
{
	return lprocfs_obd_max_pages_per_rpc_seq_show(m, m->private);
}
LPROC_SEQ_FOPS_RO(mdc_obd_max_pages_per_rpc);

LPROC_SEQ_FOPS_RW_TYPE(mdc, import);
LPROC_SEQ_FOPS_RW_TYPE(mdc, pinger_recov);

struct lprocfs_seq_vars lprocfs_mdc_obd_vars[] = {
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
	/*
	 * FIXME: below proc entry is provided, but not in used, instead
	 * sbi->sb_md_brw_size is used, the per obd variable should be used
	 * when CMD is enabled, and dir pages are managed in MDC layer.
	 * Remember to enable proc write function.
	 */
	{ .name	=	"max_pages_per_rpc",
	  .fops	=	&mdc_obd_max_pages_per_rpc_fops	},
	{ .name	=	"max_rpcs_in_flight",
	  .fops	=	&mdc_max_rpcs_in_flight_fops	},
	{ .name	=	"timeouts",
	  .fops	=	&mdc_timeouts_fops		},
	{ .name	=	"import",
	  .fops	=	&mdc_import_fops		},
	{ .name	=	"state",
	  .fops	=	&mdc_state_fops			},
	{ .name	=	"pinger_recov",
	  .fops	=	&mdc_pinger_recov_fops		},
	{ NULL }
};
#endif /* CONFIG_PROC_FS */
