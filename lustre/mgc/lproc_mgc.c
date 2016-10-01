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
 * Copyright (c) 2011, Intel Corporation.
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
#include "mgc_internal.h"

#ifdef CONFIG_PROC_FS

LPROC_SEQ_FOPS_RO_TYPE(mgc, uuid);
LPROC_SEQ_FOPS_RO_TYPE(mgc, connect_flags);
LPROC_SEQ_FOPS_RO_TYPE(mgc, server_uuid);
LPROC_SEQ_FOPS_RO_TYPE(mgc, conn_uuid);
LPROC_SEQ_FOPS_RO_TYPE(mgc, import);
LPROC_SEQ_FOPS_RO_TYPE(mgc, state);

LPROC_SEQ_FOPS_WO_TYPE(mgc, ping);

static int mgc_ir_state_seq_show(struct seq_file *m, void *v)
{
	return lprocfs_mgc_rd_ir_state(m, m->private);
}
LPROC_SEQ_FOPS_RO(mgc_ir_state);

struct lprocfs_vars lprocfs_mgc_obd_vars[] = {
	{ .name	=	"uuid",
	  .fops	=	&mgc_uuid_fops		},
	{ .name	=	"ping",
	  .fops	=	&mgc_ping_fops,
	  .proc_mode =	0222			},
	{ .name	=	"connect_flags",
	  .fops	=	&mgc_connect_flags_fops	},
	{ .name	=	"mgs_server_uuid",
	  .fops	=	&mgc_server_uuid_fops	},
	{ .name	=	"mgs_conn_uuid",
	  .fops	=	&mgc_conn_uuid_fops	},
	{ .name	=	"import",
	  .fops	=	&mgc_import_fops	},
	{ .name	=	"state",
	  .fops	=	&mgc_state_fops		},
	{ .name	=	"ir_state",
	  .fops	=	&mgc_ir_state_fops	},
	{ NULL }
};
#endif /* CONFIG_PROC_FS */
