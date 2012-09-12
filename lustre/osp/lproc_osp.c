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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osp/lproc_osp.c
 *
 * Lustre OST Proxy Device, procfs functions
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include "osp_internal.h"

#ifdef LPROCFS
static struct lprocfs_vars lprocfs_osp_obd_vars[] = {
	{ "uuid",		lprocfs_rd_uuid, 0, 0 },
	{ "ping",		0, lprocfs_wr_ping, 0, 0, 0222 },
	{ "connect_flags",	lprocfs_rd_connect_flags, 0, 0 },
	{ "blocksize",		lprocfs_rd_blksize, 0, 0 },
	{ "kbytestotal",	lprocfs_rd_kbytestotal, 0, 0 },
	{ "kbytesfree",		lprocfs_rd_kbytesfree, 0, 0 },
	{ "kbytesavail",	lprocfs_rd_kbytesavail, 0, 0 },
	{ "filestotal",		lprocfs_rd_filestotal, 0, 0 },
	{ "filesfree",		lprocfs_rd_filesfree, 0, 0 },
	{ "ost_server_uuid",	lprocfs_rd_server_uuid, 0, 0 },
	{ "ost_conn_uuid",	lprocfs_rd_conn_uuid, 0, 0 },
	{ "timeouts",		lprocfs_rd_timeouts, 0, 0 },
	{ "import",		lprocfs_rd_import, lprocfs_wr_import, 0 },
	{ "state",		lprocfs_rd_state, 0, 0 },
	{ 0 }
};

static struct lprocfs_vars lprocfs_osp_module_vars[] = {
	{ "num_refs",		lprocfs_rd_numrefs, 0, 0 },
	{ 0 }
};

void lprocfs_osp_init_vars(struct lprocfs_static_vars *lvars)
{
	lvars->module_vars = lprocfs_osp_module_vars;
	lvars->obd_vars = lprocfs_osp_obd_vars;
}
#endif /* LPROCFS */

