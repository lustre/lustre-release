/* GPL HEADER START
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __OBD_TARGET_H
#define __OBD_TARGET_H
#include <lprocfs_status.h>

/* server-side individual type definitions */

#define OBT_MAGIC       0xBDDECEAE
/* hold common fields for "target" device */
struct obd_device_target {
	__u32			obt_magic;
	__u32			obt_instance;
	struct lu_target       *obt_lut;
	__u64			obt_mount_count;
	struct obd_job_stats	obt_jobstats;
	struct nm_config_file	*obt_nodemap_config_file;
};

#define OBJ_SUBDIR_COUNT 32 /* set to zero for no subdirs */

struct filter_obd {
	/* NB this field MUST be first */
	struct obd_device_target	 fo_obt;
};

struct echo_obd {
	struct obd_device_target	eo_obt;
	struct obdo			eo_oa;
	spinlock_t			eo_lock;
	u64				eo_lastino;
	struct lustre_handle		eo_nl_lock;
	atomic_t			eo_prep;
};

struct ost_obd {
	struct ptlrpc_service	*ost_service;
	struct ptlrpc_service	*ost_create_service;
	struct ptlrpc_service	*ost_io_service;
	struct ptlrpc_service	*ost_seq_service;
	struct ptlrpc_service	*ost_out_service;
	struct mutex		 ost_health_mutex;
};

#endif /* __OBD_TARGET_H */
