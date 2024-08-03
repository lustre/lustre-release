/* SPDX-License-Identifier: GPL-2.0 */

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
#include <obd.h>

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

static inline struct obd_device_target *obd2obt(struct obd_device *obd)
{
	struct obd_device_target *obt;

	BUILD_BUG_ON(sizeof(obd->u) < sizeof(*obt));

	if (!obd)
		return NULL;
	obt = (void *)&obd->u;
	LASSERT(obt->obt_magic == OBT_MAGIC);
	return obt;
}

static inline struct obd_device_target *obd_obt_init(struct obd_device *obd)
{
	struct obd_device_target *obt;

	obt = (void *)&obd->u;
	obt->obt_magic = OBT_MAGIC;
	obt->obt_instance = 0;

	return obt;
}

static inline struct echo_obd *obd2echo(struct obd_device *obd)
{
	struct echo_obd *echo;

	BUILD_BUG_ON(sizeof(obd->u) < sizeof(*echo));

	if (!obd)
		return NULL;
	echo = (void *)&obd->u;

	return echo;
}

static inline struct ost_obd *obd2ost(struct obd_device *obd)
{
	struct ost_obd *ost;

	BUILD_BUG_ON(sizeof(obd->u) < sizeof(*ost));

	if (!obd)
		return NULL;
	ost = (void *)&obd->u;

	return ost;
}

#endif /* __OBD_TARGET_H */
