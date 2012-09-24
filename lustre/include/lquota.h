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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 * Use is subject to license terms.
 */

#include <dt_object.h>
#include <lustre_fid.h>
#include <lustre_dlm.h>

#ifndef _LUSTRE_LQUOTA_H
#define _LUSTRE_LQUOTA_H

/* Gather all quota record type in an union that can be used to read any records
 * from disk. All fields of these records must be 64-bit aligned, otherwise the
 * OSD layer may swab them incorrectly. */
union lquota_rec {
	struct lquota_glb_rec	lqr_glb_rec;
	struct lquota_slv_rec	lqr_slv_rec;
	struct lquota_acct_rec	lqr_acct_rec;
};

/* Index features supported by the global index objects
 * Only used for migration purpose and should be removed once on-disk migration
 * is no longer needed */
extern struct dt_index_features dt_quota_iusr_features;
extern struct dt_index_features dt_quota_busr_features;
extern struct dt_index_features dt_quota_igrp_features;
extern struct dt_index_features dt_quota_bgrp_features;

/* Name used in the configuration logs to identify the default metadata pool
 * (composed of all the MDTs, with pool ID 0) and the default data pool (all
 * the OSTs, with pool ID 0 too). */
#define QUOTA_METAPOOL_NAME   "mdt="
#define QUOTA_DATAPOOL_NAME   "ost="

/*
 * Quota information attached to a transaction
 */

struct lquota_entry;

struct lquota_id_info {
	/* quota identifier */
	union lquota_id		 lqi_id;

	/* USRQUOTA or GRPQUOTA for now, could be expanded for
	 * directory quota or other types later.  */
	int			 lqi_type;

	/* inodes or kbytes to be consumed or released, it could
	 * be negative when releasing space.  */
	long long		 lqi_space;

	/* quota slave entry structure associated with this ID */
	struct lquota_entry	*lqi_qentry;

	/* whether we are reporting blocks or inodes */
	bool			 lqi_is_blk;
};

/* Since we enforce only inode quota in meta pool (MDTs), and block quota in
 * data pool (OSTs), there are at most 4 quota ids being enforced in a single
 * transaction, which is chown transaction:
 * original uid and gid, new uid and gid.
 *
 * This value might need to be revised when directory quota is added.  */
#define QUOTA_MAX_TRANSIDS    4

/* all qids involved in a single transaction */
struct lquota_trans {
        unsigned short         lqt_id_cnt;
        struct lquota_id_info  lqt_ids[QUOTA_MAX_TRANSIDS];
};

/* flags for quota local enforcement */
#define QUOTA_FL_OVER_USRQUOTA  0x01
#define QUOTA_FL_OVER_GRPQUOTA  0x02
#define QUOTA_FL_SYNC           0x04

/*
 * Quota enforcement support on slaves
 */

struct qsd_instance;

/* The quota slave feature is implemented under the form of a library.
 * The API is the following:
 *
 * - qsd_init(): the user (mostly the OSD layer) should first allocate a qsd
 *               instance via qsd_init(). This sets up on-disk objects
 *               associated with the quota slave feature and initiates the quota
 *               reintegration procedure if needed. qsd_init() should typically
 *               be called when ->ldo_start is invoked.
 *
 * - qsd_fini(): is used to release a qsd_instance structure allocated with
 *               qsd_init(). This releases all quota slave objects and frees the
 *               structures associated with the qsd_instance.
 *
 * Below are the function prototypes to be used by OSD layer to manage quota
 * enforcement. Arguments are documented where each function is defined.  */

struct qsd_instance *qsd_init(const struct lu_env *, char *, struct dt_device *,
			      cfs_proc_dir_entry_t *);

void qsd_fini(const struct lu_env *, struct qsd_instance *);

/* helper function used by MDT & OFD to retrieve quota accounting information
 * on slave */
int lquotactl_slv(const struct lu_env *, struct dt_device *,
		  struct obd_quotactl *);

/* XXX: dummy qsd_op_begin() & qsd_op_end(), will be replaced with the real
 *      one once all the enforcement code landed. */
static inline int qsd_op_begin(const struct lu_env *env,
			       struct qsd_instance *qsd,
			       struct lquota_trans *trans,
			       struct lquota_id_info *qi,
			       int *flags)
{
	return 0;
}

static inline void qsd_op_end(const struct lu_env *env,
			      struct qsd_instance *qsd,
			      struct lquota_trans *trans)
{
}
#endif /* _LUSTRE_LQUOTA_H */
