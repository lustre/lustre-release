/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_QUOTA_H
#define _LUSTRE_QUOTA_H

/** \defgroup quota quota
 *
 */

#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/quotaops.h>
#include <linux/sort.h>
#include <lustre_fid.h>
#include <lustre_dlm.h>

#ifndef MAX_IQ_TIME
#define MAX_IQ_TIME  604800     /* (7*24*60*60) 1 week */
#endif

#ifndef MAX_DQ_TIME
#define MAX_DQ_TIME  604800     /* (7*24*60*60) 1 week */
#endif

struct lquota_id_info;
struct lquota_trans;

/* Gather all quota record type in an union that can be used to read any records
 * from disk. All fields of these records must be 64-bit aligned, otherwise the
 * OSD layer may swab them incorrectly.
 */
union lquota_rec {
	struct lquota_glb_rec	lqr_glb_rec;
	struct lquota_slv_rec	lqr_slv_rec;
	struct lquota_acct_rec	lqr_acct_rec;
};

/* flags for inode/block quota accounting */
enum osd_qid_declare_flags {
	OSD_QID_INODE	= BIT(0),
	OSD_QID_BLK	= BIT(1),
	OSD_QID_FORCE	= BIT(2),
};

/* the length of the buffer to contain the quotas gotten from QMT/QSD,
 * the maximum is 128 quota IDs (each struct lquota_glb_rec for MD or DT),
 * it can contain about 420 quota IDs for theirs quota usage.
 */
#define LQUOTA_ITER_BUFLEN					\
	(128 * 2 * (sizeof(__u64) + sizeof(struct lquota_glb_rec)))

struct lquota_iter {
	struct list_head li_link;
	__u32		 li_md_size;
	__u32		 li_dt_size;
	char		 li_buffer[];
};

struct if_quotactl_iter {
	struct list_head	qci_link;
	struct if_quotactl	qci_qc;
};

/* Index features supported by the global index objects
 * Only used for migration purpose and should be removed once on-disk migration
 * is no longer needed
 */
extern struct dt_index_features dt_quota_iusr_features;
extern struct dt_index_features dt_quota_busr_features;
extern struct dt_index_features dt_quota_igrp_features;
extern struct dt_index_features dt_quota_bgrp_features;

/* Name used in the configuration logs to identify the default metadata pool
 * (composed of all the MDTs, with pool ID 0) and the default data pool (all
 * the OSTs, with pool ID 0 too).
 */
#define QUOTA_METAPOOL_NAME   "mdt="
#define QUOTA_DATAPOOL_NAME   "ost="

/*
 * Quota Master Target support
 */

/* Request handlers for quota master operations.
 * This is used by the MDT to pass quota/lock requests to the quota master
 * target. This won't be needed any more once the QMT is a real target and
 * does not rely any more on the MDT service threads and namespace.
 */
struct qmt_handlers {
	/* Handle quotactl request from client. */
	int (*qmth_quotactl)(const struct lu_env *env, struct lu_device *d,
			     struct obd_quotactl *, char *buf, int len);

	/* Handle dqacq/dqrel request from slave. */
	int (*qmth_dqacq)(const struct lu_env *env, struct lu_device *d,
			  struct ptlrpc_request *req);

	/* LDLM intent policy associated with quota locks */
	int (*qmth_intent_policy)(const struct lu_env *env, struct lu_device *d,
				  struct ptlrpc_request *req,
				  struct ldlm_lock **lock, int i);

	/* Initialize LVB of ldlm resource associated with quota objects */
	int (*qmth_lvbo_init)(struct lu_device *d, struct ldlm_resource *res);

	/* Update LVB of ldlm resource associated with quota objects */
	int (*qmth_lvbo_update)(struct lu_device *d, struct ldlm_resource *res,
				struct ptlrpc_request *req, int i);

	/* Return size of LVB to be packed in ldlm message */
	int (*qmth_lvbo_size)(struct lu_device *d, struct ldlm_lock *lock);

	/* Fill request buffer with lvb */
	int (*qmth_lvbo_fill)(struct lu_device *d, struct ldlm_lock *lock,
			      void *lvb, int lvblen);

	/* Free lvb associated with ldlm resource */
	int (*qmth_lvbo_free)(struct lu_device *d, struct ldlm_resource *res);
};

/* actual handlers are defined in lustre/quota/qmt_handler.c */
extern struct qmt_handlers qmt_hdls;

/*
 * Quota enforcement support on slaves
 */

struct qsd_instance;

/* The quota slave feature is implemented under the form of a library.
 * The API is the following:
 *
 * - qsd_init(): the user (mostly the OSD layer) should first allocate a qsd
 *               instance via qsd_init(). This creates all required structures
 *               to manage quota enforcement for this target and performs all
 *               low-level initialization which does not involve any lustre
 *               object. qsd_init() should typically be called when the OSD
 *               is being set up.
 *
 * - qsd_prepare(): This sets up on-disk objects associated with the quota slave
 *                  feature and initiates the quota reintegration procedure if
 *                  needed. qsd_prepare() should typically be called when
 *                  ->ldo_prepare is invoked.
 *
 * - qsd_start(): a qsd instance should be started once recovery is completed
 *                (i.e. when ->ldo_recovery_complete is called). This is used
 *                to notify the qsd layer that quota should now be enforced
 *                again via the qsd_op_begin/end functions. The last step of the
 *                reintegration prodecure (namely usage reconciliation) will be
 *                completed during start.
 *
 * - qsd_fini(): is used to release a qsd_instance structure allocated with
 *               qsd_init(). This releases all quota slave objects and frees the
 *               structures associated with the qsd_instance.
 *
 * - qsd_op_begin(): is used to enforce quota, it must be called in the
 *                   declaration of each operation. qsd_op_end() should then be
 *                   invoked later once all operations have been completed in
 *                   order to release/adjust the quota space.
 *                   Running qsd_op_begin() before qsd_start() isn't fatal and
 *                   will return success.
 *                   Once qsd_start() has been run, qsd_op_begin() will block
 *                   until the reintegration procedure is completed.
 *
 * - qsd_op_end(): performs the post operation quota processing. This must be
 *                 called after the operation transaction stopped.
 *                 While qsd_op_begin() must be invoked each time a new
 *                 operation is declared, qsd_op_end() should be called only
 *                 once for the whole transaction.
 *
 * - qsd_op_adjust(): triggers pre-acquire/release if necessary.
 *
 * Below are the function prototypes to be used by OSD layer to manage quota
 * enforcement. Arguments are documented where each function is defined.
 */

/* flags for quota local enforcement */
enum osd_quota_local_flags {
	QUOTA_FL_OVER_USRQUOTA	= BIT(0),
	QUOTA_FL_OVER_GRPQUOTA	= BIT(1),
	QUOTA_FL_SYNC		= BIT(2),
	QUOTA_FL_OVER_PRJQUOTA	= BIT(3),
	QUOTA_FL_ROOT_PRJQUOTA	= BIT(4),
};

struct qsd_instance *qsd_init(const struct lu_env *env, char *svnname,
			      struct dt_device *d, struct proc_dir_entry *proc,
			      bool is_md, bool excl);
int qsd_prepare(const struct lu_env *env, struct qsd_instance *qsd);
int qsd_start(const struct lu_env *env, struct qsd_instance *qsd);
void qsd_fini(const struct lu_env *env, struct qsd_instance *qsd);
int qsd_op_begin(const struct lu_env *env, struct qsd_instance *qsd,
		 struct lquota_trans *trans, struct lquota_id_info *lqi,
		 enum osd_quota_local_flags *flags);
void qsd_op_end(const struct lu_env *env, struct qsd_instance *qsd,
		struct lquota_trans *trans);
void qsd_op_adjust(const struct lu_env *env, struct qsd_instance *qsd,
		   union lquota_id *id, int i);
int qsd_transfer(const struct lu_env *env, struct qsd_instance *qsd,
		 struct lquota_trans *trans, unsigned int qtype,
		 u64 orig_id, u64 new_id, u64 bspace,
		 struct lquota_id_info *qi);
int qsd_reserve_or_free_quota(const struct lu_env *env,
			      struct qsd_instance *qsd,
			      struct lquota_id_info *qi);

/*
 * Quota information attached to a transaction
 */

struct lquota_entry;

struct lquota_id_info {
	/* quota identifier */
	union lquota_id		 lqi_id;

	/* USRQUOTA or GRPQUOTA for now, could be expanded for
	 * directory quota or other types later.
	 */
	int			 lqi_type;

	/* inodes or kbytes to be consumed or released, it could
	 * be negative when releasing space.
	 */
	long long		 lqi_space;

	/* quota slave entry structure associated with this ID */
	struct lquota_entry	*lqi_qentry;

	/* whether we are reporting blocks or inodes */
	bool			 lqi_is_blk;
};

/* With the DoM, both inode quota in meta pool and block quota in data pool
 * will be enforced at MDT, there are at most 4 quota ids being enforced in
 * a single transaction for inode and block quota, which is chown transaction:
 * original uid and gid, new uid and gid.
 *
 * Given a parent dir and a sub dir, with different uid, gid and project id,
 * need <parent,child> x <user,group,project> x <block,inode> = 12 ids
 */
#define QUOTA_MAX_TRANSIDS    12

/* all qids involved in a single transaction */
struct lquota_trans {
	unsigned short		lqt_id_cnt;
	struct lquota_id_info	lqt_ids[QUOTA_MAX_TRANSIDS];
};

#define IS_LQUOTA_RES(res)						\
	(res->lr_name.name[LUSTRE_RES_ID_SEQ_OFF] == FID_SEQ_QUOTA ||	\
	 res->lr_name.name[LUSTRE_RES_ID_SEQ_OFF] == FID_SEQ_QUOTA_GLB)

/* helper function used by MDT & OFD to retrieve quota accounting information
 * on slave
 */
int lquotactl_slv(const struct lu_env *env, struct dt_device *dt,
		  struct obd_quotactl *obdq, char *buf, int len);

/** @} quota */
#endif /* _LUSTRE_QUOTA_H */
