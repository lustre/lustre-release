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
 * Copyright (c) 2012 Intel, Inc.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

/*
 * Quota Slave Driver (QSD) management.
 *
 * The quota slave feature is implemented under the form of a library called
 * QSD. Each OSD device should create a QSD instance via qsd_init() which will
 * be used to manage quota enforcement for this device. This implies:
 * - completing the reintegration procedure with the quota master (aka QMT, see
 *   qmt_dev.c) to retrieve the latest quota settings and space distribution.
 * - managing quota locks in order to be notified of configuration changes.
 * - acquiring space from the QMT when quota space for a given user/group is
 *   close to exhaustion.
 * - allocating quota space to service threads for local request processing.
 *
 * Once the QSD instance created, the OSD device should invoke qsd_start()
 * when recovery is completed. This notifies the QSD that we are about to
 * process new requests on which quota should be strictly enforced.
 * Then, qsd_op_begin/end can be used to reserve/release/pre-acquire quota space
 * for/after each operation until shutdown where the QSD instance should be
 * freed via qsd_fini().
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <obd_class.h>
#include "qsd_internal.h"

/* define qsd thread key */
LU_KEY_INIT_FINI(qsd, struct qsd_thread_info);
LU_CONTEXT_KEY_DEFINE(qsd, LCT_MD_THREAD | LCT_DT_THREAD | LCT_LOCAL);
LU_KEY_INIT_GENERIC(qsd);

/* some procfs helpers */
static int lprocfs_qsd_rd_state(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	struct qsd_instance	*qsd = (struct qsd_instance *)data;

	LASSERT(qsd != NULL);

	return snprintf(page, count,
			"target name:    %s\n"
			"pool ID:        %d\n"
			"type:           %s\n"
			"quota enabled:  none\n",
			qsd->qsd_svname, qsd->qsd_pool_id,
			qsd->qsd_is_md ? "md" : "dt");
}

static int lprocfs_qsd_rd_enabled(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	struct qsd_instance	*qsd = (struct qsd_instance *)data;
	char			 enabled[5];
	LASSERT(qsd != NULL);

	memset(enabled, 0, sizeof(enabled));
	if (qsd_type_enabled(qsd, USRQUOTA))
		strcat(enabled, "u");
	if (qsd_type_enabled(qsd, GRPQUOTA))
		strcat(enabled, "g");
	if (strlen(enabled) == 0)
		strcat(enabled, "none");

	return snprintf(page, count, "%s\n", enabled);
}

static struct lprocfs_vars lprocfs_quota_qsd_vars[] = {
	{ "info", lprocfs_qsd_rd_state, 0, 0},
	{ "enabled", lprocfs_qsd_rd_enabled, 0, 0},
	{ NULL }
};

/*
 * Release qsd_qtype_info structure which contains data associated with a
 * given quota type. This releases the accounting objects.
 * It's called on OSD cleanup when the qsd instance is released.
 *
 * \param env - is the environment passed by the caller
 * \param qsd - is the qsd instance managing the qsd_qtype_info structure
 *              to be released
 * \param qtype - is the quota type to be shutdown
 */
static void qsd_qtype_fini(const struct lu_env *env, struct qsd_instance *qsd,
			   int qtype)
{
	struct qsd_qtype_info	*qqi;
	ENTRY;

	if (qsd->qsd_type_array[qtype] == NULL)
		RETURN_EXIT;
	qqi = qsd->qsd_type_array[qtype];
	qsd->qsd_type_array[qtype] = NULL;

	/* by now, all qqi users should have gone away */
	LASSERT(cfs_atomic_read(&qqi->qqi_ref) == 1);
	lu_ref_fini(&qqi->qqi_reference);

	/* release accounting object */
	if (qqi->qqi_acct_obj != NULL && !IS_ERR(qqi->qqi_acct_obj)) {
		lu_object_put(env, &qqi->qqi_acct_obj->do_lu);
		qqi->qqi_acct_obj = NULL;
	}

	/* release slv index */
	if (qqi->qqi_slv_obj != NULL && !IS_ERR(qqi->qqi_slv_obj)) {
		lu_object_put(env, &qqi->qqi_slv_obj->do_lu);
		qqi->qqi_slv_obj = NULL;
		qqi->qqi_slv_ver = 0;
	}

	/* release global index */
	if (qqi->qqi_glb_obj != NULL && !IS_ERR(qqi->qqi_glb_obj)) {
		lu_object_put(env, &qqi->qqi_glb_obj->do_lu);
		qqi->qqi_glb_obj = NULL;
		qqi->qqi_glb_ver = 0;
	}

	OBD_FREE_PTR(qqi);
	EXIT;
}

/*
 * Allocate and initialize a qsd_qtype_info structure for quota type \qtype.
 * This opens the accounting object and initializes the proc file.
 * It's called on OSD start when the qsd_prepare() is invoked on the qsd
 * instance.
 *
 * \param env  - the environment passed by the caller
 * \param qsd  - is the qsd instance which will be in charge of the new
 *               qsd_qtype_info instance.
 * \param qtype - is quota type to set up
 *
 * \retval - 0 on success and qsd->qsd_type_array[qtype] is allocated,
 *           appropriate error on failure
 */
static int qsd_qtype_init(const struct lu_env *env, struct qsd_instance *qsd,
			  int qtype)
{
	struct qsd_qtype_info	*qqi;
	int			 rc;
	struct obd_uuid		 uuid;
	ENTRY;

	LASSERT(qsd->qsd_type_array[qtype] == NULL);

	/* allocate structure for this quota type */
	OBD_ALLOC_PTR(qqi);
	if (qqi == NULL)
		RETURN(-ENOMEM);
	qsd->qsd_type_array[qtype] = qqi;
	cfs_atomic_set(&qqi->qqi_ref, 1); /* referenced from qsd */

	/* set backpointer and other parameters */
	qqi->qqi_qsd   = qsd;
	qqi->qqi_qtype = qtype;
	lu_ref_init(&qqi->qqi_reference);
	lquota_generate_fid(&qqi->qqi_fid, qsd->qsd_pool_id, QSD_RES_TYPE(qsd),
			    qtype);
	qqi->qqi_glb_uptodate = false;
	qqi->qqi_slv_uptodate = false;
	qqi->qqi_reint        = false;
	memset(&qqi->qqi_lockh, 0, sizeof(qqi->qqi_lockh));

        /* open accounting object */
        LASSERT(qqi->qqi_acct_obj == NULL);
	qqi->qqi_acct_obj = acct_obj_lookup(env, qsd->qsd_dev,
					    qtype == USRQUOTA ? ACCT_USER_OID
							      : ACCT_GROUP_OID);
	/* don't print any error message on failure in order not to confuse
	 * non-OFD user (e.g. 2.3 MDT stack) */
	if (IS_ERR(qqi->qqi_acct_obj))
		qqi->qqi_acct_obj = NULL;

	/* open global index copy */
	LASSERT(qqi->qqi_glb_obj == NULL);
	qqi->qqi_glb_obj = lquota_disk_glb_find_create(env, qsd->qsd_dev,
						       qsd->qsd_root,
						       &qqi->qqi_fid, true);
	if (IS_ERR(qqi->qqi_glb_obj)) {
		CERROR("%s: can't open global index copy "DFID" %ld\n",
		       qsd->qsd_svname, PFID(&qqi->qqi_fid),
		       PTR_ERR(qqi->qqi_glb_obj));
		GOTO(out, rc = PTR_ERR(qqi->qqi_glb_obj));
	}
	qqi->qqi_glb_ver = dt_version_get(env, qqi->qqi_glb_obj);

	/* open slave index copy */
	LASSERT(qqi->qqi_slv_obj == NULL);
	obd_str2uuid(&uuid, qsd->qsd_svname);
	qqi->qqi_slv_obj = lquota_disk_slv_find_create(env, qsd->qsd_dev,
						       qsd->qsd_root,
						       &qqi->qqi_fid, &uuid,
						       true);
	if (IS_ERR(qqi->qqi_slv_obj)) {
		CERROR("%s: can't open slave index copy "DFID" %ld\n",
		       qsd->qsd_svname, PFID(&qqi->qqi_fid),
		       PTR_ERR(qqi->qqi_slv_obj));
		GOTO(out, rc = PTR_ERR(qqi->qqi_slv_obj));
	}
	qqi->qqi_slv_ver = dt_version_get(env, qqi->qqi_slv_obj);

	/* register proc entry for accounting object */
	rc = lprocfs_seq_create(qsd->qsd_proc,
				qtype == USRQUOTA ? "acct_user" : "acct_group",
				0444, &lprocfs_quota_seq_fops,
				qqi->qqi_acct_obj);
	if (rc) {
		CWARN("%s: can't add procfs entry for accounting file %d\n",
		      qsd->qsd_svname, rc);
		GOTO(out, rc);
	}

	EXIT;
out:
	if (rc)
		qsd_qtype_fini(env, qsd, qtype);
	return rc;
}

/*
 * Release a qsd_instance. Companion of qsd_init(). This releases all data
 * structures associated with the quota slave.
 * This function should be called when the OSD is shutting down.
 *
 * \param env - is the environment passed by the caller
 * \param qsd - is the qsd instance to shutdown
 */
void qsd_fini(const struct lu_env *env, struct qsd_instance *qsd)
{
	int	qtype;
	ENTRY;

	CDEBUG(D_QUOTA, "%s: initiating QSD shutdown\n", qsd->qsd_svname);
	qsd->qsd_stopping = true;

	/* remove from the list of fsinfo */
	if (!cfs_list_empty(&qsd->qsd_link)) {
		LASSERT(qsd->qsd_fsinfo != NULL);
		cfs_down(&qsd->qsd_fsinfo->qfs_sem);
		cfs_list_del_init(&qsd->qsd_link);
		cfs_up(&qsd->qsd_fsinfo->qfs_sem);
	}

	/* remove qsd proc entry */
	if (qsd->qsd_proc != NULL) {
		lprocfs_remove(&qsd->qsd_proc);
		qsd->qsd_proc = NULL;
	}

	/* free per-quota type data */
	for (qtype = USRQUOTA; qtype < MAXQUOTAS; qtype++)
		qsd_qtype_fini(env, qsd, qtype);

	/* release per-filesystem information */
	if (qsd->qsd_fsinfo != NULL)
		qsd_put_fsinfo(qsd->qsd_fsinfo);

	/* release quota root directory */
	if (qsd->qsd_root != NULL) {
		lu_object_put(env, &qsd->qsd_root->do_lu);
		qsd->qsd_root = NULL;
	}

	/* release reference on dt_device */
	if (qsd->qsd_dev != NULL) {
		lu_ref_del(&qsd->qsd_dev->dd_lu_dev.ld_reference, "qsd", qsd);
		lu_device_put(&qsd->qsd_dev->dd_lu_dev);
		qsd->qsd_dev = NULL;
	}

	OBD_FREE_PTR(qsd);
	EXIT;
}
EXPORT_SYMBOL(qsd_fini);

/*
 * Create a new qsd_instance to be associated with backend osd device
 * identified by \dev.
 *
 * \param env    - the environment passed by the caller
 * \param svname - is the service name of the OSD device creating this instance
 * \param dev    - is the dt_device where to store quota index files
 * \param osd_proc - is the procfs parent directory where to create procfs file
 *                   related to this new qsd instance
 *
 * \retval - pointer to new qsd_instance associated with dev \dev on success,
 *           appropriate error on failure
 */
struct qsd_instance *qsd_init(const struct lu_env *env, char *svname,
			      struct dt_device *dev,
			      cfs_proc_dir_entry_t *osd_proc)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct qsd_instance	*qsd;
	int			 rc;
	ENTRY;

	/* allocate qsd instance */
	OBD_ALLOC_PTR(qsd);
	if (qsd == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	cfs_rwlock_init(&qsd->qsd_lock);
	CFS_INIT_LIST_HEAD(&qsd->qsd_link);
	/* copy service name */
	strncpy(qsd->qsd_svname, svname, MAX_OBD_NAME);

	/* grab reference on osd device */
	lu_device_get(&dev->dd_lu_dev);
	lu_ref_add(&dev->dd_lu_dev.ld_reference, "qsd", qsd);
	qsd->qsd_dev = dev;

	/* we only support pool ID 0 (default data or metadata pool) for the
	 * time being. A different pool ID could be assigned to this target via
	 * the configuration log in the future */
	qsd->qsd_pool_id  = 0;

	/* get fsname from svname */
	rc = server_name2fsname(svname, qti->qti_buf, NULL);
	if (rc) {
		CERROR("%s: fail to extract filesystem name\n", svname);
		GOTO(out, rc);
	}

	/* look up quota setting for the filesystem the target belongs to */
	qsd->qsd_fsinfo = qsd_get_fsinfo(qti->qti_buf, 1);
	if (qsd->qsd_fsinfo == NULL) {
		CERROR("%s: failed to locate filesystem information\n", svname);
		GOTO(out, rc = -EINVAL);
	}

	/* add in the list of lquota_fsinfo */
	cfs_down(&qsd->qsd_fsinfo->qfs_sem);
	list_add_tail(&qsd->qsd_link, &qsd->qsd_fsinfo->qfs_qsd_list);
	cfs_up(&qsd->qsd_fsinfo->qfs_sem);

	/* register procfs directory */
	qsd->qsd_proc = lprocfs_register(QSD_DIR, osd_proc,
					 lprocfs_quota_qsd_vars, qsd);
	if (IS_ERR(qsd->qsd_proc)) {
		rc = PTR_ERR(qsd->qsd_proc);
		qsd->qsd_proc = NULL;
		CERROR("%s: fail to create quota slave proc entry (%d)\n",
		       svname, rc);
		GOTO(out, rc);
        }
out:
	if (rc) {
		qsd_fini(env, qsd);
		return ERR_PTR(rc);
	}
	RETURN(qsd);
}
EXPORT_SYMBOL(qsd_init);

/*
 * Initialize on-disk structures in order to manage quota enforcement for
 * the target associated with the qsd instance \qsd and starts the reintegration
 * procedure for each quota type as soon as possible.
 * The last step of the reintegration will be completed once qsd_start() is
 * called, at which points the space reconciliation with the master will be
 * executed.
 * This function must be called when the server stack is fully configured,
 * typically when ->ldo_prepare is called across the stack.
 *
 * \param env - the environment passed by the caller
 * \param qsd - is qsd_instance to prepare
 *
 * \retval - 0 on success, appropriate error on failure
 */
int qsd_prepare(const struct lu_env *env, struct qsd_instance *qsd)
{
	int	rc, qtype;
	ENTRY;

	LASSERT(qsd != NULL);

	/* Record whether this qsd instance is managing quota enforcement for a
	 * MDT (i.e. inode quota) or OST (block quota) */
	if (lu_device_is_md(qsd->qsd_dev->dd_lu_dev.ld_site->ls_top_dev))
		qsd->qsd_is_md = true;

	/* look-up on-disk directory for the quota slave */
	qsd->qsd_root = lquota_disk_dir_find_create(env, qsd->qsd_dev, NULL,
						    QSD_DIR);
	if (IS_ERR(qsd->qsd_root)) {
		rc = PTR_ERR(qsd->qsd_root);
		qsd->qsd_root = NULL;
		CERROR("%s: failed to create quota slave root dir (%d)\n",
		       qsd->qsd_svname, rc);
		RETURN(rc);
	}

	/* initialize per-quota type data */
	for (qtype = USRQUOTA; qtype < MAXQUOTAS; qtype++) {
		rc = qsd_qtype_init(env, qsd, qtype);
		if (rc)
			RETURN(rc);
	}

	RETURN(0);
}
EXPORT_SYMBOL(qsd_prepare);

void lustre_register_quota_process_config(int (*qpc)(struct lustre_cfg *lcfg));

/*
 * Global initialization performed at module load time
 */
int qsd_glb_init(void)
{
	qsd_key_init_generic(&qsd_thread_key, NULL);
	lu_context_key_register(&qsd_thread_key);
	lustre_register_quota_process_config(qsd_process_config);
	return 0;
}

/*
 * Companion of qsd_glb_init() called at module unload time
 */
void qsd_glb_fini(void)
{
	lustre_register_quota_process_config(NULL);
	lu_context_key_degister(&qsd_thread_key);
}
