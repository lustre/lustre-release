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
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann@whamcloud.com>
 * Author: Niu    Yawei    <niu@whamcloud.com>
 */

/*
 * Quota Slave Driver (QSD) management.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "qsd_internal.h"

/* some procfs helpers */
static int lprocfs_qsd_rd_state(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	struct qsd_instance	*qsd = (struct qsd_instance *)data;

	LASSERT(qsd != NULL);

	return snprintf(page, count,
			"target name:    %s\n"
			"quota enabled:  none\n",
			qsd->qsd_svname);
}

static struct lprocfs_vars lprocfs_quota_qsd_vars[] = {
	{ "info", lprocfs_qsd_rd_state, 0, 0},
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

	/* release accounting object */
	if (qqi->qqi_acct_obj != NULL && !IS_ERR(qqi->qqi_acct_obj)) {
		lu_object_put(env, &qqi->qqi_acct_obj->do_lu);
		qqi->qqi_acct_obj = NULL;
	}

	OBD_FREE_PTR(qqi);
	EXIT;
}

/*
 * Allocate and initialize a qsd_qtype_info structure for quota type \qtype.
 * This opens the accounting object and initializes the proc file.
 * It's called on OSD start when the qsd instance is created.
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
	ENTRY;

	LASSERT(qsd->qsd_type_array[qtype] == NULL);

	/* allocate structure for this quota type */
	OBD_ALLOC_PTR(qqi);
	if (qqi == NULL)
		RETURN(-ENOMEM);
	qsd->qsd_type_array[qtype] = qqi;

	/* set backpointer and other parameters */
	qqi->qqi_qsd   = qsd;
	qqi->qqi_qtype = qtype;

        /* open accounting object */
        LASSERT(qqi->qqi_acct_obj == NULL);
	qqi->qqi_acct_obj = acct_obj_lookup(env, qsd->qsd_dev,
					    qtype == USRQUOTA ? ACCT_USER_OID
							      : ACCT_GROUP_OID);
	/* don't print any error message on failure in order not to confuse
	 * non-OFD user (e.g. 2.3 MDT stack) */
	if (IS_ERR(qqi->qqi_acct_obj))
		qqi->qqi_acct_obj = NULL;

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

	/* remove qsd proc entry */
	if (qsd->qsd_proc != NULL && !IS_ERR(qsd->qsd_proc)) {
		lprocfs_remove(&qsd->qsd_proc);
		qsd->qsd_proc = NULL;
	}

	/* free per-quota type data */
	for (qtype = USRQUOTA; qtype < MAXQUOTAS; qtype++)
		qsd_qtype_fini(env, qsd, qtype);

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
 * identified by \dev. For now, this function just create procfs files which
 * dumps the accounting information
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
	struct qsd_instance	*qsd;
	int			 rc, qtype;
	ENTRY;

	/* allocate qsd instance */
	OBD_ALLOC_PTR(qsd);
	if (qsd == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* copy service name */
	strncpy(qsd->qsd_svname, svname, MAX_OBD_NAME);

	/* grab reference on osd device */
	lu_device_get(&dev->dd_lu_dev);
	lu_ref_add(&dev->dd_lu_dev.ld_reference, "qsd", qsd);
	qsd->qsd_dev = dev;

	/* register procfs directory */
	qsd->qsd_proc = lprocfs_register(QSD_DIR, osd_proc,
					 lprocfs_quota_qsd_vars, qsd);
	if (IS_ERR(qsd->qsd_proc)) {
		rc = PTR_ERR(qsd->qsd_proc);
		CERROR("%s: fail to create quota slave proc entry (%d)\n",
		       svname, rc);
		GOTO(out, rc);
        }

	/* initialize per-quota type data */
	for (qtype = USRQUOTA; qtype < MAXQUOTAS; qtype++) {
		rc = qsd_qtype_init(env, qsd, qtype);
		if (rc)
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
