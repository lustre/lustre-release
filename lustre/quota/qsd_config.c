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
 * Copyright (c) 2012, 2014, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <obd_class.h>
#include <uapi/linux/lustre_param.h>

#include "qsd_internal.h"

static struct list_head qfs_list = LIST_HEAD_INIT(qfs_list);
/* protect the qfs_list */
static DEFINE_SPINLOCK(qfs_list_lock);

/*
 * Put reference of qsd_fsinfo.
 *
 * \param  qfs    - the qsd_fsinfo to be put
 */
void qsd_put_fsinfo(struct qsd_fsinfo *qfs)
{
	ENTRY;
	LASSERT(qfs != NULL);

	spin_lock(&qfs_list_lock);
	LASSERT(qfs->qfs_ref > 0);
	qfs->qfs_ref--;
	if (qfs->qfs_ref == 0) {
		LASSERT(list_empty(&qfs->qfs_qsd_list));
		list_del(&qfs->qfs_link);
		OBD_FREE_PTR(qfs);
	}
	spin_unlock(&qfs_list_lock);
	EXIT;
}

/*
 * Find or create a qsd_fsinfo
 *
 * \param  name   - filesystem name
 * \param  create - when @create is non-zero, create new one if fail to
 *                  find existing qfs by @name
 *
 * \retval qsd_fsinfo - success
 * \retval NULL          - failure
 */
struct qsd_fsinfo *qsd_get_fsinfo(char *name, bool create)
{
	struct qsd_fsinfo	*qfs, *new = NULL;
	ENTRY;

	if (name == NULL ||  strlen(name) >= MTI_NAME_MAXLEN)
		RETURN(NULL);

	if (create) {
		/* pre-allocate a qsd_fsinfo in case there isn't one already.
		 * we can afford the extra cost since qsd_get_fsinfo() isn't
		 * called very often with create = true */

		OBD_ALLOC_PTR(new);
		if (new == NULL)
			RETURN(NULL);

		mutex_init(&new->qfs_mutex);
		INIT_LIST_HEAD(&new->qfs_qsd_list);
		strcpy(new->qfs_name, name);
		new->qfs_ref = 1;
	}

	/* search in the fsinfo list */
	spin_lock(&qfs_list_lock);
	list_for_each_entry(qfs, &qfs_list, qfs_link) {
		if (!strcmp(qfs->qfs_name, name)) {
			qfs->qfs_ref++;
			goto out;
		}
	}

	qfs = NULL; /* not found */

	if (new) {
		/* not found, but we were asked to create a new one */
		list_add_tail(&new->qfs_link, &qfs_list);
		qfs = new;
		new = NULL;
	}
out:
	spin_unlock(&qfs_list_lock);

	if (new)
		OBD_FREE_PTR(new);
	RETURN(qfs);
}

/*
 * Quota configuration handlers in charge of processing all per-filesystem quota
 * parameters set via conf_param.
 *
 * \param lcfg - quota configuration log to be processed
 */
int qsd_process_config(struct lustre_cfg *lcfg)
{
	struct qsd_fsinfo	*qfs;
	char			*fsname = lustre_cfg_string(lcfg, 0);
	char			*cfgstr = lustre_cfg_string(lcfg, 1);
	char			*keystr, *valstr;
	int			 rc, pool, enabled = 0;
	bool			 reint = false;
	ENTRY;

	CDEBUG(D_QUOTA, "processing quota parameter: fs:%s cfgstr:%s\n", fsname,
	       cfgstr);

	if (class_match_param(cfgstr, PARAM_QUOTA, &keystr) != 0)
		RETURN(-EINVAL);

	if (!class_match_param(keystr, QUOTA_METAPOOL_NAME, &valstr))
		pool = LQUOTA_RES_MD;
	else if (!class_match_param(keystr, QUOTA_DATAPOOL_NAME, &valstr))
		pool = LQUOTA_RES_DT;
	else
		RETURN(-EINVAL);

	qfs = qsd_get_fsinfo(fsname, 0);
	if (qfs == NULL) {
		CERROR("failed to find quota filesystem information for %s\n",
		       fsname);
		RETURN(-ENOENT);
	}

	if (strchr(valstr, 'u'))
		enabled |= 1 << USRQUOTA;
	if (strchr(valstr, 'g'))
		enabled |= 1 << GRPQUOTA;
	if (strchr(valstr, 'p'))
		enabled |= 1 << PRJQUOTA;

	mutex_lock(&qfs->qfs_mutex);
	if (qfs->qfs_enabled[pool - LQUOTA_FIRST_RES] == enabled)
		/* no change required */
		GOTO(out, rc = 0);

	if ((qfs->qfs_enabled[pool - LQUOTA_FIRST_RES] & enabled) != enabled)
		reint = true;

	qfs->qfs_enabled[pool - LQUOTA_FIRST_RES] = enabled;

	/* trigger reintegration for all qsd */
	if (reint) {
		struct qsd_instance	*qsd;
		struct qsd_qtype_info	*qqi;

		list_for_each_entry(qsd, &qfs->qfs_qsd_list, qsd_link) {
			bool	skip = false;
			int	type;

			/* start reintegration only if qsd_prepare() was
			 * successfully called */
			read_lock(&qsd->qsd_lock);
			if (!qsd->qsd_prepared)
				skip = true;
			read_unlock(&qsd->qsd_lock);
			if (skip)
				continue;

			for (type = USRQUOTA; type < LL_MAXQUOTAS; type++) {
				qqi = qsd->qsd_type_array[type];
				if (qqi->qqi_acct_failed) {
					LCONSOLE_ERROR("%s: can't enable quota "
						       "enforcement since space "
						       "accounting isn't functional. "
						       "Please run tunefs.lustre "
						       "--quota on an unmounted "
						       "filesystem if not done already"
						       "\n", qsd->qsd_svname);
					continue;
				}
				qsd_start_reint_thread(qqi);
			}
		}
	}
out:
	mutex_unlock(&qfs->qfs_mutex);
	qsd_put_fsinfo(qfs);
	RETURN(0);
}
