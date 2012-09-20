/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lod/lod_qos.c
 *
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <libcfs/libcfs.h>
#include <obd_class.h>
#include <obd_lov.h>
#include <lustre/lustre_idl.h>
#include "lod_internal.h"

/*
 * force QoS policy (not RR) to be used for testing purposes
 */
#define FORCE_QOS_

#define D_QOS   D_OTHER

#if 0
#define QOS_DEBUG(fmt, ...)     CDEBUG(D_OTHER, fmt, ## __VA_ARGS__)
#define QOS_CONSOLE(fmt, ...)   LCONSOLE(D_OTHER, fmt, ## __VA_ARGS__)
#else
#define QOS_DEBUG(fmt, ...)
#define QOS_CONSOLE(fmt, ...)
#endif

#define TGT_BAVAIL(i) (OST_TGT(lod,i)->ltd_statfs.os_bavail * \
		       OST_TGT(lod,i)->ltd_statfs.os_bsize)

int qos_add_tgt(struct lod_device *lod, struct lod_ost_desc *ost_desc)
{
	struct lov_qos_oss *oss = NULL, *temposs;
	struct obd_export  *exp = ost_desc->ltd_exp;
	int		    rc = 0, found = 0;
	cfs_list_t	   *list;
	ENTRY;

	cfs_down_write(&lod->lod_qos.lq_rw_sem);
	/*
	 * a bit hacky approach to learn NID of corresponding connection
	 * but there is no official API to access information like this
	 * with OSD API.
	 */
	cfs_list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
		if (obd_uuid_equals(&oss->lqo_uuid,
				    &exp->exp_connection->c_remote_uuid)) {
			found++;
			break;
		}
	}

	if (!found) {
		OBD_ALLOC_PTR(oss);
		if (!oss)
			GOTO(out, rc = -ENOMEM);
		memcpy(&oss->lqo_uuid, &exp->exp_connection->c_remote_uuid,
		       sizeof(oss->lqo_uuid));
	} else {
		/* Assume we have to move this one */
		cfs_list_del(&oss->lqo_oss_list);
	}

	oss->lqo_ost_count++;
	ost_desc->ltd_qos.ltq_oss = oss;

	CDEBUG(D_QOS, "add tgt %s to OSS %s (%d OSTs)\n",
	       obd_uuid2str(&ost_desc->ltd_uuid), obd_uuid2str(&oss->lqo_uuid),
	       oss->lqo_ost_count);

	/* Add sorted by # of OSTs.  Find the first entry that we're
	   bigger than... */
	list = &lod->lod_qos.lq_oss_list;
	cfs_list_for_each_entry(temposs, list, lqo_oss_list) {
		if (oss->lqo_ost_count > temposs->lqo_ost_count)
			break;
	}
	/* ...and add before it.  If we're the first or smallest, temposs
	   points to the list head, and we add to the end. */
	cfs_list_add_tail(&oss->lqo_oss_list, &temposs->lqo_oss_list);

	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_rr.lqr_dirty = 1;

out:
	cfs_up_write(&lod->lod_qos.lq_rw_sem);
	RETURN(rc);
}

int qos_del_tgt(struct lod_device *lod, struct lod_ost_desc *ost_desc)
{
	struct lov_qos_oss *oss;
	int                 rc = 0;
	ENTRY;

	cfs_down_write(&lod->lod_qos.lq_rw_sem);
	oss = ost_desc->ltd_qos.ltq_oss;
	if (!oss)
		GOTO(out, rc = -ENOENT);

	oss->lqo_ost_count--;
	if (oss->lqo_ost_count == 0) {
		CDEBUG(D_QOS, "removing OSS %s\n",
		       obd_uuid2str(&oss->lqo_uuid));
		cfs_list_del(&oss->lqo_oss_list);
		ost_desc->ltd_qos.ltq_oss = NULL;
		OBD_FREE_PTR(oss);
	}

	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_rr.lqr_dirty = 1;
out:
	cfs_up_write(&lod->lod_qos.lq_rw_sem);
	RETURN(rc);
}

