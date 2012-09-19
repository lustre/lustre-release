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
 */
/*
 * lustre/lod/lod_lov.c
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com> 
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <obd_lov.h>

#include "lod_internal.h"

/*
 * Keep a refcount of lod->lod_osts usage to prevent racing with
 * addition/deletion. Any function that expects lov_tgts to remain stationary
 * must take a ref.
 *
 * \param lod - is the lod device from which we want to grab a reference
 */
void lod_getref(struct lod_device *lod)
{
	cfs_down_read(&lod->lod_rw_sem);
	cfs_mutex_lock(&lod->lod_mutex);
	lod->lod_refcount++;
	cfs_mutex_unlock(&lod->lod_mutex);
}

/*
 * Companion of lod_getref() to release a reference on the lod table.
 * If this is the last reference and the ost entry was scheduled for deletion,
 * the descriptor is removed from the array.
 *
 * \param lod - is the lod device from which we release a reference
 */
void lod_putref(struct lod_device *lod)
{
	cfs_mutex_lock(&lod->lod_mutex);
	lod->lod_refcount--;
	if (lod->lod_refcount == 0 && lod->lod_death_row) {
		struct lod_ost_desc *ost_desc, *tmp;
		int                  idx;
		CFS_LIST_HEAD(kill);

		CDEBUG(D_CONFIG, "destroying %d lod desc\n",
		       lod->lod_death_row);

		cfs_foreach_bit(lod->lod_ost_bitmap, idx) {
			ost_desc = OST_TGT(lod, idx);
			LASSERT(ost_desc);

			if (!ost_desc->ltd_reap)
				continue;

			cfs_list_add(&ost_desc->ltd_kill, &kill);
			/* XXX: remove from the pool */
			OST_TGT(lod, idx) = NULL;
			lod->lod_ostnr--;
			cfs_bitmap_clear(lod->lod_ost_bitmap, idx);
			if (ost_desc->ltd_active)
				lod->lod_desc.ld_active_tgt_count--;
			lod->lod_death_row--;
		}
		cfs_mutex_unlock(&lod->lod_mutex);
		cfs_up_read(&lod->lod_rw_sem);

		cfs_list_for_each_entry_safe(ost_desc, tmp, &kill, ltd_kill) {
			int rc;
			cfs_list_del(&ost_desc->ltd_kill);
			/* XXX: remove from QoS structures */
			/* disconnect from OSP */
			rc = obd_disconnect(ost_desc->ltd_exp);
			if (rc)
				CERROR("%s: failed to disconnect %s (%d)\n",
				       lod2obd(lod)->obd_name,
				       obd_uuid2str(&ost_desc->ltd_uuid), rc);
			OBD_FREE_PTR(ost_desc);
		}
	} else {
		cfs_mutex_unlock(&lod->lod_mutex);
		cfs_up_read(&lod->lod_rw_sem);
	}
}

