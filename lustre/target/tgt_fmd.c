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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 *
 * Copyright (c) 2019, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/target/tgt_fmd.c
 *
 * This file provides functions to handle Filter Modification Data (FMD).
 * The FMD is responsible for file attributes to be applied in
 * Transaction ID (XID) order, so older requests can't re-write newer
 * attributes.
 *
 * FMD is organized as per-client list and identified by FID of object. Each
 * FMD stores FID of object and the highest received XID of modification
 * request for this object.
 *
 * FMD can expire if there are no updates for a long time to keep the list
 * reasonably small.
 *
 * Author: Andreas Dilger <adilger@whamcloud.com>
 * Author: Mike Pershin <mpershin@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include <obd_class.h>

#include "tgt_internal.h"

/**
 * Drop FMD reference and free it if reference drops to zero.
 *
 * Must be called with ted_fmd_lock held.
 *
 * \param[in] exp	OBD export
 * \param[in] fmd	FMD to put
 */
static inline void tgt_fmd_put_nolock(struct obd_export *exp,
				      struct tgt_fmd_data *fmd)
{
	struct tg_export_data *ted = &exp->exp_target_data;

	assert_spin_locked(&ted->ted_fmd_lock);
	if (--fmd->fmd_refcount == 0) {
		ted->ted_fmd_count--;
		list_del(&fmd->fmd_list);
		OBD_SLAB_FREE_PTR(fmd, tgt_fmd_kmem);
	}
}

/**
 * Wrapper to drop FMD reference with ted_fmd_lock held.
 *
 * \param[in] exp	OBD export
 * \param[in] fmd	FMD to put
 */
void tgt_fmd_put(struct obd_export *exp, struct tgt_fmd_data *fmd)
{
	struct tg_export_data *ted = &exp->exp_target_data;

	spin_lock(&ted->ted_fmd_lock);
	tgt_fmd_put_nolock(exp, fmd); /* caller reference */
	spin_unlock(&ted->ted_fmd_lock);
}

/**
 * Expire FMD entries.
 *
 * Expire entries from the FMD list if there are too many
 * of them or they are too old.
 *
 * This function must be called with ted_fmd_lock held.
 *
 * The \a keep FMD is not to be expired in any case. This parameter is used
 * by ofd_fmd_find_nolock() to prohibit a FMD that was just found from
 * expiring.
 *
 * \param[in] exp	OBD export
 * \param[in] keep	FMD to keep always
 */
static void tgt_fmd_expire_nolock(struct obd_export *exp,
				  struct tgt_fmd_data *keep)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct lu_target *lut = exp->exp_obd->u.obt.obt_lut;
	time64_t now = ktime_get_seconds();
	struct tgt_fmd_data *fmd, *tmp;

	list_for_each_entry_safe(fmd, tmp, &ted->ted_fmd_list, fmd_list) {
		if (fmd == keep)
			break;

		if (now < fmd->fmd_expire &&
		    ted->ted_fmd_count < lut->lut_fmd_max_num)
			break;

		list_del_init(&fmd->fmd_list);
		tgt_fmd_put_nolock(exp, fmd); /* list reference */
	}
}

/**
 * Expire FMD entries.
 *
 * This is a wrapper to call ofd_fmd_expire_nolock() with the required lock.
 *
 * \param[in] exp	OBD export
 */
void tgt_fmd_expire(struct obd_export *exp)
{
	struct tg_export_data *ted = &exp->exp_target_data;

	spin_lock(&ted->ted_fmd_lock);
	tgt_fmd_expire_nolock(exp, NULL);
	spin_unlock(&ted->ted_fmd_lock);
}

/**
 * Find FMD by specified FID.
 *
 * Function finds FMD entry by FID in the tg_export_data::ted_fmd_list.
 *
 * Caller must hold tg_export_data::ted_fmd_lock and take FMD reference.
 *
 * \param[in] exp	OBD export
 * \param[in] fid	FID of FMD to find
 *
 * \retval		struct tgt_fmd_data found by FID
 * \retval		NULL is FMD is not found
 */
static struct tgt_fmd_data *tgt_fmd_find_nolock(struct obd_export *exp,
						const struct lu_fid *fid)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct tgt_fmd_data *found = NULL, *fmd;
	struct lu_target *lut = exp->exp_obd->u.obt.obt_lut;
	time64_t now = ktime_get_seconds();

	assert_spin_locked(&ted->ted_fmd_lock);

	list_for_each_entry_reverse(fmd, &ted->ted_fmd_list, fmd_list) {
		if (lu_fid_eq(&fmd->fmd_fid, fid)) {
			found = fmd;
			list_move_tail(&fmd->fmd_list, &ted->ted_fmd_list);
			fmd->fmd_expire = now + lut->lut_fmd_max_age;
			break;
		}
	}

	tgt_fmd_expire_nolock(exp, found);

	return found;
}

/**
 * Find FMD by specified FID with locking.
 *
 * Wrapper to the ofd_fmd_find_nolock() with correct locks.
 *
 * \param[in] exp	OBD export
 * \param[in] fid	FID of FMD to find
 *
 * \retval		struct tgt_fmd_data found by FID
 * \retval		NULL indicates FMD is not found
 */
struct tgt_fmd_data *tgt_fmd_find(struct obd_export *exp,
				  const struct lu_fid *fid)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct tgt_fmd_data *fmd;

	spin_lock(&ted->ted_fmd_lock);
	fmd = tgt_fmd_find_nolock(exp, fid);
	if (fmd)
		fmd->fmd_refcount++;    /* caller reference */
	spin_unlock(&ted->ted_fmd_lock);

	return fmd;
}

/**
 * Find FMD by FID or create a new one if none is found.
 *
 * It is possible for this function to return NULL under memory pressure,
 * or if the passed FID is zero (which will only cause old entries to expire).
 * Currently this is not fatal because any FMD state is transient and
 * may also be freed when it gets sufficiently old.
 *
 * \param[in] exp	OBD export
 * \param[in] fid	FID of FMD to find
 *
 * \retval		struct tgt_fmd_data found by FID
 * \retval		NULL indicates FMD is not found
 */
struct tgt_fmd_data *tgt_fmd_get(struct obd_export *exp,
				 const struct lu_fid *fid)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct tgt_fmd_data *found = NULL, *fmd_new = NULL;

	OBD_SLAB_ALLOC_PTR(fmd_new, tgt_fmd_kmem);

	spin_lock(&ted->ted_fmd_lock);
	found = tgt_fmd_find_nolock(exp, fid);
	if (fmd_new) {
		if (!found) {
			list_add_tail(&fmd_new->fmd_list, &ted->ted_fmd_list);
			fmd_new->fmd_fid = *fid;
			fmd_new->fmd_refcount++;   /* list reference */
			found = fmd_new;
			ted->ted_fmd_count++;
		} else {
			OBD_SLAB_FREE_PTR(fmd_new, tgt_fmd_kmem);
		}
	}
	if (found) {
		found->fmd_refcount++; /* caller reference */
		found->fmd_expire = ktime_get_seconds() +
			class_exp2tgt(exp)->lut_fmd_max_age;
	} else {
		LCONSOLE_WARN("%s: cannot allocate FMD for "DFID
			      ", timestamps may be out of sync\n",
			      exp->exp_obd->obd_name, PFID(fid));
	}
	spin_unlock(&ted->ted_fmd_lock);

	return found;
}

#ifdef DO_FMD_DROP
/**
 * Drop FMD list reference so it will disappear when last reference is dropped
 * to zero.
 *
 * This function is called from ofd_destroy() and may only affect
 * the one client that is doing the unlink and at worst we have an stale entry
 * referencing an object that should never be used again.
 *
 * NB: this function is used only if DO_FMD_DROP is defined. It is not
 * currently defined, so FMD drop doesn't happen and FMD are dropped only
 * when expired.
 *
 * \param[in] exp	OBD export
 * \param[in] fid	FID of FMD to drop
 */
void tgt_fmd_drop(struct obd_export *exp, const struct lu_fid *fid)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct tgt_fmd_data *fmd = NULL;

	spin_lock(&ted->ted_fmd_lock);
	fmd = tgt_fmd_find_nolock(exp, fid);
	if (fmd) {
		list_del_init(&fmd->fmd_list);
		tgt_fmd_put_nolock(exp, fmd);
	}
	spin_unlock(&ted->ted_fmd_lock);
}
EXPORT_SYMBOL(tgt_fmd_drop);
#endif

/**
 * Remove all entries from FMD list.
 *
 * Cleanup function to free all FMD enries on the given export.
 *
 * \param[in] exp	OBD export
 */
void tgt_fmd_cleanup(struct obd_export *exp)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct tgt_fmd_data *fmd = NULL, *tmp;

	spin_lock(&ted->ted_fmd_lock);
	list_for_each_entry_safe(fmd, tmp, &ted->ted_fmd_list, fmd_list) {
		list_del_init(&fmd->fmd_list);
		if (fmd->fmd_refcount > 1) {
			CDEBUG(D_INFO,
			       "fmd %p still referenced (refcount = %d)\n",
			       fmd, fmd->fmd_refcount);
		}
		tgt_fmd_put_nolock(exp, fmd);
	}
	spin_unlock(&ted->ted_fmd_lock);
	LASSERT(list_empty(&exp->exp_target_data.ted_fmd_list));
}

/**
 * Update FMD with the latest request XID.
 *
 * Save a new setattr/punch XID in FMD if exists.
 *
 * \param[in] exp	OBD export
 * \param[in] fid	FID of FMD to find
 * \param[in] xid	request XID
 */
void tgt_fmd_update(struct obd_export *exp, const struct lu_fid *fid, __u64 xid)
{
	struct tgt_fmd_data *fmd;

	fmd = tgt_fmd_get(exp, fid);
	if (fmd) {
		if (fmd->fmd_mactime_xid < xid)
			fmd->fmd_mactime_xid = xid;
		tgt_fmd_put(exp, fmd);
	}
}
EXPORT_SYMBOL(tgt_fmd_update);

/**
 * Chech that time can be updated by the request with given XID.
 *
 * Check FMD XID if exists to be less than supplied XID
 *
 * \param[in] exp	OBD export
 * \param[in] fid	FID of FMD to find
 * \param[in] xid	request XID
 *
 * \retval true if FMD has no greater XID, so time attr can be updated
 */
bool tgt_fmd_check(struct obd_export *exp, const struct lu_fid *fid, __u64 xid)
{
	struct tgt_fmd_data *fmd;
	bool can_update = true;

	fmd = tgt_fmd_find(exp, fid);
	if (fmd) {
		can_update = fmd->fmd_mactime_xid < xid;
		tgt_fmd_put(exp, fmd);
	}

	return can_update;
}
EXPORT_SYMBOL(tgt_fmd_check);

