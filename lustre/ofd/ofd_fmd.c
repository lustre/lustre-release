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
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_fmd.c
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
 * Author: Andreas Dilger <andreas.dilger@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

static struct kmem_cache *ll_fmd_cachep;

/**
 * Drop FMD reference and free it if reference drops to zero.
 *
 * Must be called with fed_lock held.
 *
 * \param[in] exp	OBD export
 * \param[in] fmd	FMD to put
 */
static inline void ofd_fmd_put_nolock(struct obd_export *exp,
				      struct ofd_mod_data *fmd)
{
	struct filter_export_data *fed = &exp->exp_filter_data;

	assert_spin_locked(&fed->fed_lock);
	if (--fmd->fmd_refcount == 0) {
		/* XXX when we have persistent reservations and the handle
		 * is stored herein we need to drop it here. */
		fed->fed_mod_count--;
		list_del(&fmd->fmd_list);
		OBD_SLAB_FREE(fmd, ll_fmd_cachep, sizeof(*fmd));
	}
}

/**
 * Wrapper to drop FMD reference with fed_lock held.
 *
 * \param[in] exp	OBD export
 * \param[in] fmd	FMD to put
 */
void ofd_fmd_put(struct obd_export *exp, struct ofd_mod_data *fmd)
{
	struct filter_export_data *fed = &exp->exp_filter_data;

	if (fmd == NULL)
		return;

	spin_lock(&fed->fed_lock);
	ofd_fmd_put_nolock(exp, fmd); /* caller reference */
	spin_unlock(&fed->fed_lock);
}

/**
 * Expire FMD entries.
 *
 * Expire entries from the FMD list if there are too many
 * of them or they are too old.
 *
 * This function must be called with fed_lock held.
 *
 * The \a keep FMD is not to be expired in any case. This parameter is used
 * by ofd_fmd_find_nolock() to prohibit a FMD that was just found from
 * expiring.
 *
 * \param[in] exp	OBD export
 * \param[in] keep	FMD to keep always
 */
static void ofd_fmd_expire_nolock(struct obd_export *exp,
				  struct ofd_mod_data *keep)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct ofd_mod_data		*fmd, *tmp;

	cfs_time_t now = cfs_time_current();

	list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
		if (fmd == keep)
			break;

		if (cfs_time_before(now, fmd->fmd_expire) &&
		    fed->fed_mod_count < ofd->ofd_fmd_max_num)
			break;

		list_del_init(&fmd->fmd_list);
		ofd_fmd_put_nolock(exp, fmd); /* list reference */
	}
}

/**
 * Expire FMD entries.
 *
 * This is a wrapper to call ofd_fmd_expire_nolock() with the required lock.
 *
 * \param[in] exp	OBD export
 */
void ofd_fmd_expire(struct obd_export *exp)
{
	struct filter_export_data *fed = &exp->exp_filter_data;

	spin_lock(&fed->fed_lock);
	ofd_fmd_expire_nolock(exp, NULL);
	spin_unlock(&fed->fed_lock);
}

/**
 * Find FMD by specified FID.
 *
 * Function finds FMD entry by FID in the filter_export_data::fed_fmd_list.
 *
 * Caller must hold filter_export_data::fed_lock and take FMD reference.
 *
 * \param[in] exp	OBD export
 * \param[in] fid	FID of FMD to find
 *
 * \retval		struct ofd_mod_data found by FID
 * \retval		NULL is FMD is not found
 */
static struct ofd_mod_data *ofd_fmd_find_nolock(struct obd_export *exp,
						const struct lu_fid *fid)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_mod_data		*found = NULL, *fmd;
	struct ofd_device		*ofd = ofd_exp(exp);

	cfs_time_t now = cfs_time_current();

	assert_spin_locked(&fed->fed_lock);

	list_for_each_entry_reverse(fmd, &fed->fed_mod_list, fmd_list) {
		if (lu_fid_eq(&fmd->fmd_fid, fid)) {
			found = fmd;
			list_del(&fmd->fmd_list);
			list_add_tail(&fmd->fmd_list, &fed->fed_mod_list);
			fmd->fmd_expire = cfs_time_add(now, ofd->ofd_fmd_max_age);
			break;
		}
	}

	ofd_fmd_expire_nolock(exp, found);

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
 * \retval		struct ofd_mod_data found by FID
 * \retval		NULL indicates FMD is not found
 */
struct ofd_mod_data *ofd_fmd_find(struct obd_export *exp,
				  const struct lu_fid *fid)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_mod_data		*fmd;

	spin_lock(&fed->fed_lock);
	fmd = ofd_fmd_find_nolock(exp, fid);
	if (fmd)
		fmd->fmd_refcount++;    /* caller reference */
	spin_unlock(&fed->fed_lock);

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
 * \retval		struct ofd_mod_data found by FID
 * \retval		NULL indicates FMD is not found
 */
struct ofd_mod_data *ofd_fmd_get(struct obd_export *exp, const struct lu_fid *fid)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct ofd_mod_data		*found = NULL, *fmd_new = NULL;

	cfs_time_t now = cfs_time_current();

	OBD_SLAB_ALLOC_PTR(fmd_new, ll_fmd_cachep);

	spin_lock(&fed->fed_lock);
	found = ofd_fmd_find_nolock(exp, fid);
	if (fmd_new) {
		if (found == NULL) {
			list_add_tail(&fmd_new->fmd_list,
				      &fed->fed_mod_list);
			fmd_new->fmd_fid = *fid;
			fmd_new->fmd_refcount++;   /* list reference */
			found = fmd_new;
			fed->fed_mod_count++;
		} else {
			OBD_SLAB_FREE_PTR(fmd_new, ll_fmd_cachep);
		}
	}
	if (found) {
		found->fmd_refcount++; /* caller reference */
		found->fmd_expire = cfs_time_add(now, ofd->ofd_fmd_max_age);
	}

	spin_unlock(&fed->fed_lock);

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
void ofd_fmd_drop(struct obd_export *exp, const struct lu_fid *fid)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_mod_data		*found = NULL;

	spin_lock(&fed->fed_lock);
	found = ofd_fmd_find_nolock(exp, fid);
	if (found) {
		list_del_init(&found->fmd_list);
		ofd_fmd_put_nolock(exp, found);
	}
	spin_unlock(&fed->fed_lock);
}
#endif

/**
 * Remove all entries from FMD list.
 *
 * Cleanup function to free all FMD enries on the given export.
 *
 * \param[in] exp	OBD export
 */
void ofd_fmd_cleanup(struct obd_export *exp)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_mod_data		*fmd = NULL, *tmp;

	spin_lock(&fed->fed_lock);
	list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
		list_del_init(&fmd->fmd_list);
		if (fmd->fmd_refcount > 1) {
			CDEBUG(D_INFO, "fmd %p still referenced (refcount = %d)\n",
			       fmd, fmd->fmd_refcount);
		}
		ofd_fmd_put_nolock(exp, fmd);
	}
	spin_unlock(&fed->fed_lock);
}

/**
 * Initialize FMD subsystem.
 *
 * This function is called upon OFD setup and initialize memory to be used
 * by FMD entries.
 */
int ofd_fmd_init(void)
{
	ll_fmd_cachep = kmem_cache_create("ll_fmd_cache",
					  sizeof(struct ofd_mod_data),
					  0, 0, NULL);
	if (!ll_fmd_cachep)
		return -ENOMEM;
	else
		return 0;
}

/**
 * Stop FMD subsystem.
 *
 * This function is called upon OFD cleanup and destroy memory used
 * by FMD entries.
 */
void ofd_fmd_exit(void)
{
	if (ll_fmd_cachep) {
		kmem_cache_destroy(ll_fmd_cachep);
		ll_fmd_cachep = NULL;
	}
}
