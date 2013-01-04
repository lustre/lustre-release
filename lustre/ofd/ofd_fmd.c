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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 *  lustre/ofd/filter_fmd.c
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

static cfs_mem_cache_t *ll_fmd_cachep;

/* drop fmd reference, free it if last ref. must be called with fed_lock held.*/
static inline void ofd_fmd_put_nolock(struct obd_export *exp,
				      struct ofd_mod_data *fmd)
{
	struct filter_export_data *fed = &exp->exp_filter_data;

	LASSERT_SPIN_LOCKED(&fed->fed_lock);
	if (--fmd->fmd_refcount == 0) {
		/* XXX when we have persistent reservations and the handle
		 * is stored herein we need to drop it here. */
		fed->fed_mod_count--;
		cfs_list_del(&fmd->fmd_list);
		OBD_SLAB_FREE(fmd, ll_fmd_cachep, sizeof(*fmd));
	}
}

/* drop fmd reference, free it if last ref */
void ofd_fmd_put(struct obd_export *exp, struct ofd_mod_data *fmd)
{
	struct filter_export_data *fed = &exp->exp_filter_data;

	if (fmd == NULL)
		return;

	spin_lock(&fed->fed_lock);
	ofd_fmd_put_nolock(exp, fmd); /* caller reference */
	spin_unlock(&fed->fed_lock);
}

/* expire entries from the end of the list if there are too many
 * or they are too old */
static void ofd_fmd_expire_nolock(struct obd_export *exp,
				  struct ofd_mod_data *keep)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct ofd_mod_data		*fmd, *tmp;

	cfs_time_t now = cfs_time_current();

	cfs_list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
		if (fmd == keep)
			break;

		if (cfs_time_before(now, fmd->fmd_expire) &&
		    fed->fed_mod_count < ofd->ofd_fmd_max_num)
			break;

		cfs_list_del_init(&fmd->fmd_list);
		ofd_fmd_put_nolock(exp, fmd); /* list reference */
	}
}

void ofd_fmd_expire(struct obd_export *exp)
{
	struct filter_export_data *fed = &exp->exp_filter_data;

	spin_lock(&fed->fed_lock);
	ofd_fmd_expire_nolock(exp, NULL);
	spin_unlock(&fed->fed_lock);
}

/* find specified fid in fed_fmd_list.
 * caller must hold fed_lock and take fmd reference itself */
static struct ofd_mod_data *ofd_fmd_find_nolock(struct obd_export *exp,
						const struct lu_fid *fid)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_mod_data		*found = NULL, *fmd;
	struct ofd_device		*ofd = ofd_exp(exp);

	cfs_time_t now = cfs_time_current();

	LASSERT_SPIN_LOCKED(&fed->fed_lock);

	cfs_list_for_each_entry_reverse(fmd, &fed->fed_mod_list, fmd_list) {
		if (lu_fid_eq(&fmd->fmd_fid, fid)) {
			found = fmd;
			cfs_list_del(&fmd->fmd_list);
			cfs_list_add_tail(&fmd->fmd_list, &fed->fed_mod_list);
			fmd->fmd_expire = cfs_time_add(now, ofd->ofd_fmd_max_age);
			break;
		}
	}

	ofd_fmd_expire_nolock(exp, found);

	return found;
}

/* Find fmd based on fid or return NULL if not found. */
struct ofd_mod_data *ofd_fmd_find(struct obd_export *exp,
				  struct lu_fid *fid)
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

/* Find fmd based on FID, or create a new one if none is found.
 * It is possible for this function to return NULL under memory pressure,
 * or if fid = 0 is passed (which will only cause old entries to expire).
 * Currently this is not fatal because any fmd state is transient and
 * may also be freed when it gets sufficiently old. */
struct ofd_mod_data *ofd_fmd_get(struct obd_export *exp, struct lu_fid *fid)
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
			cfs_list_add_tail(&fmd_new->fmd_list,
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
/* drop fmd list reference so it will disappear when last reference is put.
 * This isn't so critical because it would in fact only affect the one client
 * that is doing the unlink and at worst we have an stale entry referencing
 * an object that should never be used again. */
void ofd_fmd_drop(struct obd_export *exp, struct lu_fid *fid)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_mod_data		*found = NULL;

	spin_lock(&fed->fed_lock);
	found = ofd_fmd_find_nolock(exp, fid);
	if (found) {
		cfs_list_del_init(&found->fmd_list);
		ofd_fmd_put_nolock(exp, found);
	}
	spin_unlock(&fed->fed_lock);
}
#endif

/* remove all entries from fmd list */
void ofd_fmd_cleanup(struct obd_export *exp)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct ofd_mod_data		*fmd = NULL, *tmp;

	spin_lock(&fed->fed_lock);
	cfs_list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
		cfs_list_del_init(&fmd->fmd_list);
		if (fmd->fmd_refcount > 1) {
			CDEBUG(D_INFO, "fmd %p still referenced (refcount = %d)\n",
			       fmd, fmd->fmd_refcount);
		}
		ofd_fmd_put_nolock(exp, fmd);
	}
	spin_unlock(&fed->fed_lock);
}

int ofd_fmd_init(void)
{
	ll_fmd_cachep = cfs_mem_cache_create("ll_fmd_cache",
					     sizeof(struct ofd_mod_data),
					     0, 0);
	if (!ll_fmd_cachep)
		return -ENOMEM;
	else
		return 0;
}

void ofd_fmd_exit(void)
{
	if (ll_fmd_cachep) {
		int rc = cfs_mem_cache_destroy(ll_fmd_cachep);

		LASSERTF(rc == 0, "Cannot destroy ll_fmd_cachep: rc %d\n", rc);
		ll_fmd_cachep = NULL;
	}
}
