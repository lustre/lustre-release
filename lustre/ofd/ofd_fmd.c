/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/obdfilter/filter_fmd.c
 *
 *  Copyright (c) 2007 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <libcfs/libcfs.h>

#include "ofd_internal.h"

cfs_mem_cache_t *ll_fmd_cachep;

/* drop fmd reference, free it if last ref. must be called with fed_lock held.*/
static inline void filter_fmd_put_nolock(struct obd_export *exp,
                                         struct filter_mod_data *fmd)
{
        struct filter_export_data *fed = &exp->exp_filter_data;

        LASSERT_SPIN_LOCKED(&fed->fed_lock);
        if (--fmd->fmd_refcount == 0) {
                /* XXX when we have persistent reservations and the handle
                 * is stored herein we need to drop it here. */
                fed->fed_mod_count--;
                list_del(&fmd->fmd_list);
                OBD_SLAB_FREE(fmd, ll_fmd_cachep, sizeof(*fmd));
        }
}

/* drop fmd reference, free it if last ref */
void filter_fmd_put(struct obd_export *exp, struct filter_mod_data *fmd)
{
        struct filter_export_data *fed = &exp->exp_filter_data;

        if (fmd == NULL)
                return;

        spin_lock(&fed->fed_lock);
        filter_fmd_put_nolock(exp, fmd); /* caller reference */
        spin_unlock(&fed->fed_lock);
}

/* expire entries from the end of the list if there are too many
 * or they are too old */
static void filter_fmd_expire_nolock(struct obd_export *exp,
                                     struct filter_mod_data *keep)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_device *ofd = filter_exp(exp);

        struct filter_mod_data *fmd, *tmp;
        cfs_time_t now = cfs_time_current();

        list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
                if (fmd == keep)
                        break;

                if (cfs_time_before(now, fmd->fmd_expire) &&
                    fed->fed_mod_count < ofd->ofd_fmd_max_num)
                        break;

                list_del_init(&fmd->fmd_list);
                filter_fmd_put_nolock(exp, fmd); /* list reference */
        }
}

void filter_fmd_expire(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;

        spin_lock(&fed->fed_lock);
        filter_fmd_expire_nolock(exp, NULL);
        spin_unlock(&fed->fed_lock);
}

/* find specified fid in fed_fmd_list.
 * caller must hold fed_lock and take fmd reference itself */
static struct filter_mod_data *filter_fmd_find_nolock(struct obd_export *exp,
						      const struct lu_fid *fid)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *found = NULL, *fmd;
        struct filter_device *ofd = filter_exp(exp);
        cfs_time_t now = cfs_time_current();

        LASSERT_SPIN_LOCKED(&fed->fed_lock);

        list_for_each_entry_reverse(fmd, &fed->fed_mod_list, fmd_list) {
                if (lu_fid_eq(&fmd->fmd_fid, fid)) {
                        found = fmd;
                        list_del(&fmd->fmd_list);
                        list_add_tail(&fmd->fmd_list, &fed->fed_mod_list);
                        fmd->fmd_expire = cfs_time_add(now, ofd->ofd_fmd_max_age);
                        break;
                }
        }

        filter_fmd_expire_nolock(exp, found);

        return found;
}

/* Find fmd based on fid or return NULL if not found. */
struct filter_mod_data *filter_fmd_find(struct obd_export *exp,
                                        struct lu_fid *fid)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *fmd;

        spin_lock(&fed->fed_lock);
        fmd = filter_fmd_find_nolock(exp, fid);
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
struct filter_mod_data *filter_fmd_get(struct obd_export *exp,
                                       struct lu_fid *fid)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_device *ofd = filter_exp(exp);
        struct filter_mod_data *found = NULL, *fmd_new = NULL;
        cfs_time_t now = cfs_time_current();

        OBD_SLAB_ALLOC(fmd_new, ll_fmd_cachep, CFS_ALLOC_IO, sizeof(*fmd_new));

        spin_lock(&fed->fed_lock);
        found = filter_fmd_find_nolock(exp, fid);
        if (fmd_new) {
                if (found == NULL) {
                        list_add_tail(&fmd_new->fmd_list, &fed->fed_mod_list);
                        fmd_new->fmd_fid = *fid;
                        fmd_new->fmd_refcount++;   /* list reference */
                        found = fmd_new;
                        fed->fed_mod_count++;
                } else {
                        OBD_SLAB_FREE(fmd_new, ll_fmd_cachep, sizeof(*fmd_new));
                }
        }
        if (found) {
                found->fmd_refcount++;          /* caller reference */
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
void filter_fmd_drop(struct obd_export *exp, struct lu_fid *fid)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *found = NULL;

        spin_lock(&fed->fed_lock);
        found = filter_fmd_find_nolock(exp, fid);
        if (found) {
                list_del_init(&found->fmd_list);
                filter_fmd_put_nolock(exp, found);
        }
        spin_unlock(&fed->fed_lock);
}
#endif

/* remove all entries from fmd list */
void filter_fmd_cleanup(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *fmd = NULL, *tmp;

        spin_lock(&fed->fed_lock);
        list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
                list_del_init(&fmd->fmd_list);
                if (fmd->fmd_refcount > 1) {
                        CDEBUG(D_INFO, "fmd %p still referenced (refcount = %d)\n",
                               fmd, fmd->fmd_refcount);
                }
                filter_fmd_put_nolock(exp, fmd);
        }
        spin_unlock(&fed->fed_lock);
}

int ofd_fmd_init(void)
{
        ll_fmd_cachep = cfs_mem_cache_create("ll_fmd_cache",
                                             sizeof(struct filter_mod_data),
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
