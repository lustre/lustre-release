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
 * Copyright (c) 2023, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 */
#define DEBUG_SUBSYSTEM S_SEC

#include <lustre_idmap.h>
#include <md_object.h>
#include <upcall_cache.h>
#include "upcall_cache_internal.h"

inline void refresh_entry_internal(struct upcall_cache *cache,
				   struct upcall_cache_entry *entry,
				   __u32 fsgid, struct group_info **ginfo)
{
	get_entry(entry);
	entry->u.identity.mi_uid = entry->ue_key;
	entry->u.identity.mi_gid = fsgid;
	if (*ginfo)
		entry->u.identity.mi_ginfo = *ginfo;
	entry->u.identity.mi_nperms = 0;
	entry->u.identity.mi_perms = NULL;
	entry->ue_expire = ktime_get_seconds() + cache->uc_entry_expire;
	UC_CACHE_SET_VALID(entry);
	put_entry(cache, entry);

	CDEBUG(D_OTHER,
	       "%s: INTERNAL refreshed entry for '%llu' with %d groups\n",
	       cache->uc_name, entry->ue_key,
	       *ginfo ? (*ginfo)->ngroups : 0);

	*ginfo = NULL;
}

int upcall_cache_get_entry_internal(struct upcall_cache *cache,
				    struct upcall_cache_entry *entry,
				    void *args, gid_t *fsgid,
				    struct group_info **pginfo)
{
	struct lu_ucred *uc = (struct lu_ucred *)args;
	gid_t inval = (__u32)__kgid_val(INVALID_GID);
	struct md_identity *identity;
	bool supp_in_ginfo[2];
	gid_t *groups = NULL, *glist_p;
	int i, groups_num, ginfo_ngroups = 0, rc = 0;

	if (*pginfo || !uc)
		/* ginfo already built, or no creds provided
		 * => return immediately
		 */
		goto out;

restart:
	groups_num = 0;
	/* We just deal with NEW and VALID entries. Other states will
	 * be handled by the caller, no need to return an error.
	 */
	if (!UC_CACHE_IS_NEW(entry) && !UC_CACHE_IS_VALID(entry))
		goto out;

	identity = &entry->u.identity;
	*fsgid = uc->uc_fsgid;
	supp_in_ginfo[0] = (uc->uc_suppgids[0] == inval);
	supp_in_ginfo[1] = (uc->uc_suppgids[1] == inval);
	if (identity->mi_ginfo && identity->mi_ginfo->ngroups)
		ginfo_ngroups = identity->mi_ginfo->ngroups;

	/* check if provided supp groups are already in cache */
	for (i = 0; i < 2 && uc->uc_suppgids[i] != inval; i++) {
		if (unlikely(uc->uc_suppgids[i] == uc->uc_fsuid)) {
			/* Do not place user's group ID in group list */
			supp_in_ginfo[i] = true;
		} else if (ginfo_ngroups) {
			atomic_inc(&identity->mi_ginfo->usage);
			supp_in_ginfo[i] =
				lustre_groups_search(identity->mi_ginfo,
						     uc->uc_suppgids[i]);
			atomic_dec(&identity->mi_ginfo->usage);
		}
	}

	/* build new list of groups, which is a merge of provided supp
	 * groups and all other groups already in cache
	 */
	if (!supp_in_ginfo[0] || !supp_in_ginfo[1]) {
		CDEBUG(D_OTHER,
		       "%s: INTERNAL might add suppgids %d,%d for entry '%llu'\n",
		       cache->uc_name, uc->uc_suppgids[0],
		       uc->uc_suppgids[1], entry->ue_key);

		if (!supp_in_ginfo[0])
			groups_num++;
		if (!supp_in_ginfo[1])
			groups_num++;
		CFS_ALLOC_PTR_ARRAY(groups, groups_num + ginfo_ngroups);
		if (groups == NULL)
			GOTO(out, rc = -ENOMEM);

		glist_p = groups;
		for (i = 0; i < 2; i++) {
			if (!supp_in_ginfo[i])
				*(glist_p++) = uc->uc_suppgids[i];
		}

		/* An existing entry is never modified once it is marked as
		 * VALID. But it can change when updated from NEW to VALID,
		 * for instance the mi_ginfo can be set. This means the number
		 * of groups can only grow from 0 (mi_ginfo not set) to
		 * mi_ginfo->ngroups.
		 * So only copy mi_ginfo to the groups array if necessary space
		 * was allocated for it.
		 * In case we detect a concurrent change in mi_ginfo->ngroups,
		 * just start over.
		 */
		if (ginfo_ngroups) {
			atomic_inc(&identity->mi_ginfo->usage);
			lustre_list_from_groups(glist_p, identity->mi_ginfo);
			atomic_dec(&identity->mi_ginfo->usage);
		} else if (identity->mi_ginfo && identity->mi_ginfo->ngroups) {
			CFS_FREE_PTR_ARRAY(groups, groups_num + ginfo_ngroups);
			groups = NULL;
			goto restart;
		}

		if (!UC_CACHE_IS_NEW(entry)) {
			/* force refresh as an existing cache entry
			 * cannot be modified
			 */
			/* we are called from upcall_cache_get_entry() after
			 * write lock has been dropped
			 */
			write_lock(&cache->uc_lock);
			entry->ue_expire = ktime_get_seconds();
			write_unlock(&cache->uc_lock);
		}
	}

out:
	if (groups) {
		int ngroups = groups_num + ginfo_ngroups;
		struct group_info *ginfo;

		ginfo = groups_alloc(ngroups);
		if (ginfo) {
			lustre_groups_from_list(ginfo, groups);
			lustre_groups_sort(ginfo);
			*pginfo = ginfo;
		} else {
			CDEBUG(D_OTHER,
			       "failed to alloc %d groups: rc = %d\n",
			       ngroups, -ENOMEM);
			rc = -ENOMEM;
		}
		CFS_FREE_PTR_ARRAY(groups, ngroups);
	}
	return rc;
}
