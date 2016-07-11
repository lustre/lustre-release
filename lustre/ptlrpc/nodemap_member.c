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
 * Copyright (C) 2013, Trustees of Indiana University
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */
#include <linux/module.h>
#include <lustre_net.h>
#include <obd_class.h>
#include "nodemap_internal.h"

#define HASH_NODEMAP_MEMBER_BKT_BITS 3
#define HASH_NODEMAP_MEMBER_CUR_BITS 3
#define HASH_NODEMAP_MEMBER_MAX_BITS 7


/**
 * Delete an export from a nodemap's member list. Called after client
 * disconnects, or during system shutdown.
 *
 * Requires active_config_lock and nodemap's nm_member_list_lock.
 *
 * \param	nodemap		nodemap containing list
 * \param	exp		export member to delete
 */
void nm_member_del(struct lu_nodemap *nodemap, struct obd_export *exp)
{
	ENTRY;

	/* because all changes to ted_nodemap are with active_config_lock */
	LASSERT(exp->exp_target_data.ted_nodemap == nodemap);

	/* protected by nm_member_list_lock */
	list_del_init(&exp->exp_target_data.ted_nodemap_member);

	spin_lock(&exp->exp_target_data.ted_nodemap_lock);
	exp->exp_target_data.ted_nodemap = NULL;
	spin_unlock(&exp->exp_target_data.ted_nodemap_lock);

	/* ref formerly held by ted_nodemap */
	nodemap_putref(nodemap);

	/* ref formerly held by ted_nodemap_member */
	class_export_put(exp);

	EXIT;
}

/**
 * Delete a member list from a nodemap
 *
 * Requires active config lock.
 *
 * \param	nodemap		nodemap to remove the list from
 */
void nm_member_delete_list(struct lu_nodemap *nodemap)
{
	struct obd_export *exp;
	struct obd_export *tmp;

	mutex_lock(&nodemap->nm_member_list_lock);
	list_for_each_entry_safe(exp, tmp, &nodemap->nm_member_list,
				 exp_target_data.ted_nodemap_member)
		nm_member_del(nodemap, exp);
	mutex_unlock(&nodemap->nm_member_list_lock);
}

/**
 * Add a member export to a nodemap
 *
 * Must be called under active_config_lock.
 *
 * \param	nodemap		nodemap to add to
 * \param	exp		obd_export to add
 * \retval	-EEXIST		export is already part of a different nodemap
 * \retval	-EINVAL		export is NULL
 */
int nm_member_add(struct lu_nodemap *nodemap, struct obd_export *exp)
{
	ENTRY;

	if (exp == NULL) {
		CWARN("attempted to add null export to nodemap %s\n",
		      nodemap->nm_name);
		RETURN(-EINVAL);
	}

	mutex_lock(&nodemap->nm_member_list_lock);
	if (exp->exp_target_data.ted_nodemap != NULL &&
	    !list_empty(&exp->exp_target_data.ted_nodemap_member)) {
		mutex_unlock(&nodemap->nm_member_list_lock);

		/* export is already member of nodemap */
		if (exp->exp_target_data.ted_nodemap == nodemap)
			RETURN(0);

		/* possibly reconnecting while about to be reclassified */
		CWARN("export %p %s already hashed, failed to add to "
		      "nodemap %s already member of %s\n", exp,
		      exp->exp_client_uuid.uuid,
		      nodemap->nm_name,
		      (exp->exp_target_data.ted_nodemap == NULL) ? "unknown" :
				exp->exp_target_data.ted_nodemap->nm_name);
		RETURN(-EEXIST);
	}

	class_export_get(exp);
	nodemap_getref(nodemap);
	/* ted_nodemap changes also require ac lock, member_list_lock */
	spin_lock(&exp->exp_target_data.ted_nodemap_lock);
	exp->exp_target_data.ted_nodemap = nodemap;
	spin_unlock(&exp->exp_target_data.ted_nodemap_lock);
	list_add(&exp->exp_target_data.ted_nodemap_member,
		 &nodemap->nm_member_list);
	mutex_unlock(&nodemap->nm_member_list_lock);

	RETURN(0);
}

/**
 * Revokes the locks on an export if it is attached to an MDT and not in
 * recovery. As a performance enhancement, the lock revoking process could
 * revoke only the locks that cover files affected by the nodemap change.
 */
static void nm_member_exp_revoke(struct obd_export *exp)
{
	struct obd_type *type = exp->exp_obd->obd_type;
	if (strcmp(type->typ_name, LUSTRE_MDT_NAME) != 0)
		return;
	if (exp->exp_obd->obd_recovering)
		return;

	ldlm_revoke_export_locks(exp);
}

/**
 * Reclassify the members of a nodemap after range changes or activation.
 * This function reclassifies the members of a nodemap based on the member
 * export's NID and the nodemap's new NID ranges. Exports that are no longer
 * classified as being part of this nodemap are moved to the nodemap whose
 * NID ranges contain the export's NID, and their locks are revoked.
 *
 * Callers should hold the active_config_lock and active_config
 * nmc_range_tree_lock.
 *
 * \param	nodemap		nodemap with members to reclassify
 */
void nm_member_reclassify_nodemap(struct lu_nodemap *nodemap)
{
	struct obd_export *exp;
	struct obd_export *tmp;
	struct lu_nodemap *new_nodemap;

	ENTRY;

	mutex_lock(&nodemap->nm_member_list_lock);

	list_for_each_entry_safe(exp, tmp, &nodemap->nm_member_list,
				 exp_target_data.ted_nodemap_member) {
		lnet_nid_t nid;

		/* if no conn assigned to this exp, reconnect will reclassify */
		spin_lock(&exp->exp_lock);
		if (exp->exp_connection) {
			nid = exp->exp_connection->c_peer.nid;
		} else {
			spin_unlock(&exp->exp_lock);
			continue;
		}
		spin_unlock(&exp->exp_lock);

		/* nodemap_classify_nid requires nmc_range_tree_lock */
		new_nodemap = nodemap_classify_nid(nid);
		if (IS_ERR(new_nodemap))
			continue;

		if (new_nodemap != nodemap) {
			/* could deadlock if new_nodemap also reclassifying,
			 * active_config_lock serializes reclassifies
			 */
			mutex_lock(&new_nodemap->nm_member_list_lock);

			/* don't use member_del because ted_nodemap
			 * should never be NULL with a live export
			 */
			list_del_init(&exp->exp_target_data.ted_nodemap_member);

			/* keep the new_nodemap ref from classify */
			spin_lock(&exp->exp_target_data.ted_nodemap_lock);
			exp->exp_target_data.ted_nodemap = new_nodemap;
			spin_unlock(&exp->exp_target_data.ted_nodemap_lock);
			nodemap_putref(nodemap);

			list_add(&exp->exp_target_data.ted_nodemap_member,
				 &new_nodemap->nm_member_list);
			mutex_unlock(&new_nodemap->nm_member_list_lock);

			if (nodemap_active)
				nm_member_exp_revoke(exp);
		} else {
			nodemap_putref(new_nodemap);
		}
	}
	mutex_unlock(&nodemap->nm_member_list_lock);

	EXIT;
}

/**
 * Revoke the locks for member exports if nodemap system is active.
 *
 * Changing the idmap is akin to deleting the security context. If the locks
 * are not canceled, the client could cache permissions that are no longer
 * correct with the map.
 *
 * \param	nodemap		nodemap that has been altered
 */
void nm_member_revoke_locks(struct lu_nodemap *nodemap)
{
	if (!nodemap_active)
		return;

	nm_member_revoke_locks_always(nodemap);
}

void nm_member_revoke_locks_always(struct lu_nodemap *nodemap)
{
	struct obd_export *exp;
	struct obd_export *tmp;

	mutex_lock(&nodemap->nm_member_list_lock);
	list_for_each_entry_safe(exp, tmp, &nodemap->nm_member_list,
			    exp_target_data.ted_nodemap_member)
		nm_member_exp_revoke(exp);
	mutex_unlock(&nodemap->nm_member_list_lock);
}
