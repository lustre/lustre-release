// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#include <linux/module.h>
#include <lustre_net.h>
#include <obd_class.h>
#include <linux/capability.h>
#include "nodemap_internal.h"

#define HASH_NODEMAP_MEMBER_BKT_BITS 3
#define HASH_NODEMAP_MEMBER_CUR_BITS 3
#define HASH_NODEMAP_MEMBER_MAX_BITS 7


/**
 * nm_member_del() - Delete an export from a nodemap's member list
 * @nodemap: nodemap containing list
 * @exp: export member to delete
 *
 * Delete an export from a nodemap's member list. Called after client
 * disconnects, or during system shutdown.
 *
 * Note: Requires active_config_lock and nodemap's nm_member_list_lock.
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
 * nm_member_delete_list() - Delete a member list from a nodemap
 * @nodemap: nodemap to remove the list from
 *
 * Requires active config lock.
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

static void nm_register_obd_stats(struct lu_nodemap *nm, struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;

	if (unlikely(!exp->exp_obd->obd_stats && !exp->exp_obd->obd_md_stats))
		return;
	if (obd->obd_stats && nm->nm_dt_stats)
		return;
	if (obd->obd_md_stats && nm->nm_md_stats)
		return;

	mutex_lock(&nm->nm_stats_lock);
	if (obd->obd_md_stats && !nm->nm_md_stats) {
		/*
		 * here we have no idea how to configure stats properly
		 * (fields, their names, units, etc), so we rather ask
		 * obdclass to duplicate configuration of the existing
		 * stats.
		 */
		nm->nm_md_stats = lprocfs_stats_dup(obd->obd_md_stats);
		if (!nm->nm_md_stats) {
			CERROR("%s: can't alloc stats for nodemap %s\n",
				obd->obd_name, nm->nm_name);
			goto unlock;
		}
		debugfs_create_file("md_stats", 0644,
				    nm->nm_pde_data->npe_debugfs_entry,
				    nm->nm_md_stats,
				    &ldebugfs_stats_seq_fops);
	}
	if (obd->obd_stats && !nm->nm_dt_stats) {
		nm->nm_dt_stats = lprocfs_stats_dup(obd->obd_stats);
		if (!nm->nm_dt_stats) {
			CERROR("%s: can't alloc stats for nodemap %s\n",
				obd->obd_name, nm->nm_name);
			goto unlock;
		}
		debugfs_create_file("dt_stats", 0644,
				    nm->nm_pde_data->npe_debugfs_entry,
				    nm->nm_dt_stats,
				    &ldebugfs_stats_seq_fops);
	}

unlock:
	mutex_unlock(&nm->nm_stats_lock);
}

/**
 * nm_member_add() - Add a member export to a nodemap
 * @nodemap: nodemap to add to
 * @exp: obd_export to add
 *
 * Must be called under active_config_lock.
 *
 * Return:
 * * %0 on sucessful add
 * * %-EEXIST export is already part of a different nodemap
 * * %-EINVAL export is NULL
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

	nm_register_obd_stats(nodemap, exp);

	RETURN(0);
}

/*
 * Revokes the locks on an export if it is not in recovery, and attached to
 * an MDT, or an OST if force_ost is true.
 * To not break server to server communications, we skip lock revoking for LWP
 * and loopback connections.
 */
static void nm_member_exp_revoke(struct obd_export *exp, bool force_ost)
{
	struct obd_type *type = exp->exp_obd->obd_type;

	if (!force_ost && strcmp(type->typ_name, LUSTRE_MDT_NAME) != 0)
		return;
	if (test_bit(OBDF_RECOVERING, exp->exp_obd->obd_flags))
		return;
	if (nid_is_lo0(&exp->exp_connection->c_peer.nid) ||
	    is_lwp_on_ost(exp->exp_client_uuid.uuid) ||
	    is_lwp_on_mdt(exp->exp_client_uuid.uuid))
		return;

	ldlm_revoke_export_locks(exp);
}

/* Cache for nodemap_change_need_update() results.
 * As comparing nodemap properties can be time consuming, a temporary cache is
 * created for each nodemap being reclassified. Cache entries contain a
 * reference to the nodemap being compared with, and the comparison result.
 */
struct nm_cmp_cache_entry {
	struct lu_nodemap *cce_nm;
	bool		   cce_need_update;
	struct rhash_head  cce_node;
};

static void nm_cmp_cache_free(void *ptr, void *arg)
{
	struct nm_cmp_cache_entry *entry = ptr;

	OBD_FREE_PTR(entry);
}

static const struct rhashtable_params nm_cmp_cache_params = {
	.head_offset = offsetof(struct nm_cmp_cache_entry, cce_node),
	.key_offset  = offsetof(struct nm_cmp_cache_entry, cce_nm),
	.key_len     = sizeof(struct lu_nodemap *),
	.automatic_shrinking = true,
};

static struct rhashtable nm_cmp_cache;
static bool use_nm_cmp_cache;

/* Return true if idmaps are identical */
static bool idmaps_match(struct rb_root *old, struct rb_root *new)
{
	struct lu_idmap	*idmapold, *idmapnew;
	struct rb_node *nold = rb_first(old);
	struct rb_node *nnew = rb_first(new);

	while (nold && nnew) {
		idmapold = rb_entry(nold, struct lu_idmap, id_fs_to_client);
		idmapnew = rb_entry(nnew, struct lu_idmap, id_fs_to_client);

		if (idmapold->id_fs != idmapnew->id_fs ||
		    idmapold->id_client != idmapnew->id_client)
			return false;

		nold = rb_next(nold);
		nnew = rb_next(nnew);
	}

	if (nold || nnew)
		return false;

	return true;
}

/**
 * nodemap_change_need_update() - Compare old and new nodemap definitions
 * @old: old nodemap
 * @new: new nodemap
 *
 * If nodemaps are different, the client must revoke its locks.
 * Callers should hold the active_config_lock and active_config
 * nmc_range_tree_lock and nm_member_list_lock and nm_idmap_lock.
 *
 * Return:
 * * %true if nodemap changes require to revoke client locks
 * * %false otherwise
 */
static bool nodemap_change_need_update(struct lu_nodemap *old,
				       struct lu_nodemap *new)
{
	struct nm_cmp_cache_entry *entry;
	bool res = true;

	if (use_nm_cmp_cache) {
		struct nm_cmp_cache_entry *found;

		found = rhashtable_lookup_fast(&nm_cmp_cache, &new,
					       nm_cmp_cache_params);
		if (found)
			return found->cce_need_update;
	}

	/* If old and new nodemap names are different, client was moved to a
	 * different nodemap. This requires the client to revoke its locks.
	 */
	if (strcmp(old->nm_name, new->nm_name))
		goto out_change;

	/* We do not want clients to cache permissions that are no longer
	 * correct. So any changes to properties below require to revoke locks.
	 */
	if (old->nmf_trust_client_ids != new->nmf_trust_client_ids ||
	    old->nmf_allow_root_access != new->nmf_allow_root_access ||
	    old->nmf_deny_unknown != new->nmf_deny_unknown ||
	    old->nmf_map_mode != new->nmf_map_mode ||
	    old->nmf_caps_type != new->nmf_caps_type ||
	    old->nm_squash_uid != new->nm_squash_uid ||
	    old->nm_squash_gid != new->nm_squash_gid ||
	    old->nm_squash_projid != new->nm_squash_projid ||
	    old->nm_offset_start_uid != new->nm_offset_start_uid ||
	    old->nm_offset_limit_uid != new->nm_offset_limit_uid ||
	    old->nm_offset_start_gid != new->nm_offset_start_gid ||
	    old->nm_offset_limit_gid != new->nm_offset_limit_gid ||
	    old->nm_offset_start_projid != new->nm_offset_start_projid ||
	    old->nm_offset_limit_projid != new->nm_offset_limit_projid ||
	    !cap_issubset(old->nm_capabilities, new->nm_capabilities) ||
	    !cap_issubset(new->nm_capabilities, old->nm_capabilities))
		goto out_change;

	/* Same for id mappings */
	if (!idmaps_match(&old->nm_fs_to_client_uidmap,
			  &new->nm_fs_to_client_uidmap) ||
	    !idmaps_match(&old->nm_fs_to_client_gidmap,
			  &new->nm_fs_to_client_gidmap) ||
	    !idmaps_match(&old->nm_fs_to_client_projidmap,
			  &new->nm_fs_to_client_projidmap))
		goto out_change;

	res = false;

out_change:
	if (!use_nm_cmp_cache)
		goto out_end;

	/* best effort to create a cache entry, do not fail on error */
	OBD_ALLOC_PTR(entry);
	if (entry) {
		entry->cce_nm = new;
		entry->cce_need_update = res;
		if (rhashtable_insert_fast(&nm_cmp_cache, &entry->cce_node,
					   nm_cmp_cache_params))
			OBD_FREE_PTR(entry);
	}
out_end:
	return res;
}

/**
 * nm_member_reclassify_nodemap() - Reclassify members of a nodemap
 * @nodemap: nodemap with members to reclassify
 *
 * Reclassify the members of a nodemap after range changes or activation.
 * This function reclassifies the members of a nodemap based on the member
 * export's NID and the nodemap's new NID ranges. Exports that are no longer
 * classified as being part of this nodemap are moved to the nodemap whose
 * NID ranges contain the export's NID, and their locks are revoked.
 *
 * Callers should hold the active_config_lock and active_config
 * nmc_range_tree_lock.
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
		struct lnet_nid *nid;
		bool banned, newly_banned;

		/* if no conn assigned to this exp, reconnect will reclassify */
		spin_lock(&exp->exp_lock);
		if (exp->exp_connection) {
			nid = &exp->exp_connection->c_peer.nid;
		} else {
			spin_unlock(&exp->exp_lock);
			continue;
		}
		spin_unlock(&exp->exp_lock);

		if (!use_nm_cmp_cache &&
		    !rhashtable_init(&nm_cmp_cache, &nm_cmp_cache_params))
			use_nm_cmp_cache = true;

		/* nodemap_classify_nid requires nmc_range_tree_lock and
		 * nmc_ban_range_tree_lock
		 */
		down_read(&active_config->nmc_ban_range_tree_lock);
		new_nodemap = nodemap_classify_nid(nid, &banned);
		up_read(&active_config->nmc_ban_range_tree_lock);
		if (IS_ERR(new_nodemap))
			continue;

		newly_banned = banned && !exp->exp_banned;
		if (newly_banned) {
			LCONSOLE_WARN(
			       "%s: nodemap %s banning client %s (at %s)\n",
			       exp->exp_obd->obd_name, new_nodemap->nm_name,
			       obd_uuid2str(&exp->exp_client_uuid),
			       obd_export_nid2str(exp));
			exp->exp_banned = 1;
		} else if (!banned && exp->exp_banned) {
			LCONSOLE_WARN(
			       "%s: nodemap %s un-banned client %s (at %s)\n",
			       exp->exp_obd->obd_name, new_nodemap->nm_name,
			       obd_uuid2str(&exp->exp_client_uuid),
			       obd_export_nid2str(exp));
			exp->exp_banned = 0;
		}

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

			nm_register_obd_stats(new_nodemap, exp);

			if (nodemap_active) {
				down_read(&nodemap->nm_idmap_lock);
				if (newly_banned ||
				    nodemap_change_need_update(nodemap,
							       new_nodemap))
					nm_member_exp_revoke(exp, banned);
				up_read(&nodemap->nm_idmap_lock);
			}
		} else {
			nodemap_putref(new_nodemap);
		}
	}

	if (use_nm_cmp_cache) {
		rhashtable_free_and_destroy(&nm_cmp_cache,
					    nm_cmp_cache_free, NULL);
		use_nm_cmp_cache = false;
	}

	mutex_unlock(&nodemap->nm_member_list_lock);

	EXIT;
}

/**
 * nm_member_revoke_locks() - Revoke the locks for member exports if nodemap
 * system is active.
 * @nodemap: nodemap that has been altered
 *
 * Changing the idmap is akin to deleting the security context. If the locks
 * are not canceled, the client could cache permissions that are no longer
 * correct with the map.
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
		nm_member_exp_revoke(exp, false);
	mutex_unlock(&nodemap->nm_member_list_lock);
}
