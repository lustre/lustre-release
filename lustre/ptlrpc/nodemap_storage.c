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
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 * Author: Kit Westneat <cwestnea@iu.edu>
 *
 * Implements the storage functionality for the nodemap configuration. Functions
 * in this file prepare, store, and load nodemap configuration data. Targets
 * using nodemap services should register a configuration file object. Nodemap
 * configuration changes that need to persist should call the appropriate
 * storage function for the data being modified.
 *
 * There are several index types as defined in enum nodemap_idx_type:
 *	NODEMAP_CLUSTER_IDX	stores the data found on the lu_nodemap struct,
 *				like root squash and config flags, as well as
 *				the name.
 *	NODEMAP_RANGE_IDX	stores NID range information for a nodemap
 *	NODEMAP_UIDMAP_IDX	stores a fs/client UID mapping pair
 *	NODEMAP_GIDMAP_IDX	stores a fs/client GID mapping pair
 *	NODEMAP_GLOBAL_IDX	stores whether or not nodemaps are active
 */

#include <libcfs/libcfs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/linux/lnet/lnet-types.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <dt_object.h>
#include <lu_object.h>
#include <lustre_net.h>
#include <lustre_nodemap.h>
#include <obd_class.h>
#include <obd_support.h>
#include "nodemap_internal.h"

/* list of registered nodemap index files, except MGS */
static LIST_HEAD(ncf_list_head);
static DEFINE_MUTEX(ncf_list_lock);

/* MGS index is different than others, others are listeners to MGS idx */
static struct nm_config_file *nodemap_mgs_ncf;

/* lu_nodemap flags */
enum nm_flag_shifts {
	NM_FL_ALLOW_ROOT_ACCESS = 0x1,
	NM_FL_TRUST_CLIENT_IDS = 0x2,
	NM_FL_DENY_UNKNOWN = 0x4,
	NM_FL_MAP_UID_ONLY = 0x8,
	NM_FL_MAP_GID_ONLY = 0x10,
	NM_FL_ENABLE_AUDIT = 0x20,
	NM_FL_FORBID_ENCRYPT = 0x40,
};

static void nodemap_cluster_key_init(struct nodemap_key *nk, unsigned int nm_id)
{
	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(nm_id,
							NODEMAP_CLUSTER_IDX));
	nk->nk_unused = 0;
}

static void nodemap_cluster_rec_init(union nodemap_rec *nr,
				     const struct lu_nodemap *nodemap)
{
	BUILD_BUG_ON(sizeof(nr->ncr.ncr_name) != sizeof(nodemap->nm_name));

	strncpy(nr->ncr.ncr_name, nodemap->nm_name, sizeof(nr->ncr.ncr_name));
	nr->ncr.ncr_squash_uid = cpu_to_le32(nodemap->nm_squash_uid);
	nr->ncr.ncr_squash_gid = cpu_to_le32(nodemap->nm_squash_gid);
	nr->ncr.ncr_flags = cpu_to_le32(
		(nodemap->nmf_trust_client_ids ?
			NM_FL_TRUST_CLIENT_IDS : 0) |
		(nodemap->nmf_allow_root_access ?
			NM_FL_ALLOW_ROOT_ACCESS : 0) |
		(nodemap->nmf_deny_unknown ?
			NM_FL_DENY_UNKNOWN : 0) |
		(nodemap->nmf_map_uid_only ?
			NM_FL_MAP_UID_ONLY : 0) |
		(nodemap->nmf_map_gid_only ?
			NM_FL_MAP_GID_ONLY : 0) |
		(nodemap->nmf_enable_audit ?
			NM_FL_ENABLE_AUDIT : 0) |
		(nodemap->nmf_forbid_encryption ?
			NM_FL_FORBID_ENCRYPT : 0));
}

static void nodemap_idmap_key_init(struct nodemap_key *nk, unsigned int nm_id,
				   enum nodemap_id_type id_type,
				   u32 id_client)
{
	enum nodemap_idx_type idx_type;

	if (id_type == NODEMAP_UID)
		idx_type = NODEMAP_UIDMAP_IDX;
	else
		idx_type = NODEMAP_GIDMAP_IDX;

	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(nm_id, idx_type));
	nk->nk_id_client = cpu_to_le32(id_client);
}

static void nodemap_idmap_rec_init(union nodemap_rec *nr, u32 id_fs)
{
	nr->nir.nir_id_fs = cpu_to_le32(id_fs);
}

static void nodemap_range_key_init(struct nodemap_key *nk, unsigned int nm_id,
				   unsigned int rn_id)
{
	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(nm_id,
							NODEMAP_RANGE_IDX));
	nk->nk_range_id = cpu_to_le32(rn_id);
}

static void nodemap_range_rec_init(union nodemap_rec *nr,
				   const lnet_nid_t nid[2])
{
	nr->nrr.nrr_start_nid = cpu_to_le64(nid[0]);
	nr->nrr.nrr_end_nid = cpu_to_le64(nid[1]);
}

static void nodemap_global_key_init(struct nodemap_key *nk)
{
	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(0, NODEMAP_GLOBAL_IDX));
	nk->nk_unused = 0;
}

static void nodemap_global_rec_init(union nodemap_rec *nr, bool active)
{
	nr->ngr.ngr_is_active = active;
}

/* should be called with dt_write lock */
static void nodemap_inc_version(const struct lu_env *env,
				struct dt_object *nodemap_idx,
				struct thandle *th)
{
	u64 ver = dt_version_get(env, nodemap_idx);
	dt_version_set(env, nodemap_idx, ver + 1, th);
}

enum ncfc_find_create {
	NCFC_CREATE_NEW = 1,
};

static struct dt_object *nodemap_cache_find_create(const struct lu_env *env,
						   struct dt_device *dev,
						   struct local_oid_storage *los,
						   enum ncfc_find_create create_new)
{
	struct lu_fid tfid;
	struct dt_object *root_obj;
	struct dt_object *nm_obj;
	int rc = 0;

	rc = dt_root_get(env, dev, &tfid);
	if (rc < 0)
		GOTO(out, nm_obj = ERR_PTR(rc));

	root_obj = dt_locate(env, dev, &tfid);
	if (unlikely(IS_ERR(root_obj)))
		GOTO(out, nm_obj = root_obj);

	rc = dt_lookup_dir(env, root_obj, LUSTRE_NODEMAP_NAME, &tfid);
	if (rc == -ENOENT) {
		if (dev->dd_rdonly)
			GOTO(out_root, nm_obj = ERR_PTR(-EROFS));
	} else if (rc) {
		GOTO(out_root, nm_obj = ERR_PTR(rc));
	} else if (dev->dd_rdonly && create_new == NCFC_CREATE_NEW) {
		GOTO(out_root, nm_obj = ERR_PTR(-EROFS));
	}

again:
	/* if loading index fails the first time, create new index */
	if (create_new == NCFC_CREATE_NEW && rc != -ENOENT) {
		CDEBUG(D_INFO, "removing old index, creating new one\n");
		rc = local_object_unlink(env, dev, root_obj,
					 LUSTRE_NODEMAP_NAME);
		if (rc < 0) {
			/* XXX not sure the best way to get obd name. */
			CERROR("cannot destroy nodemap index: rc = %d\n",
			       rc);
			GOTO(out_root, nm_obj = ERR_PTR(rc));
		}
	}

	nm_obj = local_index_find_or_create(env, los, root_obj,
						LUSTRE_NODEMAP_NAME,
						S_IFREG | S_IRUGO | S_IWUSR,
						&dt_nodemap_features);
	if (IS_ERR(nm_obj))
		GOTO(out_root, nm_obj);

	if (nm_obj->do_index_ops == NULL) {
		rc = nm_obj->do_ops->do_index_try(env, nm_obj,
						      &dt_nodemap_features);
		/* even if loading from tgt fails, connecting to MGS will
		 * rewrite the config
		 */
		if (rc < 0) {
			dt_object_put(env, nm_obj);

			if (create_new == NCFC_CREATE_NEW)
				GOTO(out_root, nm_obj = ERR_PTR(rc));

			CERROR("cannot load nodemap index from disk, creating "
			       "new index: rc = %d\n", rc);
			create_new = NCFC_CREATE_NEW;
			goto again;
		}
	}

out_root:
	dt_object_put(env, root_obj);
out:
	return nm_obj;
}

static int nodemap_idx_insert(const struct lu_env *env,
			      struct dt_object *idx,
			      const struct nodemap_key *nk,
			      const union nodemap_rec *nr)
{
	struct thandle *th;
	struct dt_device *dev = lu2dt_dev(idx->do_lu.lo_dev);
	int rc;

	BUILD_BUG_ON(sizeof(union nodemap_rec) != 32);

	th = dt_trans_create(env, dev);

	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_insert(env, idx,
			       (const struct dt_rec *)nr,
			       (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_version_set(env, idx, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(out, rc);

	dt_write_lock(env, idx, 0);

	rc = dt_insert(env, idx, (const struct dt_rec *)nr,
		       (const struct dt_key *)nk, th);

	nodemap_inc_version(env, idx, th);
	dt_write_unlock(env, idx);
out:
	dt_trans_stop(env, dev, th);

	return rc;
}

static int nodemap_idx_update(const struct lu_env *env,
			      struct dt_object *idx,
			      const struct nodemap_key *nk,
			      const union nodemap_rec *nr)
{
	struct thandle		*th;
	struct dt_device	*dev = lu2dt_dev(idx->do_lu.lo_dev);
	int			 rc = 0;

	th = dt_trans_create(env, dev);

	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, idx, (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_insert(env, idx, (const struct dt_rec *)nr,
			       (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_version_set(env, idx, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(out, rc);

	dt_write_lock(env, idx, 0);

	rc = dt_delete(env, idx, (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out_lock, rc);

	rc = dt_insert(env, idx, (const struct dt_rec *)nr,
		       (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out_lock, rc);

	nodemap_inc_version(env, idx, th);
out_lock:
	dt_write_unlock(env, idx);
out:
	dt_trans_stop(env, dev, th);

	return rc;
}

static int nodemap_idx_delete(const struct lu_env *env,
			      struct dt_object *idx,
			      const struct nodemap_key *nk,
			      const union nodemap_rec *unused)
{
	struct thandle		*th;
	struct dt_device	*dev = lu2dt_dev(idx->do_lu.lo_dev);
	int			 rc = 0;

	th = dt_trans_create(env, dev);

	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, idx, (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_version_set(env, idx, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(out, rc);

	dt_write_lock(env, idx, 0);

	rc = dt_delete(env, idx, (const struct dt_key *)nk, th);

	nodemap_inc_version(env, idx, th);

	dt_write_unlock(env, idx);
out:
	dt_trans_stop(env, dev, th);

	return rc;
}

enum nm_add_update {
	NM_ADD = 0,
	NM_UPDATE = 1,
};

static int nodemap_idx_nodemap_add_update(const struct lu_nodemap *nodemap,
					  struct dt_object *idx,
					  enum nm_add_update update)
{
	struct nodemap_key nk;
	union nodemap_rec nr;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		RETURN(rc);

	nodemap_cluster_key_init(&nk, nodemap->nm_id);
	nodemap_cluster_rec_init(&nr, nodemap);

	if (update == NM_UPDATE)
		rc = nodemap_idx_update(&env, idx, &nk, &nr);
	else
		rc = nodemap_idx_insert(&env, idx, &nk, &nr);

	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_nodemap_add(const struct lu_nodemap *nodemap)
{
	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	return nodemap_idx_nodemap_add_update(nodemap, nodemap_mgs_ncf->ncf_obj,
					      NM_ADD);
}

int nodemap_idx_nodemap_update(const struct lu_nodemap *nodemap)
{
	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	return nodemap_idx_nodemap_add_update(nodemap, nodemap_mgs_ncf->ncf_obj,
					      NM_UPDATE);
}

int nodemap_idx_nodemap_del(const struct lu_nodemap *nodemap)
{
	struct rb_root		 root;
	struct lu_idmap		*idmap;
	struct lu_idmap		*temp;
	struct lu_nid_range	*range;
	struct lu_nid_range	*range_temp;
	struct nodemap_key	 nk;
	struct lu_env		 env;
	int			 rc = 0;
	int			 rc2 = 0;

	ENTRY;

	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	root = nodemap->nm_fs_to_client_uidmap;
	nm_rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
						id_fs_to_client) {
		nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_UID,
				       idmap->id_client);
		rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj,
					 &nk, NULL);
		if (rc2 < 0)
			rc = rc2;
	}

	root = nodemap->nm_client_to_fs_gidmap;
	nm_rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
						id_client_to_fs) {
		nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_GID,
				       idmap->id_client);
		rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj,
					 &nk, NULL);
		if (rc2 < 0)
			rc = rc2;
	}

	list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
				 rn_list) {
		nodemap_range_key_init(&nk, nodemap->nm_id, range->rn_id);
		rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj,
					 &nk, NULL);
		if (rc2 < 0)
			rc = rc2;
	}

	nodemap_cluster_key_init(&nk, nodemap->nm_id);
	rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	if (rc2 < 0)
		rc = rc2;

	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_range_add(const struct lu_nid_range *range,
			  const lnet_nid_t nid[2])
{
	struct nodemap_key	 nk;
	union nodemap_rec	 nr;
	struct lu_env		 env;
	int			 rc = 0;
	ENTRY;

	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_range_key_init(&nk, range->rn_nodemap->nm_id, range->rn_id);
	nodemap_range_rec_init(&nr, nid);

	rc = nodemap_idx_insert(&env, nodemap_mgs_ncf->ncf_obj, &nk, &nr);
	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_range_del(const struct lu_nid_range *range)
{
	struct nodemap_key	 nk;
	struct lu_env		 env;
	int			 rc = 0;
	ENTRY;

	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_range_key_init(&nk, range->rn_nodemap->nm_id, range->rn_id);

	rc = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_idmap_add(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const u32 map[2])
{
	struct nodemap_key	 nk;
	union nodemap_rec	 nr;
	struct lu_env		 env;
	int			 rc = 0;
	ENTRY;

	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_idmap_key_init(&nk, nodemap->nm_id, id_type, map[0]);
	nodemap_idmap_rec_init(&nr, map[1]);

	rc = nodemap_idx_insert(&env, nodemap_mgs_ncf->ncf_obj, &nk, &nr);
	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_idmap_del(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const u32 map[2])
{
	struct nodemap_key	 nk;
	struct lu_env		 env;
	int			 rc = 0;
	ENTRY;

	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_idmap_key_init(&nk, nodemap->nm_id, id_type, map[0]);

	rc = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	lu_env_fini(&env);

	RETURN(rc);
}

static int nodemap_idx_global_add_update(bool value, enum nm_add_update update)
{
	struct nodemap_key	 nk;
	union nodemap_rec	 nr;
	struct lu_env		 env;
	int			 rc = 0;
	ENTRY;

	if (nodemap_mgs_ncf == NULL) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_global_key_init(&nk);
	nodemap_global_rec_init(&nr, value);

	if (update == NM_UPDATE)
		rc = nodemap_idx_update(&env, nodemap_mgs_ncf->ncf_obj,
					&nk, &nr);
	else
		rc = nodemap_idx_insert(&env, nodemap_mgs_ncf->ncf_obj,
					&nk, &nr);

	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_nodemap_activate(bool value)
{
	return nodemap_idx_global_add_update(value, NM_UPDATE);
}

static enum nodemap_idx_type nodemap_get_key_type(const struct nodemap_key *key)
{
	u32			 nodemap_id;

	nodemap_id = le32_to_cpu(key->nk_nodemap_id);
	return nm_idx_get_type(nodemap_id);
}

/**
 * Process a key/rec pair and modify the new configuration.
 *
 * \param	config		configuration to update with this key/rec data
 * \param	key		key of the record that was loaded
 * \param	rec		record that was loaded
 * \param	recent_nodemap	last referenced nodemap
 * \retval	type of record processed, see enum #nodemap_idx_type
 * \retval	-ENOENT		range or map loaded before nodemap record
 * \retval	-EINVAL		duplicate nodemap cluster records found with
 *				different IDs, or nodemap has invalid name
 * \retval	-ENOMEM
 */
static int nodemap_process_keyrec(struct nodemap_config *config,
				  const struct nodemap_key *key,
				  const union nodemap_rec *rec,
				  struct lu_nodemap **recent_nodemap)
{
	struct lu_nodemap *nodemap = NULL;
	enum nodemap_idx_type type;
	enum nodemap_id_type id_type;
	u8 flags;
	u32 nodemap_id;
	lnet_nid_t nid[2];
	u32 map[2];
	int rc;

	ENTRY;

	BUILD_BUG_ON(sizeof(union nodemap_rec) != 32);

	nodemap_id = le32_to_cpu(key->nk_nodemap_id);
	type = nodemap_get_key_type(key);
	nodemap_id = nm_idx_set_type(nodemap_id, 0);

	CDEBUG(D_INFO, "found config entry, nm_id %d type %d\n",
	       nodemap_id, type);

	/* find the correct nodemap in the load list */
	if (type == NODEMAP_RANGE_IDX || type == NODEMAP_UIDMAP_IDX ||
	    type == NODEMAP_GIDMAP_IDX) {
		struct lu_nodemap *tmp = NULL;

		nodemap = *recent_nodemap;

		if (nodemap == NULL)
			GOTO(out, rc = -ENOENT);

		if (nodemap->nm_id != nodemap_id) {
			list_for_each_entry(tmp, &nodemap->nm_list, nm_list)
				if (tmp->nm_id == nodemap_id) {
					nodemap = tmp;
					break;
				}

			if (nodemap->nm_id != nodemap_id)
				GOTO(out, rc = -ENOENT);
		}

		/* update most recently used nodemap if necessay */
		if (nodemap != *recent_nodemap)
			*recent_nodemap = nodemap;
	}

	switch (type) {
	case NODEMAP_EMPTY_IDX:
		if (nodemap_id != 0)
			CWARN("Found nodemap config record without type field, "
			      " nodemap_id=%d. nodemap config file corrupt?\n",
			      nodemap_id);
		break;
	case NODEMAP_CLUSTER_IDX: {
		struct lu_nodemap *old_nm = NULL;

		nodemap = cfs_hash_lookup(config->nmc_nodemap_hash,
					  rec->ncr.ncr_name);
		if (nodemap == NULL) {
			if (nodemap_id == LUSTRE_NODEMAP_DEFAULT_ID) {
				nodemap = nodemap_create(rec->ncr.ncr_name,
							 config, 1);
			} else {
				nodemap = nodemap_create(rec->ncr.ncr_name,
							 config, 0);
			}
			if (IS_ERR(nodemap))
				GOTO(out, rc = PTR_ERR(nodemap));

			/* we need to override the local ID with the saved ID */
			nodemap->nm_id = nodemap_id;
			if (nodemap_id > config->nmc_nodemap_highest_id)
				config->nmc_nodemap_highest_id = nodemap_id;

		} else if (nodemap->nm_id != nodemap_id) {
			nodemap_putref(nodemap);
			GOTO(out, rc = -EINVAL);
		}

		nodemap->nm_squash_uid =
				le32_to_cpu(rec->ncr.ncr_squash_uid);
		nodemap->nm_squash_gid =
				le32_to_cpu(rec->ncr.ncr_squash_gid);

		flags = le32_to_cpu(rec->ncr.ncr_flags);
		nodemap->nmf_allow_root_access =
					flags & NM_FL_ALLOW_ROOT_ACCESS;
		nodemap->nmf_trust_client_ids =
					flags & NM_FL_TRUST_CLIENT_IDS;
		nodemap->nmf_deny_unknown =
					flags & NM_FL_DENY_UNKNOWN;
		nodemap->nmf_map_uid_only =
					flags & NM_FL_MAP_UID_ONLY;
		nodemap->nmf_map_gid_only =
					flags & NM_FL_MAP_GID_ONLY;
		nodemap->nmf_enable_audit =
					flags & NM_FL_ENABLE_AUDIT;
		nodemap->nmf_forbid_encryption =
					flags & NM_FL_FORBID_ENCRYPT;

		/* The fileset should be saved otherwise it will be empty
		 * every time in case of "NODEMAP_CLUSTER_IDX". */
		mutex_lock(&active_config_lock);
		old_nm = nodemap_lookup(rec->ncr.ncr_name);
		if (!IS_ERR(old_nm) && old_nm->nm_fileset[0] != '\0')
			strlcpy(nodemap->nm_fileset, old_nm->nm_fileset,
				sizeof(nodemap->nm_fileset));
		mutex_unlock(&active_config_lock);
		if (!IS_ERR(old_nm))
			nodemap_putref(old_nm);

		if (*recent_nodemap == NULL) {
			*recent_nodemap = nodemap;
			INIT_LIST_HEAD(&nodemap->nm_list);
		} else {
			list_add(&nodemap->nm_list,
				 &(*recent_nodemap)->nm_list);
		}
		nodemap_putref(nodemap);
		break;
	}
	case NODEMAP_RANGE_IDX:
		nid[0] = le64_to_cpu(rec->nrr.nrr_start_nid);
		nid[1] = le64_to_cpu(rec->nrr.nrr_end_nid);

		rc = nodemap_add_range_helper(config, nodemap, nid,
					le32_to_cpu(key->nk_range_id));
		if (rc != 0)
			GOTO(out, rc);
		break;
	case NODEMAP_UIDMAP_IDX:
	case NODEMAP_GIDMAP_IDX:
		map[0] = le32_to_cpu(key->nk_id_client);
		map[1] = le32_to_cpu(rec->nir.nir_id_fs);

		if (type == NODEMAP_UIDMAP_IDX)
			id_type = NODEMAP_UID;
		else
			id_type = NODEMAP_GID;

		rc = nodemap_add_idmap_helper(nodemap, id_type, map);
		if (rc != 0)
			GOTO(out, rc);
		break;
	case NODEMAP_GLOBAL_IDX:
		config->nmc_nodemap_is_active = rec->ngr.ngr_is_active;
		break;
	default:
		CERROR("got keyrec pair for unknown type %d\n", type);
		break;
	}

	rc = type;

	EXIT;

out:
	return rc;
}

enum nm_config_passes {
	NM_READ_CLUSTERS = 0,
	NM_READ_ATTRIBUTES = 1,
};

static int nodemap_load_entries(const struct lu_env *env,
				struct dt_object *nodemap_idx)
{
	const struct dt_it_ops *iops;
	struct dt_it *it;
	struct lu_nodemap *recent_nodemap = NULL;
	struct nodemap_config *new_config = NULL;
	u64 hash = 0;
	bool activate_nodemap = false;
	bool loaded_global_idx = false;
	enum nm_config_passes cur_pass = NM_READ_CLUSTERS;
	int rc = 0;

	ENTRY;

	iops = &nodemap_idx->do_index_ops->dio_it;

	dt_read_lock(env, nodemap_idx, 0);
	it = iops->init(env, nodemap_idx, 0);
	if (IS_ERR(it))
		GOTO(out, rc = PTR_ERR(it));

	rc = iops->load(env, it, hash);
	if (rc < 0)
		GOTO(out_iops_fini, rc);

	/* rc == 0 means we need to advance to record */
	if (rc == 0) {
		rc = iops->next(env, it);

		if (rc < 0)
			GOTO(out_iops_put, rc);
		/* rc > 0 is eof, will be checked in while below */
	} else {
		/* rc == 1, we found initial record and can process below */
		rc = 0;
	}

	new_config = nodemap_config_alloc();
	if (IS_ERR(new_config)) {
		rc = PTR_ERR(new_config);
		new_config = NULL;
		GOTO(out_iops_put, rc);
	}

	/* rc > 0 is eof, check initial iops->next here as well */
	while (rc == 0) {
		struct nodemap_key *key;
		union nodemap_rec rec;
		enum nodemap_idx_type key_type;

		key = (struct nodemap_key *)iops->key(env, it);
		key_type = nodemap_get_key_type((struct nodemap_key *)key);
		if ((cur_pass == NM_READ_CLUSTERS &&
				key_type == NODEMAP_CLUSTER_IDX) ||
		    (cur_pass == NM_READ_ATTRIBUTES &&
				key_type != NODEMAP_CLUSTER_IDX &&
				key_type != NODEMAP_EMPTY_IDX)) {
			rc = iops->rec(env, it, (struct dt_rec *)&rec, 0);
			if (rc != -ESTALE) {
				if (rc != 0)
					GOTO(out_nodemap_config, rc);
				rc = nodemap_process_keyrec(new_config, key, &rec,
							    &recent_nodemap);
				if (rc < 0)
					GOTO(out_nodemap_config, rc);
				if (rc == NODEMAP_GLOBAL_IDX)
					loaded_global_idx = true;
			}
		}

		do
			rc = iops->next(env, it);
		while (rc == -ESTALE);

		/* move to second pass */
		if (rc > 0 && cur_pass == NM_READ_CLUSTERS) {
			cur_pass = NM_READ_ATTRIBUTES;
			rc = iops->load(env, it, 0);
			if (rc == 0)
				rc = iops->next(env, it);
			else if (rc > 0)
				rc = 0;
			else
				GOTO(out, rc);
		}
	}

	if (rc > 0)
		rc = 0;

out_nodemap_config:
	if (rc != 0)
		nodemap_config_dealloc(new_config);
	else
		/* creating new default needs to be done outside dt read lock */
		activate_nodemap = true;
out_iops_put:
	iops->put(env, it);
out_iops_fini:
	iops->fini(env, it);
out:
	dt_read_unlock(env, nodemap_idx);

	if (rc != 0)
		CWARN("%s: failed to load nodemap configuration: rc = %d\n",
		      nodemap_idx->do_lu.lo_dev->ld_obd->obd_name, rc);

	if (!activate_nodemap)
		RETURN(rc);

	if (new_config->nmc_default_nodemap == NULL) {
		/* new MGS won't have a default nm on disk, so create it here */
		struct lu_nodemap *nodemap =
			nodemap_create(DEFAULT_NODEMAP, new_config, 1);
		if (IS_ERR(nodemap)) {
			rc = PTR_ERR(nodemap);
		} else {
			rc = nodemap_idx_nodemap_add_update(
					new_config->nmc_default_nodemap,
					nodemap_idx,
					NM_ADD);
			nodemap_putref(new_config->nmc_default_nodemap);
		}
	}

	/* new nodemap config won't have an active/inactive record */
	if (rc == 0 && loaded_global_idx == false) {
		struct nodemap_key	 nk;
		union nodemap_rec	 nr;

		nodemap_global_key_init(&nk);
		nodemap_global_rec_init(&nr, false);
		rc = nodemap_idx_insert(env, nodemap_idx, &nk, &nr);
	}

	if (rc == 0)
		nodemap_config_set_active(new_config);
	else
		nodemap_config_dealloc(new_config);

	RETURN(rc);
}

/**
 * Step through active config and write to disk.
 */
struct dt_object *nodemap_save_config_cache(const struct lu_env *env,
					    struct dt_device *dev,
					    struct local_oid_storage *los)
{
	struct dt_object *o;
	struct lu_nodemap *nodemap;
	struct lu_nodemap *nm_tmp;
	struct lu_nid_range *range;
	struct lu_nid_range *range_temp;
	struct lu_idmap *idmap;
	struct lu_idmap *id_tmp;
	struct rb_root root;
	struct nodemap_key nk;
	union nodemap_rec nr;
	LIST_HEAD(nodemap_list_head);
	int rc = 0, rc2;

	ENTRY;

	/* create a new index file to fill with active config */
	o = nodemap_cache_find_create(env, dev, los, NCFC_CREATE_NEW);
	if (IS_ERR(o))
		RETURN(o);

	mutex_lock(&active_config_lock);

	/* convert hash to list so we don't spin */
	cfs_hash_for_each_safe(active_config->nmc_nodemap_hash,
			       nm_hash_list_cb, &nodemap_list_head);

	list_for_each_entry_safe(nodemap, nm_tmp, &nodemap_list_head, nm_list) {
		nodemap_cluster_key_init(&nk, nodemap->nm_id);
		nodemap_cluster_rec_init(&nr, nodemap);

		rc2 = nodemap_idx_insert(env, o, &nk, &nr);
		if (rc2 < 0) {
			rc = rc2;
			continue;
		}

		down_read(&active_config->nmc_range_tree_lock);
		list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
					 rn_list) {
			lnet_nid_t nid[2] = {
				range->rn_start,
				range->rn_end
			};
			nodemap_range_key_init(&nk, nodemap->nm_id,
					       range->rn_id);
			nodemap_range_rec_init(&nr, nid);
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}
		up_read(&active_config->nmc_range_tree_lock);

		/* we don't need to take nm_idmap_lock because active config
		 * lock prevents changes from happening to nodemaps
		 */
		root = nodemap->nm_client_to_fs_uidmap;
		nm_rbtree_postorder_for_each_entry_safe(idmap, id_tmp, &root,
							id_client_to_fs) {
			nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_UID,
					       idmap->id_client);
			nodemap_idmap_rec_init(&nr, idmap->id_fs);
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}

		root = nodemap->nm_client_to_fs_gidmap;
		nm_rbtree_postorder_for_each_entry_safe(idmap, id_tmp, &root,
							id_client_to_fs) {
			nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_GID,
					       idmap->id_client);
			nodemap_idmap_rec_init(&nr, idmap->id_fs);
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}
	}
	nodemap_global_key_init(&nk);
	nodemap_global_rec_init(&nr, active_config->nmc_nodemap_is_active);
	rc2 = nodemap_idx_insert(env, o, &nk, &nr);
	if (rc2 < 0)
		rc = rc2;

	mutex_unlock(&active_config_lock);

	if (rc < 0) {
		dt_object_put(env, o);
		o = ERR_PTR(rc);
	}

	RETURN(o);
}

static void nodemap_save_all_caches(void)
{
	struct nm_config_file	*ncf;
	struct lu_env		 env;
	int			 rc = 0;

	/* recreating nodemap cache requires fld_thread_key be in env */
	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD | LCT_MG_THREAD);
	if (rc != 0) {
		CWARN("cannot init env for nodemap config: rc = %d\n", rc);
		return;
	}

	mutex_lock(&ncf_list_lock);
	list_for_each_entry(ncf, &ncf_list_head, ncf_list) {
		struct dt_device *dev = lu2dt_dev(ncf->ncf_obj->do_lu.lo_dev);
		struct obd_device *obd = ncf->ncf_obj->do_lu.lo_dev->ld_obd;
		struct dt_object *o;

		/* put current config file so save conf can rewrite it */
		dt_object_put_nocache(&env, ncf->ncf_obj);
		ncf->ncf_obj = NULL;

		o = nodemap_save_config_cache(&env, dev, ncf->ncf_los);
		if (IS_ERR(o))
			CWARN("%s: error writing to nodemap config: rc = %d\n",
			      obd->obd_name, rc);
		else
			ncf->ncf_obj = o;
	}
	mutex_unlock(&ncf_list_lock);

	lu_env_fini(&env);
}

/* tracks if config still needs to be loaded, either from disk or network */
static bool nodemap_config_loaded;
static DEFINE_MUTEX(nodemap_config_loaded_lock);

/**
 * Ensures that configs loaded over the wire are prioritized over those loaded
 * from disk.
 *
 * \param config	config to set as the active config
 */
void nodemap_config_set_active_mgc(struct nodemap_config *config)
{
	mutex_lock(&nodemap_config_loaded_lock);
	nodemap_config_set_active(config);
	nodemap_config_loaded = true;
	nodemap_save_all_caches();
	mutex_unlock(&nodemap_config_loaded_lock);
}
EXPORT_SYMBOL(nodemap_config_set_active_mgc);

/**
 * Register a dt_object representing the config index file. This should be
 * called by targets in order to load the nodemap configuration from disk. The
 * dt_object should be created with local_index_find_or_create and the index
 * features should be enabled with do_index_try.
 *
 * \param obj	dt_object returned by local_index_find_or_create
 *
 * \retval	on success: nm_config_file handle for later deregistration
 * \retval	-ENOMEM		memory allocation failure
 * \retval	-ENOENT		error loading nodemap config
 * \retval	-EINVAL		error loading nodemap config
 * \retval	-EEXIST		nodemap config already registered for MGS
 */
struct nm_config_file *nm_config_file_register_mgs(const struct lu_env *env,
						   struct dt_object *obj,
						   struct local_oid_storage *los)
{
	struct nm_config_file *ncf;
	int rc = 0;
	ENTRY;

	if (nodemap_mgs_ncf != NULL)
		GOTO(out, ncf = ERR_PTR(-EEXIST));

	OBD_ALLOC_PTR(ncf);
	if (ncf == NULL)
		GOTO(out, ncf = ERR_PTR(-ENOMEM));

	/* if loading from cache, prevent activation of MGS config until cache
	 * loading is done, so disk config is overwritten by MGS config.
	 */
	mutex_lock(&nodemap_config_loaded_lock);
	rc = nodemap_load_entries(env, obj);
	if (!rc)
		nodemap_config_loaded = true;
	mutex_unlock(&nodemap_config_loaded_lock);

	if (rc) {
		OBD_FREE_PTR(ncf);
		GOTO(out, ncf = ERR_PTR(rc));
	}

	lu_object_get(&obj->do_lu);

	ncf->ncf_obj = obj;
	ncf->ncf_los = los;

	nodemap_mgs_ncf = ncf;

out:
	return ncf;
}
EXPORT_SYMBOL(nm_config_file_register_mgs);

struct nm_config_file *nm_config_file_register_tgt(const struct lu_env *env,
						   struct dt_device *dev,
						   struct local_oid_storage *los)
{
	struct nm_config_file *ncf;
	struct dt_object *config_obj = NULL;
	int rc = 0;

	OBD_ALLOC_PTR(ncf);
	if (ncf == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* don't load from cache if config already loaded */
	mutex_lock(&nodemap_config_loaded_lock);
	if (!nodemap_config_loaded) {
		config_obj = nodemap_cache_find_create(env, dev, los, 0);
		if (IS_ERR(config_obj))
			rc = PTR_ERR(config_obj);
		else
			rc = nodemap_load_entries(env, config_obj);

		if (!rc)
			nodemap_config_loaded = true;
	}
	mutex_unlock(&nodemap_config_loaded_lock);
	if (rc)
		GOTO(out_ncf, rc);

	/* sync on disk caches w/ loaded config in memory, ncf_obj may change */
	if (!config_obj) {
		config_obj = nodemap_save_config_cache(env, dev, los);
		if (IS_ERR(config_obj))
			GOTO(out_ncf, rc = PTR_ERR(config_obj));
	}

	ncf->ncf_obj = config_obj;
	ncf->ncf_los = los;

	mutex_lock(&ncf_list_lock);
	list_add(&ncf->ncf_list, &ncf_list_head);
	mutex_unlock(&ncf_list_lock);

out_ncf:
	if (rc) {
		OBD_FREE_PTR(ncf);
		RETURN(ERR_PTR(rc));
	}

	RETURN(ncf);
}
EXPORT_SYMBOL(nm_config_file_register_tgt);

/**
 * Deregister a nm_config_file. Should be called by targets during cleanup.
 *
 * \param ncf	config file to deregister
 */
void nm_config_file_deregister_mgs(const struct lu_env *env,
				   struct nm_config_file *ncf)
{
	ENTRY;
	LASSERT(nodemap_mgs_ncf == ncf);

	nodemap_mgs_ncf = NULL;
	if (ncf->ncf_obj)
		dt_object_put(env, ncf->ncf_obj);

	OBD_FREE_PTR(ncf);

	EXIT;
}
EXPORT_SYMBOL(nm_config_file_deregister_mgs);

void nm_config_file_deregister_tgt(const struct lu_env *env,
				   struct nm_config_file *ncf)
{
	ENTRY;

	if (ncf == NULL)
		return;

	mutex_lock(&ncf_list_lock);
	list_del(&ncf->ncf_list);
	mutex_unlock(&ncf_list_lock);

	if (ncf->ncf_obj)
		dt_object_put(env, ncf->ncf_obj);

	OBD_FREE_PTR(ncf);

	EXIT;
}
EXPORT_SYMBOL(nm_config_file_deregister_tgt);

int nodemap_process_idx_pages(struct nodemap_config *config, union lu_page *lip,
			      struct lu_nodemap **recent_nodemap)
{
	struct nodemap_key *key;
	union nodemap_rec *rec;
	char *entry;
	int j;
	int k;
	int rc = 0;
	int size = dt_nodemap_features.dif_keysize_max +
		   dt_nodemap_features.dif_recsize_max;
	ENTRY;

	for (j = 0; j < LU_PAGE_COUNT; j++) {
		if (lip->lp_idx.lip_magic != LIP_MAGIC)
			return -EINVAL;

		/* get and process keys and records from page */
		for (k = 0; k < lip->lp_idx.lip_nr; k++) {
			entry = lip->lp_idx.lip_entries + k * size;
			key = (struct nodemap_key *)entry;

			entry += dt_nodemap_features.dif_keysize_max;
			rec = (union nodemap_rec *)entry;

			rc = nodemap_process_keyrec(config, key, rec,
						    recent_nodemap);
			if (rc < 0)
				return rc;
		}
		lip++;
	}

	EXIT;
	return 0;
}
EXPORT_SYMBOL(nodemap_process_idx_pages);

static int nodemap_page_build(const struct lu_env *env, union lu_page *lp,
			      size_t nob, const struct dt_it_ops *iops,
			      struct dt_it *it, __u32 attr, void *arg)
{
	struct idx_info *ii = (struct idx_info *)arg;
	struct lu_idxpage *lip = &lp->lp_idx;
	char *entry;
	size_t size = ii->ii_keysize + ii->ii_recsize;
	int rc;
	ENTRY;

	if (nob < LIP_HDR_SIZE)
		return -EINVAL;

	/* initialize the header of the new container */
	memset(lip, 0, LIP_HDR_SIZE);
	lip->lip_magic = LIP_MAGIC;
	nob           -= LIP_HDR_SIZE;

	entry = lip->lip_entries;
	do {
		char		*tmp_entry = entry;
		struct dt_key	*key;
		__u64		hash;
		enum nodemap_idx_type key_type;

		/* fetch 64-bit hash value */
		hash = iops->store(env, it);
		ii->ii_hash_end = hash;

		if (OBD_FAIL_CHECK(OBD_FAIL_OBD_IDX_READ_BREAK)) {
			if (lip->lip_nr != 0)
				GOTO(out, rc = 0);
		}

		if (nob < size) {
			if (lip->lip_nr == 0)
				GOTO(out, rc = -EINVAL);
			GOTO(out, rc = 0);
		}

		key = iops->key(env, it);
		key_type = nodemap_get_key_type((struct nodemap_key *)key);

		/* on the first pass, get only the cluster types. On second
		 * pass, get all the rest */
		if ((ii->ii_attrs == NM_READ_CLUSTERS &&
				key_type == NODEMAP_CLUSTER_IDX) ||
		    (ii->ii_attrs == NM_READ_ATTRIBUTES &&
				key_type != NODEMAP_CLUSTER_IDX &&
				key_type != NODEMAP_EMPTY_IDX)) {
			memcpy(tmp_entry, key, ii->ii_keysize);
			tmp_entry += ii->ii_keysize;

			/* and finally the record */
			rc = iops->rec(env, it, (struct dt_rec *)tmp_entry,
				       attr);
			if (rc != -ESTALE) {
				if (rc != 0)
					GOTO(out, rc);

				/* hash/key/record successfully copied! */
				lip->lip_nr++;
				if (unlikely(lip->lip_nr == 1 &&
				    ii->ii_count == 0))
					ii->ii_hash_start = hash;

				entry = tmp_entry + ii->ii_recsize;
				nob -= size;
			}
		}

		/* move on to the next record */
		do {
			rc = iops->next(env, it);
		} while (rc == -ESTALE);

		/* move to second pass */
		if (rc > 0 && ii->ii_attrs == NM_READ_CLUSTERS) {
			ii->ii_attrs = NM_READ_ATTRIBUTES;
			rc = iops->load(env, it, 0);
			if (rc == 0)
				rc = iops->next(env, it);
			else if (rc > 0)
				rc = 0;
			else
				GOTO(out, rc);
		}

	} while (rc == 0);

	GOTO(out, rc);
out:
	if (rc >= 0 && lip->lip_nr > 0)
		/* one more container */
		ii->ii_count++;
	if (rc > 0)
		/* no more entries */
		ii->ii_hash_end = II_END_OFF;
	return rc;
}


int nodemap_index_read(struct lu_env *env,
		       struct nm_config_file *ncf,
		       struct idx_info *ii,
		       const struct lu_rdpg *rdpg)
{
	struct dt_object	*nodemap_idx = ncf->ncf_obj;
	__u64			 version;
	int			 rc = 0;

	ii->ii_keysize = dt_nodemap_features.dif_keysize_max;
	ii->ii_recsize = dt_nodemap_features.dif_recsize_max;

	dt_read_lock(env, nodemap_idx, 0);
	version = dt_version_get(env, nodemap_idx);
	if (rdpg->rp_hash != 0 && ii->ii_version != version) {
		CDEBUG(D_INFO, "nodemap config changed inflight, old %llu, new %llu\n",
		       ii->ii_version,
		       version);
		ii->ii_hash_end = 0;
	} else {
		rc = dt_index_walk(env, nodemap_idx, rdpg, nodemap_page_build,
				   ii);
		CDEBUG(D_INFO, "walked index, hashend %llx\n", ii->ii_hash_end);
	}

	if (rc >= 0)
		ii->ii_version = version;

	dt_read_unlock(env, nodemap_idx);
	return rc;
}
EXPORT_SYMBOL(nodemap_index_read);

/**
 * Returns the current nodemap configuration to MGC by walking the nodemap
 * config index and storing it in the response buffer.
 *
 * \param	req		incoming MGS_CONFIG_READ request
 * \retval	0		success
 * \retval	-EINVAL		malformed request
 * \retval	-ENOTCONN	client evicted/reconnected already
 * \retval	-ETIMEDOUT	client timeout or network error
 * \retval	-ENOMEM
 */
int nodemap_get_config_req(struct obd_device *mgs_obd,
			   struct ptlrpc_request *req)
{
	const struct ptlrpc_bulk_frag_ops *frag_ops = &ptlrpc_bulk_kiov_pin_ops;
	struct mgs_config_body *body;
	struct mgs_config_res *res;
	struct lu_rdpg rdpg;
	struct idx_info nodemap_ii;
	struct ptlrpc_bulk_desc *desc;
	struct tg_export_data *rqexp_ted = &req->rq_export->exp_target_data;
	int i;
	int page_count;
	int bytes = 0;
	int rc = 0;

	body = req_capsule_client_get(&req->rq_pill, &RMF_MGS_CONFIG_BODY);
	if (!body)
		RETURN(-EINVAL);

	if (body->mcb_type != MGS_CFG_T_NODEMAP)
		RETURN(-EINVAL);

	rdpg.rp_count = (body->mcb_units << body->mcb_bits);
	rdpg.rp_npages = (rdpg.rp_count + PAGE_SIZE - 1) >>
		PAGE_SHIFT;
	if (rdpg.rp_npages > PTLRPC_MAX_BRW_PAGES)
		RETURN(-EINVAL);

	CDEBUG(D_INFO, "reading nodemap log, name '%s', size = %u\n",
	       body->mcb_name, rdpg.rp_count);

	/* allocate pages to store the containers */
	OBD_ALLOC_PTR_ARRAY(rdpg.rp_pages, rdpg.rp_npages);
	if (rdpg.rp_pages == NULL)
		RETURN(-ENOMEM);
	for (i = 0; i < rdpg.rp_npages; i++) {
		rdpg.rp_pages[i] = alloc_page(GFP_NOFS);
		if (rdpg.rp_pages[i] == NULL)
			GOTO(out, rc = -ENOMEM);
	}

	rdpg.rp_hash = body->mcb_offset;
	nodemap_ii.ii_magic = IDX_INFO_MAGIC;
	nodemap_ii.ii_flags = II_FL_NOHASH;
	nodemap_ii.ii_version = rqexp_ted->ted_nodemap_version;
	nodemap_ii.ii_attrs = body->mcb_nm_cur_pass;

	bytes = nodemap_index_read(req->rq_svc_thread->t_env,
				   mgs_obd->u.obt.obt_nodemap_config_file,
				   &nodemap_ii, &rdpg);
	if (bytes < 0)
		GOTO(out, rc = bytes);

	rqexp_ted->ted_nodemap_version = nodemap_ii.ii_version;

	res = req_capsule_server_get(&req->rq_pill, &RMF_MGS_CONFIG_RES);
	if (res == NULL)
		GOTO(out, rc = -EINVAL);
	res->mcr_offset = nodemap_ii.ii_hash_end;
	res->mcr_nm_cur_pass = nodemap_ii.ii_attrs;

	page_count = (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
	LASSERT(page_count <= rdpg.rp_count);
	desc = ptlrpc_prep_bulk_exp(req, page_count, 1,
				    PTLRPC_BULK_PUT_SOURCE,
				    MGS_BULK_PORTAL, frag_ops);
	if (desc == NULL)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < page_count && bytes > 0; i++) {
		frag_ops->add_kiov_frag(desc, rdpg.rp_pages[i], 0,
					min_t(int, bytes, PAGE_SIZE));
		bytes -= PAGE_SIZE;
	}

	rc = target_bulk_io(req->rq_export, desc);
	ptlrpc_free_bulk(desc);

out:
	if (rdpg.rp_pages != NULL) {
		for (i = 0; i < rdpg.rp_npages; i++)
			if (rdpg.rp_pages[i] != NULL)
				__free_page(rdpg.rp_pages[i]);
		OBD_FREE_PTR_ARRAY(rdpg.rp_pages, rdpg.rp_npages);
	}
	return rc;
}
EXPORT_SYMBOL(nodemap_get_config_req);
