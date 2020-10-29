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
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */
#include <linux/module.h>
#include <linux/sort.h>
#include <uapi/linux/lnet/nidstr.h>
#include <lustre_net.h>
#include <lustre_acl.h>
#include <obd_class.h>
#include "nodemap_internal.h"

#define HASH_NODEMAP_BKT_BITS 3
#define HASH_NODEMAP_CUR_BITS 3
#define HASH_NODEMAP_MAX_BITS 7

#define DEFAULT_NODEMAP "default"

/* nodemap proc root proc directory under fs/lustre */
struct proc_dir_entry *proc_lustre_nodemap_root;

/* Copy of config active flag to avoid locking in mapping functions */
bool nodemap_active;

/* Lock protecting the active config, useful primarily when proc and
 * nodemap_hash might be replaced when loading a new config
 * Any time the active config is referenced, the lock should be held.
 */
DEFINE_MUTEX(active_config_lock);
struct nodemap_config *active_config;

/**
 * Nodemap destructor
 *
 * \param	nodemap		nodemap to destroy
 */
static void nodemap_destroy(struct lu_nodemap *nodemap)
{
	ENTRY;

	if (nodemap->nm_pde_data != NULL)
		lprocfs_nodemap_remove(nodemap->nm_pde_data);

	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);
	nm_member_reclassify_nodemap(nodemap);
	up_read(&active_config->nmc_range_tree_lock);

	down_write(&nodemap->nm_idmap_lock);
	idmap_delete_tree(nodemap);
	up_write(&nodemap->nm_idmap_lock);

	mutex_unlock(&active_config_lock);

	if (!list_empty(&nodemap->nm_member_list))
		CWARN("nodemap_destroy failed to reclassify all members\n");

	nm_member_delete_list(nodemap);

	OBD_FREE_PTR(nodemap);

	EXIT;
}

/**
 * Functions used for the cfs_hash
 */
void nodemap_getref(struct lu_nodemap *nodemap)
{
	atomic_inc(&nodemap->nm_refcount);
	CDEBUG(D_INFO, "GETting nodemap %s(p=%p) : new refcount %d\n",
	       nodemap->nm_name, nodemap, atomic_read(&nodemap->nm_refcount));
}

/**
 * Destroy nodemap if last reference is put. Should be called outside
 * active_config_lock
 */
void nodemap_putref(struct lu_nodemap *nodemap)
{
	if (!nodemap)
		return;

	LASSERT(atomic_read(&nodemap->nm_refcount) > 0);

	CDEBUG(D_INFO, "PUTting nodemap %s(p=%p) : new refcount %d\n",
	       nodemap->nm_name, nodemap,
	       atomic_read(&nodemap->nm_refcount) - 1);

	if (atomic_dec_and_test(&nodemap->nm_refcount))
		nodemap_destroy(nodemap);
}
EXPORT_SYMBOL(nodemap_putref);

static __u32 nodemap_hashfn(struct cfs_hash *hash_body,
			    const void *key, unsigned mask)
{
	return cfs_hash_djb2_hash(key, strlen(key), mask);
}

static void *nodemap_hs_key(struct hlist_node *hnode)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);

	return nodemap->nm_name;
}

static int nodemap_hs_keycmp(const void *key,
			     struct hlist_node *compared_hnode)
{
	char *nodemap_name;

	nodemap_name = nodemap_hs_key(compared_hnode);

	return !strcmp(key, nodemap_name);
}

static void *nodemap_hs_hashobject(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct lu_nodemap, nm_hash);
}

static void nodemap_hs_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	nodemap_getref(nodemap);
}

static void nodemap_hs_put_locked(struct cfs_hash *hs,
				  struct hlist_node *hnode)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	nodemap_putref(nodemap);
}

static struct cfs_hash_ops nodemap_hash_operations = {
	.hs_hash	= nodemap_hashfn,
	.hs_key		= nodemap_hs_key,
	.hs_keycmp	= nodemap_hs_keycmp,
	.hs_object	= nodemap_hs_hashobject,
	.hs_get		= nodemap_hs_get,
	.hs_put_locked	= nodemap_hs_put_locked,
};

/* end of cfs_hash functions */

/**
 * Initialize nodemap_hash
 *
 * \retval	0		success
 * \retval	-ENOMEM		cannot create hash
 */
static int nodemap_init_hash(struct nodemap_config *nmc)
{
	nmc->nmc_nodemap_hash = cfs_hash_create("NODEMAP",
						HASH_NODEMAP_CUR_BITS,
						HASH_NODEMAP_MAX_BITS,
						HASH_NODEMAP_BKT_BITS, 0,
						CFS_HASH_MIN_THETA,
						CFS_HASH_MAX_THETA,
						&nodemap_hash_operations,
						CFS_HASH_DEFAULT);

	if (nmc->nmc_nodemap_hash == NULL) {
		CERROR("cannot create nodemap_hash table\n");
		return -ENOMEM;
	}

	return 0;
}

/**
 * Check for valid nodemap name
 *
 * \param	name		nodemap name
 * \retval	true		valid
 * \retval	false		invalid
 */
static bool nodemap_name_is_valid(const char *name)
{
	if (strlen(name) > LUSTRE_NODEMAP_NAME_LENGTH ||
	    strlen(name) == 0)
		return false;

	for (; *name != '\0'; name++) {
		if (!isalnum(*name) && *name != '_')
			return false;
	}

	return true;
}

/**
 * Nodemap lookup
 *
 * Look nodemap up in the active_config nodemap hash. Caller should hold the
 * active_config_lock.
 *
 * \param	name		name of nodemap
 * \retval	nodemap		pointer set to found nodemap
 * \retval	-EINVAL		name is not valid
 * \retval	-ENOENT		nodemap not found
 */
struct lu_nodemap *nodemap_lookup(const char *name)
{
	struct lu_nodemap *nodemap = NULL;

	if (!nodemap_name_is_valid(name))
		return ERR_PTR(-EINVAL);

	nodemap = cfs_hash_lookup(active_config->nmc_nodemap_hash, name);
	if (nodemap == NULL)
		return ERR_PTR(-ENOENT);

	return nodemap;
}

/**
 * Classify the nid into the proper nodemap. Caller must hold active config and
 * nm_range_tree_lock, and call nodemap_putref when done with nodemap.
 *
 * \param	nid			nid to classify
 * \retval	nodemap			nodemap containing the nid
 * \retval	default_nodemap		default nodemap
 * \retval	-EINVAL			LO nid given without other local nid
 */
struct lu_nodemap *nodemap_classify_nid(lnet_nid_t nid)
{
	struct lu_nid_range *range;
	struct lu_nodemap *nodemap;
	int rc;

	ENTRY;

	/* don't use 0@lo, use the first non-lo local NID instead */
	if (nid == LNET_NID_LO_0) {
		struct lnet_process_id id;
		int i = 0;

		do {
			rc = LNetGetId(i++, &id);
			if (rc < 0)
				RETURN(ERR_PTR(-EINVAL));
		} while (id.nid == LNET_NID_LO_0);

		nid = id.nid;
		CDEBUG(D_INFO, "found nid %s\n", libcfs_nid2str(nid));
	}

	range = range_search(&active_config->nmc_range_tree, nid);
	if (range != NULL)
		nodemap = range->rn_nodemap;
	else
		nodemap = active_config->nmc_default_nodemap;

	LASSERT(nodemap != NULL);
	nodemap_getref(nodemap);

	RETURN(nodemap);
}

/**
 * simple check for default nodemap
 */
static bool is_default_nodemap(const struct lu_nodemap *nodemap)
{
	return nodemap->nm_id == 0;
}

/**
 * parse a nodemap range string into two nids
 *
 * \param	range_str		string to parse
 * \param	range[2]		array of two nids
 * \reyval	0 on success
 */
int nodemap_parse_range(const char *range_str, lnet_nid_t range[2])
{
	char	buf[LNET_NIDSTR_SIZE * 2 + 2];
	char	*ptr = NULL;
	char    *start_nidstr;
	char    *end_nidstr;
	int     rc = 0;

	snprintf(buf, sizeof(buf), "%s", range_str);
	ptr = buf;
	start_nidstr = strsep(&ptr, ":");
	end_nidstr = strsep(&ptr, ":");

	if (start_nidstr == NULL || end_nidstr == NULL)
		GOTO(out, rc = -EINVAL);

	range[0] = libcfs_str2nid(start_nidstr);
	range[1] = libcfs_str2nid(end_nidstr);

out:
	return rc;

}
EXPORT_SYMBOL(nodemap_parse_range);

/**
 * parse a string containing an id map of form "client_id:filesystem_id"
 * into an array of __u32 * for use in mapping functions
 *
 * \param	idmap_str		map string
 * \param	idmap			array[2] of __u32
 *
 * \retval	0 on success
 * \retval	-EINVAL if idmap cannot be parsed
 */
int nodemap_parse_idmap(char *idmap_str, __u32 idmap[2])
{
	char			*sep;
	long unsigned int	 idmap_buf;
	int			 rc;

	if (idmap_str == NULL)
		return -EINVAL;

	sep = strchr(idmap_str, ':');
	if (sep == NULL)
		return -EINVAL;
	*sep = '\0';
	sep++;

	rc = kstrtoul(idmap_str, 10, &idmap_buf);
	if (rc != 0)
		return -EINVAL;
	idmap[0] = idmap_buf;

	rc = kstrtoul(sep, 10, &idmap_buf);
	if (rc != 0)
		return -EINVAL;
	idmap[1] = idmap_buf;

	return 0;
}
EXPORT_SYMBOL(nodemap_parse_idmap);

/**
 * add a member to a nodemap
 *
 * \param	nid		nid to add to the members
 * \param	exp		obd_export structure for the connection
 *				that is being added
 * \retval	-EINVAL		export is NULL, or has invalid NID
 * \retval	-EEXIST		export is already member of a nodemap
 */
int nodemap_add_member(lnet_nid_t nid, struct obd_export *exp)
{
	struct lu_nodemap *nodemap;
	int rc = 0;
	ENTRY;

	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);

	nodemap = nodemap_classify_nid(nid);

	if (IS_ERR(nodemap)) {
		CWARN("%s: error adding to nodemap, no valid NIDs found\n",
			  exp->exp_obd->obd_name);
		rc = -EINVAL;
	} else {
		rc = nm_member_add(nodemap, exp);
	}

	up_read(&active_config->nmc_range_tree_lock);
	mutex_unlock(&active_config_lock);

	if (!IS_ERR(nodemap))
		nodemap_putref(nodemap);

	RETURN(rc);
}
EXPORT_SYMBOL(nodemap_add_member);

/**
 * delete a member from a nodemap
 *
 * \param	exp		export to remove from a nodemap
 */
void nodemap_del_member(struct obd_export *exp)
{
	struct lu_nodemap *nodemap;

	ENTRY;

	/* using ac lock to prevent nodemap reclassification while deleting */
	mutex_lock(&active_config_lock);

	/* use of ted_nodemap is protected by active_config_lock. we take an
	 * extra reference to make sure nodemap isn't destroyed under
	 * active_config_lock
	 */
	nodemap = exp->exp_target_data.ted_nodemap;
	if (nodemap == NULL)
		goto out;
	else
		nodemap_getref(nodemap);

	mutex_lock(&nodemap->nm_member_list_lock);
	nm_member_del(nodemap, exp);
	mutex_unlock(&nodemap->nm_member_list_lock);

out:
	mutex_unlock(&active_config_lock);

	if (nodemap)
		nodemap_putref(nodemap);

	EXIT;
}
EXPORT_SYMBOL(nodemap_del_member);

/**
 * add an idmap to the proper nodemap trees
 *
 * \param	nodemap		nodemap to add idmap to
 * \param	id_type		NODEMAP_UID or NODEMAP_GID
 * \param	map		array[2] __u32 containing the map values
 *				map[0] is client id
 *				map[1] is the filesystem id
 *
 * \retval	0	on success
 * \retval	< 0	if error occurs
 */
int nodemap_add_idmap_helper(struct lu_nodemap *nodemap,
			     enum nodemap_id_type id_type,
			     const __u32 map[2])
{
	struct lu_idmap		*idmap;
	struct lu_idmap		*temp;
	int			rc = 0;

	idmap = idmap_create(map[0], map[1]);
	if (idmap == NULL)
		GOTO(out, rc = -ENOMEM);

	down_write(&nodemap->nm_idmap_lock);
	temp = idmap_insert(id_type, idmap, nodemap);
	/* If the new id_client or id_fs is matched, the old idmap and its
	 * index should be deleted according to its id_client before the new
	 * idmap is added again.
	 */
	if (IS_ERR(temp))
		GOTO(out_insert, rc = PTR_ERR(temp));
	if (temp) {
		__u32 del_map[2];

		del_map[0] = temp->id_client;
		idmap_delete(id_type, temp, nodemap);
		rc = nodemap_idx_idmap_del(nodemap, id_type, del_map);
		/* In case there is any corrupted idmap */
		if (!rc || unlikely(rc == -ENOENT)) {
			temp = idmap_insert(id_type, idmap, nodemap);
			if (IS_ERR(temp))
				rc = PTR_ERR(temp);
			else if (!temp)
				rc = 0;
			else
				rc = -EPERM;
		}
	}
out_insert:
	if (rc)
		OBD_FREE_PTR(idmap);
	up_write(&nodemap->nm_idmap_lock);
	nm_member_revoke_locks(nodemap);

out:
	return rc;
}

int nodemap_add_idmap(const char *name, enum nodemap_id_type id_type,
		      const __u32 map[2])
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc;

	ENTRY;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap)) {
		rc = -EINVAL;
	} else {
		rc = nodemap_add_idmap_helper(nodemap, id_type, map);
		if (rc == 0)
			rc = nodemap_idx_idmap_add(nodemap, id_type, map);
	}
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);

out:
	RETURN(rc);
}
EXPORT_SYMBOL(nodemap_add_idmap);

/**
 * delete idmap from proper nodemap tree
 *
 * \param	name		name of nodemap
 * \param	id_type		NODEMAP_UID or NODEMAP_GID
 * \param	map		array[2] __u32 containing the mapA values
 *				map[0] is client id
 *				map[1] is the filesystem id
 *
 * \retval	0 on success
 */
int nodemap_del_idmap(const char *name, enum nodemap_id_type id_type,
		      const __u32 map[2])
{
	struct lu_nodemap	*nodemap = NULL;
	struct lu_idmap		*idmap = NULL;
	int			rc = 0;

	ENTRY;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_putref, rc = -EINVAL);

	down_write(&nodemap->nm_idmap_lock);
	idmap = idmap_search(nodemap, NODEMAP_CLIENT_TO_FS, id_type,
			     map[0]);
	if (idmap == NULL) {
		rc = -EINVAL;
	} else {
		idmap_delete(id_type, idmap, nodemap);
		rc = nodemap_idx_idmap_del(nodemap, id_type, map);
	}
	up_write(&nodemap->nm_idmap_lock);

out_putref:
	mutex_unlock(&active_config_lock);
	if (rc == 0)
		nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);

out:
	RETURN(rc);
}
EXPORT_SYMBOL(nodemap_del_idmap);

/**
 * Get nodemap assigned to given export. Takes a reference on the nodemap.
 *
 * Note that this function may return either NULL, or an ERR_PTR()
 * or a valid nodemap pointer.  All of the functions accessing the
 * returned nodemap can check IS_ERR(nodemap) to see if an error is
 * returned.  NULL is not considered an error, which is OK since this
 * is a valid case if nodemap are not in use.  All nodemap handling
 * functions must check for nodemap == NULL and do nothing, and the
 * nodemap returned from this function should not be dereferenced.
 *
 * \param	export		export to get nodemap for
 *
 * \retval	pointer to nodemap on success
 * \retval	NULL	nodemap subsystem disabled
 * \retval	-EACCES	export does not have nodemap assigned
 */
struct lu_nodemap *nodemap_get_from_exp(struct obd_export *exp)
{
	struct lu_nodemap *nodemap;

	ENTRY;

	if (!nodemap_active)
		RETURN(NULL);

	spin_lock(&exp->exp_target_data.ted_nodemap_lock);
	nodemap = exp->exp_target_data.ted_nodemap;
	if (nodemap)
		nodemap_getref(nodemap);
	spin_unlock(&exp->exp_target_data.ted_nodemap_lock);

	if (!nodemap) {
		CDEBUG(D_INFO, "%s: nodemap null on export %s (at %s)\n",
		       exp->exp_obd->obd_name,
		       obd_uuid2str(&exp->exp_client_uuid),
		       obd_export_nid2str(exp));
		RETURN(ERR_PTR(-EACCES));
	}

	RETURN(nodemap);
}
EXPORT_SYMBOL(nodemap_get_from_exp);

/**
 * mapping function for nodemap idmaps
 *
 * \param	nodemap		lu_nodemap structure defining nodemap
 * \param	node_type	NODEMAP_UID or NODEMAP_GID
 * \param	tree_type	NODEMAP_CLIENT_TO_FS or
 *				NODEMAP_FS_TO_CLIENT
 * \param	id		id to map
 *
 * \retval	mapped id according to the rules below.
 *
 * if the nodemap_active is false, just return the passed id without mapping
 *
 * if the id to be looked up is 0, check that root access is allowed and if it
 * is, return 0. Otherwise, return the squash uid or gid.
 *
 * if the nodemap is configured to trusted the ids from the client system, just
 * return the passed id without mapping.
 *
 * if by this point, we haven't returned and the nodemap in question is the
 * default nodemap, return the squash uid or gid.
 *
 * after these checks, search the proper tree for the mapping, and if found
 * return the mapped value, otherwise return the squash uid or gid.
 */
__u32 nodemap_map_id(struct lu_nodemap *nodemap,
		     enum nodemap_id_type id_type,
		     enum nodemap_tree_type tree_type, __u32 id)
{
	struct lu_idmap		*idmap = NULL;
	__u32			 found_id;

	ENTRY;

	if (!nodemap_active)
		goto out;

	if (unlikely(nodemap == NULL))
		goto out;

	if (nodemap->nmf_map_uid_only && id_type == NODEMAP_GID)
		goto out;

	if (nodemap->nmf_map_gid_only && id_type == NODEMAP_UID)
		goto out;

	if (id == 0) {
		if (nodemap->nmf_allow_root_access)
			goto out;
		else
			goto squash;
	}

	if (nodemap->nmf_trust_client_ids)
		goto out;

	if (is_default_nodemap(nodemap))
		goto squash;

	down_read(&nodemap->nm_idmap_lock);
	idmap = idmap_search(nodemap, tree_type, id_type, id);
	if (idmap == NULL) {
		up_read(&nodemap->nm_idmap_lock);
		goto squash;
	}

	if (tree_type == NODEMAP_FS_TO_CLIENT)
		found_id = idmap->id_client;
	else
		found_id = idmap->id_fs;
	up_read(&nodemap->nm_idmap_lock);
	RETURN(found_id);

squash:
	if (id_type == NODEMAP_UID)
		RETURN(nodemap->nm_squash_uid);
	else
		RETURN(nodemap->nm_squash_gid);
out:
	RETURN(id);
}
EXPORT_SYMBOL(nodemap_map_id);

/**
 * Map posix ACL entries according to the nodemap membership. Removes any
 * squashed ACLs.
 *
 * \param	lu_nodemap	nodemap
 * \param	buf		buffer containing xattr encoded ACLs
 * \param	size		size of ACLs in bytes
 * \param	tree_type	direction of mapping
 * \retval	size		new size of ACLs in bytes
 * \retval	-EINVAL		bad \a size param, see posix_acl_xattr_count()
 */
ssize_t nodemap_map_acl(struct lu_nodemap *nodemap, void *buf, size_t size,
			enum nodemap_tree_type tree_type)
{
	posix_acl_xattr_header	*header = buf;
	posix_acl_xattr_entry	*entry = GET_POSIX_ACL_XATTR_ENTRY(header);
	posix_acl_xattr_entry	*new_entry = entry;
	posix_acl_xattr_entry	*end;
	int			 count;

	ENTRY;

	if (!nodemap_active)
		RETURN(size);

	if (unlikely(nodemap == NULL))
		RETURN(size);

	count = posix_acl_xattr_count(size);
	if (count < 0)
		RETURN(-EINVAL);
	if (count == 0)
		RETURN(0);

	for (end = entry + count; entry != end; entry++) {
		__u16 tag = le16_to_cpu(entry->e_tag);
		__u32 id = le32_to_cpu(entry->e_id);

		switch (tag) {
		case ACL_USER:
			id = nodemap_map_id(nodemap, NODEMAP_UID,
					    tree_type, id);
			if (id == nodemap->nm_squash_uid)
				continue;
			entry->e_id = cpu_to_le32(id);
			break;
		case ACL_GROUP:
			id = nodemap_map_id(nodemap, NODEMAP_GID,
					    tree_type, id);
			if (id == nodemap->nm_squash_gid)
				continue;
			entry->e_id = cpu_to_le32(id);
			break;
		}

		/* if we skip an ACL, copy the following ones over it */
		if (new_entry != entry)
			*new_entry = *entry;

		new_entry++;
	}

	RETURN((void *)new_entry - (void *)header);
}
EXPORT_SYMBOL(nodemap_map_acl);

/*
 * Add nid range to given nodemap
 *
 * \param	config		nodemap config to work on
 * \param	nodemap		nodemap to add range to
 * \param	nid		nid range to add
 * \param	range_id	should be 0 unless loading from disk
 * \retval	0		success
 * \retval	-ENOMEM
 *
 */
int nodemap_add_range_helper(struct nodemap_config *config,
			     struct lu_nodemap *nodemap,
			     const lnet_nid_t nid[2],
			     unsigned int range_id)
{
	struct lu_nid_range	*range;
	int rc;

	down_write(&config->nmc_range_tree_lock);
	range = range_create(&config->nmc_range_tree, nid[0], nid[1],
			     nodemap, range_id);
	if (range == NULL) {
		up_write(&config->nmc_range_tree_lock);
		GOTO(out, rc = -ENOMEM);
	}

	rc = range_insert(&config->nmc_range_tree, range);
	if (rc != 0) {
		CERROR("cannot insert nodemap range into '%s': rc = %d\n",
		      nodemap->nm_name, rc);
		up_write(&config->nmc_range_tree_lock);
		list_del(&range->rn_list);
		range_destroy(range);
		GOTO(out, rc = -ENOMEM);
	}

	list_add(&range->rn_list, &nodemap->nm_ranges);

	/* nodemaps have no members if they aren't on the active config */
	if (config == active_config)
		nm_member_reclassify_nodemap(config->nmc_default_nodemap);

	up_write(&config->nmc_range_tree_lock);

	/* if range_id is non-zero, we are loading from disk */
	if (range_id == 0)
		rc = nodemap_idx_range_add(range, nid);

	if (config == active_config) {
		nm_member_revoke_locks(config->nmc_default_nodemap);
		nm_member_revoke_locks(nodemap);
	}

out:
	return rc;
}
int nodemap_add_range(const char *name, const lnet_nid_t nid[2])
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap))
		rc = -EINVAL;
	else
		rc = nodemap_add_range_helper(active_config, nodemap, nid, 0);
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_add_range);

/**
 * delete a range
 * \param	name		nodemap name
 * \param	nid		nid range
 * \retval	0 on success
 *
 * Delete range from global range tree, and remove it
 * from the list in the associated nodemap.
 */
int nodemap_del_range(const char *name, const lnet_nid_t nid[2])
{
	struct lu_nodemap	*nodemap;
	struct lu_nid_range	*range;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_putref, rc = -EINVAL);

	down_write(&active_config->nmc_range_tree_lock);
	range = range_find(&active_config->nmc_range_tree, nid[0], nid[1]);
	if (range == NULL) {
		up_write(&active_config->nmc_range_tree_lock);
		GOTO(out_putref, rc = -EINVAL);
	}
	if (range->rn_nodemap != nodemap) {
		up_write(&active_config->nmc_range_tree_lock);
		GOTO(out_putref, rc = -EINVAL);
	}
	rc = nodemap_idx_range_del(range);
	range_delete(&active_config->nmc_range_tree, range);
	nm_member_reclassify_nodemap(nodemap);
	up_write(&active_config->nmc_range_tree_lock);

	nm_member_revoke_locks(active_config->nmc_default_nodemap);
	nm_member_revoke_locks(nodemap);

out_putref:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_del_range);

/**
 * set fileset on nodemap
 * \param	name		nodemap to set fileset on
 * \param	fileset		string containing fileset
 * \retval	0 on success
 *
 * set a fileset on the named nodemap
 */
static int nodemap_set_fileset_helper(struct nodemap_config *config,
				      struct lu_nodemap *nodemap,
				      const char *fileset)
{
	int rc = 0;

	/* Allow 'fileset=clear' in addition to 'fileset=""' to clear fileset
	 * because either command 'lctl set_param -P *.*.fileset=""' or
	 * 'lctl nodemap_set_fileset --fileset ""' can only work correctly
	 * on MGS, while on other servers, both commands will invoke upcall
	 * "/usr/sbin/lctl set_param nodemap.default.fileset=" by function
	 * process_param2_config(), which will cause "no value" error and
	 * won't clear fileset.
	 * 'fileset=""' is still kept for compatibility reason.
	 */
	if (fileset == NULL)
		rc = -EINVAL;
	else if (fileset[0] == '\0' || strcmp(fileset, "clear") == 0)
		nodemap->nm_fileset[0] = '\0';
	else if (fileset[0] != '/')
		rc = -EINVAL;
	else if (strlcpy(nodemap->nm_fileset, fileset,
			 sizeof(nodemap->nm_fileset)) >=
		 sizeof(nodemap->nm_fileset))
		rc = -ENAMETOOLONG;

	return rc;
}

int nodemap_set_fileset(const char *name, const char *fileset)
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	rc = nodemap_set_fileset_helper(active_config, nodemap, fileset);
	mutex_unlock(&active_config_lock);

	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_fileset);

/**
 * get fileset defined on nodemap
 * \param	nodemap		nodemap to get fileset from
 * \retval	fileset name, or NULL if not defined or not activated
 *
 * get the fileset defined on the nodemap
 */
char *nodemap_get_fileset(const struct lu_nodemap *nodemap)
{
	if (!nodemap_active)
		return NULL;

	return (char *)nodemap->nm_fileset;
}
EXPORT_SYMBOL(nodemap_get_fileset);

static int nodemap_validate_sepol(const char *sepol)
{
	char buf[LUSTRE_NODEMAP_SEPOL_LENGTH + 1];
	char *p = (char *)sepol;
	char *q = buf;
	char polname[NAME_MAX + 1] = "";
	char hash[SELINUX_POLICY_HASH_LEN + 1] = "";
	unsigned char mode;
	unsigned short ver;

	BUILD_BUG_ON(sizeof(buf) != sizeof(((struct lu_nodemap *)0)->nm_sepol));

	if (sepol == NULL)
		return -EINVAL;

	/* we allow sepol = "" which means clear SELinux policy info */
	if (sepol[0] == '\0')
		return 0;

	/* make a copy of sepol, by replacing ':' with space
	 * so that we can use sscanf over the string
	 */
	while (p-sepol < sizeof(buf)) {
		if (*p == ':')
			*q = ' ';
		else
			*q = *p;
		if (*p == '\0')
			break;
		p++;
		q++;
	}
	if (p-sepol == sizeof(buf))
		return -ENAMETOOLONG;

	if (sscanf(buf, "%1hhu %s %hu %s", &mode, polname, &ver, hash) != 4)
		return -EINVAL;

	if (mode != 0 && mode != 1)
		return -EINVAL;

	return 0;
}

/**
 * set SELinux policy on nodemap
 * \param	name		nodemap to set SELinux policy info on
 * \param	sepol		string containing SELinux policy info
 * \retval	0 on success
 *
 * set SELinux policy info on the named nodemap
 */
int nodemap_set_sepol(const char *name, const char *sepol)
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc;

	rc = nodemap_validate_sepol(sepol);
	if (rc < 0)
		GOTO(out, rc);

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap)) {
		/* We do not want nodes in the default nodemap to have
		 * SELinux restrictions. Sec admin should create dedicated
		 * nodemap entries for this.
		 */
		GOTO(out_putref, rc = -EINVAL);
	}

	/* truncation cannot happen, as string length was checked in
	 * nodemap_validate_sepol()
	 */
	strlcpy(nodemap->nm_sepol, sepol, sizeof(nodemap->nm_sepol));

out_putref:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_sepol);

/**
 * get SELinux policy info defined on nodemap
 * \param	nodemap		nodemap to get SELinux policy info from
 * \retval	SELinux policy info, or NULL if not defined or not activated
 *
 * get the SELinux policy info defined on the nodemap
 */
const char *nodemap_get_sepol(const struct lu_nodemap *nodemap)
{
	if (is_default_nodemap(nodemap))
		return NULL;
	else
		return (char *)nodemap->nm_sepol;
}
EXPORT_SYMBOL(nodemap_get_sepol);

/**
 * Nodemap constructor
 *
 * Creates an lu_nodemap structure and assigns sane default
 * member values. If this is the default nodemap, the defaults
 * are the most restrictive in terms of mapping behavior. Otherwise
 * the default flags should be inherited from the default nodemap.
 * The adds nodemap to nodemap_hash.
 *
 * Requires that the caller take the active_config_lock
 *
 * \param	name		name of nodemap
 * \param	is_default	true if default nodemap
 * \retval	nodemap		success
 * \retval	-EINVAL		invalid nodemap name
 * \retval	-EEXIST		nodemap already exists
 * \retval	-ENOMEM		cannot allocate memory for nodemap
 */
struct lu_nodemap *nodemap_create(const char *name,
				  struct nodemap_config *config,
				  bool is_default)
{
	struct lu_nodemap	*nodemap = NULL;
	struct lu_nodemap	*default_nodemap;
	struct cfs_hash		*hash = config->nmc_nodemap_hash;
	int			 rc = 0;
	ENTRY;

	default_nodemap = config->nmc_default_nodemap;

	if (!nodemap_name_is_valid(name))
		GOTO(out, rc = -EINVAL);

	if (hash == NULL) {
		CERROR("Config nodemap hash is NULL, unable to add %s\n", name);
		GOTO(out, rc = -EINVAL);
	}

	OBD_ALLOC_PTR(nodemap);
	if (nodemap == NULL) {
		CERROR("cannot allocate memory (%zu bytes) for nodemap '%s'\n",
		       sizeof(*nodemap), name);
		GOTO(out, rc = -ENOMEM);
	}

	/*
	 * take an extra reference to prevent nodemap from being destroyed
	 * while it's being created.
	 */
	atomic_set(&nodemap->nm_refcount, 2);
	snprintf(nodemap->nm_name, sizeof(nodemap->nm_name), "%s", name);
	rc = cfs_hash_add_unique(hash, name, &nodemap->nm_hash);
	if (rc != 0) {
		OBD_FREE_PTR(nodemap);
		GOTO(out, rc = -EEXIST);
	}

	INIT_LIST_HEAD(&nodemap->nm_ranges);
	INIT_LIST_HEAD(&nodemap->nm_list);
	INIT_LIST_HEAD(&nodemap->nm_member_list);

	mutex_init(&nodemap->nm_member_list_lock);
	init_rwsem(&nodemap->nm_idmap_lock);
	nodemap->nm_fs_to_client_uidmap = RB_ROOT;
	nodemap->nm_client_to_fs_uidmap = RB_ROOT;
	nodemap->nm_fs_to_client_gidmap = RB_ROOT;
	nodemap->nm_client_to_fs_gidmap = RB_ROOT;

	if (is_default) {
		nodemap->nm_id = LUSTRE_NODEMAP_DEFAULT_ID;
		config->nmc_default_nodemap = nodemap;
	} else {
		config->nmc_nodemap_highest_id++;
		nodemap->nm_id = config->nmc_nodemap_highest_id;
	}

	if (is_default || default_nodemap == NULL) {
		nodemap->nmf_trust_client_ids = 0;
		nodemap->nmf_allow_root_access = 0;
		nodemap->nmf_deny_unknown = 0;
		nodemap->nmf_map_uid_only = 0;
		nodemap->nmf_map_gid_only = 0;
		nodemap->nmf_enable_audit = 1;
		nodemap->nmf_forbid_encryption = 0;

		nodemap->nm_squash_uid = NODEMAP_NOBODY_UID;
		nodemap->nm_squash_gid = NODEMAP_NOBODY_GID;
		nodemap->nm_fileset[0] = '\0';
		nodemap->nm_sepol[0] = '\0';
		if (!is_default)
			CWARN("adding nodemap '%s' to config without"
			      " default nodemap\n", nodemap->nm_name);
	} else {
		nodemap->nmf_trust_client_ids =
				default_nodemap->nmf_trust_client_ids;
		nodemap->nmf_allow_root_access =
				default_nodemap->nmf_allow_root_access;
		nodemap->nmf_deny_unknown =
				default_nodemap->nmf_deny_unknown;
		nodemap->nmf_map_uid_only =
				default_nodemap->nmf_map_uid_only;
		nodemap->nmf_map_gid_only =
				default_nodemap->nmf_map_gid_only;
		nodemap->nmf_enable_audit =
			default_nodemap->nmf_enable_audit;
		nodemap->nmf_forbid_encryption =
			default_nodemap->nmf_forbid_encryption;

		nodemap->nm_squash_uid = default_nodemap->nm_squash_uid;
		nodemap->nm_squash_gid = default_nodemap->nm_squash_gid;
		nodemap->nm_fileset[0] = '\0';
		nodemap->nm_sepol[0] = '\0';
	}

	RETURN(nodemap);

out:
	CERROR("cannot add nodemap: '%s': rc = %d\n", name, rc);
	RETURN(ERR_PTR(rc));
}

/**
 * Set the nmf_deny_unknown flag to true or false.
 * \param	name		nodemap name
 * \param	deny_unknown	if true, squashed users will get EACCES
 * \retval	0 on success
 *
 */
int nodemap_set_deny_unknown(const char *name, bool deny_unknown)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nmf_deny_unknown = deny_unknown;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_deny_unknown);

/**
 * Set the nmf_allow_root_access flag to true or false.
 * \param	name		nodemap name
 * \param	allow_root	if true, nodemap will not squash the root user
 * \retval	0 on success
 *
 */
int nodemap_set_allow_root(const char *name, bool allow_root)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nmf_allow_root_access = allow_root;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_allow_root);

/**
 * Set the nmf_trust_client_ids flag to true or false.
 *
 * \param	name			nodemap name
 * \param	trust_client_ids	if true, nodemap will not map its IDs
 * \retval	0 on success
 *
 */
int nodemap_set_trust_client_ids(const char *name, bool trust_client_ids)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nmf_trust_client_ids = trust_client_ids;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_trust_client_ids);

int nodemap_set_mapping_mode(const char *name, enum nodemap_mapping_modes mode)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	switch (mode) {
	case NODEMAP_MAP_BOTH:
		nodemap->nmf_map_uid_only = 0;
		nodemap->nmf_map_gid_only = 0;
		break;
	case NODEMAP_MAP_UID_ONLY:
		nodemap->nmf_map_uid_only = 1;
		nodemap->nmf_map_gid_only = 0;
		break;
	case NODEMAP_MAP_GID_ONLY:
		nodemap->nmf_map_uid_only = 0;
		nodemap->nmf_map_gid_only = 1;
		break;
	default:
		CWARN("cannot set unknown mapping mode, mode = %d\n", mode);
	}
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_mapping_mode);

/**
 * Update the squash_uid for a nodemap.
 *
 * \param	name		nodemap name
 * \param	uid		the new uid to squash unknown users to
 * \retval	0 on success
 *
 * Update the squash_uid for a nodemap. The squash_uid is the uid
 * that the all client uids are mapped to if nodemap is active,
 * the trust_client_ids flag is not set, and the uid is not in
 * the idmap tree.
 */
int nodemap_set_squash_uid(const char *name, uid_t uid)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nm_squash_uid = uid;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_squash_uid);

/**
 * Update the squash_gid for a nodemap.
 *
 * \param	name		nodemap name
 * \param	gid		the new gid to squash unknown gids to
 * \retval	0 on success
 *
 * Update the squash_gid for a nodemap. The squash_uid is the gid
 * that the all client gids are mapped to if nodemap is active,
 * the trust_client_ids flag is not set, and the gid is not in
 * the idmap tree.
 */
int nodemap_set_squash_gid(const char *name, gid_t gid)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nm_squash_gid = gid;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_squash_gid);

/**
 * Returns true if this nodemap has root user access. Always returns true if
 * nodemaps are not active.
 *
 * \param	nodemap		nodemap to check access for
 */
bool nodemap_can_setquota(const struct lu_nodemap *nodemap)
{
	return !nodemap_active || (nodemap && nodemap->nmf_allow_root_access);
}
EXPORT_SYMBOL(nodemap_can_setquota);

/**
 * Set the nmf_enable_audit flag to true or false.
 * \param	name		nodemap name
 * \param	audit_mode	if true, allow audit
 * \retval	0 on success
 *
 */
int nodemap_set_audit_mode(const char *name, bool enable_audit)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nmf_enable_audit = enable_audit;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_audit_mode);

/**
 * Set the nmf_forbid_encryption flag to true or false.
 * \param	name			nodemap name
 * \param	forbid_encryption	if true, forbid encryption
 * \retval	0 on success
 *
 */
int nodemap_set_forbid_encryption(const char *name, bool forbid_encryption)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nmf_forbid_encryption = forbid_encryption;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_forbid_encryption);


/**
 * Add a nodemap
 *
 * \param	name		name of nodemap
 * \retval	0		success
 * \retval	-EINVAL		invalid nodemap name
 * \retval	-EEXIST		nodemap already exists
 * \retval	-ENOMEM		cannot allocate memory for nodemap
 */
int nodemap_add(const char *nodemap_name)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_create(nodemap_name, active_config, 0);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		return PTR_ERR(nodemap);
	}

	rc = nodemap_idx_nodemap_add(nodemap);
	if (rc == 0)
		rc = lprocfs_nodemap_register(nodemap, 0);

	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);

	return rc;
}
EXPORT_SYMBOL(nodemap_add);

/**
 * Delete a nodemap
 *
 * \param	name		name of nodemmap
 * \retval	0		success
 * \retval	-EINVAL		invalid input
 * \retval	-ENOENT		no existing nodemap
 */
int nodemap_del(const char *nodemap_name)
{
	struct lu_nodemap	*nodemap;
	struct lu_nid_range	*range;
	struct lu_nid_range	*range_temp;
	int			 rc = 0;
	int			 rc2 = 0;

	if (strcmp(nodemap_name, DEFAULT_NODEMAP) == 0)
		RETURN(-EINVAL);

	mutex_lock(&active_config_lock);
	nodemap = cfs_hash_del_key(active_config->nmc_nodemap_hash,
				   nodemap_name);
	if (nodemap == NULL) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = -ENOENT);
	}

	/* erase nodemap from active ranges to prevent client assignment */
	down_write(&active_config->nmc_range_tree_lock);
	list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
				 rn_list) {
		rc2 = nodemap_idx_range_del(range);
		if (rc2 < 0)
			rc = rc2;

		range_delete(&active_config->nmc_range_tree, range);
	}
	up_write(&active_config->nmc_range_tree_lock);

	rc2 = nodemap_idx_nodemap_del(nodemap);
	if (rc2 < 0)
		rc = rc2;

	/*
	 * remove procfs here in case nodemap_create called with same name
	 * before nodemap_destroy is run.
	 */
	lprocfs_nodemap_remove(nodemap->nm_pde_data);
	nodemap->nm_pde_data = NULL;

	/* reclassify all member exports from nodemap, so they put their refs */
	down_read(&active_config->nmc_range_tree_lock);
	nm_member_reclassify_nodemap(nodemap);
	up_read(&active_config->nmc_range_tree_lock);

	if (!list_empty(&nodemap->nm_member_list))
		CWARN("nodemap_del failed to reclassify all members\n");

	mutex_unlock(&active_config_lock);

	nodemap_putref(nodemap);

out:
	return rc;
}
EXPORT_SYMBOL(nodemap_del);

/**
 * activate nodemap functions
 *
 * \param	value		1 for on, 0 for off
 */
void nodemap_activate(const bool value)
{
	mutex_lock(&active_config_lock);
	active_config->nmc_nodemap_is_active = value;

	/* copy active value to global to avoid locking in map functions */
	nodemap_active = value;
	nodemap_idx_nodemap_activate(value);
	mutex_unlock(&active_config_lock);
	nm_member_revoke_all();
}
EXPORT_SYMBOL(nodemap_activate);

/**
 * Helper iterator to convert nodemap hash to list.
 *
 * \param	hs			hash structure
 * \param	bd			bucket descriptor
 * \param	hnode			hash node
 * \param	nodemap_list_head	list head for list of nodemaps in hash
 */
static int nodemap_cleanup_iter_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				   struct hlist_node *hnode,
				   void *nodemap_list_head)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	list_add(&nodemap->nm_list, nodemap_list_head);

	cfs_hash_bd_del_locked(hs, bd, hnode);

	return 0;
}

struct nodemap_config *nodemap_config_alloc(void)
{
	struct nodemap_config *config;
	int rc = 0;

	OBD_ALLOC_PTR(config);
	if (config == NULL)
		return ERR_PTR(-ENOMEM);

	rc = nodemap_init_hash(config);
	if (rc != 0) {
		OBD_FREE_PTR(config);
		return ERR_PTR(rc);
	}

	init_rwsem(&config->nmc_range_tree_lock);

	config->nmc_range_tree.nmrt_range_interval_root = INTERVAL_TREE_ROOT;

	return config;
}
EXPORT_SYMBOL(nodemap_config_alloc);

/**
 * Walk the nodemap_hash and remove all nodemaps.
 */
void nodemap_config_dealloc(struct nodemap_config *config)
{
	struct lu_nodemap	*nodemap = NULL;
	struct lu_nodemap	*nodemap_temp;
	struct lu_nid_range	*range;
	struct lu_nid_range	*range_temp;
	LIST_HEAD(nodemap_list_head);

	cfs_hash_for_each_safe(config->nmc_nodemap_hash,
			       nodemap_cleanup_iter_cb, &nodemap_list_head);
	cfs_hash_putref(config->nmc_nodemap_hash);

	/* Because nodemap_destroy might sleep, we can't destroy them
	 * in cfs_hash_for_each, so we build a list there and destroy here
	 */
	list_for_each_entry_safe(nodemap, nodemap_temp, &nodemap_list_head,
				 nm_list) {
		mutex_lock(&active_config_lock);
		down_write(&config->nmc_range_tree_lock);

		/* move members to new config, requires ac lock */
		nm_member_reclassify_nodemap(nodemap);
		list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
					 rn_list)
			range_delete(&config->nmc_range_tree, range);
		up_write(&config->nmc_range_tree_lock);
		mutex_unlock(&active_config_lock);

		/* putref must be outside of ac lock if nm could be destroyed */
		nodemap_putref(nodemap);
	}
	OBD_FREE_PTR(config);
}
EXPORT_SYMBOL(nodemap_config_dealloc);

/*
 * callback for cfs_hash_for_each_safe used to convert a nodemap hash to a
 * nodemap list, generally for locking purposes as a hash cb can't sleep.
 */
int nm_hash_list_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
		    struct hlist_node *hnode,
		    void *nodemap_list_head)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	list_add(&nodemap->nm_list, nodemap_list_head);
	return 0;
}

void nodemap_config_set_active(struct nodemap_config *config)
{
	struct nodemap_config	*old_config = active_config;
	struct lu_nodemap	*nodemap;
	struct lu_nodemap	*tmp;
	bool revoke_locks;
	LIST_HEAD(nodemap_list_head);

	ENTRY;

	LASSERT(active_config != config);
	LASSERT(config->nmc_default_nodemap);

	mutex_lock(&active_config_lock);

	/* move proc entries from already existing nms, create for new nms */
	cfs_hash_for_each_safe(config->nmc_nodemap_hash,
			       nm_hash_list_cb, &nodemap_list_head);
	list_for_each_entry_safe(nodemap, tmp, &nodemap_list_head, nm_list) {
		struct lu_nodemap *old_nm = NULL;

		if (active_config != NULL)
			old_nm = cfs_hash_lookup(
					active_config->nmc_nodemap_hash,
					nodemap->nm_name);
		if (old_nm != NULL) {
			nodemap->nm_pde_data = old_nm->nm_pde_data;
			old_nm->nm_pde_data = NULL;
			nodemap_putref(old_nm);
		} else {
			bool is_def = (nodemap == config->nmc_default_nodemap);

			lprocfs_nodemap_register(nodemap, is_def);
		}
	}

	/*
	 * We only need to revoke locks if old nodemap was active, and new
	 * config is now nodemap inactive. nodemap_config_dealloc will
	 * reclassify exports, triggering a lock revoke if and only if new
	 * nodemap is active.
	 */
	revoke_locks = !config->nmc_nodemap_is_active && nodemap_active;

	/* if new config is inactive, deactivate live config before switching */
	if (!config->nmc_nodemap_is_active)
		nodemap_active = false;
	active_config = config;
	if (config->nmc_nodemap_is_active)
		nodemap_active = true;

	mutex_unlock(&active_config_lock);

	if (old_config != NULL)
		nodemap_config_dealloc(old_config);

	if (revoke_locks)
		nm_member_revoke_all();

	EXIT;
}

/**
 * Cleanup nodemap module on exit
 */
void nodemap_mod_exit(void)
{
	nodemap_config_dealloc(active_config);
	nodemap_procfs_exit();
}

/**
 * Initialize the nodemap module
 */
int nodemap_mod_init(void)
{
	struct nodemap_config	*new_config;
	struct lu_nodemap	*nodemap;
	int			 rc = 0;

	rc = nodemap_procfs_init();
	if (rc != 0)
		return rc;

	new_config = nodemap_config_alloc();
	if (IS_ERR(new_config)) {
		nodemap_procfs_exit();
		GOTO(out, rc = PTR_ERR(new_config));
	}

	nodemap = nodemap_create(DEFAULT_NODEMAP, new_config, 1);
	if (IS_ERR(nodemap)) {
		nodemap_config_dealloc(new_config);
		nodemap_procfs_exit();
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	nodemap_config_set_active(new_config);
	nodemap_putref(nodemap);

out:
	return rc;
}

/**
 * Revoke locks for all nodemaps.
 */
void nm_member_revoke_all(void)
{
	struct lu_nodemap *nodemap;
	struct lu_nodemap *tmp;
	LIST_HEAD(nodemap_list_head);

	mutex_lock(&active_config_lock);
	cfs_hash_for_each_safe(active_config->nmc_nodemap_hash,
			       nm_hash_list_cb, &nodemap_list_head);

	/* revoke_locks sleeps, so can't call in cfs hash cb */
	list_for_each_entry_safe(nodemap, tmp, &nodemap_list_head, nm_list)
		nm_member_revoke_locks_always(nodemap);
	mutex_unlock(&active_config_lock);
}

/**
 * Returns the nodemap classification for a given nid into an ioctl buffer.
 * Useful for testing the nodemap configuration to make sure it is working as
 * expected.
 *
 * \param	nid		nid to classify
 * \param[out]	name_buf	buffer to write the nodemap name to
 * \param	name_len	length of buffer
 */
void nodemap_test_nid(lnet_nid_t nid, char *name_buf, size_t name_len)
{
	struct lu_nodemap	*nodemap;

	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);
	nodemap = nodemap_classify_nid(nid);
	up_read(&active_config->nmc_range_tree_lock);
	mutex_unlock(&active_config_lock);

	if (IS_ERR(nodemap))
		return;

	strncpy(name_buf, nodemap->nm_name, name_len);
	if (name_len > 0)
		name_buf[name_len - 1] = '\0';

	nodemap_putref(nodemap);
}
EXPORT_SYMBOL(nodemap_test_nid);

/**
 * Passes back the id mapping for a given nid/id pair. Useful for testing the
 * nodemap configuration to make sure it is working as expected.
 *
 * \param	nid		nid to classify
 * \param	idtype		uid or gid
 * \param	client_id	id to map to fs
 * \param	fs_id_buf	pointer to save mapped fs_id to
 *
 * \retval	0	success
 * \retval	-EINVAL	invalid NID
 */
int nodemap_test_id(lnet_nid_t nid, enum nodemap_id_type idtype,
		    __u32 client_id, __u32 *fs_id)
{
	struct lu_nodemap	*nodemap;

	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);
	nodemap = nodemap_classify_nid(nid);
	up_read(&active_config->nmc_range_tree_lock);
	mutex_unlock(&active_config_lock);

	if (IS_ERR(nodemap))
		return PTR_ERR(nodemap);

	*fs_id = nodemap_map_id(nodemap, idtype, NODEMAP_CLIENT_TO_FS,
			       client_id);
	nodemap_putref(nodemap);

	return 0;
}
EXPORT_SYMBOL(nodemap_test_id);
