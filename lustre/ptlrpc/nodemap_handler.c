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
#include "ptlrpc_internal.h"

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

static unsigned int
nodemap_hashfn(struct cfs_hash *hash_body,
	       const void *key, const unsigned int bits)
{
	return cfs_hash_djb2_hash(key, strlen(key), bits);
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
struct lu_nodemap *nodemap_classify_nid(struct lnet_nid *nid)
{
	struct lu_nid_range *range;
	struct lu_nodemap *nodemap;
	int rc;

	ENTRY;
	/* don't use 0@lo, use the first non-lo local NID instead */
	if (nid_is_lo0(nid)) {
		struct lnet_processid id;
		int i = 0;

		do {
			rc = LNetGetId(i++, &id, true);
			if (rc < 0)
				RETURN(ERR_PTR(-EINVAL));
		} while (nid_is_lo0(&id.nid));

		nid = &id.nid;
		CDEBUG(D_INFO, "found nid %s\n", libcfs_nidstr(nid));
	}

	range = range_search(active_config, nid);
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
int nodemap_parse_range(const char *range_str, struct lnet_nid range[2],
			u8 *netmask)
{
	char	buf[LNET_NIDSTR_SIZE * 2 + 2];
	char	*ptr = NULL;
	char    *start_nidstr;
	char    *end_nidstr;
	int     rc = 0;

	snprintf(buf, sizeof(buf), "%s", range_str);
	ptr = buf;

	/* For large NID we use netmasks. Currently we only
	 * support /128 which is a single NID.
	 */
	if (strchr(ptr, '/')) {
		start_nidstr = strsep(&ptr, "/");

		rc = kstrtou8(ptr, 10, netmask);
		if (rc < 0)
			GOTO(out, rc);
		if (*netmask != 128)
			GOTO(out, rc = -ERANGE);
		end_nidstr = start_nidstr;
	} else {
		start_nidstr = strsep(&ptr, ":");
		end_nidstr = strsep(&ptr, ":");
	}

	if (start_nidstr == NULL || end_nidstr == NULL)
		GOTO(out, rc = -EINVAL);

	rc = libcfs_strnid(&range[0], start_nidstr);
	if (rc < 0)
		GOTO(out, rc);

	rc = libcfs_strnid(&range[1], end_nidstr);
out:
	return rc;

}
EXPORT_SYMBOL(nodemap_parse_range);

/**
 * parse a string containing an id map of form "client_id:filesystem_id"
 * into an array of __u32 * for use in mapping functions
 *
 * the string can also be a range of "ci_start-ci_end:fs_start[-fs_end]"
 *
 * \param	nodemap_name		nodemap name string
 * \param	idmap_str		map string
 * \param	idmap			array[2] of __u32
 * \param	range_count		potential idmap range u32
 *
 * \retval	0 on success
 * \retval	-EINVAL if idmap cannot be parsed
 */
int nodemap_parse_idmap(const char *nodemap_name, char *idmap_str,
			__u32 idmap[2], u32 *range_count)
{
	char *sep;
	char *sep_range;
	char *potential_range;
	unsigned long id;
	int rc;
	int range = 1;

	if (idmap_str == NULL)
		return -EINVAL;

	sep = strchr(idmap_str, ':');
	if (sep == NULL)
		return -EINVAL;
	*sep = '\0';
	sep++;

	/* see if range is passed in idmap_str */
	sep_range = strchr(idmap_str, '-');
	if (sep_range)
		*sep_range++ = '\0';

	rc = kstrtoul(idmap_str, 10, &id);
	if (rc)
		return -EINVAL;
	idmap[0] = id;

	/* parse cid range end if it is supplied */
	if (sep_range) {
		rc = kstrtoul(sep_range, 10, &id);
		if (rc)
			return -EINVAL;

		range = id - idmap[0] + 1;
		if (range <= 0)
			return -ERANGE;
	}

	potential_range = strchr(sep, '-');
	if (potential_range)
		*potential_range++ = '\0';

	rc = kstrtoul(sep, 10, &id);
	if (rc)
		return -EINVAL;
	idmap[1] = id;

	/* parse fsid range end if it is supplied */
	if (potential_range) {
		rc = kstrtoul(potential_range, 10, &id);
		if (rc)
			return -ERANGE;

		/* make sure fsid range is equal to cid range */
		if (id - idmap[1] + 1 != range) {
			rc = -EINVAL;
			CERROR("%s: range length mismatch between client id %s-%s and fs id %s-%s: rc = %d\n",
			       nodemap_name, idmap_str, sep_range, sep,
			       potential_range, rc);
			return rc;
		}
	}
	*range_count = range;

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
int nodemap_add_member(struct lnet_nid *nid, struct obd_export *exp)
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

static int nodemap_add_idmap_range(const char *nodemap_name,
				   enum nodemap_id_type id_type,
				   const __u32 map[2], const u32 range_count)
{
	int rc = 0;
	int i;

	for (i = 0; i < range_count && !rc; i++) {
		rc = nodemap_add_idmap(nodemap_name, id_type,
				       (int[2]){map[0] + i, map[1] + i});
	}

	return rc;
}

int nodemap_add_idmap(const char *nodemap_name, enum nodemap_id_type id_type,
		      const __u32 map[2])
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc;

	ENTRY;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(nodemap_name);
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
int nodemap_del_idmap(const char *nodemap_name, enum nodemap_id_type id_type,
		      const __u32 map[2])
{
	struct lu_nodemap	*nodemap = NULL;
	struct lu_idmap		*idmap = NULL;
	int			rc = 0;

	ENTRY;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(nodemap_name);
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

static int nodemap_del_idmap_range(const char *nodemap_name,
				   enum nodemap_id_type id_type,
				   const __u32 map[2], const u32 range_count)
{
	int rc = 0;
	int i;

	for (i = 0; i < range_count && !rc; i++) {
		rc = nodemap_del_idmap(nodemap_name, id_type,
				       (int[2]) {map[0] + i, map[1] + i});
	}

	return rc;
}

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
 * \param	node_type	NODEMAP_UID or NODEMAP_GID or NODEMAP_PROJID
 * \param	tree_type	NODEMAP_CLIENT_TO_FS or
 *				NODEMAP_FS_TO_CLIENT
 * \param	id		id to map
 *
 * \retval	mapped id according to the rules below.
 *
 * if the nodemap_active is false, just return the passed id without mapping
 *
 * if the id to be looked up is 0, check that root access is allowed and if it
 * is, return 0. Otherwise, return the mapped uid or gid if any.
 * Otherwise, return the squash uid or gid.
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

	if (id == 0) {
		if (nodemap->nmf_allow_root_access)
			goto out;
		goto map;
	}

	if (id_type == NODEMAP_UID &&
	    !(nodemap->nmf_map_mode & NODEMAP_MAP_UID))
		goto out;

	if (id_type == NODEMAP_GID &&
	    !(nodemap->nmf_map_mode & NODEMAP_MAP_GID))
		goto out;

	if (id_type == NODEMAP_PROJID &&
	    !(nodemap->nmf_map_mode & NODEMAP_MAP_PROJID))
		goto out;

	if (nodemap->nmf_trust_client_ids)
		goto out;

map:
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
	if (id_type == NODEMAP_GID)
		RETURN(nodemap->nm_squash_gid);
	if (id_type == NODEMAP_PROJID)
		RETURN(nodemap->nm_squash_projid);
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
		/* if not proper ACL, do nothing and return initial size */
		RETURN(size);

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
			     const struct lnet_nid nid[2],
			     u8 netmask, unsigned int range_id)
{
	struct lu_nid_range *range;
	int rc;

	down_write(&config->nmc_range_tree_lock);
	range = range_create(config, &nid[0], &nid[1], netmask, nodemap,
			     range_id);
	if (range == NULL) {
		up_write(&config->nmc_range_tree_lock);
		GOTO(out, rc = -ENOMEM);
	}

	rc = range_insert(config, range);
	if (rc) {
		CDEBUG_LIMIT(rc == -EEXIST ? D_INFO : D_ERROR,
			     "cannot insert nodemap range into '%s': rc = %d\n",
			     nodemap->nm_name, rc);
		up_write(&config->nmc_range_tree_lock);
		list_del(&range->rn_list);
		range_destroy(range);
		GOTO(out, rc);
	}

	list_add(&range->rn_list, &nodemap->nm_ranges);

	/* nodemaps have no members if they aren't on the active config */
	if (config == active_config)
		nm_member_reclassify_nodemap(config->nmc_default_nodemap);

	up_write(&config->nmc_range_tree_lock);

	/* if range_id is non-zero, we are loading from disk */
	if (range_id == 0)
		rc = nodemap_idx_range_add(range);

	if (config == active_config) {
		nm_member_revoke_locks(config->nmc_default_nodemap);
		nm_member_revoke_locks(nodemap);
	}

out:
	return rc;
}

int nodemap_add_range(const char *name, const struct lnet_nid nid[2],
		      u8 netmask)
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
		rc = nodemap_add_range_helper(active_config, nodemap, nid,
					      netmask, 0);
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
int nodemap_del_range(const char *name, const struct lnet_nid nid[2],
		      u8 netmask)
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
	range = range_find(active_config, &nid[0], &nid[1], netmask);
	if (range == NULL) {
		up_write(&active_config->nmc_range_tree_lock);
		GOTO(out_putref, rc = -EINVAL);
	}
	if (range->rn_nodemap != nodemap) {
		up_write(&active_config->nmc_range_tree_lock);
		GOTO(out_putref, rc = -EINVAL);
	}
	rc = nodemap_idx_range_del(range);
	range_delete(active_config, range);
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
	else if (strscpy(nodemap->nm_fileset, fileset,
			 sizeof(nodemap->nm_fileset)) < 0)
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
	strscpy(nodemap->nm_sepol, sepol, sizeof(nodemap->nm_sepol));

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
	nodemap->nm_fs_to_client_projidmap = RB_ROOT;
	nodemap->nm_client_to_fs_projidmap = RB_ROOT;

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
		nodemap->nmf_map_mode = NODEMAP_MAP_ALL;
		nodemap->nmf_enable_audit = 1;
		nodemap->nmf_forbid_encryption = 0;
		nodemap->nmf_readonly_mount = 0;
		nodemap->nmf_rbac = NODEMAP_RBAC_ALL;

		nodemap->nm_squash_uid = NODEMAP_NOBODY_UID;
		nodemap->nm_squash_gid = NODEMAP_NOBODY_GID;
		nodemap->nm_squash_projid = NODEMAP_NOBODY_PROJID;
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
		nodemap->nmf_deny_unknown = default_nodemap->nmf_deny_unknown;
		nodemap->nmf_map_mode = default_nodemap->nmf_map_mode;
		nodemap->nmf_enable_audit = default_nodemap->nmf_enable_audit;
		nodemap->nmf_forbid_encryption =
			default_nodemap->nmf_forbid_encryption;
		nodemap->nmf_readonly_mount =
			default_nodemap->nmf_readonly_mount;
		nodemap->nmf_rbac = default_nodemap->nmf_rbac;

		nodemap->nm_squash_uid = default_nodemap->nm_squash_uid;
		nodemap->nm_squash_gid = default_nodemap->nm_squash_gid;
		nodemap->nm_squash_projid = default_nodemap->nm_squash_projid;
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

int nodemap_set_mapping_mode(const char *name,
			     enum nodemap_mapping_modes map_mode)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nmf_map_mode = map_mode;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_mapping_mode);

int nodemap_set_rbac(const char *name, enum nodemap_rbac_roles rbac)
{
	struct lu_nodemap *nodemap = NULL;
	enum nodemap_rbac_roles old_rbac;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	if (is_default_nodemap(nodemap))
		GOTO(put, rc = -EINVAL);

	old_rbac = nodemap->nmf_rbac;
	/* if value does not change, do nothing */
	if (rbac == old_rbac)
		GOTO(put, rc = 0);

	nodemap->nmf_rbac = rbac;
	if (rbac == NODEMAP_RBAC_ALL)
		/* if new value is ALL (default), just delete
		 * NODEMAP_CLUSTER_ROLES idx
		 */
		rc = nodemap_idx_cluster_roles_del(nodemap);
	else if (old_rbac == NODEMAP_RBAC_ALL)
		/* if old value is ALL (default), need to insert
		 * NODEMAP_CLUSTER_ROLES idx
		 */
		rc = nodemap_idx_cluster_roles_add(nodemap);
	else
		/* otherwise just update existing NODEMAP_CLUSTER_ROLES idx */
		rc = nodemap_idx_cluster_roles_update(nodemap);

	nm_member_revoke_locks(nodemap);
put:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_rbac);

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
 * Update the squash_gid for a nodemap. The squash_gid is the gid
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
 * Update the squash_projid for a nodemap.
 *
 * \param	name		nodemap name
 * \param	gid		the new projid to squash unknown projids to
 * \retval	0 on success
 *
 * Update the squash_projid for a nodemap. The squash_projid is the projid
 * that the all client projids are mapped to if nodemap is active,
 * the trust_client_ids flag is not set, and the projid is not in
 * the idmap tree.
 */
int nodemap_set_squash_projid(const char *name, projid_t projid)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nm_squash_projid = projid;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_squash_projid);

/**
 * Check if nodemap allows setting quota.
 *
 * If nodemap is not active, always allow.
 * For user and group quota, allow if the nodemap allows root access.
 * For project quota, allow if project id is not squashed or deny_unknown
 * is not set.
 *
 * \param	nodemap		nodemap to check access for
 * \param	qc_type		quota type
 * \param	id		client id to map
 * \retval	true is setquota is allowed, false otherwise
 */
bool nodemap_can_setquota(struct lu_nodemap *nodemap, __u32 qc_type, __u32 id)
{
	if (!nodemap_active)
		return true;

	if (!nodemap || !nodemap->nmf_allow_root_access ||
	    !(nodemap->nmf_rbac & NODEMAP_RBAC_QUOTA_OPS))
		return false;

	if (qc_type == PRJQUOTA) {
		id = nodemap_map_id(nodemap, NODEMAP_PROJID,
				    NODEMAP_CLIENT_TO_FS, id);

		if (id == nodemap->nm_squash_projid &&
		    nodemap->nmf_deny_unknown)
			return false;
	}

	return true;
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
 * Set the nmf_readonly_mount flag to true or false.
 * \param	name			nodemap name
 * \param	readonly_mount		if true, forbid rw mount
 * \retval	0 on success
 *
 */
int nodemap_set_readonly_mount(const char *name, bool readonly_mount)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));

	nodemap->nmf_readonly_mount = readonly_mount;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_readonly_mount);

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

		range_delete(active_config, range);
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

	INIT_LIST_HEAD(&config->nmc_netmask_setup);
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
			range_delete(config, range);
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
	struct nodemap_config *new_config;
	struct lu_nodemap *nodemap;
	int rc = 0;

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
void nodemap_test_nid(struct lnet_nid *nid, char *name_buf, size_t name_len)
{
	struct lu_nodemap *nodemap;

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
int nodemap_test_id(struct lnet_nid *nid, enum nodemap_id_type idtype,
		    u32 client_id, u32 *fs_id)
{
	struct lu_nodemap *nodemap;

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

static int cfg_nodemap_cmd(enum lcfg_command_type cmd, const char *nodemap_name,
			   char *param, bool dynamic)
{
	struct lnet_nid nid[2];
	bool bool_switch;
	u8 netmask = 0;
	u32 idmap[2];
	u32 range_count;
	u32 int_id;
	int rc = 0;

	ENTRY;
	switch (cmd) {
	case LCFG_NODEMAP_ADD:
		rc = nodemap_add(nodemap_name);
		break;
	case LCFG_NODEMAP_DEL:
		rc = nodemap_del(nodemap_name);
		break;
	case LCFG_NODEMAP_ADD_RANGE:
		rc = nodemap_parse_range(param, nid, &netmask);
		if (rc != 0)
			break;
		rc = nodemap_add_range(nodemap_name, nid, netmask);
		break;
	case LCFG_NODEMAP_DEL_RANGE:
		rc = nodemap_parse_range(param, nid, &netmask);
		if (rc != 0)
			break;
		rc = nodemap_del_range(nodemap_name, nid, netmask);
		break;
	case LCFG_NODEMAP_ADMIN:
		rc = kstrtobool(param, &bool_switch);
		if (rc)
			break;
		rc = nodemap_set_allow_root(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_DENY_UNKNOWN:
		rc = kstrtobool(param, &bool_switch);
		if (rc)
			break;
		rc = nodemap_set_deny_unknown(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_AUDIT_MODE:
		rc = kstrtobool(param, &bool_switch);
		if (rc == 0)
			rc = nodemap_set_audit_mode(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_FORBID_ENCRYPT:
		rc = kstrtobool(param, &bool_switch);
		if (rc == 0)
			rc = nodemap_set_forbid_encryption(nodemap_name,
							   bool_switch);
		break;
	case LCFG_NODEMAP_READONLY_MOUNT:
		rc = kstrtobool(param, &bool_switch);
		if (rc == 0)
			rc = nodemap_set_readonly_mount(nodemap_name,
							bool_switch);
		break;
	case LCFG_NODEMAP_MAP_MODE:
	{
		char *p;
		__u8 map_mode = 0;

		if ((p = strstr(param, "all")) != NULL) {
			if ((p == param || *(p-1) == ',') &&
			    (*(p+3) == '\0' || *(p+3) == ',')) {
				map_mode = NODEMAP_MAP_ALL;
			} else {
				rc = -EINVAL;
				break;
			}
		} else {
			while ((p = strsep(&param, ",")) != NULL) {
				if (!*p)
					break;

				if (strcmp("both", p) == 0)
					map_mode |= NODEMAP_MAP_BOTH;
				else if (strcmp("uid_only", p) == 0 ||
					 strcmp("uid", p) == 0)
					map_mode |= NODEMAP_MAP_UID;
				else if (strcmp("gid_only", p) == 0 ||
					 strcmp("gid", p) == 0)
					map_mode |= NODEMAP_MAP_GID;
				else if (strcmp("projid_only", p) == 0 ||
					 strcmp("projid", p) == 0)
					map_mode |= NODEMAP_MAP_PROJID;
				else
					break;
			}
			if (p) {
				rc = -EINVAL;
				break;
			}
		}

		rc = nodemap_set_mapping_mode(nodemap_name, map_mode);
		break;
	}
	case LCFG_NODEMAP_RBAC:
	{
		enum nodemap_rbac_roles rbac;
		char *p;

		if (strcmp(param, "all") == 0) {
			rbac = NODEMAP_RBAC_ALL;
		} else if (strcmp(param, "none") == 0) {
			rbac = NODEMAP_RBAC_NONE;
		} else {
			rbac = NODEMAP_RBAC_NONE;
			while ((p = strsep(&param, ",")) != NULL) {
				int i;

				if (!*p)
					break;

				for (i = 0; i < ARRAY_SIZE(nodemap_rbac_names);
				     i++) {
					if (strcmp(p,
						 nodemap_rbac_names[i].nrn_name)
					    == 0) {
						rbac |=
						 nodemap_rbac_names[i].nrn_mode;
						break;
					}
				}
				if (i == ARRAY_SIZE(nodemap_rbac_names))
					break;
			}
			if (p) {
				rc = -EINVAL;
				break;
			}
		}

		rc = nodemap_set_rbac(nodemap_name, rbac);
		break;
	}
	case LCFG_NODEMAP_TRUSTED:
		rc = kstrtobool(param, &bool_switch);
		if (rc)
			break;
		rc = nodemap_set_trust_client_ids(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_SQUASH_UID:
		rc = kstrtouint(param, 10, &int_id);
		if (rc)
			break;
		rc = nodemap_set_squash_uid(nodemap_name, int_id);
		break;
	case LCFG_NODEMAP_SQUASH_GID:
		rc = kstrtouint(param, 10, &int_id);
		if (rc)
			break;
		rc = nodemap_set_squash_gid(nodemap_name, int_id);
		break;
	case LCFG_NODEMAP_SQUASH_PROJID:
		rc = kstrtouint(param, 10, &int_id);
		if (rc)
			break;
		rc = nodemap_set_squash_projid(nodemap_name, int_id);
		break;
	case LCFG_NODEMAP_ADD_UIDMAP:
	case LCFG_NODEMAP_ADD_GIDMAP:
	case LCFG_NODEMAP_ADD_PROJIDMAP:
		rc = nodemap_parse_idmap(nodemap_name, param, idmap, &range_count);
		if (rc != 0)
			break;
		if (cmd == LCFG_NODEMAP_ADD_UIDMAP)
			rc = nodemap_add_idmap_range(nodemap_name, NODEMAP_UID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_ADD_GIDMAP)
			rc = nodemap_add_idmap_range(nodemap_name, NODEMAP_GID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_ADD_PROJIDMAP)
			rc = nodemap_add_idmap_range(nodemap_name, NODEMAP_PROJID,
						     idmap, range_count);
		else
			rc = -EINVAL;
		break;
	case LCFG_NODEMAP_DEL_UIDMAP:
	case LCFG_NODEMAP_DEL_GIDMAP:
	case LCFG_NODEMAP_DEL_PROJIDMAP:
		rc = nodemap_parse_idmap(nodemap_name, param, idmap, &range_count);
		if (rc != 0)
			break;
		if (cmd == LCFG_NODEMAP_DEL_UIDMAP)
			rc = nodemap_del_idmap_range(nodemap_name, NODEMAP_UID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_DEL_GIDMAP)
			rc = nodemap_del_idmap_range(nodemap_name, NODEMAP_GID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_DEL_PROJIDMAP)
			rc = nodemap_del_idmap_range(nodemap_name, NODEMAP_PROJID,
						     idmap, range_count);
		else
			rc = -EINVAL;
		break;
	case LCFG_NODEMAP_SET_FILESET:
		rc = nodemap_set_fileset(nodemap_name, param);
		break;
	case LCFG_NODEMAP_SET_SEPOL:
		rc = nodemap_set_sepol(nodemap_name, param);
		break;
	default:
		rc = -EINVAL;
	}

	RETURN(rc);
}

int server_iocontrol_nodemap(struct obd_device *obd,
			     struct obd_ioctl_data *data, bool dynamic)
{
	char name_buf[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	struct lustre_cfg *lcfg = NULL;
	const char *nodemap_name = NULL;
	const char *client_idstr = NULL;
	const char *idtype_str = NULL;
	const char *nidstr = NULL;
	unsigned long client_id;
	struct lnet_nid	nid;
	char *param = NULL;
	char fs_idstr[16];
	__u32 fs_id, cmd;
	int idtype;
	int rc = 0;

	ENTRY;

	if (data->ioc_plen1 > PAGE_SIZE)
		GOTO(out, rc = -E2BIG);

	OBD_ALLOC(lcfg, data->ioc_plen1);
	if (lcfg == NULL)
		GOTO(out, rc = -ENOMEM);

	if (copy_from_user(lcfg, data->ioc_pbuf1, data->ioc_plen1))
		GOTO(out_lcfg, rc = -EFAULT);
	if (lustre_cfg_sanity_check(lcfg, data->ioc_plen1))
		GOTO(out_lcfg, rc = -EINVAL);

	cmd = lcfg->lcfg_command;

	switch (cmd) {
	case LCFG_NODEMAP_ACTIVATE:
		if (lcfg->lcfg_bufcount != 2)
			GOTO(out_lcfg, rc = -EINVAL);
		param = lustre_cfg_string(lcfg, 1);
		if (strcmp(param, "1") == 0)
			nodemap_activate(1);
		else
			nodemap_activate(0);
		break;
	case LCFG_NODEMAP_ADD:
	case LCFG_NODEMAP_DEL:
		if (lcfg->lcfg_bufcount != 2)
			GOTO(out_lcfg, rc = -EINVAL);
		nodemap_name = lustre_cfg_string(lcfg, 1);
		rc = cfg_nodemap_cmd(cmd, nodemap_name, param, dynamic);
		break;
	case LCFG_NODEMAP_TEST_NID:
		if (lcfg->lcfg_bufcount != 2)
			GOTO(out_lcfg, rc = -EINVAL);
		nidstr = lustre_cfg_string(lcfg, 1);
		rc = libcfs_strnid(&nid, nidstr);
		if (rc < 0)
			GOTO(out_lcfg, rc);

		nodemap_test_nid(&nid, name_buf, sizeof(name_buf));
		rc = copy_to_user(data->ioc_pbuf1, name_buf,
				  min_t(size_t, data->ioc_plen1,
					sizeof(name_buf)));
		if (rc != 0)
			GOTO(out_lcfg, rc = -EFAULT);
		break;
	case LCFG_NODEMAP_TEST_ID:
		if (lcfg->lcfg_bufcount != 4)
			GOTO(out_lcfg, rc = -EINVAL);
		nidstr = lustre_cfg_string(lcfg, 1);
		idtype_str = lustre_cfg_string(lcfg, 2);
		client_idstr = lustre_cfg_string(lcfg, 3);

		rc = libcfs_strnid(&nid, nidstr);
		if (rc < 0)
			GOTO(out_lcfg, rc);

		if (strcmp(idtype_str, "uid") == 0)
			idtype = NODEMAP_UID;
		else if (strcmp(idtype_str, "gid") == 0)
			idtype = NODEMAP_GID;
		else if (strcmp(idtype_str, "projid") == 0)
			idtype = NODEMAP_PROJID;
		else
			GOTO(out_lcfg, rc = -EINVAL);

		rc = kstrtoul(client_idstr, 10, &client_id);
		if (rc != 0)
			GOTO(out_lcfg, rc = -EINVAL);

		rc = nodemap_test_id(&nid, idtype, client_id, &fs_id);
		if (rc < 0)
			GOTO(out_lcfg, rc = -EINVAL);

		if (data->ioc_plen1 < sizeof(fs_idstr))
			GOTO(out_lcfg, rc = -EINVAL);

		snprintf(fs_idstr, sizeof(fs_idstr), "%u", fs_id);
		if (copy_to_user(data->ioc_pbuf1, fs_idstr,
				 sizeof(fs_idstr)) != 0)
			GOTO(out_lcfg, rc = -EINVAL);
		break;
	case LCFG_NODEMAP_ADD_RANGE:
	case LCFG_NODEMAP_DEL_RANGE:
	case LCFG_NODEMAP_ADD_UIDMAP:
	case LCFG_NODEMAP_DEL_UIDMAP:
	case LCFG_NODEMAP_ADD_GIDMAP:
	case LCFG_NODEMAP_DEL_GIDMAP:
	case LCFG_NODEMAP_ADD_PROJIDMAP:
	case LCFG_NODEMAP_DEL_PROJIDMAP:
	case LCFG_NODEMAP_SET_FILESET:
	case LCFG_NODEMAP_SET_SEPOL:
		if (lcfg->lcfg_bufcount != 3)
			GOTO(out_lcfg, rc = -EINVAL);
		nodemap_name = lustre_cfg_string(lcfg, 1);
		param = lustre_cfg_string(lcfg, 2);
		rc = cfg_nodemap_cmd(cmd, nodemap_name, param, dynamic);
		break;
	case LCFG_NODEMAP_ADMIN:
	case LCFG_NODEMAP_TRUSTED:
	case LCFG_NODEMAP_DENY_UNKNOWN:
	case LCFG_NODEMAP_SQUASH_UID:
	case LCFG_NODEMAP_SQUASH_GID:
	case LCFG_NODEMAP_SQUASH_PROJID:
	case LCFG_NODEMAP_MAP_MODE:
	case LCFG_NODEMAP_AUDIT_MODE:
	case LCFG_NODEMAP_FORBID_ENCRYPT:
	case LCFG_NODEMAP_READONLY_MOUNT:
	case LCFG_NODEMAP_RBAC:
		if (lcfg->lcfg_bufcount != 4)
			GOTO(out_lcfg, rc = -EINVAL);
		nodemap_name = lustre_cfg_string(lcfg, 1);
		param = lustre_cfg_string(lcfg, 3);
		rc = cfg_nodemap_cmd(cmd, nodemap_name, param, dynamic);
		break;
	default:
		rc = -ENOTTY;
	}

	if (rc) {
		CDEBUG_LIMIT(rc == -EEXIST ? D_INFO : D_ERROR,
			     "%s: OBD_IOC_NODEMAP command %X for %s: rc = %d\n",
			     obd->obd_name, lcfg->lcfg_command,
			     nodemap_name, rc);
		GOTO(out_lcfg, rc);
	}

out_lcfg:
	OBD_FREE(lcfg, data->ioc_plen1);
out:
	RETURN(rc);
}
EXPORT_SYMBOL(server_iocontrol_nodemap);
