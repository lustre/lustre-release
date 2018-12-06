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

#ifndef _LUSTRE_NODEMAP_H
#define _LUSTRE_NODEMAP_H

#include <uapi/linux/lustre/lustre_idl.h>

#define LUSTRE_NODEMAP_NAME "nodemap"

#define LUSTRE_NODEMAP_DEFAULT_ID 0

/** enums containing the types of ids contained in a nodemap
 * kept so other modules (mgs, mdt, etc) can define the type
 * of search easily
 */

enum nodemap_id_type {
	NODEMAP_UID,
	NODEMAP_GID,
};

enum nodemap_tree_type {
	NODEMAP_FS_TO_CLIENT,
	NODEMAP_CLIENT_TO_FS,
};

enum nodemap_mapping_modes {
	NODEMAP_MAP_BOTH,
	NODEMAP_MAP_UID_ONLY,
	NODEMAP_MAP_GID_ONLY,
};

struct nodemap_pde {
	char			 npe_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	struct proc_dir_entry	*npe_proc_entry;
	struct list_head	 npe_list_member;
};

/** The nodemap id 0 will be the default nodemap. It will have a configuration
 * set by the MGS, but no ranges will be allowed as all NIDs that do not map
 * will be added to the default nodemap
 */

struct lu_nodemap {
	/* human readable ID */
	char			 nm_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	/* flags to govern nodemap behavior */
	bool			 nmf_trust_client_ids:1,
				 nmf_deny_unknown:1,
				 nmf_allow_root_access:1,
				 nmf_map_uid_only:1,
				 nmf_map_gid_only:1,
				 nmf_enable_audit:1;
	/* unique ID set by MGS */
	unsigned int		 nm_id;
	/* nodemap ref counter */
	atomic_t		 nm_refcount;
	/* UID to squash unmapped UIDs */
	uid_t			 nm_squash_uid;
	/* GID to squash unmapped GIDs */
	gid_t			 nm_squash_gid;
	/* NID range list */
	struct list_head	 nm_ranges;
	/* lock for idmap red/black trees */
	struct rw_semaphore	 nm_idmap_lock;
	/* UID map keyed by local UID */
	struct rb_root		 nm_fs_to_client_uidmap;
	/* UID map keyed by remote UID */
	struct rb_root		 nm_client_to_fs_uidmap;
	/* GID map keyed by local UID */
	struct rb_root		 nm_fs_to_client_gidmap;
	/* GID map keyed by remote UID */
	struct rb_root		 nm_client_to_fs_gidmap;
	/* attached client members of this nodemap */
	struct mutex		 nm_member_list_lock;
	struct list_head	 nm_member_list;
	/* access by nodemap name */
	struct hlist_node	 nm_hash;
	struct nodemap_pde	*nm_pde_data;
	/* fileset the nodes of this nodemap are restricted to */
	char			 nm_fileset[PATH_MAX+1];
	/* information about the expected SELinux policy on the nodes */
	char			 nm_sepol[LUSTRE_NODEMAP_SEPOL_LENGTH + 1];

	/* used when loading/unloading nodemaps */
	struct list_head	 nm_list;
};

/* Store handles to local MGC storage to save config locally. In future
 * versions of nodemap, mgc will receive the config directly and so this might
 * not be needed.
 */
struct nm_config_file {
	struct local_oid_storage	*ncf_los;
	struct dt_object		*ncf_obj;
	struct list_head		 ncf_list;
};

void nodemap_activate(const bool value);
int nodemap_add(const char *nodemap_name);
int nodemap_del(const char *nodemap_name);
int nodemap_add_member(lnet_nid_t nid, struct obd_export *exp);
void nodemap_del_member(struct obd_export *exp);
int nodemap_parse_range(const char *range_string, lnet_nid_t range[2]);
int nodemap_parse_idmap(char *idmap_string, __u32 idmap[2]);
int nodemap_add_range(const char *name, const lnet_nid_t nid[2]);
int nodemap_del_range(const char *name, const lnet_nid_t nid[2]);
int nodemap_set_allow_root(const char *name, bool allow_root);
int nodemap_set_trust_client_ids(const char *name, bool trust_client_ids);
int nodemap_set_deny_unknown(const char *name, bool deny_unknown);
int nodemap_set_mapping_mode(const char *name, enum nodemap_mapping_modes mode);
int nodemap_set_squash_uid(const char *name, uid_t uid);
int nodemap_set_squash_gid(const char *name, gid_t gid);
int nodemap_set_audit_mode(const char *name, bool enable_audit);
bool nodemap_can_setquota(const struct lu_nodemap *nodemap);
int nodemap_add_idmap(const char *name, enum nodemap_id_type id_type,
		      const __u32 map[2]);
int nodemap_del_idmap(const char *name, enum nodemap_id_type id_type,
		      const __u32 map[2]);
int nodemap_set_fileset(const char *name, const char *fileset);
char *nodemap_get_fileset(const struct lu_nodemap *nodemap);
int nodemap_set_sepol(const char *name, const char *sepol);
const char *nodemap_get_sepol(const struct lu_nodemap *nodemap);
__u32 nodemap_map_id(struct lu_nodemap *nodemap,
		     enum nodemap_id_type id_type,
		     enum nodemap_tree_type tree_type, __u32 id);
ssize_t nodemap_map_acl(struct lu_nodemap *nodemap, void *buf, size_t size,
			enum nodemap_tree_type tree_type);
#ifdef HAVE_SERVER_SUPPORT
void nodemap_test_nid(lnet_nid_t nid, char *name_buf, size_t name_len);
#else
#define nodemap_test_nid(nid, name_buf, name_len) do {} while(0)
#endif
int nodemap_test_id(lnet_nid_t nid, enum nodemap_id_type idtype,
		    __u32 client_id, __u32 *fs_id);

struct nm_config_file *nm_config_file_register_mgs(const struct lu_env *env,
						   struct dt_object *obj,
						   struct local_oid_storage *los);
struct dt_device;
struct nm_config_file *nm_config_file_register_tgt(const struct lu_env *env,
						   struct dt_device *dev,
						   struct local_oid_storage *los);
void nm_config_file_deregister_mgs(const struct lu_env *env,
				   struct nm_config_file *ncf);
void nm_config_file_deregister_tgt(const struct lu_env *env,
				   struct nm_config_file *ncf);
struct lu_nodemap *nodemap_get_from_exp(struct obd_export *exp);
void nodemap_putref(struct lu_nodemap *nodemap);

#ifdef HAVE_SERVER_SUPPORT
struct nodemap_range_tree {
	struct interval_node *nmrt_range_interval_root;
	unsigned int nmrt_range_highest_id;
};

struct nodemap_config {
	/* Highest numerical lu_nodemap.nm_id defined */
	unsigned int nmc_nodemap_highest_id;

	/* Simple flag to determine if nodemaps are active */
	bool nmc_nodemap_is_active;

	/* Pointer to default nodemap as it is needed more often */
	struct lu_nodemap *nmc_default_nodemap;

	/**
	 * Lock required to access the range tree.
	 */
	struct rw_semaphore nmc_range_tree_lock;
	struct nodemap_range_tree nmc_range_tree;

	/**
	 * Hash keyed on nodemap name containing all
	 * nodemaps
	 */
	struct cfs_hash *nmc_nodemap_hash;
};

struct nodemap_config *nodemap_config_alloc(void);
void nodemap_config_dealloc(struct nodemap_config *config);
void nodemap_config_set_active_mgc(struct nodemap_config *config);

int nodemap_process_idx_pages(struct nodemap_config *config, union lu_page *lip,
			      struct lu_nodemap **recent_nodemap);

#else /* disable nodemap processing in MGC of non-servers */
static inline int nodemap_process_idx_pages(void *config,
					    union lu_page *lip,
					    struct lu_nodemap **recent_nodemap)
{ return 0; }
#endif /* HAVE_SERVER_SUPPORT */

int nodemap_get_config_req(struct obd_device *mgs_obd,
			   struct ptlrpc_request *req);
#endif	/* _LUSTRE_NODEMAP_H */
