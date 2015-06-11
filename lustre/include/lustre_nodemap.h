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
 * GPL HEADER END
 */
/*
 * Copyright (C) 2013, Trustees of Indiana University
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#ifndef _LUSTRE_NODEMAP_H
#define _LUSTRE_NODEMAP_H

#define LUSTRE_NODEMAP_NAME "nodemap"
#define LUSTRE_NODEMAP_NAME_LENGTH 16

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
				 nmf_allow_root_access:1,
				 nmf_block_lookups:1,
				 nmf_hmac_required:1,
				 nmf_encryption_required:1;
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
	rwlock_t		 nm_idmap_lock;
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

	/* used when unloading nodemaps */
	struct list_head	 nm_list;
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
int nodemap_set_squash_uid(const char *name, uid_t uid);
int nodemap_set_squash_gid(const char *name, gid_t gid);
bool nodemap_can_setquota(const struct lu_nodemap *nodemap);
int nodemap_add_idmap(const char *name, enum nodemap_id_type id_type,
		      const __u32 map[2]);
int nodemap_del_idmap(const char *name, enum nodemap_id_type id_type,
		      const __u32 map[2]);
__u32 nodemap_map_id(struct lu_nodemap *nodemap,
		     enum nodemap_id_type id_type,
		     enum nodemap_tree_type tree_type, __u32 id);
ssize_t nodemap_map_acl(struct lu_nodemap *nodemap, void *buf, size_t size,
			enum nodemap_tree_type tree_type);
void nodemap_test_nid(lnet_nid_t nid, char *name_buf, size_t name_len);
__u32 nodemap_test_id(lnet_nid_t nid, enum nodemap_id_type idtype,
		      __u32 client_id);
#endif	/* _LUSTRE_NODEMAP_H */
