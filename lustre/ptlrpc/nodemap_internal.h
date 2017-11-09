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
 * Copyright (c) 2013, 2014, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#ifndef _NODEMAP_INTERNAL_H
#define _NODEMAP_INTERNAL_H

#include <lustre_nodemap.h>
#include <interval_tree.h>

#define DEFAULT_NODEMAP "default"

/* Turn on proc debug interface to allow OSS and
 * MDS nodes to configure nodemap independently of
 * MGS (since the nodemap distribution is not written
 * yet */
#define NODEMAP_PROC_DEBUG 1

/* Default nobody uid and gid values */

#define NODEMAP_NOBODY_UID 99
#define NODEMAP_NOBODY_GID 99

struct lprocfs_static_vars;

/* nodemap root proc directory under fs/lustre */
extern struct proc_dir_entry *proc_lustre_nodemap_root;
/* flag if nodemap is active */
extern bool nodemap_active;

extern struct mutex active_config_lock;
extern struct nodemap_config *active_config;

struct lu_nid_range {
	/* unique id set by mgs */
	unsigned int		 rn_id;
	/* lu_nodemap containing this range */
	struct lu_nodemap	*rn_nodemap;
	/* list for nodemap */
	struct list_head	 rn_list;
	/* nid interval tree */
	struct interval_node	 rn_node;
};

struct lu_idmap {
	/* uid/gid of client */
	__u32		id_client;
	/* uid/gid on filesystem */
	__u32		id_fs;
	/* tree mapping client ids to filesystem ids */
	struct rb_node	id_client_to_fs;
	/* tree mappung filesystem to client */
	struct rb_node	id_fs_to_client;
};

/* first 4 bits of the nodemap_id is the index type */
struct nodemap_key {
	__u32 nk_nodemap_id;
	union {
		__u32 nk_range_id;
		__u32 nk_id_client;
		__u32 nk_unused;
	};
};

enum nodemap_idx_type {
	NODEMAP_EMPTY_IDX = 0,		/* index created with blank record */
	NODEMAP_CLUSTER_IDX = 1,	/* a nodemap cluster of nodes */
	NODEMAP_RANGE_IDX = 2,		/* nid range assigned to a nm cluster */
	NODEMAP_UIDMAP_IDX = 3,		/* uid map assigned to a nm cluster */
	NODEMAP_GIDMAP_IDX = 4,		/* gid map assigned to a nm cluster */
	NODEMAP_GLOBAL_IDX = 15,	/* stores nodemap activation status */
};

#define NM_TYPE_MASK 0x0FFFFFFF
#define NM_TYPE_SHIFT 28

static inline enum nodemap_idx_type nm_idx_get_type(unsigned int id)
{
	return id >> NM_TYPE_SHIFT;
}

static inline __u32 nm_idx_set_type(unsigned int id, enum nodemap_idx_type t)
{
	return (id & NM_TYPE_MASK) | (t << NM_TYPE_SHIFT);
}

void nodemap_config_set_active(struct nodemap_config *config);
struct lu_nodemap *nodemap_create(const char *name,
				  struct nodemap_config *config,
				  bool is_default);
void nodemap_putref(struct lu_nodemap *nodemap);
struct lu_nodemap *nodemap_lookup(const char *name);

int nodemap_procfs_init(void);
void nodemap_procfs_exit(void);
int lprocfs_nodemap_register(struct lu_nodemap *nodemap,
			     bool is_default_nodemap);
void lprocfs_nodemap_remove(struct nodemap_pde *nodemap_pde);
struct lu_nid_range *nodemap_range_find(lnet_nid_t start_nid,
					lnet_nid_t end_nid);
struct lu_nid_range *range_create(struct nodemap_range_tree *nm_range_tree,
				  lnet_nid_t start_nid, lnet_nid_t end_nid,
				  struct lu_nodemap *nodemap,
				  unsigned int range_id);
void range_destroy(struct lu_nid_range *range);
int range_insert(struct nodemap_range_tree *nm_range_tree,
		 struct lu_nid_range *data);
void range_delete(struct nodemap_range_tree *nm_range_tree,
		  struct lu_nid_range *data);
struct lu_nid_range *range_search(struct nodemap_range_tree *nm_range_tree,
				  lnet_nid_t nid);
struct lu_nid_range *range_find(struct nodemap_range_tree *nm_range_tree,
				lnet_nid_t start_nid, lnet_nid_t end_nid);
int range_parse_nidstring(char *range_string, lnet_nid_t *start_nid,
			  lnet_nid_t *end_nid);
void range_init_tree(void);
struct lu_idmap *idmap_create(__u32 client_id, __u32 fs_id);
struct lu_idmap *idmap_insert(enum nodemap_id_type id_type,
			      struct lu_idmap *idmap,
			      struct lu_nodemap *nodemap);
void idmap_delete(enum nodemap_id_type id_type,  struct lu_idmap *idmap,
		  struct lu_nodemap *nodemap);
void idmap_delete_tree(struct lu_nodemap *nodemap);
struct lu_idmap *idmap_search(struct lu_nodemap *nodemap,
			      enum nodemap_tree_type,
			      enum nodemap_id_type id_type,
			      __u32 id);
int nm_member_add(struct lu_nodemap *nodemap, struct obd_export *exp);
void nm_member_del(struct lu_nodemap *nodemap, struct obd_export *exp);
void nm_member_delete_list(struct lu_nodemap *nodemap);
struct lu_nodemap *nodemap_classify_nid(lnet_nid_t nid);
void nm_member_reclassify_nodemap(struct lu_nodemap *nodemap);
void nm_member_revoke_locks(struct lu_nodemap *nodemap);
void nm_member_revoke_locks_always(struct lu_nodemap *nodemap);
void nm_member_revoke_all(void);

int nodemap_add_idmap_helper(struct lu_nodemap *nodemap,
			     enum nodemap_id_type id_type,
			     const __u32 map[2]);
int nodemap_add_range_helper(struct nodemap_config *config,
			     struct lu_nodemap *nodemap,
			     const lnet_nid_t nid[2],
			     unsigned int range_id);

struct rb_node *nm_rb_next_postorder(const struct rb_node *node);
struct rb_node *nm_rb_first_postorder(const struct rb_root *root);
void nodemap_getref(struct lu_nodemap *nodemap);
void nodemap_putref(struct lu_nodemap *nodemap);
int nm_hash_list_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
		    struct hlist_node *hnode,
		    void *nodemap_list_head);

#define nm_rbtree_postorder_for_each_entry_safe(pos, n,			\
						root, field)		\
	for (pos = nm_rb_first_postorder(root) ?			\
		rb_entry(nm_rb_first_postorder(root), typeof(*pos),	\
		field) : NULL,						\
		n = (pos && nm_rb_next_postorder(&pos->field)) ?	\
		rb_entry(nm_rb_next_postorder(&pos->field),		\
		typeof(*pos), field) : NULL;				\
		pos != NULL;						\
		pos = n,						\
		n = (pos && nm_rb_next_postorder(&pos->field)) ?	\
		rb_entry(nm_rb_next_postorder(&pos->field),		\
		typeof(*pos), field) : NULL)

int nodemap_idx_nodemap_add(const struct lu_nodemap *nodemap);
int nodemap_idx_nodemap_update(const struct lu_nodemap *nodemap);
int nodemap_idx_nodemap_del(const struct lu_nodemap *nodemap);
int nodemap_idx_idmap_add(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const __u32 map[2]);
int nodemap_idx_idmap_del(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const __u32 map[2]);
int nodemap_idx_range_add(const struct lu_nid_range *range,
			  const lnet_nid_t nid[2]);
int nodemap_idx_range_del(const struct lu_nid_range *range);
int nodemap_idx_nodemap_activate(bool value);
#endif  /* _NODEMAP_INTERNAL_H */
