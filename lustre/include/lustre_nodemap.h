/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Copyright (c) 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#ifndef _LUSTRE_NODEMAP_H
#define _LUSTRE_NODEMAP_H

#include <uapi/linux/lustre/lustre_disk.h>
#include <uapi/linux/lustre/lustre_ioctl.h>

#define LUSTRE_NODEMAP_NAME "nodemap"

#define LUSTRE_NODEMAP_DEFAULT_ID 0

static const struct nodemap_rbac_name {
	enum nodemap_rbac_roles nrn_mode;
	const char	       *nrn_name;
} nodemap_rbac_names[] = {
	{ NODEMAP_RBAC_FILE_PERMS,	"file_perms"	},
	{ NODEMAP_RBAC_DNE_OPS,		"dne_ops"	},
	{ NODEMAP_RBAC_QUOTA_OPS,	"quota_ops"	},
	{ NODEMAP_RBAC_BYFID_OPS,	"byfid_ops"	},
	{ NODEMAP_RBAC_CHLG_OPS,	"chlg_ops"	},
	{ NODEMAP_RBAC_FSCRYPT_ADMIN,   "fscrypt_admin"	},
	{ NODEMAP_RBAC_SERVER_UPCALL,	"server_upcall"	},
	{ NODEMAP_RBAC_IGN_ROOT_PRJQUOTA,	"ignore_root_prjquota"	},
	{ NODEMAP_RBAC_HSM_OPS,		"hsm_ops"	},
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
				 nmf_enable_audit:1,
				 nmf_forbid_encryption:1,
				 nmf_readonly_mount:1;
	/* bitmap for mapping type */
	enum nodemap_mapping_modes nmf_map_mode;
	/* bitmap for rbac, enum nodemap_rbac_roles */
	enum nodemap_rbac_roles	 nmf_rbac;
	/* unique ID set by MGS */
	unsigned int		 nm_id;
	/* nodemap ref counter */
	atomic_t		 nm_refcount;
	/* UID to squash unmapped UIDs */
	uid_t			 nm_squash_uid;
	/* GID to squash unmapped GIDs */
	gid_t			 nm_squash_gid;
	/* PROJID to squash unmapped PROJIDs */
	projid_t		 nm_squash_projid;
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
	/* PROJID map keyed by local UID */
	struct rb_root		 nm_fs_to_client_projidmap;
	/* PROJID map keyed by remote UID */
	struct rb_root		 nm_client_to_fs_projidmap;
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
	/* is a dynamic nodemap */
	bool			 nm_dyn;
	/* value to start UID offset */
	unsigned int		 nm_offset_start_uid;
	/* number of values allocated to UID offset */
	unsigned int		 nm_offset_limit_uid;
	/* value to start GID offset */
	unsigned int		 nm_offset_start_gid;
	/* number of values allocated to GID offset */
	unsigned int		 nm_offset_limit_gid;
	/* value to start PROJID offset */
	unsigned int		 nm_offset_start_projid;
	/* number of values allocated to PROJID offset */
	unsigned int		 nm_offset_limit_projid;
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
int nodemap_add(const char *nodemap_name, bool dynamic);
int nodemap_del(const char *nodemap_name);
int nodemap_add_member(struct lnet_nid *nid, struct obd_export *exp);
void nodemap_del_member(struct obd_export *exp);
int nodemap_parse_range(const char *range_string, struct lnet_nid range[2],
			u8 *netmask);
int nodemap_parse_idmap(const char *nodemap_name, char *idmap_str,
			__u32 idmap[2], u32 *range_count);
int nodemap_add_range(const char *name, const struct lnet_nid nid[2],
		      u8 netmask);
int nodemap_del_range(const char *name, const struct lnet_nid nid[2],
		      u8 netmask);
int nodemap_set_allow_root(const char *name, bool allow_root);
int nodemap_set_trust_client_ids(const char *name, bool trust_client_ids);
int nodemap_set_deny_unknown(const char *name, bool deny_unknown);
int nodemap_set_mapping_mode(const char *name,
			     enum nodemap_mapping_modes map_mode);
int nodemap_set_rbac(const char *name, enum nodemap_rbac_roles rbac);
int nodemap_add_offset(const char *nodemap_name, char *offset);
int nodemap_del_offset(const char *nodemap_name);
int nodemap_set_squash_uid(const char *name, uid_t uid);
int nodemap_set_squash_gid(const char *name, gid_t gid);
int nodemap_set_squash_projid(const char *name, projid_t projid);
int nodemap_set_audit_mode(const char *name, bool enable_audit);
int nodemap_set_forbid_encryption(const char *name, bool forbid_encryption);
int nodemap_set_readonly_mount(const char *name, bool readonly_mount);
bool nodemap_can_setquota(struct lu_nodemap *nodemap, __u32 qc_type, __u32 id);
int nodemap_add_idmap(const char *nodemap_name, enum nodemap_id_type id_type,
		      const __u32 map[2]);
int nodemap_del_idmap(const char *nodemap_name, enum nodemap_id_type id_type,
		      const __u32 map[2]);
int nodemap_set_fileset(const char *name, const char *fileset, bool checkperm);
char *nodemap_get_fileset(const struct lu_nodemap *nodemap);
int nodemap_set_sepol(const char *name, const char *sepol, bool checkperm);
const char *nodemap_get_sepol(const struct lu_nodemap *nodemap);
__u32 nodemap_map_id(struct lu_nodemap *nodemap,
		     enum nodemap_id_type id_type,
		     enum nodemap_tree_type tree_type, __u32 id);
ssize_t nodemap_map_acl(struct lu_nodemap *nodemap, void *buf, size_t size,
			enum nodemap_tree_type tree_type);
#ifdef HAVE_SERVER_SUPPORT
void nodemap_test_nid(struct lnet_nid *nid, char *name_buf, size_t name_len);
#else
#define nodemap_test_nid(nid, name_buf, name_len) do {} while (0)
#endif
int nodemap_test_id(struct lnet_nid *nid, enum nodemap_id_type idtype,
		    u32 client_id, u32 *fs_id);

int server_iocontrol_nodemap(struct obd_device *obd,
			     struct obd_ioctl_data *data, bool dynamic);


struct nm_config_file *nm_config_file_register_mgs(const struct lu_env *env,
						   struct dt_object *obj,
						   struct local_oid_storage *l);
struct dt_device;
struct nm_config_file *nm_config_file_register_tgt(const struct lu_env *env,
						   struct dt_device *dev,
						   struct local_oid_storage *l);
void nm_config_file_deregister_mgs(const struct lu_env *env,
				   struct nm_config_file *ncf);
void nm_config_file_deregister_tgt(const struct lu_env *env,
				   struct nm_config_file *ncf);
struct lu_nodemap *nodemap_get_from_exp(struct obd_export *exp);
void nodemap_putref(struct lu_nodemap *nodemap);

#ifdef HAVE_SERVER_SUPPORT

struct nodemap_range_tree {
	struct interval_tree_root nmrt_range_interval_root;
	unsigned int nmrt_range_highest_id;
};

struct nodemap_config {
	/* Highest numerical lu_nodemap.nm_id defined */
	unsigned int nmc_nodemap_highest_id;

	/* Simple flag to determine if nodemaps are active */
	bool nmc_nodemap_is_active;

	/* Pointer to default nodemap as it is needed more often */
	struct lu_nodemap *nmc_default_nodemap;

	/* list of netmask + address prefix */
	struct list_head nmc_netmask_setup;

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
void nodemap_config_set_loading_mgc(bool loading);
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
