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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/md_object.h
 *
 * Extention of lu_object.h for metadata objects
 */

#ifndef _LUSTRE_MD_OBJECT_H
#define _LUSTRE_MD_OBJECT_H

#ifndef HAVE_SERVER_SUPPORT
# error "client code should not depend on md_object.h"
#endif /* !HAVE_SERVER_SUPPORT */

/** \defgroup md md
 * Sub-class of lu_object with methods common for "meta-data" objects in MDT
 * stack.
 *
 * Meta-data objects implement namespace operations: you can link, unlink
 * them, and treat them as directories.
 *
 * Examples: mdt, cmm, and mdt are implementations of md interface.
 * @{
 */


/*
 * super-class definitions.
 */
#include <dt_object.h>

struct md_device;
struct md_device_operations;
struct md_object;
struct obd_export;

/** metadata attributes */
enum ma_valid {
	MA_INODE     = 1 << 0,
	MA_LOV       = 1 << 1,
	MA_FLAGS     = 1 << 2,
	MA_LMV       = 1 << 3,
	MA_ACL_DEF   = 1 << 4,
	MA_LOV_DEF   = 1 << 5,
	MA_HSM       = 1 << 6,
	MA_PFID      = 1 << 7,
	MA_LMV_DEF   = 1 << 8,
	MA_SOM	     = 1 << 9,
};

typedef enum {
        MDL_MINMODE  = 0,
        MDL_EX       = 1,
        MDL_PW       = 2,
        MDL_PR       = 4,
        MDL_CW       = 8,
        MDL_CR       = 16,
        MDL_NL       = 32,
        MDL_GROUP    = 64,
        MDL_MAXMODE
} mdl_mode_t;

typedef enum {
        MDT_NUL_LOCK = 0,
        MDT_REG_LOCK = (1 << 0),
        MDT_PDO_LOCK = (1 << 1)
} mdl_type_t;

/* lfs rgetfacl permission check */
#define MAY_RGETFACL    (1 << 14)

/* memory structure for hsm attributes
 * for fields description see the on disk structure hsm_attrs
 * which is defined in lustre_idl.h
 */
struct md_hsm {
	__u32	mh_compat;
	__u32	mh_flags;
	__u64	mh_arch_id;
	__u64	mh_arch_ver;
};


/* memory structure for SOM attributes
 * for fields description see the on disk structure som_attrs
 * which is defined in lustre_idl.h
 */
struct md_som {
	__u16	ms_valid;
	__u64	ms_size;
	__u64	ms_blocks;
};

struct md_attr {
	__u64			 ma_valid;
	__u64			 ma_need;
	__u64			 ma_attr_flags;
	struct lu_attr		 ma_attr;
	struct lu_fid		 ma_pfid;
	struct md_hsm		 ma_hsm;
	struct md_som		 ma_som;
	struct lov_mds_md	*ma_lmm;
	union lmv_mds_md	*ma_lmv;
	void			*ma_acl;
	int			 ma_lmm_size;
	int			 ma_lmv_size;
	int			 ma_acl_size;
	int			 ma_enable_chprojid_gid;
};

/** Additional parameters for create */
struct md_op_spec {
	union {
		/** symlink target */
		const char *sp_symname;
		/** eadata for regular files */
		struct md_spec_reg {
			void *eadata;
			int  eadatalen;
		} sp_ea;
	} u;

	/** Open flags from client: such as MDS_OPEN_CREAT, and others. */
	__u64      sp_cr_flags;

	/* File security context for creates. */
	const char	*sp_cr_file_secctx_name; /* (security) xattr name */
	void		*sp_cr_file_secctx; /* xattr value */
	size_t		 sp_cr_file_secctx_size; /* xattr value size */

	/** don't create lov objects or llog cookie - this replay */
	unsigned int no_create:1,
		     sp_cr_lookup:1, /* do lookup sanity check or not. */
		     sp_rm_entry:1,  /* only remove name entry */
		     sp_permitted:1, /* do not check permission */
		     sp_migrate_close:1; /* close the file during migrate */
	/** Current lock mode for parent dir where create is performing. */
	mdl_mode_t sp_cr_mode;

	/** to create directory */
	const struct dt_index_features *sp_feat;
};

enum md_layout_opc {
	MD_LAYOUT_NOP	= 0,
	MD_LAYOUT_WRITE,	/* FLR: write the file */
	MD_LAYOUT_RESYNC,	/* FLR: resync starts */
	MD_LAYOUT_RESYNC_DONE,	/* FLR: resync done */
};

/**
 * Parameters for layout change API.
 */
struct md_layout_change {
	enum md_layout_opc	 mlc_opc;
	__u16			 mlc_mirror_id;
	struct layout_intent	*mlc_intent;
	struct lu_buf		 mlc_buf;
	struct lustre_som_attrs	 mlc_som;
	size_t			 mlc_resync_count;
	__u32			*mlc_resync_ids;
};

union ldlm_policy_data;
/**
 * Operations implemented for each md object (both directory and leaf).
 */
struct md_object_operations {
	int (*moo_permission)(const struct lu_env *env,
			      struct md_object *pobj, struct md_object *cobj,
			      struct md_attr *attr, int mask);

	int (*moo_attr_get)(const struct lu_env *env, struct md_object *obj,
			    struct md_attr *attr);

	int (*moo_attr_set)(const struct lu_env *env, struct md_object *obj,
			    const struct md_attr *attr);

	int (*moo_xattr_get)(const struct lu_env *env, struct md_object *obj,
			     struct lu_buf *buf, const char *name);

	int (*moo_xattr_list)(const struct lu_env *env, struct md_object *obj,
			      struct lu_buf *buf);

	int (*moo_xattr_set)(const struct lu_env *env, struct md_object *obj,
			     const struct lu_buf *buf, const char *name,
			     int fl);

	int (*moo_xattr_del)(const struct lu_env *env, struct md_object *obj,
			     const char *name);

	/** This method is used to swap the layouts between 2 objects */
	int (*moo_swap_layouts)(const struct lu_env *env,
			       struct md_object *obj1, struct md_object *obj2,
			       __u64 flags);

	/** \retval number of bytes actually read upon success */
	int (*moo_readpage)(const struct lu_env *env, struct md_object *obj,
			    const struct lu_rdpg *rdpg);

	int (*moo_readlink)(const struct lu_env *env, struct md_object *obj,
			    struct lu_buf *buf);

	int (*moo_changelog)(const struct lu_env *env,
			     enum changelog_rec_type type,
			     enum changelog_rec_flags clf_flags,
			     struct md_device *m, const struct lu_fid *fid);

	int (*moo_open)(const struct lu_env *env,
			struct md_object *obj, u64 open_flags);

	int (*moo_close)(const struct lu_env *env, struct md_object *obj,
			 struct md_attr *ma, u64 open_flags);

	int (*moo_object_sync)(const struct lu_env *, struct md_object *);

	int (*moo_object_lock)(const struct lu_env *env, struct md_object *obj,
			       struct lustre_handle *lh,
			       struct ldlm_enqueue_info *einfo,
			       union ldlm_policy_data *policy);
	int (*moo_object_unlock)(const struct lu_env *env,
				 struct md_object *obj,
				 struct ldlm_enqueue_info *einfo,
				 union ldlm_policy_data *policy);

	int (*moo_invalidate)(const struct lu_env *env, struct md_object *obj);
	/**
	 * Trying to write to un-instantiated layout component.
	 *
	 * The caller should have held layout lock.
	 *
	 * This API can be extended to support every other layout changing
	 * operations, such as component {add,del,change}, layout swap,
	 * layout merge, etc. One of the benefits by doing this is that the MDT
	 * no longer needs to understand layout.
	 *
	 * However, layout creation, removal, and fetch should still use
	 * xattr_{get,set}() because they don't interpret layout on the
	 * MDT layer.
	 *
	 * \param[in] env	execution environment
	 * \param[in] obj	MD object
	 * \param[in] layout	data structure to describe the changes to
	 *			the MD object's layout
	 *
	 * \retval 0		success
	 * \retval -ne		error code
	 */
	int (*moo_layout_change)(const struct lu_env *env,
				 struct md_object *obj,
				 struct md_layout_change *layout);
};

/**
 * Operations implemented for each directory object.
 */
struct md_dir_operations {
	int (*mdo_is_subdir)(const struct lu_env *env, struct md_object *obj,
			     const struct lu_fid *fid);

	int (*mdo_lookup)(const struct lu_env *env, struct md_object *obj,
			  const struct lu_name *lname, struct lu_fid *fid,
			  struct md_op_spec *spec);

	mdl_mode_t (*mdo_lock_mode)(const struct lu_env *env,
				    struct md_object *obj,
				    mdl_mode_t mode);

	int (*mdo_create)(const struct lu_env *env, struct md_object *pobj,
			  const struct lu_name *lname, struct md_object *child,
			  struct md_op_spec *spec,
			  struct md_attr *ma);

	/** This method is used for creating data object for this meta object*/
	int (*mdo_create_data)(const struct lu_env *env, struct md_object *p,
			       struct md_object *o,
			       const struct md_op_spec *spec,
			       struct md_attr *ma);

	int (*mdo_rename)(const struct lu_env *env, struct md_object *spobj,
			  struct md_object *tpobj, const struct lu_fid *lf,
			  const struct lu_name *lsname, struct md_object *tobj,
			  const struct lu_name *ltname, struct md_attr *ma);

	int (*mdo_link)(const struct lu_env *env, struct md_object *tgt_obj,
			struct md_object *src_obj, const struct lu_name *lname,
			struct md_attr *ma);

	int (*mdo_unlink)(const struct lu_env *env, struct md_object *pobj,
			  struct md_object *cobj, const struct lu_name *lname,
			  struct md_attr *ma, int no_name);

	int (*mdo_migrate)(const struct lu_env *env, struct md_object *pobj,
			   struct md_object *sobj, const struct lu_name *lname,
			   struct md_object *tobj, struct md_op_spec *spec,
			   struct md_attr *ma);
};

struct md_device_operations {
        /** meta-data device related handlers. */
	int (*mdo_root_get)(const struct lu_env *env, struct md_device *m,
			    struct lu_fid *f);

	const struct dt_device_param *(*mdo_dtconf_get)(const struct lu_env *e,
							struct md_device *m);

        int (*mdo_statfs)(const struct lu_env *env, struct md_device *m,
                          struct obd_statfs *sfs);

        int (*mdo_llog_ctxt_get)(const struct lu_env *env,
                                 struct md_device *m, int idx, void **h);

        int (*mdo_iocontrol)(const struct lu_env *env, struct md_device *m,
                             unsigned int cmd, int len, void *data);
};

struct md_device {
        struct lu_device                   md_lu_dev;
        const struct md_device_operations *md_ops;
};

struct md_object {
        struct lu_object                   mo_lu;
        const struct md_object_operations *mo_ops;
        const struct md_dir_operations    *mo_dir_ops;
};

static inline struct md_device *lu2md_dev(const struct lu_device *d)
{
        LASSERT(IS_ERR(d) || lu_device_is_md(d));
        return container_of0(d, struct md_device, md_lu_dev);
}

static inline struct lu_device *md2lu_dev(struct md_device *d)
{
        return &d->md_lu_dev;
}

static inline struct md_object *lu2md(const struct lu_object *o)
{
        LASSERT(o == NULL || IS_ERR(o) || lu_device_is_md(o->lo_dev));
        return container_of0(o, struct md_object, mo_lu);
}

static inline int md_device_init(struct md_device *md, struct lu_device_type *t)
{
        return lu_device_init(&md->md_lu_dev, t);
}

static inline void md_device_fini(struct md_device *md)
{
        lu_device_fini(&md->md_lu_dev);
}

static inline struct md_object *md_object_find_slice(const struct lu_env *env,
                                                     struct md_device *md,
                                                     const struct lu_fid *f)
{
        return lu2md(lu_object_find_slice(env, md2lu_dev(md), f, NULL));
}


/** md operations */
static inline int mo_permission(const struct lu_env *env, struct md_object *p,
				struct md_object *c, struct md_attr *at,
				int mask)
{
	LASSERT(c->mo_ops->moo_permission);
	return c->mo_ops->moo_permission(env, p, c, at, mask);
}

static inline int mo_attr_get(const struct lu_env *env, struct md_object *m,
			      struct md_attr *at)
{
	LASSERT(m->mo_ops->moo_attr_get);
	return m->mo_ops->moo_attr_get(env, m, at);
}

static inline int mo_readlink(const struct lu_env *env,
                              struct md_object *m,
                              struct lu_buf *buf)
{
        LASSERT(m->mo_ops->moo_readlink);
        return m->mo_ops->moo_readlink(env, m, buf);
}

static inline int mo_changelog(const struct lu_env *env,
			       enum changelog_rec_type type,
			       enum changelog_rec_flags clf_flags,
			       struct md_device *m, const struct lu_fid *fid)
{
	struct lu_fid rootfid;
	struct md_object *root;
	int rc;

	rc = m->md_ops->mdo_root_get(env, m, &rootfid);
	if (rc)
		return rc;

	root = md_object_find_slice(env, m, &rootfid);
	if (IS_ERR(root))
		RETURN(PTR_ERR(root));

	LASSERT(root->mo_ops->moo_changelog);
	rc = root->mo_ops->moo_changelog(env, type, clf_flags, m, fid);

	lu_object_put(env, &root->mo_lu);

	return rc;
}

static inline int mo_attr_set(const struct lu_env *env,
                              struct md_object *m,
                              const struct md_attr *at)
{
        LASSERT(m->mo_ops->moo_attr_set);
        return m->mo_ops->moo_attr_set(env, m, at);
}

static inline int mo_xattr_get(const struct lu_env *env,
                               struct md_object *m,
                               struct lu_buf *buf,
                               const char *name)
{
        LASSERT(m->mo_ops->moo_xattr_get);
        return m->mo_ops->moo_xattr_get(env, m, buf, name);
}

static inline int mo_xattr_del(const struct lu_env *env,
                               struct md_object *m,
                               const char *name)
{
        LASSERT(m->mo_ops->moo_xattr_del);
        return m->mo_ops->moo_xattr_del(env, m, name);
}

static inline int mo_xattr_set(const struct lu_env *env,
                               struct md_object *m,
                               const struct lu_buf *buf,
                               const char *name,
                               int flags)
{
        LASSERT(m->mo_ops->moo_xattr_set);
        return m->mo_ops->moo_xattr_set(env, m, buf, name, flags);
}

static inline int mo_xattr_list(const struct lu_env *env,
                                struct md_object *m,
                                struct lu_buf *buf)
{
        LASSERT(m->mo_ops->moo_xattr_list);
        return m->mo_ops->moo_xattr_list(env, m, buf);
}

static inline int mo_invalidate(const struct lu_env *env, struct md_object *m)
{
	LASSERT(m->mo_ops->moo_invalidate);
	return m->mo_ops->moo_invalidate(env, m);
}

static inline int mo_layout_change(const struct lu_env *env,
				   struct md_object *m,
				   struct md_layout_change *layout)
{
	/* need instantiate objects which in the access range */
	LASSERT(m->mo_ops->moo_layout_change);
	return m->mo_ops->moo_layout_change(env, m, layout);
}

static inline int mo_swap_layouts(const struct lu_env *env,
				  struct md_object *o1,
				  struct md_object *o2, __u64 flags)
{
	LASSERT(o1->mo_ops->moo_swap_layouts);
	LASSERT(o2->mo_ops->moo_swap_layouts);
	if (o1->mo_ops->moo_swap_layouts != o2->mo_ops->moo_swap_layouts)
		return -EPERM;
	return o1->mo_ops->moo_swap_layouts(env, o1, o2, flags);
}

static inline int mo_open(const struct lu_env *env, struct md_object *m,
			  u64 open_flags)
{
	LASSERT(m->mo_ops->moo_open);
	return m->mo_ops->moo_open(env, m, open_flags);
}

static inline int mo_close(const struct lu_env *env, struct md_object *m,
			   struct md_attr *ma, u64 open_flags)
{
	LASSERT(m->mo_ops->moo_close);
	return m->mo_ops->moo_close(env, m, ma, open_flags);
}

static inline int mo_readpage(const struct lu_env *env,
                              struct md_object *m,
                              const struct lu_rdpg *rdpg)
{
        LASSERT(m->mo_ops->moo_readpage);
        return m->mo_ops->moo_readpage(env, m, rdpg);
}

static inline int mo_object_sync(const struct lu_env *env, struct md_object *m)
{
        LASSERT(m->mo_ops->moo_object_sync);
        return m->mo_ops->moo_object_sync(env, m);
}

static inline int mo_object_lock(const struct lu_env *env,
				 struct md_object *m,
				 struct lustre_handle *lh,
				 struct ldlm_enqueue_info *einfo,
				 union ldlm_policy_data *policy)
{
	LASSERT(m->mo_ops->moo_object_lock);
	return m->mo_ops->moo_object_lock(env, m, lh, einfo, policy);
}

static inline int mo_object_unlock(const struct lu_env *env,
				   struct md_object *m,
				   struct ldlm_enqueue_info *einfo,
				   union ldlm_policy_data *policy)
{
	LASSERT(m->mo_ops->moo_object_unlock);
	return m->mo_ops->moo_object_unlock(env, m, einfo, policy);
}

static inline int mdo_lookup(const struct lu_env *env,
                             struct md_object *p,
                             const struct lu_name *lname,
                             struct lu_fid *f,
                             struct md_op_spec *spec)
{
        LASSERT(p->mo_dir_ops->mdo_lookup);
        return p->mo_dir_ops->mdo_lookup(env, p, lname, f, spec);
}

static inline mdl_mode_t mdo_lock_mode(const struct lu_env *env,
                                       struct md_object *mo,
                                       mdl_mode_t lm)
{
        if (mo->mo_dir_ops->mdo_lock_mode == NULL)
                return MDL_MINMODE;
        return mo->mo_dir_ops->mdo_lock_mode(env, mo, lm);
}

static inline int mdo_create(const struct lu_env *env,
                             struct md_object *p,
                             const struct lu_name *lchild_name,
                             struct md_object *c,
                             struct md_op_spec *spc,
                             struct md_attr *at)
{
	LASSERT(p->mo_dir_ops->mdo_create);
	return p->mo_dir_ops->mdo_create(env, p, lchild_name, c, spc, at);
}

static inline int mdo_create_data(const struct lu_env *env,
                                  struct md_object *p,
                                  struct md_object *c,
                                  const struct md_op_spec *spec,
                                  struct md_attr *ma)
{
        LASSERT(c->mo_dir_ops->mdo_create_data);
        return c->mo_dir_ops->mdo_create_data(env, p, c, spec, ma);
}

static inline int mdo_rename(const struct lu_env *env,
                             struct md_object *sp,
                             struct md_object *tp,
                             const struct lu_fid *lf,
                             const struct lu_name *lsname,
                             struct md_object *t,
                             const struct lu_name *ltname,
                             struct md_attr *ma)
{
        LASSERT(tp->mo_dir_ops->mdo_rename);
        return tp->mo_dir_ops->mdo_rename(env, sp, tp, lf, lsname, t, ltname,
                                          ma);
}

static inline int mdo_migrate(const struct lu_env *env,
			     struct md_object *pobj,
			     struct md_object *sobj,
			     const struct lu_name *lname,
			     struct md_object *tobj,
			     struct md_op_spec *spec,
			     struct md_attr *ma)
{
	LASSERT(pobj->mo_dir_ops->mdo_migrate);
	return pobj->mo_dir_ops->mdo_migrate(env, pobj, sobj, lname, tobj, spec,
					     ma);
}

static inline int mdo_is_subdir(const struct lu_env *env,
				struct md_object *mo,
				const struct lu_fid *fid)
{
	LASSERT(mo->mo_dir_ops->mdo_is_subdir);
	return mo->mo_dir_ops->mdo_is_subdir(env, mo, fid);
}

static inline int mdo_link(const struct lu_env *env,
                           struct md_object *p,
                           struct md_object *s,
                           const struct lu_name *lname,
                           struct md_attr *ma)
{
        LASSERT(s->mo_dir_ops->mdo_link);
        return s->mo_dir_ops->mdo_link(env, p, s, lname, ma);
}

static inline int mdo_unlink(const struct lu_env *env,
			     struct md_object *p,
			     struct md_object *c,
			     const struct lu_name *lname,
			     struct md_attr *ma, int no_name)
{
	LASSERT(p->mo_dir_ops->mdo_unlink);
	return p->mo_dir_ops->mdo_unlink(env, p, c, lname, ma, no_name);
}

static inline int mdo_statfs(const struct lu_env *env,
			     struct md_device *m,
			     struct obd_statfs *sfs)
{
	LASSERT(m->md_ops->mdo_statfs);
	return m->md_ops->mdo_statfs(env, m, sfs);
}

/**
 * Used in MDD/OUT layer for object lock rule
 **/
enum mdd_object_role {
	MOR_SRC_PARENT,
	MOR_SRC_CHILD,
	MOR_TGT_PARENT,
	MOR_TGT_CHILD,
	MOR_TGT_ORPHAN
};

struct dt_device;

void lustre_som_swab(struct lustre_som_attrs *attrs);
int lustre_buf2hsm(void *buf, int rc, struct md_hsm *mh);
void lustre_hsm2buf(void *buf, const struct md_hsm *mh);

enum {
	UCRED_INVALID	= -1,
	UCRED_INIT	= 0,
	UCRED_OLD	= 1,
	UCRED_NEW	= 2,
};

struct lu_ucred {
	__u32			 uc_valid;
	__u32			 uc_o_uid;
	__u32			 uc_o_gid;
	__u32			 uc_o_fsuid;
	__u32			 uc_o_fsgid;
	__u32			 uc_uid;
	__u32			 uc_gid;
	__u32			 uc_fsuid;
	__u32			 uc_fsgid;
	__u32			 uc_suppgids[2];
	cfs_cap_t		 uc_cap;
	__u32			 uc_umask;
	struct group_info	*uc_ginfo;
	struct md_identity	*uc_identity;
	char			 uc_jobid[LUSTRE_JOBID_SIZE];
	lnet_nid_t		 uc_nid;
	bool			 uc_enable_audit;
};

struct lu_ucred *lu_ucred(const struct lu_env *env);

struct lu_ucred *lu_ucred_check(const struct lu_env *env);

struct lu_ucred *lu_ucred_assert(const struct lu_env *env);

int lu_ucred_global_init(void);

void lu_ucred_global_fini(void);

#define md_cap_t(x) (x)

#define MD_CAP_TO_MASK(x) (1 << (x))

#define md_cap_raised(c, flag) (md_cap_t(c) & MD_CAP_TO_MASK(flag))

/* capable() is copied from linux kernel! */
static inline int md_capable(struct lu_ucred *uc, cfs_cap_t cap)
{
	if (md_cap_raised(uc->uc_cap, cap))
		return 1;
	return 0;
}

/** @} md */
#endif /* _LINUX_MD_OBJECT_H */
