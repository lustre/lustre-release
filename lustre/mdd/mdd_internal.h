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
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_internal.h
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

#include <lustre_acl.h>
#include <lustre_eacl.h>
#include <md_object.h>
#include <dt_object.h>
#include <lustre_lfsck.h>
#include <lustre_fid.h>
#include <lustre_capa.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include <lustre_linkea.h>

/* Changelog flags */
/** changelog is recording */
#define CLM_ON    0x00001
/** internal error prevented changelogs from starting */
#define CLM_ERR   0x00002
/* Marker flags */
/** changelogs turned on */
#define CLM_START 0x10000
/** changelogs turned off */
#define CLM_FINI  0x20000
/** some changelog records purged */
#define CLM_PURGE 0x40000

struct mdd_changelog {
	spinlock_t		mc_lock;	/* for index */
	int			mc_flags;
	int			mc_mask;
	__u64			mc_index;
	__u64			mc_starttime;
	spinlock_t		mc_user_lock;
	int			mc_lastuser;
};

static inline __u64 cl_time(void) {
	cfs_fs_time_t time;

	cfs_fs_time_current(&time);
	return (((__u64)time.tv_sec) << 30) + time.tv_nsec;
}

/** Objects in .lustre dir */
struct mdd_dot_lustre_objs {
        struct mdd_object *mdd_obf;
};

struct mdd_device {
        struct md_device                 mdd_md_dev;
	struct obd_export               *mdd_child_exp;
        struct dt_device                *mdd_child;
	struct dt_device		*mdd_bottom;
	struct lu_fid                    mdd_root_fid; /* /ROOT */
	struct lu_fid			 mdd_local_root_fid;
        struct dt_device_param           mdd_dt_conf;
        struct dt_object                *mdd_orphans; /* PENDING directory */
        cfs_proc_dir_entry_t            *mdd_proc_entry;
        struct mdd_changelog             mdd_cl;
        unsigned long                    mdd_atime_diff;
        struct mdd_object               *mdd_dot_lustre;
        struct mdd_dot_lustre_objs       mdd_dot_lustre_objs;
	unsigned int			 mdd_sync_permission;
	int				 mdd_connects;
	struct local_oid_storage	*mdd_los;
};

enum mod_flags {
        /* The dir object has been unlinked */
        DEAD_OBJ   = 1 << 0,
        APPEND_OBJ = 1 << 1,
        IMMUTE_OBJ = 1 << 2,
        ORPHAN_OBJ = 1 << 3,
};

struct mdd_object {
        struct md_object   mod_obj;
        /* open count */
        __u32             mod_count;
        __u32             mod_valid;
        __u64             mod_cltime;
        unsigned long     mod_flags;
#ifdef CONFIG_LOCKDEP
        /* "dep_map" name is assumed by lockdep.h macros. */
        struct lockdep_map dep_map;
#endif
};

struct mdd_thread_info {
        struct lu_fid             mti_fid;
        struct lu_fid             mti_fid2; /* used for be & cpu converting */
        struct lu_attr            mti_la;
        struct lu_attr            mti_la_for_fix;
	struct lu_attr            mti_pattr;
	struct lu_attr            mti_cattr;
        struct md_attr            mti_ma;
        struct obd_info           mti_oi;
	/* mti_ent and mti_key must be conjoint,
	 * then mti_ent::lde_name will be mti_key. */
	struct lu_dirent	  mti_ent;
	char			  mti_key[NAME_MAX + 16];
        struct obd_trans_info     mti_oti;
        struct lu_buf             mti_buf[4];
        struct lu_buf             mti_big_buf; /* biggish persistent buf */
	struct lu_buf		  mti_link_buf; /* buf for link ea */
        struct lu_name            mti_name;
	struct lu_name            mti_name2;
        struct obdo               mti_oa;
        char                      mti_xattr_buf[LUSTRE_POSIX_ACL_MAX_SIZE];
        struct dt_allocation_hint mti_hint;
        struct lov_mds_md        *mti_max_lmm;
        int                       mti_max_lmm_size;
        struct llog_cookie       *mti_max_cookie;
        int                       mti_max_cookie_size;
        struct dt_object_format   mti_dof;
        struct obd_quotactl       mti_oqctl;
	struct linkea_data	  mti_link_data;
};

extern const char orph_index_name[];

extern const struct dt_index_features orph_index_features;

struct lov_mds_md *mdd_max_lmm_buffer(const struct lu_env *env, int size);
struct lov_mds_md *mdd_max_lmm_get(const struct lu_env *env,
                                   struct mdd_device *mdd);

struct llog_cookie *mdd_max_cookie_get(const struct lu_env *env,
                                       struct mdd_device *mdd);

int mdd_init_obd(const struct lu_env *env, struct mdd_device *mdd,
                 struct lustre_cfg *cfg);
int mdd_fini_obd(const struct lu_env *env, struct mdd_device *mdd,
                 struct lustre_cfg *lcfg);
int __mdd_xattr_set(const struct lu_env *env, struct mdd_object *obj,
                    const struct lu_buf *buf, const char *name,
                    int fl, struct thandle *handle);
int mdd_xattr_set_txn(const struct lu_env *env, struct mdd_object *obj,
                      const struct lu_buf *buf, const char *name, int fl,
                      struct thandle *txn);
int mdd_lsm_sanity_check(const struct lu_env *env, struct mdd_object *obj);
int mdd_lov_set_md(const struct lu_env *env, struct mdd_object *pobj,
                   struct mdd_object *child, struct lov_mds_md *lmm,
                   int lmm_size, struct thandle *handle, int set_stripe);
int mdd_lov_create(const struct lu_env *env, struct mdd_device *mdd,
                   struct mdd_object *parent, struct mdd_object *child,
                   struct lov_mds_md **lmm, int *lmm_size,
                   const struct md_op_spec *spec, struct md_attr *ma);
int mdd_lov_objid_prepare(struct mdd_device *mdd, struct lov_mds_md *lmm);
int mdd_declare_lov_objid_update(const struct lu_env *, struct mdd_device *,
                                 struct thandle *);
void mdd_lov_objid_update(struct mdd_device *mdd, struct lov_mds_md *lmm);
void mdd_lov_create_finish(const struct lu_env *env, struct mdd_device *mdd,
                           struct lov_mds_md *lmm, int lmm_size,
                           const struct md_op_spec *spec);
int mdd_file_lock(const struct lu_env *env, struct md_object *obj,
                  struct lov_mds_md *lmm, struct ldlm_extent *extent,
                  struct lustre_handle *lockh);
int mdd_file_unlock(const struct lu_env *env, struct md_object *obj,
                    struct lov_mds_md *lmm, struct lustre_handle *lockh);
int mdd_lum_lmm_cmp(const struct lu_env *env, struct md_object *cobj,
                    const struct md_op_spec *spec, struct md_attr *ma);
int mdd_get_md(const struct lu_env *env, struct mdd_object *obj,
               void *md, int *md_size, const char *name);
int mdd_get_md_locked(const struct lu_env *env, struct mdd_object *obj,
                      void *md, int *md_size, const char *name);
int mdd_data_get(const struct lu_env *env, struct mdd_object *obj, void **data);
int mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
               struct lu_attr *la, struct lustre_capa *capa);
int mdd_attr_get(const struct lu_env *env, struct md_object *obj,
		 struct md_attr *ma);
int mdd_attr_set(const struct lu_env *env, struct md_object *obj,
		 const struct md_attr *ma);
int mdd_attr_set_internal(const struct lu_env *env,
			  struct mdd_object *obj,
			  const struct lu_attr *attr,
			  struct thandle *handle,
			  int needacl);
int mdd_attr_check_set_internal(const struct lu_env *env,
                                struct mdd_object *obj,
                                struct lu_attr *attr,
                                struct thandle *handle,
                                int needacl);
int mdd_declare_object_kill(const struct lu_env *env, struct mdd_object *obj,
                            struct md_attr *ma, struct thandle *handle);
int mdd_object_kill(const struct lu_env *env, struct mdd_object *obj,
                    struct md_attr *ma, struct thandle *handle);
int mdd_iattr_get(const struct lu_env *env, struct mdd_object *mdd_obj,
                  struct md_attr *ma);
int mdd_object_create_internal(const struct lu_env *env, struct mdd_object *p,
			       struct mdd_object *c, struct lu_attr *attr,
			       struct thandle *handle,
			       const struct md_op_spec *spec);
int mdd_attr_check_set_internal_locked(const struct lu_env *env,
                                       struct mdd_object *obj,
                                       struct lu_attr *attr,
                                       struct thandle *handle,
                                       int needacl);
int mdd_lmm_get_locked(const struct lu_env *env, struct mdd_object *mdd_obj,
                       struct md_attr *ma);

/* mdd_lock.c */
void mdd_write_lock(const struct lu_env *env, struct mdd_object *obj,
                    enum mdd_object_role role);
void mdd_read_lock(const struct lu_env *env, struct mdd_object *obj,
                   enum mdd_object_role role);
void mdd_write_unlock(const struct lu_env *env, struct mdd_object *obj);
void mdd_read_unlock(const struct lu_env *env, struct mdd_object *obj);
int mdd_write_locked(const struct lu_env *env, struct mdd_object *obj);

unsigned long mdd_name2hash(const char *name);
void *mdd_pdo_write_lock(const struct lu_env *env, struct mdd_object *obj,
                         const char *name, enum mdd_object_role role);
void mdd_pdo_write_unlock(const struct lu_env *env, struct mdd_object *obj,
                          void *dlh);
/* mdd_dir.c */
int mdd_parent_fid(const struct lu_env *env, struct mdd_object *obj,
		   struct lu_fid *fid);
int mdd_is_subdir(const struct lu_env *env, struct md_object *mo,
                  const struct lu_fid *fid, struct lu_fid *sfid);
int mdd_may_create(const struct lu_env *env, struct mdd_object *pobj,
                   struct mdd_object *cobj, int check_perm, int check_nlink);
int mdd_may_unlink(const struct lu_env *env, struct mdd_object *pobj,
		   const struct lu_attr *attr);
int mdd_may_delete(const struct lu_env *env, struct mdd_object *pobj,
		   struct mdd_object *cobj, struct lu_attr *cattr,
		   struct lu_attr *src_attr, int check_perm, int check_empty);
int mdd_unlink_sanity_check(const struct lu_env *env, struct mdd_object *pobj,
			    struct mdd_object *cobj, struct lu_attr *cattr);
int mdd_finish_unlink(const struct lu_env *env, struct mdd_object *obj,
		      struct md_attr *ma, const struct mdd_object *pobj,
		      const struct lu_name *lname, struct thandle *th);

int mdd_link_sanity_check(const struct lu_env *env, struct mdd_object *tgt_obj,
                          const struct lu_name *lname, struct mdd_object *src_obj);
int mdd_is_root(struct mdd_device *mdd, const struct lu_fid *fid);
int mdd_lookup(const struct lu_env *env,
               struct md_object *pobj, const struct lu_name *lname,
               struct lu_fid* fid, struct md_op_spec *spec);
int mdd_links_read(const struct lu_env *env, struct mdd_object *mdd_obj,
		   struct linkea_data *ldata);
int mdd_declare_links_add(const struct lu_env *env, struct mdd_object *mdd_obj,
			  struct thandle *handle, struct linkea_data *ldata);
int mdd_links_write(const struct lu_env *env, struct mdd_object *mdd_obj,
		    struct linkea_data *ldata, struct thandle *handle);
struct lu_buf *mdd_links_get(const struct lu_env *env,
                             struct mdd_object *mdd_obj);
int mdd_links_rename(const struct lu_env *env,
		     struct mdd_object *mdd_obj,
		     const struct lu_fid *oldpfid,
		     const struct lu_name *oldlname,
		     const struct lu_fid *newpfid,
		     const struct lu_name *newlname,
		     struct thandle *handle,
		     struct linkea_data *ldata,
		     int first, int check);
int mdd_declare_links_add(const struct lu_env *env, struct mdd_object *mdd_obj,
			  struct thandle *handle, struct linkea_data *ldata);

/* mdd_lov.c */
int mdd_declare_unlink_log(const struct lu_env *env, struct mdd_object *obj,
                           struct md_attr *ma, struct thandle *handle);
int mdd_unlink_log(const struct lu_env *env, struct mdd_device *mdd,
                   struct mdd_object *mdd_cobj, struct md_attr *ma);

int mdd_setattr_log(const struct lu_env *env, struct mdd_device *mdd,
                    const struct md_attr *ma,
                    struct lov_mds_md *lmm, int lmm_size,
                    struct llog_cookie *logcookies, int cookies_size);

int mdd_get_cookie_size(const struct lu_env *env, struct mdd_device *mdd,
                        struct lov_mds_md *lmm);

int mdd_lov_setattr_async(const struct lu_env *env, struct mdd_object *obj,
                          struct lov_mds_md *lmm, int lmm_size,
                          struct llog_cookie *logcookies);

int mdd_lovobj_unlink(const struct lu_env *env, struct mdd_device *mdd,
		      struct mdd_object *obj, struct lu_attr *la,
		      struct md_attr *ma, int log_unlink);

struct mdd_thread_info *mdd_env_info(const struct lu_env *env);

const struct lu_name *mdd_name_get_const(const struct lu_env *env,
					 const void *area, ssize_t len);
struct lu_buf *mdd_buf_get(const struct lu_env *env, void *area, ssize_t len);
const struct lu_buf *mdd_buf_get_const(const struct lu_env *env,
                                       const void *area, ssize_t len);

int __mdd_orphan_cleanup(const struct lu_env *env, struct mdd_device *d);
int __mdd_orphan_add(const struct lu_env *, struct mdd_object *,
                     struct thandle *);
int __mdd_orphan_del(const struct lu_env *, struct mdd_object *,
                     struct thandle *);
int orph_index_init(const struct lu_env *env, struct mdd_device *mdd);
void orph_index_fini(const struct lu_env *env, struct mdd_device *mdd);
int orph_declare_index_insert(const struct lu_env *, struct mdd_object *,
			      umode_t mode, struct thandle *);
int orph_declare_index_delete(const struct lu_env *, struct mdd_object *,
                              struct thandle *);

/* mdd_lproc.c */
void lprocfs_mdd_init_vars(struct lprocfs_static_vars *lvars);
int mdd_procfs_init(struct mdd_device *mdd, const char *name);
int mdd_procfs_fini(struct mdd_device *mdd);

/* mdd_object.c */
int mdd_get_flags(const struct lu_env *env, struct mdd_object *obj);
struct lu_buf *mdd_buf_alloc(const struct lu_env *env, ssize_t len);
int mdd_buf_grow(const struct lu_env *env, ssize_t len);
void mdd_buf_put(struct lu_buf *buf);

struct lu_buf *mdd_link_buf_alloc(const struct lu_env *env, ssize_t len);
int mdd_link_buf_grow(const struct lu_env *env, ssize_t len);
extern const struct md_dir_operations    mdd_dir_ops;
extern const struct md_object_operations mdd_obj_ops;

int accmode(const struct lu_env *env, struct lu_attr *la, int flags);
extern struct lu_context_key mdd_thread_key;
extern const struct lu_device_operations mdd_lu_ops;

struct mdd_object *mdd_object_find(const struct lu_env *env,
                                   struct mdd_device *d,
                                   const struct lu_fid *f);
int mdd_get_default_md(struct mdd_object *mdd_obj, struct lov_mds_md *lmm);
int mdd_readpage(const struct lu_env *env, struct md_object *obj,
                 const struct lu_rdpg *rdpg);
int mdd_declare_changelog_store(const struct lu_env *env,
				struct mdd_device *mdd,
				const struct lu_name *fname,
				struct thandle *handle);
int mdd_changelog_store(const struct lu_env *env, struct mdd_device *mdd,
			struct llog_changelog_rec *rec, struct thandle *th);
int mdd_changelog_data_store(const struct lu_env *env, struct mdd_device *mdd,
			     enum changelog_rec_type type, int flags,
			     struct mdd_object *mdd_obj,
			     struct thandle *handle);
int mdd_changelog_ns_store(const struct lu_env *env, struct mdd_device *mdd,
			   enum changelog_rec_type type, unsigned flags,
			   struct mdd_object *target, struct mdd_object *parent,
			   const struct lu_name *tname, struct thandle *handle);
int mdd_declare_object_create_internal(const struct lu_env *env,
				       struct mdd_object *p,
				       struct mdd_object *c,
				       struct lu_attr *attr,
				       struct thandle *handle,
				       const struct md_op_spec *spec);

/* mdd_trans.c */
int mdd_lov_destroy(const struct lu_env *env, struct mdd_device *mdd,
                    struct mdd_object *obj, struct lu_attr *la);

void mdd_object_make_hint(const struct lu_env *env, struct mdd_object *parent,
			  struct mdd_object *child, struct lu_attr *attr);

static inline void mdd_object_get(struct mdd_object *o)
{
	lu_object_get(&o->mod_obj.mo_lu);
}

static inline void mdd_object_put(const struct lu_env *env,
                                  struct mdd_object *o)
{
        lu_object_put(env, &o->mod_obj.mo_lu);
}

struct thandle *mdd_trans_create(const struct lu_env *env,
                                 struct mdd_device *mdd);
int mdd_trans_start(const struct lu_env *env, struct mdd_device *mdd,
                    struct thandle *th);
void mdd_trans_stop(const struct lu_env *env, struct mdd_device *mdd,
                    int rc, struct thandle *handle);
int mdd_txn_stop_cb(const struct lu_env *env, struct thandle *txn,
                    void *cookie);
int mdd_txn_start_cb(const struct lu_env *env, struct thandle *,
                     void *cookie);

/* mdd_device.c */
struct lu_object *mdd_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *d);
int mdd_local_file_create(const struct lu_env *env, struct mdd_device *mdd,
			  const struct lu_fid *pfid, const char *name,
			  __u32 mode, struct lu_fid *fid);

int mdd_acl_chmod(const struct lu_env *env, struct mdd_object *o, __u32 mode,
                  struct thandle *handle);
int __mdd_declare_acl_init(const struct lu_env *env, struct mdd_object *obj,
                           int is_dir, struct thandle *handle);
int mdd_acl_set(const struct lu_env *env, struct mdd_object *obj,
		const struct lu_buf *buf, int fl);
int __mdd_fix_mode_acl(const struct lu_env *env, struct lu_buf *buf,
		       __u32 *mode);
int __mdd_permission_internal(const struct lu_env *env, struct mdd_object *obj,
                              struct lu_attr *la, int mask, int role);
int mdd_permission(const struct lu_env *env,
                   struct md_object *pobj, struct md_object *cobj,
                   struct md_attr *ma, int mask);
int mdd_capa_get(const struct lu_env *env, struct md_object *obj,
                 struct lustre_capa *capa, int renewal);

/* mdd_prepare.c */
int mdd_compat_fixes(const struct lu_env *env, struct mdd_device *mdd);

/* inline functions */
static inline int lu_device_is_mdd(struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdd_lu_ops);
}

static inline struct mdd_device* lu2mdd_dev(struct lu_device *d)
{
        LASSERT(lu_device_is_mdd(d));
        return container_of0(d, struct mdd_device, mdd_md_dev.md_lu_dev);
}

static inline struct lu_device *mdd2lu_dev(struct mdd_device *d)
{
        return (&d->mdd_md_dev.md_lu_dev);
}

static inline struct mdd_object *lu2mdd_obj(struct lu_object *o)
{
        LASSERT(ergo(o != NULL, lu_device_is_mdd(o->lo_dev)));
        return container_of0(o, struct mdd_object, mod_obj.mo_lu);
}

static inline struct mdd_device* mdo2mdd(struct md_object *mdo)
{
        return lu2mdd_dev(mdo->mo_lu.lo_dev);
}

static inline struct mdd_object* md2mdd_obj(struct md_object *mdo)
{
        return container_of0(mdo, struct mdd_object, mod_obj);
}

static inline const struct dt_device_operations *
mdd_child_ops(struct mdd_device *d)
{
        return d->mdd_child->dd_ops;
}

static inline struct lu_object *mdd2lu_obj(struct mdd_object *obj)
{
        return &obj->mod_obj.mo_lu;
}

static inline struct dt_object* mdd_object_child(struct mdd_object *o)
{
        return container_of0(lu_object_next(mdd2lu_obj(o)),
                             struct dt_object, do_lu);
}

static inline struct obd_device *mdd2obd_dev(struct mdd_device *mdd)
{
	return (mdd->mdd_md_dev.md_lu_dev.ld_obd);
}

static inline struct mdd_device *mdd_obj2mdd_dev(struct mdd_object *obj)
{
        return mdo2mdd(&obj->mod_obj);
}

static inline const struct lu_fid *mdo2fid(const struct mdd_object *obj)
{
        return lu_object_fid(&obj->mod_obj.mo_lu);
}

static inline int mdd_object_obf(const struct mdd_object *obj)
{
	return lu_fid_eq(mdo2fid(obj), &LU_OBF_FID);
}

static inline umode_t mdd_object_type(const struct mdd_object *obj)
{
        return lu_object_attr(&obj->mod_obj.mo_lu);
}

static inline int mdd_is_immutable(struct mdd_object *obj)
{
        return obj->mod_flags & IMMUTE_OBJ;
}

static inline int mdd_is_dead_obj(struct mdd_object *obj)
{
        return obj && obj->mod_flags & DEAD_OBJ;
}

static inline int mdd_is_append(struct mdd_object *obj)
{
        return obj->mod_flags & APPEND_OBJ;
}

static inline int mdd_object_exists(struct mdd_object *obj)
{
        return lu_object_exists(mdd2lu_obj(obj));
}

static inline int mdd_object_remote(struct mdd_object *obj)
{
	return lu_object_remote(mdd2lu_obj(obj));
}

static inline const struct lu_fid *mdd_object_fid(struct mdd_object *obj)
{
        return lu_object_fid(mdd2lu_obj(obj));
}

static inline struct seq_server_site *mdd_seq_site(struct mdd_device *mdd)
{
	return mdd2lu_dev(mdd)->ld_site->ld_seq_site;
}

static inline struct lustre_capa *mdd_object_capa(const struct lu_env *env,
						  const struct mdd_object *obj)
{
	struct lu_capainfo *lci = lu_capainfo_get(env);
	const struct lu_fid *fid = mdo2fid(obj);
	int i;

	/* NB: in mdt_init0 */
	if (lci == NULL)
		return BYPASS_CAPA;

	for (i = 0; i < LU_CAPAINFO_MAX; i++)
		if (lu_fid_eq(&lci->lci_fid[i], fid))
			return lci->lci_capa[i];
	return NULL;
}

static inline void mdd_set_capainfo(const struct lu_env *env, int offset,
				    const struct mdd_object *obj,
				    struct lustre_capa *capa)
{
	struct lu_capainfo *lci = lu_capainfo_get(env);
	const struct lu_fid *fid = mdo2fid(obj);

	LASSERT(offset >= 0 && offset < LU_CAPAINFO_MAX);
	/* NB: in mdt_init0 */
	if (lci == NULL)
		return;

	lci->lci_fid[offset]  = *fid;
	lci->lci_capa[offset] = capa;
}

static inline const char *mdd_obj_dev_name(const struct mdd_object *obj)
{
        return lu_dev_name(obj->mod_obj.mo_lu.lo_dev);
}

#define MAX_ATIME_DIFF 60

enum {
        LPROC_MDD_NR
};

static inline int mdd_permission_internal(const struct lu_env *env,
                                          struct mdd_object *obj,
                                          struct lu_attr *la, int mask)
{
        return __mdd_permission_internal(env, obj, la, mask, -1);
}

static inline int mdd_permission_internal_locked(const struct lu_env *env,
                                                 struct mdd_object *obj,
                                                 struct lu_attr *la, int mask,
                                                 enum mdd_object_role role)
{
        return __mdd_permission_internal(env, obj, la, mask, role);
}

static inline int mdo_data_get(const struct lu_env *env,
                               struct mdd_object *obj,
                               void **data)
{
        struct dt_object *next = mdd_object_child(obj);
        next->do_ops->do_data_get(env, next, data);
        return 0;
}

/* mdd inline func for calling osd_dt_object ops */
static inline int mdo_attr_get(const struct lu_env *env, struct mdd_object *obj,
                               struct lu_attr *la, struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        return next->do_ops->do_attr_get(env, next, la, capa);
}

static inline int mdo_declare_attr_set(const struct lu_env *env,
                                       struct mdd_object *obj,
                                       const struct lu_attr *la,
                                       struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        return dt_declare_attr_set(env, next, la, handle);
}

static inline int mdo_attr_set(const struct lu_env *env,
                               struct mdd_object *obj,
                               const struct lu_attr *la,
                               struct thandle *handle,
                               struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        return next->do_ops->do_attr_set(env, next, la, handle, capa);
}

static inline int mdo_xattr_get(const struct lu_env *env,struct mdd_object *obj,
                                struct lu_buf *buf, const char *name,
                                struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        return next->do_ops->do_xattr_get(env, next, buf, name, capa);
}

static inline int mdo_declare_xattr_set(const struct lu_env *env,
                                        struct mdd_object *obj,
                                        const struct lu_buf *buf,
                                        const char *name,
                                        int fl, struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        return dt_declare_xattr_set(env, next, buf, name, fl, handle);
}

static inline int mdo_xattr_set(const struct lu_env *env,struct mdd_object *obj,
                                const struct lu_buf *buf, const char *name,
                                int fl, struct thandle *handle,
                                struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        return next->do_ops->do_xattr_set(env, next, buf, name, fl, handle,
                                          capa);
}

static inline int mdo_declare_xattr_del(const struct lu_env *env,
                                        struct mdd_object *obj,
                                        const char *name,
                                        struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        return dt_declare_xattr_del(env, next, name, handle);
}

static inline int mdo_xattr_del(const struct lu_env *env,struct mdd_object *obj,
                                const char *name, struct thandle *handle,
                                struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        return next->do_ops->do_xattr_del(env, next, name, handle, capa);
}

static inline
int mdo_xattr_list(const struct lu_env *env, struct mdd_object *obj,
                   struct lu_buf *buf, struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        return next->do_ops->do_xattr_list(env, next, buf, capa);
}

static inline
int mdo_index_try(const struct lu_env *env, struct mdd_object *obj,
                                 const struct dt_index_features *feat)
{
        struct dt_object *next = mdd_object_child(obj);
        return next->do_ops->do_index_try(env, next, feat);
}

static inline
int mdo_declare_index_insert(const struct lu_env *env, struct mdd_object *obj,
                             const struct lu_fid *fid, const char *name,
                             struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        int              rc = 0;

        /*
         * if the object doesn't exist yet, then it's supposed to be created
         * and declaration of the creation should be enough to insert ./..
         */
	 /* FIXME: remote object should not be awared by MDD layer, but local
	  * creation does not declare insert ./.. (comments above), which
	  * is required by remote directory creation.
	  * This remote check should be removed when mdd_object_exists check is
	  * removed.
	  */
	 if (mdd_object_exists(obj) || mdd_object_remote(obj)) {
                rc = -ENOTDIR;
                if (dt_try_as_dir(env, next))
                        rc = dt_declare_insert(env, next,
                                               (struct dt_rec *)fid,
                                               (const struct dt_key *)name,
                                               handle);
        }

        return rc;
}

static inline
int mdo_declare_index_delete(const struct lu_env *env, struct mdd_object *obj,
                             const char *name, struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);

        if (!dt_try_as_dir(env, next))
                return -ENOTDIR;

        return dt_declare_delete(env, next, (const struct dt_key *)name,
                                 handle);
}

static inline int mdo_declare_ref_add(const struct lu_env *env,
                                      struct mdd_object *obj,
                                      struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        return dt_declare_ref_add(env, next, handle);
}

static inline int mdo_ref_add(const struct lu_env *env, struct mdd_object *obj,
                              struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        return next->do_ops->do_ref_add(env, next, handle);
}

static inline int mdo_declare_ref_del(const struct lu_env *env,
                                      struct mdd_object *obj,
                                      struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        return dt_declare_ref_del(env, next, handle);
}

static inline int mdo_ref_del(const struct lu_env *env, struct mdd_object *obj,
                              struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        return next->do_ops->do_ref_del(env, next, handle);
}

static inline
int mdo_declare_create_obj(const struct lu_env *env, struct mdd_object *o,
                           struct lu_attr *attr,
                           struct dt_allocation_hint *hint,
                           struct dt_object_format *dof,
                           struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(o);
        return next->do_ops->do_declare_create(env, next, attr, hint,
                                               dof, handle);
}

static inline
int mdo_create_obj(const struct lu_env *env, struct mdd_object *o,
                   struct lu_attr *attr,
                   struct dt_allocation_hint *hint,
                   struct dt_object_format *dof,
                   struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(o);
	int rc;

	rc = next->do_ops->do_create(env, next, attr, hint, dof, handle);

	return rc;
}

static inline
int mdo_declare_destroy(const struct lu_env *env, struct mdd_object *o,
                        struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(o);
        return dt_declare_destroy(env, next, handle);
}

static inline
int mdo_destroy(const struct lu_env *env, struct mdd_object *o,
                struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(o);
        return dt_destroy(env, next, handle);
}

static inline struct obd_capa *mdo_capa_get(const struct lu_env *env,
                                            struct mdd_object *obj,
                                            struct lustre_capa *old,
                                            __u64 opc)
{
        struct dt_object *next = mdd_object_child(obj);
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return ERR_PTR(-ENOENT);
        }
        return next->do_ops->do_capa_get(env, next, old, opc);
}

#endif
