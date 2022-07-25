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
 *
 * lustre/mdd/mdd_internal.h
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

#include <lustre_acl.h>
#include <lustre_compat.h>
#include <md_object.h>
#include <dt_object.h>
#include <lustre_lfsck.h>
#include <lustre_fid.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include <lustre_linkea.h>

/* ChangeLog params for automatic purge mechanism */
/* max time allowed for a user to stay idle in seconds */
#define CHLOG_MAX_IDLE_TIME 2592000 /* = 30 days */
/* max gap allowed for a user to stay idle in number of ChangeLog records
 * this is an evaluation, assuming that chunk-size is LLOG_MIN_CHUNK_SIZE, of
 * the indexes gap for half full changelogs */
#define CHLOG_MAX_IDLE_INDEXES (((LLOG_MIN_CHUNK_SIZE - \
				  offsetof(struct llog_log_hdr, \
					   llh_bitmap[0]) - \
				  sizeof(struct llog_rec_tail)) * 4) * \
				((LLOG_MIN_CHUNK_SIZE - \
				  offsetof(struct llog_log_hdr, \
					   llh_bitmap[0]) - \
				  sizeof(struct llog_rec_tail)) * 8))
/* min time in seconds between two gc thread runs if none already started */
#define CHLOG_MIN_GC_INTERVAL 3600
/* minimum number of free ChangeLog catalog entries (ie, between cur and
 * last indexes) before starting garbage collect */
#define CHLOG_MIN_FREE_CAT_ENTRIES 2

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
/** changelog cleanup done, to prevent double cleanup */
#define CLM_CLEANUP_DONE 0x80000

#define LLOG_CHANGELOG_HDR_SZ (sizeof(struct llog_changelog_rec) - \
			       sizeof(struct changelog_rec))
/* mc_gc_task values */
/** no GC thread to be started **/
#define MDD_CHLG_GC_NONE NULL
/** a GC thread need to be started **/
#define MDD_CHLG_GC_NEED (struct task_struct *)(-1)
/** a GC thread will be started now **/
#define MDD_CHLG_GC_START (struct task_struct *)(-2)
/** else the started task_struct address when running **/

struct mdd_changelog {
	spinlock_t		mc_lock;	/* for index */
	int			mc_flags;
	__u32			mc_proc_mask; /* per-server mask set via parameters */
	__u32			mc_current_mask; /* combined global+users */
	__u32			mc_mintime; /* the oldest changelog user time */
	__u64			mc_minrec; /* last known minimal used index */
	__u64			mc_index;
	ktime_t			mc_starttime;
	spinlock_t		mc_user_lock;
	int			mc_lastuser;
	int			mc_users;      /* registered users number */
	struct task_struct	*mc_gc_task;
	time64_t		mc_gc_time;    /* last GC check or run time */
	unsigned int		mc_deniednext; /* interval for recording denied
						* accesses
						*/
};

static inline __u64 cl_time(void)
{
	struct timespec64 time;

	ktime_get_real_ts64(&time);
	return (((__u64)time.tv_sec) << 30) + time.tv_nsec;
}

/** Objects in .lustre dir */
struct mdd_dot_lustre_objs {
	struct mdd_object *mdd_obf;
	struct mdd_object *mdd_lpf;
};

struct mdd_generic_thread {
	struct completion	mgt_started;
	struct completion	mgt_finished;
	void		       *mgt_data;
	bool			mgt_abort;
	bool			mgt_init;
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
        struct mdd_changelog             mdd_cl;
	unsigned int			 mdd_changelog_gc;
	time64_t			 mdd_changelog_max_idle_time;
	unsigned long			 mdd_changelog_max_idle_indexes;
	time64_t			 mdd_changelog_min_gc_interval;
	unsigned int			 mdd_changelog_min_free_cat_entries;
	time64_t			 mdd_atime_diff;
        struct mdd_object               *mdd_dot_lustre;
        struct mdd_dot_lustre_objs       mdd_dot_lustre_objs;
	unsigned int			 mdd_sync_permission;
	int				 mdd_connects;
	int				 mdd_append_stripe_count;
	char				 mdd_append_pool[LOV_MAXPOOLNAME + 1];
	struct local_oid_storage	*mdd_los;
	struct mdd_generic_thread	 mdd_orphan_cleanup_thread;
	struct kobject			 mdd_kobj;
	struct kobj_type		 mdd_ktype;
	struct completion		 mdd_kobj_unregister;
};

enum mod_flags {
	/* The dir object has been unlinked */
	DEAD_OBJ	= BIT(0),
	ORPHAN_OBJ	= BIT(1),
	VOLATILE_OBJ	= BIT(4),
};

struct mdd_object {
	struct md_object	mod_obj;
	/* open count */
	u32			mod_count;
	u32			mod_valid;
	ktime_t			mod_cltime;
	unsigned long		mod_flags;
	struct list_head	mod_users;  /**< unique user opens */
};

#define MDI_KEEP_KEY	0x01

struct mdd_thread_info {
	struct lu_fid		  mdi_fid;
	struct lu_fid		  mdi_fid2; /* used for be & cpu converting */
	/**
	* only be used by MDD interfaces, can be passed into local MDD APIs.
	*/
	struct lu_attr		  mdi_pattr;
	struct lu_attr		  mdi_cattr;
	struct lu_attr		  mdi_tpattr;
	struct lu_attr		  mdi_tattr;
	/** used to set ctime/mtime */
	struct lu_attr		  mdi_la_for_fix;
	/* Only used in mdd_object_start */
	struct lu_attr		  mdi_la_for_start;
	/* mdi_ent/mdi_key must be together so mdi_ent::lde_name is mdi_key */
	struct lu_dirent	  mdi_ent;
	char			  mdi_key[NAME_MAX + 16];
	int			  mdi_flags;
	char			  mdi_name[NAME_MAX + 1];
	struct lu_buf		  mdi_buf[4];
	/* persistent buffers, must be handled with lu_buf_alloc/free */
	struct lu_buf		  mdi_big_buf;
	struct lu_buf		  mdi_chlg_buf;
	struct lu_buf		  mdi_link_buf; /* buf for link ea */
	struct lu_buf		  mdi_xattr_buf;
	struct obdo		  mdi_oa;
	struct dt_allocation_hint mdi_hint;
	struct dt_object_format	  mdi_dof;
	struct linkea_data	  mdi_link_data;
	struct md_op_spec	  mdi_spec;
	struct dt_insert_rec	  mdi_dt_rec;
	struct lu_seq_range	  mdi_range;
	struct md_layout_change	  mdi_mlc;
};

int mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
	       struct lu_attr *la);
int mdd_attr_get(const struct lu_env *env, struct md_object *obj,
		 struct md_attr *ma);
int mdd_attr_set(const struct lu_env *env, struct md_object *obj,
		 const struct md_attr *ma);
int mdd_attr_set_internal(const struct lu_env *env,
			  struct mdd_object *obj,
			  const struct lu_attr *attr,
			  struct thandle *handle,
			  int needacl);
int mdd_update_time(const struct lu_env *env, struct mdd_object *obj,
		    const struct lu_attr *oattr, struct lu_attr *attr,
		    struct thandle *handle);
int mdd_create_object_internal(const struct lu_env *env, struct mdd_object *p,
			       struct mdd_object *c, struct lu_attr *attr,
			       struct thandle *handle,
			       const struct md_op_spec *spec,
			       struct dt_allocation_hint *hint);

/* mdd_lock.c */
void mdd_write_lock(const struct lu_env *env, struct mdd_object *obj,
		    enum dt_object_role role);
void mdd_read_lock(const struct lu_env *env, struct mdd_object *obj,
		   enum dt_object_role role);
void mdd_write_unlock(const struct lu_env *env, struct mdd_object *obj);
void mdd_read_unlock(const struct lu_env *env, struct mdd_object *obj);
int mdd_write_locked(const struct lu_env *env, struct mdd_object *obj);

/* mdd_dir.c */
int mdd_may_create(const struct lu_env *env, struct mdd_object *pobj,
		   const struct lu_attr *pattr, struct mdd_object *cobj,
		   bool check_perm);
int mdd_may_unlink(const struct lu_env *env, struct mdd_object *pobj,
		   const struct lu_attr *pattr, const struct lu_attr *attr);
int mdd_may_delete(const struct lu_env *env, struct mdd_object *tpobj,
		   const struct lu_attr *tpattr, struct mdd_object *tobj,
		   const struct lu_attr *tattr, const struct lu_attr *cattr,
		   int check_perm, int check_empty);
int mdd_unlink_sanity_check(const struct lu_env *env, struct mdd_object *pobj,
			    const struct lu_attr *pattr,
			    struct mdd_object *cobj,
			    const struct lu_attr *cattr);
int mdd_finish_unlink(const struct lu_env *env, struct mdd_object *obj,
		      struct md_attr *ma, struct mdd_object *pobj,
		      const struct lu_name *lname, struct thandle *th);

int mdd_is_root(struct mdd_device *mdd, const struct lu_fid *fid);
int mdd_lookup(const struct lu_env *env,
               struct md_object *pobj, const struct lu_name *lname,
               struct lu_fid* fid, struct md_op_spec *spec);
int mdd_links_write(const struct lu_env *env, struct mdd_object *mdd_obj,
		    struct linkea_data *ldata, struct thandle *handle);
int mdd_links_read(const struct lu_env *env,
		   struct mdd_object *mdd_obj,
		   struct linkea_data *ldata);
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
int mdd_dir_layout_shrink(const struct lu_env *env,
			  struct md_object *md_obj,
			  struct md_layout_change *mlc);
int mdd_dir_layout_split(const struct lu_env *env, struct md_object *o,
			 struct md_layout_change *mlc);

int mdd_changelog_write_rec(const struct lu_env *env,
			    struct llog_handle *loghandle,
			    struct llog_rec_hdr *rec,
			    struct llog_cookie *cookie,
			    int idx, struct thandle *th);

struct mdd_thread_info *mdd_env_info(const struct lu_env *env);

#define MDD_ENV_VAR(env, var) (&mdd_env_info(env)->mdi_##var)

struct lu_buf *mdd_buf_get(const struct lu_env *env, void *area, ssize_t len);
const struct lu_buf *mdd_buf_get_const(const struct lu_env *env,
                                       const void *area, ssize_t len);

int mdd_orphan_cleanup(const struct lu_env *env, struct mdd_device *d);
int mdd_orphan_insert(const struct lu_env *env, struct mdd_object *obj,
		      struct thandle *thandle);
int mdd_orphan_delete(const struct lu_env *env, struct mdd_object *obj,
		      struct thandle *thandle);
int mdd_orphan_index_init(const struct lu_env *env, struct mdd_device *mdd);
void mdd_orphan_index_fini(const struct lu_env *env, struct mdd_device *mdd);
int mdd_orphan_declare_insert(const struct lu_env *env, struct mdd_object *obj,
			      umode_t mode, struct thandle *thandle);
int mdd_orphan_declare_delete(const struct lu_env *env, struct mdd_object *obj,
			      struct thandle *thandle);
int mdd_dir_is_empty(const struct lu_env *env, struct mdd_object *dir);

/* mdd_lproc.c */
int mdd_procfs_init(struct mdd_device *mdd, const char *name);
void mdd_procfs_fini(struct mdd_device *mdd);

/* mdd_object.c */
extern struct kmem_cache *mdd_object_kmem;
extern const struct md_dir_operations    mdd_dir_ops;
extern const struct md_object_operations mdd_obj_ops;
int mdd_readlink(const struct lu_env *env, struct md_object *obj,
		 struct lu_buf *buf);
extern struct lu_context_key mdd_thread_key;
extern const struct lu_device_operations mdd_lu_ops;

struct mdd_object *mdd_object_find(const struct lu_env *env,
                                   struct mdd_device *d,
                                   const struct lu_fid *f);
int mdd_readpage(const struct lu_env *env, struct md_object *obj,
                 const struct lu_rdpg *rdpg);
int mdd_declare_changelog_store(const struct lu_env *env,
				struct mdd_device *mdd,
				enum changelog_rec_type type,
				const struct lu_name *tname,
				const struct lu_name *sname,
				struct thandle *handle);
void mdd_changelog_rec_ext_jobid(struct changelog_rec *rec, const char *jobid);
void mdd_changelog_rec_ext_extra_flags(struct changelog_rec *rec, __u64 eflags);
void mdd_changelog_rec_extra_uidgid(struct changelog_rec *rec,
				    __u64 uid, __u64 gid);
void mdd_changelog_rec_extra_nid(struct changelog_rec *rec,
				 lnet_nid_t nid);
void mdd_changelog_rec_extra_omode(struct changelog_rec *rec, u32 flags);
void mdd_changelog_rec_extra_xattr(struct changelog_rec *rec,
				   const char *xattr_name);
int mdd_changelog_store(const struct lu_env *env, struct mdd_device *mdd,
			struct llog_changelog_rec *rec, struct thandle *th);
int mdd_changelog_data_store(const struct lu_env *env, struct mdd_device *mdd,
			     enum changelog_rec_type type,
			     enum changelog_rec_flags clf_flags,
			     struct mdd_object *mdd_obj,
			     struct thandle *handle,
			     const struct lu_fid *pfid);
int mdd_changelog_ns_store(const struct lu_env *env, struct mdd_device *mdd,
			   enum changelog_rec_type type,
			   enum changelog_rec_flags clf_flags,
			   struct mdd_object *target,
			   const struct lu_fid *tpfid,
			   const struct lu_fid *sfid,
			   const struct lu_fid *spfid,
			   const struct lu_name *tname,
			   const struct lu_name *sname,
			   struct thandle *handle);
int mdd_invalidate(const struct lu_env *env, struct md_object *obj);
int mdd_declare_create_object_internal(const struct lu_env *env,
				       struct mdd_object *p,
				       struct mdd_object *c,
				       struct lu_attr *attr,
				       struct thandle *handle,
				       const struct md_op_spec *spec,
				       struct dt_allocation_hint *hint);
int mdd_stripe_get(const struct lu_env *env, struct mdd_object *obj,
		   struct lu_buf *lmm_buf, const char *name);
int mdd_changelog_data_store_xattr(const struct lu_env *env,
				   struct mdd_device *mdd,
				   enum changelog_rec_type type,
				   enum changelog_rec_flags clf_flags,
				   struct mdd_object *mdd_obj,
				   const char *xattr_name,
				   struct thandle *handle);

/* mdd_trans.c */
void mdd_object_make_hint(const struct lu_env *env, struct mdd_object *parent,
			  struct mdd_object *child, const struct lu_attr *attr,
			  const struct md_op_spec *spec,
			  struct dt_allocation_hint *hint);

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
int mdd_trans_stop(const struct lu_env *env, struct mdd_device *mdd,
		   int rc, struct thandle *handle);

/* mdd_device.c */
struct lu_object *mdd_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *d);
int mdd_local_file_create(const struct lu_env *env, struct mdd_device *mdd,
			  const struct lu_fid *pfid, const char *name,
			  __u32 mode, struct lu_fid *fid);

int mdd_acl_chmod(const struct lu_env *env, struct mdd_object *o, __u32 mode,
                  struct thandle *handle);
int mdd_acl_set(const struct lu_env *env, struct mdd_object *obj,
		struct lu_attr *attr, const struct lu_buf *buf, int fl);
int __mdd_fix_mode_acl(const struct lu_env *env, struct lu_buf *buf,
		       __u32 *mode);
int __mdd_permission_internal(const struct lu_env *env, struct mdd_object *obj,
			      const struct lu_attr *la, unsigned int may_mask,
			      int role);
int mdd_permission(const struct lu_env *env, struct md_object *pobj,
		   struct md_object *cobj, struct md_attr *ma,
		   unsigned int may_mask);
int mdd_generic_thread_start(struct mdd_generic_thread *thread,
			     int (*func)(void *), void *data, char *name);
void mdd_generic_thread_stop(struct mdd_generic_thread *thread);
int mdd_changelog_user_purge(const struct lu_env *env, struct mdd_device *mdd,
			     __u32 id);
char *mdd_chlg_username(struct llog_changelog_user_rec2 *rec, char *buf,
			size_t len);
__u32 mdd_chlg_usermask(struct llog_changelog_user_rec2 *rec);
int mdd_changelog_recalc_mask(const struct lu_env *env, struct mdd_device *mdd);

/* mdd_prepare.c */
int mdd_compat_fixes(const struct lu_env *env, struct mdd_device *mdd);

/* acl.c */
extern int lustre_posix_acl_permission(struct lu_ucred *mu,
				       const struct lu_attr *la,
				       unsigned int may_mask,
				       posix_acl_xattr_entry *entry,
				       int count);
extern int lustre_posix_acl_chmod_masq(posix_acl_xattr_entry *entry,
				       __u32 mode, int count);
extern int lustre_posix_acl_create_masq(posix_acl_xattr_entry *entry,
					__u32 *pmode, int count);
extern int lustre_posix_acl_equiv_mode(posix_acl_xattr_entry *entry,
				       mode_t *mode_p, int count);

/* inline functions */
static inline int lu_device_is_mdd(struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdd_lu_ops);
}

static inline struct mdd_device *lu2mdd_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_mdd(d));
	return container_of_safe(d, struct mdd_device, mdd_md_dev.md_lu_dev);
}

static inline struct lu_device *mdd2lu_dev(struct mdd_device *mdd)
{
	return &mdd->mdd_md_dev.md_lu_dev;
}

static inline struct mdd_object *lu2mdd_obj(struct lu_object *o)
{
	LASSERT(ergo(o != NULL, lu_device_is_mdd(o->lo_dev)));
	return container_of_safe(o, struct mdd_object,
				 mod_obj.mo_lu);
}

static inline struct mdd_device *mdo2mdd(struct md_object *mdo)
{
	return lu2mdd_dev(mdo->mo_lu.lo_dev);
}

static inline struct mdd_object *md2mdd_obj(struct md_object *mdo)
{
	return container_of_safe(mdo, struct mdd_object, mod_obj);
}

static inline const
struct dt_device_operations *mdd_child_ops(struct mdd_device *mdd)
{
	return mdd->mdd_child->dd_ops;
}

static inline struct lu_object *mdd2lu_obj(struct mdd_object *obj)
{
	return &obj->mod_obj.mo_lu;
}

static inline struct dt_object *mdd_object_child(struct mdd_object *obj)
{
	return container_of(lu_object_next(mdd2lu_obj(obj)),
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

static inline umode_t mdd_object_type(const struct mdd_object *mdd_obj)
{
	return lu_object_attr(&mdd_obj->mod_obj.mo_lu);
}

static inline int mdd_is_dead_obj(struct mdd_object *mdd_obj)
{
	return mdd_obj && mdd_obj->mod_flags & DEAD_OBJ;
}

static inline bool mdd_is_volatile_obj(struct mdd_object *mdd_obj)
{
	return mdd_obj->mod_flags & VOLATILE_OBJ;
}

static inline bool mdd_is_orphan_obj(struct mdd_object *mdd_obj)
{
	return mdd_obj->mod_flags & ORPHAN_OBJ;
}

static inline int mdd_object_exists(struct mdd_object *mdd_obj)
{
	return lu_object_exists(mdd2lu_obj(mdd_obj));
}

static inline int mdd_object_remote(struct mdd_object *mdd_obj)
{
	return lu_object_remote(mdd2lu_obj(mdd_obj));
}

static inline const struct lu_fid *mdd_object_fid(struct mdd_object *mdd_obj)
{
	return lu_object_fid(mdd2lu_obj(mdd_obj));
}

static inline struct seq_server_site *mdd_seq_site(struct mdd_device *mdd)
{
	return mdd2lu_dev(mdd)->ld_site->ld_seq_site;
}

static inline const char *mdd_obj_dev_name(const struct mdd_object *mdd_obj)
{
	return lu_dev_name(mdd_obj->mod_obj.mo_lu.lo_dev);
}

#define MAX_ATIME_DIFF 60

static inline int mdd_permission_internal(const struct lu_env *env,
					  struct mdd_object *obj,
					  const struct lu_attr *la,
					  unsigned int may_mask)
{
	return __mdd_permission_internal(env, obj, la, may_mask, -1);
}

static inline int mdd_permission_internal_locked(const struct lu_env *env,
						struct mdd_object *obj,
						const struct lu_attr *la,
						unsigned int may_mask,
						enum dt_object_role role)
{
	return __mdd_permission_internal(env, obj, la, may_mask, role);
}

/* mdd inline func for calling osd_dt_object ops */
static inline int mdo_attr_get(const struct lu_env *env, struct mdd_object *obj,
			       struct lu_attr *la)
{
	struct dt_object *next = mdd_object_child(obj);
	return dt_attr_get(env, next, la);
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
			       struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(obj);

	if (!mdd_object_exists(obj))
		return -ENOENT;

	return dt_attr_set(env, next, la, handle);
}

static inline int mdo_xattr_get(const struct lu_env *env,struct mdd_object *obj,
				struct lu_buf *buf, const char *name)
{
	struct dt_object *next = mdd_object_child(obj);
	return dt_xattr_get(env, next, buf, name);
}

static inline int mdo_declare_xattr_set(const struct lu_env *env,
                                        struct mdd_object *obj,
                                        const struct lu_buf *buf,
                                        const char *name,
                                        int fl, struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(obj);
	int rc;

	rc = dt_declare_xattr_set(env, next, buf, name, fl, handle);
	if (rc >= 0 &&
	    (strcmp(name, LL_XATTR_NAME_ENCRYPTION_CONTEXT) == 0 ||
	     strcmp(name, LL_XATTR_NAME_ENCRYPTION_CONTEXT_OLD) == 0)) {
		struct lu_attr la = { 0 };

		la.la_valid = LA_FLAGS;
		la.la_flags = LUSTRE_ENCRYPT_FL;
		rc = dt_declare_attr_set(env, next, &la, handle);
	}
	return rc;
}

static inline int mdo_xattr_set(const struct lu_env *env,struct mdd_object *obj,
				const struct lu_buf *buf, const char *name,
				int fl, struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(obj);
	int rc = 0;

	if (!mdd_object_exists(obj))
		return -ENOENT;

	/* If we are about to set the LL_XATTR_NAME_ENCRYPTION_CONTEXT
	 * xattr, it means the file/dir is encrypted. In that case we want
	 * to set the LUSTRE_ENCRYPT_FL flag as well: it will be stored
	 * into the LMA, making it more efficient to recognise we are
	 * dealing with an encrypted file/dir, as LMA info is cached upon
	 * object init.
	 * However, marking a dir as encrypted is only possible if it is
	 * being created or migrated (LU_XATTR_CREATE flag not set), or
	 * if it is empty.
	 */
	if ((strcmp(name, LL_XATTR_NAME_ENCRYPTION_CONTEXT) == 0 ||
	     strcmp(name, LL_XATTR_NAME_ENCRYPTION_CONTEXT_OLD) == 0) &&
	    (!S_ISDIR(mdd_object_type(obj)) ||
	     !(fl & LU_XATTR_CREATE) ||
	     (rc = mdd_dir_is_empty(env, obj)) == 0)) {
		struct lu_attr la = { 0 };

		la.la_valid = LA_FLAGS;
		la.la_flags = LUSTRE_ENCRYPT_FL;
		/* if this is an old client using the old enc xattr name,
		 * switch to the new name for consistency
		 */
		if (strcmp(name, LL_XATTR_NAME_ENCRYPTION_CONTEXT_OLD) == 0)
			name = LL_XATTR_NAME_ENCRYPTION_CONTEXT;
		rc = dt_attr_set(env, next, &la, handle);
	}
	if (rc >= 0)
		rc = dt_xattr_set(env, next, buf, name, fl, handle);

	return rc;
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
				const char *name, struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(obj);

	if (!mdd_object_exists(obj))
		return -ENOENT;

	return dt_xattr_del(env, next, name, handle);
}

static inline int
mdo_xattr_list(const struct lu_env *env, struct mdd_object *obj,
	       struct lu_buf *buf)
{
	struct dt_object *next = mdd_object_child(obj);

	if (!mdd_object_exists(obj))
		return -ENOENT;

	return dt_xattr_list(env, next, buf);
}

static inline int
mdo_invalidate(const struct lu_env *env, struct mdd_object *obj)
{
	return dt_invalidate(env, mdd_object_child(obj));
}

static inline int
mdo_declare_layout_change(const struct lu_env *env, struct mdd_object *obj,
			  struct md_layout_change *mlc, struct thandle *handle)
{
	return dt_declare_layout_change(env, mdd_object_child(obj),
					mlc, handle);
}

static inline int
mdo_layout_change(const struct lu_env *env, struct mdd_object *obj,
		  struct md_layout_change *mlc, struct thandle *handle)
{
	return dt_layout_change(env, mdd_object_child(obj), mlc, handle);
}

static inline
int mdo_declare_index_insert(const struct lu_env *env, struct mdd_object *obj,
			     const struct lu_fid *fid, __u32 type,
			     const char *name, struct thandle *handle)
{
	struct dt_object *next	= mdd_object_child(obj);
	int		  rc;

	/*
	 * if the object doesn't exist yet, then it's supposed to be created
	 * and declaration of the creation should be enough to insert ./..
	 */

	rc = -ENOTDIR;
	if (dt_try_as_dir(env, next)) {
		struct dt_insert_rec *rec = &mdd_env_info(env)->mdi_dt_rec;

		rec->rec_fid = fid;
		rec->rec_type = type;
		rc = dt_declare_insert(env, next, (const struct dt_rec *)rec,
				       (const struct dt_key *)name, handle);
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

	if (!mdd_object_exists(obj))
		return -ENOENT;

	return dt_ref_add(env, next, handle);
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

	if (!mdd_object_exists(obj))
		return -ENOENT;

	return dt_ref_del(env, next, handle);
}

static inline int
mdo_declare_create_object(const struct lu_env *env, struct mdd_object *obj,
			  struct lu_attr *attr, struct dt_allocation_hint *hint,
			  struct dt_object_format *dof, struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(obj);
	return dt_declare_create(env, next, attr, hint, dof, handle);
}

static inline int
mdo_create_object(const struct lu_env *env, struct mdd_object *obj,
		  struct lu_attr *attr, struct dt_allocation_hint *hint,
		  struct dt_object_format *dof, struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(obj);
	return dt_create(env, next, attr, hint, dof, handle);
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

static inline bool mdd_changelog_enabled(const struct lu_env *env,
					struct mdd_device *mdd,
					enum changelog_rec_type type)
{
	const struct lu_ucred *uc;

	if ((mdd->mdd_cl.mc_flags & CLM_ON) &&
	    (mdd->mdd_cl.mc_current_mask & BIT(type))) {
		uc = lu_ucred_check(env);

		return uc != NULL ? uc->uc_enable_audit : true;
	} else {
		return false;
	}
}

static inline bool mdd_changelog_is_too_idle(struct mdd_device *mdd,
					     __u64 cl_rec, __u32 cl_time)
{
	__u64 idle_indexes = mdd->mdd_cl.mc_index - cl_rec;
	__u32 idle_time = (__u32)ktime_get_real_seconds() - cl_time;

	return (idle_indexes > mdd->mdd_changelog_max_idle_indexes ||
		idle_time > mdd->mdd_changelog_max_idle_time ||
		idle_time * idle_indexes > (24 * 3600ULL << 32));
}

#endif
