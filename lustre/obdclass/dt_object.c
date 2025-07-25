// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Dt Object.
 * Generic functions from dt_object.h
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/list.h>
#include <obd_class.h>
#include <dt_object.h>
/* fid_be_to_cpu() */
#include <lustre_fid.h>
#include <lustre_nodemap.h>
#include <lustre_quota.h>
#include <lustre_lfsck.h>
#include <uapi/linux/lustre/lustre_disk.h>

/* context key constructor/destructor: dt_global_key_init, dt_global_key_fini */
LU_KEY_INIT(dt_global, struct dt_thread_info);
LU_KEY_FINI(dt_global, struct dt_thread_info);

struct lu_context_key dt_key = {
	.lct_tags = LCT_MD_THREAD | LCT_DT_THREAD | LCT_MG_THREAD | LCT_LOCAL,
	.lct_init = dt_global_key_init,
	.lct_fini = dt_global_key_fini
};
EXPORT_SYMBOL(dt_key);

/*
 * no lock is necessary to protect the list, because call-backs
 * are added during system startup. Please refer to "struct dt_device".
 */
void dt_txn_callback_add(struct dt_device *dev, struct dt_txn_callback *cb)
{
	list_add(&cb->dtc_linkage, &dev->dd_txn_callbacks);
}
EXPORT_SYMBOL(dt_txn_callback_add);

void dt_txn_callback_del(struct dt_device *dev, struct dt_txn_callback *cb)
{
	list_del_init(&cb->dtc_linkage);
}
EXPORT_SYMBOL(dt_txn_callback_del);

int dt_txn_hook_start(const struct lu_env *env,
		      struct dt_device *dev, struct thandle *th)
{
	int rc = 0;
	struct dt_txn_callback *cb;

	if (th->th_local)
		return 0;

	list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
		struct thandle *dtc_th = th;

		if (cb->dtc_txn_start == NULL ||
		    !(cb->dtc_tag & env->le_ctx.lc_tags))
			continue;

		/*
		 * Usually dt_txn_hook_start is called from bottom device,
		 * and if the thandle has th_top, then we need use top
		 * thandle for the callback in the top thandle layer
		 */
		if (th->th_top != NULL)
			dtc_th = th->th_top;

		rc = cb->dtc_txn_start(env, dtc_th, cb->dtc_cookie);
		if (rc < 0)
			break;
	}
	return rc;
}
EXPORT_SYMBOL(dt_txn_hook_start);

int dt_txn_hook_stop(const struct lu_env *env, struct thandle *th)
{
	struct dt_device *dev = th->th_dev;
	struct dt_txn_callback *cb;
	int rc = 0;

	if (th->th_local)
		return 0;

	if (CFS_FAIL_CHECK(OBD_FAIL_DT_TXN_STOP))
		return -EIO;

	list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
		struct thandle *dtc_th = th;

		if (cb->dtc_txn_stop == NULL ||
		    !(cb->dtc_tag & env->le_ctx.lc_tags))
			continue;

		/*
		 * Usually dt_txn_hook_stop is called from bottom device,
		 * and if the thandle has th_top, then we need use top
		 * thandle for the callback in the top thandle layer
		 */
		if (th->th_top != NULL)
			dtc_th = th->th_top;

		rc = cb->dtc_txn_stop(env, dtc_th, cb->dtc_cookie);
		if (rc < 0)
			break;
	}
	return rc;
}
EXPORT_SYMBOL(dt_txn_hook_stop);

int dt_device_init(struct dt_device *dev, struct lu_device_type *t)
{
	INIT_LIST_HEAD(&dev->dd_txn_callbacks);
	return lu_device_init(&dev->dd_lu_dev, t);
}
EXPORT_SYMBOL(dt_device_init);

void dt_device_fini(struct dt_device *dev)
{
	lu_device_fini(&dev->dd_lu_dev);
}
EXPORT_SYMBOL(dt_device_fini);

int dt_object_init(struct dt_object *obj,
		   struct lu_object_header *h, struct lu_device *d)

{
	return lu_object_init(&obj->do_lu, h, d);
}
EXPORT_SYMBOL(dt_object_init);

void dt_object_fini(struct dt_object *obj)
{
	lu_object_fini(&obj->do_lu);
}
EXPORT_SYMBOL(dt_object_fini);

/**
 * Set directory .do_index_ops.
 *
 * Set directory index operations, if the caller knows directory exists,
 * \a check should be set to ensure object is directory and exists, while for
 * new directories, skip check and the index operations will be used to create
 * ".." under directory.
 *
 * Normally this is called before dt_lookup() to ensure directory objects
 * exists and .do_index_ops is correctly set.
 *
 * \param env	lu_env object.
 * \param obj	dt object.
 * \param check	check \a obj existence and type, return if index ops is set.
 * \retval 1	on success.
 * \retval 0	on error.
 */
int dt_try_as_dir(const struct lu_env *env, struct dt_object *obj, bool check)
{
	if (check) {
		if (unlikely(!dt_object_exists(obj)))
			return 0;

		if (unlikely(!S_ISDIR(lu_object_attr(&obj->do_lu))))
			return 0;

		if (obj->do_index_ops)
			return 1;
	}

	obj->do_ops->do_index_try(env, obj, &dt_directory_features);

	return obj->do_index_ops != NULL;
}
EXPORT_SYMBOL(dt_try_as_dir);

enum dt_format_type dt_mode_to_dft(__u32 mode)
{
	enum dt_format_type result;

	switch (mode & S_IFMT) {
	case S_IFDIR:
		result = DFT_DIR;
		break;
	case S_IFREG:
		result = DFT_REGULAR;
		break;
	case S_IFLNK:
		result = DFT_SYM;
		break;
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		result = DFT_NODE;
		break;
	default:
		LASSERTF(0, "invalid mode %o\n", mode);
		result = 0; /* Just for satisfying compiler. */
		break;
	}
	return result;
}
EXPORT_SYMBOL(dt_mode_to_dft);

/**
 * lookup fid for object named \a name in directory \a dir.
 */

int dt_lookup_dir(const struct lu_env *env, struct dt_object *dir,
                  const char *name, struct lu_fid *fid)
{
	if (dt_try_as_dir(env, dir, true))
		return dt_lookup(env, dir, (struct dt_rec *)fid,
				 (const struct dt_key *)name);
	return -ENOTDIR;
}
EXPORT_SYMBOL(dt_lookup_dir);

/*
 * this differs from dt_locate by top_dev as parameter
 * but not one from lu_site
 */
struct dt_object *dt_locate_at(const struct lu_env *env,
			       struct dt_device *dev,
			       const struct lu_fid *fid,
			       struct lu_device *top_dev,
			       const struct lu_object_conf *conf)
{
	struct lu_object *lo;
	struct lu_object *n;

	lo = lu_object_find_at(env, top_dev, fid, conf);
	if (IS_ERR(lo))
		return ERR_CAST(lo);

	LASSERT(lo != NULL);

	list_for_each_entry(n, &lo->lo_header->loh_layers, lo_linkage) {
		if (n->lo_dev == &dev->dd_lu_dev)
			return container_of(n, struct dt_object, do_lu);
	}

	lu_object_put(env, lo);
	return ERR_PTR(-ENOENT);
}
EXPORT_SYMBOL(dt_locate_at);

struct dt_object *dt_find_or_create(const struct lu_env *env,
				    struct dt_device *dt,
				    const struct lu_fid *fid,
				    struct dt_object_format *dof,
				    struct lu_attr *at)
{
	struct dt_object *dto;
	struct thandle *th;
	int rc;

	ENTRY;

	dto = dt_locate(env, dt, fid);
	if (IS_ERR(dto))
		RETURN(dto);

	LASSERT(dto != NULL);
	if (dt_object_exists(dto))
		RETURN(dto);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_create(env, dto, at, NULL, dof, th);
	if (rc)
		GOTO(trans_stop, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(trans_stop, rc);

	dt_write_lock(env, dto, 0);
	if (dt_object_exists(dto))
		GOTO(unlock, rc = 0);

	CDEBUG(D_OTHER, "create new object "DFID"\n", PFID(fid));

	rc = dt_create(env, dto, at, NULL, dof, th);
	if (rc)
                GOTO(unlock, rc);
	LASSERT(dt_object_exists(dto));
unlock:
	dt_write_unlock(env, dto);
trans_stop:
	dt_trans_stop(env, dt, th);
out:
	if (rc) {
		dt_object_put(env, dto);
		dto = ERR_PTR(rc);
	}

	RETURN(dto);
}
EXPORT_SYMBOL(dt_find_or_create);

/* dt class init function. */
int dt_global_init(void)
{
	int result;

	LU_CONTEXT_KEY_INIT(&dt_key);
	result = lu_context_key_register(&dt_key);
	return result;
}

void dt_global_fini(void)
{
	lu_context_key_degister(&dt_key);
}

/**
 * Generic read helper. May return an error for partial reads.
 *
 * \param env  lustre environment
 * \param dt   object to be read
 * \param buf  lu_buf to be filled, with buffer pointer and length
 * \param pos position to start reading, updated as data is read
 *
 * \retval real size of data read
 * \retval -ve errno on failure
 */
int dt_read(const struct lu_env *env, struct dt_object *dt,
	    struct lu_buf *buf, loff_t *pos)
{
	LASSERTF(dt != NULL, "dt is NULL when we want to read record\n");
	return dt->do_body_ops->dbo_read(env, dt, buf, pos);
}
EXPORT_SYMBOL(dt_read);

/**
 * Read structures of fixed size from storage.  Unlike dt_read(), using
 * dt_record_read() will return an error for partial reads.
 *
 * \param env  lustre environment
 * \param dt   object to be read
 * \param buf  lu_buf to be filled, with buffer pointer and length
 * \param pos position to start reading, updated as data is read
 *
 * \retval 0 on successfully reading full buffer
 * \retval -EFAULT on short read
 * \retval -ve errno on failure
 */
int dt_record_read(const struct lu_env *env, struct dt_object *dt,
                   struct lu_buf *buf, loff_t *pos)
{
	ssize_t size;

	LASSERTF(dt != NULL, "dt is NULL when we want to read record\n");

	size = dt->do_body_ops->dbo_read(env, dt, buf, pos);
	if (size < 0)
		return size;
	return (size == (ssize_t)buf->lb_len) ? 0 : -EFAULT;
}
EXPORT_SYMBOL(dt_record_read);

int dt_record_write(const struct lu_env *env, struct dt_object *dt,
		    const struct lu_buf *buf, loff_t *pos, struct thandle *th)
{
	ssize_t size;

	LASSERTF(dt != NULL, "dt is NULL when we want to write record\n");
	LASSERT(th != NULL);
	LASSERT(dt->do_body_ops);
	LASSERTF(dt->do_body_ops->dbo_write, DFID"\n",
		 PFID(lu_object_fid(&dt->do_lu)));

	size = dt->do_body_ops->dbo_write(env, dt, buf, pos, th);
	if (size < 0)
		return size;
	return (size == (ssize_t)buf->lb_len) ? 0 : -EFAULT;
}
EXPORT_SYMBOL(dt_record_write);

int dt_declare_version_set(const struct lu_env *env, struct dt_object *o,
			   struct thandle *th)
{
	struct lu_buf vbuf;
	char *xname = XATTR_NAME_VERSION;

	LASSERT(o);
	vbuf.lb_buf = NULL;
	vbuf.lb_len = sizeof(dt_obj_version_t);
	return dt_declare_xattr_set(env, o, NULL, &vbuf, xname, 0, th);
}
EXPORT_SYMBOL(dt_declare_version_set);

void dt_version_set(const struct lu_env *env, struct dt_object *o,
		    dt_obj_version_t version, struct thandle *th)
{
	struct lu_buf vbuf;
	char *xname = XATTR_NAME_VERSION;
	int rc;

	LASSERT(o);
	vbuf.lb_buf = &version;
	vbuf.lb_len = sizeof(version);
	rc = dt_xattr_set(env, o, &vbuf, xname, 0, th);
	if (rc < 0)
		CDEBUG(D_INODE, "Can't set version, rc %d\n", rc);
}
EXPORT_SYMBOL(dt_version_set);

dt_obj_version_t dt_version_get(const struct lu_env *env, struct dt_object *o)
{
	struct lu_buf vbuf;
	char *xname = XATTR_NAME_VERSION;
	dt_obj_version_t version;
	int rc;

	LASSERT(o);
	vbuf.lb_buf = &version;
	vbuf.lb_len = sizeof(version);
	rc = dt_xattr_get(env, o, &vbuf, xname);
	if (rc != sizeof(version)) {
		CDEBUG(D_INODE, "Can't get version, rc %d\n", rc);
		version = 0;
	}

	return version;
}
EXPORT_SYMBOL(dt_version_get);

int dt_declare_data_version_set(const struct lu_env *env, struct dt_object *o,
				struct thandle *th)
{
	struct lu_buf vbuf;

	vbuf.lb_buf = NULL;
	vbuf.lb_len = sizeof(dt_obj_version_t);

	return dt_declare_xattr_set(env, o, NULL, &vbuf, XATTR_NAME_DATAVER, 0,
	       th);
}
EXPORT_SYMBOL(dt_declare_data_version_set);

void dt_data_version_set(const struct lu_env *env, struct dt_object *o,
			 dt_obj_version_t version, struct thandle *th)
{
	struct lu_buf vbuf;

	CDEBUG(D_INODE, DFID": set new data version -> %llu\n",
	       PFID(lu_object_fid(&o->do_lu)), version);

	/* version should never be set to zero */
	LASSERT(version);
	vbuf.lb_buf = &version;
	vbuf.lb_len = sizeof(version);
	dt_xattr_set(env, o, &vbuf, XATTR_NAME_DATAVER, 0, th);
}
EXPORT_SYMBOL(dt_data_version_set);

int dt_declare_data_version_del(const struct lu_env *env, struct dt_object *o,
				struct thandle *th)
{
	return dt_declare_xattr_del(env, o, XATTR_NAME_DATAVER, th);
}
EXPORT_SYMBOL(dt_declare_data_version_del);

void dt_data_version_del(const struct lu_env *env, struct dt_object *o,
			 struct thandle *th)
{
	/* file doesn't need explicit data version anymore */
	CDEBUG(D_INODE, DFID": remove explicit data version\n",
	       PFID(lu_object_fid(&o->do_lu)));
	dt_xattr_del(env, o, XATTR_NAME_DATAVER, th);
}
EXPORT_SYMBOL(dt_data_version_del);

/* Initialize explicit data version, e.g. for DoM files.
 * It uses inode version as initial value.
 */
dt_obj_version_t dt_data_version_init(const struct lu_env *env,
				      struct dt_object *o)
{
	struct dt_device *dt = lu2dt_dev(o->do_lu.lo_dev);
	dt_obj_version_t dv;
	struct thandle *th;
	int rc;

	ENTRY;

	dv = dt_version_get(env, o);
	if (!dv)
		RETURN(1);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_data_version_set(env, o, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(stop, rc);

	dt_data_version_set(env, o, dv, th);
stop:
	dt_trans_stop(env, dt, th);
out:
	/* Ignore failure but report the error */
	if (rc)
		CDEBUG(D_INODE, "can't init data version for "DFID": rc = %d\n",
		       PFID(lu_object_fid(&o->do_lu)), rc);

	RETURN(dv);
}

dt_obj_version_t dt_data_version_get(const struct lu_env *env,
				     struct dt_object *o)
{
	struct lu_buf vbuf;
	dt_obj_version_t version;
	int rc;

	vbuf.lb_buf = &version;
	vbuf.lb_len = sizeof(version);
	rc = dt_xattr_get(env, o, &vbuf, XATTR_NAME_DATAVER);

	CDEBUG(D_INODE, DFID": get data version %llu: rc = %d\n",
	       PFID(lu_object_fid(&o->do_lu)), version, rc);

	if (rc == sizeof(version))
		return version;

	/* data version EA wasn't set yet on the object, initialize it now */
	if (rc == -ENODATA)
		return dt_data_version_init(env, o);

	CDEBUG(D_INODE, "Can't get data version: rc = %d\n", rc);

	return 0;
}
EXPORT_SYMBOL(dt_data_version_get);

/* list of all supported index types */

/* directories */
const struct dt_index_features dt_directory_features;
EXPORT_SYMBOL(dt_directory_features);

/* scrub iterator */
const struct dt_index_features dt_otable_features;
EXPORT_SYMBOL(dt_otable_features);

/* lfsck layout orphan */
const struct dt_index_features dt_lfsck_layout_orphan_features = {
	.dif_flags		= 0,
	.dif_keysize_min	= sizeof(struct lu_fid),
	.dif_keysize_max	= sizeof(struct lu_fid),
	.dif_recsize_min	= sizeof(struct lu_orphan_rec_v3),
	.dif_recsize_max	= sizeof(struct lu_orphan_rec_v3),
	.dif_ptrsize		= 4
};
EXPORT_SYMBOL(dt_lfsck_layout_orphan_features);

/* lfsck layout dangling */
const struct dt_index_features dt_lfsck_layout_dangling_features = {
	.dif_flags		= DT_IND_UPDATE,
	.dif_keysize_min	= sizeof(struct lfsck_layout_dangling_key),
	.dif_keysize_max	= sizeof(struct lfsck_layout_dangling_key),
	.dif_recsize_min	= sizeof(struct lu_fid),
	.dif_recsize_max	= sizeof(struct lu_fid),
	.dif_ptrsize		= 4
};
EXPORT_SYMBOL(dt_lfsck_layout_dangling_features);

/* lfsck namespace */
const struct dt_index_features dt_lfsck_namespace_features = {
	.dif_flags		= DT_IND_UPDATE,
	.dif_keysize_min	= sizeof(struct lu_fid),
	.dif_keysize_max	= sizeof(struct lu_fid),
	.dif_recsize_min	= sizeof(__u8),
	.dif_recsize_max	= sizeof(__u8),
	.dif_ptrsize		= 4
};
EXPORT_SYMBOL(dt_lfsck_namespace_features);

/* accounting indexes */
const struct dt_index_features dt_acct_features = {
	.dif_flags		= DT_IND_UPDATE,
	.dif_keysize_min	= sizeof(__u64), /* 64-bit uid/gid */
	.dif_keysize_max	= sizeof(__u64), /* 64-bit uid/gid */
	.dif_recsize_min	= sizeof(struct lquota_acct_rec), /* 16 bytes */
	.dif_recsize_max	= sizeof(struct lquota_acct_rec), /* 16 bytes */
	.dif_ptrsize		= 4
};
EXPORT_SYMBOL(dt_acct_features);

/* global quota files */
const struct dt_index_features dt_quota_glb_features = {
	.dif_flags		= DT_IND_UPDATE,
	/* a different key would have to be used for per-directory quota */
	.dif_keysize_min	= sizeof(__u64), /* 64-bit uid/gid */
	.dif_keysize_max	= sizeof(__u64), /* 64-bit uid/gid */
	.dif_recsize_min	= sizeof(struct lquota_glb_rec), /* 32 bytes */
	.dif_recsize_max	= sizeof(struct lquota_glb_rec), /* 32 bytes */
	.dif_ptrsize		= 4
};
EXPORT_SYMBOL(dt_quota_glb_features);

/* slave quota files */
const struct dt_index_features dt_quota_slv_features = {
	.dif_flags		= DT_IND_UPDATE,
	/* a different key would have to be used for per-directory quota */
	.dif_keysize_min	= sizeof(__u64), /* 64-bit uid/gid */
	.dif_keysize_max	= sizeof(__u64), /* 64-bit uid/gid */
	.dif_recsize_min	= sizeof(struct lquota_slv_rec), /* 8 bytes */
	.dif_recsize_max	= sizeof(struct lquota_slv_rec), /* 8 bytes */
	.dif_ptrsize		= 4
};
EXPORT_SYMBOL(dt_quota_slv_features);

/* nodemap files, nodemap_rec size asserted in nodemap_storage.c */
const struct dt_index_features dt_nodemap_features = {
	.dif_flags		= DT_IND_UPDATE,
	.dif_keysize_min	= sizeof(__u64), /* 64-bit nodemap/record id */
	.dif_keysize_max	= sizeof(__u64), /* 64-bit nodemap/record id */
	.dif_recsize_min	= sizeof(union nodemap_rec), /* 32 bytes */
	.dif_recsize_max	= sizeof(union nodemap_rec), /* 32 bytes */
	.dif_ptrsize		= 4
};
EXPORT_SYMBOL(dt_nodemap_features);

/*
 * helper function returning what dt_index_features structure should be used
 * based on the FID sequence. This is used by OBD_IDX_READ RPC
 */
static inline const struct dt_index_features *dt_index_feat_select(__u64 seq,
								   __u32 mode)
{
	if (seq == FID_SEQ_QUOTA_GLB) {
		/* global quota index */
		if (!S_ISREG(mode))
			/* global quota index should be a regular file */
			return ERR_PTR(-ENOENT);
		return &dt_quota_glb_features;
	} else if (seq == FID_SEQ_QUOTA) {
		/* quota slave index */
		if (!S_ISREG(mode))
			/* slave index should be a regular file */
			return ERR_PTR(-ENOENT);
		return &dt_quota_slv_features;
	} else if (seq == FID_SEQ_LAYOUT_RBTREE){
		return &dt_lfsck_layout_orphan_features;
	} else if (seq >= FID_SEQ_NORMAL) {
		/* object is part of the namespace, verify that it is a
		 * directory */
		if (!S_ISDIR(mode))
			/* sorry, we can only deal with directory */
			return ERR_PTR(-ENOTDIR);
		return &dt_directory_features;
	}

	return ERR_PTR(-EOPNOTSUPP);
}

/*
 * Fill a lu_idxpage with key/record pairs read for transfer via OBD_IDX_READ
 * RPC
 *
 * \param env - is the environment passed by the caller
 * \param obj - index object being traversed (mostly for debugging)
 * \param lp  - is a pointer to the lu_page to fill
 * \param bytes - is the maximum number of bytes that should be copied
 * \param iops - is the index operation vector associated with the index object
 * \param it   - is a pointer to the current iterator
 * \param attr - is the index attribute to pass to iops->rec()
 * \param arg  - is a pointer to the idx_info structure
 */
static int dt_index_page_build(const struct lu_env *env, struct dt_object *obj,
			       union lu_page *lp, size_t bytes,
			       const struct dt_it_ops *iops,
			       struct dt_it *it, __u32 attr, void *arg)
{
	struct idx_info *ii = (struct idx_info *)arg;
	struct lu_idxpage *lip = &lp->lp_idx;
	void *entry;
	__u64 hash;
	__u16 hashsize = 0;
	__u16 keysize = 0;
	__u16 recsize;
	int rc;

	ENTRY;

	if (bytes < LIP_HDR_SIZE)
		return -EINVAL;

	/* initialize the header of the new container */
	memset(lip, 0, LIP_HDR_SIZE);
	lip->lip_magic = LIP_MAGIC;
	bytes -= LIP_HDR_SIZE;

	/* client wants to the 64-bit hash value associated with each record */
	if (!(ii->ii_flags & II_FL_NOHASH))
		hashsize = sizeof(hash);

	entry = lip->lip_entries;
	do {
		/* fetch 64-bit hash value */
		hash = iops->store(env, it);
		ii->ii_hash_end = hash;

		if (CFS_FAIL_CHECK(OBD_FAIL_OBD_IDX_READ_BREAK)) {
			if (lip->lip_nr != 0)
				GOTO(out, rc = 0);
		}

		if (!(ii->ii_flags & II_FL_NOKEY)) {
			keysize = iops->key_size(env, it);
			if (!(ii->ii_flags & II_FL_VARKEY) &&
			    keysize != ii->ii_keysize) {
				rc = -EINVAL;
				CERROR("%s: keysize mismatch %hu != %hu on "
				       DFID": rc = %d\n",
				       lu_dev_name(obj->do_lu.lo_dev),
				       keysize, ii->ii_keysize,
				       PFID(lu_object_fid(&obj->do_lu)), rc);
				GOTO(out, rc);
			}
		}

		/* and finally the record */
		if (ii->ii_flags & II_FL_VARREC)
			recsize = iops->rec_size(env, it, attr);
		else
			recsize = ii->ii_recsize;

		if (bytes < hashsize + keysize + recsize) {
			if (lip->lip_nr == 0)
				GOTO(out, rc = -E2BIG);
			GOTO(out, rc = 0);
		}

		rc = iops->rec(env, it,
			       (struct dt_rec *)(entry + hashsize + keysize),
			       attr);
		if (!rc) {
			if (hashsize)
				memcpy(entry, &hash, hashsize);
			if (keysize) {
				struct dt_key *key;

				key = iops->key(env, it);
				memcpy(entry + hashsize, key, keysize);
			}
			/* hash/key/record successfully copied! */
			lip->lip_nr++;
			if (unlikely(lip->lip_nr == 1 && ii->ii_count == 0))
				ii->ii_hash_start = hash;
			entry += hashsize + keysize + recsize;
			bytes -= hashsize + keysize + recsize;
		} else if (rc != -ESTALE) {
			GOTO(out, rc);
		}

		/* move on to the next record */
		do {
			rc = iops->next(env, it);
		} while (rc == -ESTALE);
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


/* for dt_index*/
void *rdpg_page_get(const struct lu_rdpg *rdpg, unsigned int index)
{
	if (rdpg->rp_npages) {
		LASSERT(index < rdpg->rp_npages);
		return kmap(rdpg->rp_pages[index]);
	}
	LASSERT(index << PAGE_SHIFT < rdpg->rp_count);

	return rdpg->rp_data + (index << PAGE_SHIFT);
}
EXPORT_SYMBOL(rdpg_page_get);

void rdpg_page_put(const struct lu_rdpg *rdpg, unsigned int index, void *kaddr)
{
	if (rdpg->rp_npages)
		kunmap(kmap_to_page(kaddr));
}
EXPORT_SYMBOL(rdpg_page_put);

/*
 * Walk index and fill lu_page containers with key/record pairs
 *
 * \param env - is the environment passed by the caller
 * \param obj - is the index object to parse
 * \param rdpg - is the lu_rdpg descriptor associated with the transfer
 * \param filler - is the callback function responsible for filling a lu_page
 *                 with key/record pairs in the format wanted by the caller.
 *                 If NULL, uses dt_index_page_build
 * \param arg    - is an opaq argument passed to the filler function
 *
 * \retval sum (in bytes) of all filled lu_pages
 * \retval -ve errno on failure
 */
int dt_index_walk(const struct lu_env *env, struct dt_object *obj,
		  const struct lu_rdpg *rdpg, dt_index_page_build_t filler,
		  void *arg)
{
	struct dt_it *it;
	const struct dt_it_ops *iops;
	size_t pageidx, bytes, nlupgs = 0;
	int rc;
	ENTRY;

	LASSERT(rdpg->rp_pages != NULL);
	LASSERT(obj->do_index_ops != NULL);

	if (filler == NULL)
		filler = dt_index_page_build;

	bytes = rdpg->rp_count;
	if (bytes == 0)
		RETURN(-EFAULT);

	/* Iterate through index and fill containers from @rdpg */
	iops = &obj->do_index_ops->dio_it;
	LASSERT(iops != NULL);
	it = iops->init(env, obj, rdpg->rp_attrs);
	if (IS_ERR(it))
		RETURN(PTR_ERR(it));

	rc = iops->load(env, it, rdpg->rp_hash);
	if (rc == 0) {
		/*
		 * Iterator didn't find record with exactly the key requested.
		 *
		 * It is currently either
		 *
		 *     - positioned above record with key less than
		 *     requested---skip it.
		 *     - or not positioned at all (is in IAM_IT_SKEWED
		 *     state)---position it on the next item.
		 */
		rc = iops->next(env, it);
	} else if (rc > 0) {
		rc = 0;
	} else {
		if (rc == -ENODATA)
			rc = 0;
		GOTO(out, rc);
	}

	/*
	 * Fill containers one after the other. There might be multiple
	 * containers per physical page.
	 *
	 * At this point and across for-loop:
	 *  rc == 0 -> ok, proceed.
	 *  rc >  0 -> end of index.
	 *  rc <  0 -> error.
	 */
	for (pageidx = 0; rc == 0 && bytes > 0; pageidx++) {
		void *addr;
		union lu_page	*lp;
		int		 i;

		lp = addr = rdpg_page_get(rdpg, pageidx);
		/* fill lu pages */
		for (i = 0; i < LU_PAGE_COUNT; i++, lp++, bytes-=LU_PAGE_SIZE) {
			rc = filler(env, obj, lp,
				    min_t(size_t, bytes, LU_PAGE_SIZE),
				    iops, it, rdpg->rp_attrs, arg);
			if (rc < 0)
				break;
			/* one more lu_page */
			nlupgs++;
			if (rc > 0)
				/* end of index */
				break;
		}
		rdpg_page_put(rdpg, pageidx, addr);
	}

out:
	iops->put(env, it);
	iops->fini(env, it);

	if (rc >= 0)
		rc = min_t(size_t, nlupgs * LU_PAGE_SIZE, rdpg->rp_count);

	RETURN(rc);
}
EXPORT_SYMBOL(dt_index_walk);

/**
 * Walk key/record pairs of an index and copy them into 4KB containers to be
 * transferred over the network. This is the common handler for OBD_IDX_READ
 * RPC processing.
 *
 * \param env - is the environment passed by the caller
 * \param dev - is the dt_device storing the index
 * \param ii  - is the idx_info structure packed by the client in the
 *              OBD_IDX_READ request
 * \param rdpg - is the lu_rdpg descriptor
 *
 * \retval on success, return sum (in bytes) of all filled containers
 * \retval appropriate error otherwise.
 */
int dt_index_read(const struct lu_env *env, struct dt_device *dev,
		  struct idx_info *ii, const struct lu_rdpg *rdpg)
{
	const struct dt_index_features	*feat;
	struct dt_object		*obj;
	int				 rc;
	ENTRY;

	/*
	 * rp_count shouldn't be null and should be a multiple of the container
	 * size
	 */
	if (rdpg->rp_count == 0 || (rdpg->rp_count & (LU_PAGE_SIZE - 1)) != 0)
		RETURN(-EFAULT);

	if (!fid_is_quota(&ii->ii_fid) && !fid_is_layout_rbtree(&ii->ii_fid) &&
	    !fid_is_norm(&ii->ii_fid))
		RETURN(-EOPNOTSUPP);

	/* lookup index object subject to the transfer */
	obj = dt_locate(env, dev, &ii->ii_fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));
	if (dt_object_exists(obj) == 0)
		GOTO(out, rc = -ENOENT);

	/* fetch index features associated with index object */
	feat = dt_index_feat_select(fid_seq(&ii->ii_fid),
				    lu_object_attr(&obj->do_lu));
	if (IS_ERR(feat))
		GOTO(out, rc = PTR_ERR(feat));

	/* load index feature if not done already */
	if (obj->do_index_ops == NULL) {
		rc = obj->do_ops->do_index_try(env, obj, feat);
		if (rc)
			GOTO(out, rc);
	}

	/* fill ii_flags with supported index features */
	ii->ii_flags &= (II_FL_NOHASH | II_FL_NOKEY | II_FL_VARKEY |
			 II_FL_VARREC);

	if (!(feat->dif_flags & DT_IND_VARKEY))
		ii->ii_keysize = feat->dif_keysize_max;

	if (!(feat->dif_flags & DT_IND_VARREC))
		ii->ii_recsize = feat->dif_recsize_max;

	if (feat->dif_flags & DT_IND_NONUNQ)
		/* key isn't necessarily unique */
		ii->ii_flags |= II_FL_NONUNQ;

	if (!fid_is_layout_rbtree(&ii->ii_fid)) {
		dt_read_lock(env, obj, 0);
		/* fetch object version before walking the index */
		ii->ii_version = dt_version_get(env, obj);
	}

	/* walk the index and fill lu_idxpages with key/record pairs */
	rc = dt_index_walk(env, obj, rdpg, dt_index_page_build, ii);
	if (!fid_is_layout_rbtree(&ii->ii_fid))
		dt_read_unlock(env, obj);

	if (rc == 0) {
		/* index is empty */
		LASSERT(ii->ii_count == 0);
		ii->ii_hash_end = II_END_OFF;
	}

	/*
	 * For partial lu_idxpage filling of the end system page,
	 * init the header of the remain lu_idxpages.
	 */
	if (rc > 0)
		dt_index_page_adjust(rdpg->rp_pages, rdpg->rp_npages,
				     ii->ii_count);

	GOTO(out, rc);
out:
	dt_object_put(env, obj);
	return rc;
}
EXPORT_SYMBOL(dt_index_read);

#if PAGE_SIZE > LU_PAGE_SIZE
/*
 * For partial lu_idxpage filling of the end system page, init the header of the
 * remain lu_idxpages. So that the clients handle partial filling correctly.
 * Current lu_idxpage read clients are osp_it_next_page(),
 * nodemap_process_idx_pages() and qsd_reint_entries().
 */
void dt_index_page_adjust(struct page **pages, const u32 npages,
			  const size_t nlupgs)
{
	u32 nlupgs_mod = nlupgs % LU_PAGE_COUNT;

	if (nlupgs_mod) {
		void *kaddr = kmap_local_page(pages[pgidx]);
		struct lu_idxpage *lip;
		union lu_page *lp;
		u32 remain_nlupgs;
		u32 pgidx;
		int i;

		pgidx = nlupgs / LU_PAGE_COUNT;
		LASSERT(pgidx < npages);
		lp = kaddr;
		remain_nlupgs = LU_PAGE_COUNT - nlupgs_mod;

		/* initialize the header for the remain lu_pages */
		for (i = 0, lp += nlupgs_mod; i < remain_nlupgs; i++, lp++) {
			lip = &lp->lp_idx;
			memset(lip, 0, LIP_HDR_SIZE);
			lip->lip_magic = LIP_MAGIC;
		}

		kunmap_local(kaddr);
	}
}
#else
void dt_index_page_adjust(struct page **pages, const u32 npages,
			  const size_t nlupgs)
{
}
#endif
EXPORT_SYMBOL(dt_index_page_adjust);

static ssize_t uuid_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_device *lu = dt2lu_dev(dt);

	if (!lu->ld_obd)
		return -ENODEV;

	return scnprintf(buf, PAGE_SIZE, "%s\n", lu->ld_obd->obd_uuid.uuid);
}
LUSTRE_RO_ATTR(uuid);

static ssize_t blocksize_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%u\n", osfs.os_bsize);
}
LUSTRE_RO_ATTR(blocksize);

static ssize_t kbytestotal_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	u32 blk_size;
	u64 result;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	blk_size = osfs.os_bsize >> 10;
	result = osfs.os_blocks;

	while (blk_size >>= 1)
		result <<= 1;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", result);
}
LUSTRE_RO_ATTR(kbytestotal);

static ssize_t kbytesfree_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	u32 blk_size;
	u64 result;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	blk_size = osfs.os_bsize >> 10;
	result = osfs.os_bfree;

	while (blk_size >>= 1)
		result <<= 1;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", result);
}
LUSTRE_RO_ATTR(kbytesfree);

static ssize_t kbytesavail_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	u32 blk_size;
	u64 result;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	blk_size = osfs.os_bsize >> 10;
	result = osfs.os_bavail;

	while (blk_size >>= 1)
		result <<= 1;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", result);
}
LUSTRE_RO_ATTR(kbytesavail);

static ssize_t filestotal_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", osfs.os_files);
}
LUSTRE_RO_ATTR(filestotal);

static ssize_t filesfree_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", osfs.os_ffree);
}
LUSTRE_RO_ATTR(filesfree);

static ssize_t maxbytes_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", osfs.os_maxbytes);
}
LUSTRE_RO_ATTR(maxbytes);

static ssize_t namelen_max_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%u\n", osfs.os_namelen);
}
LUSTRE_RO_ATTR(namelen_max);

static ssize_t statfs_state_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct obd_statfs osfs;
	int rc;

	rc = dt_statfs(NULL, dt, &osfs);
	if (rc)
		return rc;

	return lprocfs_statfs_state(buf, PAGE_SIZE, osfs.os_state);
}
LUSTRE_RO_ATTR(statfs_state);

static const struct attribute *dt_def_attrs[] = {
	&lustre_attr_blocksize.attr,
	&lustre_attr_filestotal.attr,
	&lustre_attr_filesfree.attr,
	&lustre_attr_kbytestotal.attr,
	&lustre_attr_kbytesfree.attr,
	&lustre_attr_kbytesavail.attr,
	&lustre_attr_maxbytes.attr,
	&lustre_attr_namelen_max.attr,
	&lustre_attr_statfs_state.attr,
	&lustre_attr_uuid.attr,
	NULL,
};

static void dt_sysfs_release(struct kobject *kobj)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);

	debugfs_remove_recursive(dt->dd_debugfs_entry);
	dt->dd_debugfs_entry = NULL;

	complete(&dt->dd_kobj_unregister);
}

void dt_tunables_fini(struct dt_device *dt)
{
	if (!dt)
		return;

	if (dt->dd_def_attrs) {
		sysfs_remove_files(&dt->dd_kobj, dt->dd_def_attrs);
		kobject_put(&dt->dd_kobj);
		wait_for_completion(&dt->dd_kobj_unregister);
	}
}
EXPORT_SYMBOL(dt_tunables_fini);

int dt_tunables_init(struct dt_device *dt, struct obd_type *type,
		     const char *name, struct ldebugfs_vars *list)
{
	int rc;

	dt->dd_ktype.sysfs_ops = &lustre_sysfs_ops;
	dt->dd_ktype.release = dt_sysfs_release;

	init_completion(&dt->dd_kobj_unregister);
	rc = kobject_init_and_add(&dt->dd_kobj, &dt->dd_ktype, &type->typ_kobj,
				  "%s", name);
	if (rc)
		return rc;

	dt->dd_def_attrs = dt_def_attrs;

	rc = sysfs_create_files(&dt->dd_kobj, dt->dd_def_attrs);
	if (rc) {
		kobject_put(&dt->dd_kobj);
		dt->dd_def_attrs = NULL;
		return rc;
	}

	/*
	 * No need to register debugfs if no enteries. This allows us to
	 * choose between using dt_device or obd_device for debugfs.
	 */
	if (!list)
		return rc;

	dt->dd_debugfs_entry = debugfs_create_dir(name,
						 type->typ_debugfs_entry);
	ldebugfs_add_vars(dt->dd_debugfs_entry, list, dt);

	return rc;
}
EXPORT_SYMBOL(dt_tunables_init);
