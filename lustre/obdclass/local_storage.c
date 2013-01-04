/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * lustre/obdclass/local_storage.c
 *
 * Local storage for file/objects with fid generation. Works on top of OSD.
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include "local_storage.h"

/* all initialized local storages on this node are linked on this */
static CFS_LIST_HEAD(ls_list_head);
static DEFINE_MUTEX(ls_list_mutex);

static int ls_object_init(const struct lu_env *env, struct lu_object *o,
			  const struct lu_object_conf *unused)
{
	struct ls_device	*ls;
	struct lu_object	*below;
	struct lu_device	*under;

	ENTRY;

	ls = container_of0(o->lo_dev, struct ls_device, ls_top_dev.dd_lu_dev);
	under = &ls->ls_osd->dd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
	if (below == NULL)
		RETURN(-ENOMEM);

	lu_object_add(o, below);

	RETURN(0);
}

static void ls_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct ls_object	*obj = lu2ls_obj(o);
	struct lu_object_header	*h = o->lo_header;

	dt_object_fini(&obj->ls_obj);
	lu_object_header_fini(h);
	OBD_FREE_PTR(obj);
}

struct lu_object_operations ls_lu_obj_ops = {
	.loo_object_init  = ls_object_init,
	.loo_object_free  = ls_object_free,
};

struct lu_object *ls_object_alloc(const struct lu_env *env,
				  const struct lu_object_header *_h,
				  struct lu_device *d)
{
	struct lu_object_header	*h;
	struct ls_object	*o;
	struct lu_object	*l;

	LASSERT(_h == NULL);

	OBD_ALLOC_PTR(o);
	if (o != NULL) {
		l = &o->ls_obj.do_lu;
		h = &o->ls_header;

		lu_object_header_init(h);
		dt_object_init(&o->ls_obj, h, d);
		lu_object_add_top(h, l);

		l->lo_ops = &ls_lu_obj_ops;

		return l;
	} else {
		return NULL;
	}
}

static struct lu_device_operations ls_lu_dev_ops = {
	.ldo_object_alloc =	ls_object_alloc
};

static struct ls_device *__ls_find_dev(struct dt_device *dev)
{
	struct ls_device *ls, *ret = NULL;

	cfs_list_for_each_entry(ls, &ls_list_head, ls_linkage) {
		if (ls->ls_osd == dev) {
			cfs_atomic_inc(&ls->ls_refcount);
			ret = ls;
			break;
		}
	}
	return ret;
}

struct ls_device *ls_find_dev(struct dt_device *dev)
{
	struct ls_device *ls;

	mutex_lock(&ls_list_mutex);
	ls = __ls_find_dev(dev);
	mutex_unlock(&ls_list_mutex);

	return ls;
}

static struct lu_device_type_operations ls_device_type_ops = {
	.ldto_start = NULL,
	.ldto_stop  = NULL,
};

static struct lu_device_type ls_lu_type = {
	.ldt_name = "local_storage",
	.ldt_ops  = &ls_device_type_ops,
};

struct ls_device *ls_device_get(struct dt_device *dev)
{
	struct ls_device *ls;

	ENTRY;

	mutex_lock(&ls_list_mutex);
	ls = __ls_find_dev(dev);
	if (ls)
		GOTO(out_ls, ls);

	/* not found, then create */
	OBD_ALLOC_PTR(ls);
	if (ls == NULL)
		GOTO(out_ls, ls = ERR_PTR(-ENOMEM));

	cfs_atomic_set(&ls->ls_refcount, 1);
	CFS_INIT_LIST_HEAD(&ls->ls_los_list);
	mutex_init(&ls->ls_los_mutex);

	ls->ls_osd = dev;

	LASSERT(dev->dd_lu_dev.ld_site);
	lu_device_init(&ls->ls_top_dev.dd_lu_dev, &ls_lu_type);
	ls->ls_top_dev.dd_lu_dev.ld_ops = &ls_lu_dev_ops;
	ls->ls_top_dev.dd_lu_dev.ld_site = dev->dd_lu_dev.ld_site;

	/* finally add ls to the list */
	cfs_list_add(&ls->ls_linkage, &ls_list_head);
out_ls:
	mutex_unlock(&ls_list_mutex);
	RETURN(ls);
}

void ls_device_put(const struct lu_env *env, struct ls_device *ls)
{
	LASSERT(env);
	if (!cfs_atomic_dec_and_test(&ls->ls_refcount))
		return;

	mutex_lock(&ls_list_mutex);
	if (cfs_atomic_read(&ls->ls_refcount) == 0) {
		LASSERT(cfs_list_empty(&ls->ls_los_list));
		cfs_list_del(&ls->ls_linkage);
		lu_site_purge(env, ls->ls_top_dev.dd_lu_dev.ld_site, ~0);
		lu_device_fini(&ls->ls_top_dev.dd_lu_dev);
		OBD_FREE_PTR(ls);
	}
	mutex_unlock(&ls_list_mutex);
}

/**
 * local file fid generation
 */
int local_object_fid_generate(const struct lu_env *env,
			      struct local_oid_storage *los,
			      struct lu_fid *fid)
{
	LASSERT(los->los_dev);
	LASSERT(los->los_obj);

	/* take next OID */

	/* to make it unique after reboot we store
	 * the latest generated fid atomically with
	 * object creation see local_object_create() */

	mutex_lock(&los->los_id_lock);
	fid->f_seq = los->los_seq;
	fid->f_oid = los->los_last_oid++;
	fid->f_ver = 0;
	mutex_unlock(&los->los_id_lock);

	return 0;
}

int local_object_declare_create(const struct lu_env *env,
				struct local_oid_storage *los,
				struct dt_object *o, struct lu_attr *attr,
				struct dt_object_format *dof,
				struct thandle *th)
{
	struct dt_thread_info	*dti = dt_info(env);
	int			 rc;

	ENTRY;

	/* update fid generation file */
	if (los != NULL) {
		LASSERT(dt_object_exists(los->los_obj));
		rc = dt_declare_record_write(env, los->los_obj,
					     sizeof(struct los_ondisk), 0, th);
		if (rc)
			RETURN(rc);
	}

	rc = dt_declare_create(env, o, attr, NULL, dof, th);
	if (rc)
		RETURN(rc);

	dti->dti_lb.lb_buf = NULL;
	dti->dti_lb.lb_len = sizeof(dti->dti_lma);
	rc = dt_declare_xattr_set(env, o, &dti->dti_lb, XATTR_NAME_LMA, 0, th);

	RETURN(rc);
}

int local_object_create(const struct lu_env *env,
			struct local_oid_storage *los,
			struct dt_object *o, struct lu_attr *attr,
			struct dt_object_format *dof, struct thandle *th)
{
	struct dt_thread_info	*dti = dt_info(env);
	struct los_ondisk	 losd;
	int			 rc;

	ENTRY;

	rc = dt_create(env, o, attr, NULL, dof, th);
	if (rc)
		RETURN(rc);

	lustre_lma_init(&dti->dti_lma, lu_object_fid(&o->do_lu));
	lustre_lma_swab(&dti->dti_lma);
	dti->dti_lb.lb_buf = &dti->dti_lma;
	dti->dti_lb.lb_len = sizeof(dti->dti_lma);
	rc = dt_xattr_set(env, o, &dti->dti_lb, XATTR_NAME_LMA, 0, th,
			  BYPASS_CAPA);

	if (los == NULL)
		RETURN(rc);

	LASSERT(los->los_obj);
	LASSERT(dt_object_exists(los->los_obj));

	/* many threads can be updated this, serialize
	 * them here to avoid the race where one thread
	 * takes the value first, but writes it last */
	mutex_lock(&los->los_id_lock);

	/* update local oid number on disk so that
	 * we know the last one used after reboot */
	losd.lso_magic = cpu_to_le32(LOS_MAGIC);
	losd.lso_next_oid = cpu_to_le32(los->los_last_oid);

	dti->dti_off = 0;
	dti->dti_lb.lb_buf = &losd;
	dti->dti_lb.lb_len = sizeof(losd);
	rc = dt_record_write(env, los->los_obj, &dti->dti_lb, &dti->dti_off,
			     th);
	mutex_unlock(&los->los_id_lock);

	RETURN(rc);
}

/*
 * Create local named object (file, directory or index) in parent directory.
 */
struct dt_object *__local_file_create(const struct lu_env *env,
				      const struct lu_fid *fid,
				      struct local_oid_storage *los,
				      struct ls_device *ls,
				      struct dt_object *parent,
				      const char *name, struct lu_attr *attr,
				      struct dt_object_format *dof)
{
	struct dt_thread_info	*dti = dt_info(env);
	struct dt_object	*dto;
	struct thandle		*th;
	int			 rc;

	dto = ls_locate(env, ls, fid);
	if (unlikely(IS_ERR(dto)))
		RETURN(dto);

	LASSERT(dto != NULL);
	if (dt_object_exists(dto))
		GOTO(out, rc = -EEXIST);

	th = dt_trans_create(env, ls->ls_osd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = local_object_declare_create(env, los, dto, attr, dof, th);
	if (rc)
		GOTO(trans_stop, rc);

	if (dti->dti_dof.dof_type == DFT_DIR) {
		dt_declare_ref_add(env, dto, th);
		dt_declare_ref_add(env, parent, th);
	}

	rc = dt_declare_insert(env, parent, (void *)fid, (void *)name, th);
	if (rc)
		GOTO(trans_stop, rc);

	rc = dt_trans_start_local(env, ls->ls_osd, th);
	if (rc)
		GOTO(trans_stop, rc);

	dt_write_lock(env, dto, 0);
	if (dt_object_exists(dto))
		GOTO(unlock, rc = 0);

	CDEBUG(D_OTHER, "create new object "DFID"\n",
	       PFID(lu_object_fid(&dto->do_lu)));
	rc = local_object_create(env, los, dto, attr, dof, th);
	if (rc)
		GOTO(unlock, rc);
	LASSERT(dt_object_exists(dto));

	if (dti->dti_dof.dof_type == DFT_DIR) {
		if (!dt_try_as_dir(env, dto))
			GOTO(destroy, rc = -ENOTDIR);
		/* Add "." and ".." for newly created dir */
		rc = dt_insert(env, dto, (void *)fid, (void *)".", th,
			       BYPASS_CAPA, 1);
		if (rc)
			GOTO(destroy, rc);
		dt_ref_add(env, dto, th);
		rc = dt_insert(env, dto, (void *)lu_object_fid(&parent->do_lu),
			       (void *)"..", th, BYPASS_CAPA, 1);
		if (rc)
			GOTO(destroy, rc);
	}

	dt_write_lock(env, parent, 0);
	rc = dt_insert(env, parent, (const struct dt_rec *)fid,
		       (const struct dt_key *)name, th, BYPASS_CAPA, 1);
	if (dti->dti_dof.dof_type == DFT_DIR)
		dt_ref_add(env, parent, th);
	dt_write_unlock(env, parent);
	if (rc)
		GOTO(destroy, rc);
destroy:
	if (rc)
		dt_destroy(env, dto, th);
unlock:
	dt_write_unlock(env, dto);
trans_stop:
	dt_trans_stop(env, ls->ls_osd, th);
out:
	if (rc) {
		lu_object_put_nocache(env, &dto->do_lu);
		dto = ERR_PTR(rc);
	} else {
		struct lu_fid dti_fid;
		/* since local files FIDs are not in OI the directory entry
		 * is used to get inode number/generation, we need to do lookup
		 * again to cache this data after create */
		rc = dt_lookup_dir(env, parent, name, &dti_fid);
		LASSERT(rc == 0);
	}
	RETURN(dto);
}

/*
 * Look up and create (if it does not exist) a local named file or directory in
 * parent directory.
 */
struct dt_object *local_file_find_or_create(const struct lu_env *env,
					    struct local_oid_storage *los,
					    struct dt_object *parent,
					    const char *name, __u32 mode)
{
	struct dt_thread_info	*dti = dt_info(env);
	struct dt_object	*dto;
	int			 rc;

	LASSERT(parent);

	rc = dt_lookup_dir(env, parent, name, &dti->dti_fid);
	if (rc == 0)
		/* name is found, get the object */
		dto = ls_locate(env, dt2ls_dev(los->los_dev), &dti->dti_fid);
	else if (rc != -ENOENT)
		dto = ERR_PTR(rc);
	else {
		rc = local_object_fid_generate(env, los, &dti->dti_fid);
		if (rc < 0) {
			dto = ERR_PTR(rc);
		} else {
			/* create the object */
			dti->dti_attr.la_valid	= LA_MODE;
			dti->dti_attr.la_mode	= mode;
			dti->dti_dof.dof_type	= dt_mode_to_dft(mode & S_IFMT);
			dto = __local_file_create(env, &dti->dti_fid, los,
						  dt2ls_dev(los->los_dev),
						  parent, name, &dti->dti_attr,
						  &dti->dti_dof);
		}
	}
	return dto;
}
EXPORT_SYMBOL(local_file_find_or_create);

struct dt_object *local_file_find_or_create_with_fid(const struct lu_env *env,
						     struct dt_device *dt,
						     const struct lu_fid *fid,
						     struct dt_object *parent,
						     const char *name,
						     __u32 mode)
{
	struct dt_thread_info	*dti = dt_info(env);
	struct dt_object	*dto;
	int			 rc;

	LASSERT(parent);

	rc = dt_lookup_dir(env, parent, name, &dti->dti_fid);
	if (rc == 0) {
		/* name is found, get the object */
		if (!lu_fid_eq(fid, &dti->dti_fid))
			dto = ERR_PTR(-EINVAL);
		else
			dto = dt_locate(env, dt, fid);
	} else if (rc != -ENOENT) {
		dto = ERR_PTR(rc);
	} else {
		struct ls_device *ls;

		ls = ls_device_get(dt);
		if (IS_ERR(ls)) {
			dto = ERR_PTR(PTR_ERR(ls));
		} else {
			/* create the object */
			dti->dti_attr.la_valid	= LA_MODE;
			dti->dti_attr.la_mode	= mode;
			dti->dti_dof.dof_type	= dt_mode_to_dft(mode & S_IFMT);
			dto = __local_file_create(env, fid, NULL, ls, parent,
						  name, &dti->dti_attr,
						  &dti->dti_dof);
			/* ls_device_put() will finalize the ls device, we
			 * have to open the object in other device stack */
			if (!IS_ERR(dto)) {
				dti->dti_fid = dto->do_lu.lo_header->loh_fid;
				lu_object_put_nocache(env, &dto->do_lu);
				dto = dt_locate(env, dt, &dti->dti_fid);
			}
			ls_device_put(env, ls);
		}
	}
	return dto;
}
EXPORT_SYMBOL(local_file_find_or_create_with_fid);

/*
 * Look up and create (if it does not exist) a local named index file in parent
 * directory.
 */
struct dt_object *local_index_find_or_create(const struct lu_env *env,
					     struct local_oid_storage *los,
					     struct dt_object *parent,
					     const char *name, __u32 mode,
					     const struct dt_index_features *ft)
{
	struct dt_thread_info	*dti = dt_info(env);
	struct dt_object	*dto;
	int			 rc;

	LASSERT(parent);

	rc = dt_lookup_dir(env, parent, name, &dti->dti_fid);
	if (rc == 0) {
		/* name is found, get the object */
		dto = ls_locate(env, dt2ls_dev(los->los_dev), &dti->dti_fid);
	} else if (rc != -ENOENT) {
		dto = ERR_PTR(rc);
	} else {
		rc = local_object_fid_generate(env, los, &dti->dti_fid);
		if (rc < 0) {
			dto = ERR_PTR(rc);
		} else {
			/* create the object */
			dti->dti_attr.la_valid		= LA_MODE;
			dti->dti_attr.la_mode		= mode;
			dti->dti_dof.dof_type		= DFT_INDEX;
			dti->dti_dof.u.dof_idx.di_feat	= ft;
			dto = __local_file_create(env, &dti->dti_fid, los,
						  dt2ls_dev(los->los_dev),
						  parent, name, &dti->dti_attr,
						  &dti->dti_dof);
		}
	}
	return dto;

}
EXPORT_SYMBOL(local_index_find_or_create);

struct dt_object *
local_index_find_or_create_with_fid(const struct lu_env *env,
				    struct dt_device *dt,
				    const struct lu_fid *fid,
				    struct dt_object *parent,
				    const char *name, __u32 mode,
				    const struct dt_index_features *ft)
{
	struct dt_thread_info	*dti = dt_info(env);
	struct dt_object	*dto;
	int			 rc;

	LASSERT(parent);

	rc = dt_lookup_dir(env, parent, name, &dti->dti_fid);
	if (rc == 0) {
		/* name is found, get the object */
		if (!lu_fid_eq(fid, &dti->dti_fid))
			dto = ERR_PTR(-EINVAL);
		else
			dto = dt_locate(env, dt, fid);
	} else if (rc != -ENOENT) {
		dto = ERR_PTR(rc);
	} else {
		struct ls_device *ls;

		ls = ls_device_get(dt);
		if (IS_ERR(ls)) {
			dto = ERR_PTR(PTR_ERR(ls));
		} else {
			/* create the object */
			dti->dti_attr.la_valid		= LA_MODE;
			dti->dti_attr.la_mode		= mode;
			dti->dti_dof.dof_type		= DFT_INDEX;
			dti->dti_dof.u.dof_idx.di_feat  = ft;
			dto = __local_file_create(env, fid, NULL, ls, parent,
						  name, &dti->dti_attr,
						  &dti->dti_dof);
			/* ls_device_put() will finalize the ls device, we
			 * have to open the object in other device stack */
			if (!IS_ERR(dto)) {
				dti->dti_fid = dto->do_lu.lo_header->loh_fid;
				lu_object_put_nocache(env, &dto->do_lu);
				dto = dt_locate(env, dt, &dti->dti_fid);
			}
			ls_device_put(env, ls);
		}
	}
	return dto;
}
EXPORT_SYMBOL(local_index_find_or_create_with_fid);

struct local_oid_storage *dt_los_find(struct ls_device *ls, __u64 seq)
{
	struct local_oid_storage *los, *ret = NULL;

	cfs_list_for_each_entry(los, &ls->ls_los_list, los_list) {
		if (los->los_seq == seq) {
			cfs_atomic_inc(&los->los_refcount);
			ret = los;
			break;
		}
	}
	return ret;
}

void dt_los_put(struct local_oid_storage *los)
{
	if (cfs_atomic_dec_and_test(&los->los_refcount))
		/* should never happen, only local_oid_storage_fini should
		 * drop refcount to zero */
		LBUG();
	return;
}

/**
 * Initialize local OID storage for required sequence.
 * That may be needed for services that uses local files and requires
 * dynamic OID allocation for them.
 *
 * Per each sequence we have an object with 'first_fid' identificator
 * containing the counter for OIDs of locally created files with that
 * sequence.
 *
 * It is used now by llog subsystem and MGS for NID tables
 *
 * Function gets first_fid to create counter object.
 * All dynamic fids will be generated with the same sequence and incremented
 * OIDs
 *
 * Returned local_oid_storage is in-memory representaion of OID storage
 */
int local_oid_storage_init(const struct lu_env *env, struct dt_device *dev,
			   const struct lu_fid *first_fid,
			   struct local_oid_storage **los)
{
	struct dt_thread_info	*dti = dt_info(env);
	struct ls_device	*ls;
	struct los_ondisk	 losd;
	struct dt_object	*root = NULL;
	struct dt_object	*o = NULL;
	struct thandle		*th;
	int			 rc;

	ENTRY;

	ls = ls_device_get(dev);
	if (IS_ERR(ls))
		RETURN(PTR_ERR(ls));

	mutex_lock(&ls->ls_los_mutex);
	*los = dt_los_find(ls, fid_seq(first_fid));
	if (*los != NULL)
		GOTO(out, rc = 0);

	/* not found, then create */
	OBD_ALLOC_PTR(*los);
	if (*los == NULL)
		GOTO(out, rc = -ENOMEM);

	cfs_atomic_set(&(*los)->los_refcount, 1);
	mutex_init(&(*los)->los_id_lock);
	(*los)->los_dev = &ls->ls_top_dev;
	cfs_atomic_inc(&ls->ls_refcount);
	cfs_list_add(&(*los)->los_list, &ls->ls_los_list);

	rc = dt_root_get(env, dev, &dti->dti_fid);
	if (rc)
		GOTO(out_los, rc);

	root = ls_locate(env, ls, &dti->dti_fid);
	if (IS_ERR(root))
		GOTO(out_los, rc = PTR_ERR(root));

	snprintf(dti->dti_buf, sizeof(dti->dti_buf), "seq-%Lx-lastid",
		 fid_seq(first_fid));
	rc = dt_lookup_dir(env, root, dti->dti_buf, &dti->dti_fid);
	if (rc != 0 && rc != -ENOENT)
		GOTO(out_los, rc);

	/* initialize data allowing to generate new fids,
	 * literally we need a sequence */
	if (rc == 0)
		o = ls_locate(env, ls, &dti->dti_fid);
	else
		o = ls_locate(env, ls, first_fid);
	if (IS_ERR(o))
		GOTO(out_los, rc = PTR_ERR(o));

	dt_write_lock(env, o, 0);
	if (!dt_object_exists(o)) {
		LASSERT(rc == -ENOENT);

		th = dt_trans_create(env, dev);
		if (IS_ERR(th))
			GOTO(out_lock, rc = PTR_ERR(th));

		dti->dti_attr.la_valid = LA_MODE | LA_TYPE;
		dti->dti_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
		dti->dti_dof.dof_type = dt_mode_to_dft(S_IFREG);

		rc = dt_declare_create(env, o, &dti->dti_attr, NULL,
				       &dti->dti_dof, th);
		if (rc)
			GOTO(out_trans, rc);

		rc = dt_declare_insert(env, root,
				       (const struct dt_rec *)lu_object_fid(&o->do_lu),
				       (const struct dt_key *)dti->dti_buf,
				       th);
		if (rc)
			GOTO(out_trans, rc);

		dti->dti_lb.lb_buf = NULL;
		dti->dti_lb.lb_len = sizeof(dti->dti_lma);
		rc = dt_declare_xattr_set(env, o, &dti->dti_lb, XATTR_NAME_LMA,
					  0, th);
		if (rc)
			GOTO(out_trans, rc);

		rc = dt_declare_record_write(env, o, sizeof(losd), 0, th);
		if (rc)
			GOTO(out_trans, rc);

		rc = dt_trans_start_local(env, dev, th);
		if (rc)
			GOTO(out_trans, rc);

		LASSERT(!dt_object_exists(o));
		rc = dt_create(env, o, &dti->dti_attr, NULL, &dti->dti_dof, th);
		if (rc)
			GOTO(out_trans, rc);
		LASSERT(dt_object_exists(o));

		lustre_lma_init(&dti->dti_lma, lu_object_fid(&o->do_lu));
		lustre_lma_swab(&dti->dti_lma);
		dti->dti_lb.lb_buf = &dti->dti_lma;
		dti->dti_lb.lb_len = sizeof(dti->dti_lma);
		rc = dt_xattr_set(env, o, &dti->dti_lb, XATTR_NAME_LMA, 0,
				  th, BYPASS_CAPA);
		if (rc)
			GOTO(out_trans, rc);

		losd.lso_magic = cpu_to_le32(LOS_MAGIC);
		losd.lso_next_oid = cpu_to_le32(fid_oid(first_fid) + 1);

		dti->dti_off = 0;
		dti->dti_lb.lb_buf = &losd;
		dti->dti_lb.lb_len = sizeof(losd);
		rc = dt_record_write(env, o, &dti->dti_lb, &dti->dti_off, th);
		if (rc)
			GOTO(out_trans, rc);
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 3, 90, 0)
#error "fix this before release"
#endif
		/*
		 * there is one technical debt left in Orion:
		 * proper hanlding of named vs no-name objects.
		 * Llog objects have name always as they are placed in O/d/...
		 */
		if (fid_seq(lu_object_fid(&o->do_lu)) != FID_SEQ_LLOG) {
			rc = dt_insert(env, root,
				       (const struct dt_rec *)first_fid,
				       (const struct dt_key *)dti->dti_buf,
				       th, BYPASS_CAPA, 1);
			if (rc)
				GOTO(out_trans, rc);
		}
out_trans:
		dt_trans_stop(env, dev, th);
	} else {
		dti->dti_off = 0;
		dti->dti_lb.lb_buf = &losd;
		dti->dti_lb.lb_len = sizeof(losd);
		rc = dt_record_read(env, o, &dti->dti_lb, &dti->dti_off);
		if (rc == 0 && le32_to_cpu(losd.lso_magic) != LOS_MAGIC) {
			CERROR("local storage file "DFID" is corrupted\n",
			       PFID(first_fid));
			rc = -EINVAL;
		}
	}
out_lock:
	dt_write_unlock(env, o);
out_los:
	if (root != NULL && !IS_ERR(root))
		lu_object_put_nocache(env, &root->do_lu);

	if (rc != 0) {
		cfs_list_del(&(*los)->los_list);
		cfs_atomic_dec(&ls->ls_refcount);
		OBD_FREE_PTR(*los);
		*los = NULL;
		if (o != NULL && !IS_ERR(o))
			lu_object_put_nocache(env, &o->do_lu);
	} else {
		(*los)->los_seq = fid_seq(first_fid);
		(*los)->los_last_oid = le32_to_cpu(losd.lso_next_oid);
		(*los)->los_obj = o;
	}
out:
	mutex_unlock(&ls->ls_los_mutex);
	ls_device_put(env, ls);
	return rc;
}
EXPORT_SYMBOL(local_oid_storage_init);

void local_oid_storage_fini(const struct lu_env *env,
                            struct local_oid_storage *los)
{
	struct ls_device *ls;

	if (!cfs_atomic_dec_and_test(&los->los_refcount))
		return;

	LASSERT(env);
	LASSERT(los->los_dev);
	ls = dt2ls_dev(los->los_dev);

	mutex_lock(&ls->ls_los_mutex);
	if (cfs_atomic_read(&los->los_refcount) == 0) {
		if (los->los_obj)
			lu_object_put_nocache(env, &los->los_obj->do_lu);
		cfs_list_del(&los->los_list);
		OBD_FREE_PTR(los);
	}
	mutex_unlock(&ls->ls_los_mutex);
	ls_device_put(env, ls);
}
EXPORT_SYMBOL(local_oid_storage_fini);
