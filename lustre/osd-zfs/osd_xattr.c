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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/osd_xattr.c
 * functions to manipulate extended attributes and system attributes
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <lustre_ver.h>
#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>

#include "osd_internal.h"

#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <sys/spa.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa_impl.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_prop.h>
#include <sys/sa_impl.h>
#include <sys/txg.h>

#include <linux/posix_acl_xattr.h>


int __osd_xattr_load(struct osd_device *osd, sa_handle_t *hdl, nvlist_t **sa)
{
	char	    *buf;
	int	     rc, size;

	rc = -sa_size(hdl, SA_ZPL_DXATTR(osd), &size);
	if (rc) {
		if (rc == -ENOENT)
			rc = -nvlist_alloc(sa, NV_UNIQUE_NAME, KM_SLEEP);
		goto out_sa;
	}

	buf = osd_zio_buf_alloc(size);
	if (buf == NULL) {
		rc = -ENOMEM;
		goto out_sa;
	}
	rc = -sa_lookup(hdl, SA_ZPL_DXATTR(osd), buf, size);
	if (rc == 0)
		rc = -nvlist_unpack(buf, size, sa, KM_SLEEP);
	osd_zio_buf_free(buf, size);
out_sa:

	return rc;
}

static inline int __osd_xattr_cache(struct osd_object *obj)
{
	LASSERT(obj->oo_sa_hdl);
	if (obj->oo_sa_xattr != NULL)
		return 0;
	return __osd_xattr_load(osd_obj2dev(obj),
				obj->oo_sa_hdl, &obj->oo_sa_xattr);
}

static int
__osd_sa_xattr_get(const struct lu_env *env, struct osd_object *obj,
		   const struct lu_buf *buf, const char *name, int *sizep)
{
	uchar_t *nv_value;
	int      rc = 0;

	rc = __osd_xattr_cache(obj);
	if (rc)
		return rc;

	LASSERT(obj->oo_sa_xattr);
	rc = -nvlist_lookup_byte_array(obj->oo_sa_xattr, name,
				       &nv_value, sizep);
	if (rc)
		return rc;

	if (buf == NULL || buf->lb_buf == NULL) {
		/* return the required size by *sizep */
		return 0;
	}

	if (*sizep > buf->lb_len)
		return -ERANGE; /* match ldiskfs error */

	memcpy(buf->lb_buf, nv_value, *sizep);
	return 0;
}

int __osd_xattr_get_large(const struct lu_env *env, struct osd_device *osd,
			  uint64_t xattr, struct lu_buf *buf,
			  const char *name, int *sizep)
{
	dnode_t		*xa_data_dn;
	sa_handle_t *sa_hdl = NULL;
	uint64_t	 xa_data_obj, size;
	int		 rc;

	/* are there any extended attributes? */
	if (xattr == ZFS_NO_OBJECT)
		return -ENOENT;

	/* Lookup the object number containing the xattr data */
	rc = -zap_lookup(osd->od_os, xattr, name, sizeof(uint64_t), 1,
			&xa_data_obj);
	if (rc)
		return rc;

	rc = __osd_obj2dnode(osd->od_os, xa_data_obj, &xa_data_dn);
	if (rc)
		return rc;

	rc = -sa_handle_get(osd->od_os, xa_data_obj, NULL, SA_HDL_PRIVATE,
			&sa_hdl);
	if (rc)
		goto out_rele;

	/* Get the xattr value length / object size */
	rc = -sa_lookup(sa_hdl, SA_ZPL_SIZE(osd), &size, 8);
	if (rc)
		goto out;

	if (size > INT_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}

	*sizep = (int)size;

	if (buf == NULL || buf->lb_buf == NULL) {
		/* We only need to return the required size */
		goto out;
	}
	if (*sizep > buf->lb_len) {
		rc = -ERANGE; /* match ldiskfs error */
		goto out;
	}

	rc = -dmu_read(osd->od_os, xa_data_dn->dn_object, 0,
			size, buf->lb_buf, DMU_READ_PREFETCH);

out:
	sa_handle_destroy(sa_hdl);
out_rele:
	osd_dnode_rele(xa_data_dn);

	return rc;
}

/**
 * Copy an extended attribute into the buffer provided, or compute
 * the required buffer size if \a buf is NULL.
 *
 * On success, the number of bytes used or required is stored in \a sizep.
 *
 * Note that no locking is done here.
 *
 * \param[in] env      execution environment
 * \param[in] obj      object for which to retrieve xattr
 * \param[out] buf     buffer to store xattr value in
 * \param[in] name     name of xattr to copy
 * \param[out] sizep   bytes used or required to store xattr
 *
 * \retval 0           on success
 * \retval negative    negated errno on failure
 */
int __osd_xattr_get(const struct lu_env *env, struct osd_object *obj,
		    struct lu_buf *buf, const char *name, int *sizep)
{
	int rc;

	if (unlikely(!dt_object_exists(&obj->oo_dt) || obj->oo_destroyed))
		return -ENOENT;

	/* check SA_ZPL_DXATTR first then fallback to directory xattr */
	rc = __osd_sa_xattr_get(env, obj, buf, name, sizep);
	if (rc != -ENOENT)
		return rc;

	return __osd_xattr_get_large(env, osd_obj2dev(obj), obj->oo_xattr,
				     buf, name, sizep);
}

int osd_xattr_get(const struct lu_env *env, struct dt_object *dt,
		  struct lu_buf *buf, const char *name)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	int                 rc, size = 0;
	ENTRY;

	LASSERT(obj->oo_dn != NULL);
	LASSERT(osd_invariant(obj));

	if (!osd_obj2dev(obj)->od_posix_acl &&
	    (strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) == 0 ||
	     strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
		RETURN(-EOPNOTSUPP);

	down_read(&obj->oo_guard);
	rc = __osd_xattr_get(env, obj, buf, name, &size);
	up_read(&obj->oo_guard);

	if (rc == -ENOENT)
		rc = -ENODATA;
	else if (rc == 0)
		rc = size;
	RETURN(rc);
}

/* the function is used to declare EAs when SA is not supported */
void __osd_xattr_declare_legacy(const struct lu_env *env,
				struct osd_object *obj,
				int vallen, const char *name,
				struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dmu_tx_t *tx = oh->ot_tx;
	uint64_t xa_data_obj;
	int rc;

	if (obj->oo_xattr == ZFS_NO_OBJECT) {
		/* xattr zap + entry */
		dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, TRUE, (char *) name);
		/* xattr value obj */
		dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, vallen);
		return;
	}

	rc = -zap_lookup(osd->od_os, obj->oo_xattr, name, sizeof(uint64_t), 1,
			&xa_data_obj);
	if (rc == 0) {
		/*
		 * Entry already exists.
		 * We'll truncate the existing object.
		 */
		dmu_tx_hold_bonus(tx, xa_data_obj);
		dmu_tx_hold_free(tx, xa_data_obj, vallen, DMU_OBJECT_END);
		dmu_tx_hold_write(tx, xa_data_obj, 0, vallen);
	} else if (rc == -ENOENT) {
		/*
		 * Entry doesn't exist, we need to create a new one and a new
		 * object to store the value.
		 */
		dmu_tx_hold_bonus(tx, obj->oo_xattr);
		dmu_tx_hold_zap(tx, obj->oo_xattr, TRUE, (char *) name);
		dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, vallen);
	}
}

void __osd_xattr_declare_set(const struct lu_env *env, struct osd_object *obj,
			     int vallen, const char *name,
			     struct osd_thandle *oh)
{
	dmu_tx_t *tx = oh->ot_tx;
	int bonuslen;

	if (unlikely(obj->oo_destroyed))
		return;

	if (unlikely(!osd_obj2dev(obj)->od_xattr_in_sa)) {
		__osd_xattr_declare_legacy(env, obj, vallen, name, oh);
		return;
	}

	/* declare EA in SA */
	if (dt_object_exists(&obj->oo_dt)) {
		LASSERT(obj->oo_sa_hdl);
		/* XXX: it should be possible to skip spill
		 * declaration if specific EA is part of
		 * bonus and doesn't grow */
		dmu_tx_hold_spill(tx, obj->oo_dn->dn_object);
		return;
	}

	bonuslen = osd_obj_bonuslen(obj);

	/* the object doesn't exist, but we've declared bonus
	 * in osd_declare_object_create() yet */
	if (obj->oo_ea_in_bonus > bonuslen) {
		/* spill has been declared already */
	} else if (obj->oo_ea_in_bonus + vallen > bonuslen) {
		/* we're about to exceed bonus, let's declare spill */
		dmu_tx_hold_spill(tx, DMU_NEW_OBJECT);
	}
	obj->oo_ea_in_bonus += vallen;
}

int osd_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, const char *name,
			  int fl, struct thandle *handle)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	ENTRY;

	LASSERT(handle != NULL);
	oh = container_of0(handle, struct osd_thandle, ot_super);

	down_read(&obj->oo_guard);
	__osd_xattr_declare_set(env, obj, buf->lb_len, name, oh);
	up_read(&obj->oo_guard);

	RETURN(0);
}

int __osd_sa_attr_init(const struct lu_env *env, struct osd_object *obj,
		       struct osd_thandle *oh)
{
	sa_bulk_attr_t	*bulk = osd_oti_get(env)->oti_attr_bulk;
	struct osa_attr	*osa = &osd_oti_get(env)->oti_osa;
	struct lu_buf *lb = &osd_oti_get(env)->oti_xattr_lbuf;
	struct osd_device *osd = osd_obj2dev(obj);
	uint64_t crtime[2], gen;
	timestruc_t now;
	size_t size;
	int rc, cnt;

	obj->oo_late_xattr = 0;
	obj->oo_late_attr_set = 0;

	gen = dmu_tx_get_txg(oh->ot_tx);
	gethrestime(&now);
	ZFS_TIME_ENCODE(&now, crtime);

	osa->atime[0] = obj->oo_attr.la_atime;
	osa->ctime[0] = obj->oo_attr.la_ctime;
	osa->mtime[0] = obj->oo_attr.la_mtime;
	osa->mode = obj->oo_attr.la_mode;
	osa->uid = obj->oo_attr.la_uid;
	osa->gid = obj->oo_attr.la_gid;
	osa->rdev = obj->oo_attr.la_rdev;
	osa->nlink = obj->oo_attr.la_nlink;
	osa->flags = attrs_fs2zfs(obj->oo_attr.la_flags);
	osa->size  = obj->oo_attr.la_size;
#ifdef ZFS_PROJINHERIT
	if (osd->od_projectused_dn) {
		if (obj->oo_attr.la_valid & LA_PROJID)
			osa->projid = obj->oo_attr.la_projid;
		else
			osa->projid = ZFS_DEFAULT_PROJID;
		osa->flags |= ZFS_PROJID;
		obj->oo_with_projid = 1;
	}
#endif

	cnt = 0;
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MODE(osd), NULL, &osa->mode, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_SIZE(osd), NULL, &osa->size, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_GEN(osd), NULL, &gen, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_UID(osd), NULL, &osa->uid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_GID(osd), NULL, &osa->gid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_PARENT(osd), NULL,
			 &obj->oo_parent, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_FLAGS(osd), NULL, &osa->flags, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_ATIME(osd), NULL, osa->atime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MTIME(osd), NULL, osa->mtime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CTIME(osd), NULL, osa->ctime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CRTIME(osd), NULL, crtime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_LINKS(osd), NULL, &osa->nlink, 8);
#ifdef ZFS_PROJINHERIT
	if (osd->od_projectused_dn)
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_PROJID(osd), NULL,
				 &osa->projid, 8);
#endif
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_RDEV(osd), NULL, &osa->rdev, 8);
	LASSERT(cnt <= ARRAY_SIZE(osd_oti_get(env)->oti_attr_bulk));

	/* Update the SA for additions, modifications, and removals. */
	rc = -nvlist_size(obj->oo_sa_xattr, &size, NV_ENCODE_XDR);
	if (rc)
		return rc;

	lu_buf_check_and_alloc(lb, size);
	if (lb->lb_buf == NULL) {
		CERROR("%s: can't allocate buffer for xattr update\n",
				osd->od_svname);
		return -ENOMEM;
	}

	rc = -nvlist_pack(obj->oo_sa_xattr, (char **)&lb->lb_buf, &size,
			  NV_ENCODE_XDR, KM_SLEEP);
	if (rc)
		return rc;

	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_DXATTR(osd), NULL, lb->lb_buf, size);

	rc = -sa_replace_all_by_template(obj->oo_sa_hdl, bulk, cnt, oh->ot_tx);

	return rc;
}

int __osd_sa_xattr_update(const struct lu_env *env, struct osd_object *obj,
			   struct osd_thandle *oh)
{
	struct lu_buf	  *lb = &osd_oti_get(env)->oti_xattr_lbuf;
	struct osd_device *osd = osd_obj2dev(obj);
	char              *dxattr;
	size_t             size;
	int                rc;

	obj->oo_late_xattr = 0;

	/* Update the SA for additions, modifications, and removals. */
	rc = -nvlist_size(obj->oo_sa_xattr, &size, NV_ENCODE_XDR);
	if (rc)
		return rc;

	lu_buf_check_and_alloc(lb, size);
	if (lb->lb_buf == NULL) {
		CERROR("%s: can't allocate buffer for xattr update\n",
				osd->od_svname);
		return -ENOMEM;
	}

	dxattr = lb->lb_buf;
	rc = -nvlist_pack(obj->oo_sa_xattr, &dxattr, &size,
			NV_ENCODE_XDR, KM_SLEEP);
	if (rc)
		return rc;
	LASSERT(dxattr == lb->lb_buf);

	sa_update(obj->oo_sa_hdl, SA_ZPL_DXATTR(osd), dxattr, size, oh->ot_tx);

	return 0;
}

/*
 * Set an extended attribute.
 * This transaction must have called udmu_xattr_declare_set() first.
 *
 * Returns 0 on success or a negative error number on failure.
 *
 * No locking is done here.
 */
int __osd_sa_xattr_schedule_update(const struct lu_env *env,
				   struct osd_object *obj,
				   struct osd_thandle *oh)
{
	ENTRY;
	LASSERT(obj->oo_sa_hdl);
	LASSERT(obj->oo_sa_xattr);

	/* schedule batched SA update in osd_object_sa_dirty_rele() */
	obj->oo_late_xattr = 1;
	osd_object_sa_dirty_add(obj, oh);

	RETURN(0);

}

int __osd_sa_xattr_set(const struct lu_env *env, struct osd_object *obj,
		       const struct lu_buf *buf, const char *name, int fl,
		       struct osd_thandle *oh)
{
	uchar_t *nv_value;
	size_t  size;
	int	nv_size;
	int	rc;
	int	too_big = 0;

	rc = __osd_xattr_cache(obj);
	if (rc)
		return rc;

	LASSERT(obj->oo_sa_xattr);
	/* Limited to 32k to keep nvpair memory allocations small */
	if (buf->lb_len > DXATTR_MAX_ENTRY_SIZE) {
		too_big = 1;
	} else {
		/* Prevent the DXATTR SA from consuming the entire SA
		 * region */
		rc = -nvlist_size(obj->oo_sa_xattr, &size, NV_ENCODE_XDR);
		if (rc)
			return rc;

		if (size + buf->lb_len > DXATTR_MAX_SA_SIZE)
			too_big = 1;
	}

	/* even in case of -EFBIG we must lookup xattr and check can we
	 * rewrite it then delete from SA */
	rc = -nvlist_lookup_byte_array(obj->oo_sa_xattr, name, &nv_value,
					&nv_size);
	if (rc == 0) {
		if (fl & LU_XATTR_CREATE) {
			return -EEXIST;
		} else if (too_big) {
			rc = -nvlist_remove(obj->oo_sa_xattr, name,
						DATA_TYPE_BYTE_ARRAY);
			if (rc < 0)
				return rc;
			rc = __osd_sa_xattr_schedule_update(env, obj, oh);
			return rc == 0 ? -EFBIG : rc;
		}
	} else if (rc == -ENOENT) {
		if (fl & LU_XATTR_REPLACE)
			return -ENODATA;
		else if (too_big)
			return -EFBIG;
	} else {
		return rc;
	}

	/* Ensure xattr doesn't exist in ZAP */
	if (obj->oo_xattr != ZFS_NO_OBJECT) {
		struct osd_device *osd = osd_obj2dev(obj);
		uint64_t           objid;
		rc = -zap_lookup(osd->od_os, obj->oo_xattr,
				 name, 8, 1, &objid);
		if (rc == 0) {
			rc = -dmu_object_free(osd->od_os, objid, oh->ot_tx);
			if (rc == 0)
				zap_remove(osd->od_os, obj->oo_xattr,
					   name, oh->ot_tx);
		}
	}

	rc = -nvlist_add_byte_array(obj->oo_sa_xattr, name,
				    (uchar_t *)buf->lb_buf, buf->lb_len);
	if (rc)
		return rc;

	/* batch updates only for just created dnodes where we
	 * used to set number of EAs in a single transaction */
	if (obj->oo_dn->dn_allocated_txg == oh->ot_tx->tx_txg)
		rc = __osd_sa_xattr_schedule_update(env, obj, oh);
	else
		rc = __osd_sa_xattr_update(env, obj, oh);

	return rc;
}

int
__osd_xattr_set(const struct lu_env *env, struct osd_object *obj,
		const struct lu_buf *buf, const char *name, int fl,
		struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dnode_t *xa_zap_dn = NULL;
	dnode_t *xa_data_dn = NULL;
	uint64_t           xa_data_obj;
	sa_handle_t       *sa_hdl = NULL;
	dmu_tx_t          *tx = oh->ot_tx;
	uint64_t           size;
	int                rc;

	LASSERT(obj->oo_sa_hdl);

	if (obj->oo_xattr == ZFS_NO_OBJECT) {
		struct lu_attr *la = &osd_oti_get(env)->oti_la;

		la->la_valid = LA_MODE;
		la->la_mode = S_IFDIR | S_IRUGO | S_IWUSR | S_IXUGO;
		rc = __osd_zap_create(env, osd, &xa_zap_dn, tx, la, 0, 0);
		if (rc)
			return rc;

		obj->oo_xattr = xa_zap_dn->dn_object;
		rc = osd_object_sa_update(obj, SA_ZPL_XATTR(osd),
				&obj->oo_xattr, 8, oh);
		if (rc)
			goto out;
	}

	rc = -zap_lookup(osd->od_os, obj->oo_xattr, name, sizeof(uint64_t), 1,
			 &xa_data_obj);
	if (rc == 0) {
		if (fl & LU_XATTR_CREATE) {
			rc = -EEXIST;
			goto out;
		}
		/*
		 * Entry already exists.
		 * We'll truncate the existing object.
		 */
		rc = __osd_obj2dnode(osd->od_os, xa_data_obj, &xa_data_dn);
		if (rc)
			goto out;

		rc = -sa_handle_get(osd->od_os, xa_data_obj, NULL,
					SA_HDL_PRIVATE, &sa_hdl);
		if (rc)
			goto out;

		rc = -sa_lookup(sa_hdl, SA_ZPL_SIZE(osd), &size, 8);
		if (rc)
			goto out_sa;

		rc = -dmu_free_range(osd->od_os, xa_data_dn->dn_object,
				     0, DMU_OBJECT_END, tx);
		if (rc)
			goto out_sa;
	} else if (rc == -ENOENT) {
		struct lu_attr *la = &osd_oti_get(env)->oti_la;
		/*
		 * Entry doesn't exist, we need to create a new one and a new
		 * object to store the value.
		 */
		if (fl & LU_XATTR_REPLACE) {
			/* should be ENOATTR according to the
			 * man, but that is undefined here */
			rc = -ENODATA;
			goto out;
		}

		la->la_valid = LA_MODE;
		la->la_mode = S_IFREG | S_IRUGO | S_IWUSR;
		rc = __osd_object_create(env, obj, &xa_data_dn, tx, la);
		if (rc)
			goto out;
		xa_data_obj = xa_data_dn->dn_object;

		rc = -sa_handle_get(osd->od_os, xa_data_obj, NULL,
					SA_HDL_PRIVATE, &sa_hdl);
		if (rc)
			goto out;

		rc = -zap_add(osd->od_os, obj->oo_xattr, name, sizeof(uint64_t),
				1, &xa_data_obj, tx);
		if (rc)
			goto out_sa;
	} else {
		/* There was an error looking up the xattr name */
		goto out;
	}

	/* Finally write the xattr value */
	dmu_write(osd->od_os, xa_data_obj, 0, buf->lb_len, buf->lb_buf, tx);

	size = buf->lb_len;
	rc = -sa_update(sa_hdl, SA_ZPL_SIZE(osd), &size, 8, tx);

out_sa:
	sa_handle_destroy(sa_hdl);
out:
	if (xa_data_dn != NULL)
		osd_dnode_rele(xa_data_dn);
	if (xa_zap_dn != NULL)
		osd_dnode_rele(xa_zap_dn);

	return rc;
}

int osd_xattr_set(const struct lu_env *env, struct dt_object *dt,
		  const struct lu_buf *buf, const char *name, int fl,
		  struct thandle *handle)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	int rc = 0;
	ENTRY;

	LASSERT(handle != NULL);
	LASSERT(osd_invariant(obj));

	if (!osd_obj2dev(obj)->od_posix_acl &&
	    (strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) == 0 ||
	     strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
		RETURN(-EOPNOTSUPP);

	oh = container_of0(handle, struct osd_thandle, ot_super);

	down_write(&obj->oo_guard);
	CDEBUG(D_INODE, "Setting xattr %s with size %d\n",
		name, (int)buf->lb_len);
	rc = osd_xattr_set_internal(env, obj, buf, name, fl, oh);
	up_write(&obj->oo_guard);

	RETURN(rc);
}

static void
__osd_xattr_declare_del(const struct lu_env *env, struct osd_object *obj,
			const char *name, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dmu_tx_t          *tx = oh->ot_tx;
	uint64_t           xa_data_obj;
	int                rc;

	/* update SA_ZPL_DXATTR if xattr was in SA */
	dmu_tx_hold_sa(tx, obj->oo_sa_hdl, 0);

	if (obj->oo_xattr == ZFS_NO_OBJECT)
		return;

	rc = -zap_lookup(osd->od_os, obj->oo_xattr, name, 8, 1, &xa_data_obj);
	if (rc == 0) {
		/*
		 * Entry exists.
		 * We'll delete the existing object and ZAP entry.
		 */
		dmu_tx_hold_bonus(tx, xa_data_obj);
		dmu_tx_hold_free(tx, xa_data_obj, 0, DMU_OBJECT_END);
		dmu_tx_hold_zap(tx, obj->oo_xattr, FALSE, (char *) name);
		return;
	} else if (rc == -ENOENT) {
		/*
		 * Entry doesn't exist, nothing to be changed.
		 */
		return;
	}

	/* An error happened */
	tx->tx_err = -rc;
}

int osd_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
			  const char *name, struct thandle *handle)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	ENTRY;

	LASSERT(handle != NULL);
	LASSERT(osd_invariant(obj));

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);
	LASSERT(obj->oo_dn != NULL);

	down_read(&obj->oo_guard);
	if (likely(dt_object_exists(&obj->oo_dt) && !obj->oo_destroyed))
		__osd_xattr_declare_del(env, obj, name, oh);
	up_read(&obj->oo_guard);

	RETURN(0);
}

static int __osd_sa_xattr_del(const struct lu_env *env, struct osd_object *obj,
			      const char *name, struct osd_thandle *oh)
{
	int rc;

	rc = __osd_xattr_cache(obj);
	if (rc)
		return rc;

	rc = -nvlist_remove(obj->oo_sa_xattr, name, DATA_TYPE_BYTE_ARRAY);
	if (rc == 0)
		rc = __osd_sa_xattr_schedule_update(env, obj, oh);
	return rc;
}

static int __osd_xattr_del(const struct lu_env *env, struct osd_object *obj,
			   const char *name, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	uint64_t           xa_data_obj;
	int                rc;

	if (unlikely(!dt_object_exists(&obj->oo_dt) || obj->oo_destroyed))
		return -ENOENT;

	/* try remove xattr from SA at first */
	rc = __osd_sa_xattr_del(env, obj, name, oh);
	if (rc != -ENOENT)
		return rc;

	if (obj->oo_xattr == ZFS_NO_OBJECT)
		return 0;

	rc = -zap_lookup(osd->od_os, obj->oo_xattr, name, sizeof(uint64_t), 1,
			&xa_data_obj);
	if (rc == -ENOENT) {
		rc = 0;
	} else if (rc == 0) {
		/*
		 * Entry exists.
		 * We'll delete the existing object and ZAP entry.
		 */
		rc = -dmu_object_free(osd->od_os, xa_data_obj, oh->ot_tx);
		if (rc)
			return rc;

		rc = -zap_remove(osd->od_os, obj->oo_xattr, name, oh->ot_tx);
	}

	return rc;
}

int osd_xattr_del(const struct lu_env *env, struct dt_object *dt,
		  const char *name, struct thandle *handle)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	int                 rc;
	ENTRY;

	LASSERT(handle != NULL);
	LASSERT(obj->oo_dn != NULL);
	LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt));
	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);

	if (!osd_obj2dev(obj)->od_posix_acl &&
	    (strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) == 0 ||
	     strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
		RETURN(-EOPNOTSUPP);

	down_write(&obj->oo_guard);
	rc = __osd_xattr_del(env, obj, name, oh);
	up_write(&obj->oo_guard);

	RETURN(rc);
}

void osd_declare_xattrs_destroy(const struct lu_env *env,
				struct osd_object *obj, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	zap_attribute_t	  *za = &osd_oti_get(env)->oti_za;
	uint64_t	   oid = obj->oo_xattr, xid;
	dmu_tx_t	  *tx = oh->ot_tx;
	zap_cursor_t	  *zc;
	int		   rc;

	if (oid == ZFS_NO_OBJECT)
		return; /* Nothing to do for SA xattrs */

	/* Declare to free the ZAP holding xattrs */
	dmu_tx_hold_free(tx, oid, 0, DMU_OBJECT_END);

	rc = osd_zap_cursor_init(&zc, osd->od_os, oid, 0);
	if (rc)
		goto out;

	while (zap_cursor_retrieve(zc, za) == 0) {
		LASSERT(za->za_num_integers == 1);
		LASSERT(za->za_integer_length == sizeof(uint64_t));

		rc = -zap_lookup(osd->od_os, oid, za->za_name,
				 sizeof(uint64_t), 1, &xid);
		if (rc) {
			CERROR("%s: xattr %s lookup failed: rc = %d\n",
			       osd->od_svname, za->za_name, rc);
			break;
		}
		dmu_tx_hold_free(tx, xid, 0, DMU_OBJECT_END);

		zap_cursor_advance(zc);
	}

	osd_zap_cursor_fini(zc);
out:
	if (rc && tx->tx_err == 0)
		tx->tx_err = -rc;
}

int osd_xattrs_destroy(const struct lu_env *env,
		       struct osd_object *obj, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dmu_tx_t	  *tx = oh->ot_tx;
	zap_attribute_t	  *za = &osd_oti_get(env)->oti_za;
	zap_cursor_t	  *zc;
	uint64_t	   xid;
	int		   rc;

	/* The transaction must have been assigned to a transaction group. */
	LASSERT(tx->tx_txg != 0);

	if (obj->oo_xattr == ZFS_NO_OBJECT)
		return 0; /* Nothing to do for SA xattrs */

	/* Free the ZAP holding the xattrs */
	rc = osd_zap_cursor_init(&zc, osd->od_os, obj->oo_xattr, 0);
	if (rc)
		return rc;

	while (zap_cursor_retrieve(zc, za) == 0) {
		LASSERT(za->za_num_integers == 1);
		LASSERT(za->za_integer_length == sizeof(uint64_t));

		rc = -zap_lookup(osd->od_os, obj->oo_xattr, za->za_name,
				 sizeof(uint64_t), 1, &xid);
		if (rc) {
			CERROR("%s: lookup xattr %s failed: rc = %d\n",
			       osd->od_svname, za->za_name, rc);
		} else {
			rc = -dmu_object_free(osd->od_os, xid, tx);
			if (rc)
				CERROR("%s: free xattr %s failed: rc = %d\n",
				       osd->od_svname, za->za_name, rc);
		}
		zap_cursor_advance(zc);
	}
	osd_zap_cursor_fini(zc);

	rc = -dmu_object_free(osd->od_os, obj->oo_xattr, tx);
	if (rc)
		CERROR("%s: free xattr %llu failed: rc = %d\n",
		       osd->od_svname, obj->oo_xattr, rc);

	return rc;
}

static int
osd_sa_xattr_list(const struct lu_env *env, struct osd_object *obj,
		  const struct lu_buf *lb)
{
	nvpair_t *nvp = NULL;
	int       len, counted = 0;
	int       rc = 0;

	rc = __osd_xattr_cache(obj);
	if (rc)
		return rc;

	while ((nvp = nvlist_next_nvpair(obj->oo_sa_xattr, nvp)) != NULL) {
		const char *name = nvpair_name(nvp);

		if (!osd_obj2dev(obj)->od_posix_acl &&
		    (strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) == 0 ||
		     strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
			continue;

		len = strlen(name);
		if (lb->lb_buf != NULL) {
			if (counted + len + 1 > lb->lb_len)
				return -ERANGE;

			memcpy(lb->lb_buf + counted, name, len + 1);
		}
		counted += len + 1;
	}
	return counted;
}

int osd_xattr_list(const struct lu_env *env, struct dt_object *dt,
		   const struct lu_buf *lb)
{
	struct osd_object      *obj = osd_dt_obj(dt);
	struct osd_device      *osd = osd_obj2dev(obj);
	zap_attribute_t	       *za = &osd_oti_get(env)->oti_za;
	zap_cursor_t           *zc;
	int                    rc, counted;
	ENTRY;

	LASSERT(obj->oo_dn != NULL);
	LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt));

	down_read(&obj->oo_guard);

	rc = osd_sa_xattr_list(env, obj, lb);
	if (rc < 0)
		GOTO(out, rc);

	counted = rc;

	/* continue with dnode xattr if any */
	if (obj->oo_xattr == ZFS_NO_OBJECT)
		GOTO(out, rc = counted);

	rc = osd_zap_cursor_init(&zc, osd->od_os, obj->oo_xattr, 0);
	if (rc)
		GOTO(out, rc);

	while ((rc = -zap_cursor_retrieve(zc, za)) == 0) {
		if (!osd_obj2dev(obj)->od_posix_acl &&
		    (strcmp(za->za_name, XATTR_NAME_POSIX_ACL_ACCESS) == 0 ||
		     strcmp(za->za_name, XATTR_NAME_POSIX_ACL_DEFAULT) == 0)) {
			zap_cursor_advance(zc);
			continue;
		}

		rc = strlen(za->za_name);
		if (lb->lb_buf != NULL) {
			if (counted + rc + 1 > lb->lb_len)
				GOTO(out_fini, rc = -ERANGE);

			memcpy(lb->lb_buf + counted, za->za_name, rc + 1);
		}
		counted += rc + 1;

		zap_cursor_advance(zc);
	}
	if (rc == -ENOENT) /* no more kes in the index */
		rc = 0;
	else if (unlikely(rc < 0))
		GOTO(out_fini, rc);
	rc = counted;

out_fini:
	osd_zap_cursor_fini(zc);
out:
	up_read(&obj->oo_guard);
	RETURN(rc);

}
