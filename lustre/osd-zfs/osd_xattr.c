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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, 2013, Intel Corporation.
 * Use is subject to license terms.
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

/*
 * Copy an extended attribute into the buffer provided, or compute the
 * required buffer size.
 *
 * If buf is NULL, it computes the required buffer size.
 *
 * Returns 0 on success or a negative error number on failure.
 * On success, the number of bytes used / required is stored in 'size'.
 *
 * No locking is done here.
 */
int __osd_xattr_load(udmu_objset_t *uos, uint64_t dnode, nvlist_t **sa_xattr)
{
	sa_handle_t *sa_hdl;
	char	    *buf;
	int	     rc, size;

	if (unlikely(dnode == ZFS_NO_OBJECT))
		return -ENOENT;

	rc = -sa_handle_get(uos->os, dnode, NULL, SA_HDL_PRIVATE, &sa_hdl);
	if (rc)
		return rc;

	rc = -sa_size(sa_hdl, SA_ZPL_DXATTR(uos), &size);
	if (rc) {
		if (rc == -ENOENT)
			rc = -nvlist_alloc(sa_xattr, NV_UNIQUE_NAME, KM_SLEEP);
		goto out_sa;
	}

	buf = sa_spill_alloc(KM_SLEEP);
	if (buf == NULL) {
		rc = -ENOMEM;
		goto out_sa;
	}
	rc = -sa_lookup(sa_hdl, SA_ZPL_DXATTR(uos), buf, size);
	if (rc == 0)
		rc = -nvlist_unpack(buf, size, sa_xattr, KM_SLEEP);
	sa_spill_free(buf);
out_sa:
	sa_handle_destroy(sa_hdl);

	return rc;
}

static inline int __osd_xattr_cache(const struct lu_env *env,
				    struct osd_object *obj)
{
	LASSERT(obj->oo_sa_xattr == NULL);
	LASSERT(obj->oo_db != NULL);

	return __osd_xattr_load(&osd_obj2dev(obj)->od_objset,
				obj->oo_db->db_object, &obj->oo_sa_xattr);
}

int __osd_sa_xattr_get(const struct lu_env *env, struct osd_object *obj,
		const struct lu_buf *buf, const char *name, int *sizep)
{
	uchar_t *nv_value;
	int      rc;

	LASSERT(obj->oo_sa_hdl);

	if (obj->oo_sa_xattr == NULL) {
		rc = __osd_xattr_cache(env, obj);
		if (rc)
			return rc;
	}

	LASSERT(obj->oo_sa_xattr);
	rc = -nvlist_lookup_byte_array(obj->oo_sa_xattr, name, &nv_value,
			sizep);
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

int __osd_xattr_get_large(const struct lu_env *env, udmu_objset_t *uos,
			  uint64_t xattr, struct lu_buf *buf,
			  const char *name, int *sizep)
{
	dmu_buf_t	*xa_data_db;
	sa_handle_t	*sa_hdl = NULL;
	uint64_t	 xa_data_obj, size;
	int		 rc;

	/* are there any extended attributes? */
	if (xattr == ZFS_NO_OBJECT)
		return -ENOENT;

	/* Lookup the object number containing the xattr data */
	rc = -zap_lookup(uos->os, xattr, name, sizeof(uint64_t), 1,
			&xa_data_obj);
	if (rc)
		return rc;

	rc = __osd_obj2dbuf(env, uos->os, xa_data_obj, &xa_data_db, FTAG);
	if (rc)
		return rc;

	rc = -sa_handle_get(uos->os, xa_data_obj, NULL, SA_HDL_PRIVATE,
			&sa_hdl);
	if (rc)
		goto out_rele;

	/* Get the xattr value length / object size */
	rc = -sa_lookup(sa_hdl, SA_ZPL_SIZE(uos), &size, 8);
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

	rc = -dmu_read(uos->os, xa_data_db->db_object, 0,
			size, buf->lb_buf, DMU_READ_PREFETCH);

out:
	sa_handle_destroy(sa_hdl);
out_rele:
	dmu_buf_rele(xa_data_db, FTAG);

	return rc;
}

int __osd_xattr_get(const struct lu_env *env, struct osd_object *obj,
		struct lu_buf *buf, const char *name, int *sizep)
{
	int rc;

	/* check SA_ZPL_DXATTR first then fallback to directory xattr */
	rc = __osd_sa_xattr_get(env, obj, buf, name, sizep);
	if (rc != -ENOENT)
		return rc;

	rc = __osd_xattr_get_large(env, &osd_obj2dev(obj)->od_objset,
				   obj->oo_xattr, buf, name, sizep);

	return rc;
}

int osd_xattr_get(const struct lu_env *env, struct dt_object *dt,
		struct lu_buf *buf, const char *name,
		struct lustre_capa *capa)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	int                 rc, size = 0;
	ENTRY;

	LASSERT(obj->oo_db != NULL);
	LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt));

	if (!osd_obj2dev(obj)->od_posix_acl &&
	    (!strcmp(name, POSIX_ACL_XATTR_ACCESS) ||
	     !strcmp(name, POSIX_ACL_XATTR_DEFAULT)))
		RETURN(-EOPNOTSUPP);

	down(&obj->oo_guard);
	rc = __osd_xattr_get(env, obj, buf, name, &size);
	up(&obj->oo_guard);

	if (rc == -ENOENT)
		rc = -ENODATA;
	else if (rc == 0)
		rc = size;
	RETURN(rc);
}

void __osd_xattr_declare_set(const struct lu_env *env, struct osd_object *obj,
			int vallen, const char *name, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	udmu_objset_t     *uos = &osd->od_objset;
	dmu_buf_t         *db = obj->oo_db;
	dmu_tx_t          *tx = oh->ot_tx;
	uint64_t           xa_data_obj;
	int                rc = 0;
	int                here;

	here = dt_object_exists(&obj->oo_dt);

	/* object may be not yet created */
	if (here) {
		LASSERT(db);
		LASSERT(obj->oo_sa_hdl);
		/* we might just update SA_ZPL_DXATTR */
		dmu_tx_hold_sa(tx, obj->oo_sa_hdl, 1);

		if (obj->oo_xattr == ZFS_NO_OBJECT)
			rc = -ENOENT;
	}

	if (!here || rc == -ENOENT) {
		/* we'll be updating SA_ZPL_XATTR */
		if (here) {
			LASSERT(obj->oo_sa_hdl);
			dmu_tx_hold_sa(tx, obj->oo_sa_hdl, 1);
		}
		/* xattr zap + entry */
		dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, TRUE, (char *) name);
		/* xattr value obj */
		dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, vallen);
		return;
	}

	rc = -zap_lookup(uos->os, obj->oo_xattr, name, sizeof(uint64_t), 1,
			&xa_data_obj);
	if (rc == 0) {
		/*
		 * Entry already exists.
		 * We'll truncate the existing object.
		 */
		dmu_tx_hold_bonus(tx, xa_data_obj);
		dmu_tx_hold_free(tx, xa_data_obj, vallen, DMU_OBJECT_END);
		dmu_tx_hold_write(tx, xa_data_obj, 0, vallen);
		return;
	} else if (rc == -ENOENT) {
		/*
		 * Entry doesn't exist, we need to create a new one and a new
		 * object to store the value.
		 */
		dmu_tx_hold_bonus(tx, obj->oo_xattr);
		dmu_tx_hold_zap(tx, obj->oo_xattr, TRUE, (char *) name);
		dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, vallen);
		return;
	}

	/* An error happened */
	tx->tx_err = -rc;
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

	down(&obj->oo_guard);
	__osd_xattr_declare_set(env, obj, buf->lb_len, name, oh);
	up(&obj->oo_guard);

	RETURN(0);
}

/*
 * Set an extended attribute.
 * This transaction must have called udmu_xattr_declare_set() first.
 *
 * Returns 0 on success or a negative error number on failure.
 *
 * No locking is done here.
 */
static int
__osd_sa_xattr_update(const struct lu_env *env, struct osd_object *obj,
			struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	udmu_objset_t     *uos = &osd->od_objset;
	char              *dxattr;
	size_t             sa_size;
	int                rc;

	ENTRY;
	LASSERT(obj->oo_sa_hdl);
	LASSERT(obj->oo_sa_xattr);

	/* Update the SA for additions, modifications, and removals. */
	rc = -nvlist_size(obj->oo_sa_xattr, &sa_size, NV_ENCODE_XDR);
	if (rc)
		return rc;

	dxattr = sa_spill_alloc(KM_SLEEP);
	if (dxattr == NULL)
		RETURN(-ENOMEM);

	rc = -nvlist_pack(obj->oo_sa_xattr, &dxattr, &sa_size,
				NV_ENCODE_XDR, KM_SLEEP);
	if (rc)
		GOTO(out_free, rc);

	rc = osd_object_sa_update(obj, SA_ZPL_DXATTR(uos), dxattr, sa_size, oh);
out_free:
	sa_spill_free(dxattr);
	RETURN(rc);
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

	LASSERT(obj->oo_sa_hdl);
	if (obj->oo_sa_xattr == NULL) {
		rc = __osd_xattr_cache(env, obj);
		if (rc)
			return rc;
	}

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
			rc = __osd_sa_xattr_update(env, obj, oh);
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
		udmu_objset_t     *uos = &osd_obj2dev(obj)->od_objset;
		uint64_t           xa_data_obj;
		rc = -zap_lookup(uos->os, obj->oo_xattr,
				 name, 8, 1, &xa_data_obj);
		if (rc == 0) {
			rc = __osd_object_free(uos, xa_data_obj, oh->ot_tx);
			if (rc == 0)
				zap_remove(uos->os, obj->oo_xattr,
					   name, oh->ot_tx);
		}
	}

	rc = -nvlist_add_byte_array(obj->oo_sa_xattr, name,
				    (uchar_t *)buf->lb_buf, buf->lb_len);
	if (rc)
		return rc;

	rc = __osd_sa_xattr_update(env, obj, oh);
	return rc;
}

int
__osd_xattr_set(const struct lu_env *env, struct osd_object *obj,
		const struct lu_buf *buf, const char *name, int fl,
		struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	udmu_objset_t     *uos = &osd->od_objset;
	dmu_buf_t         *xa_zap_db = NULL;
	dmu_buf_t         *xa_data_db = NULL;
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
		rc = __osd_zap_create(env, uos, &xa_zap_db, tx, la,
				      obj->oo_db->db_object, FTAG, 0);
		if (rc)
			return rc;

		obj->oo_xattr = xa_zap_db->db_object;
		rc = osd_object_sa_update(obj, SA_ZPL_XATTR(uos),
				&obj->oo_xattr, 8, oh);
		if (rc)
			goto out;
	}

	rc = -zap_lookup(uos->os, obj->oo_xattr, name, sizeof(uint64_t), 1,
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
		rc = __osd_obj2dbuf(env, uos->os, xa_data_obj,
					&xa_data_db, FTAG);
		if (rc)
			goto out;

		rc = -sa_handle_get(uos->os, xa_data_obj, NULL,
					SA_HDL_PRIVATE, &sa_hdl);
		if (rc)
			goto out;

		rc = -sa_lookup(sa_hdl, SA_ZPL_SIZE(uos), &size, 8);
		if (rc)
			goto out_sa;

		rc = -dmu_free_range(uos->os, xa_data_db->db_object,
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
		rc = __osd_object_create(env, uos, &xa_data_db, tx, la,
					 obj->oo_xattr, FTAG);
		if (rc)
			goto out;
		xa_data_obj = xa_data_db->db_object;

		rc = -sa_handle_get(uos->os, xa_data_obj, NULL,
					SA_HDL_PRIVATE, &sa_hdl);
		if (rc)
			goto out;

		rc = -zap_add(uos->os, obj->oo_xattr, name, sizeof(uint64_t),
				1, &xa_data_obj, tx);
		if (rc)
			goto out_sa;
	} else {
		/* There was an error looking up the xattr name */
		goto out;
	}

	/* Finally write the xattr value */
	dmu_write(uos->os, xa_data_obj, 0, buf->lb_len, buf->lb_buf, tx);

	size = buf->lb_len;
	rc = -sa_update(sa_hdl, SA_ZPL_SIZE(uos), &size, 8, tx);

out_sa:
	sa_handle_destroy(sa_hdl);
out:
	if (xa_data_db != NULL)
		dmu_buf_rele(xa_data_db, FTAG);
	if (xa_zap_db != NULL)
		dmu_buf_rele(xa_zap_db, FTAG);

	return rc;
}

int osd_xattr_set(const struct lu_env *env, struct dt_object *dt,
		  const struct lu_buf *buf, const char *name, int fl,
		  struct thandle *handle, struct lustre_capa *capa)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	int rc = 0;
	ENTRY;

	LASSERT(handle != NULL);
	LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	if (!osd_obj2dev(obj)->od_posix_acl &&
	    (!strcmp(name, POSIX_ACL_XATTR_ACCESS) ||
	     !strcmp(name, POSIX_ACL_XATTR_DEFAULT)))
		RETURN(-EOPNOTSUPP);

	oh = container_of0(handle, struct osd_thandle, ot_super);

	down(&obj->oo_guard);
	CDEBUG(D_INODE, "Setting xattr %s with size %d\n",
		name, (int)buf->lb_len);
	rc = osd_xattr_set_internal(env, obj, buf, name, fl, oh, capa);
	up(&obj->oo_guard);

	RETURN(rc);
}

static void
__osd_xattr_declare_del(const struct lu_env *env, struct osd_object *obj,
			const char *name, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	udmu_objset_t     *uos = &osd->od_objset;
	dmu_tx_t          *tx = oh->ot_tx;
	uint64_t           xa_data_obj;
	int                rc;

	/* update SA_ZPL_DXATTR if xattr was in SA */
	dmu_tx_hold_sa(tx, obj->oo_sa_hdl, 0);

	if (obj->oo_xattr == ZFS_NO_OBJECT)
		return;

	rc = -zap_lookup(uos->os, obj->oo_xattr, name, 8, 1, &xa_data_obj);
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
	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);
	LASSERT(obj->oo_db != NULL);

	down(&obj->oo_guard);
	__osd_xattr_declare_del(env, obj, name, oh);
	up(&obj->oo_guard);

	RETURN(0);
}

int __osd_sa_xattr_del(const struct lu_env *env, struct osd_object *obj,
			const char *name, struct osd_thandle *oh)
{
	int rc;

	if (obj->oo_sa_xattr == NULL) {
		rc = __osd_xattr_cache(env, obj);
		if (rc)
			return rc;
	}

	rc = -nvlist_remove(obj->oo_sa_xattr, name, DATA_TYPE_BYTE_ARRAY);
	if (rc == 0)
		rc = __osd_sa_xattr_update(env, obj, oh);
	return rc;
}

int __osd_xattr_del(const struct lu_env *env, struct osd_object *obj,
			const char *name, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	udmu_objset_t     *uos = &osd->od_objset;
	uint64_t           xa_data_obj;
	int                rc;

	/* try remove xattr from SA at first */
	rc = __osd_sa_xattr_del(env, obj, name, oh);
	if (rc != -ENOENT)
		return rc;

	if (obj->oo_xattr == ZFS_NO_OBJECT)
		return 0;

	rc = -zap_lookup(uos->os, obj->oo_xattr, name, sizeof(uint64_t), 1,
			&xa_data_obj);
	if (rc == -ENOENT) {
		rc = 0;
	} else if (rc == 0) {
		/*
		 * Entry exists.
		 * We'll delete the existing object and ZAP entry.
		 */
		rc = __osd_object_free(uos, xa_data_obj, oh->ot_tx);
		if (rc)
			return rc;

		rc = -zap_remove(uos->os, obj->oo_xattr, name, oh->ot_tx);
	}

	return rc;
}

int osd_xattr_del(const struct lu_env *env, struct dt_object *dt,
		const char *name, struct thandle *handle,
		struct lustre_capa *capa)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	int                 rc;
	ENTRY;

	LASSERT(handle != NULL);
	LASSERT(obj->oo_db != NULL);
	LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt));
	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);

	if (!osd_obj2dev(obj)->od_posix_acl &&
	    (!strcmp(name, POSIX_ACL_XATTR_ACCESS) ||
	     !strcmp(name, POSIX_ACL_XATTR_DEFAULT)))
		RETURN(-EOPNOTSUPP);

	down(&obj->oo_guard);
	rc = __osd_xattr_del(env, obj, name, oh);
	up(&obj->oo_guard);

	RETURN(rc);
}

static int
osd_sa_xattr_list(const struct lu_env *env, struct osd_object *obj,
		struct lu_buf *lb)
{
	nvpair_t *nvp = NULL;
	int       len, counted = 0, remain = lb->lb_len;
	int       rc = 0;

	if (obj->oo_sa_xattr == NULL) {
		rc = __osd_xattr_cache(env, obj);
		if (rc)
			return rc;
	}

	LASSERT(obj->oo_sa_xattr);

	while ((nvp = nvlist_next_nvpair(obj->oo_sa_xattr, nvp)) != NULL) {
		const char *name = nvpair_name(nvp);

		if (!osd_obj2dev(obj)->od_posix_acl &&
		    (!strcmp(name, POSIX_ACL_XATTR_ACCESS) ||
		     !strcmp(name, POSIX_ACL_XATTR_DEFAULT)))
			continue;

		len = strlen(nvpair_name(nvp));
		if (lb->lb_buf != NULL) {
			if (len + 1 > remain)
				return -ERANGE;

			memcpy(lb->lb_buf, name, len);
			lb->lb_buf += len;
			*((char *)lb->lb_buf) = '\0';
			lb->lb_buf++;
			remain -= len + 1;
		}
		counted += len + 1;
	}
	return counted;
}

int osd_xattr_list(const struct lu_env *env, struct dt_object *dt,
		struct lu_buf *lb, struct lustre_capa *capa)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object      *obj = osd_dt_obj(dt);
	struct osd_device      *osd = osd_obj2dev(obj);
	udmu_objset_t          *uos = &osd->od_objset;
	zap_cursor_t           *zc;
	int                    rc, counted = 0, remain = lb->lb_len;
	ENTRY;

	LASSERT(obj->oo_db != NULL);
	LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt));

	down(&obj->oo_guard);

	rc = osd_sa_xattr_list(env, obj, lb);
	if (rc < 0)
		GOTO(out, rc);
	counted = rc;
	remain -= counted;

	/* continue with dnode xattr if any */
	if (obj->oo_xattr == ZFS_NO_OBJECT)
		GOTO(out, rc = counted);

	rc = -udmu_zap_cursor_init(&zc, uos, obj->oo_xattr, 0);
	if (rc)
		GOTO(out, rc);

	while ((rc = -udmu_zap_cursor_retrieve_key(env, zc, oti->oti_key,
						MAXNAMELEN)) == 0) {
		if (!osd_obj2dev(obj)->od_posix_acl &&
		    (!strcmp(oti->oti_key, POSIX_ACL_XATTR_ACCESS) ||
		     !strcmp(oti->oti_key, POSIX_ACL_XATTR_DEFAULT))) {
			zap_cursor_advance(zc);
			continue;
		}

		rc = strlen(oti->oti_key);
		if (lb->lb_buf != NULL) {
			if (rc + 1 > remain)
				RETURN(-ERANGE);

			memcpy(lb->lb_buf, oti->oti_key, rc);
			lb->lb_buf += rc;
			*((char *)lb->lb_buf) = '\0';
			lb->lb_buf++;
			remain -= rc + 1;
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
	udmu_zap_cursor_fini(zc);
out:
	up(&obj->oo_guard);
	RETURN(rc);

}


