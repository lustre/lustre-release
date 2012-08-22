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
 * Copyright (c) 2011, 2012 Whamcloud, Inc.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/osd_index.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSD

#include <lustre_ver.h>
#include <libcfs/libcfs.h>
#include <lustre_fsfilt.h>
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

static struct dt_it *osd_zap_it_init(const struct lu_env *env,
				     struct dt_object *dt,
				     __u32 unused,
				     struct lustre_capa *capa)
{
	struct osd_thread_info  *info = osd_oti_get(env);
	struct osd_zap_it       *it;
	struct osd_object       *obj = osd_dt_obj(dt);
	struct osd_device       *osd = osd_obj2dev(obj);
	struct lu_object        *lo  = &dt->do_lu;
	ENTRY;

	/* XXX: check capa ? */

	LASSERT(lu_object_exists(lo));
	LASSERT(obj->oo_db);
	LASSERT(udmu_object_is_zap(obj->oo_db));
	LASSERT(info);

	it = &info->oti_it_zap;

	if (udmu_zap_cursor_init(&it->ozi_zc, &osd->od_objset,
				 obj->oo_db->db_object, 0))
		RETURN(ERR_PTR(-ENOMEM));

	it->ozi_obj   = obj;
	it->ozi_capa  = capa;
	it->ozi_reset = 1;
	lu_object_get(lo);

	RETURN((struct dt_it *)it);
}

static void osd_zap_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj;
	ENTRY;

	LASSERT(it);
	LASSERT(it->ozi_obj);

	obj = it->ozi_obj;

	udmu_zap_cursor_fini(it->ozi_zc);
	lu_object_put(env, &obj->oo_dt.do_lu);

	EXIT;
}

/**
 *  Move Iterator to record specified by \a key
 *
 *  \param  di      osd iterator
 *  \param  key     key for index
 *
 *  \retval +ve  di points to record with least key not larger than key
 *  \retval  0   di points to exact matched key
 *  \retval -ve  failure
 */

static int osd_zap_it_get(const struct lu_env *env,
			  struct dt_it *di, const struct dt_key *key)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	struct osd_device *osd = osd_obj2dev(obj);
	ENTRY;

	LASSERT(it);
	LASSERT(it->ozi_zc);

	/* XXX: API is broken at the moment */
	LASSERT(((const char *)key)[0] == '\0');

	udmu_zap_cursor_fini(it->ozi_zc);
	if (udmu_zap_cursor_init(&it->ozi_zc, &osd->od_objset,
				 obj->oo_db->db_object, 0))
		RETURN(-ENOMEM);

	it->ozi_reset = 1;

	RETURN(+1);
}

static void osd_zap_it_put(const struct lu_env *env, struct dt_it *di)
{
	/* PBS: do nothing : ref are incremented at retrive and decreamented
	 *      next/finish. */
}

int udmu_zap_cursor_retrieve_key(const struct lu_env *env,
				 zap_cursor_t *zc, char *key, int max)
{
	zap_attribute_t *za = &osd_oti_get(env)->oti_za;
	int             err;

	if ((err = zap_cursor_retrieve(zc, za)))
		return err;

	if (key) {
		if (strlen(za->za_name) > max)
			return EOVERFLOW;
		strcpy(key, za->za_name);
	}

	return 0;
}

/**
 * to load a directory entry at a time and stored it in
 * iterator's in-memory data structure.
 *
 * \param di, struct osd_it_ea, iterator's in memory structure
 *
 * \retval +ve, iterator reached to end
 * \retval   0, iterator not reached to end
 * \retval -ve, on error
 */
static int osd_zap_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	int                rc;
	ENTRY;

	if (it->ozi_reset == 0)
		zap_cursor_advance(it->ozi_zc);
	it->ozi_reset = 0;

	/*
	 * According to current API we need to return error if its last entry.
	 * zap_cursor_advance() does return any value. So we need to call
	 * retrieve to check if there is any record.  We should make
	 * changes to Iterator API to not return status for this API
	 */
	rc = -udmu_zap_cursor_retrieve_key(env, it->ozi_zc, NULL, NAME_MAX);
	if (rc == -ENOENT) /* end of dir*/
		RETURN(+1);

	RETURN((rc));
}

static struct dt_key *osd_zap_it_key(const struct lu_env *env,
					const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	int                rc = 0;
	ENTRY;

	it->ozi_reset = 0;
	rc = -udmu_zap_cursor_retrieve_key(env, it->ozi_zc, it->ozi_name,
					   NAME_MAX + 1);
	if (!rc)
		RETURN((struct dt_key *)it->ozi_name);
	else
		RETURN(ERR_PTR(rc));
}

static int osd_zap_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	int                rc;
	ENTRY;

	it->ozi_reset = 0;
	rc = -udmu_zap_cursor_retrieve_key(env, it->ozi_zc, it->ozi_name,
					   NAME_MAX + 1);
	if (!rc)
		RETURN(strlen(it->ozi_name));
	else
		RETURN(rc);
}

/*
 * zap_cursor_retrieve read from current record.
 * to read bytes we need to call zap_lookup explicitly.
 */
int udmu_zap_cursor_retrieve_value(const struct lu_env *env,
				   zap_cursor_t *zc,  char *buf,
				   int buf_size, int *bytes_read)
{
	zap_attribute_t *za = &osd_oti_get(env)->oti_za;
	int err, actual_size;


	if ((err = zap_cursor_retrieve(zc, za)))
		return err;

	if (za->za_integer_length <= 0)
		return (ERANGE);

	actual_size = za->za_integer_length * za->za_num_integers;

	if (actual_size > buf_size) {
		actual_size = buf_size;
		buf_size = actual_size / za->za_integer_length;
	} else {
		buf_size = za->za_num_integers;
	}

	err = -zap_lookup(zc->zc_objset, zc->zc_zapobj,
			  za->za_name, za->za_integer_length,
			  buf_size, buf);

	if (!err)
		*bytes_read = actual_size;

	return err;
}

static inline void osd_it_append_attrs(struct lu_dirent *ent, __u32 attr,
				       int len, __u16 type)
{
	const unsigned    align = sizeof(struct luda_type) - 1;
	struct luda_type *lt;

	/* check if file type is required */
	if (attr & LUDA_TYPE) {
		len = (len + align) & ~align;

		lt = (void *)ent->lde_name + len;
		lt->lt_type = cpu_to_le16(CFS_DTTOIF(type));
		ent->lde_attrs |= LUDA_TYPE;
	}

	ent->lde_attrs = cpu_to_le32(ent->lde_attrs);
}

static int osd_zap_it_rec(const struct lu_env *env, const struct dt_it *di,
			  struct dt_rec *dtrec, __u32 attr)
{
	struct luz_direntry *zde = &osd_oti_get(env)->oti_zde;
	zap_attribute_t     *za = &osd_oti_get(env)->oti_za;
	struct osd_zap_it   *it = (struct osd_zap_it *)di;
	struct lu_dirent    *lde = (struct lu_dirent *)dtrec;
	int                  rc, namelen;
	ENTRY;

	it->ozi_reset = 0;
	LASSERT(lde);

	lde->lde_hash = cpu_to_le64(udmu_zap_cursor_serialize(it->ozi_zc));

	if ((rc = -zap_cursor_retrieve(it->ozi_zc, za)))
		GOTO(out, rc);

	namelen = strlen(za->za_name);
	if (namelen > NAME_MAX)
		GOTO(out, rc = -EOVERFLOW);
	strcpy(lde->lde_name, za->za_name);
	lde->lde_namelen = cpu_to_le16(namelen);

	if (za->za_integer_length != 8 || za->za_num_integers < 3) {
		CERROR("%s: unsupported direntry format: %d %d\n",
		       osd_obj2dev(it->ozi_obj)->od_svname,
		       za->za_integer_length, (int)za->za_num_integers);

		GOTO(out, rc = -EIO);
	}

	rc = -zap_lookup(it->ozi_zc->zc_objset, it->ozi_zc->zc_zapobj,
			 za->za_name, za->za_integer_length, 3, zde);
	if (rc)
		GOTO(out, rc);

	lde->lde_fid = zde->lzd_fid;
	lde->lde_attrs = LUDA_FID;

	/* append lustre attributes */
	osd_it_append_attrs(lde, attr, namelen, zde->lzd_reg.zde_type);

	lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(namelen, attr));

out:
	RETURN(rc);
}

static __u64 osd_zap_it_store(const struct lu_env *env, const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;

	it->ozi_reset = 0;
	RETURN(udmu_zap_cursor_serialize(it->ozi_zc));
}

/*
 * return status :
 *  rc == 0 -> ok, proceed.
 *  rc >  0 -> end of directory.
 *  rc <  0 -> error.  ( EOVERFLOW  can be masked.)
 */
static int osd_zap_it_load(const struct lu_env *env,
			const struct dt_it *di, __u64 hash)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	struct osd_device *osd = osd_obj2dev(obj);
	int                rc;
	ENTRY;

	udmu_zap_cursor_fini(it->ozi_zc);
	if (udmu_zap_cursor_init(&it->ozi_zc, &osd->od_objset,
				 obj->oo_db->db_object, hash))
		RETURN(-ENOMEM);
	it->ozi_reset = 0;

	/* same as osd_zap_it_next()*/
	rc = -udmu_zap_cursor_retrieve_key(env, it->ozi_zc, NULL,
					   NAME_MAX + 1);
	if (rc == 0)
		RETURN(+1);
	else if (rc == -ENOENT) /* end of dir*/
		RETURN(0);

	RETURN(rc);
}

static int osd_dir_lookup(const struct lu_env *env, struct dt_object *dt,
			  struct dt_rec *rec, const struct dt_key *key,
			  struct lustre_capa *capa)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	int                 rc;
	ENTRY;

	LASSERT(udmu_object_is_zap(obj->oo_db));

	rc = -zap_lookup(osd->od_objset.os, obj->oo_db->db_object,
			 (char *)key, 8, sizeof(oti->oti_zde) / 8,
			 (void *)&oti->oti_zde);
	memcpy(rec, &oti->oti_zde.lzd_fid, sizeof(struct lu_fid));

	RETURN(rc == 0 ? 1 : rc);
}

static int osd_declare_dir_insert(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_rec *rec,
				  const struct dt_key *key,
				  struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	ENTRY;

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	LASSERT(obj->oo_db);
	LASSERT(udmu_object_is_zap(obj->oo_db));

	dmu_tx_hold_bonus(oh->ot_tx, obj->oo_db->db_object);
	dmu_tx_hold_zap(oh->ot_tx, obj->oo_db->db_object, TRUE, (char *)key);

	RETURN(0);
}

/**
 * Find the osd object for given fid.
 *
 * \param fid need to find the osd object having this fid
 *
 * \retval osd_object on success
 * \retval        -ve on error
 */
struct osd_object *osd_object_find(const struct lu_env *env,
				   struct dt_object *dt,
				   const struct lu_fid *fid)
{
	struct lu_device         *ludev = dt->do_lu.lo_dev;
	struct osd_object        *child = NULL;
	struct lu_object         *luch;
	struct lu_object         *lo;

	/*
	 * at this point topdev might not exist yet
	 * (i.e. MGS is preparing profiles). so we can
	 * not rely on topdev and instead lookup with
	 * our device passed as topdev. this can't work
	 * if the object isn't cached yet (as osd doesn't
	 * allocate lu_header). IOW, the object must be
	 * in the cache, otherwise lu_object_alloc() crashes
	 * -bzzz
	 */
	luch = lu_object_find_at(env, ludev, fid, NULL);
	if (IS_ERR(luch))
		return (void *)luch;

	if (lu_object_exists(luch)) {
		lo = lu_object_locate(luch->lo_header, ludev->ld_type);
		if (lo != NULL)
			child = osd_obj(lo);
		else
			LU_OBJECT_DEBUG(D_ERROR, env, luch,
					"%s: object can't be located "DFID"\n",
					ludev->ld_obd->obd_name, PFID(fid));

		if (child == NULL) {
			lu_object_put(env, luch);
			CERROR("%s: Unable to get osd_object "DFID"\n",
			       ludev->ld_obd->obd_name, PFID(fid));
			child = ERR_PTR(-ENOENT);
		}
	} else {
		LU_OBJECT_DEBUG(D_ERROR, env, luch,
				"%s: lu_object does not exists "DFID"\n",
				ludev->ld_obd->obd_name, PFID(fid));
		lu_object_put(env, luch);
		child = ERR_PTR(-ENOENT);
	}

	return child;
}

/**
 * Put the osd object once done with it.
 *
 * \param obj osd object that needs to be put
 */
static inline void osd_object_put(const struct lu_env *env,
				  struct osd_object *obj)
{
	lu_object_put(env, &obj->oo_dt.do_lu);
}

/**
 *      Inserts (key, value) pair in \a directory object.
 *
 *      \param  dt      osd index object
 *      \param  key     key for index
 *      \param  rec     record reference
 *      \param  th      transaction handler
 *      \param  capa    capability descriptor
 *      \param  ignore_quota update should not affect quota
 *
 *      \retval  0  success
 *      \retval -ve failure
 */
static int osd_dir_insert(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_rec *rec, const struct dt_key *key,
			  struct thandle *th, struct lustre_capa *capa,
			  int ignore_quota)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object   *parent = osd_dt_obj(dt);
	struct osd_device   *osd = osd_obj2dev(parent);
	struct lu_fid       *fid = (struct lu_fid *)rec;
	struct osd_thandle  *oh;
	struct osd_object   *child;
	__u32                attr;
	int                  rc;
	ENTRY;

	LASSERT(parent->oo_db);
	LASSERT(udmu_object_is_zap(parent->oo_db));

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(parent));

	/*
	 * zfs_readdir() generates ./.. on fly, but
	 * we want own entries (.. at least) with a fid
	 */
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 3, 55, 0)
#warning "fix '.' and '..' handling"
#endif

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	child = osd_object_find(env, dt, fid);
	if (IS_ERR(child))
		RETURN(PTR_ERR(child));

	LASSERT(child->oo_db);

	CLASSERT(sizeof(oti->oti_zde.lzd_reg) == 8);
	CLASSERT(sizeof(oti->oti_zde) % 8 == 0);
	attr = child->oo_dt.do_lu.lo_header ->loh_attr;
	oti->oti_zde.lzd_reg.zde_type = IFTODT(attr & S_IFMT);
	oti->oti_zde.lzd_reg.zde_dnode = child->oo_db->db_object;
	oti->oti_zde.lzd_fid = *fid;

	/* Insert (key,oid) into ZAP */
	rc = -zap_add(osd->od_objset.os, parent->oo_db->db_object,
		      (char *)key, 8, sizeof(oti->oti_zde) / 8,
		      (void *)&oti->oti_zde, oh->ot_tx);

	osd_object_put(env, child);

	RETURN(rc);
}

static int osd_declare_dir_delete(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_key *key,
				  struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	LASSERT(obj->oo_db);
	LASSERT(udmu_object_is_zap(obj->oo_db));

	dmu_tx_hold_zap(oh->ot_tx, obj->oo_db->db_object, TRUE, (char *)key);

	RETURN(0);
}

static int osd_dir_delete(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_key *key, struct thandle *th,
			  struct lustre_capa *capa)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	dmu_buf_t *zap_db = obj->oo_db;
	int rc;
	ENTRY;

	LASSERT(obj->oo_db);
	LASSERT(udmu_object_is_zap(obj->oo_db));

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	/* Remove key from the ZAP */
	rc = -zap_remove(osd->od_objset.os, zap_db->db_object,
			 (char *) key, oh->ot_tx);

	if (rc && rc != -ENOENT)
		CERROR("%s: zap_remove failed: rc = %d\n", osd->od_svname, rc);

	RETURN(rc);
}

static struct dt_index_operations osd_dir_ops = {
	.dio_lookup         = osd_dir_lookup,
	.dio_declare_insert = osd_declare_dir_insert,
	.dio_insert         = osd_dir_insert,
	.dio_declare_delete = osd_declare_dir_delete,
	.dio_delete         = osd_dir_delete,
	.dio_it     = {
		.init     = osd_zap_it_init,
		.fini     = osd_zap_it_fini,
		.get      = osd_zap_it_get,
		.put      = osd_zap_it_put,
		.next     = osd_zap_it_next,
		.key      = osd_zap_it_key,
		.key_size = osd_zap_it_key_size,
		.rec      = osd_zap_it_rec,
		.store    = osd_zap_it_store,
		.load     = osd_zap_it_load
	}
};

/*
 * Primitives for index files using binary keys.
 * XXX: only 64-bit keys are supported for now.
 */

static int osd_index_lookup(const struct lu_env *env, struct dt_object *dt,
			struct dt_rec *rec, const struct dt_key *key,
			struct lustre_capa *capa)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	int                rc;
	ENTRY;

	rc = -zap_lookup_uint64(osd->od_objset.os, obj->oo_db->db_object,
				(const __u64 *)key, 1, 8, obj->oo_recsize,
				(void *)rec);
	RETURN(rc == 0 ? 1 : rc);
}

static int osd_declare_index_insert(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_rec *rec,
				    const struct dt_key *key,
				    struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	ENTRY;

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	LASSERT(obj->oo_db);

	dmu_tx_hold_bonus(oh->ot_tx, obj->oo_db->db_object);

	/* It is not clear what API should be used for binary keys, so we pass
	 * a null name which has the side effect of over-reserving space,
	 * accounting for the worst case. See zap_count_write() */
	dmu_tx_hold_zap(oh->ot_tx, obj->oo_db->db_object, TRUE, NULL);

	RETURN(0);
}

static int osd_index_insert(const struct lu_env *env, struct dt_object *dt,
			    const struct dt_rec *rec, const struct dt_key *key,
			    struct thandle *th, struct lustre_capa *capa,
			    int ignore_quota)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	int                 rc;
	ENTRY;

	LASSERT(obj->oo_db);
	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(th != NULL);

	oh = container_of0(th, struct osd_thandle, ot_super);

	/* Insert (key,oid) into ZAP */
	rc = -zap_add_uint64(osd->od_objset.os, obj->oo_db->db_object,
			     (const __u64 *)key, 1, 8, obj->oo_recsize,
			     (void *)rec, oh->ot_tx);
	RETURN(rc);
}

static int osd_declare_index_delete(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_key *key,
				    struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(th != NULL);
	LASSERT(obj->oo_db);

	oh = container_of0(th, struct osd_thandle, ot_super);
	dmu_tx_hold_zap(oh->ot_tx, obj->oo_db->db_object, TRUE, NULL);

	RETURN(0);
}

static int osd_index_delete(const struct lu_env *env, struct dt_object *dt,
			    const struct dt_key *key, struct thandle *th,
			    struct lustre_capa *capa)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	int                 rc;
	ENTRY;

	LASSERT(obj->oo_db);
	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	/* Remove binary key from the ZAP */
	rc = -zap_remove_uint64(osd->od_objset.os, obj->oo_db->db_object,
				(const __u64 *)key, 1, oh->ot_tx);
	RETURN(rc);
}

static int osd_index_it_get(const struct lu_env *env, struct dt_it *di,
			    const struct dt_key *key)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	struct osd_device *osd = osd_obj2dev(obj);
	ENTRY;

	LASSERT(it);
	LASSERT(it->ozi_zc);

	/* XXX: API is broken at the moment */
	LASSERT(*((const __u64 *)key) == 0);

	zap_cursor_fini(it->ozi_zc);
	memset(it->ozi_zc, 0, sizeof(*it->ozi_zc));
	zap_cursor_init(it->ozi_zc, osd->od_objset.os, obj->oo_db->db_object);
	it->ozi_reset = 1;

	RETURN(+1);
}

static int osd_index_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	zap_attribute_t   *za = &osd_oti_get(env)->oti_za;
	int                rc;
	ENTRY;

	if (it->ozi_reset == 0)
		zap_cursor_advance(it->ozi_zc);
	it->ozi_reset = 0;

	/*
	 * According to current API we need to return error if it's last entry.
	 * zap_cursor_advance() does not return any value. So we need to call
	 * retrieve to check if there is any record.  We should make
	 * changes to Iterator API to not return status for this API
	 */
	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (rc == -ENOENT)
		RETURN(+1);

	RETURN((rc));
}

static struct dt_key *osd_index_it_key(const struct lu_env *env,
				       const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	zap_attribute_t   *za = &osd_oti_get(env)->oti_za;
	int                rc = 0;
	ENTRY;

	it->ozi_reset = 0;
	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (rc)
		RETURN(ERR_PTR(rc));

	/* the binary key is stored in the name */
	it->ozi_key = *((__u64 *)za->za_name);

	RETURN((struct dt_key *)&it->ozi_key);
}

static int osd_index_it_key_size(const struct lu_env *env,
				const struct dt_it *di)
{
	/* we only support 64-bit binary keys for the time being */
	RETURN(sizeof(__u64));
}

static int osd_index_it_rec(const struct lu_env *env, const struct dt_it *di,
			    struct dt_rec *rec, __u32 attr)
{
	zap_attribute_t   *za = &osd_oti_get(env)->oti_za;
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	struct osd_device *osd = osd_obj2dev(obj);
	int                rc;
	ENTRY;

	it->ozi_reset = 0;
	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (rc)
		RETURN(rc);

	rc = -zap_lookup_uint64(osd->od_objset.os, obj->oo_db->db_object,
				(const __u64 *)za->za_name, 1, 8,
				obj->oo_recsize, (void *)rec);
	RETURN(rc);
}

static __u64 osd_index_it_store(const struct lu_env *env,
				const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;

	it->ozi_reset = 0;
	RETURN((__u64)zap_cursor_serialize(it->ozi_zc));
}

static int osd_index_it_load(const struct lu_env *env, const struct dt_it *di,
			     __u64 hash)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	struct osd_device *osd = osd_obj2dev(obj);
	zap_attribute_t   *za = &osd_oti_get(env)->oti_za;
	int                rc;
	ENTRY;

	/* close the current cursor */
	zap_cursor_fini(it->ozi_zc);

	/* create a new one starting at hash */
	memset(it->ozi_zc, 0, sizeof(*it->ozi_zc));
	zap_cursor_init_serialized(it->ozi_zc, osd->od_objset.os,
				   obj->oo_db->db_object, hash);
	it->ozi_reset = 0;

	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (rc == 0)
		RETURN(+1);
	else if (rc == -ENOENT)
		RETURN(0);

	RETURN(rc);
}

static struct dt_index_operations osd_index_ops = {
	.dio_lookup		= osd_index_lookup,
	.dio_declare_insert	= osd_declare_index_insert,
	.dio_insert		= osd_index_insert,
	.dio_declare_delete	= osd_declare_index_delete,
	.dio_delete		= osd_index_delete,
	.dio_it	= {
		.init		= osd_zap_it_init,
		.fini		= osd_zap_it_fini,
		.get		= osd_index_it_get,
		.put		= osd_zap_it_put,
		.next		= osd_index_it_next,
		.key		= osd_index_it_key,
		.key_size	= osd_index_it_key_size,
		.rec		= osd_index_it_rec,
		.store		= osd_index_it_store,
		.load		= osd_index_it_load
	}
};

int osd_index_try(const struct lu_env *env, struct dt_object *dt,
		const struct dt_index_features *feat)
{
	struct osd_object *obj = osd_dt_obj(dt);
	ENTRY;

	LASSERT(dt_object_exists(dt));

	/*
	 * XXX: implement support for fixed-size keys sorted with natural
	 *      numerical way (not using internal hash value)
	 */
	if (feat->dif_flags & DT_IND_RANGE)
		RETURN(-ERANGE);

	if (unlikely(feat == &dt_otable_features))
		/* do not support oi scrub yet. */
		RETURN(-ENOTSUPP);

	LASSERT(obj->oo_db != NULL);
	if (likely(feat == &dt_directory_features)) {
		if (udmu_object_is_zap(obj->oo_db))
			dt->do_index_ops = &osd_dir_ops;
		else
			RETURN(-ENOTDIR);
	} else if (unlikely(feat == &dt_acct_features)) {
		LASSERT(fid_is_acct(lu_object_fid(&dt->do_lu)));
		dt->do_index_ops = &osd_acct_index_ops;
	} else if (udmu_object_is_zap(obj->oo_db) &&
		   dt->do_index_ops == NULL) {
		/* For index file, we don't support variable key & record sizes
		 * and the key has to be unique */
		if ((feat->dif_flags & ~DT_IND_UPDATE) != 0)
			RETURN(-EINVAL);

		/* Although the zap_*_uint64() primitives support large keys, we
		 * limit ourselves to 64-bit keys for now */
		if (feat->dif_keysize_max != sizeof(__u64) ||
		    feat->dif_keysize_min != sizeof(__u64))
			RETURN(-EINVAL);

		/* As for the record size, it should be a multiple of 8 bytes
		 * and smaller than the maximum value length supported by ZAP.
		 */
		if (feat->dif_recsize_max > ZAP_MAXVALUELEN)
			RETURN(-E2BIG);
		if (feat->dif_recsize_max != feat->dif_recsize_min ||
		    (feat->dif_recsize_max & (sizeof(__u64) - 1)))
			RETURN(-EINVAL);

		obj->oo_recsize = feat->dif_recsize_max / sizeof(__u64);
		dt->do_index_ops = &osd_index_ops;
	}

	RETURN(0);
}

