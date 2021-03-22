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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osd-zfs/osd_index.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>

#include "osd_internal.h"

#include <sys/dnode.h>
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
#include <lustre_scrub.h>

/* We don't actually have direct access to the zap_hashbits() function
 * so just pretend like we do for now.  If this ever breaks we can look at
 * it at that time. */
#define zap_hashbits(zc) 48
/*
 * ZFS hash format:
 * | cd (16 bits) | hash (48 bits) |
 * we need it in other form:
 * |0| hash (48 bit) | cd (15 bit) |
 * to be a full 64-bit ordered hash so that Lustre readdir can use it to merge
 * the readdir hashes from multiple directory stripes uniformly on the client.
 * Another point is sign bit, the hash range should be in [0, 2^63-1] because
 * loff_t (for llseek) needs to be a positive value.  This means the "cd" field
 * should only be the low 15 bits.
 */
uint64_t osd_zap_cursor_serialize(zap_cursor_t *zc)
{
	uint64_t zfs_hash = zap_cursor_serialize(zc) & (~0ULL >> 1);

	return (zfs_hash >> zap_hashbits(zc)) |
		(zfs_hash << (63 - zap_hashbits(zc)));
}

void osd_zap_cursor_init_serialized(zap_cursor_t *zc, struct objset *os,
				    uint64_t id, uint64_t dirhash)
{
	uint64_t zfs_hash = ((dirhash << zap_hashbits(zc)) & (~0ULL >> 1)) |
		(dirhash >> (63 - zap_hashbits(zc)));

	zap_cursor_init_serialized(zc, os, id, zfs_hash);
}

int osd_zap_cursor_init(zap_cursor_t **zc, struct objset *os,
			uint64_t id, uint64_t dirhash)
{
	zap_cursor_t *t;

	OBD_ALLOC_PTR(t);
	if (unlikely(t == NULL))
		return -ENOMEM;

	osd_zap_cursor_init_serialized(t, os, id, dirhash);
	*zc = t;

	return 0;
}

void osd_zap_cursor_fini(zap_cursor_t *zc)
{
	zap_cursor_fini(zc);
	OBD_FREE_PTR(zc);
}

static inline void osd_obj_cursor_init_serialized(zap_cursor_t *zc,
						 struct osd_object *o,
						 uint64_t dirhash)
{
	struct osd_device *d = osd_obj2dev(o);
	osd_zap_cursor_init_serialized(zc, d->od_os,
				       o->oo_dn->dn_object, dirhash);
}

static inline int osd_obj_cursor_init(zap_cursor_t **zc, struct osd_object *o,
			uint64_t dirhash)
{
	struct osd_device *d = osd_obj2dev(o);
	return osd_zap_cursor_init(zc, d->od_os, o->oo_dn->dn_object, dirhash);
}

static struct dt_it *osd_index_it_init(const struct lu_env *env,
				       struct dt_object *dt,
				       __u32 unused)
{
	struct osd_thread_info  *info = osd_oti_get(env);
	struct osd_zap_it       *it;
	struct osd_object       *obj = osd_dt_obj(dt);
	struct lu_object        *lo  = &dt->do_lu;
	int			 rc;
	ENTRY;

	if (obj->oo_destroyed)
		RETURN(ERR_PTR(-ENOENT));

	LASSERT(lu_object_exists(lo));
	LASSERT(obj->oo_dn);
	LASSERT(info);

	OBD_SLAB_ALLOC_PTR_GFP(it, osd_zapit_cachep, GFP_NOFS);
	if (it == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	rc = osd_obj_cursor_init(&it->ozi_zc, obj, 0);
	if (rc != 0) {
		OBD_SLAB_FREE_PTR(it, osd_zapit_cachep);
		RETURN(ERR_PTR(rc));
	}

	it->ozi_obj   = obj;
	it->ozi_reset = 1;
	lu_object_get(lo);

	RETURN((struct dt_it *)it);
}

static void osd_index_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_zap_it	*it	= (struct osd_zap_it *)di;
	struct osd_object	*obj;
	ENTRY;

	LASSERT(it);
	LASSERT(it->ozi_obj);

	obj = it->ozi_obj;

	osd_zap_cursor_fini(it->ozi_zc);
	osd_object_put(env, obj);
	OBD_SLAB_FREE_PTR(it, osd_zapit_cachep);

	EXIT;
}


static void osd_index_it_put(const struct lu_env *env, struct dt_it *di)
{
	/* PBS: do nothing : ref are incremented at retrive and decreamented
	 *      next/finish. */
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
		lt->lt_type = cpu_to_le16(DTTOIF(type));
		ent->lde_attrs |= LUDA_TYPE;
	}

	ent->lde_attrs = cpu_to_le32(ent->lde_attrs);
}

int __osd_xattr_load_by_oid(struct osd_device *osd, uint64_t oid, nvlist_t **sa)
{
	sa_handle_t *hdl;
	dmu_buf_t *db;
	int rc;

	rc = -dmu_bonus_hold(osd->od_os, oid, osd_obj_tag, &db);
	if (rc < 0) {
		CERROR("%s: can't get bonus, rc = %d\n", osd->od_svname, rc);
		return rc;
	}

	rc = -sa_handle_get_from_db(osd->od_os, db, NULL, SA_HDL_PRIVATE, &hdl);
	if (rc) {
		dmu_buf_rele(db, osd_obj_tag);
		return rc;
	}

	rc = __osd_xattr_load(osd, hdl, sa);

	sa_handle_destroy(hdl);

	return rc;
}
/**
 * Get the object's FID from its LMA EA.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] osd	pointer to the OSD device
 * \param[in] oid	the object's local identifier
 * \param[out] fid	the buffer to hold the object's FID
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osd_get_fid_by_oid(const struct lu_env *env, struct osd_device *osd,
		       uint64_t oid, struct lu_fid *fid)
{
	struct objset		*os	  = osd->od_os;
	struct osd_thread_info	*oti	  = osd_oti_get(env);
	struct lustre_mdt_attrs	*lma	  =
			(struct lustre_mdt_attrs *)oti->oti_buf;
	struct lu_buf		 buf;
	nvlist_t		*sa_xattr = NULL;
	sa_handle_t		*sa_hdl   = NULL;
	uchar_t			*nv_value = NULL;
	uint64_t		 xattr	  = ZFS_NO_OBJECT;
	int			 size	  = 0;
	int			 rc;
	ENTRY;

	rc = __osd_xattr_load_by_oid(osd, oid, &sa_xattr);
	if (rc == -ENOENT)
		goto regular;

	if (rc != 0)
		GOTO(out, rc);

	rc = -nvlist_lookup_byte_array(sa_xattr, XATTR_NAME_LMA, &nv_value,
				       &size);
	if (rc == -ENOENT)
		goto regular;

	if (rc != 0)
		GOTO(out, rc);

	if (unlikely(size > sizeof(oti->oti_buf)))
		GOTO(out, rc = -ERANGE);

	memcpy(lma, nv_value, size);

	goto found;

regular:
	rc = -sa_handle_get(os, oid, NULL, SA_HDL_PRIVATE, &sa_hdl);
	if (rc != 0)
		GOTO(out, rc);

	rc = -sa_lookup(sa_hdl, SA_ZPL_XATTR(osd), &xattr, 8);
	sa_handle_destroy(sa_hdl);
	if (rc != 0)
		GOTO(out, rc);

	buf.lb_buf = lma;
	buf.lb_len = sizeof(oti->oti_buf);
	rc = __osd_xattr_get_large(env, osd, xattr, &buf,
				   XATTR_NAME_LMA, &size);
	if (rc != 0)
		GOTO(out, rc);

found:
	if (size < sizeof(*lma))
		GOTO(out, rc = -EIO);

	lustre_lma_swab(lma);
	if (unlikely((lma->lma_incompat & ~LMA_INCOMPAT_SUPP) ||
		     CFS_FAIL_CHECK(OBD_FAIL_OSD_LMA_INCOMPAT))) {
		CWARN("%s: unsupported incompat LMA feature(s) %#x for "
		      "oid = %#llx\n", osd->od_svname,
		      lma->lma_incompat & ~LMA_INCOMPAT_SUPP, oid);
		GOTO(out, rc = -EOPNOTSUPP);
	} else {
		*fid = lma->lma_self_fid;
		GOTO(out, rc = 0);
	}

out:
	if (sa_xattr != NULL)
		nvlist_free(sa_xattr);
	return rc;
}

/*
 * As we don't know FID, we can't use LU object, so this function
 * partially duplicate osd_xattr_get_internal() which is built around
 * LU-object and uses it to cache data like regular EA dnode, etc
 */
static int osd_find_parent_by_dnode(const struct lu_env *env,
				    struct dt_object *o,
				    struct lu_fid *fid, uint64_t *oid)
{
	struct osd_object	*obj = osd_dt_obj(o);
	struct osd_device	*osd = osd_obj2dev(obj);
	uint64_t		 dnode = ZFS_NO_OBJECT;
	int			 rc;
	ENTRY;

	/* first of all, get parent dnode from own attributes */
	rc = osd_sa_handle_get(obj);
	if (rc != 0)
		RETURN(rc);
	rc = -sa_lookup(obj->oo_sa_hdl, SA_ZPL_PARENT(osd), &dnode, 8);
	if (!rc) {
		if (oid)
			*oid = dnode;
		rc = osd_get_fid_by_oid(env, osd, dnode, fid);
	}

	RETURN(rc);
}

static int osd_find_parent_fid(const struct lu_env *env, struct dt_object *o,
			       struct lu_fid *fid, uint64_t *oid)
{
	struct link_ea_header  *leh;
	struct link_ea_entry   *lee;
	struct lu_buf		buf;
	int			rc;
	ENTRY;

	buf.lb_buf = osd_oti_get(env)->oti_buf;
	buf.lb_len = sizeof(osd_oti_get(env)->oti_buf);

	rc = osd_xattr_get(env, o, &buf, XATTR_NAME_LINK);
	if (rc == -ERANGE) {
		rc = osd_xattr_get(env, o, &LU_BUF_NULL, XATTR_NAME_LINK);
		if (rc < 0)
			RETURN(rc);
		LASSERT(rc > 0);
		OBD_ALLOC(buf.lb_buf, rc);
		if (buf.lb_buf == NULL)
			RETURN(-ENOMEM);
		buf.lb_len = rc;
		rc = osd_xattr_get(env, o, &buf, XATTR_NAME_LINK);
	}
	if (rc < 0)
		GOTO(out, rc);
	if (rc < sizeof(*leh) + sizeof(*lee))
		GOTO(out, rc = -EINVAL);

	leh = buf.lb_buf;
	if (leh->leh_magic == __swab32(LINK_EA_MAGIC)) {
		leh->leh_magic = LINK_EA_MAGIC;
		leh->leh_reccount = __swab32(leh->leh_reccount);
		leh->leh_len = __swab64(leh->leh_len);
	}
	if (leh->leh_magic != LINK_EA_MAGIC)
		GOTO(out, rc = -EINVAL);
	if (leh->leh_reccount == 0)
		GOTO(out, rc = -ENODATA);

	lee = (struct link_ea_entry *)(leh + 1);
	fid_be_to_cpu(fid, (const struct lu_fid *)&lee->lee_parent_fid);
	rc = 0;

out:
	if (buf.lb_buf != osd_oti_get(env)->oti_buf)
		OBD_FREE(buf.lb_buf, buf.lb_len);

#if 0
	/* this block can be enabled for additional verification
	 * it's trying to match FID from LinkEA vs. FID from LMA */
	if (rc == 0) {
		struct lu_fid fid2;
		int rc2;
		rc2 = osd_find_parent_by_dnode(env, o, &fid2, oid);
		if (rc2 == 0)
			if (lu_fid_eq(fid, &fid2) == 0)
				CERROR("wrong parent: "DFID" != "DFID"\n",
				       PFID(fid), PFID(&fid2));
	}
#endif

	/* no LinkEA is found, let's try to find the fid in parent's LMA */
	if (unlikely(rc != 0))
		rc = osd_find_parent_by_dnode(env, o, fid, oid);

	RETURN(rc);
}

/*
 * When lookup item under striped directory, we need to locate the master
 * MDT-object of the striped directory firstly, then the client will send
 * lookup (getattr_by_name) RPC to the MDT with some slave MDT-object's FID
 * and the item's name. If the system is restored from MDT file level backup,
 * then before the OI scrub completely built the OI files, the OI mappings of
 * the master MDT-object and slave MDT-object may be invalid. Usually, it is
 * not a problem for the master MDT-object. Because when locate the master
 * MDT-object, we will do name based lookup (for the striped directory itself)
 * firstly, during such process we can setup the correct OI mapping for the
 * master MDT-object. But it will be trouble for the slave MDT-object. Because
 * the client will not trigger name based lookup on the MDT to locate the slave
 * MDT-object before locating item under the striped directory, then when
 * osd_fid_lookup(), it will find that the OI mapping for the slave MDT-object
 * is invalid and does not know what the right OI mapping is, then the MDT has
 * to return -EINPROGRESS to the client to notify that the OI scrub is rebuiding
 * the OI file, related OI mapping is unknown yet, please try again later. And
 * then client will re-try the RPC again and again until related OI mapping has
 * been updated. That is quite inefficient.
 *
 * To resolve above trouble, we will handle it as the following two cases:
 *
 * 1) The slave MDT-object and the master MDT-object are on different MDTs.
 *    It is relative easy. Be as one of remote MDT-objects, the slave MDT-object
 *    is linked under /REMOTE_PARENT_DIR with the name of its FID string.
 *    We can locate the slave MDT-object via lookup the /REMOTE_PARENT_DIR
 *    directly. Please check osd_fid_lookup().
 *
 * 2) The slave MDT-object and the master MDT-object reside on the same MDT.
 *    Under such case, during lookup the master MDT-object, we will lookup the
 *    slave MDT-object via readdir against the master MDT-object, because the
 *    slave MDT-objects information are stored as sub-directories with the name
 *    "${FID}:${index}". Then when find the local slave MDT-object, its OI
 *    mapping will be recorded. Then subsequent osd_fid_lookup() will know
 *    the correct OI mapping for the slave MDT-object.
 */
static int osd_check_lmv(const struct lu_env *env, struct osd_device *osd,
			 uint64_t oid, const struct lu_fid *fid)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct luz_direntry *zde = &info->oti_zde;
	zap_attribute_t *za = &info->oti_za;
	zap_cursor_t *zc = &info->oti_zc;
	struct lu_fid *tfid = &info->oti_fid;
	nvlist_t *nvbuf = NULL;
	struct lmv_mds_md_v1 *lmv = NULL;
	int size;
	int rc;
	ENTRY;

	rc = __osd_xattr_load_by_oid(osd, oid, &nvbuf);
	if (rc == -ENOENT || rc == -EEXIST || rc == -ENODATA)
		RETURN(0);

	if (rc)
		RETURN(rc);

	rc = -nvlist_lookup_byte_array(nvbuf, XATTR_NAME_LMV,
				       (uchar_t **)&lmv, &size);
	if (rc == -ENOENT || rc == -EEXIST || rc == -ENODATA)
		GOTO(out_nvbuf, rc = 0);

	if (rc)
		GOTO(out_nvbuf, rc);

	if (le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_V1)
		GOTO(out_nvbuf, rc = -EINVAL);

	zap_cursor_init_serialized(zc, osd->od_os, oid, 0);
	rc = -zap_cursor_retrieve(zc, za);
	if (rc == -ENOENT) {
		zap_cursor_advance(zc);
	} else if (rc) {
		CERROR("%s: fail to init for check LMV "DFID"(%llu): rc = %d\n",
		       osd_name(osd), PFID(fid), oid, rc);
		GOTO(out_zc, rc);
	}

	while (1) {
		rc = -zap_cursor_retrieve(zc, za);
		if (rc == -ENOENT)
			GOTO(out_zc, rc = 0);

		if (rc) {
			CERROR("%s: fail to locate next for check LMV "
			       DFID"(%llu): rc = %d\n",
			       osd_name(osd), PFID(fid), oid, rc);
			GOTO(out_zc, rc);
		}

		fid_zero(tfid);
		sscanf(za->za_name + 1, SFID, RFID(tfid));
		if (fid_is_sane(tfid) && !osd_remote_fid(env, osd, tfid)) {
			rc = osd_zap_lookup(osd, oid, NULL, za->za_name,
					za->za_integer_length,
					sizeof(*zde) / za->za_integer_length,
					(void *)zde);
			if (rc) {
				CERROR("%s: fail to lookup for check LMV "
				       DFID"(%llu): rc = %d\n",
				       osd_name(osd), PFID(fid), oid, rc);
				GOTO(out_zc, rc);
			}

			rc = osd_oii_insert(env, osd, tfid,
					    zde->lzd_reg.zde_dnode, false);
			GOTO(out_zc, rc);
		}

		zap_cursor_advance(zc);
	}

out_zc:
	zap_cursor_fini(zc);
out_nvbuf:
	nvlist_free(nvbuf);

	return rc;
}

static int
osd_consistency_check(const struct lu_env *env, struct osd_device *osd,
		      struct osd_object *obj, const struct lu_fid *fid,
		      uint64_t oid, bool is_dir)
{
	struct lustre_scrub *scrub = &osd->od_scrub;
	dnode_t *dn = NULL;
	uint64_t oid2;
	int once = 0;
	bool insert;
	int rc;
	ENTRY;

	if (!fid_is_norm(fid) && !fid_is_igif(fid))
		RETURN(0);

	/* oid == ZFS_NO_OBJECT must be for lookup ".." case */
	if (oid == ZFS_NO_OBJECT) {
		rc = osd_sa_handle_get(obj);
		if (rc)
			RETURN(rc);

		rc = -sa_lookup(obj->oo_sa_hdl, SA_ZPL_PARENT(osd), &oid, 8);
		if (rc)
			RETURN(rc);
	}

	if (scrub->os_running) {
		if (scrub->os_pos_current > oid)
			RETURN(0);
	} else if (osd->od_auto_scrub_interval == AS_NEVER) {
		RETURN(0);
	} else {
		if (ktime_get_real_seconds() <
		    scrub->os_file.sf_time_last_complete +
		    osd->od_auto_scrub_interval)
			RETURN(0);
	}

again:
	rc = osd_fid_lookup(env, osd, fid, &oid2);
	if (rc == -ENOENT) {
		insert = true;
		if (dn)
			goto trigger;

		rc = __osd_obj2dnode(osd->od_os, oid, &dn);
		/* The object has been removed (by race maybe). */
		if (rc)
			RETURN(rc = (rc == -EEXIST ? -ENOENT : rc));

		goto trigger;
	} else if (rc || oid == oid2) {
		GOTO(out, rc);
	}

	insert = false;

trigger:
	if (scrub->os_running) {
		if (!dn) {
			rc = __osd_obj2dnode(osd->od_os, oid, &dn);
			/* The object has been removed (by race maybe). */
			if (rc)
				RETURN(rc = (rc == -EEXIST ? -ENOENT : rc));
		}

		rc = osd_oii_insert(env, osd, fid, oid, insert);
		/* There is race condition between osd_oi_lookup and OI scrub.
		 * The OI scrub finished just after osd_oi_lookup() failure.
		 * Under such case, it is unnecessary to trigger OI scrub again,
		 * but try to call osd_oi_lookup() again. */
		if (unlikely(rc == -EAGAIN))
			goto again;

		if (is_dir)
			rc = osd_check_lmv(env, osd, oid, fid);
		else
			rc = 0;

		GOTO(out, rc);
	}

	if (osd->od_auto_scrub_interval != AS_NEVER && ++once == 1) {
		rc = osd_scrub_start(env, osd, SS_AUTO_FULL |
				     SS_CLEAR_DRYRUN | SS_CLEAR_FAILOUT);
		CDEBUG_LIMIT(D_LFSCK | D_CONSOLE | D_WARNING,
			     "%s: trigger partial OI scrub for RPC inconsistency, checking FID "DFID"/%#llx): rc = %d\n",
			     osd_name(osd), PFID(fid), oid, rc);
		if (!rc)
			goto again;
	}

	GOTO(out, rc);

out:
	if (dn)
		osd_dnode_rele(dn);

	return rc;
}

static int osd_dir_lookup(const struct lu_env *env, struct dt_object *dt,
			  struct dt_rec *rec, const struct dt_key *key)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	struct lu_fid *fid = (struct lu_fid *)rec;
	char *name = (char *)key;
	uint64_t oid = ZFS_NO_OBJECT;
	int rc;
	ENTRY;

	if (name[0] == '.') {
		if (name[1] == 0) {
			const struct lu_fid *f = lu_object_fid(&dt->do_lu);
			memcpy(rec, f, sizeof(*f));
			RETURN(1);
		} else if (name[1] == '.' && name[2] == 0) {
			rc = osd_find_parent_fid(env, dt, fid, &oid);
			GOTO(out, rc);
		}
	}

	memset(&oti->oti_zde.lzd_fid, 0, sizeof(struct lu_fid));
	rc = osd_zap_lookup(osd, obj->oo_dn->dn_object, obj->oo_dn,
			    (char *)key, 8, sizeof(oti->oti_zde) / 8,
			    (void *)&oti->oti_zde);
	if (rc != 0)
		RETURN(rc);

	oid = oti->oti_zde.lzd_reg.zde_dnode;
	if (likely(fid_is_sane(&oti->oti_zde.lzd_fid))) {
		memcpy(rec, &oti->oti_zde.lzd_fid, sizeof(struct lu_fid));
		GOTO(out, rc = 0);
	}

	rc = osd_get_fid_by_oid(env, osd, oti->oti_zde.lzd_reg.zde_dnode, fid);

	GOTO(out, rc);

out:
	if (!rc && !osd_remote_fid(env, osd, fid)) {
		/*
		 * this should ask the scrubber to check OI given
		 * the mapping we just found in the dir entry.
		 * but result of that check should not affect
		 * result of the lookup in the directory.
		 * otherwise such a direntry becomes hidden
		 * from the layers above, including LFSCK which
		 * is supposed to fix dangling entries.
		 */
		osd_consistency_check(env, osd, obj, fid, oid,
				S_ISDIR(DTTOIF(oti->oti_zde.lzd_reg.zde_type)));
	}

	return rc == 0 ? 1 : (rc == -ENOENT ? -ENODATA : rc);
}

/*
 * In DNE environment, the object and its name entry may reside on different
 * MDTs. Under such case, we will create an agent object on the MDT where the
 * name entry resides. The agent object is empty, and indicates that the real
 * object for the name entry resides on another MDT. If without agent object,
 * related name entry will be skipped when perform MDT side file level backup
 * and restore via ZPL by userspace tool, such as 'tar'.
 */
static int osd_create_agent_object(const struct lu_env *env,
				   struct osd_device *osd,
				   struct luz_direntry *zde,
				   uint64_t parent, dmu_tx_t *tx)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lustre_mdt_attrs *lma = &info->oti_mdt_attrs;
	struct lu_attr *la = &info->oti_la;
	nvlist_t *nvbuf = NULL;
	dnode_t *dn = NULL;
	sa_handle_t *hdl;
	int rc = 0;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_AGENTOBJ))
		RETURN(0);

	rc = -nvlist_alloc(&nvbuf, NV_UNIQUE_NAME, KM_SLEEP);
	if (rc)
		RETURN(rc);

	lustre_lma_init(lma, &zde->lzd_fid, 0, LMAI_AGENT);
	lustre_lma_swab(lma);
	rc = -nvlist_add_byte_array(nvbuf, XATTR_NAME_LMA, (uchar_t *)lma,
				    sizeof(*lma));
	if (rc)
		GOTO(out, rc);

	la->la_valid = LA_TYPE | LA_MODE;
	la->la_mode = (DTTOIF(zde->lzd_reg.zde_type) & S_IFMT) |
			S_IRUGO | S_IWUSR | S_IXUGO;

	if (S_ISDIR(la->la_mode))
		rc = __osd_zap_create(env, osd, &dn, tx, la,
				osd_find_dnsize(osd, OSD_BASE_EA_IN_BONUS), 0);
	else
		rc = __osd_object_create(env, osd, NULL, &zde->lzd_fid,
					 &dn, tx, la);
	if (rc)
		GOTO(out, rc);

	zde->lzd_reg.zde_dnode = dn->dn_object;
	rc = -sa_handle_get(osd->od_os, dn->dn_object, NULL,
			    SA_HDL_PRIVATE, &hdl);
	if (!rc) {
		rc = __osd_attr_init(env, osd, NULL, hdl, tx,
				     la, parent, nvbuf);
		sa_handle_destroy(hdl);
	}

	GOTO(out, rc);

out:
	if (dn) {
		if (rc)
			dmu_object_free(osd->od_os, dn->dn_object, tx);
		osd_dnode_rele(dn);
	}

	if (nvbuf)
		nvlist_free(nvbuf);

	return rc;
}

int osd_add_to_remote_parent(const struct lu_env *env,
			     struct osd_device *osd,
			     struct osd_object *obj,
			     struct osd_thandle *oh)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct luz_direntry *zde = &info->oti_zde;
	char *name = info->oti_str;
	const struct lu_fid *fid = lu_object_fid(&obj->oo_dt.do_lu);
	struct lustre_mdt_attrs *lma = (struct lustre_mdt_attrs *)info->oti_buf;
	struct lu_buf buf = {
		.lb_buf = lma,
		.lb_len = sizeof(info->oti_buf),
	};
	int size = 0;
	int rc;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_AGENTENT))
		RETURN(0);

	rc = osd_xattr_get_internal(env, obj, &buf, XATTR_NAME_LMA, &size);
	if (rc) {
		CWARN("%s: fail to load LMA for adding "
		      DFID" to remote parent: rc = %d\n",
		      osd_name(osd), PFID(fid), rc);
		RETURN(rc);
	}

	lustre_lma_swab(lma);
	lma->lma_incompat |= LMAI_REMOTE_PARENT;
	lustre_lma_swab(lma);
	buf.lb_len = size;
	rc = osd_xattr_set_internal(env, obj, &buf, XATTR_NAME_LMA,
				    LU_XATTR_REPLACE, oh);
	if (rc) {
		CWARN("%s: fail to update LMA for adding "
		      DFID" to remote parent: rc = %d\n",
		      osd_name(osd), PFID(fid), rc);
		RETURN(rc);
	}

	osd_fid2str(name, fid, sizeof(info->oti_str));
	zde->lzd_reg.zde_dnode = obj->oo_dn->dn_object;
	zde->lzd_reg.zde_type = S_DT(S_IFDIR);
	zde->lzd_fid = *fid;

	rc = osd_zap_add(osd, osd->od_remote_parent_dir, NULL,
			 name, 8, sizeof(*zde) / 8, zde, oh->ot_tx);
	if (unlikely(rc == -EEXIST))
		rc = 0;
	if (rc)
		CWARN("%s: fail to add name entry for "
		      DFID" to remote parent: rc = %d\n",
		      osd_name(osd), PFID(fid), rc);
	else
		lu_object_set_agent_entry(&obj->oo_dt.do_lu);

	RETURN(rc);
}

int osd_delete_from_remote_parent(const struct lu_env *env,
				  struct osd_device *osd,
				  struct osd_object *obj,
				  struct osd_thandle *oh, bool destroy)
{
	struct osd_thread_info *info = osd_oti_get(env);
	char *name = info->oti_str;
	const struct lu_fid *fid = lu_object_fid(&obj->oo_dt.do_lu);
	struct lustre_mdt_attrs *lma = (struct lustre_mdt_attrs *)info->oti_buf;
	struct lu_buf buf = {
		.lb_buf = lma,
		.lb_len = sizeof(info->oti_buf),
	};
	int size = 0;
	int rc;
	ENTRY;

	osd_fid2str(name, fid, sizeof(info->oti_str));
	rc = osd_zap_remove(osd, osd->od_remote_parent_dir, NULL,
			    name, oh->ot_tx);
	if (unlikely(rc == -ENOENT))
		rc = 0;
	if (rc)
		CERROR("%s: fail to remove entry under remote "
		       "parent for "DFID": rc = %d\n",
		       osd_name(osd), PFID(fid), rc);

	if (destroy || rc)
		RETURN(rc);

	rc = osd_xattr_get_internal(env, obj, &buf, XATTR_NAME_LMA, &size);
	if (rc) {
		CERROR("%s: fail to load LMA for removing "
		       DFID" from remote parent: rc = %d\n",
		       osd_name(osd), PFID(fid), rc);
		RETURN(rc);
	}

	lustre_lma_swab(lma);
	lma->lma_incompat &= ~LMAI_REMOTE_PARENT;
	lustre_lma_swab(lma);
	buf.lb_len = size;
	rc = osd_xattr_set_internal(env, obj, &buf, XATTR_NAME_LMA,
				    LU_XATTR_REPLACE, oh);
	if (rc)
		CERROR("%s: fail to update LMA for removing "
		       DFID" from remote parent: rc = %d\n",
		       osd_name(osd), PFID(fid), rc);
	else
		lu_object_clear_agent_entry(&obj->oo_dt.do_lu);

	RETURN(rc);
}

static int osd_declare_dir_insert(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_rec *rec,
				  const struct dt_key *key,
				  struct thandle *th)
{
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	const struct dt_insert_rec *rec1;
	const struct lu_fid	*fid;
	struct osd_thandle	*oh;
	uint64_t		 object;
	struct osd_idmap_cache *idc;
	ENTRY;

	rec1 = (struct dt_insert_rec *)rec;
	fid = rec1->rec_fid;
	LASSERT(fid != NULL);
	LASSERT(rec1->rec_type != 0);

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	idc = osd_idc_find_or_init(env, osd, fid);
	if (IS_ERR(idc))
		RETURN(PTR_ERR(idc));

	if (idc->oic_remote) {
		const char *name = (const char *)key;

		if (name[0] != '.' || name[1] != '.' || name[2] != 0) {
			/* Prepare agent object for remote entry that will
			 * be used for operations via ZPL, such as MDT side
			 * file-level backup and restore. */
			dmu_tx_hold_sa_create(oh->ot_tx,
				osd_find_dnsize(osd, OSD_BASE_EA_IN_BONUS));
			if (S_ISDIR(rec1->rec_type))
				dmu_tx_hold_zap(oh->ot_tx, DMU_NEW_OBJECT,
						FALSE, NULL);
		}
	}

	/* This is for inserting dot/dotdot for new created dir. */
	if (obj->oo_dn == NULL)
		object = DMU_NEW_OBJECT;
	else
		object = obj->oo_dn->dn_object;

	/* do not specify the key as then DMU is trying to look it up
	 * which is very expensive. usually the layers above lookup
	 * before insertion */
	osd_tx_hold_zap(oh->ot_tx, object, obj->oo_dn, TRUE, NULL);

	RETURN(0);
}

static int osd_seq_exists(const struct lu_env *env, struct osd_device *osd,
			  u64 seq)
{
	struct lu_seq_range	*range = &osd_oti_get(env)->oti_seq_range;
	struct seq_server_site	*ss = osd_seq_site(osd);
	int			rc;
	ENTRY;

	LASSERT(ss != NULL);
	LASSERT(ss->ss_server_fld != NULL);

	rc = osd_fld_lookup(env, osd, seq, range);
	if (rc != 0) {
		if (rc != -ENOENT)
			CERROR("%s: Can not lookup fld for %#llx\n",
			       osd_name(osd), seq);
		RETURN(0);
	}

	RETURN(ss->ss_node_id == range->lsr_index);
}

int osd_remote_fid(const struct lu_env *env, struct osd_device *osd,
		   const struct lu_fid *fid)
{
	struct seq_server_site	*ss = osd_seq_site(osd);
	ENTRY;

	/* FID seqs not in FLDB, must be local seq */
	if (unlikely(!fid_seq_in_fldb(fid_seq(fid))))
		RETURN(0);

	/* If FLD is not being initialized yet, it only happens during the
	 * initialization, likely during mgs initialization, and we assume
	 * this is local FID. */
	if (ss == NULL || ss->ss_server_fld == NULL)
		RETURN(0);

	/* Only check the local FLDB here */
	if (osd_seq_exists(env, osd, fid_seq(fid)))
		RETURN(0);

	RETURN(1);
}

/**
 *      Inserts (key, value) pair in \a directory object.
 *
 *      \param  dt      osd index object
 *      \param  key     key for index
 *      \param  rec     record reference
 *      \param  th      transaction handler
 *
 *      \retval  0  success
 *      \retval -ve failure
 */
static int osd_dir_insert(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_rec *rec, const struct dt_key *key,
			  struct thandle *th)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object   *parent = osd_dt_obj(dt);
	struct osd_device   *osd = osd_obj2dev(parent);
	struct dt_insert_rec *rec1 = (struct dt_insert_rec *)rec;
	const struct lu_fid *fid = rec1->rec_fid;
	struct osd_thandle *oh;
	struct osd_idmap_cache *idc;
	const char *name = (const char *)key;
	struct luz_direntry *zde = &oti->oti_zde;
	int num = sizeof(*zde) / 8;
	int rc;
	ENTRY;

	LASSERT(parent->oo_dn);

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(parent));

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	idc = osd_idc_find(env, osd, fid);
	if (unlikely(idc == NULL)) {
		/* this dt_insert() wasn't declared properly, so
		 * FID is missing in OI cache. we better do not
		 * lookup FID in FLDB/OI and don't risk to deadlock,
		 * but in some special cases (lfsck testing, etc)
		 * it's much simpler than fixing a caller */
		idc = osd_idc_find_or_init(env, osd, fid);
		if (IS_ERR(idc)) {
			CERROR("%s: "DFID" wasn't declared for insert\n",
			       osd_name(osd), PFID(fid));
			RETURN(PTR_ERR(idc));
		}
	}

	BUILD_BUG_ON(sizeof(zde->lzd_reg) != 8);
	BUILD_BUG_ON(sizeof(*zde) % 8 != 0);

	memset(&zde->lzd_reg, 0, sizeof(zde->lzd_reg));
	zde->lzd_reg.zde_type = S_DT(rec1->rec_type & S_IFMT);
	zde->lzd_fid = *fid;

	if (idc->oic_remote) {
		if (name[0] != '.' || name[1] != '.' || name[2] != 0) {
			/* Create agent inode for remote object that will
			 * be used for MDT file-level backup and restore. */
			rc = osd_create_agent_object(env, osd, zde,
					parent->oo_dn->dn_object, oh->ot_tx);
			if (rc) {
				CWARN("%s: Fail to create agent object for "
				      DFID": rc = %d\n",
				      osd_name(osd), PFID(fid), rc);
				/* Ignore the failure since the system can go
				 * ahead if we do not care about the MDT side
				 * file-level backup and restore. */
				rc = 0;
			}
		}
	} else {
		if (unlikely(idc->oic_dnode == 0)) {
			/* for a reason OI cache wasn't filled properly */
			CERROR("%s: OIC for "DFID" isn't filled\n",
			       osd_name(osd), PFID(fid));
			RETURN(-EINVAL);
		}
		if (name[0] == '.') {
			if (name[1] == 0) {
				/* do not store ".", instead generate it
				 * during iteration */
				GOTO(out, rc = 0);
			} else if (name[1] == '.' && name[2] == 0) {
				uint64_t dnode = idc->oic_dnode;
				if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_PARENT))
					dnode--;

				/* update parent dnode in the child.
				 * later it will be used to generate ".." */
				rc = osd_object_sa_update(parent,
						 SA_ZPL_PARENT(osd),
						 &dnode, 8, oh);

				GOTO(out, rc);
			}
		}
		zde->lzd_reg.zde_dnode = idc->oic_dnode;
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_FID_INDIR))
		zde->lzd_fid.f_ver = ~0;

	/* The logic is not related with IGIF, just re-use the fail_loc value
	 * to be consistent with ldiskfs case, then share the same test logic */
	if (OBD_FAIL_CHECK(OBD_FAIL_FID_IGIF))
		num = 1;

	/* Insert (key,oid) into ZAP */
	rc = osd_zap_add(osd, parent->oo_dn->dn_object, parent->oo_dn,
			 name, 8, num, (void *)zde, oh->ot_tx);
	if (unlikely(rc == -EEXIST &&
		     name[0] == '.' && name[1] == '.' && name[2] == 0))
		/* Update (key,oid) in ZAP */
		rc = -zap_update(osd->od_os, parent->oo_dn->dn_object, name, 8,
				 sizeof(*zde) / 8, (void *)zde, oh->ot_tx);

out:

	RETURN(rc);
}

static int osd_declare_dir_delete(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_key *key,
				  struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	dnode_t *zap_dn = obj->oo_dn;
	struct osd_thandle *oh;
	const char *name = (const char *)key;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(zap_dn != NULL);

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	/*
	 * In Orion . and .. were stored in the directory (not generated upon
	 * request as now). We preserve them for backward compatibility.
	 */
	if (name[0] == '.') {
		if (name[1] == 0)
			RETURN(0);
		else if (name[1] == '.' && name[2] == 0)
			RETURN(0);
	}

	/* do not specify the key as then DMU is trying to look it up
	 * which is very expensive. usually the layers above lookup
	 * before deletion */
	osd_tx_hold_zap(oh->ot_tx, zap_dn->dn_object, zap_dn, FALSE, NULL);

	/* For destroying agent object if have. */
	dmu_tx_hold_bonus(oh->ot_tx, DMU_NEW_OBJECT);

	RETURN(0);
}

static int osd_dir_delete(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_key *key, struct thandle *th)
{
	struct luz_direntry *zde = &osd_oti_get(env)->oti_zde;
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	dnode_t *zap_dn = obj->oo_dn;
	char	  *name = (char *)key;
	int rc;
	ENTRY;

	LASSERT(zap_dn);

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	/*
	 * In Orion . and .. were stored in the directory (not generated upon
	 * request as now). we preserve them for backward compatibility
	 */
	if (name[0] == '.') {
		if (name[1] == 0) {
			RETURN(0);
		} else if (name[1] == '.' && name[2] == 0) {
			RETURN(0);
		}
	}

	/* XXX: We have to say that lookup during delete_declare will affect
	 *	performance, but we have to check whether the name entry (to
	 *	be deleted) has agent object or not to avoid orphans.
	 *
	 *	We will improve that in the future, some possible solutions,
	 *	for example:
	 *	1) Some hint from the caller via transaction handle to make
	 *	   the lookup conditionally.
	 *	2) Enhance the ZFS logic to recognize the OSD lookup result
	 *	   and delete the given entry directly without lookup again
	 *	   internally. LU-10190 */
	memset(&zde->lzd_fid, 0, sizeof(zde->lzd_fid));
	rc = osd_zap_lookup(osd, zap_dn->dn_object, zap_dn, name, 8, 3, zde);
	if (unlikely(rc)) {
		if (rc != -ENOENT)
			CERROR("%s: failed to locate entry  %s: rc = %d\n",
			       osd->od_svname, name, rc);
		RETURN(rc);
	}

	if (unlikely(osd_remote_fid(env, osd, &zde->lzd_fid) > 0)) {
		rc = -dmu_object_free(osd->od_os, zde->lzd_reg.zde_dnode,
				      oh->ot_tx);
		if (rc)
			CERROR("%s: failed to destroy agent object (%llu) "
			       "for the entry %s: rc = %d\n", osd->od_svname,
			       (__u64)zde->lzd_reg.zde_dnode, name, rc);
	}

	/* Remove key from the ZAP */
	rc = osd_zap_remove(osd, zap_dn->dn_object, zap_dn,
			    (char *)key, oh->ot_tx);
	if (unlikely(rc))
		CERROR("%s: zap_remove %s failed: rc = %d\n",
		       osd->od_svname, name, rc);

	RETURN(rc);
}

static struct dt_it *osd_dir_it_init(const struct lu_env *env,
				     struct dt_object *dt,
				     __u32 unused)
{
	struct osd_zap_it *it;

	it = (struct osd_zap_it *)osd_index_it_init(env, dt, unused);
	if (!IS_ERR(it))
		it->ozi_pos = OZI_POS_INIT;

	RETURN((struct dt_it *)it);
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
static int osd_dir_it_get(const struct lu_env *env,
			  struct dt_it *di, const struct dt_key *key)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	char		  *name = (char *)key;
	int		   rc;
	ENTRY;

	LASSERT(it);
	LASSERT(it->ozi_zc);

	/* reset the cursor */
	zap_cursor_fini(it->ozi_zc);
	osd_obj_cursor_init_serialized(it->ozi_zc, obj, 0);

	/* XXX: implementation of the API is broken at the moment */
	LASSERT(((const char *)key)[0] == 0);

	if (name[0] == 0) {
		it->ozi_pos = OZI_POS_INIT;
		RETURN(1);
	}

	if (name[0] == '.') {
		if (name[1] == 0) {
			it->ozi_pos = OZI_POS_DOT;
			GOTO(out, rc = 1);
		} else if (name[1] == '.' && name[2] == 0) {
			it->ozi_pos = OZI_POS_DOTDOT;
			GOTO(out, rc = 1);
		}
	}

	/* neither . nor .. - some real record */
	it->ozi_pos = OZI_POS_REAL;
	rc = +1;

out:
	RETURN(rc);
}

static void osd_dir_it_put(const struct lu_env *env, struct dt_it *di)
{
	/* PBS: do nothing : ref are incremented at retrive and decreamented
	 *      next/finish. */
}

/*
 * in Orion . and .. were stored in the directory, while ZPL
 * and current osd-zfs generate them up on request. so, we
 * need to ignore previously stored . and ..
 */
static int osd_index_retrieve_skip_dots(struct osd_zap_it *it,
					zap_attribute_t *za)
{
	int rc, isdot;

	do {
		rc = -zap_cursor_retrieve(it->ozi_zc, za);

		isdot = 0;
		if (unlikely(rc == 0 && za->za_name[0] == '.')) {
			if (za->za_name[1] == 0) {
				isdot = 1;
			} else if (za->za_name[1] == '.' &&
				   za->za_name[2] == 0) {
				isdot = 1;
			}
			if (unlikely(isdot))
				zap_cursor_advance(it->ozi_zc);
		}
	} while (unlikely(rc == 0 && isdot));

	return rc;
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
static int osd_dir_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	zap_attribute_t	  *za = &osd_oti_get(env)->oti_za;
	int		   rc;

	ENTRY;

	/* temp. storage should be enough for any key supported by ZFS */
	BUILD_BUG_ON(sizeof(za->za_name) > sizeof(it->ozi_name));

	/*
	 * the first ->next() moves the cursor to .
	 * the second ->next() moves the cursor to ..
	 * then we get to the real records and have to verify any exist
	 */
	if (it->ozi_pos <= OZI_POS_DOTDOT) {
		it->ozi_pos++;
		if (it->ozi_pos <= OZI_POS_DOTDOT)
			RETURN(0);

	} else {
		zap_cursor_advance(it->ozi_zc);
	}

	/*
	 * According to current API we need to return error if its last entry.
	 * zap_cursor_advance() does not return any value. So we need to call
	 * retrieve to check if there is any record.  We should make
	 * changes to Iterator API to not return status for this API
	 */
	rc = osd_index_retrieve_skip_dots(it, za);

	if (rc == -ENOENT) /* end of dir */
		RETURN(+1);

	RETURN(rc);
}

static struct dt_key *osd_dir_it_key(const struct lu_env *env,
				     const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	zap_attribute_t	  *za = &osd_oti_get(env)->oti_za;
	int		   rc = 0;
	ENTRY;

	if (it->ozi_pos <= OZI_POS_DOT) {
		it->ozi_pos = OZI_POS_DOT;
		RETURN((struct dt_key *)".");
	} else if (it->ozi_pos == OZI_POS_DOTDOT) {
		RETURN((struct dt_key *)"..");
	}

	if ((rc = -zap_cursor_retrieve(it->ozi_zc, za)))
		RETURN(ERR_PTR(rc));

	strcpy(it->ozi_name, za->za_name);

	RETURN((struct dt_key *)it->ozi_name);
}

static int osd_dir_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	zap_attribute_t	  *za = &osd_oti_get(env)->oti_za;
	int		   rc;
	ENTRY;

	if (it->ozi_pos <= OZI_POS_DOT) {
		it->ozi_pos = OZI_POS_DOT;
		RETURN(2);
	} else if (it->ozi_pos == OZI_POS_DOTDOT) {
		RETURN(3);
	}

	if ((rc = -zap_cursor_retrieve(it->ozi_zc, za)) == 0)
		rc = strlen(za->za_name);

	RETURN(rc);
}

static int
osd_dirent_update(const struct lu_env *env, struct osd_device *dev,
		  uint64_t zap, const char *key, struct luz_direntry *zde)
{
	dmu_tx_t *tx;
	int rc;
	ENTRY;

	tx = dmu_tx_create(dev->od_os);
	if (!tx)
		RETURN(-ENOMEM);

	dmu_tx_hold_zap(tx, zap, TRUE, NULL);
	rc = -dmu_tx_assign(tx, TXG_WAIT);
	if (!rc)
		rc = -zap_update(dev->od_os, zap, key, 8, sizeof(*zde) / 8,
				 (const void *)zde, tx);
	if (rc)
		dmu_tx_abort(tx);
	else
		dmu_tx_commit(tx);

	RETURN(rc);
}

static int osd_update_entry_for_agent(const struct lu_env *env,
				      struct osd_device *osd,
				      uint64_t zap, const char *name,
				      struct luz_direntry *zde, __u32 attr)
{
	dmu_tx_t *tx = NULL;
	int rc = 0;
	ENTRY;

	if (attr & LUDA_VERIFY_DRYRUN)
		GOTO(out, rc = 0);

	tx = dmu_tx_create(osd->od_os);
	if (!tx)
		GOTO(out, rc = -ENOMEM);

	dmu_tx_hold_sa_create(tx, osd_find_dnsize(osd, OSD_BASE_EA_IN_BONUS));
	dmu_tx_hold_zap(tx, zap, FALSE, NULL);
	rc = -dmu_tx_assign(tx, TXG_WAIT);
	if (rc) {
		dmu_tx_abort(tx);
		GOTO(out, rc);
	}

	rc = osd_create_agent_object(env, osd, zde, zap, tx);
	if (!rc)
		rc = -zap_update(osd->od_os, zap, name, 8, sizeof(*zde) / 8,
				 (const void *)zde, tx);
	dmu_tx_commit(tx);

	GOTO(out, rc);

out:
	CDEBUG(D_LFSCK, "%s: Updated (%s) remote entry for "DFID": rc = %d\n",
	       osd_name(osd), (attr & LUDA_VERIFY_DRYRUN) ? "(ro)" : "(rw)",
	       PFID(&zde->lzd_fid), rc);
	return rc;
}

static int osd_dir_it_rec(const struct lu_env *env, const struct dt_it *di,
			  struct dt_rec *dtrec, __u32 attr)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct lu_dirent *lde = (struct lu_dirent *)dtrec;
	struct osd_thread_info *info = osd_oti_get(env);
	struct luz_direntry *zde = &info->oti_zde;
	zap_attribute_t *za = &info->oti_za;
	struct lu_fid *fid = &info->oti_fid;
	struct osd_device *osd = osd_obj2dev(it->ozi_obj);
	int rc, namelen;
	ENTRY;

	lde->lde_attrs = 0;
	if (it->ozi_pos <= OZI_POS_DOT) {
		/* notice hash=0 here, this is needed to avoid
		 * case when some real entry (after ./..) may
		 * have hash=0. in this case the client would
		 * be confused having records out of hash order. */
		lde->lde_hash = cpu_to_le64(0);
		strcpy(lde->lde_name, ".");
		lde->lde_namelen = cpu_to_le16(1);
		fid_cpu_to_le(&lde->lde_fid,
			      lu_object_fid(&it->ozi_obj->oo_dt.do_lu));
		lde->lde_attrs = LUDA_FID;
		/* append lustre attributes */
		osd_it_append_attrs(lde, attr, 1, S_DT(S_IFDIR));
		lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(1, attr));
		it->ozi_pos = OZI_POS_DOT;
		RETURN(0);
	} else if (it->ozi_pos == OZI_POS_DOTDOT) {
		/* same as for . above */
		lde->lde_hash = cpu_to_le64(0);
		strcpy(lde->lde_name, "..");
		lde->lde_namelen = cpu_to_le16(2);
		rc = osd_find_parent_fid(env, &it->ozi_obj->oo_dt, fid, NULL);
		if (!rc) {
			fid_cpu_to_le(&lde->lde_fid, fid);
			lde->lde_attrs = LUDA_FID;
		} else if (rc != -ENOENT) {
			/* ENOENT happens at the root of filesystem, ignore */
			RETURN(rc);
		}

		/* append lustre attributes */
		osd_it_append_attrs(lde, attr, 2, S_DT(S_IFDIR));
		lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(2, attr));
		RETURN(0);
	}

	LASSERT(lde);

	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (unlikely(rc))
		RETURN(rc);

	lde->lde_hash = cpu_to_le64(osd_zap_cursor_serialize(it->ozi_zc));
	namelen = strlen(za->za_name);
	if (namelen > NAME_MAX)
		RETURN(-EOVERFLOW);
	strcpy(lde->lde_name, za->za_name);
	lde->lde_namelen = cpu_to_le16(namelen);

	if (za->za_integer_length != 8) {
		CERROR("%s: unsupported direntry format: %d %d\n",
		       osd->od_svname,
		       za->za_integer_length, (int)za->za_num_integers);
		RETURN(-EIO);
	}

	rc = osd_zap_lookup(osd, it->ozi_zc->zc_zapobj, it->ozi_obj->oo_dn,
			    za->za_name, za->za_integer_length, 3, zde);
	if (rc)
		RETURN(rc);

	if (za->za_num_integers >= 3 && fid_is_sane(&zde->lzd_fid)) {
		lde->lde_attrs = LUDA_FID;
		fid_cpu_to_le(&lde->lde_fid, &zde->lzd_fid);
		if (unlikely(zde->lzd_reg.zde_dnode == ZFS_NO_OBJECT &&
			     osd_remote_fid(env, osd, &zde->lzd_fid) > 0 &&
			     attr & LUDA_VERIFY)) {
			/* It is mainly used for handling the MDT
			 * upgraded from old ZFS based backend. */
			rc = osd_update_entry_for_agent(env, osd,
					it->ozi_obj->oo_dn->dn_object,
					za->za_name, zde, attr);
			if (!rc)
				lde->lde_attrs |= LUDA_REPAIR;
			else
				lde->lde_attrs |= LUDA_UNKNOWN;
		}

		if (!(attr & (LUDA_VERIFY | LUDA_VERIFY_DRYRUN)))
			GOTO(pack_attr, rc = 0);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_FID_LOOKUP))
		RETURN(-ENOENT);

	rc = osd_get_fid_by_oid(env, osd, zde->lzd_reg.zde_dnode, fid);
	if (rc) {
		lde->lde_attrs = LUDA_UNKNOWN;
		GOTO(pack_attr, rc = 0);
	}

	if (za->za_num_integers >= 3 && fid_is_sane(&zde->lzd_fid) &&
	    lu_fid_eq(&zde->lzd_fid, fid))
		GOTO(pack_attr, rc = 0);

	if (!(attr & LUDA_VERIFY)) {
		fid_cpu_to_le(&lde->lde_fid, fid);
		lde->lde_attrs = LUDA_FID;
		GOTO(pack_attr, rc = 0);
	}

	if (attr & LUDA_VERIFY_DRYRUN) {
		fid_cpu_to_le(&lde->lde_fid, fid);
		lde->lde_attrs = LUDA_FID | LUDA_REPAIR;
		GOTO(pack_attr, rc = 0);
	}

	fid_cpu_to_le(&lde->lde_fid, fid);
	lde->lde_attrs = LUDA_FID;
	zde->lzd_fid = *fid;
	rc = osd_dirent_update(env, osd, it->ozi_zc->zc_zapobj,
			       za->za_name, zde);
	if (rc) {
		lde->lde_attrs |= LUDA_UNKNOWN;
		GOTO(pack_attr, rc = 0);
	}

	lde->lde_attrs |= LUDA_REPAIR;

	GOTO(pack_attr, rc = 0);

pack_attr:
	osd_it_append_attrs(lde, attr, namelen, zde->lzd_reg.zde_type);
	lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(namelen, attr));
	return rc;
}

static int osd_dir_it_rec_size(const struct lu_env *env, const struct dt_it *di,
			       __u32 attr)
{
	struct osd_zap_it   *it = (struct osd_zap_it *)di;
	zap_attribute_t     *za = &osd_oti_get(env)->oti_za;
	size_t		     namelen = 0;
	int		     rc;
	ENTRY;

	if (it->ozi_pos <= OZI_POS_DOT)
		namelen = 1;
	else if (it->ozi_pos == OZI_POS_DOTDOT)
		namelen = 2;

	if (namelen > 0) {
		rc = lu_dirent_calc_size(namelen, attr);
		RETURN(rc);
	}

	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (unlikely(rc != 0))
		RETURN(rc);

	if (za->za_integer_length != 8 || za->za_num_integers < 3) {
		CERROR("%s: unsupported direntry format: %d %d\n",
		       osd_obj2dev(it->ozi_obj)->od_svname,
		       za->za_integer_length, (int)za->za_num_integers);
		RETURN(-EIO);
	}

	namelen = strlen(za->za_name);
	if (namelen > NAME_MAX)
		RETURN(-EOVERFLOW);

	rc = lu_dirent_calc_size(namelen, attr);

	RETURN(rc);
}

static __u64 osd_dir_it_store(const struct lu_env *env, const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	__u64		   pos;
	ENTRY;

	if (it->ozi_pos <= OZI_POS_DOTDOT)
		pos = 0;
	else
		pos = osd_zap_cursor_serialize(it->ozi_zc);

	RETURN(pos);
}

/*
 * return status :
 *  rc == 0 -> end of directory.
 *  rc >  0 -> ok, proceed.
 *  rc <  0 -> error.  ( EOVERFLOW  can be masked.)
 */
static int osd_dir_it_load(const struct lu_env *env,
			const struct dt_it *di, __u64 hash)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	zap_attribute_t   *za = &osd_oti_get(env)->oti_za;
	int		   rc;
	ENTRY;

	/* reset the cursor */
	zap_cursor_fini(it->ozi_zc);
	osd_obj_cursor_init_serialized(it->ozi_zc, obj, hash);

	if (hash == 0) {
		it->ozi_pos = OZI_POS_INIT;
		rc = +1; /* there will be ./.. at least */
	} else {
		it->ozi_pos = OZI_POS_REAL;
		/* to return whether the end has been reached */
		rc = osd_index_retrieve_skip_dots(it, za);
		if (rc == 0)
			rc = +1;
		else if (rc == -ENOENT)
			rc = 0;
	}

	RETURN(rc);
}

const struct dt_index_operations osd_dir_ops = {
	.dio_lookup         = osd_dir_lookup,
	.dio_declare_insert = osd_declare_dir_insert,
	.dio_insert         = osd_dir_insert,
	.dio_declare_delete = osd_declare_dir_delete,
	.dio_delete         = osd_dir_delete,
	.dio_it     = {
		.init     = osd_dir_it_init,
		.fini     = osd_index_it_fini,
		.get      = osd_dir_it_get,
		.put      = osd_dir_it_put,
		.next     = osd_dir_it_next,
		.key      = osd_dir_it_key,
		.key_size = osd_dir_it_key_size,
		.rec      = osd_dir_it_rec,
		.rec_size = osd_dir_it_rec_size,
		.store    = osd_dir_it_store,
		.load     = osd_dir_it_load
	}
};

/*
 * Primitives for index files using binary keys.
 */

/* key integer_size is 8 */
static int osd_prepare_key_uint64(struct osd_object *o, __u64 *dst,
				  const struct dt_key *src)
{
	int size;

	LASSERT(dst);
	LASSERT(src);

	/* align keysize to 64bit */
	size = (o->oo_keysize + sizeof(__u64) - 1) / sizeof(__u64);
	size *= sizeof(__u64);

	LASSERT(size <= MAXNAMELEN);

	if (unlikely(size > o->oo_keysize))
		memset(dst + o->oo_keysize, 0, size - o->oo_keysize);
	memcpy(dst, (const char *)src, o->oo_keysize);

	return (size/sizeof(__u64));
}

static int osd_index_lookup(const struct lu_env *env, struct dt_object *dt,
			struct dt_rec *rec, const struct dt_key *key)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	__u64		  *k = osd_oti_get(env)->oti_key64;
	int                rc;
	ENTRY;

	rc = osd_prepare_key_uint64(obj, k, key);

	rc = -zap_lookup_uint64(osd->od_os, obj->oo_dn->dn_object,
				k, rc, obj->oo_recusize, obj->oo_recsize,
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
	oh = container_of(th, struct osd_thandle, ot_super);

	LASSERT(obj->oo_dn);

	/* do not specify the key as then DMU is trying to look it up
	 * which is very expensive. usually the layers above lookup
	 * before insertion */
	osd_tx_hold_zap(oh->ot_tx, obj->oo_dn->dn_object, obj->oo_dn,
			TRUE, NULL);

	RETURN(0);
}

static int osd_index_insert(const struct lu_env *env, struct dt_object *dt,
			    const struct dt_rec *rec, const struct dt_key *key,
			    struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	__u64		   *k = osd_oti_get(env)->oti_key64;
	int                 rc;
	ENTRY;

	LASSERT(obj->oo_dn);
	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(th != NULL);

	oh = container_of(th, struct osd_thandle, ot_super);

	rc = osd_prepare_key_uint64(obj, k, key);

	/* Insert (key,oid) into ZAP */
	rc = -zap_add_uint64(osd->od_os, obj->oo_dn->dn_object,
			     k, rc, obj->oo_recusize, obj->oo_recsize,
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
	LASSERT(obj->oo_dn);

	oh = container_of(th, struct osd_thandle, ot_super);

	/* do not specify the key as then DMU is trying to look it up
	 * which is very expensive. usually the layers above lookup
	 * before deletion */
	osd_tx_hold_zap(oh->ot_tx, obj->oo_dn->dn_object, obj->oo_dn,
			FALSE, NULL);

	RETURN(0);
}

static int osd_index_delete(const struct lu_env *env, struct dt_object *dt,
			    const struct dt_key *key, struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	__u64		   *k = osd_oti_get(env)->oti_key64;
	int                 rc;
	ENTRY;

	LASSERT(obj->oo_dn);
	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	rc = osd_prepare_key_uint64(obj, k, key);

	/* Remove binary key from the ZAP */
	rc = -zap_remove_uint64(osd->od_os, obj->oo_dn->dn_object,
				k, rc, oh->ot_tx);
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

	/*
	 * XXX: we need a binary version of zap_cursor_move_to_key()
	 *	to implement this API */
	if (*((const __u64 *)key) != 0)
		CERROR("NOT IMPLEMETED YET (move to %#llx)\n",
		       *((__u64 *)key));

	zap_cursor_fini(it->ozi_zc);
	zap_cursor_init(it->ozi_zc, osd->od_os, obj->oo_dn->dn_object);
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
	struct osd_object *obj = it->ozi_obj;
	zap_attribute_t   *za = &osd_oti_get(env)->oti_za;
	int                rc = 0;
	ENTRY;

	it->ozi_reset = 0;
	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (rc)
		RETURN(ERR_PTR(rc));

	/* the binary key is stored in the name */
	memcpy(&it->ozi_key, za->za_name, obj->oo_keysize);

	RETURN((struct dt_key *)&it->ozi_key);
}

static int osd_index_it_key_size(const struct lu_env *env,
				const struct dt_it *di)
{
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	RETURN(obj->oo_keysize);
}

static int osd_index_it_rec(const struct lu_env *env, const struct dt_it *di,
			    struct dt_rec *rec, __u32 attr)
{
	zap_attribute_t   *za = &osd_oti_get(env)->oti_za;
	struct osd_zap_it *it = (struct osd_zap_it *)di;
	struct osd_object *obj = it->ozi_obj;
	struct osd_device *osd = osd_obj2dev(obj);
	__u64		  *k = osd_oti_get(env)->oti_key64;
	int                rc;
	ENTRY;

	it->ozi_reset = 0;
	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (rc)
		RETURN(rc);

	rc = osd_prepare_key_uint64(obj, k, (const struct dt_key *)za->za_name);

	rc = -zap_lookup_uint64(osd->od_os, obj->oo_dn->dn_object,
				k, rc, obj->oo_recusize, obj->oo_recsize,
				(void *)rec);
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

	/* reset the cursor */
	zap_cursor_fini(it->ozi_zc);
	zap_cursor_init_serialized(it->ozi_zc, osd->od_os,
				   obj->oo_dn->dn_object, hash);
	it->ozi_reset = 0;

	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (rc == 0)
		RETURN(+1);
	else if (rc == -ENOENT)
		RETURN(0);

	RETURN(rc);
}

static const struct dt_index_operations osd_index_ops = {
	.dio_lookup		= osd_index_lookup,
	.dio_declare_insert	= osd_declare_index_insert,
	.dio_insert		= osd_index_insert,
	.dio_declare_delete	= osd_declare_index_delete,
	.dio_delete		= osd_index_delete,
	.dio_it	= {
		.init		= osd_index_it_init,
		.fini		= osd_index_it_fini,
		.get		= osd_index_it_get,
		.put		= osd_index_it_put,
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
	struct osd_device *osd = osd_obj2dev(obj);
	const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
	int rc = 0;
	ENTRY;

	down_read(&obj->oo_guard);

	/*
	 * XXX: implement support for fixed-size keys sorted with natural
	 *      numerical way (not using internal hash value)
	 */
	if (feat->dif_flags & DT_IND_RANGE)
		GOTO(out, rc = -ERANGE);

	if (unlikely(feat == &dt_otable_features)) {
		dt->do_index_ops = &osd_otable_ops;
		GOTO(out, rc = 0);
	}

	LASSERT(!dt_object_exists(dt) || obj->oo_dn != NULL);
	if (likely(feat == &dt_directory_features)) {
		if (!dt_object_exists(dt) || osd_object_is_zap(obj->oo_dn))
			dt->do_index_ops = &osd_dir_ops;
		else
			GOTO(out, rc = -ENOTDIR);
	} else if (unlikely(feat == &dt_acct_features)) {
		LASSERT(fid_is_acct(fid));
		dt->do_index_ops = &osd_acct_index_ops;
	} else if (dt->do_index_ops == NULL) {
		/* For index file, we don't support variable key & record sizes
		 * and the key has to be unique */
		if ((feat->dif_flags & ~DT_IND_UPDATE) != 0)
			GOTO(out, rc = -EINVAL);

		if (feat->dif_keysize_max > ZAP_MAXNAMELEN)
			GOTO(out, rc = -E2BIG);
		if (feat->dif_keysize_max != feat->dif_keysize_min)
			GOTO(out, rc = -EINVAL);

		/* As for the record size, it should be a multiple of 8 bytes
		 * and smaller than the maximum value length supported by ZAP.
		 */
		if (feat->dif_recsize_max > ZAP_MAXVALUELEN)
			GOTO(out, rc = -E2BIG);
		if (feat->dif_recsize_max != feat->dif_recsize_min)
			GOTO(out, rc = -EINVAL);

		obj->oo_keysize = feat->dif_keysize_max;
		obj->oo_recsize = feat->dif_recsize_max;
		obj->oo_recusize = 1;

		/* ZFS prefers to work with array of 64bits */
		if ((obj->oo_recsize & 7) == 0) {
			obj->oo_recsize >>= 3;
			obj->oo_recusize = 8;
		}
		dt->do_index_ops = &osd_index_ops;

		if (feat == &dt_lfsck_layout_orphan_features ||
		    feat == &dt_lfsck_layout_dangling_features ||
		    feat == &dt_lfsck_namespace_features)
			GOTO(out, rc = 0);

		rc = osd_index_register(osd, fid, obj->oo_keysize,
					obj->oo_recusize * obj->oo_recsize);
		if (rc < 0)
			CWARN("%s: failed to register index "DFID": rc = %d\n",
			      osd_name(osd), PFID(fid), rc);
		else if (rc > 0)
			rc = 0;
		else
			CDEBUG(D_LFSCK, "%s: index object "DFID
			       " (%u/%u/%u) registered\n",
			       osd_name(osd), PFID(fid), obj->oo_keysize,
			       obj->oo_recusize, obj->oo_recsize);
	}

out:
	up_read(&obj->oo_guard);

	RETURN(rc);
}
