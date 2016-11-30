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
 * lustre/osd-zfs/osd_index.c
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

static inline int osd_object_is_zap(dnode_t *dn)
{
	return (dn->dn_type == DMU_OT_DIRECTORY_CONTENTS ||
			dn->dn_type == DMU_OT_USERGROUP_USED);
}

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
static int osd_get_fid_by_oid(const struct lu_env *env, struct osd_device *osd,
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
 * partially duplicate __osd_xattr_get() which is built around
 * LU-object and uses it to cache data like regular EA dnode, etc
 */
static int osd_find_parent_by_dnode(const struct lu_env *env,
				    struct dt_object *o,
				    struct lu_fid *fid)
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
	if (rc == 0)
		rc = osd_get_fid_by_oid(env, osd, dnode, fid);

	RETURN(rc);
}

static int osd_find_parent_fid(const struct lu_env *env, struct dt_object *o,
			       struct lu_fid *fid)
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
		rc2 = osd_find_parent_by_dnode(env, o, &fid2);
		if (rc2 == 0)
			if (lu_fid_eq(fid, &fid2) == 0)
				CERROR("wrong parent: "DFID" != "DFID"\n",
				       PFID(fid), PFID(&fid2));
	}
#endif

	/* no LinkEA is found, let's try to find the fid in parent's LMA */
	if (unlikely(rc != 0))
		rc = osd_find_parent_by_dnode(env, o, fid);

	RETURN(rc);
}

static int osd_dir_lookup(const struct lu_env *env, struct dt_object *dt,
			  struct dt_rec *rec, const struct dt_key *key)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	char		   *name = (char *)key;
	int                 rc;
	ENTRY;

	if (name[0] == '.') {
		if (name[1] == 0) {
			const struct lu_fid *f = lu_object_fid(&dt->do_lu);
			memcpy(rec, f, sizeof(*f));
			RETURN(1);
		} else if (name[1] == '.' && name[2] == 0) {
			rc = osd_find_parent_fid(env, dt, (struct lu_fid *)rec);
			RETURN(rc == 0 ? 1 : rc);
		}
	}

	memset(&oti->oti_zde.lzd_fid, 0, sizeof(struct lu_fid));
	rc = osd_zap_lookup(osd, obj->oo_dn->dn_object, obj->oo_dn,
			    (char *)key, 8, sizeof(oti->oti_zde) / 8,
			    (void *)&oti->oti_zde);
	if (rc != 0)
		RETURN(rc);

	if (likely(fid_is_sane(&oti->oti_zde.lzd_fid))) {
		memcpy(rec, &oti->oti_zde.lzd_fid, sizeof(struct lu_fid));
		RETURN(1);
	}

	rc = osd_get_fid_by_oid(env, osd, oti->oti_zde.lzd_reg.zde_dnode,
				(struct lu_fid *)rec);

	RETURN(rc == 0 ? 1 : (rc == -ENOENT ? -ENODATA : rc));
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
	ENTRY;

	rec1 = (struct dt_insert_rec *)rec;
	fid = rec1->rec_fid;
	LASSERT(fid != NULL);
	LASSERT(rec1->rec_type != 0);

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	/* This is for inserting dot/dotdot for new created dir. */
	if (obj->oo_dn == NULL)
		object = DMU_NEW_OBJECT;
	else
		object = obj->oo_dn->dn_object;

	/* do not specify the key as then DMU is trying to look it up
	 * which is very expensive. usually the layers above lookup
	 * before insertion */
	osd_tx_hold_zap(oh->ot_tx, object, obj->oo_dn, TRUE, NULL);

	osd_idc_find_or_init(env, osd, fid);

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
 *      \param  ignore_quota update should not affect quota
 *
 *      \retval  0  success
 *      \retval -ve failure
 */
static int osd_dir_insert(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_rec *rec, const struct dt_key *key,
			  struct thandle *th, int ignore_quota)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object   *parent = osd_dt_obj(dt);
	struct osd_device   *osd = osd_obj2dev(parent);
	struct dt_insert_rec *rec1 = (struct dt_insert_rec *)rec;
	const struct lu_fid *fid = rec1->rec_fid;
	struct osd_thandle *oh;
	struct osd_idmap_cache *idc;
	char		    *name = (char *)key;
	int                  rc;
	ENTRY;

	LASSERT(parent->oo_dn);

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(parent));

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	idc = osd_idc_find(env, osd, fid);
	if (unlikely(idc == NULL)) {
		/* this dt_insert() wasn't declared properly, so
		 * FID is missing in OI cache. we better do not
		 * lookup FID in FLDB/OI and don't risk to deadlock,
		 * but in some special cases (lfsck testing, etc)
		 * it's much simpler than fixing a caller */
		CERROR("%s: "DFID" wasn't declared for insert\n",
		       osd_name(osd), PFID(fid));
		idc = osd_idc_find_or_init(env, osd, fid);
		if (IS_ERR(idc))
			RETURN(PTR_ERR(idc));
	}

	if (idc->oic_remote) {
		/* Insert remote entry */
		memset(&oti->oti_zde.lzd_reg, 0, sizeof(oti->oti_zde.lzd_reg));
		oti->oti_zde.lzd_reg.zde_type = IFTODT(rec1->rec_type & S_IFMT);
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
		CLASSERT(sizeof(oti->oti_zde.lzd_reg) == 8);
		CLASSERT(sizeof(oti->oti_zde) % 8 == 0);
		oti->oti_zde.lzd_reg.zde_type = IFTODT(rec1->rec_type & S_IFMT);
		oti->oti_zde.lzd_reg.zde_dnode = idc->oic_dnode;
	}

	oti->oti_zde.lzd_fid = *fid;
	/* Insert (key,oid) into ZAP */
	rc = osd_zap_add(osd, parent->oo_dn->dn_object, parent->oo_dn,
			 (char *)key, 8, sizeof(oti->oti_zde) / 8,
			 (void *)&oti->oti_zde, oh->ot_tx);
	if (unlikely(rc == -EEXIST &&
		     name[0] == '.' && name[1] == '.' && name[2] == 0))
		/* Update (key,oid) in ZAP */
		rc = -zap_update(osd->od_os, parent->oo_dn->dn_object,
				(char *)key, 8, sizeof(oti->oti_zde) / 8,
				(void *)&oti->oti_zde, oh->ot_tx);

out:

	RETURN(rc);
}

static int osd_declare_dir_delete(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_key *key,
				  struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	uint64_t	    dnode;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	if (dt_object_exists(dt)) {
		LASSERT(obj->oo_dn);
		dnode = obj->oo_dn->dn_object;
	} else {
		dnode = DMU_NEW_OBJECT;
	}

	/* do not specify the key as then DMU is trying to look it up
	 * which is very expensive. usually the layers above lookup
	 * before deletion */
	osd_tx_hold_zap(oh->ot_tx, dnode, obj->oo_dn, FALSE, NULL);

	RETURN(0);
}

static int osd_dir_delete(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_key *key, struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	dnode_t *zap_dn = obj->oo_dn;
	char	  *name = (char *)key;
	int rc;
	ENTRY;

	LASSERT(zap_dn);

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

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

	/* Remove key from the ZAP */
	rc = osd_zap_remove(osd, zap_dn->dn_object, zap_dn,
			    (char *)key, oh->ot_tx);

	if (unlikely(rc && rc != -ENOENT))
		CERROR("%s: zap_remove failed: rc = %d\n", osd->od_svname, rc);

	RETURN(rc);
}

static struct dt_it *osd_dir_it_init(const struct lu_env *env,
				     struct dt_object *dt,
				     __u32 unused)
{
	struct osd_zap_it *it;

	it = (struct osd_zap_it *)osd_index_it_init(env, dt, unused);
	if (!IS_ERR(it))
		it->ozi_pos = 0;

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
		it->ozi_pos = 0;
		RETURN(1);
	}

	if (name[0] == '.') {
		if (name[1] == 0) {
			it->ozi_pos = 1;
			GOTO(out, rc = 1);
		} else if (name[1] == '.' && name[2] == 0) {
			it->ozi_pos = 2;
			GOTO(out, rc = 1);
		}
	}

	/* neither . nor .. - some real record */
	it->ozi_pos = 3;
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
	CLASSERT(sizeof(za->za_name) <= sizeof(it->ozi_name));

	/*
	 * the first ->next() moves the cursor to .
	 * the second ->next() moves the cursor to ..
	 * then we get to the real records and have to verify any exist
	 */
	if (it->ozi_pos <= 2) {
		it->ozi_pos++;
		if (it->ozi_pos <=2)
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

	if (it->ozi_pos <= 1) {
		it->ozi_pos = 1;
		RETURN((struct dt_key *)".");
	} else if (it->ozi_pos == 2) {
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

	if (it->ozi_pos <= 1) {
		it->ozi_pos = 1;
		RETURN(2);
	} else if (it->ozi_pos == 2) {
		RETURN(3);
	}

	if ((rc = -zap_cursor_retrieve(it->ozi_zc, za)) == 0)
		rc = strlen(za->za_name);

	RETURN(rc);
}

static int osd_dir_it_rec(const struct lu_env *env, const struct dt_it *di,
			  struct dt_rec *dtrec, __u32 attr)
{
	struct osd_zap_it   *it = (struct osd_zap_it *)di;
	struct lu_dirent    *lde = (struct lu_dirent *)dtrec;
	struct luz_direntry *zde = &osd_oti_get(env)->oti_zde;
	zap_attribute_t     *za = &osd_oti_get(env)->oti_za;
	int		     rc, namelen;
	ENTRY;

	if (it->ozi_pos <= 1) {
		lde->lde_hash = cpu_to_le64(1);
		strcpy(lde->lde_name, ".");
		lde->lde_namelen = cpu_to_le16(1);
		lde->lde_fid = *lu_object_fid(&it->ozi_obj->oo_dt.do_lu);
		lde->lde_attrs = LUDA_FID;
		/* append lustre attributes */
		osd_it_append_attrs(lde, attr, 1, IFTODT(S_IFDIR));
		lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(1, attr));
		it->ozi_pos = 1;
		GOTO(out, rc = 0);

	} else if (it->ozi_pos == 2) {
		lde->lde_hash = cpu_to_le64(2);
		strcpy(lde->lde_name, "..");
		lde->lde_namelen = cpu_to_le16(2);
		lde->lde_attrs = LUDA_FID;
		/* append lustre attributes */
		osd_it_append_attrs(lde, attr, 2, IFTODT(S_IFDIR));
		lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(2, attr));
		rc = osd_find_parent_fid(env, &it->ozi_obj->oo_dt, &lde->lde_fid);

		/* ENOENT happens at the root of filesystem so ignore it */
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out, rc);
	}

	LASSERT(lde);

	rc = -zap_cursor_retrieve(it->ozi_zc, za);
	if (unlikely(rc != 0))
		GOTO(out, rc);

	lde->lde_hash = cpu_to_le64(osd_zap_cursor_serialize(it->ozi_zc));
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

	rc = osd_zap_lookup(osd_obj2dev(it->ozi_obj), it->ozi_zc->zc_zapobj,
			    it->ozi_obj->oo_dn, za->za_name,
			    za->za_integer_length, 3, zde);
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

static int osd_dir_it_rec_size(const struct lu_env *env, const struct dt_it *di,
			       __u32 attr)
{
	struct osd_zap_it   *it = (struct osd_zap_it *)di;
	zap_attribute_t     *za = &osd_oti_get(env)->oti_za;
	size_t		     namelen = 0;
	int		     rc;
	ENTRY;

	if (it->ozi_pos <= 1)
		namelen = 1;
	else if (it->ozi_pos == 2)
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

	if (it->ozi_pos <= 2)
		pos = it->ozi_pos;
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

	if (hash <= 2) {
		it->ozi_pos = hash;
		rc = +1;
	} else {
		it->ozi_pos = 3;
		/* to return whether the end has been reached */
		rc = osd_index_retrieve_skip_dots(it, za);
		if (rc == 0)
			rc = +1;
		else if (rc == -ENOENT)
			rc = 0;
	}

	RETURN(rc);
}

struct dt_index_operations osd_dir_ops = {
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
	oh = container_of0(th, struct osd_thandle, ot_super);

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
			    struct thandle *th, int ignore_quota)
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

	oh = container_of0(th, struct osd_thandle, ot_super);

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

	oh = container_of0(th, struct osd_thandle, ot_super);

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
	oh = container_of0(th, struct osd_thandle, ot_super);

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

static struct dt_index_operations osd_index_ops = {
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

struct osd_metadnode_it {
	struct osd_device       *mit_dev;
	__u64			 mit_pos;
	struct lu_fid		 mit_fid;
	int			 mit_prefetched;
	__u64			 mit_prefetched_dnode;
};

static struct dt_it *osd_zfs_otable_it_init(const struct lu_env *env,
					    struct dt_object *dt, __u32 attr)
{
	struct osd_device	*dev   = osd_dev(dt->do_lu.lo_dev);
	struct osd_metadnode_it *it;
	ENTRY;

	OBD_ALLOC_PTR(it);
	if (unlikely(it == NULL))
		RETURN(ERR_PTR(-ENOMEM));

	it->mit_dev = dev;

	/* XXX: dmu_object_next() does NOT find dnodes allocated
	 *	in the current non-committed txg, so we force txg
	 *	commit to find all existing dnodes ... */
	if (!dev->od_dt_dev.dd_rdonly)
		txg_wait_synced(dmu_objset_pool(dev->od_os), 0ULL);

	RETURN((struct dt_it *)it);
}

static void osd_zfs_otable_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_metadnode_it *it  = (struct osd_metadnode_it *)di;

	OBD_FREE_PTR(it);
}

static int osd_zfs_otable_it_get(const struct lu_env *env,
				 struct dt_it *di, const struct dt_key *key)
{
	return 0;
}

static void osd_zfs_otable_it_put(const struct lu_env *env, struct dt_it *di)
{
}

#define OTABLE_PREFETCH		256

static void osd_zfs_otable_prefetch(const struct lu_env *env,
				    struct osd_metadnode_it *it)
{
	struct osd_device	*dev = it->mit_dev;
	int			 rc;

	/* can go negative on the very first access to the iterator
	 * or if some non-Lustre objects were found */
	if (unlikely(it->mit_prefetched < 0))
		it->mit_prefetched = 0;

	if (it->mit_prefetched >= (OTABLE_PREFETCH >> 1))
		return;

	if (it->mit_prefetched_dnode == 0)
		it->mit_prefetched_dnode = it->mit_pos;

	while (it->mit_prefetched < OTABLE_PREFETCH) {
		rc = -dmu_object_next(dev->od_os, &it->mit_prefetched_dnode,
				      B_FALSE, 0);
		if (unlikely(rc != 0))
			break;

		osd_dmu_prefetch(dev->od_os, it->mit_prefetched_dnode,
				 0, 0, 0, ZIO_PRIORITY_ASYNC_READ);

		it->mit_prefetched++;
	}
}

static int osd_zfs_otable_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_metadnode_it *it  = (struct osd_metadnode_it *)di;
	struct lustre_mdt_attrs *lma;
	struct osd_device	*dev = it->mit_dev;
	nvlist_t		*nvbuf = NULL;
	uchar_t			*v;
	__u64			 dnode;
	int			 rc, s;

	memset(&it->mit_fid, 0, sizeof(it->mit_fid));

	dnode = it->mit_pos;
	do {
		rc = -dmu_object_next(dev->od_os, &it->mit_pos, B_FALSE, 0);
		if (unlikely(rc != 0))
			GOTO(out, rc = 1);
		it->mit_prefetched--;

		/* LMA is required for this to be a Lustre object.
		 * If there is no xattr skip it. */
		rc = __osd_xattr_load_by_oid(dev, it->mit_pos, &nvbuf);
		if (unlikely(rc != 0))
			continue;

		LASSERT(nvbuf != NULL);
		rc = -nvlist_lookup_byte_array(nvbuf, XATTR_NAME_LMA, &v, &s);
		if (likely(rc == 0)) {
			/* Lustre object */
			lma = (struct lustre_mdt_attrs *)v;
			lustre_lma_swab(lma);
			it->mit_fid = lma->lma_self_fid;
			nvlist_free(nvbuf);
			break;
		} else {
			/* not a Lustre object, try next one */
			nvlist_free(nvbuf);
		}

	} while (1);


	/* we aren't prefetching in the above loop because the number of
	 * non-Lustre objects is very small and we will be repeating very
	 * rare. in case we want to use this to iterate over non-Lustre
	 * objects (i.e. when we convert regular ZFS in Lustre) it makes
	 * sense to initiate prefetching in the loop */

	/* 0 - there are more items, +1 - the end */
	if (likely(rc == 0))
		osd_zfs_otable_prefetch(env, it);

	CDEBUG(D_OTHER, "advance: %llu -> %llu "DFID": %d\n", dnode,
	       it->mit_pos, PFID(&it->mit_fid), rc);

out:
	return rc;
}

static struct dt_key *osd_zfs_otable_it_key(const struct lu_env *env,
					    const struct dt_it *di)
{
	return NULL;
}

static int osd_zfs_otable_it_key_size(const struct lu_env *env,
				      const struct dt_it *di)
{
	return sizeof(__u64);
}

static int osd_zfs_otable_it_rec(const struct lu_env *env,
				 const struct dt_it *di,
				 struct dt_rec *rec, __u32 attr)
{
	struct osd_metadnode_it *it  = (struct osd_metadnode_it *)di;
	struct lu_fid *fid = (struct lu_fid *)rec;
	ENTRY;

	*fid = it->mit_fid;

	RETURN(0);
}


static __u64 osd_zfs_otable_it_store(const struct lu_env *env,
				     const struct dt_it *di)
{
	struct osd_metadnode_it *it  = (struct osd_metadnode_it *)di;

	return it->mit_pos;
}

static int osd_zfs_otable_it_load(const struct lu_env *env,
				  const struct dt_it *di, __u64 hash)
{
	struct osd_metadnode_it *it  = (struct osd_metadnode_it *)di;

	it->mit_pos = hash;
	it->mit_prefetched = 0;
	it->mit_prefetched_dnode = 0;

	return osd_zfs_otable_it_next(env, (struct dt_it *)di);
}

static int osd_zfs_otable_it_key_rec(const struct lu_env *env,
				     const struct dt_it *di, void *key_rec)
{
	return 0;
}

const struct dt_index_operations osd_zfs_otable_ops = {
	.dio_it = {
		.init     = osd_zfs_otable_it_init,
		.fini     = osd_zfs_otable_it_fini,
		.get      = osd_zfs_otable_it_get,
		.put	  = osd_zfs_otable_it_put,
		.next     = osd_zfs_otable_it_next,
		.key	  = osd_zfs_otable_it_key,
		.key_size = osd_zfs_otable_it_key_size,
		.rec      = osd_zfs_otable_it_rec,
		.store    = osd_zfs_otable_it_store,
		.load     = osd_zfs_otable_it_load,
		.key_rec  = osd_zfs_otable_it_key_rec,
	}
};

int osd_index_try(const struct lu_env *env, struct dt_object *dt,
		const struct dt_index_features *feat)
{
	struct osd_object *obj = osd_dt_obj(dt);
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
		dt->do_index_ops = &osd_zfs_otable_ops;
		GOTO(out, rc = 0);
	}

	LASSERT(!dt_object_exists(dt) || obj->oo_dn != NULL);
	if (likely(feat == &dt_directory_features)) {
		if (!dt_object_exists(dt) || osd_object_is_zap(obj->oo_dn))
			dt->do_index_ops = &osd_dir_ops;
		else
			GOTO(out, rc = -ENOTDIR);
	} else if (unlikely(feat == &dt_acct_features)) {
		LASSERT(fid_is_acct(lu_object_fid(&dt->do_lu)));
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
	}

out:
	up_read(&obj->oo_guard);

	RETURN(rc);
}
