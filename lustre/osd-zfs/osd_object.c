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
 * lustre/osd-zfs/osd_object.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 * Author: Johann Lombardi <johann@whamcloud.com>
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

char *osd_obj_tag = "osd_object";
static int osd_object_sync_delay_us = -1;

static const struct dt_object_operations osd_obj_ops;
static const struct lu_object_operations osd_lu_obj_ops;
static const struct dt_object_operations osd_obj_otable_it_ops;

static void
osd_object_sa_fini(struct osd_object *obj)
{
	if (obj->oo_sa_hdl) {
		sa_handle_destroy(obj->oo_sa_hdl);
		obj->oo_sa_hdl = NULL;
	}
}

static int
osd_object_sa_init(struct osd_object *obj, struct osd_device *o)
{
	int rc;

	LASSERT(obj->oo_sa_hdl == NULL);
	LASSERT(obj->oo_dn != NULL);

	rc = osd_sa_handle_get(obj);
	if (rc)
		return rc;

	/* Cache the xattr object id, valid for the life of the object */
	rc = -sa_lookup(obj->oo_sa_hdl, SA_ZPL_XATTR(o), &obj->oo_xattr, 8);
	if (rc == -ENOENT) {
		obj->oo_xattr = ZFS_NO_OBJECT;
		rc = 0;
	} else if (rc) {
		osd_object_sa_fini(obj);
	}

	return rc;
}

/*
 * Add object to list of dirty objects in tx handle.
 */
void osd_object_sa_dirty_add(struct osd_object *obj, struct osd_thandle *oh)
{
	if (!list_empty(&obj->oo_sa_linkage))
		return;

	write_lock(&obj->oo_attr_lock);
	if (likely(list_empty(&obj->oo_sa_linkage)))
		list_add(&obj->oo_sa_linkage, &oh->ot_sa_list);
	write_unlock(&obj->oo_attr_lock);
}

/*
 * Release spill block dbuf hold for all dirty SAs.
 */
void osd_object_sa_dirty_rele(const struct lu_env *env, struct osd_thandle *oh)
{
	struct osd_object *obj;

	while (!list_empty(&oh->ot_sa_list)) {
		obj = list_entry(oh->ot_sa_list.next,
				 struct osd_object, oo_sa_linkage);
		write_lock(&obj->oo_attr_lock);
		list_del_init(&obj->oo_sa_linkage);
		write_unlock(&obj->oo_attr_lock);
		if (obj->oo_late_xattr) {
			/*
			 * take oo_guard to protect oo_sa_xattr buffer
			 * from concurrent update by osd_xattr_set()
			 */
			LASSERT(oh->ot_assigned != 0);
			down_write(&obj->oo_guard);
			if (obj->oo_late_attr_set)
				__osd_sa_attr_init(env, obj, oh);
			else if (obj->oo_late_xattr)
				__osd_sa_xattr_update(env, obj, oh);
			up_write(&obj->oo_guard);
		}
		sa_spill_rele(obj->oo_sa_hdl);
	}
}

/*
 * Update the SA and add the object to the dirty list.
 */
int osd_object_sa_update(struct osd_object *obj, sa_attr_type_t type,
			 void *buf, uint32_t buflen, struct osd_thandle *oh)
{
	int rc;

	LASSERT(obj->oo_sa_hdl != NULL);
	LASSERT(oh->ot_tx != NULL);

	rc = -sa_update(obj->oo_sa_hdl, type, buf, buflen, oh->ot_tx);
	osd_object_sa_dirty_add(obj, oh);

	return rc;
}

/*
 * Bulk update the SA and add the object to the dirty list.
 */
static int
osd_object_sa_bulk_update(struct osd_object *obj, sa_bulk_attr_t *attrs,
			  int count, struct osd_thandle *oh)
{
	int rc;

	LASSERT(obj->oo_sa_hdl != NULL);
	LASSERT(oh->ot_tx != NULL);

	rc = -sa_bulk_update(obj->oo_sa_hdl, attrs, count, oh->ot_tx);
	osd_object_sa_dirty_add(obj, oh);

	return rc;
}

/*
 * Retrieve the attributes of a DMU object
 */
static int __osd_object_attr_get(const struct lu_env *env, struct osd_device *o,
				 struct osd_object *obj, struct lu_attr *la)
{
	struct osa_attr *osa = &osd_oti_get(env)->oti_osa;
	sa_bulk_attr_t *bulk = osd_oti_get(env)->oti_attr_bulk;
	struct lustre_mdt_attrs *lma;
	struct lu_buf buf;
	int cnt = 0;
	int		 rc;
	ENTRY;

	LASSERT(obj->oo_dn != NULL);

	la->la_valid |= LA_ATIME | LA_MTIME | LA_CTIME | LA_BTIME | LA_MODE |
			LA_TYPE | LA_SIZE | LA_UID | LA_GID | LA_FLAGS |
			LA_NLINK;

	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_ATIME(o), NULL, osa->atime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MTIME(o), NULL, osa->mtime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CTIME(o), NULL, osa->ctime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CRTIME(o), NULL, osa->btime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MODE(o), NULL, &osa->mode, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_SIZE(o), NULL, &osa->size, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_LINKS(o), NULL, &osa->nlink, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_UID(o), NULL, &osa->uid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_GID(o), NULL, &osa->gid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_FLAGS(o), NULL, &osa->flags, 8);
	LASSERT(cnt <= ARRAY_SIZE(osd_oti_get(env)->oti_attr_bulk));

	rc = -sa_bulk_lookup(obj->oo_sa_hdl, bulk, cnt);
	if (rc)
		GOTO(out_sa, rc);

#ifdef ZFS_PROJINHERIT
	if (o->od_projectused_dn && osa->flags & ZFS_PROJID) {
		rc = -sa_lookup(obj->oo_sa_hdl, SA_ZPL_PROJID(o),
				&osa->projid, 8);
		if (rc)
			GOTO(out_sa, rc);

		la->la_projid = osa->projid;
		la->la_valid |= LA_PROJID;
		obj->oo_with_projid = 1;
	} else {
		la->la_projid = ZFS_DEFAULT_PROJID;
		la->la_valid &= ~LA_PROJID;
	}
#else
	la->la_projid = 0;
	la->la_valid &= ~LA_PROJID;
#endif

	la->la_atime = osa->atime[0];
	la->la_mtime = osa->mtime[0];
	la->la_ctime = osa->ctime[0];
	la->la_btime = osa->btime[0];
	la->la_mode = osa->mode;
	la->la_uid = osa->uid;
	la->la_gid = osa->gid;
	la->la_nlink = osa->nlink;
	la->la_flags = attrs_zfs2fs(osa->flags);
	la->la_size = osa->size;

	/* Try to get extra flags from LMA */
	lma = (struct lustre_mdt_attrs *)osd_oti_get(env)->oti_buf;
	buf.lb_buf = lma;
	buf.lb_len = sizeof(osd_oti_get(env)->oti_buf);
	down_read(&obj->oo_guard);
	rc = osd_xattr_get_lma(env, obj, &buf);
	if (!rc) {
		lma->lma_incompat = le32_to_cpu(lma->lma_incompat);
		obj->oo_lma_flags =
			lma_to_lustre_flags(lma->lma_incompat);
	} else if (rc == -ENODATA ||
		   !(S_ISDIR(la->la_mode) &&
		     dt_object_exists(&obj->oo_dt))) {
		rc = 0;
	}
	up_read(&obj->oo_guard);

	if (S_ISCHR(la->la_mode) || S_ISBLK(la->la_mode)) {
		rc = -sa_lookup(obj->oo_sa_hdl, SA_ZPL_RDEV(o), &osa->rdev, 8);
		if (rc)
			GOTO(out_sa, rc);
		la->la_rdev = osa->rdev;
		la->la_valid |= LA_RDEV;
	}
out_sa:

	RETURN(rc);
}

int __osd_obj2dnode(objset_t *os, uint64_t oid, dnode_t **dnp)
{
	dmu_buf_t *db;
	dmu_buf_impl_t *dbi;
	int rc;

	rc = -dmu_bonus_hold(os, oid, osd_obj_tag, &db);
	if (rc)
		return rc;

	dbi = (dmu_buf_impl_t *)db;
	DB_DNODE_ENTER(dbi);
	*dnp = DB_DNODE(dbi);
	DB_DNODE_EXIT(dbi);
	LASSERT(*dnp != NULL);

	return 0;
}

/*
 * Concurrency: no concurrent access is possible that early in object
 * life-cycle.
 */
struct lu_object *osd_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *d)
{
	struct osd_object *mo;

	OBD_SLAB_ALLOC_PTR_GFP(mo, osd_object_kmem, GFP_NOFS);
	if (mo != NULL) {
		struct lu_object *l;
		struct lu_object_header *h;
		struct osd_device *o = osd_dev(d);

		l = &mo->oo_dt.do_lu;
		if (unlikely(o->od_in_init)) {
			OBD_ALLOC_PTR(h);
			if (!h) {
				OBD_FREE_PTR(mo);
				return NULL;
			}

			lu_object_header_init(h);
			lu_object_init(l, h, d);
			lu_object_add_top(h, l);
			mo->oo_header = h;
		} else {
			dt_object_init(&mo->oo_dt, NULL, d);
			mo->oo_header = NULL;
		}

		mo->oo_dt.do_ops = &osd_obj_ops;
		l->lo_ops = &osd_lu_obj_ops;
		INIT_LIST_HEAD(&mo->oo_sa_linkage);
		INIT_LIST_HEAD(&mo->oo_unlinked_linkage);
		init_rwsem(&mo->oo_sem);
		init_rwsem(&mo->oo_guard);
		rwlock_init(&mo->oo_attr_lock);
		mo->oo_destroy = OSD_DESTROY_NONE;
		return l;
	} else {
		return NULL;
	}
}

static void osd_obj_set_blksize(const struct lu_env *env,
				struct osd_device *osd, struct osd_object *obj)
{
	const struct lu_fid *fid = lu_object_fid(&obj->oo_dt.do_lu);
	dmu_tx_t *tx;
	dnode_t *dn = obj->oo_dn;
	uint32_t blksz;
	int rc = 0;
	ENTRY;

	LASSERT(!osd_oti_get(env)->oti_in_trans);

	tx = dmu_tx_create(osd->od_os);
	if (!tx) {
		CERROR("%s: fail to create tx to set blksize for "DFID"\n",
		       osd->od_svname, PFID(fid));
		RETURN_EXIT;
	}

	dmu_tx_hold_bonus(tx, dn->dn_object);
	rc = -dmu_tx_assign(tx, TXG_WAIT);
	if (rc) {
		dmu_tx_abort(tx);
		CERROR("%s: fail to assign tx to set blksize for "DFID
		       ": rc = %d\n", osd->od_svname, PFID(fid), rc);
		RETURN_EXIT;
	}

	down_write(&obj->oo_guard);
	if (unlikely((1 << dn->dn_datablkshift) >= PAGE_SIZE))
		GOTO(out, rc = 1);

	blksz = dn->dn_datablksz;
	if (!is_power_of_2(blksz))
		blksz = size_roundup_power2(blksz);

	if (blksz > osd->od_max_blksz)
		blksz = osd->od_max_blksz;
	else if (blksz < PAGE_SIZE)
		blksz = PAGE_SIZE;
	rc = -dmu_object_set_blocksize(osd->od_os, dn->dn_object, blksz, 0, tx);

	GOTO(out, rc);

out:
	up_write(&obj->oo_guard);
	if (rc) {
		dmu_tx_abort(tx);
		if (unlikely(obj->oo_dn->dn_maxblkid > 0))
			rc = 1;
		if (rc < 0)
			CERROR("%s: fail to set blksize for "DFID": rc = %d\n",
			       osd->od_svname, PFID(fid), rc);
	} else {
		dmu_tx_commit(tx);
		CDEBUG(D_INODE, "%s: set blksize as %u for "DFID"\n",
		       osd->od_svname, blksz, PFID(fid));
	}
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_object_init0(const struct lu_env *env, struct osd_object *obj)
{
	struct osd_device	*osd = osd_obj2dev(obj);
	const struct lu_fid	*fid = lu_object_fid(&obj->oo_dt.do_lu);
	int			 rc = 0;
	ENTRY;

	LASSERT(obj->oo_dn);

	rc = osd_object_sa_init(obj, osd);
	if (rc)
		RETURN(rc);

	/* cache attrs in object */
	rc = __osd_object_attr_get(env, osd, obj, &obj->oo_attr);
	if (rc)
		RETURN(rc);

	if (likely(!fid_is_acct(fid))) {
		/* no body operations for accounting objects */
		obj->oo_dt.do_body_ops = &osd_body_ops;

		if (S_ISREG(obj->oo_attr.la_mode) &&
		    obj->oo_dn->dn_maxblkid == 0 &&
		    (1 << obj->oo_dn->dn_datablkshift) < PAGE_SIZE &&
		    (fid_is_idif(fid) || fid_is_norm(fid) ||
		     fid_is_echo(fid)) &&
		    osd->od_is_ost && !osd->od_dt_dev.dd_rdonly)
			osd_obj_set_blksize(env, osd, obj);
	}

	/*
	 * initialize object before marking it existing
	 */
	obj->oo_dt.do_lu.lo_header->loh_attr |= obj->oo_attr.la_mode & S_IFMT;

	smp_mb();
	obj->oo_dt.do_lu.lo_header->loh_attr |= LOHA_EXISTS;

	RETURN(0);
}

static int osd_check_lma(const struct lu_env *env, struct osd_object *obj)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct lu_buf		buf;
	int			rc;
	struct lustre_mdt_attrs	*lma;
	const struct lu_fid *rfid = lu_object_fid(&obj->oo_dt.do_lu);
	ENTRY;

	BUILD_BUG_ON(sizeof(info->oti_buf) < sizeof(*lma));
	lma = (struct lustre_mdt_attrs *)info->oti_buf;
	buf.lb_buf = lma;
	buf.lb_len = sizeof(info->oti_buf);

	rc = osd_xattr_get(env, &obj->oo_dt, &buf, XATTR_NAME_LMA);
	if (rc > 0) {
		rc = 0;
		lustre_lma_swab(lma);
		if (unlikely((lma->lma_incompat & ~LMA_INCOMPAT_SUPP) ||
			     CFS_FAIL_CHECK(OBD_FAIL_OSD_LMA_INCOMPAT))) {
			CWARN("%s: unsupported incompat LMA feature(s) %#x for "
			      "fid = "DFID"\n", osd_obj2dev(obj)->od_svname,
			      lma->lma_incompat & ~LMA_INCOMPAT_SUPP,
			      PFID(rfid));
			rc = -EOPNOTSUPP;
		} else if (unlikely(!lu_fid_eq(rfid, &lma->lma_self_fid))) {
			CERROR("%s: FID-in-LMA "DFID" does not match the "
			      "object self-fid "DFID"\n",
			      osd_obj2dev(obj)->od_svname,
			      PFID(&lma->lma_self_fid), PFID(rfid));
			rc = -EREMCHG;
		} else {
			struct osd_device *osd = osd_obj2dev(obj);

			if (lma->lma_compat & LMAC_STRIPE_INFO &&
			    osd->od_is_ost)
				obj->oo_pfid_in_lma = 1;
			if (unlikely(lma->lma_incompat & LMAI_REMOTE_PARENT) &&
			    osd->od_remote_parent_dir != ZFS_NO_OBJECT)
				lu_object_set_agent_entry(&obj->oo_dt.do_lu);
		}
	} else if (rc == -ENODATA) {
		/* haven't initialize LMA xattr */
		rc = 0;
	}

	RETURN(rc);
}

/**
 * Helper function to retrieve DMU object id from fid for accounting object
 */
static dnode_t *osd_quota_fid2dmu(const struct osd_device *osd,
				  const struct lu_fid *fid)
{
	dnode_t *dn = NULL;

	LASSERT(fid_is_acct(fid));

	switch (fid_oid(fid)) {
	case ACCT_USER_OID:
		dn = osd->od_userused_dn;
		break;
	case ACCT_GROUP_OID:
		dn = osd->od_groupused_dn;
		break;
#ifdef ZFS_PROJINHERIT
	case ACCT_PROJECT_OID:
		dn = osd->od_projectused_dn;
		break;
#endif
	default:
		break;
	}

	return dn;
}

/*
 * Concurrency: no concurrent access is possible that early in object
 * life-cycle.
 */
static int osd_object_init(const struct lu_env *env, struct lu_object *l,
			   const struct lu_object_conf *conf)
{
	struct osd_object *obj = osd_obj(l);
	struct osd_device *osd = osd_obj2dev(obj);
	const struct lu_fid *fid = lu_object_fid(l);
	struct lustre_scrub *scrub = &osd->od_scrub;
	struct osd_thread_info *info = osd_oti_get(env);
	struct luz_direntry *zde = &info->oti_zde;
	struct osd_idmap_cache *idc;
	char *name = info->oti_str;
	uint64_t oid;
	int rc = 0;
	int rc1;
	bool remote = false;
	ENTRY;

	LASSERT(osd_invariant(obj));

	if (fid_is_otable_it(&l->lo_header->loh_fid)) {
		obj->oo_dt.do_ops = &osd_obj_otable_it_ops;
		l->lo_header->loh_attr |= LOHA_EXISTS;

		GOTO(out, rc = 0);
	}

	if (conf && conf->loc_flags & LOC_F_NEW)
		GOTO(out, rc = 0);

	if (unlikely(fid_is_acct(fid))) {
		obj->oo_dn = osd_quota_fid2dmu(osd, fid);
		if (obj->oo_dn) {
			obj->oo_dt.do_index_ops = &osd_acct_index_ops;
			l->lo_header->loh_attr |= LOHA_EXISTS;
		}

		GOTO(out, rc = 0);
	}

	idc = osd_idc_find(env, osd, fid);
	if (idc && !idc->oic_remote && idc->oic_dnode != ZFS_NO_OBJECT) {
		oid = idc->oic_dnode;
		goto zget;
	}

	rc = -ENOENT;
	if (!list_empty(&osd->od_scrub.os_inconsistent_items))
		rc = osd_oii_lookup(osd, fid, &oid);

	if (rc)
		rc = osd_fid_lookup(env, osd, fid, &oid);

	if (rc == -ENOENT) {
		if (likely(!(fid_is_norm(fid) || fid_is_igif(fid)) ||
			   fid_is_on_ost(env, osd, fid) ||
			   !zfs_test_bit(osd_oi_fid2idx(osd, fid),
					 scrub->os_file.sf_oi_bitmap)))
			GOTO(out, rc = 0);

		rc = -EREMCHG;
		goto trigger;
	}

	if (rc)
		GOTO(out, rc);

zget:
	LASSERT(obj->oo_dn == NULL);

	rc = __osd_obj2dnode(osd->od_os, oid, &obj->oo_dn);
	/* EEXIST will be returned if object is being deleted in ZFS */
	if (rc == -EEXIST)
		GOTO(out, rc = 0);

	if (rc) {
		CERROR("%s: lookup "DFID"/%#llx failed: rc = %d\n",
		       osd->od_svname, PFID(lu_object_fid(l)), oid, rc);
		GOTO(out, rc);
	}

	rc = osd_object_init0(env, obj);
	if (rc)
		GOTO(out, rc);

	if (unlikely(obj->oo_header))
		GOTO(out, rc = 0);

	rc = osd_check_lma(env, obj);
	if (rc != -EREMCHG)
		GOTO(out, rc);

	osd_scrub_refresh_mapping(env, osd, fid, oid, DTO_INDEX_DELETE, true,
				  NULL);

trigger:
	/* We still have chance to get the valid dnode: for the object that is
	 * referenced by remote name entry, the object on the local MDT will be
	 * linked under the dir /REMOTE_PARENT_DIR with its FID string as name.
	 *
	 * During the OI scrub, if we cannot find the OI mapping, we may still
	 * have change to map the FID to local OID via lookup the dir
	 * /REMOTE_PARENT_DIR. */
	if (!remote && !fid_is_on_ost(env, osd, fid)) {
		osd_fid2str(name, fid, sizeof(info->oti_str));
		rc = osd_zap_lookup(osd, osd->od_remote_parent_dir,
				    NULL, name, 8, 3, (void *)zde);
		if (!rc) {
			oid = zde->lzd_reg.zde_dnode;
			osd_dnode_rele(obj->oo_dn);
			obj->oo_dn = NULL;
			remote = true;
			goto zget;
		}
	}

	/* The case someone triggered the OI scrub already. */
	if (scrub->os_running) {
		if (!rc) {
			LASSERT(remote);

			lu_object_set_agent_entry(l);
			osd_oii_insert(env, osd, fid, oid, false);
		} else {
			rc = -EINPROGRESS;
		}

		GOTO(out, rc);
	}

	/* The case NOT allow to trigger OI scrub automatically. */
	if (osd->od_auto_scrub_interval == AS_NEVER)
		GOTO(out, rc);

	/* It is me to trigger the OI scrub. */
	rc1 = osd_scrub_start(env, osd, SS_CLEAR_DRYRUN |
			      SS_CLEAR_FAILOUT | SS_AUTO_FULL);
	CDEBUG_LIMIT(D_LFSCK | D_CONSOLE | D_WARNING,
		     "%s: trigger OI scrub by RPC for "DFID"/%#llx: rc = %d\n",
		     osd_name(osd), PFID(fid), oid, rc1);
	if (!rc) {
		LASSERT(remote);

		lu_object_set_agent_entry(l);
		if (!rc1)
			osd_oii_insert(env, osd, fid, oid, false);
	} else {
		if (!rc1)
			rc = -EINPROGRESS;
		else
			rc = -EREMCHG;
	}

	GOTO(out, rc);

out:
	RETURN(rc);
}

/*
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle.
 */
static void osd_object_free(const struct lu_env *env, struct lu_object *l)
{
	struct osd_object *obj = osd_obj(l);
	struct lu_object_header *h = obj->oo_header;

	LASSERT(osd_invariant(obj));

	dt_object_fini(&obj->oo_dt);
	/* obj doesn't contain an lu_object_header, so we don't need call_rcu */
	OBD_SLAB_FREE_PTR(obj, osd_object_kmem);
	if (unlikely(h))
		lu_object_header_free(h);
}

static int
osd_object_unlinked_add(struct osd_object *obj, struct osd_thandle *oh)
{
	int rc = -EBUSY;

	LASSERT(obj->oo_destroy == OSD_DESTROY_ASYNC);

	/* the object is supposed to be exclusively locked by
	 * the caller (osd_destroy()), while the transaction
	 * (oh) is per-thread and not shared */
	if (likely(list_empty(&obj->oo_unlinked_linkage))) {
		list_add(&obj->oo_unlinked_linkage, &oh->ot_unlinked_list);
		rc = 0;
	}

	return rc;
}

/* Default to max data size covered by a level-1 indirect block */
static unsigned long osd_sync_destroy_max_size =
	1UL << (DN_MAX_INDBLKSHIFT - SPA_BLKPTRSHIFT + SPA_MAXBLOCKSHIFT);
module_param(osd_sync_destroy_max_size, ulong, 0444);
MODULE_PARM_DESC(osd_sync_destroy_max_size, "Maximum object size to use synchronous destroy.");

static inline void
osd_object_set_destroy_type(struct osd_object *obj)
{
	/*
	 * Lock-less OST_WRITE can race with OST_DESTROY, so set destroy type
	 * only once and use it consistently thereafter.
	 */
	down_write(&obj->oo_guard);
	if (obj->oo_destroy == OSD_DESTROY_NONE) {
		if (obj->oo_attr.la_size <= osd_sync_destroy_max_size)
			obj->oo_destroy = OSD_DESTROY_SYNC;
		else /* Larger objects are destroyed asynchronously */
			obj->oo_destroy = OSD_DESTROY_ASYNC;
	}
	up_write(&obj->oo_guard);
}

static int osd_declare_destroy(const struct lu_env *env, struct dt_object *dt,
			       struct thandle *th)
{
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	struct osd_thandle	*oh;
	dnode_t *dn;
	int			 rc;
	uint64_t		 zapid;
	ENTRY;

	LASSERT(th != NULL);
	LASSERT(dt_object_exists(dt));

	oh = container_of(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);

	dmu_tx_mark_netfree(oh->ot_tx);

	/* declare that we'll remove object from fid-dnode mapping */
	zapid = osd_get_name_n_idx(env, osd, fid, NULL, 0, &dn);
	osd_tx_hold_zap(oh->ot_tx, zapid, dn, FALSE, NULL);

	osd_declare_xattrs_destroy(env, obj, oh);

	/* one less inode */
	rc = osd_declare_quota(env, osd, obj->oo_attr.la_uid,
			       obj->oo_attr.la_gid, obj->oo_attr.la_projid,
			       -1, oh, NULL, OSD_QID_INODE);
	if (rc)
		RETURN(rc);

	/* data to be truncated */
	rc = osd_declare_quota(env, osd, obj->oo_attr.la_uid,
			       obj->oo_attr.la_gid, obj->oo_attr.la_projid,
			       0, oh, NULL, OSD_QID_BLK);
	if (rc)
		RETURN(rc);

	osd_object_set_destroy_type(obj);
	if (obj->oo_destroy == OSD_DESTROY_SYNC)
		dmu_tx_hold_free(oh->ot_tx, obj->oo_dn->dn_object,
				 0, DMU_OBJECT_END);
	else
		osd_tx_hold_zap(oh->ot_tx, osd->od_unlinked->dn_object,
				osd->od_unlinked, TRUE, NULL);

	/* remove agent entry (if have) from remote parent */
	if (lu_object_has_agent_entry(&obj->oo_dt.do_lu))
		osd_tx_hold_zap(oh->ot_tx, osd->od_remote_parent_dir,
				NULL, FALSE, NULL);

	/* will help to find FID->ino when this object is being
	 * added to PENDING/ */
	osd_idc_find_and_init(env, osd, obj);

	RETURN(0);
}

static int osd_destroy(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	char			*buf = info->oti_str;
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_thandle	*oh;
	int			 rc;
	uint64_t		 oid, zapid;
	dnode_t *zdn;
	ENTRY;

	down_write(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = -ENOENT);

	LASSERT(obj->oo_dn != NULL);

	oh = container_of(th, struct osd_thandle, ot_super);
	LASSERT(oh != NULL);
	LASSERT(oh->ot_tx != NULL);

	/* remove obj ref from index dir (it depends) */
	zapid = osd_get_name_n_idx(env, osd, fid, buf,
				   sizeof(info->oti_str), &zdn);
	rc = osd_xattrs_destroy(env, obj, oh);
	if (rc) {
		CERROR("%s: cannot destroy xattrs for %s: rc = %d\n",
		       osd->od_svname, buf, rc);
		GOTO(out, rc);
	}

	if (lu_object_has_agent_entry(&obj->oo_dt.do_lu)) {
		rc = osd_delete_from_remote_parent(env, osd, obj, oh, true);
		if (rc)
			GOTO(out, rc);
	}

	oid = obj->oo_dn->dn_object;
	if (unlikely(obj->oo_destroy == OSD_DESTROY_NONE)) {
		/* this may happen if the destroy wasn't declared
		 * e.g. when the object is created and then destroyed
		 * in the same transaction - we don't need additional
		 * space for destroy specifically */
		LASSERT(obj->oo_attr.la_size <= osd_sync_destroy_max_size);
		rc = -dmu_object_free(osd->od_os, oid, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to free %s/%#llx: rc = %d\n",
			       osd->od_svname, buf, oid, rc);
	} else if (obj->oo_destroy == OSD_DESTROY_SYNC) {
		rc = -dmu_object_free(osd->od_os, oid, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to free %s/%#llx: rc = %d\n",
			       osd->od_svname, buf, oid, rc);
	} else { /* asynchronous destroy */
		char *key = info->oti_key;

		rc = osd_object_unlinked_add(obj, oh);
		if (rc)
			GOTO(out, rc);

		snprintf(key, sizeof(info->oti_key), "%llx", oid);
		rc = osd_zap_add(osd, osd->od_unlinked->dn_object,
				 osd->od_unlinked, key, 8, 1, &oid, oh->ot_tx);
		if (rc)
			CERROR("%s: zap_add_int() failed %s/%#llx: rc = %d\n",
			       osd->od_svname, buf, oid, rc);
	}

	/* Remove the OI mapping after the destroy to handle the race with
	 * OI scrub that may insert missed OI mapping during the interval. */
	rc = osd_zap_remove(osd, zapid, zdn, buf, oh->ot_tx);
	if (unlikely(rc == -ENOENT))
		rc = 0;
	if (rc)
		CERROR("%s: zap_remove(%s) failed: rc = %d\n",
		       osd->od_svname, buf, rc);

	GOTO(out, rc);

out:
	/* not needed in the cache anymore */
	set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);
	if (rc == 0)
		obj->oo_destroyed = 1;
	up_write(&obj->oo_guard);
	RETURN (0);
}

static void osd_object_delete(const struct lu_env *env, struct lu_object *l)
{
	struct osd_object *obj = osd_obj(l);
	const struct lu_fid *fid = lu_object_fid(l);

	if (obj->oo_dn) {
		if (likely(!fid_is_acct(fid))) {
			osd_object_sa_fini(obj);
			if (obj->oo_sa_xattr) {
				nvlist_free(obj->oo_sa_xattr);
				obj->oo_sa_xattr = NULL;
			}
			osd_dnode_rele(obj->oo_dn);
			list_del(&obj->oo_sa_linkage);
		}
		obj->oo_dn = NULL;
	}
}

/*
 * Concurrency: ->loo_object_release() is called under site spin-lock.
 */
static void osd_object_release(const struct lu_env *env,
			       struct lu_object *l)
{
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *l)
{
	struct osd_object *o = osd_obj(l);

	return (*p)(env, cookie, LUSTRE_OSD_ZFS_NAME"-object@%p", o);
}

static void osd_read_lock(const struct lu_env *env, struct dt_object *dt,
			  unsigned role)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(osd_invariant(obj));

	down_read_nested(&obj->oo_sem, role);
}

static void osd_write_lock(const struct lu_env *env, struct dt_object *dt,
			   unsigned role)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(osd_invariant(obj));

	down_write_nested(&obj->oo_sem, role);
}

static void osd_read_unlock(const struct lu_env *env, struct dt_object *dt)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(osd_invariant(obj));
	up_read(&obj->oo_sem);
}

static void osd_write_unlock(const struct lu_env *env, struct dt_object *dt)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(osd_invariant(obj));
	up_write(&obj->oo_sem);
}

static int osd_write_locked(const struct lu_env *env, struct dt_object *dt)
{
	struct osd_object *obj = osd_dt_obj(dt);
	int rc = 1;

	LASSERT(osd_invariant(obj));

	if (down_write_trylock(&obj->oo_sem)) {
		rc = 0;
		up_write(&obj->oo_sem);
	}
	return rc;
}

static int osd_attr_get(const struct lu_env *env, struct dt_object *dt,
			struct lu_attr *attr)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	uint64_t blocks;
	uint32_t blksize;
	int rc = 0;

	down_read(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = -ENOENT);

	if (unlikely(fid_is_acct(lu_object_fid(&dt->do_lu))))
		GOTO(out, rc = 0);

	LASSERT(osd_invariant(obj));
	LASSERT(obj->oo_dn);

	read_lock(&obj->oo_attr_lock);
	*attr = obj->oo_attr;
	if (obj->oo_lma_flags & LUSTRE_ORPHAN_FL) {
		attr->la_valid |= LA_FLAGS;
		attr->la_flags |= LUSTRE_ORPHAN_FL;
	}
	if (obj->oo_lma_flags & LUSTRE_ENCRYPT_FL) {
		attr->la_valid |= LA_FLAGS;
		attr->la_flags |= LUSTRE_ENCRYPT_FL;
	}
	read_unlock(&obj->oo_attr_lock);
	if (attr->la_valid & LA_FLAGS && attr->la_flags & LUSTRE_ORPHAN_FL)
		CDEBUG(D_INFO, "%s: set orphan flag on "DFID" (%#llx/%#x)\n",
		       osd_obj2dev(obj)->od_svname,
		       PFID(lu_object_fid(&dt->do_lu)),
		       attr->la_valid, obj->oo_lma_flags);

	/* with ZFS_DEBUG zrl_add_debug() called by DB_DNODE_ENTER()
	 * from within sa_object_size() can block on a mutex, so
	 * we can't call sa_object_size() holding rwlock */
	sa_object_size(obj->oo_sa_hdl, &blksize, &blocks);
	/* we do not control size of indices, so always calculate
	 * it from number of blocks reported by DMU */
	if (S_ISDIR(attr->la_mode)) {
		attr->la_size = 512 * blocks;
		rc = -zap_count(osd->od_os, obj->oo_dn->dn_object,
				&attr->la_dirent_count);
	}
	/* Block size may be not set; suggest maximal I/O transfers. */
	if (blksize == 0)
		blksize = osd_spa_maxblocksize(
			dmu_objset_spa(osd_obj2dev(obj)->od_os));

	attr->la_blksize = blksize;
	attr->la_blocks = blocks;
	attr->la_valid |= LA_BLOCKS | LA_BLKSIZE;

out:
	up_read(&obj->oo_guard);
	return rc;
}

/* Simple wrapper on top of qsd API which implement quota transfer for osd
 * setattr needs. As a reminder, only the root user can change ownership of
 * a file, that's why EDQUOT & EINPROGRESS errors are discarded */
static inline int qsd_transfer(const struct lu_env *env,
			       struct qsd_instance *qsd,
			       struct lquota_trans *trans, int qtype,
			       __u64 orig_id, __u64 new_id, __u64 bspace,
			       struct lquota_id_info *qi, bool ignore_edquot)
{
	int	rc;

	if (unlikely(qsd == NULL))
		return 0;

	LASSERT(qtype >= 0 && qtype < LL_MAXQUOTAS);
	qi->lqi_type = qtype;

	/* inode accounting */
	qi->lqi_is_blk = false;

	/* one more inode for the new owner ... */
	qi->lqi_id.qid_uid = new_id;
	qi->lqi_space      = 1;
	rc = qsd_op_begin(env, qsd, trans, qi, NULL);
	if (ignore_edquot && (rc == -EDQUOT || rc == -EINPROGRESS))
		rc = 0;
	if (rc)
		return rc;

	/* and one less inode for the current id */
	qi->lqi_id.qid_uid = orig_id;;
	qi->lqi_space      = -1;
	/* can't get EDQUOT when reducing usage */
	rc = qsd_op_begin(env, qsd, trans, qi, NULL);
	if (rc == -EINPROGRESS)
		rc = 0;
	if (rc)
		return rc;

	/* block accounting */
	qi->lqi_is_blk = true;

	/* more blocks for the new owner ... */
	qi->lqi_id.qid_uid = new_id;
	qi->lqi_space      = bspace;
	rc = qsd_op_begin(env, qsd, trans, qi, NULL);
	if (ignore_edquot && (rc == -EDQUOT || rc == -EINPROGRESS))
		rc = 0;
	if (rc)
		return rc;

	/* and finally less blocks for the current owner */
	qi->lqi_id.qid_uid = orig_id;
	qi->lqi_space      = -bspace;
	rc = qsd_op_begin(env, qsd, trans, qi, NULL);
	/* can't get EDQUOT when reducing usage */
	if (rc == -EINPROGRESS)
		rc = 0;
	return rc;
}

static int osd_declare_attr_set(const struct lu_env *env,
				struct dt_object *dt,
				const struct lu_attr *attr,
				struct thandle *handle)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	dmu_tx_hold_t		*txh;
	struct osd_thandle	*oh;
	uint64_t		 bspace;
	uint32_t		 blksize;
	int			 rc = 0;
	bool			 found;
	ENTRY;


	LASSERT(handle != NULL);
	LASSERT(osd_invariant(obj));

	oh = container_of(handle, struct osd_thandle, ot_super);

	down_read(&obj->oo_guard);
	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = 0);

	LASSERT(obj->oo_sa_hdl != NULL);
	LASSERT(oh->ot_tx != NULL);
	/* regular attributes are part of the bonus buffer */
	/* let's check whether this object is already part of
	 * transaction.. */
	found = false;
	for (txh = list_head(&oh->ot_tx->tx_holds); txh;
	     txh = list_next(&oh->ot_tx->tx_holds, txh)) {
		if (txh->txh_dnode == NULL)
			continue;
		if (txh->txh_dnode->dn_object != obj->oo_dn->dn_object)
			continue;
		/* this object is part of the transaction already
		 * we don't need to declare bonus again */
		found = true;
		break;
	}
	if (!found)
		dmu_tx_hold_bonus(oh->ot_tx, obj->oo_dn->dn_object);
	if (oh->ot_tx->tx_err != 0)
		GOTO(out, rc = -oh->ot_tx->tx_err);

	if (attr && attr->la_valid & LA_FLAGS) {
		/* LMA is usually a part of bonus, no need to declare
		 * anything else */
	}

	if (attr && (attr->la_valid & (LA_UID | LA_GID | LA_PROJID))) {
		sa_object_size(obj->oo_sa_hdl, &blksize, &bspace);
		bspace = toqb(bspace * 512);

		CDEBUG(D_QUOTA,
		       "%s: enforce quota on UID %u, GID %u, the quota space is %lld (%u)\n",
		       osd->od_svname,
		       attr->la_uid, attr->la_gid, bspace, blksize);
	}

	if (attr && attr->la_valid & LA_UID) {
		/* quota enforcement for user */
		if (attr->la_uid != obj->oo_attr.la_uid) {
			rc = qsd_transfer(env, osd_def_qsd(osd),
					  &oh->ot_quota_trans, USRQUOTA,
					  obj->oo_attr.la_uid, attr->la_uid,
					  bspace, &info->oti_qi, true);
			if (rc)
				GOTO(out, rc);
		}
	}
	if (attr && attr->la_valid & LA_GID) {
		/* quota enforcement for group */
		if (attr->la_gid != obj->oo_attr.la_gid) {
			rc = qsd_transfer(env, osd_def_qsd(osd),
					  &oh->ot_quota_trans, GRPQUOTA,
					  obj->oo_attr.la_gid, attr->la_gid,
					  bspace, &info->oti_qi,
					  !(attr->la_flags &
							LUSTRE_SET_SYNC_FL));
			if (rc)
				GOTO(out, rc);
		}
	}
#ifdef ZFS_PROJINHERIT
	if (attr && attr->la_valid & LA_PROJID) {
		/* quota enforcement for project */
		if (attr->la_projid != obj->oo_attr.la_projid) {
			if (!osd->od_projectused_dn)
				GOTO(out, rc = -EOPNOTSUPP);

			/* Usually, if project quota is upgradable for the
			 * device, then the upgrade will be done before or when
			 * mount the device. So when we come here, this project
			 * should have project ID attribute already (that is
			 * zero by default).  Otherwise, there was something
			 * wrong during the former upgrade, let's return failure
			 * to report that.
			 *
			 * Please note that, different from other attributes,
			 * you can NOT simply set the project ID attribute under
			 * such case, because adding (NOT change) project ID
			 * attribute needs to change the object's attribute
			 * layout to match zfs backend quota accounting
			 * requirement. */
			if (unlikely(!obj->oo_with_projid))
				GOTO(out, rc = -ENXIO);

			rc = qsd_transfer(env, osd_def_qsd(osd),
					  &oh->ot_quota_trans, PRJQUOTA,
					  obj->oo_attr.la_projid,
					  attr->la_projid, bspace,
					  &info->oti_qi, true);
			if (rc)
				GOTO(out, rc);
		}
	}
#endif
out:
	up_read(&obj->oo_guard);
	RETURN(rc);
}

/*
 * Set the attributes of an object
 *
 * The transaction passed to this routine must have
 * dmu_tx_hold_bonus(tx, oid) called and then assigned
 * to a transaction group.
 */
static int osd_attr_set(const struct lu_env *env, struct dt_object *dt,
			const struct lu_attr *la, struct thandle *handle)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	sa_bulk_attr_t		*bulk = osd_oti_get(env)->oti_attr_bulk;
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	struct osd_thandle	*oh;
	struct osa_attr		*osa = &info->oti_osa;
	__u64			 valid = la->la_valid;
	int			 cnt;
	int			 rc = 0;

	ENTRY;

	down_read(&obj->oo_guard);
	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = -ENOENT);

	LASSERT(handle != NULL);
	LASSERT(osd_invariant(obj));
	LASSERT(obj->oo_sa_hdl);

	oh = container_of(handle, struct osd_thandle, ot_super);
	/* Assert that the transaction has been assigned to a
	   transaction group. */
	LASSERT(oh->ot_tx->tx_txg != 0);

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_FID_MAPPING) && !osd->od_is_ost) {
		struct zpl_direntry *zde = &info->oti_zde.lzd_reg;
		char *buf = info->oti_str;
		dnode_t *zdn = NULL;
		uint64_t zapid;

		zapid = osd_get_name_n_idx(env, osd, lu_object_fid(&dt->do_lu),
					   buf, sizeof(info->oti_str), &zdn);
		rc = osd_zap_lookup(osd, zapid, zdn, buf, 8,
				    sizeof(*zde) / 8, zde);
		if (!rc) {
			zde->zde_dnode -= 1;
			rc = -zap_update(osd->od_os, zapid, buf, 8,
					 sizeof(*zde) / 8, zde, oh->ot_tx);
		}
		if (rc > 0)
			rc = 0;
		GOTO(out, rc);
	}

	/* Only allow set size for regular file */
	if (!S_ISREG(dt->do_lu.lo_header->loh_attr))
		valid &= ~(LA_SIZE | LA_BLOCKS);

	if (valid & LA_CTIME && la->la_ctime == obj->oo_attr.la_ctime)
		valid &= ~LA_CTIME;

	if (valid & LA_MTIME && la->la_mtime == obj->oo_attr.la_mtime)
		valid &= ~LA_MTIME;

	if (valid & LA_ATIME && la->la_atime == obj->oo_attr.la_atime)
		valid &= ~LA_ATIME;

	if (valid == 0)
		GOTO(out, rc = 0);

	if (valid & LA_FLAGS) {
		struct lustre_mdt_attrs *lma;
		struct lu_buf buf;
		int size = 0;

		if (la->la_flags & LUSTRE_LMA_FL_MASKS) {
			LASSERT(!obj->oo_pfid_in_lma);
			BUILD_BUG_ON(sizeof(info->oti_buf) < sizeof(*lma));
			lma = (struct lustre_mdt_attrs *)&info->oti_buf;
			buf.lb_buf = lma;
			buf.lb_len = sizeof(info->oti_buf);

			/* Please do NOT call osd_xattr_get() directly, that
			 * will cause recursive down_read() on oo_guard. */
			rc = osd_xattr_get_internal(env, obj, &buf,
						    XATTR_NAME_LMA, &size);
			if (!rc && unlikely(size < sizeof(*lma))) {
				rc = -EINVAL;
			} else if (!rc) {
				lma->lma_incompat =
					le32_to_cpu(lma->lma_incompat);
				lma->lma_incompat |=
					lustre_to_lma_flags(la->la_flags);
				lma->lma_incompat =
					cpu_to_le32(lma->lma_incompat);
				buf.lb_buf = lma;
				buf.lb_len = sizeof(*lma);
				rc = osd_xattr_set_internal(env, obj, &buf,
							    XATTR_NAME_LMA,
							    LU_XATTR_REPLACE,
							    oh);
			}
			if (rc < 0) {
				CWARN("%s: failed to set LMA flags: rc = %d\n",
				       osd->od_svname, rc);
				GOTO(out, rc);
			} else {
				obj->oo_lma_flags =
					la->la_flags & LUSTRE_LMA_FL_MASKS;
			}
		}
	}

	write_lock(&obj->oo_attr_lock);
	cnt = 0;

	if (valid & LA_PROJID) {
#ifdef ZFS_PROJINHERIT
		if (osd->od_projectused_dn) {
			LASSERT(obj->oo_with_projid);

			osa->projid = obj->oo_attr.la_projid = la->la_projid;
			SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_PROJID(osd), NULL,
					 &osa->projid, 8);
		} else
#endif
			valid &= ~LA_PROJID;
	}

	if (valid & LA_ATIME) {
		osa->atime[0] = obj->oo_attr.la_atime = la->la_atime;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_ATIME(osd), NULL,
				 osa->atime, 16);
	}
	if (valid & LA_MTIME) {
		osa->mtime[0] = obj->oo_attr.la_mtime = la->la_mtime;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MTIME(osd), NULL,
				 osa->mtime, 16);
	}
	if (valid & LA_CTIME) {
		osa->ctime[0] = obj->oo_attr.la_ctime = la->la_ctime;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CTIME(osd), NULL,
				 osa->ctime, 16);
	}
	if (valid & LA_MODE) {
		/* mode is stored along with type, so read it first */
		obj->oo_attr.la_mode = (obj->oo_attr.la_mode & S_IFMT) |
			(la->la_mode & ~S_IFMT);
		osa->mode = obj->oo_attr.la_mode;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MODE(osd), NULL,
				 &osa->mode, 8);
	}
	if (valid & LA_SIZE) {
		osa->size = obj->oo_attr.la_size = la->la_size;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_SIZE(osd), NULL,
				 &osa->size, 8);
	}
	if (valid & LA_NLINK) {
		osa->nlink = obj->oo_attr.la_nlink = la->la_nlink;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_LINKS(osd), NULL,
				 &osa->nlink, 8);
	}
	if (valid & LA_RDEV) {
		osa->rdev = obj->oo_attr.la_rdev = la->la_rdev;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_RDEV(osd), NULL,
				 &osa->rdev, 8);
	}
	if (valid & LA_FLAGS) {
		osa->flags = attrs_fs2zfs(la->la_flags);
		/* many flags are not supported by zfs, so ensure a good cached
		 * copy */
		obj->oo_attr.la_flags = attrs_zfs2fs(osa->flags);
#ifdef ZFS_PROJINHERIT
		if (obj->oo_with_projid && osd->od_projectused_dn)
			osa->flags |= ZFS_PROJID;
#endif
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_FLAGS(osd), NULL,
				 &osa->flags, 8);
	}
	if (valid & LA_UID) {
		osa->uid = obj->oo_attr.la_uid = la->la_uid;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_UID(osd), NULL,
				 &osa->uid, 8);
	}
	if (valid & LA_GID) {
		osa->gid = obj->oo_attr.la_gid = la->la_gid;
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_GID(osd), NULL,
				 &osa->gid, 8);
	}
	obj->oo_attr.la_valid |= valid;
	write_unlock(&obj->oo_attr_lock);

	LASSERT(cnt <= ARRAY_SIZE(osd_oti_get(env)->oti_attr_bulk));
	rc = osd_object_sa_bulk_update(obj, bulk, cnt, oh);

out:
	up_read(&obj->oo_guard);
	RETURN(rc);
}

/*
 * Object creation.
 *
 * XXX temporary solution.
 */

static void osd_ah_init(const struct lu_env *env, struct dt_allocation_hint *ah,
			struct dt_object *parent, struct dt_object *child,
			umode_t child_mode)
{
	LASSERT(ah);

	ah->dah_parent = parent;
	ah->dah_mode = child_mode;

	if (parent != NULL && !dt_object_remote(parent)) {
		/* will help to find FID->ino at dt_insert("..") */
		struct osd_object *pobj = osd_dt_obj(parent);

		osd_idc_find_and_init(env, osd_obj2dev(pobj), pobj);
	}
}

static int osd_declare_create(const struct lu_env *env, struct dt_object *dt,
			      struct lu_attr *attr,
			      struct dt_allocation_hint *hint,
			      struct dt_object_format *dof,
			      struct thandle *handle)
{
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	struct osd_thandle	*oh;
	uint64_t		 zapid;
	dnode_t			*dn;
	int			 rc, dnode_size;
	ENTRY;

	LASSERT(dof);

	switch (dof->dof_type) {
		case DFT_REGULAR:
		case DFT_SYM:
		case DFT_NODE:
			if (obj->oo_dt.do_body_ops == NULL)
				obj->oo_dt.do_body_ops = &osd_body_ops;
			break;
		default:
			break;
	}

	LASSERT(handle != NULL);
	oh = container_of(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);

	/* this is the minimum set of EAs on every Lustre object */
	obj->oo_ea_in_bonus = OSD_BASE_EA_IN_BONUS;
	/* reserve 32 bytes for extra stuff like ACLs */
	dnode_size = size_roundup_power2(obj->oo_ea_in_bonus + 32);

	switch (dof->dof_type) {
		case DFT_DIR:
			dt->do_index_ops = &osd_dir_ops;
			/* fallthrough */
		case DFT_INDEX:
			/* for zap create */
			dmu_tx_hold_zap(oh->ot_tx, DMU_NEW_OBJECT, FALSE, NULL);
			dmu_tx_hold_sa_create(oh->ot_tx, dnode_size);
			break;
		case DFT_REGULAR:
		case DFT_SYM:
		case DFT_NODE:
			/* first, we'll create new object */
			dmu_tx_hold_sa_create(oh->ot_tx, dnode_size);
			break;

		default:
			LBUG();
			break;
	}

	/* and we'll add it to some mapping */
	zapid = osd_get_name_n_idx(env, osd, fid, NULL, 0, &dn);
	osd_tx_hold_zap(oh->ot_tx, zapid, dn, TRUE, NULL);

	/* will help to find FID->ino mapping at dt_insert() */
	osd_idc_find_and_init(env, osd, obj);

	rc = osd_declare_quota(env, osd, attr->la_uid, attr->la_gid,
			       attr->la_projid, 1, oh, NULL, OSD_QID_INODE);

	RETURN(rc);
}

int __osd_attr_init(const struct lu_env *env, struct osd_device *osd,
		    struct osd_object *obj, sa_handle_t *sa_hdl, dmu_tx_t *tx,
		    struct lu_attr *la, uint64_t parent,
		    nvlist_t *xattr)
{
	sa_bulk_attr_t *bulk = osd_oti_get(env)->oti_attr_bulk;
	struct osa_attr *osa = &osd_oti_get(env)->oti_osa;
	uint64_t gen;
	inode_timespec_t now;
	int cnt;
	int rc;
	char *dxattr = NULL;
	size_t sa_size;


	LASSERT(sa_hdl);

	gen = dmu_tx_get_txg(tx);
	gethrestime(&now);
	ZFS_TIME_ENCODE(&now, osa->btime);

	osa->atime[0] = la->la_atime;
	osa->ctime[0] = la->la_ctime;
	osa->mtime[0] = la->la_mtime;
	osa->mode = la->la_mode;
	osa->uid = la->la_uid;
	osa->gid = la->la_gid;
	osa->rdev = la->la_rdev;
	osa->nlink = la->la_nlink;
	if (la->la_valid & LA_FLAGS)
		osa->flags = attrs_fs2zfs(la->la_flags);
	else
		osa->flags = 0;
	osa->size  = la->la_size;
#ifdef ZFS_PROJINHERIT
	if (osd->od_projectused_dn) {
		if (la->la_valid & LA_PROJID)
			osa->projid = la->la_projid;
		else
			osa->projid = ZFS_DEFAULT_PROJID;
		osa->flags |= ZFS_PROJID;
		if (obj)
			obj->oo_with_projid = 1;
	} else {
		osa->flags &= ~ZFS_PROJID;
	}
#endif

	/*
	 * we need to create all SA below upon object create.
	 *
	 * XXX The attribute order matters since the accounting callback relies
	 * on static offsets (i.e. SA_*_OFFSET, see zfs_space_delta_cb()) to
	 * look up the UID/GID/PROJID attributes. Moreover, the callback does
	 * not seem to support the spill block.
	 * We define attributes in the same order as SA_*_OFFSET in order to
	 * work around the problem. See ORI-610.
	 */
	cnt = 0;
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MODE(osd), NULL, &osa->mode, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_SIZE(osd), NULL, &osa->size, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_GEN(osd), NULL, &gen, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_UID(osd), NULL, &osa->uid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_GID(osd), NULL, &osa->gid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_PARENT(osd), NULL, &parent, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_FLAGS(osd), NULL, &osa->flags, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_ATIME(osd), NULL, osa->atime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MTIME(osd), NULL, osa->mtime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CTIME(osd), NULL, osa->ctime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CRTIME(osd), NULL, osa->btime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_LINKS(osd), NULL, &osa->nlink, 8);
#ifdef ZFS_PROJINHERIT
	if (osd->od_projectused_dn)
		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_PROJID(osd), NULL,
				 &osa->projid, 8);
#endif
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_RDEV(osd), NULL, &osa->rdev, 8);
	LASSERT(cnt <= ARRAY_SIZE(osd_oti_get(env)->oti_attr_bulk));

	if (xattr) {
		rc = -nvlist_size(xattr, &sa_size, NV_ENCODE_XDR);
		LASSERT(rc == 0);

		dxattr = osd_zio_buf_alloc(sa_size);
		LASSERT(dxattr);

		rc = -nvlist_pack(xattr, &dxattr, &sa_size,
				NV_ENCODE_XDR, KM_SLEEP);
		LASSERT(rc == 0);

		SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_DXATTR(osd),
				NULL, dxattr, sa_size);
	}

	rc = -sa_replace_all_by_template(sa_hdl, bulk, cnt, tx);
	if (dxattr)
		osd_zio_buf_free(dxattr, sa_size);

	return rc;
}

int osd_find_new_dnode(const struct lu_env *env, dmu_tx_t *tx,
		       uint64_t oid, dnode_t **dnp)
{
	dmu_tx_hold_t *txh;
	int rc = 0;

	/* take dnode_t from tx to save on dnode#->dnode_t lookup */
	for (txh = list_tail(&tx->tx_holds); txh;
	     txh = list_prev(&tx->tx_holds, txh)) {
		dnode_t *dn = txh->txh_dnode;
		dmu_buf_impl_t *db;

		if (dn == NULL)
			continue;
		if (dn->dn_object != oid)
			continue;
		db = dn->dn_bonus;
		if (db == NULL) {
			rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
			if (dn->dn_bonus == NULL)
				dbuf_create_bonus(dn);
			rw_exit(&dn->dn_struct_rwlock);
		}
		db = dn->dn_bonus;
		LASSERT(db);
		LASSERT(dn->dn_handle);
		DB_DNODE_ENTER(db);
		if (zfs_refcount_add(&db->db_holds, osd_obj_tag) == 1) {
			zfs_refcount_add(&dn->dn_holds, osd_obj_tag);
			atomic_inc_32(&dn->dn_dbufs_count);
		}
		*dnp = dn;
		DB_DNODE_EXIT(db);
		dbuf_read(db, NULL, DB_RF_MUST_SUCCEED | DB_RF_NOPREFETCH);
		break;
	}

	if (unlikely(*dnp == NULL))
		rc = __osd_obj2dnode(tx->tx_objset, oid, dnp);

	return rc;
}

#ifdef HAVE_DMU_OBJECT_ALLOC_DNSIZE
int osd_find_dnsize(struct osd_device *osd, int ea_in_bonus)
{
	int dnsize;

	if (osd->od_dnsize == ZFS_DNSIZE_AUTO) {
		dnsize = DNODE_MIN_SIZE;
		do {
			if (DN_BONUS_SIZE(dnsize) >= ea_in_bonus + 32)
				break;
			dnsize <<= 1;
		} while (dnsize < DNODE_MAX_SIZE);
		if (dnsize > DNODE_MAX_SIZE)
			dnsize = DNODE_MAX_SIZE;
	} else if (osd->od_dnsize == ZFS_DNSIZE_1K) {
		dnsize = 1024;
	} else if (osd->od_dnsize == ZFS_DNSIZE_2K) {
		dnsize = 2048;
	} else if (osd->od_dnsize == ZFS_DNSIZE_4K) {
		dnsize = 4096;
	} else if (osd->od_dnsize == ZFS_DNSIZE_8K) {
		dnsize = 8192;
	} else if (osd->od_dnsize == ZFS_DNSIZE_16K) {
		dnsize = 16384;
	} else {
		dnsize = DNODE_MIN_SIZE;
	}
	return dnsize;
}
#endif

/*
 * The transaction passed to this routine must have
 * dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT) called and then assigned
 * to a transaction group.
 */
int __osd_object_create(const struct lu_env *env, struct osd_device *osd,
			struct osd_object *obj, const struct lu_fid *fid,
			dnode_t **dnp, dmu_tx_t *tx, struct lu_attr *la)
{
	dmu_object_type_t type = DMU_OT_PLAIN_FILE_CONTENTS;
	uint64_t oid;
	int size;

	/* Use DMU_OTN_UINT8_METADATA for local objects so their data blocks
	 * would get an additional ditto copy */
	if (unlikely(S_ISREG(la->la_mode) &&
		     fid_seq_is_local_file(fid_seq(fid))))
		type = DMU_OTN_UINT8_METADATA;

	/* Create a new DMU object using the default dnode size. */
	if (obj)
		size = obj->oo_ea_in_bonus;
	else
		size = OSD_BASE_EA_IN_BONUS;
	oid = osd_dmu_object_alloc(osd->od_os, type, 0,
				   osd_find_dnsize(osd, size), tx);

	LASSERT(la->la_valid & LA_MODE);
	la->la_size = 0;
	la->la_nlink = 1;

	return osd_find_new_dnode(env, tx, oid, dnp);
}

/*
 * The transaction passed to this routine must have
 * dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, ...) called and then assigned
 * to a transaction group.
 *
 * Using ZAP_FLAG_HASH64 will force the ZAP to always be a FAT ZAP.
 * This is fine for directories today, because storing the FID in the dirent
 * will also require a FAT ZAP.  If there is a new type of micro ZAP created
 * then we might need to re-evaluate the use of this flag and instead do
 * a conversion from the different internal ZAP hash formats being used. */
int __osd_zap_create(const struct lu_env *env, struct osd_device *osd,
		     dnode_t **dnp, dmu_tx_t *tx, struct lu_attr *la,
		     unsigned dnsize, zap_flags_t flags)
{
	uint64_t oid;

	/* Assert that the transaction has been assigned to a
	   transaction group. */
	LASSERT(tx->tx_txg != 0);
	*dnp = NULL;

	oid = osd_zap_create_flags(osd->od_os, 0, flags | ZAP_FLAG_HASH64,
				   DMU_OT_DIRECTORY_CONTENTS,
				   14, /* == ZFS fzap_default_blockshift */
				   DN_MAX_INDBLKSHIFT, /* indirect blockshift */
				   dnsize, tx);

	la->la_size = 2;
	la->la_nlink = 1;

	return osd_find_new_dnode(env, tx, oid, dnp);
}

static dnode_t *osd_mkidx(const struct lu_env *env, struct osd_object *obj,
			  struct lu_attr *la, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dnode_t *dn;
	int rc;

	/* Index file should be created as regular file in order not to confuse
	 * ZPL which could interpret them as directory.
	 * We set ZAP_FLAG_UINT64_KEY to let ZFS know than we are going to use
	 * binary keys */
	LASSERT(S_ISREG(la->la_mode));
	rc = __osd_zap_create(env, osd, &dn, oh->ot_tx, la,
		osd_find_dnsize(osd, obj->oo_ea_in_bonus), ZAP_FLAG_UINT64_KEY);
	if (rc)
		return ERR_PTR(rc);
	return dn;
}

static dnode_t *osd_mkdir(const struct lu_env *env, struct osd_object *obj,
			  struct lu_attr *la, struct osd_thandle *oh)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dnode_t *dn;
	int rc;

	LASSERT(S_ISDIR(la->la_mode));
	rc = __osd_zap_create(env, osd, &dn, oh->ot_tx, la,
			      osd_find_dnsize(osd, obj->oo_ea_in_bonus), 0);
	if (rc)
		return ERR_PTR(rc);
	return dn;
}

static dnode_t *osd_mkreg(const struct lu_env *env, struct osd_object *obj,
			  struct lu_attr *la, struct osd_thandle *oh)
{
	const struct lu_fid *fid = lu_object_fid(&obj->oo_dt.do_lu);
	struct osd_device *osd = osd_obj2dev(obj);
	dnode_t *dn;
	int rc;

	LASSERT(S_ISREG(la->la_mode));
	rc = __osd_object_create(env, osd, obj, fid, &dn, oh->ot_tx, la);
	if (rc)
		return ERR_PTR(rc);

	if ((fid_is_idif(fid) || fid_is_norm(fid) || fid_is_echo(fid))) {
		/* The minimum block size must be at least page size otherwise
		 * it will break the assumption in tgt_thread_big_cache where
		 * the array size is PTLRPC_MAX_BRW_PAGES. It will also affect
		 * RDMA due to subpage transfer size */
		rc = -dmu_object_set_blocksize(osd->od_os, dn->dn_object,
					       PAGE_SIZE, 0, oh->ot_tx);
		if (unlikely(rc)) {
			CERROR("%s: can't change blocksize: %d\n",
			       osd->od_svname, rc);
			return ERR_PTR(rc);
		}
	} else if ((fid_is_llog(fid))) {
		rc = -dmu_object_set_blocksize(osd->od_os, dn->dn_object,
					       LLOG_MIN_CHUNK_SIZE, 0, oh->ot_tx);
		if (unlikely(rc)) {
			CERROR("%s: can't change blocksize: %d\n",
			       osd->od_svname, rc);
			return ERR_PTR(rc);
		}
	}

	return dn;
}

static dnode_t *osd_mksym(const struct lu_env *env, struct osd_object *obj,
			  struct lu_attr *la, struct osd_thandle *oh)
{
	dnode_t *dn;
	int rc;

	LASSERT(S_ISLNK(la->la_mode));
	rc = __osd_object_create(env, osd_obj2dev(obj), obj,
				 lu_object_fid(&obj->oo_dt.do_lu),
				 &dn, oh->ot_tx, la);
	if (rc)
		return ERR_PTR(rc);
	return dn;
}

static dnode_t *osd_mknod(const struct lu_env *env, struct osd_object *obj,
			  struct lu_attr *la, struct osd_thandle *oh)
{
	dnode_t *dn;
	int rc;

	if (S_ISCHR(la->la_mode) || S_ISBLK(la->la_mode))
		la->la_valid |= LA_RDEV;

	rc = __osd_object_create(env, osd_obj2dev(obj), obj,
				 lu_object_fid(&obj->oo_dt.do_lu),
				 &dn, oh->ot_tx, la);
	if (rc)
		return ERR_PTR(rc);
	return dn;
}

typedef dnode_t *(*osd_obj_type_f)(const struct lu_env *env,
				   struct osd_object *obj,
				   struct lu_attr *la,
				   struct osd_thandle *oh);

static osd_obj_type_f osd_create_type_f(enum dt_format_type type)
{
	osd_obj_type_f result;

	switch (type) {
	case DFT_DIR:
		result = osd_mkdir;
		break;
	case DFT_INDEX:
		result = osd_mkidx;
		break;
	case DFT_REGULAR:
		result = osd_mkreg;
		break;
	case DFT_SYM:
		result = osd_mksym;
		break;
	case DFT_NODE:
		result = osd_mknod;
		break;
	default:
		LBUG();
		break;
	}
	return result;
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_create(const struct lu_env *env, struct dt_object *dt,
		      struct lu_attr *attr, struct dt_allocation_hint *hint,
		      struct dt_object_format *dof, struct thandle *th)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct lustre_mdt_attrs	*lma = &info->oti_mdt_attrs;
	struct zpl_direntry	*zde = &info->oti_zde.lzd_reg;
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	char			*buf = info->oti_str;
	struct osd_thandle	*oh;
	dnode_t *dn = NULL, *zdn = NULL;
	uint64_t		 zapid, parent = 0;
	int			 rc;
	__u32 compat = 0;

	ENTRY;

	LASSERT(!fid_is_acct(fid));

	/* concurrent create declarations should not see
	 * the object inconsistent (db, attr, etc).
	 * in regular cases acquisition should be cheap */
	down_write(&obj->oo_guard);

	if (unlikely(dt_object_exists(dt)))
		GOTO(out, rc = -EEXIST);

	LASSERT(osd_invariant(obj));
	LASSERT(dof != NULL);

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	LASSERT(obj->oo_dn == NULL);

	/* to follow ZFS on-disk format we need
	 * to initialize parent dnode properly */
	if (hint != NULL && hint->dah_parent != NULL &&
	    !dt_object_remote(hint->dah_parent))
		parent = osd_dt_obj(hint->dah_parent)->oo_dn->dn_object;

	/* we may fix some attributes, better do not change the source */
	obj->oo_attr = *attr;
	obj->oo_attr.la_size = 0;
	obj->oo_attr.la_nlink = 0;
	obj->oo_attr.la_valid |= LA_SIZE | LA_NLINK | LA_TYPE;

#ifdef ZFS_PROJINHERIT
	if (osd->od_projectused_dn) {
		if (!(obj->oo_attr.la_valid & LA_PROJID))
			obj->oo_attr.la_projid = ZFS_DEFAULT_PROJID;
		obj->oo_with_projid = 1;
	}
#endif

	dn = osd_create_type_f(dof->dof_type)(env, obj, &obj->oo_attr, oh);
	if (IS_ERR(dn)) {
		rc = PTR_ERR(dn);
		dn = NULL;
		GOTO(out, rc);
	}

	zde->zde_pad = 0;
	zde->zde_dnode = dn->dn_object;
	zde->zde_type = S_DT(attr->la_mode & S_IFMT);

	zapid = osd_get_name_n_idx(env, osd, fid, buf,
				   sizeof(info->oti_str), &zdn);
	if (CFS_FAIL_CHECK(OBD_FAIL_OSD_NO_OI_ENTRY) ||
	    (osd->od_is_ost && OBD_FAIL_CHECK(OBD_FAIL_OSD_COMPAT_NO_ENTRY)))
		goto skip_add;

	if (osd->od_is_ost && OBD_FAIL_CHECK(OBD_FAIL_OSD_COMPAT_INVALID_ENTRY))
		zde->zde_dnode++;

	rc = osd_zap_add(osd, zapid, zdn, buf, 8, 1, zde, oh->ot_tx);
	if (rc)
		GOTO(out, rc);

skip_add:
	obj->oo_dn = dn;
	/* Now add in all of the "SA" attributes */
	rc = osd_sa_handle_get(obj);
	if (rc)
		GOTO(out, rc);

	rc = -nvlist_alloc(&obj->oo_sa_xattr, NV_UNIQUE_NAME, KM_SLEEP);
	if (rc)
		GOTO(out, rc);

	/* initialize LMA */
	if (fid_is_idif(fid) || (fid_is_norm(fid) && osd->od_is_ost))
		compat |= LMAC_FID_ON_OST;
	lustre_lma_init(lma, fid, compat, 0);
	lustre_lma_swab(lma);
	rc = -nvlist_add_byte_array(obj->oo_sa_xattr, XATTR_NAME_LMA,
				    (uchar_t *)lma, sizeof(*lma));
	if (rc)
		GOTO(out, rc);

	/* configure new osd object */
	obj->oo_parent = parent != 0 ? parent : zapid;
	obj->oo_late_attr_set = 1;
	rc = __osd_sa_xattr_schedule_update(env, obj, oh);
	if (rc)
		GOTO(out, rc);

	/* XXX: oo_lma_flags */
	obj->oo_dt.do_lu.lo_header->loh_attr |= obj->oo_attr.la_mode & S_IFMT;
	if (likely(!fid_is_acct(lu_object_fid(&obj->oo_dt.do_lu))))
		/* no body operations for accounting objects */
		obj->oo_dt.do_body_ops = &osd_body_ops;

	osd_idc_find_and_init(env, osd, obj);

out:
	if (unlikely(rc && dn)) {
		dmu_object_free(osd->od_os, dn->dn_object, oh->ot_tx);
		osd_dnode_rele(dn);
		obj->oo_dn = NULL;
	} else if (!rc) {
		obj->oo_dt.do_lu.lo_header->loh_attr |= LOHA_EXISTS;
	}
	up_write(&obj->oo_guard);
	RETURN(rc);
}

static int osd_declare_ref_add(const struct lu_env *env, struct dt_object *dt,
			       struct thandle *th)
{
	osd_idc_find_and_init(env, osd_dev(dt->do_lu.lo_dev), osd_dt_obj(dt));
	return osd_declare_attr_set(env, dt, NULL, th);
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_ref_add(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *handle)
{
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_thandle	*oh;
	struct osd_device	*osd = osd_obj2dev(obj);
	uint64_t		 nlink;
	int rc;

	ENTRY;

	down_read(&obj->oo_guard);
	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = -ENOENT);

	LASSERT(osd_invariant(obj));
	LASSERT(obj->oo_sa_hdl != NULL);

	oh = container_of(handle, struct osd_thandle, ot_super);

	write_lock(&obj->oo_attr_lock);
	nlink = ++obj->oo_attr.la_nlink;
	write_unlock(&obj->oo_attr_lock);

	rc = osd_object_sa_update(obj, SA_ZPL_LINKS(osd), &nlink, 8, oh);

out:
	up_read(&obj->oo_guard);
	RETURN(rc);
}

static int osd_declare_ref_del(const struct lu_env *env, struct dt_object *dt,
			       struct thandle *handle)
{
	osd_idc_find_and_init(env, osd_dev(dt->do_lu.lo_dev), osd_dt_obj(dt));
	return osd_declare_attr_set(env, dt, NULL, handle);
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_ref_del(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *handle)
{
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_thandle	*oh;
	struct osd_device	*osd = osd_obj2dev(obj);
	uint64_t		 nlink;
	int			 rc;

	ENTRY;

	down_read(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = -ENOENT);

	LASSERT(osd_invariant(obj));
	LASSERT(obj->oo_sa_hdl != NULL);

	oh = container_of(handle, struct osd_thandle, ot_super);
	LASSERT(!lu_object_is_dying(dt->do_lu.lo_header));

	write_lock(&obj->oo_attr_lock);
	nlink = --obj->oo_attr.la_nlink;
	write_unlock(&obj->oo_attr_lock);

	rc = osd_object_sa_update(obj, SA_ZPL_LINKS(osd), &nlink, 8, oh);

out:
	up_read(&obj->oo_guard);
	RETURN(rc);
}

static int osd_object_sync(const struct lu_env *env, struct dt_object *dt,
			   __u64 start, __u64 end)
{
	struct osd_device *osd = osd_obj2dev(osd_dt_obj(dt));
	uint64_t txg = 0;
	ENTRY;

	if (osd->od_dt_dev.dd_rdonly)
		RETURN(0);

	txg = osd_db_dirty_txg(osd_dt_obj(dt)->oo_dn->dn_dbuf);
	if (txg) {
		/* the object is dirty or being synced */
		if (osd_object_sync_delay_us < 0)
			txg_wait_synced(dmu_objset_pool(osd->od_os), txg);
		else
			udelay(osd_object_sync_delay_us);
	}

	RETURN(0);
}

static int osd_invalidate(const struct lu_env *env, struct dt_object *dt)
{
	return 0;
}

static bool osd_check_stale(struct dt_object *dt)
{
	return false;
}

static const struct dt_object_operations osd_obj_ops = {
	.do_read_lock		= osd_read_lock,
	.do_write_lock		= osd_write_lock,
	.do_read_unlock		= osd_read_unlock,
	.do_write_unlock	= osd_write_unlock,
	.do_write_locked	= osd_write_locked,
	.do_attr_get		= osd_attr_get,
	.do_declare_attr_set	= osd_declare_attr_set,
	.do_attr_set		= osd_attr_set,
	.do_ah_init		= osd_ah_init,
	.do_declare_create	= osd_declare_create,
	.do_create		= osd_create,
	.do_declare_destroy	= osd_declare_destroy,
	.do_destroy		= osd_destroy,
	.do_index_try		= osd_index_try,
	.do_declare_ref_add	= osd_declare_ref_add,
	.do_ref_add		= osd_ref_add,
	.do_declare_ref_del	= osd_declare_ref_del,
	.do_ref_del		= osd_ref_del,
	.do_xattr_get		= osd_xattr_get,
	.do_declare_xattr_set	= osd_declare_xattr_set,
	.do_xattr_set		= osd_xattr_set,
	.do_declare_xattr_del	= osd_declare_xattr_del,
	.do_xattr_del		= osd_xattr_del,
	.do_xattr_list		= osd_xattr_list,
	.do_object_sync		= osd_object_sync,
	.do_invalidate		= osd_invalidate,
	.do_check_stale		= osd_check_stale,
};

static const struct lu_object_operations osd_lu_obj_ops = {
	.loo_object_init	= osd_object_init,
	.loo_object_delete	= osd_object_delete,
	.loo_object_release	= osd_object_release,
	.loo_object_free	= osd_object_free,
	.loo_object_print	= osd_object_print,
	.loo_object_invariant	= osd_object_invariant,
};

static int osd_otable_it_attr_get(const struct lu_env *env,
				struct dt_object *dt,
				struct lu_attr *attr)
{
	attr->la_valid = 0;
	return 0;
}

static const struct dt_object_operations osd_obj_otable_it_ops = {
	.do_attr_get		= osd_otable_it_attr_get,
	.do_index_try		= osd_index_try,
};

module_param(osd_object_sync_delay_us, int, 0644);
MODULE_PARM_DESC(osd_object_sync_delay_us,
		 "If zero or larger delay N usec instead of doing object sync");
