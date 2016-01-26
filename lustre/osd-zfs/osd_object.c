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
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/osd_object.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 * Author: Johann Lombardi <johann@whamcloud.com>
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

char *osd_obj_tag = "osd_object";

static struct dt_object_operations osd_obj_ops;
static struct lu_object_operations osd_lu_obj_ops;
extern struct dt_body_operations osd_body_ops;
static struct dt_object_operations osd_obj_otable_it_ops;

extern struct kmem_cache *osd_object_kmem;

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
	LASSERT(obj->oo_db != NULL);

	rc = -sa_handle_get(o->od_os, obj->oo_db->db_object, obj,
			    SA_HDL_PRIVATE, &obj->oo_sa_hdl);
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
static void
osd_object_sa_dirty_add(struct osd_object *obj, struct osd_thandle *oh)
{
	if (!list_empty(&obj->oo_sa_linkage))
		return;

	down(&oh->ot_sa_lock);
	write_lock(&obj->oo_attr_lock);
	if (likely(list_empty(&obj->oo_sa_linkage)))
		list_add(&obj->oo_sa_linkage, &oh->ot_sa_list);
	write_unlock(&obj->oo_attr_lock);
	up(&oh->ot_sa_lock);
}

/*
 * Release spill block dbuf hold for all dirty SAs.
 */
void osd_object_sa_dirty_rele(struct osd_thandle *oh)
{
	struct osd_object *obj;

	down(&oh->ot_sa_lock);
	while (!list_empty(&oh->ot_sa_list)) {
		obj = list_entry(oh->ot_sa_list.next,
				 struct osd_object, oo_sa_linkage);
		sa_spill_rele(obj->oo_sa_hdl);
		write_lock(&obj->oo_attr_lock);
		list_del_init(&obj->oo_sa_linkage);
		write_unlock(&obj->oo_attr_lock);
	}
	up(&oh->ot_sa_lock);
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
int __osd_object_attr_get(const struct lu_env *env, struct osd_device *o,
			  struct osd_object *obj, struct lu_attr *la)
{
	struct osa_attr	*osa = &osd_oti_get(env)->oti_osa;
	sa_handle_t	*sa_hdl;
	sa_bulk_attr_t	*bulk;
	int		 cnt = 0;
	int		 rc;
	ENTRY;

	LASSERT(obj->oo_db != NULL);

	rc = -sa_handle_get(o->od_os, obj->oo_db->db_object, NULL,
			    SA_HDL_PRIVATE, &sa_hdl);
	if (rc)
		RETURN(rc);

	OBD_ALLOC(bulk, sizeof(sa_bulk_attr_t) * 9);
	if (bulk == NULL)
		GOTO(out_sa, rc = -ENOMEM);

	la->la_valid |= LA_ATIME | LA_MTIME | LA_CTIME | LA_MODE | LA_TYPE |
			LA_SIZE | LA_UID | LA_GID | LA_FLAGS | LA_NLINK;

	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_ATIME(o), NULL, osa->atime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MTIME(o), NULL, osa->mtime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CTIME(o), NULL, osa->ctime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_MODE(o), NULL, &osa->mode, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_SIZE(o), NULL, &osa->size, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_LINKS(o), NULL, &osa->nlink, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_UID(o), NULL, &osa->uid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_GID(o), NULL, &osa->gid, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_FLAGS(o), NULL, &osa->flags, 8);

	rc = -sa_bulk_lookup(sa_hdl, bulk, cnt);
	if (rc)
		GOTO(out_bulk, rc);

	la->la_atime = osa->atime[0];
	la->la_mtime = osa->mtime[0];
	la->la_ctime = osa->ctime[0];
	la->la_mode = osa->mode;
	la->la_uid = osa->uid;
	la->la_gid = osa->gid;
	la->la_nlink = osa->nlink;
	la->la_flags = attrs_zfs2fs(osa->flags);
	la->la_size = osa->size;

	/* Try to get extra flag from LMA. Right now, only LMAI_ORPHAN
	 * flags is stored in LMA, and it is only for orphan directory */
	if (S_ISDIR(la->la_mode) && dt_object_exists(&obj->oo_dt)) {
		struct osd_thread_info *info = osd_oti_get(env);
		struct lustre_mdt_attrs *lma;
		struct lu_buf buf;

		lma = (struct lustre_mdt_attrs *)info->oti_buf;
		buf.lb_buf = lma;
		buf.lb_len = sizeof(info->oti_buf);
		rc = osd_xattr_get(env, &obj->oo_dt, &buf, XATTR_NAME_LMA);
		if (rc > 0) {
			rc = 0;
			lma->lma_incompat = le32_to_cpu(lma->lma_incompat);
			obj->oo_lma_flags =
				lma_to_lustre_flags(lma->lma_incompat);

		} else if (rc == -ENODATA) {
			rc = 0;
		}
	}

	if (S_ISCHR(la->la_mode) || S_ISBLK(la->la_mode)) {
		rc = -sa_lookup(sa_hdl, SA_ZPL_RDEV(o), &osa->rdev, 8);
		if (rc)
			GOTO(out_bulk, rc);
		la->la_rdev = osa->rdev;
		la->la_valid |= LA_RDEV;
	}
out_bulk:
	OBD_FREE(bulk, sizeof(sa_bulk_attr_t) * 9);
out_sa:
	sa_handle_destroy(sa_hdl);

	RETURN(rc);
}

int __osd_obj2dbuf(const struct lu_env *env, objset_t *os,
		   uint64_t oid, dmu_buf_t **dbp)
{
	dmu_object_info_t *doi = &osd_oti_get(env)->oti_doi;
	int rc;

	rc = -sa_buf_hold(os, oid, osd_obj_tag, dbp);
	if (rc)
		return rc;

	dmu_object_info_from_db(*dbp, doi);
	if (unlikely (oid != DMU_USERUSED_OBJECT &&
	    oid != DMU_GROUPUSED_OBJECT && doi->doi_bonus_type != DMU_OT_SA)) {
		sa_buf_rele(*dbp, osd_obj_tag);
		*dbp = NULL;
		return -EINVAL;
	}

	LASSERT(*dbp);
	LASSERT((*dbp)->db_object == oid);
	LASSERT((*dbp)->db_offset == -1);
	LASSERT((*dbp)->db_data != NULL);

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

		l = &mo->oo_dt.do_lu;
		dt_object_init(&mo->oo_dt, NULL, d);
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

/*
 * Concurrency: shouldn't matter.
 */
int osd_object_init0(const struct lu_env *env, struct osd_object *obj)
{
	struct osd_device	*osd = osd_obj2dev(obj);
	const struct lu_fid	*fid = lu_object_fid(&obj->oo_dt.do_lu);
	int			 rc = 0;
	ENTRY;

	if (obj->oo_db == NULL)
		RETURN(0);

	/* object exist */

	rc = osd_object_sa_init(obj, osd);
	if (rc)
		RETURN(rc);

	/* cache attrs in object */
	rc = __osd_object_attr_get(env, osd, obj, &obj->oo_attr);
	if (rc)
		RETURN(rc);

	if (likely(!fid_is_acct(fid)))
		/* no body operations for accounting objects */
		obj->oo_dt.do_body_ops = &osd_body_ops;

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
	ENTRY;

	CLASSERT(sizeof(info->oti_buf) >= sizeof(*lma));
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
			      PFID(lu_object_fid(&obj->oo_dt.do_lu)));
			rc = -EOPNOTSUPP;
		}
	} else if (rc == -ENODATA) {
		/* haven't initialize LMA xattr */
		rc = 0;
	}

	RETURN(rc);
}

/*
 * Concurrency: no concurrent access is possible that early in object
 * life-cycle.
 */
static int osd_object_init(const struct lu_env *env, struct lu_object *l,
			   const struct lu_object_conf *conf)
{
	struct osd_object	*obj = osd_obj(l);
	struct osd_device	*osd = osd_obj2dev(obj);
	uint64_t		 oid;
	int			 rc;
	ENTRY;

	LASSERT(osd_invariant(obj));

	if (fid_is_otable_it(&l->lo_header->loh_fid)) {
		obj->oo_dt.do_ops = &osd_obj_otable_it_ops;
		l->lo_header->loh_attr |= LOHA_EXISTS;
		RETURN(0);
	}

	rc = osd_fid_lookup(env, osd, lu_object_fid(l), &oid);
	if (rc == 0) {
		LASSERT(obj->oo_db == NULL);
		rc = __osd_obj2dbuf(env, osd->od_os, oid, &obj->oo_db);
		/* EEXIST will be returned if object is being deleted in ZFS */
		if (rc == -EEXIST) {
			rc = 0;
			GOTO(out, rc);
		}
		if (rc != 0) {
			CERROR("%s: lookup "DFID"/"LPX64" failed: rc = %d\n",
			       osd->od_svname, PFID(lu_object_fid(l)), oid, rc);
			GOTO(out, rc);
		}
		LASSERT(obj->oo_db);
		rc = osd_object_init0(env, obj);
		if (rc != 0)
			GOTO(out, rc);

		rc = osd_check_lma(env, obj);
		if (rc != 0)
			GOTO(out, rc);
	} else if (rc == -ENOENT) {
		rc = 0;
	}
	LASSERT(osd_invariant(obj));
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

	LASSERT(osd_invariant(obj));

	dt_object_fini(&obj->oo_dt);
	OBD_SLAB_FREE_PTR(obj, osd_object_kmem);
}

static int
osd_object_unlinked_add(struct osd_object *obj, struct osd_thandle *oh)
{
	int rc = -EBUSY;

	LASSERT(obj->oo_destroy == OSD_DESTROY_ASYNC);

	/* the object is supposed to be exclusively locked by
	 * the caller (osd_object_destroy()), while the transaction
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
CFS_MODULE_PARM(osd_sync_destroy_max_size, "ul", ulong, 0444,
		"Maximum object size to use synchronous destroy.");

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

static int osd_declare_object_destroy(const struct lu_env *env,
				      struct dt_object *dt,
				      struct thandle *th)
{
	char			*buf = osd_oti_get(env)->oti_str;
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	struct osd_thandle	*oh;
	int			 rc;
	uint64_t		 zapid;
	ENTRY;

	LASSERT(th != NULL);
	LASSERT(dt_object_exists(dt));

	oh = container_of0(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);

	/* declare that we'll remove object from fid-dnode mapping */
	zapid = osd_get_name_n_idx(env, osd, fid, buf);
	dmu_tx_hold_bonus(oh->ot_tx, zapid);
	dmu_tx_hold_zap(oh->ot_tx, zapid, FALSE, buf);

	osd_declare_xattrs_destroy(env, obj, oh);

	/* declare that we'll remove object from inode accounting ZAPs */
	dmu_tx_hold_bonus(oh->ot_tx, osd->od_iusr_oid);
	dmu_tx_hold_zap(oh->ot_tx, osd->od_iusr_oid, FALSE, buf);
	dmu_tx_hold_bonus(oh->ot_tx, osd->od_igrp_oid);
	dmu_tx_hold_zap(oh->ot_tx, osd->od_igrp_oid, FALSE, buf);

	/* one less inode */
	rc = osd_declare_quota(env, osd, obj->oo_attr.la_uid,
			       obj->oo_attr.la_gid, -1, oh, false, NULL, false);
	if (rc)
		RETURN(rc);

	/* data to be truncated */
	rc = osd_declare_quota(env, osd, obj->oo_attr.la_uid,
			       obj->oo_attr.la_gid, 0, oh, true, NULL, false);
	if (rc)
		RETURN(rc);

	osd_object_set_destroy_type(obj);
	if (obj->oo_destroy == OSD_DESTROY_SYNC)
		dmu_tx_hold_free(oh->ot_tx, obj->oo_db->db_object,
				 0, DMU_OBJECT_END);
	else
		dmu_tx_hold_zap(oh->ot_tx, osd->od_unlinkedid, TRUE, NULL);

	RETURN(0);
}

static int osd_object_destroy(const struct lu_env *env,
			      struct dt_object *dt, struct thandle *th)
{
	char			*buf = osd_oti_get(env)->oti_str;
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_thandle	*oh;
	int			 rc;
	uint64_t		 oid, zapid;
	ENTRY;

	down_write(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = -ENOENT);

	LASSERT(obj->oo_db != NULL);

	oh = container_of0(th, struct osd_thandle, ot_super);
	LASSERT(oh != NULL);
	LASSERT(oh->ot_tx != NULL);

	/* remove obj ref from index dir (it depends) */
	zapid = osd_get_name_n_idx(env, osd, fid, buf);
	rc = -zap_remove(osd->od_os, zapid, buf, oh->ot_tx);
	if (rc) {
		CERROR("%s: zap_remove(%s) failed: rc = %d\n",
		       osd->od_svname, buf, rc);
		GOTO(out, rc);
	}

	rc = osd_xattrs_destroy(env, obj, oh);
	if (rc) {
		CERROR("%s: cannot destroy xattrs for %s: rc = %d\n",
		       osd->od_svname, buf, rc);
		GOTO(out, rc);
	}

	/* Remove object from inode accounting. It is not fatal for the destroy
	 * operation if something goes wrong while updating accounting, but we
	 * still log an error message to notify the administrator */
	rc = -zap_increment_int(osd->od_os, osd->od_iusr_oid,
				obj->oo_attr.la_uid, -1, oh->ot_tx);
	if (rc)
		CERROR("%s: failed to remove "DFID" from accounting ZAP for usr"
		       " %d: rc = %d\n", osd->od_svname, PFID(fid),
		       obj->oo_attr.la_uid, rc);
	rc = -zap_increment_int(osd->od_os, osd->od_igrp_oid,
				obj->oo_attr.la_gid, -1, oh->ot_tx);
	if (rc)
		CERROR("%s: failed to remove "DFID" from accounting ZAP for grp"
		       " %d: rc = %d\n", osd->od_svname, PFID(fid),
		       obj->oo_attr.la_gid, rc);

	oid = obj->oo_db->db_object;
	if (unlikely(obj->oo_destroy == OSD_DESTROY_NONE)) {
		/* this may happen if the destroy wasn't declared
		 * e.g. when the object is created and then destroyed
		 * in the same transaction - we don't need additional
		 * space for destroy specifically */
		LASSERT(obj->oo_attr.la_size <= osd_sync_destroy_max_size);
		rc = -dmu_object_free(osd->od_os, oid, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to free %s "LPU64": rc = %d\n",
			       osd->od_svname, buf, oid, rc);
	} else if (obj->oo_destroy == OSD_DESTROY_SYNC) {
		rc = -dmu_object_free(osd->od_os, oid, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to free %s "LPU64": rc = %d\n",
			       osd->od_svname, buf, oid, rc);
	} else { /* asynchronous destroy */
		rc = osd_object_unlinked_add(obj, oh);
		if (rc)
			GOTO(out, rc);

		rc = -zap_add_int(osd->od_os, osd->od_unlinkedid,
				  oid, oh->ot_tx);
		if (rc)
			CERROR("%s: zap_add_int() failed %s "LPU64": rc = %d\n",
			       osd->od_svname, buf, oid, rc);
	}

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

	if (obj->oo_db != NULL) {
		osd_object_sa_fini(obj);
		if (obj->oo_sa_xattr) {
			nvlist_free(obj->oo_sa_xattr);
			obj->oo_sa_xattr = NULL;
		}
		sa_buf_rele(obj->oo_db, osd_obj_tag);
		list_del(&obj->oo_sa_linkage);
		obj->oo_db = NULL;
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

static void osd_object_read_lock(const struct lu_env *env,
				 struct dt_object *dt, unsigned role)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(osd_invariant(obj));

	down_read_nested(&obj->oo_sem, role);
}

static void osd_object_write_lock(const struct lu_env *env,
				  struct dt_object *dt, unsigned role)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(osd_invariant(obj));

	down_write_nested(&obj->oo_sem, role);
}

static void osd_object_read_unlock(const struct lu_env *env,
				   struct dt_object *dt)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(osd_invariant(obj));
	up_read(&obj->oo_sem);
}

static void osd_object_write_unlock(const struct lu_env *env,
                                    struct dt_object *dt)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(osd_invariant(obj));
	up_write(&obj->oo_sem);
}

static int osd_object_write_locked(const struct lu_env *env,
				   struct dt_object *dt)
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

static int osd_attr_get(const struct lu_env *env,
			struct dt_object *dt,
			struct lu_attr *attr)
{
	struct osd_object	*obj = osd_dt_obj(dt);
	uint64_t		 blocks;
	uint32_t		 blksize;
	int			 rc = 0;

	down_read(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = -ENOENT);

	LASSERT(osd_invariant(obj));
	LASSERT(obj->oo_db);

	read_lock(&obj->oo_attr_lock);
	*attr = obj->oo_attr;
	if (obj->oo_lma_flags & LUSTRE_ORPHAN_FL)
		attr->la_flags |= LUSTRE_ORPHAN_FL;
	read_unlock(&obj->oo_attr_lock);

	/* with ZFS_DEBUG zrl_add_debug() called by DB_DNODE_ENTER()
	 * from within sa_object_size() can block on a mutex, so
	 * we can't call sa_object_size() holding rwlock */
	sa_object_size(obj->oo_sa_hdl, &blksize, &blocks);
	/* we do not control size of indices, so always calculate
	 * it from number of blocks reported by DMU */
	if (S_ISDIR(attr->la_mode))
		attr->la_size = 512 * blocks;
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
			       struct lquota_id_info *qi)
{
	int	rc;

	if (unlikely(qsd == NULL))
		return 0;

	LASSERT(qtype >= 0 && qtype < MAXQUOTAS);
	qi->lqi_type = qtype;

	/* inode accounting */
	qi->lqi_is_blk = false;

	/* one more inode for the new owner ... */
	qi->lqi_id.qid_uid = new_id;
	qi->lqi_space      = 1;
	rc = qsd_op_begin(env, qsd, trans, qi, NULL);
	if (rc == -EDQUOT || rc == -EINPROGRESS)
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
	if (rc == -EDQUOT || rc == -EINPROGRESS)
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
	char			*buf = osd_oti_get(env)->oti_str;
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	struct osd_thandle	*oh;
	uint64_t		 bspace;
	uint32_t		 blksize;
	int			 rc = 0;
	ENTRY;


	LASSERT(handle != NULL);
	LASSERT(osd_invariant(obj));

	oh = container_of0(handle, struct osd_thandle, ot_super);

	down_read(&obj->oo_guard);
	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		GOTO(out, rc = 0);

	LASSERT(obj->oo_sa_hdl != NULL);
	LASSERT(oh->ot_tx != NULL);
	dmu_tx_hold_sa(oh->ot_tx, obj->oo_sa_hdl, 0);
	if (oh->ot_tx->tx_err != 0)
		GOTO(out, rc = -oh->ot_tx->tx_err);

	sa_object_size(obj->oo_sa_hdl, &blksize, &bspace);
	bspace = toqb(bspace * blksize);

	__osd_xattr_declare_set(env, obj, sizeof(struct lustre_mdt_attrs),
				XATTR_NAME_LMA, oh);

	if (attr && attr->la_valid & LA_UID) {
		/* account for user inode tracking ZAP update */
		dmu_tx_hold_bonus(oh->ot_tx, osd->od_iusr_oid);
		dmu_tx_hold_zap(oh->ot_tx, osd->od_iusr_oid, TRUE, buf);

		/* quota enforcement for user */
		if (attr->la_uid != obj->oo_attr.la_uid) {
			rc = qsd_transfer(env, osd->od_quota_slave,
					  &oh->ot_quota_trans, USRQUOTA,
					  obj->oo_attr.la_uid, attr->la_uid,
					  bspace, &info->oti_qi);
			if (rc)
				GOTO(out, rc);
		}
	}
	if (attr && attr->la_valid & LA_GID) {
		/* account for user inode tracking ZAP update */
		dmu_tx_hold_bonus(oh->ot_tx, osd->od_igrp_oid);
		dmu_tx_hold_zap(oh->ot_tx, osd->od_igrp_oid, TRUE, buf);

		/* quota enforcement for group */
		if (attr->la_gid != obj->oo_attr.la_gid) {
			rc = qsd_transfer(env, osd->od_quota_slave,
					  &oh->ot_quota_trans, GRPQUOTA,
					  obj->oo_attr.la_gid, attr->la_gid,
					  bspace, &info->oti_qi);
			if (rc)
				GOTO(out, rc);
		}
	}

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
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	struct osd_thandle	*oh;
	struct osa_attr		*osa = &info->oti_osa;
	sa_bulk_attr_t		*bulk;
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

	oh = container_of0(handle, struct osd_thandle, ot_super);
	/* Assert that the transaction has been assigned to a
	   transaction group. */
	LASSERT(oh->ot_tx->tx_txg != 0);

	/* Only allow set size for regular file */
	if (!S_ISREG(dt->do_lu.lo_header->loh_attr))
		valid &= ~(LA_SIZE | LA_BLOCKS);

	if (valid == 0)
		GOTO(out, rc = 0);

	if (valid & LA_FLAGS) {
		struct lustre_mdt_attrs *lma;
		struct lu_buf buf;

		if (la->la_flags & LUSTRE_LMA_FL_MASKS) {
			CLASSERT(sizeof(info->oti_buf) >= sizeof(*lma));
			lma = (struct lustre_mdt_attrs *)&info->oti_buf;
			buf.lb_buf = lma;
			buf.lb_len = sizeof(info->oti_buf);
			rc = osd_xattr_get(env, &obj->oo_dt, &buf,
					   XATTR_NAME_LMA);
			if (rc > 0) {
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
				RETURN(rc);
			}
		}
	}

	OBD_ALLOC(bulk, sizeof(sa_bulk_attr_t) * 10);
	if (bulk == NULL)
		GOTO(out, rc = -ENOMEM);

	/* do both accounting updates outside oo_attr_lock below */
	if ((valid & LA_UID) && (la->la_uid != obj->oo_attr.la_uid)) {
		/* Update user accounting. Failure isn't fatal, but we still
		 * log an error message */
		rc = -zap_increment_int(osd->od_os, osd->od_iusr_oid,
					la->la_uid, 1, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to update accounting ZAP for user "
				"%d (%d)\n", osd->od_svname, la->la_uid, rc);
		rc = -zap_increment_int(osd->od_os, osd->od_iusr_oid,
					obj->oo_attr.la_uid, -1, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to update accounting ZAP for user "
				"%d (%d)\n", osd->od_svname,
				obj->oo_attr.la_uid, rc);
	}
	if ((valid & LA_GID) && (la->la_gid != obj->oo_attr.la_gid)) {
		/* Update group accounting. Failure isn't fatal, but we still
		 * log an error message */
		rc = -zap_increment_int(osd->od_os, osd->od_igrp_oid,
					la->la_gid, 1, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to update accounting ZAP for user "
				"%d (%d)\n", osd->od_svname, la->la_gid, rc);
		rc = -zap_increment_int(osd->od_os, osd->od_igrp_oid,
					obj->oo_attr.la_gid, -1, oh->ot_tx);
		if (rc)
			CERROR("%s: failed to update accounting ZAP for user "
				"%d (%d)\n", osd->od_svname,
				obj->oo_attr.la_gid, rc);
	}

	write_lock(&obj->oo_attr_lock);
	cnt = 0;
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

	rc = osd_object_sa_bulk_update(obj, bulk, cnt, oh);

	OBD_FREE(bulk, sizeof(sa_bulk_attr_t) * 10);
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
}

static int osd_declare_object_create(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     struct dt_allocation_hint *hint,
				     struct dt_object_format *dof,
				     struct thandle *handle)
{
	char			*buf = osd_oti_get(env)->oti_str;
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	struct osd_thandle	*oh;
	uint64_t		 zapid;
	int			 rc;
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
	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_tx != NULL);

	switch (dof->dof_type) {
		case DFT_DIR:
			dt->do_index_ops = &osd_dir_ops;
		case DFT_INDEX:
			/* for zap create */
			dmu_tx_hold_zap(oh->ot_tx, DMU_NEW_OBJECT, 1, NULL);
			break;
		case DFT_REGULAR:
		case DFT_SYM:
		case DFT_NODE:
			/* first, we'll create new object */
			dmu_tx_hold_bonus(oh->ot_tx, DMU_NEW_OBJECT);
			break;

		default:
			LBUG();
			break;
	}

	/* and we'll add it to some mapping */
	zapid = osd_get_name_n_idx(env, osd, fid, buf);
	dmu_tx_hold_bonus(oh->ot_tx, zapid);
	dmu_tx_hold_zap(oh->ot_tx, zapid, TRUE, buf);

	/* we will also update inode accounting ZAPs */
	dmu_tx_hold_bonus(oh->ot_tx, osd->od_iusr_oid);
	dmu_tx_hold_zap(oh->ot_tx, osd->od_iusr_oid, TRUE, buf);
	dmu_tx_hold_bonus(oh->ot_tx, osd->od_igrp_oid);
	dmu_tx_hold_zap(oh->ot_tx, osd->od_igrp_oid, TRUE, buf);

	dmu_tx_hold_sa_create(oh->ot_tx, ZFS_SA_BASE_ATTR_SIZE);

	__osd_xattr_declare_set(env, obj, sizeof(struct lustre_mdt_attrs),
				XATTR_NAME_LMA, oh);

	rc = osd_declare_quota(env, osd, attr->la_uid, attr->la_gid, 1, oh,
			       false, NULL, false);
	RETURN(rc);
}

int __osd_attr_init(const struct lu_env *env, struct osd_device *osd,
		    uint64_t oid, dmu_tx_t *tx, struct lu_attr *la,
		    uint64_t parent)
{
	sa_bulk_attr_t	*bulk;
	sa_handle_t	*sa_hdl;
	struct osa_attr	*osa = &osd_oti_get(env)->oti_osa;
	uint64_t	 gen;
	uint64_t	 crtime[2];
	timestruc_t	 now;
	int		 cnt;
	int		 rc;

	gethrestime(&now);
	gen = dmu_tx_get_txg(tx);

	ZFS_TIME_ENCODE(&now, crtime);

	osa->atime[0] = la->la_atime;
	osa->ctime[0] = la->la_ctime;
	osa->mtime[0] = la->la_mtime;
	osa->mode = la->la_mode;
	osa->uid = la->la_uid;
	osa->gid = la->la_gid;
	osa->rdev = la->la_rdev;
	osa->nlink = la->la_nlink;
	osa->flags = attrs_fs2zfs(la->la_flags);
	osa->size  = la->la_size;

	/* Now add in all of the "SA" attributes */
	rc = -sa_handle_get(osd->od_os, oid, NULL, SA_HDL_PRIVATE, &sa_hdl);
	if (rc)
		return rc;

	OBD_ALLOC(bulk, sizeof(sa_bulk_attr_t) * 13);
	if (bulk == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	/*
	 * we need to create all SA below upon object create.
	 *
	 * XXX The attribute order matters since the accounting callback relies
	 * on static offsets (i.e. SA_*_OFFSET, see zfs_space_delta_cb()) to
	 * look up the UID/GID attributes. Moreover, the callback does not seem
	 * to support the spill block.
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
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_CRTIME(osd), NULL, crtime, 16);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_LINKS(osd), NULL, &osa->nlink, 8);
	SA_ADD_BULK_ATTR(bulk, cnt, SA_ZPL_RDEV(osd), NULL, &osa->rdev, 8);

	rc = -sa_replace_all_by_template(sa_hdl, bulk, cnt, tx);

	OBD_FREE(bulk, sizeof(sa_bulk_attr_t) * 13);
out:
	sa_handle_destroy(sa_hdl);
	return rc;
}

/*
 * The transaction passed to this routine must have
 * dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT) called and then assigned
 * to a transaction group.
 */
int __osd_object_create(const struct lu_env *env, struct osd_object *obj,
			dmu_buf_t **dbp, dmu_tx_t *tx, struct lu_attr *la,
			uint64_t parent)
{
	uint64_t	     oid;
	int		     rc;
	struct osd_device   *osd = osd_obj2dev(obj);
	const struct lu_fid *fid = lu_object_fid(&obj->oo_dt.do_lu);
	dmu_object_type_t    type = DMU_OT_PLAIN_FILE_CONTENTS;

	/* Assert that the transaction has been assigned to a
	   transaction group. */
	LASSERT(tx->tx_txg != 0);

	/* Use DMU_OTN_UINT8_METADATA for local objects so their data blocks
	 * would get an additional ditto copy */
	if (unlikely(S_ISREG(la->la_mode) &&
		     fid_seq_is_local_file(fid_seq(fid))))
		type = DMU_OTN_UINT8_METADATA;

	/* Create a new DMU object. */
	oid = dmu_object_alloc(osd->od_os, type, 0,
			       DMU_OT_SA, DN_MAX_BONUSLEN, tx);
	rc = -sa_buf_hold(osd->od_os, oid, osd_obj_tag, dbp);
	LASSERTF(rc == 0, "sa_buf_hold "LPU64" failed: %d\n", oid, rc);

	LASSERT(la->la_valid & LA_MODE);
	la->la_size = 0;
	la->la_nlink = 1;

	rc = __osd_attr_init(env, osd, oid, tx, la, parent);
	if (rc != 0) {
		sa_buf_rele(*dbp, osd_obj_tag);
		*dbp = NULL;
		dmu_object_free(osd->od_os, oid, tx);
		return rc;
	}

	return 0;
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
		     dmu_buf_t **zap_dbp, dmu_tx_t *tx,
		     struct lu_attr *la, uint64_t parent, zap_flags_t flags)
{
	uint64_t oid;
	int	 rc;

	/* Assert that the transaction has been assigned to a
	   transaction group. */
	LASSERT(tx->tx_txg != 0);

	oid = zap_create_flags(osd->od_os, 0, flags | ZAP_FLAG_HASH64,
			       DMU_OT_DIRECTORY_CONTENTS,
			       14, /* == ZFS fzap_default_block_shift */
			       DN_MAX_INDBLKSHIFT, /* indirect block shift */
			       DMU_OT_SA, DN_MAX_BONUSLEN, tx);

	rc = -sa_buf_hold(osd->od_os, oid, osd_obj_tag, zap_dbp);
	if (rc)
		return rc;

	LASSERT(la->la_valid & LA_MODE);
	la->la_size = 2;
	la->la_nlink = 1;

	return __osd_attr_init(env, osd, oid, tx, la, parent);
}

static dmu_buf_t *osd_mkidx(const struct lu_env *env, struct osd_object *obj,
			    struct lu_attr *la, uint64_t parent,
			    struct osd_thandle *oh)
{
	dmu_buf_t *db;
	int	   rc;

	/* Index file should be created as regular file in order not to confuse
	 * ZPL which could interpret them as directory.
	 * We set ZAP_FLAG_UINT64_KEY to let ZFS know than we are going to use
	 * binary keys */
	LASSERT(S_ISREG(la->la_mode));
	rc = __osd_zap_create(env, osd_obj2dev(obj), &db, oh->ot_tx, la, parent,
			      ZAP_FLAG_UINT64_KEY);
	if (rc)
		return ERR_PTR(rc);
	return db;
}

static dmu_buf_t *osd_mkdir(const struct lu_env *env, struct osd_object *obj,
			    struct lu_attr *la, uint64_t parent,
			    struct osd_thandle *oh)
{
	dmu_buf_t *db;
	int	   rc;

	LASSERT(S_ISDIR(la->la_mode));
	rc = __osd_zap_create(env, osd_obj2dev(obj), &db,
			      oh->ot_tx, la, parent, 0);
	if (rc)
		return ERR_PTR(rc);
	return db;
}

static dmu_buf_t *osd_mkreg(const struct lu_env *env, struct osd_object *obj,
			    struct lu_attr *la, uint64_t parent,
			    struct osd_thandle *oh)
{
	dmu_buf_t	  *db;
	int		   rc;
	struct osd_device *osd = osd_obj2dev(obj);

	LASSERT(S_ISREG(la->la_mode));
	rc = __osd_object_create(env, obj, &db, oh->ot_tx, la, parent);
	if (rc)
		return ERR_PTR(rc);

	/*
	 * XXX: This heuristic is non-optimal.  It would be better to
	 * increase the blocksize up to osd->od_max_blksz during the write.
	 * This is exactly how the ZPL behaves and it ensures that the right
	 * blocksize is selected based on the file size rather than the
	 * making broad assumptions based on the osd type.
	 */
	if (!lu_device_is_md(osd2lu_dev(osd))) {
		rc = -dmu_object_set_blocksize(osd->od_os, db->db_object,
					       osd->od_max_blksz, 0, oh->ot_tx);
		if (unlikely(rc)) {
			CERROR("%s: can't change blocksize: %d\n",
			       osd->od_svname, rc);
			return ERR_PTR(rc);
		}
	}

	return db;
}

static dmu_buf_t *osd_mksym(const struct lu_env *env, struct osd_object *obj,
			    struct lu_attr *la, uint64_t parent,
			    struct osd_thandle *oh)
{
	dmu_buf_t *db;
	int	   rc;

	LASSERT(S_ISLNK(la->la_mode));
	rc = __osd_object_create(env, obj, &db, oh->ot_tx, la, parent);
	if (rc)
		return ERR_PTR(rc);
	return db;
}

static dmu_buf_t *osd_mknod(const struct lu_env *env, struct osd_object *obj,
			    struct lu_attr *la, uint64_t parent,
			    struct osd_thandle *oh)
{
	dmu_buf_t *db;
	int	   rc;

	la->la_valid = LA_MODE;
	if (S_ISCHR(la->la_mode) || S_ISBLK(la->la_mode))
		la->la_valid |= LA_RDEV;

	rc = __osd_object_create(env, obj, &db, oh->ot_tx, la, parent);
	if (rc)
		return ERR_PTR(rc);
	return db;
}

typedef dmu_buf_t *(*osd_obj_type_f)(const struct lu_env *env,
				     struct osd_object *obj,
				     struct lu_attr *la,
				     uint64_t parent,
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
 * Primitives for directory (i.e. ZAP) handling
 */
static inline int osd_init_lma(const struct lu_env *env, struct osd_object *obj,
			       const struct lu_fid *fid, struct osd_thandle *oh)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct lustre_mdt_attrs	*lma = &info->oti_mdt_attrs;
	struct lu_buf		 buf;
	int rc;

	lustre_lma_init(lma, fid, 0, 0);
	lustre_lma_swab(lma);
	buf.lb_buf = lma;
	buf.lb_len = sizeof(*lma);

	rc = osd_xattr_set_internal(env, obj, &buf, XATTR_NAME_LMA,
				    LU_XATTR_CREATE, oh);

	return rc;
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_object_create(const struct lu_env *env, struct dt_object *dt,
			     struct lu_attr *attr,
			     struct dt_allocation_hint *hint,
			     struct dt_object_format *dof,
			     struct thandle *th)
{
	struct zpl_direntry	*zde = &osd_oti_get(env)->oti_zde.lzd_reg;
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_obj2dev(obj);
	char			*buf = osd_oti_get(env)->oti_str;
	struct osd_thandle	*oh;
	dmu_buf_t		*db;
	uint64_t		 zapid;
	int			 rc;

	ENTRY;

	/* concurrent create declarations should not see
	 * the object inconsistent (db, attr, etc).
	 * in regular cases acquisition should be cheap */
	down_write(&obj->oo_guard);

	if (unlikely(dt_object_exists(dt)))
		GOTO(out, rc = -EEXIST);

	LASSERT(osd_invariant(obj));
	LASSERT(dof != NULL);

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	/*
	 * XXX missing: Quote handling.
	 */

	LASSERT(obj->oo_db == NULL);

	/* to follow ZFS on-disk format we need
	 * to initialize parent dnode properly */
	zapid = 0;
	if (hint != NULL && hint->dah_parent != NULL &&
	    !dt_object_remote(hint->dah_parent))
		zapid = osd_dt_obj(hint->dah_parent)->oo_db->db_object;

	db = osd_create_type_f(dof->dof_type)(env, obj, attr, zapid, oh);
	if (IS_ERR(db))
		GOTO(out, rc = PTR_ERR(db));

	zde->zde_pad = 0;
	zde->zde_dnode = db->db_object;
	zde->zde_type = IFTODT(attr->la_mode & S_IFMT);

	zapid = osd_get_name_n_idx(env, osd, fid, buf);

	rc = -zap_add(osd->od_os, zapid, buf, 8, 1, zde, oh->ot_tx);
	if (rc)
		GOTO(out, rc);

	/* Add new object to inode accounting.
	 * Errors are not considered as fatal */
	rc = -zap_increment_int(osd->od_os, osd->od_iusr_oid,
				(attr->la_valid & LA_UID) ? attr->la_uid : 0, 1,
				oh->ot_tx);
	if (rc)
		CERROR("%s: failed to add "DFID" to accounting ZAP for usr %d "
			"(%d)\n", osd->od_svname, PFID(fid), attr->la_uid, rc);
	rc = -zap_increment_int(osd->od_os, osd->od_igrp_oid,
				(attr->la_valid & LA_GID) ? attr->la_gid : 0, 1,
				oh->ot_tx);
	if (rc)
		CERROR("%s: failed to add "DFID" to accounting ZAP for grp %d "
			"(%d)\n", osd->od_svname, PFID(fid), attr->la_gid, rc);

	/* configure new osd object */
	obj->oo_db = db;
	rc = osd_object_init0(env, obj);
	LASSERT(ergo(rc == 0, dt_object_exists(dt)));
	LASSERT(osd_invariant(obj));

	rc = osd_init_lma(env, obj, fid, oh);
	if (rc) {
		CERROR("%s: can not set LMA on "DFID": rc = %d\n",
		       osd->od_svname, PFID(fid), rc);
		/* ignore errors during LMA initialization */
		rc = 0;
	}

out:
	up_write(&obj->oo_guard);
	RETURN(rc);
}

static int osd_declare_object_ref_add(const struct lu_env *env,
				      struct dt_object *dt,
				      struct thandle *th)
{
	return osd_declare_attr_set(env, dt, NULL, th);
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_object_ref_add(const struct lu_env *env,
			      struct dt_object *dt,
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

	oh = container_of0(handle, struct osd_thandle, ot_super);

	write_lock(&obj->oo_attr_lock);
	nlink = ++obj->oo_attr.la_nlink;
	write_unlock(&obj->oo_attr_lock);

	rc = osd_object_sa_update(obj, SA_ZPL_LINKS(osd), &nlink, 8, oh);

out:
	up_read(&obj->oo_guard);
	RETURN(rc);
}

static int osd_declare_object_ref_del(const struct lu_env *env,
				      struct dt_object *dt,
				      struct thandle *handle)
{
	return osd_declare_attr_set(env, dt, NULL, handle);
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_object_ref_del(const struct lu_env *env,
			      struct dt_object *dt,
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

	oh = container_of0(handle, struct osd_thandle, ot_super);
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
	ENTRY;

	/* XXX: no other option than syncing the whole filesystem until we
	 * support ZIL.  If the object tracked the txg that it was last
	 * modified in, it could pass that txg here instead of "0".  Maybe
	 * the changes are already committed, so no wait is needed at all? */
	txg_wait_synced(dmu_objset_pool(osd->od_os), 0ULL);

	RETURN(0);
}

static struct dt_object_operations osd_obj_ops = {
	.do_read_lock		= osd_object_read_lock,
	.do_write_lock		= osd_object_write_lock,
	.do_read_unlock		= osd_object_read_unlock,
	.do_write_unlock	= osd_object_write_unlock,
	.do_write_locked	= osd_object_write_locked,
	.do_attr_get		= osd_attr_get,
	.do_declare_attr_set	= osd_declare_attr_set,
	.do_attr_set		= osd_attr_set,
	.do_ah_init		= osd_ah_init,
	.do_declare_create	= osd_declare_object_create,
	.do_create		= osd_object_create,
	.do_declare_destroy	= osd_declare_object_destroy,
	.do_destroy		= osd_object_destroy,
	.do_index_try		= osd_index_try,
	.do_declare_ref_add	= osd_declare_object_ref_add,
	.do_ref_add		= osd_object_ref_add,
	.do_declare_ref_del	= osd_declare_object_ref_del,
	.do_ref_del		= osd_object_ref_del,
	.do_xattr_get		= osd_xattr_get,
	.do_declare_xattr_set	= osd_declare_xattr_set,
	.do_xattr_set		= osd_xattr_set,
	.do_declare_xattr_del	= osd_declare_xattr_del,
	.do_xattr_del		= osd_xattr_del,
	.do_xattr_list		= osd_xattr_list,
	.do_object_sync		= osd_object_sync,
};

static struct lu_object_operations osd_lu_obj_ops = {
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

static struct dt_object_operations osd_obj_otable_it_ops = {
        .do_attr_get    = osd_otable_it_attr_get,
        .do_index_try   = osd_index_try,
};
