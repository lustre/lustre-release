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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osp/osp_object.c
 *
 * Lustre OST Proxy Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.tappro@intel.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "osp_internal.h"

static __u64 osp_object_assign_id(const struct lu_env *env,
				  struct osp_device *d, struct osp_object *o)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	const struct lu_fid	*f = lu_object_fid(&o->opo_obj.do_lu);

	LASSERT(fid_is_zero(f));
	LASSERT(o->opo_reserved);
	o->opo_reserved = 0;

	/* assign fid to anonymous object */
	osi->osi_oi.oi_id = osp_precreate_get_id(d);
	osi->osi_oi.oi_seq = FID_SEQ_OST_MDT0;
	fid_ostid_unpack(&osi->osi_fid, &osi->osi_oi, d->opd_index);
	lu_object_assign_fid(env, &o->opo_obj.do_lu, &osi->osi_fid);

	return osi->osi_oi.oi_id;
}

static int osp_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
				const struct lu_attr *attr, struct thandle *th)
{
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

	/*
	 * Usually we don't allow server stack to manipulate size
	 * but there is a special case when striping is created
	 * late, after stripless file got truncated to non-zero.
	 *
	 * In this case we do the following:
	 *
	 * 1) grab id in declare - this can lead to leaked OST objects
	 *    but we don't currently have proper mechanism and the only
	 *    options we have are to do truncate RPC holding transaction
	 *    open (very bad) or to grab id in declare at cost of leaked
	 *    OST object in same very rare unfortunate case (just bad)
	 *    notice 1.6-2.0 do assignment outside of running transaction
	 *    all the time, meaning many more chances for leaked objects.
	 *
	 * 2) send synchronous truncate RPC with just assigned id
	 */
	LASSERT(attr);
	if (attr->la_valid & LA_SIZE && attr->la_size > 0) {
		LASSERT(!dt_object_exists(dt));
		osp_object_assign_id(env, d, o);
		rc = osp_object_truncate(env, dt, attr->la_size);
		if (rc)
			RETURN(rc);
	}

	if (o->opo_new) {
		/* no need in logging for new objects being created */
		RETURN(0);
	}

	if (!(attr->la_valid & (LA_UID | LA_GID)))
		RETURN(0);

	/*
	 * track all UID/GID changes via llog
	 */
	rc = osp_sync_declare_add(env, o, MDS_SETATTR64_REC, th);

	RETURN(rc);
}

static int osp_attr_set(const struct lu_env *env, struct dt_object *dt,
			const struct lu_attr *attr, struct thandle *th,
			struct lustre_capa *capa)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

	/* we're interested in uid/gid changes only */
	if (!(attr->la_valid & (LA_UID | LA_GID)))
		RETURN(0);

	/* new object, the very first ->attr_set()
	 * initializing attributes needs no logging
	 * all subsequent one are subject to the
	 * logging and synchronization with OST */
	if (o->opo_new) {
		o->opo_new = 0;
		RETURN(0);
	}

	/*
	 * once transaction is committed put proper command on
	 * the queue going to our OST
	 */
	rc = osp_sync_add(env, o, MDS_SETATTR64_REC, th, attr);

	/* XXX: send new uid/gid to OST ASAP? */

	RETURN(rc);
}

static int osp_declare_object_create(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     struct dt_allocation_hint *hint,
				     struct dt_object_format *dof,
				     struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	const struct lu_fid	*fid;
	int			 rc = 0;

	ENTRY;

	LASSERT(d->opd_last_used_file);
	fid = lu_object_fid(&dt->do_lu);

	/*
	 * There can be gaps in precreated ids and record to unlink llog
	 */
	rc = osp_sync_declare_add(env, o, MDS_UNLINK64_REC, th);

	if (unlikely(!fid_is_zero(fid))) {
		/* replay case: caller knows fid */
		osi->osi_off = sizeof(osi->osi_id) * d->opd_index;
		rc = dt_declare_record_write(env, d->opd_last_used_file,
					     sizeof(osi->osi_id), osi->osi_off,
					     th);
		RETURN(rc);
	}

	/*
	 * in declaration we need to reserve object so that we don't block
	 * awaiting precreation RPC to complete
	 */
	rc = osp_precreate_reserve(env, d);
	/*
	 * we also need to declare update to local "last used id" file for
	 * recovery if object isn't used for a reason, we need to release
	 * reservation, this can be made in osd_object_release()
	 */
	if (rc == 0) {
		/* mark id is reserved: in create we don't want to talk
		 * to OST */
		LASSERT(o->opo_reserved == 0);
		o->opo_reserved = 1;

		/* common for all OSPs file hystorically */
		osi->osi_off = sizeof(osi->osi_id) * d->opd_index;
		rc = dt_declare_record_write(env, d->opd_last_used_file,
					     sizeof(osi->osi_id), osi->osi_off,
					     th);
	} else {
		/* not needed in the cache anymore */
		cfs_set_bit(LU_OBJECT_HEARD_BANSHEE,
			    &dt->do_lu.lo_header->loh_flags);
	}
	RETURN(rc);
}

static int osp_object_create(const struct lu_env *env, struct dt_object *dt,
			     struct lu_attr *attr,
			     struct dt_allocation_hint *hint,
			     struct dt_object_format *dof, struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

	if (o->opo_reserved) {
		/* regular case, id is assigned holding transaction open */
		osi->osi_id = osp_object_assign_id(env, d, o);
	} else {
		/* special case, id was assigned outside of transaction
		 * see comments in osp_declare_attr_set */
		rc = fid_ostid_pack(lu_object_fid(&dt->do_lu), &osi->osi_oi);
		LASSERT(rc == 0);
		osi->osi_id = ostid_id(&osi->osi_oi);
		cfs_spin_lock(&d->opd_pre_lock);
		osp_update_last_id(d, osi->osi_id);
		cfs_spin_unlock(&d->opd_pre_lock);
	}

	LASSERT(osi->osi_id);

	/*
	 * it's OK if the import is inactive by this moment - id was created
	 * by OST earlier, we just need to maintain it consistently on the disk
	 * once import is reconnected, OSP will claim this and other objects
	 * used and OST either keep them, if they exist or recreate
	 */

	/* we might have lost precreated objects */
	if (unlikely(d->opd_gap_count) > 0) {
		cfs_spin_lock(&d->opd_pre_lock);
		if (d->opd_gap_count > 0) {
			int count = d->opd_gap_count;

			osi->osi_oi.oi_id = d->opd_gap_start;
			d->opd_gap_count = 0;
			cfs_spin_unlock(&d->opd_pre_lock);

			CDEBUG(D_HA, "Found gap "LPU64"+%d in objids\n",
			       d->opd_gap_start, count);
			/* real gap handling is disabled intil ORI-692 will be
			 * fixed, now we only report gaps */
		} else {
			cfs_spin_unlock(&d->opd_pre_lock);
		}
	}

	/* new object, the very first ->attr_set()
	 * initializing attributes needs no logging */
	o->opo_new = 1;

	osp_objid_buf_prep(osi, d, d->opd_index);
	rc = dt_record_write(env, d->opd_last_used_file, &osi->osi_lb,
			     &osi->osi_off, th);

	RETURN(rc);
}

static int osp_declare_object_destroy(const struct lu_env *env,
				      struct dt_object *dt, struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

	/*
	 * track objects to be destroyed via llog
	 */
	rc = osp_sync_declare_add(env, o, MDS_UNLINK64_REC, th);

	RETURN(rc);
}

static int osp_object_destroy(const struct lu_env *env, struct dt_object *dt,
			      struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

	/*
	 * once transaction is committed put proper command on
	 * the queue going to our OST
	 */
	rc = osp_sync_add(env, o, MDS_UNLINK64_REC, th, NULL);

	/* not needed in cache any more */
	cfs_set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);

	RETURN(rc);
}

struct dt_object_operations osp_obj_ops = {
	.do_declare_attr_set	= osp_declare_attr_set,
	.do_attr_set		= osp_attr_set,
	.do_declare_create	= osp_declare_object_create,
	.do_create		= osp_object_create,
	.do_declare_destroy	= osp_declare_object_destroy,
	.do_destroy		= osp_object_destroy,
};

static int osp_object_init(const struct lu_env *env, struct lu_object *o,
			   const struct lu_object_conf *unused)
{
	struct osp_object *po = lu2osp_obj(o);

	po->opo_obj.do_ops = &osp_obj_ops;

	return 0;
}

static void osp_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct osp_object	*obj = lu2osp_obj(o);
	struct lu_object_header	*h = o->lo_header;

	dt_object_fini(&obj->opo_obj);
	lu_object_header_fini(h);
	OBD_SLAB_FREE_PTR(obj, osp_object_kmem);
}

static void osp_object_release(const struct lu_env *env, struct lu_object *o)
{
	struct osp_object	*po = lu2osp_obj(o);
	struct osp_device	*d  = lu2osp_dev(o->lo_dev);

	ENTRY;

	/*
	 * release reservation if object was declared but not created
	 * this may require lu_object_put() in LOD
	 */
	if (unlikely(po->opo_reserved)) {
		LASSERT(d->opd_pre_reserved > 0);
		cfs_spin_lock(&d->opd_pre_lock);
		d->opd_pre_reserved--;
		cfs_spin_unlock(&d->opd_pre_lock);

		/* not needed in cache any more */
		cfs_set_bit(LU_OBJECT_HEARD_BANSHEE, &o->lo_header->loh_flags);
	}
	EXIT;
}

static int osp_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *l)
{
	const struct osp_object *o = lu2osp_obj((struct lu_object *)l);

	return (*p)(env, cookie, LUSTRE_OSP_NAME"-object@%p", o);
}

static int osp_object_invariant(const struct lu_object *o)
{
	LBUG();
}

struct lu_object_operations osp_lu_obj_ops = {
	.loo_object_init	= osp_object_init,
	.loo_object_free	= osp_object_free,
	.loo_object_release	= osp_object_release,
	.loo_object_print	= osp_object_print,
	.loo_object_invariant	= osp_object_invariant
};
