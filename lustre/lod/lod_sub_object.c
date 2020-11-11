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
 * Copyright (c) 2015, 2017, Intel Corporation.
 */
/*
 * lustre/lod/lod_sub_object.c
 *
 * LOD sub object methods
 *
 * This file implements sub-object methods for LOD.
 *
 * LOD is Logic volume layer in the MDS stack, which will handle striping
 * and distribute the update to different OSP/OSD. After directing the updates
 * to one specific OSD/OSP, it also needs to do some thing before calling
 * OSD/OSP API, for example recording updates for cross-MDT operation, get
 * the next level transaction etc.
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_class.h>
#include <uapi/linux/lustre/lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <lustre_fid.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <md_object.h>
#include <lustre_linkea.h>
#include <lustre_log.h>

#include "lod_internal.h"

struct thandle *lod_sub_get_thandle(const struct lu_env *env,
				    struct thandle *th,
				    const struct dt_object *sub_obj,
				    bool *record_update)
{
	struct lod_device	*lod = dt2lod_dev(th->th_dev);
	struct top_thandle	*tth;
	struct thandle		*sub_th;
	int			type = LU_SEQ_RANGE_ANY;
	__u32			mdt_index;
	int			rc;
	ENTRY;

	if (record_update != NULL)
		*record_update = false;

	if (th->th_top == NULL)
		RETURN(th);

	tth = container_of(th, struct top_thandle, tt_super);
	tth->tt_master_sub_thandle->th_ignore_quota = th->th_ignore_quota;

	/* local object must be mdt object, Note: during ost object
	 * creation, FID is not assigned until osp_create(),
	 * so if the FID of sub_obj is zero, it means OST object. */
	if (!dt_object_remote(sub_obj) ||
	    fid_is_zero(lu_object_fid(&sub_obj->do_lu))) {
		/* local MDT object */
		if (fid_is_sane(lu_object_fid(&sub_obj->do_lu)) &&
		    tth->tt_multiple_thandle != NULL &&
		    record_update != NULL &&
		    th->th_result == 0)
			*record_update = true;

		RETURN(tth->tt_master_sub_thandle);
	}

	rc = lod_fld_lookup(env, lod, lu_object_fid(&sub_obj->do_lu),
			    &mdt_index, &type);
	if (rc < 0)
		RETURN(ERR_PTR(rc));

	/* th_complex means we need track all of updates for this
	 * transaction, include changes on OST */
	if (type == LU_SEQ_RANGE_OST && !th->th_complex)
		RETURN(tth->tt_master_sub_thandle);

	sub_th = thandle_get_sub(env, th, sub_obj);
	if (IS_ERR(sub_th))
		RETURN(sub_th);
	sub_th->th_ignore_quota = th->th_ignore_quota;

	if (tth->tt_multiple_thandle != NULL && record_update != NULL &&
	    th->th_result == 0)
		*record_update = true;

	RETURN(sub_th);
}

/**
 * Declare sub-object creation.
 *
 * Get transaction of next layer and declare the creation of the object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	the object being created
 * \param[in] attr	the attributes of the object being created
 * \param[in] hint	the hint of the creation
 * \param[in] dof	the object format of the creation
 * \param[th] th	the transaction handle
 *
 * \retval		0 if the declaration succeeds
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_create(const struct lu_env *env, struct dt_object *dt,
			   struct lu_attr *attr,
			   struct dt_allocation_hint *hint,
			   struct dt_object_format *dof, struct thandle *th)
{
	struct thandle *sub_th;
	bool record_update;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		return PTR_ERR(sub_th);

	if (record_update)
		update_record_size(env, create, th, lu_object_fid(&dt->do_lu),
				   attr, hint, dof);

	return dt_declare_create(env, dt, attr, hint, dof, sub_th);
}

/**
 * Create sub-object.
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation, and create the object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	the object being created
 * \param[in] attr	the attributes of the object being created
 * \param[in] hint	the hint of the creation
 * \param[in] dof	the object format of the creation
 * \param[th] th	the transaction handle
 *
 * \retval		0 if the creation succeeds
 * \retval		negative errno if the creation fails.
 */
int lod_sub_create(const struct lu_env *env, struct dt_object *dt,
		   struct lu_attr *attr, struct dt_allocation_hint *hint,
		   struct dt_object_format *dof, struct thandle *th)
{
	struct thandle	   *sub_th;
	bool		   record_update;
	int		    rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(create, th,
					lu_object_fid(&dt->do_lu),
					attr, hint, dof);
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_create(env, dt, attr, hint, dof, sub_th);

	RETURN(rc);
}

/**
 * Declare adding reference for the sub-object
 *
 * Get transaction of next layer and declare the reference adding.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt object to add reference
 * \param[in] th	transaction handle
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_ref_add(const struct lu_env *env, struct dt_object *dt,
			    struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, ref_add, th, lu_object_fid(&dt->do_lu));

	rc = dt_declare_ref_add(env, dt, sub_th);

	RETURN(rc);
}

/**
 * Add reference for the sub-object
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation and add reference of the object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt object to add reference
 * \param[in] th	transaction handle
 *
 * \retval		0 if it succeeds.
 * \retval		negative errno if it fails.
 */
int lod_sub_ref_add(const struct lu_env *env, struct dt_object *dt,
		    struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(ref_add, th,
					lu_object_fid(&dt->do_lu));
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_ref_add(env, dt, sub_th);

	RETURN(rc);
}

/**
 * Declare deleting reference for the sub-object
 *
 * Get transaction of next layer and declare the reference deleting.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt object to delete reference
 * \param[in] th	transaction handle
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_ref_del(const struct lu_env *env, struct dt_object *dt,
			    struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, ref_del, th, lu_object_fid(&dt->do_lu));

	rc = dt_declare_ref_del(env, dt, sub_th);

	RETURN(rc);
}

/**
 * Delete reference for the sub-object
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation and delete reference of the object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt object to delete reference
 * \param[in] th	transaction handle
 *
 * \retval		0 if it succeeds.
 * \retval		negative errno if it fails.
 */
int lod_sub_ref_del(const struct lu_env *env, struct dt_object *dt,
		    struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(ref_del, th,
					lu_object_fid(&dt->do_lu));
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_ref_del(env, dt, sub_th);

	RETURN(rc);
}

/**
 * Declare destroying sub-object
 *
 * Get transaction of next layer and declare the sub-object destroy.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt object to be destroyed
 * \param[in] th	transaction handle
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_destroy(const struct lu_env *env, struct dt_object *dt,
			    struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, destroy, th, lu_object_fid(&dt->do_lu));

	rc = dt_declare_destroy(env, dt, sub_th);

	RETURN(rc);
}

/**
 * Destroy sub-object
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation and destroy the object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt object to be destroyed
 * \param[in] th	transaction handle
 *
 * \retval		0 if the destroy succeeds.
 * \retval		negative errno if the destroy fails.
 */
int lod_sub_destroy(const struct lu_env *env, struct dt_object *dt,
		    struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(destroy, th, lu_object_fid(&dt->do_lu));
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_destroy(env, dt, sub_th);

	RETURN(rc);
}

/**
 * Declare sub-object index insert
 *
 * Get transaction of next layer and declare index insert.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object for which to insert index
 * \param[in] rec	record of the index which will be inserted
 * \param[in] key	key of the index which will be inserted
 * \param[in] th	the transaction handle
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_insert(const struct lu_env *env, struct dt_object *dt,
			   const struct dt_rec *rec,
			   const struct dt_key *key, struct thandle *th)
{
	struct thandle *sub_th;
	bool		record_update;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		return PTR_ERR(sub_th);

	if (record_update)
		update_record_size(env, index_insert, th,
				   lu_object_fid(&dt->do_lu), rec, key);

	return dt_declare_insert(env, dt, rec, key, sub_th);
}

/**
 * Insert index of sub object
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation, and insert the index.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object for which to insert index
 * \param[in] rec	record of the index to be inserted
 * \param[in] key	key of the index to be inserted
 * \param[in] th	the transaction handle
 *
 * \retval		0 if the insertion succeeds.
 * \retval		negative errno if the insertion fails.
 */
int lod_sub_insert(const struct lu_env *env, struct dt_object *dt,
		   const struct dt_rec *rec, const struct dt_key *key,
		   struct thandle *th)
{
	struct thandle *sub_th;
	int		rc;
	bool		record_update;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		return PTR_ERR(sub_th);

	if (record_update) {
		rc = update_record_pack(index_insert, th,
					lu_object_fid(&dt->do_lu), rec, key);
		if (rc < 0)
			return rc;
	}

	return dt_insert(env, dt, rec, key, sub_th);
}

/**
 * Declare sub-object index delete
 *
 * Get transaction of next layer and declare index deletion.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object for which to delete index
 * \param[in] key	key of the index which will be deleted
 * \param[in] th	the transaction handle
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_delete(const struct lu_env *env, struct dt_object *dt,
			   const struct dt_key *key, struct thandle *th)
{
	struct thandle *sub_th;
	bool		record_update;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		return PTR_ERR(sub_th);

	if (record_update)
		update_record_size(env, index_delete, th,
				   lu_object_fid(&dt->do_lu), key);

	return dt_declare_delete(env, dt, key, sub_th);
}

/**
 * Delete index of sub object
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation, and delete the index.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object for which to delete index
 * \param[in] key	key of the index to be deleted
 * \param[in] th	the transaction handle
 *
 * \retval		0 if the deletion succeeds.
 * \retval		negative errno if the deletion fails.
 */
int lod_sub_delete(const struct lu_env *env, struct dt_object *dt,
		   const struct dt_key *name, struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(index_delete, th,
					lu_object_fid(&dt->do_lu), name);
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_delete(env, dt, name, sub_th);
	RETURN(rc);
}

/**
 * Declare xattr_set
 *
 * Get transaction of next layer, and declare xattr set.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object on which to set xattr
 * \param[in] buf	xattr to be set
 * \param[in] name	name of the xattr
 * \param[in] fl	flag for setting xattr
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			      const struct lu_buf *buf, const char *name,
			      int fl, struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, xattr_set, th,
				   lu_object_fid(&dt->do_lu),
				   buf, name, fl);

	rc = dt_declare_xattr_set(env, dt, buf, name, fl, sub_th);

	RETURN(rc);
}

/**
 * Set xattr
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation, and set xattr to the object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object on which to set xattr
 * \param[in] buf	xattr to be set
 * \param[in] name	name of the xattr
 * \param[in] fl	flag for setting xattr
 * \param[in] th	transaction handle
 *
 * \retval		0 if the xattr setting succeeds.
 * \retval		negative errno if xattr setting fails.
 */
int lod_sub_xattr_set(const struct lu_env *env, struct dt_object *dt,
		      const struct lu_buf *buf, const char *name, int fl,
		      struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(xattr_set, th,
					lu_object_fid(&dt->do_lu),
					buf, name, fl);
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_xattr_set(env, dt, buf, name, fl, sub_th);

	RETURN(rc);
}

/**
 * Declare attr_set
 *
 * Get transaction of next layer, and declare attr set.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object on which to set attr
 * \param[in] attr	attributes to be set
 * \param[in] th	transaction handle
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
			     const struct lu_attr *attr, struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, attr_set, th,
				   lu_object_fid(&dt->do_lu), attr);

	rc = dt_declare_attr_set(env, dt, attr, sub_th);

	RETURN(rc);
}

/**
 * attributes set
 *
 * Get transaction of next layer, record updates if it belongs to cross-MDT
 * operation, and set attributes to the object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object on which to set attr
 * \param[in] attr	attrbutes to be set
 * \param[in] th	transaction handle
 *
 * \retval		0 if attributes setting succeeds.
 * \retval		negative errno if the attributes setting fails.
 */
int lod_sub_attr_set(const struct lu_env *env, struct dt_object *dt,
		     const struct lu_attr *attr, struct thandle *th)
{
	bool		   record_update;
	struct thandle	   *sub_th;
	int		    rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(attr_set, th, lu_object_fid(&dt->do_lu),
					attr);
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_attr_set(env, dt, attr, sub_th);

	RETURN(rc);
}

/**
 * Declare xattr_del
 *
 * Get transaction of next layer, and declare xattr deletion.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object on which to delete xattr
 * \param[in] name	name of the xattr to be deleted
 * \param[in] th	transaction handle
 *
 * \retval		0 if the declaration succeeds.
 * \retval		negative errno if the declaration fails.
 */
int lod_sub_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
			      const char *name, struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, xattr_del, th,
				   lu_object_fid(&dt->do_lu),
				   name);

	rc = dt_declare_xattr_del(env, dt, name, sub_th);

	RETURN(rc);
}

/**
 * xattribute deletion
 *
 * Get transaction of next layer, record update if it belongs to cross-MDT
 * operation and delete xattr.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object on which to delete xattr
 * \param[in] name	name of the xattr to be deleted
 * \param[in] th	transaction handle
 *
 * \retval		0 if the deletion succeeds.
 * \retval		negative errno if the deletion fails.
 */
int lod_sub_xattr_del(const struct lu_env *env, struct dt_object *dt,
		      const char *name, struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(xattr_del, th,
					lu_object_fid(&dt->do_lu), name);
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_xattr_del(env, dt, name, sub_th);

	RETURN(rc);
}

/**
 * Declare buffer write
 *
 * Get transaction of next layer and declare buffer write.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object to be written
 * \param[in] buf	buffer to write which includes an embedded size field
 * \param[in] pos	offet in the object to start writing at
 * \param[in] th	transaction handle
 *
 * \retval		0 if the insertion succeeds.
 * \retval		negative errno if the insertion fails.
 */
int lod_sub_declare_write(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, loff_t pos,
			  struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, write, th,
				   lu_object_fid(&dt->do_lu),
				   buf, pos);

	rc = dt_declare_write(env, dt, buf, pos, sub_th);

	RETURN(rc);
}

/**
 * Write buffer to sub object
 *
 * Get transaction of next layer, records buffer write if it belongs to
 * Cross-MDT operation, and write buffer.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object to be written
 * \param[in] buf	buffer to write which includes an embedded size field
 * \param[in] pos	offet in the object to start writing at
 * \param[in] th	transaction handle
 *
 * \retval		the buffer size in bytes if it succeeds.
 * \retval		negative errno if it fails.
 */
ssize_t lod_sub_write(const struct lu_env *env, struct dt_object *dt,
		      const struct lu_buf *buf, loff_t *pos,
		      struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	ssize_t		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(write, th, lu_object_fid(&dt->do_lu),
					buf, *pos);
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_write(env, dt, buf, pos, sub_th);
	RETURN(rc);
}

/**
 * Declare punch
 *
 * Get transaction of next layer and declare punch.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object to be written
 * \param[in] start	start offset of punch
 * \param[in] end	end offet of punch
 * \param[in] th	transaction handle
 *
 * \retval		0 if the insertion succeeds.
 * \retval		negative errno if the insertion fails.
 */
int lod_sub_declare_punch(const struct lu_env *env, struct dt_object *dt,
			  __u64 start, __u64 end, struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update)
		update_record_size(env, punch, th,
				   lu_object_fid(&dt->do_lu),
				   start, end);

	rc = dt_declare_punch(env, dt, start, end, sub_th);

	RETURN(rc);
}

/**
 * Punch to sub object
 *
 * Get transaction of next layer, records buffer write if it belongs to
 * Cross-MDT operation, and punch object.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object to be written
 * \param[in] start	start offset of punch
 * \param[in] end	end offset of punch
 * \param[in] th	transaction handle
 * \param[in] capa	capability of the write
 *
 * \retval		the buffer size in bytes if it succeeds.
 * \retval		negative errno if it fails.
 */
int lod_sub_punch(const struct lu_env *env, struct dt_object *dt,
		  __u64 start, __u64 end, struct thandle *th)
{
	struct thandle	*sub_th;
	bool		record_update;
	int		rc;
	ENTRY;

	sub_th = lod_sub_get_thandle(env, th, dt, &record_update);
	if (IS_ERR(sub_th))
		RETURN(PTR_ERR(sub_th));

	if (record_update) {
		rc = update_record_pack(punch, th, lu_object_fid(&dt->do_lu),
					start, end);
		if (rc < 0)
			RETURN(rc);
	}

	rc = dt_punch(env, dt, start, end, sub_th);

	RETURN(rc);
}

int lod_sub_prep_llog(const struct lu_env *env, struct lod_device *lod,
		      struct dt_device *dt, int index)
{
	struct lod_thread_info	*lti = lod_env_info(env);
	struct llog_ctxt	*ctxt;
	struct llog_handle	*lgh;
	struct llog_catid	*cid = &lti->lti_cid;
	struct lu_fid		*fid = &lti->lti_fid;
	struct obd_device	*obd;
	int			rc;
	bool			need_put = false;
	ENTRY;

	lu_update_log_fid(fid, index);

	rc = lodname2mdt_index(lod2obd(lod)->obd_name, (__u32 *)&index);
	if (rc < 0)
		RETURN(rc);

	rc = llog_osd_get_cat_list(env, dt, index, 1, cid, fid);
	if (rc != 0) {
		CERROR("%s: can't get id from catalogs: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		RETURN(rc);
	}

	obd = dt->dd_lu_dev.ld_obd;
	ctxt = llog_get_context(obd, LLOG_UPDATELOG_ORIG_CTXT);
	LASSERT(ctxt != NULL);
	/* concurrent config processing (e.g. setting MDT active)
	 * can try to initialize llog again before causing double
	 * initialization. check for this */
	if (ctxt->loc_handle)
		GOTO(out_put, rc = 0);

	ctxt->loc_flags |= LLOG_CTXT_FLAG_NORMAL_FID;
	ctxt->loc_chunk_size = LLOG_MIN_CHUNK_SIZE * 4;
	if (likely(logid_id(&cid->lci_logid) != 0)) {
		rc = llog_open(env, ctxt, &lgh, &cid->lci_logid, NULL,
			       LLOG_OPEN_EXISTS);

		/* re-create llog if it is missing */
		if (rc == -ENOENT)
			logid_set_id(&cid->lci_logid, 0);
		else if (rc < 0)
			GOTO(out_put, rc);
	}

	if (unlikely(logid_id(&cid->lci_logid) == 0)) {
		rc = llog_open_create(env, ctxt, &lgh, NULL, NULL);
		if (rc < 0)
			GOTO(out_put, rc);
		cid->lci_logid = lgh->lgh_id;
		need_put = true;
	}

	LASSERT(lgh != NULL);

	rc = llog_init_handle(env, lgh, LLOG_F_IS_CAT, NULL);
	if (rc != 0)
		GOTO(out_close, rc);

	if (need_put) {
		rc = llog_osd_put_cat_list(env, dt, index, 1, cid, fid);
		if (rc != 0)
			GOTO(out_close, rc);
	}

	ctxt->loc_handle = lgh;

	CDEBUG(D_INFO, "%s: init llog for index %d - catid "DFID":%x\n",
	       obd->obd_name, index, PFID(&cid->lci_logid.lgl_oi.oi_fid),
	       cid->lci_logid.lgl_ogen);
out_close:
	if (rc != 0)
		llog_cat_close(env, lgh);
out_put:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}
