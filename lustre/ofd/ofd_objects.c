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
 * lustre/ofd/ofd_objects.c
 *
 * This file contains OSD API methods related to OBD Filter Device (OFD)
 * object operations.
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <dt_object.h>
#include <lustre_lfsck.h>

#include "ofd_internal.h"

/**
 * Get object version from disk and check it.
 *
 * This function checks object version from disk with
 * ofd_thread_info::fti_pre_version filled from incoming RPC. This is part of
 * VBR (Version-Based Recovery) and ensures that object has the same version
 * upon replay as it has during original modification.
 *
 * \param[in]  info	execution thread OFD private data
 * \param[in]  fo	OFD object
 *
 * \retval		0 if version matches
 * \retval		-EOVERFLOW on version mismatch
 */
static int ofd_version_get_check(struct ofd_thread_info *info,
				 struct ofd_object *fo)
{
	dt_obj_version_t curr_version;

	if (info->fti_exp == NULL)
		RETURN(0);

	curr_version = dt_version_get(info->fti_env, ofd_object_child(fo));
	if ((__s64)curr_version == -EOPNOTSUPP)
		RETURN(0);
	/* VBR: version is checked always because costs nothing */
	if (info->fti_pre_version != 0 &&
	    info->fti_pre_version != curr_version) {
		CDEBUG(D_INODE, "Version mismatch %#llx != %#llx\n",
		       info->fti_pre_version, curr_version);
		spin_lock(&info->fti_exp->exp_lock);
		info->fti_exp->exp_vbr_failed = 1;
		spin_unlock(&info->fti_exp->exp_lock);
		RETURN (-EOVERFLOW);
	}
	info->fti_pre_version = curr_version;
	RETURN(0);
}

/**
 * Get OFD object by FID.
 *
 * This function finds OFD slice of compound object with the given FID.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of the object
 *
 * \retval		pointer to the found ofd_object
 * \retval		ERR_PTR(errno) in case of error
 */
struct ofd_object *ofd_object_find(const struct lu_env *env,
				   struct ofd_device *ofd,
				   const struct lu_fid *fid)
{
	struct ofd_object *fo;
	struct lu_object  *o;

	ENTRY;

	o = lu_object_find(env, &ofd->ofd_dt_dev.dd_lu_dev, fid, NULL);
	if (likely(!IS_ERR(o)))
		fo = ofd_obj(o);
	else
		fo = ERR_CAST(o); /* return error */

	RETURN(fo);
}

/**
 * Get FID of parent MDT object.
 *
 * This function reads extended attribute XATTR_NAME_FID of OFD object which
 * contains the MDT parent object FID and saves it in ofd_object::ofo_ff.
 *
 * The filter_fid::ff_parent::f_ver field currently holds
 * the OST-object index in the parent MDT-object's layout EA,
 * not the actual FID::f_ver of the parent. We therefore access
 * it via the macro f_stripe_idx.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 *
 * \retval		0 if successful
 * \retval		-ENODATA if there is no such xattr
 * \retval		negative value on error
 */
int ofd_object_ff_load(const struct lu_env *env, struct ofd_object *fo)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct filter_fid *ff = &fo->ofo_ff;
	struct lu_buf *buf = &info->fti_buf;
	int rc = 0;

	if (fid_is_sane(&ff->ff_parent))
		return 0;

	buf->lb_buf = ff;
	buf->lb_len = sizeof(*ff);
	rc = dt_xattr_get(env, ofd_object_child(fo), buf, XATTR_NAME_FID);
	if (rc < 0)
		return rc;

	if (unlikely(rc < sizeof(struct lu_fid))) {
		fid_zero(&ff->ff_parent);
		return -EINVAL;
	}

	filter_fid_le_to_cpu(ff, ff, rc);

	return 0;
}

struct ofd_precreate_cb {
	struct dt_txn_commit_cb	 opc_cb;
	struct ofd_seq		*opc_oseq;
	int			 opc_objects;
};

static void ofd_cb_precreate(struct lu_env *env, struct thandle *th,
			     struct dt_txn_commit_cb *cb, int err)
{
	struct ofd_precreate_cb *opc;
	struct ofd_seq *oseq;

	opc = container_of(cb, struct ofd_precreate_cb, opc_cb);
	oseq = opc->opc_oseq;

	CDEBUG(D_OTHER, "Sub %d from %d for "DFID", th_sync %d\n",
	       opc->opc_objects, atomic_read(&oseq->os_precreate_in_progress),
	       PFID(&oseq->os_oi.oi_fid), th->th_sync);
	atomic_sub(opc->opc_objects, &oseq->os_precreate_in_progress);
	ofd_seq_put(env, opc->opc_oseq);
	OBD_FREE_PTR(opc);
}

static int ofd_precreate_cb_add(const struct lu_env *env, struct thandle *th,
				struct ofd_seq *oseq, int objects)
{
	struct ofd_precreate_cb *opc;
	struct dt_txn_commit_cb *dcb;
	int precreate, rc;

	OBD_ALLOC_PTR(opc);
	if (!opc)
		return -ENOMEM;

	precreate = atomic_read(&oseq->os_precreate_in_progress);
	atomic_inc(&oseq->os_refc);
	opc->opc_oseq = oseq;
	opc->opc_objects = objects;
	CDEBUG(D_OTHER, "Add %d to %d for "DFID", th_sync %d\n",
	       opc->opc_objects, precreate,
	       PFID(&oseq->os_oi.oi_fid), th->th_sync);

	if ((precreate + objects) >= (5 * OST_MAX_PRECREATE))
		th->th_sync = 1;

	dcb = &opc->opc_cb;
	dcb->dcb_func = ofd_cb_precreate;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strlcpy(dcb->dcb_name, "ofd_cb_precreate", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		ofd_seq_put(env, oseq);
		OBD_FREE_PTR(opc);
		return rc;
	}

	atomic_add(objects, &oseq->os_precreate_in_progress);

	return 0;
}

/**
 * Precreate the given number \a nr of objects in the given sequence \a oseq.
 *
 * This function precreates new OST objects in the given sequence.
 * The precreation starts from \a id and creates \a nr objects sequentially.
 *
 * Notes:
 * This function may create fewer objects than requested.
 *
 * We mark object SUID+SGID to flag it for accepting UID+GID from client on
 * first write. Currently the permission bits on the OST are never used,
 * so this is OK.
 *
 * Initialize a/c/m time so any client timestamp will always be newer and
 * update the inode. The ctime = 0 case is also handled specially in
 * osd_inode_setattr(). See LU-221, LU-1042 for details.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] id	object ID to start precreation from
 * \param[in] oseq	object sequence
 * \param[in] nr	number of objects to precreate
 * \param[in] sync	synchronous precreation flag
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_precreate_objects(const struct lu_env *env, struct ofd_device *ofd,
			  u64 id, struct ofd_seq *oseq, int nr, int sync)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object	*fo = NULL;
	struct dt_object	*next;
	struct thandle		*th;
	struct ofd_object	**batch;
	struct lu_fid		*fid = &info->fti_fid;
	u64			tmp;
	int			rc;
	int			rc2;
	int			i;
	int			objects = 0;
	int			nr_saved = nr;

	ENTRY;

	/* Don't create objects beyond the valid range for this SEQ */
	if (unlikely(fid_seq_is_mdt0(ostid_seq(&oseq->os_oi)) &&
		     (id + nr) > IDIF_MAX_OID)) {
		CERROR("%s:"DOSTID" hit the IDIF_MAX_OID (1<<48)!\n",
		       ofd_name(ofd), id, ostid_seq(&oseq->os_oi));
		RETURN(rc = -ENOSPC);
	} else if (unlikely(!fid_seq_is_mdt0(ostid_seq(&oseq->os_oi)) &&
			    (id + nr) > OBIF_MAX_OID)) {
		CERROR("%s:"DOSTID" hit the OBIF_MAX_OID (1<<32)!\n",
		       ofd_name(ofd), id, ostid_seq(&oseq->os_oi));
		RETURN(rc = -ENOSPC);
	}

	OBD_ALLOC_PTR_ARRAY(batch, nr_saved);
	if (batch == NULL)
		RETURN(-ENOMEM);

	info->fti_attr.la_valid = LA_TYPE | LA_MODE;
	info->fti_attr.la_mode = S_IFREG | S_ISUID | S_ISGID | S_ISVTX | 0666;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	info->fti_attr.la_valid |= LA_ATIME | LA_MTIME | LA_CTIME;
	info->fti_attr.la_atime = 0;
	info->fti_attr.la_mtime = 0;
	info->fti_attr.la_ctime = 0;

	LASSERT(id != 0);

	/* prepare objects */
	*fid = *lu_object_fid(&oseq->os_lastid_obj->do_lu);
	for (i = 0; i < nr; i++) {
		rc = fid_set_id(fid, id + i);
		if (rc != 0) {
			if (i == 0)
				GOTO(out, rc);

			nr = i;
			break;
		}

		fo = ofd_object_find(env, ofd, fid);
		if (IS_ERR(fo)) {
			if (i == 0)
				GOTO(out, rc = PTR_ERR(fo));

			nr = i;
			break;
		}

		batch[i] = fo;
	}
	info->fti_buf.lb_buf = &tmp;
	info->fti_buf.lb_len = sizeof(tmp);
	info->fti_off = 0;

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	th->th_sync |= sync;

	rc = dt_declare_record_write(env, oseq->os_lastid_obj, &info->fti_buf,
				     info->fti_off, th);
	if (rc)
		GOTO(trans_stop, rc);

	for (i = 0; i < nr; i++) {
		fo = batch[i];
		LASSERT(fo);

		if (unlikely(ofd_object_exists(fo))) {
			/* object may exist being re-created by write replay */
			CDEBUG(D_INODE, "object %#llx/%#llx exists: "
			       DFID"\n", ostid_seq(&oseq->os_oi), id,
			       PFID(lu_object_fid(&fo->ofo_obj.do_lu)));
			continue;
		}

		next = ofd_object_child(fo);
		LASSERT(next != NULL);

		rc = dt_declare_create(env, next, &info->fti_attr, NULL,
				       &info->fti_dof, th);
		if (rc < 0) {
			if (i == 0)
				GOTO(trans_stop, rc);

			nr = i;
			break;
		}
	}

	rc = dt_trans_start_local(env, ofd->ofd_osd, th);
	if (rc)
		GOTO(trans_stop, rc);

	CDEBUG(D_OTHER, "%s: create new object "DFID" nr %d\n",
	       ofd_name(ofd), PFID(fid), nr);

	 /* When the LFSCK scanning the whole device to verify the LAST_ID file
	  * consistency, it will load the last_id into RAM firstly, and compare
	  * the last_id with each OST-object's ID. If the later one is larger,
	  * then it will regard the LAST_ID file crashed. But during the LFSCK
	  * scanning, the OFD may continue to create new OST-objects. Those new
	  * created OST-objects will have larger IDs than the LFSCK known ones.
	  * So from the LFSCK view, it needs to re-load the last_id from disk
	  * file, and if the latest last_id is still smaller than the object's
	  * ID, then the LAST_ID file is real crashed.
	  *
	  * To make above mechanism to work, before OFD pre-create OST-objects,
	  * it needs to update the LAST_ID file firstly, otherwise, the LFSCK
	  * may cannot get latest last_id although new OST-object created. */
	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_SKIP_LASTID)) {
		tmp = cpu_to_le64(id + nr - 1);
		dt_write_lock(env, oseq->os_lastid_obj, DT_LASTID);
		rc = dt_record_write(env, oseq->os_lastid_obj,
				     &info->fti_buf, &info->fti_off, th);
		dt_write_unlock(env, oseq->os_lastid_obj);
		if (rc != 0)
			GOTO(trans_stop, rc);
	}

	for (i = 0; i < nr; i++) {
		fo = batch[i];
		LASSERT(fo);

		ofd_write_lock(env, fo);

		/* Only the new created objects need to be recorded. */
		if (ofd->ofd_osd->dd_record_fid_accessed) {
			struct lfsck_req_local *lrl = &ofd_info(env)->fti_lrl;

			lfsck_pack_rfa(lrl, lu_object_fid(&fo->ofo_obj.do_lu),
				       LEL_FID_ACCESSED, LFSCK_TYPE_LAYOUT);
			lfsck_in_notify_local(env, ofd->ofd_osd, lrl, NULL);
		}

		if (likely(!ofd_object_exists(fo) &&
			   !OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING))) {
			next = ofd_object_child(fo);
			LASSERT(next != NULL);

			rc = dt_create(env, next, &info->fti_attr, NULL,
				       &info->fti_dof, th);
			ofd_write_unlock(env, fo);
			if (rc < 0) {
				if (i == 0)
					GOTO(trans_stop, rc);

				rc = 0;
				break;
			}
			LASSERT(ofd_object_exists(fo));
		} else {
			ofd_write_unlock(env, fo);
		}

		ofd_seq_last_oid_set(oseq, id + i);
	}

	objects = i;
	/* NOT all the wanted objects have been created,
	 * set the LAST_ID as the real created. */
	if (unlikely(objects < nr)) {
		int rc1;

		info->fti_off = 0;
		tmp = cpu_to_le64(ofd_seq_last_oid(oseq));
		dt_write_lock(env, oseq->os_lastid_obj, DT_LASTID);
		rc1 = dt_record_write(env, oseq->os_lastid_obj,
				      &info->fti_buf, &info->fti_off, th);
		dt_write_unlock(env, oseq->os_lastid_obj);
		if (rc1 != 0)
			CERROR("%s: fail to reset the LAST_ID for seq (%#llx"
			       ") from %llu to %llu\n", ofd_name(ofd),
			       ostid_seq(&oseq->os_oi), id + nr - 1,
			       ofd_seq_last_oid(oseq));
	}

	if (objects)
		ofd_precreate_cb_add(env, th, oseq, objects);
trans_stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2)
		CERROR("%s: failed to stop transaction: rc = %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	for (i = 0; i < nr_saved; i++) {
		fo = batch[i];
		if (!fo)
			continue;
		ofd_object_put(env, fo);
	}
	OBD_FREE_PTR_ARRAY(batch, nr_saved);

	CDEBUG((objects == 0 && rc == 0) ? D_ERROR : D_OTHER,
	       "created %d/%d objects: %d\n", objects, nr_saved, rc);

	LASSERT(ergo(objects == 0, rc < 0));
	RETURN(objects > 0 ? objects : rc);
}

/**
 * Fix the OFD object ownership.
 *
 * If the object still has SUID+SGID bits set, meaning that it was precreated
 * by the MDT before it was assigned to any file, (see ofd_precreate_objects())
 * then we will accept the UID/GID/PROJID if sent by the client for initializing
 * the ownership of this object.  We only allow this to happen once (so clear
 * these bits) and later only allow setattr.
 *
 * \param[in] env	 execution environment
 * \param[in] fo	 OFD object
 * \param[in] la	 object attributes
 * \param[in] is_setattr was this function called from setattr or not
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_attr_handle_id(const struct lu_env *env, struct ofd_object *fo,
			 struct lu_attr *la, int is_setattr)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct lu_attr		*ln = &info->fti_attr2;
	__u32			 mask = 0;
	int			 rc;

	ENTRY;

	if (!(la->la_valid & LA_UID) && !(la->la_valid & LA_GID) &&
	    !(la->la_valid & LA_PROJID))
		RETURN(0);

	rc = dt_attr_get(env, ofd_object_child(fo), ln);
	if (rc != 0)
		RETURN(rc);

	LASSERT(ln->la_valid & LA_MODE);

	/*
	 * Only allow setattr to change UID/GID/PROJID, if
	 * SUID+SGID is not set which means this is not
	 * initialization of this objects.
	 */
	if (!is_setattr) {
		if (!(ln->la_mode & S_ISUID))
			la->la_valid &= ~LA_UID;
		if (!(ln->la_mode & S_ISGID))
			la->la_valid &= ~LA_GID;
		if (!(ln->la_mode & S_ISVTX))
			la->la_valid &= ~LA_PROJID;
	}

	/* Initialize ownership of this object, clear SUID+SGID bits*/
	if ((la->la_valid & LA_UID) && (ln->la_mode & S_ISUID))
		mask |= S_ISUID;
	if ((la->la_valid & LA_GID) && (ln->la_mode & S_ISGID))
		mask |= S_ISGID;
	if ((la->la_valid & LA_PROJID) && (ln->la_mode & S_ISVTX))
		mask |= S_ISVTX;
	if (mask != 0) {
		if (!(la->la_valid & LA_MODE) || !is_setattr) {
			la->la_mode = ln->la_mode;
			la->la_valid |= LA_MODE;
		}
		la->la_mode &= ~mask;
	}

	RETURN(0);
}

/**
 * Check if it needs to update filter_fid by the value of @oa.
 *
 * \param[in] env	env
 * \param[in] fo	ofd object
 * \param[in] oa	obdo from client or MDT
 * \param[out] ff	if filter_fid needs updating, this field is used to
 *			return the new buffer
 *
 * \retval < 0		error occurred
 * \retval 0		doesn't need to update filter_fid
 * \retval FL_XATTR_{CREATE,REPLACE}	flag for xattr update
 */
int ofd_object_ff_update(const struct lu_env *env, struct ofd_object *fo,
			 const struct obdo *oa, struct filter_fid *ff)
{
	int rc = 0;
	ENTRY;

	if (!(oa->o_valid &
	      (OBD_MD_FLFID | OBD_MD_FLOSTLAYOUT | OBD_MD_LAYOUT_VERSION)))
		RETURN(0);

	rc = ofd_object_ff_load(env, fo);
	if (rc < 0 && rc != -ENODATA)
		RETURN(rc);

	LASSERT(ff != &fo->ofo_ff);
	if (rc == -ENODATA) {
		rc = LU_XATTR_CREATE;
		memset(ff, 0, sizeof(*ff));
	} else {
		rc = LU_XATTR_REPLACE;
		memcpy(ff, &fo->ofo_ff, sizeof(*ff));
	}

	if (oa->o_valid & OBD_MD_FLFID) {
		/* packing fid and converting it to LE for storing into EA.
		 * Here ->o_stripe_idx should be filled by LOV and rest of
		 * fields - by client. */
		ff->ff_parent.f_seq = oa->o_parent_seq;
		ff->ff_parent.f_oid = oa->o_parent_oid;
		/* XXX: we are ignoring o_parent_ver here, since this should
		 *      be the same for all objects in this fileset. */
		ff->ff_parent.f_ver = oa->o_stripe_idx;
	}
	if (oa->o_valid & OBD_MD_FLOSTLAYOUT)
		ff->ff_layout = oa->o_layout;

	if (oa->o_valid & OBD_MD_LAYOUT_VERSION) {
		CDEBUG(D_INODE, DFID": OST("DFID") layout version %u -> %u\n",
		       PFID(&fo->ofo_ff.ff_parent),
		       PFID(lu_object_fid(&fo->ofo_obj.do_lu)),
		       ff->ff_layout_version, oa->o_layout_version);

		/* only the MDS has the authority to update layout version */
		if (!(exp_connect_flags(ofd_info(env)->fti_exp) &
		      OBD_CONNECT_MDS)) {
			CERROR(DFID": update layout version from client\n",
			       PFID(&fo->ofo_ff.ff_parent));

			RETURN(-EPERM);
		}

		if (ff->ff_layout_version & LU_LAYOUT_RESYNC) {
			/* this opens a new era of writing */
			ff->ff_layout_version = 0;
			ff->ff_range = 0;
		}

		/* it's not allowed to change it to a smaller value */
		if (oa->o_layout_version < ff->ff_layout_version)
			RETURN(-EINVAL);

		if (ff->ff_layout_version == 0 ||
		    oa->o_layout_version & LU_LAYOUT_RESYNC) {
			/* if LU_LAYOUT_RESYNC is set, it closes the era of
			 * writing. Only mirror I/O can write this object. */
			ff->ff_layout_version = oa->o_layout_version;
			ff->ff_range = 0;
		} else if (oa->o_layout_version > ff->ff_layout_version) {
			ff->ff_range = max_t(__u32, ff->ff_range,
					     oa->o_layout_version -
					     ff->ff_layout_version);
		}
	}

	if (memcmp(ff, &fo->ofo_ff, sizeof(*ff)))
		filter_fid_cpu_to_le(ff, ff, sizeof(*ff));
	else /* no change */
		rc = 0;

	RETURN(rc);
}

/**
 * Set OFD object attributes.
 *
 * This function sets OFD object attributes taken from incoming request.
 * It sets not only regular attributes but also XATTR_NAME_FID extended
 * attribute if needed. The "fid" xattr allows the object's MDT parent inode
 * to be found and verified by LFSCK and other tools in case of inconsistency.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] la	object attributes
 * \param[in] oa	obdo carries fid, ost_layout, layout version
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_attr_set(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la, struct obdo *oa)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_obj2dev(fo);
	struct filter_fid *ff = &info->fti_mds_fid;
	struct thandle *th;
	int fl, rc, rc2;

	ENTRY;

	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc)
		GOTO(out, rc);

	rc = ofd_attr_handle_id(env, fo, la, 1 /* is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_attr_set(env, ofd_object_child(fo), la, th);
	if (rc)
		GOTO(stop, rc);

	info->fti_buf.lb_buf = ff;
	info->fti_buf.lb_len = sizeof(*ff);
	rc = dt_declare_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, 0, th);
	if (rc)
		GOTO(stop, rc);

	rc = ofd_trans_start(env, ofd, la->la_valid & LA_SIZE ? fo : NULL, th);
	if (rc)
		GOTO(stop, rc);

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	/* serialize vs ofd_commitrw_write() */
	if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME))
		tgt_fmd_update(info->fti_exp, &fo->ofo_header.loh_fid,
			       info->fti_xid);

	rc = dt_attr_set(env, ofd_object_child(fo), la, th);
	if (rc)
		GOTO(unlock, rc);

	fl = ofd_object_ff_update(env, fo, oa, ff);
	if (fl < 0)
		GOTO(unlock, rc = fl);

	if (fl) {
		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR1))
			ff->ff_parent.f_oid = cpu_to_le32(1UL << 31);
		else if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR2))
			le32_add_cpu(&ff->ff_parent.f_oid, -1);
		else if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NOPFID))
			GOTO(unlock, rc);

		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, fl, th);
		if (!rc)
			filter_fid_le_to_cpu(&fo->ofo_ff, ff, sizeof(*ff));
	}

	GOTO(unlock, rc);

unlock:
	ofd_write_unlock(env, fo);
stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2)
		CERROR("%s: failed to stop transaction: rc = %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	return rc;
}

/**
 * Fallocate(Preallocate) space for OFD object.
 *
 * This function allocates space for the object from the \a start
 * offset to the \a end offset.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] start	start offset to allocate from
 * \param[in] end	end of allocate
 * \param[in] mode	fallocate mode
 * \param[in] la	object attributes
 * \param[in] ff	filter_fid structure
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_object_fallocate(const struct lu_env *env, struct ofd_object *fo,
			 __u64 start, __u64 end, int mode, struct lu_attr *la,
			 struct obdo *oa)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_obj2dev(fo);
	struct dt_object *dob = ofd_object_child(fo);
	struct thandle *th;
	struct filter_fid *ff = &info->fti_mds_fid;
	bool ff_needed = false;
	int rc;

	ENTRY;

	if (!ofd_object_exists(fo))
		RETURN(-ENOENT);

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc != 0)
		RETURN(rc);

	if (ff != NULL) {
		rc = ofd_object_ff_load(env, fo);
		if (rc == -ENODATA)
			ff_needed = true;
		else if (rc < 0)
			RETURN(rc);
	}

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_attr_set(env, dob, la, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_fallocate(env, dob, start, end, mode, th);
	if (rc)
		GOTO(stop, rc);

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(stop, rc);

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME))
		tgt_fmd_update(info->fti_exp, &fo->ofo_header.loh_fid,
			       info->fti_xid);

	rc = dt_falloc(env, dob, start, end, mode, th);
	if (rc)
		GOTO(unlock, rc);

	rc = dt_attr_set(env, dob, la, th);
	if (rc)
		GOTO(unlock, rc);

	if (ff_needed) {
		rc = dt_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, 0, th);
		if (!rc)
			filter_fid_le_to_cpu(&fo->ofo_ff, ff, sizeof(*ff));
	}
unlock:
	ofd_write_unlock(env, fo);
stop:
	ofd_trans_stop(env, ofd, th, rc);
	RETURN(rc);
}

/**
 * Truncate/punch OFD object.
 *
 * This function frees all of the allocated object's space from the \a start
 * offset to the \a end offset. For truncate() operations the \a end offset
 * is OBD_OBJECT_EOF. The functionality to punch holes in an object via
 * fallocate(FALLOC_FL_PUNCH_HOLE) is not yet implemented (see LU-3606).
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] start	start offset to punch from
 * \param[in] end	end of punch
 * \param[in] la	object attributes
 * \param[in] oa	obdo struct from incoming request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_object_punch(const struct lu_env *env, struct ofd_object *fo,
		     __u64 start, __u64 end, struct lu_attr *la,
		     struct obdo *oa)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_obj2dev(fo);
	struct dt_object *dob = ofd_object_child(fo);
	struct filter_fid *ff = &info->fti_mds_fid;
	struct thandle *th;
	int fl, rc, rc2;

	ENTRY;

	/* we support truncate, not punch yet */
	LASSERT(end == OBD_OBJECT_EOF);

	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

	if (ofd->ofd_lfsck_verify_pfid && oa->o_valid & OBD_MD_FLFID) {
		rc = ofd_verify_ff(env, fo, oa);
		if (rc != 0)
			GOTO(out, rc);
	}

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc)
		GOTO(out, rc);

	rc = ofd_attr_handle_id(env, fo, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_attr_set(env, dob, la, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(stop, rc);

	info->fti_buf.lb_buf = ff;
	info->fti_buf.lb_len = sizeof(*ff);
	rc = dt_declare_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, 0, th);
	if (rc)
		GOTO(stop, rc);

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(stop, rc);

	ofd_write_lock(env, fo);

	if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME))
		tgt_fmd_update(info->fti_exp, &fo->ofo_header.loh_fid,
			       info->fti_xid);

	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	/* need to verify layout version */
	if (oa->o_valid & OBD_MD_LAYOUT_VERSION) {
		rc = ofd_verify_layout_version(env, fo, oa);
		if (rc)
			GOTO(unlock, rc);

		oa->o_valid &= ~OBD_MD_LAYOUT_VERSION;
	}

	if (oa->o_valid & OBD_MD_FLFLAGS && oa->o_flags & LUSTRE_ENCRYPT_FL) {
		/* punch must be aware we are dealing with an encrypted file */
		struct lu_attr la = {
			.la_valid = LA_FLAGS,
			.la_flags = LUSTRE_ENCRYPT_FL,
		};

		rc = dt_attr_set(env, dob, &la, th);
		if (rc)
			GOTO(unlock, rc);
	}
	rc = dt_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(unlock, rc);

	fl = ofd_object_ff_update(env, fo, oa, ff);
	if (fl < 0)
		GOTO(unlock, rc = fl);

	rc = dt_attr_set(env, dob, la, th);
	if (rc)
		GOTO(unlock, rc);

	if (fl) {
		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR1))
			ff->ff_parent.f_oid = cpu_to_le32(1UL << 31);
		else if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR2))
			le32_add_cpu(&ff->ff_parent.f_oid, -1);
		else if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NOPFID))
			GOTO(unlock, rc);

		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, fl, th);
		if (!rc)
			filter_fid_le_to_cpu(&fo->ofo_ff, ff, sizeof(*ff));
	}

	GOTO(unlock, rc);

unlock:
	ofd_write_unlock(env, fo);
stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2 != 0)
		CERROR("%s: failed to stop transaction: rc = %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	return rc;
}

/**
 * Destroy OFD object.
 *
 * This function destroys OFD object. If object wasn't used at all (orphan)
 * then local transaction is used, which means the transaction data is not
 * returned back in reply.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] orphan	flag to indicate that object is orphaned
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_destroy(const struct lu_env *env, struct ofd_object *fo,
		       int orphan)
{
	struct ofd_device	*ofd = ofd_obj2dev(fo);
	struct thandle		*th;
	int			rc = 0;
	int			rc2;

	ENTRY;

	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_ref_del(env, ofd_object_child(fo), th);
	if (rc < 0)
		GOTO(stop, rc);

	rc = dt_declare_destroy(env, ofd_object_child(fo), th);
	if (rc < 0)
		GOTO(stop, rc);

	if (orphan)
		rc = dt_trans_start_local(env, ofd->ofd_osd, th);
	else
		rc = ofd_trans_start(env, ofd, NULL, th);
	if (rc)
		GOTO(stop, rc);

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	tgt_fmd_drop(ofd_info(env)->fti_exp, &fo->ofo_header.loh_fid);

	dt_ref_del(env, ofd_object_child(fo), th);
	dt_destroy(env, ofd_object_child(fo), th);
unlock:
	ofd_write_unlock(env, fo);
stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2)
		CERROR("%s failed to stop transaction: %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	RETURN(rc);
}

/**
 * Get OFD object attributes.
 *
 * This function gets OFD object regular attributes. It is used to serve
 * incoming request as well as for local OFD purposes.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] la	object attributes
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_attr_get(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la)
{
	int rc = 0;

	ENTRY;

	if (ofd_object_exists(fo)) {
		rc = dt_attr_get(env, ofd_object_child(fo), la);
	} else {
		rc = -ENOENT;
	}
	RETURN(rc);
}
