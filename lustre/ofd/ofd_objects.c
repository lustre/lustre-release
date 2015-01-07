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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_objects.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <dt_object.h>
#include <lustre/lustre_idl.h>

#include "ofd_internal.h"

int ofd_version_get_check(struct ofd_thread_info *info,
			  struct ofd_object *fo)
{
	dt_obj_version_t curr_version;

	LASSERT(ofd_object_exists(fo));
	LASSERT(info->fti_exp);

	curr_version = dt_version_get(info->fti_env, ofd_object_child(fo));
	if ((__s64)curr_version == -EOPNOTSUPP)
		RETURN(0);
	/* VBR: version is checked always because costs nothing */
	if (info->fti_pre_version != 0 &&
	    info->fti_pre_version != curr_version) {
		CDEBUG(D_INODE, "Version mismatch "LPX64" != "LPX64"\n",
		       info->fti_pre_version, curr_version);
		spin_lock(&info->fti_exp->exp_lock);
		info->fti_exp->exp_vbr_failed = 1;
		spin_unlock(&info->fti_exp->exp_lock);
		RETURN (-EOVERFLOW);
	}
	info->fti_pre_version = curr_version;
	RETURN(0);
}

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

struct ofd_object *ofd_object_find_or_create(const struct lu_env *env,
					     struct ofd_device *ofd,
					     const struct lu_fid *fid,
					     struct lu_attr *attr)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct lu_object	*fo_obj;
	struct dt_object	*dto;

	ENTRY;

	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	dto = dt_find_or_create(env, ofd->ofd_osd, fid, &info->fti_dof, attr);
	if (IS_ERR(dto))
		RETURN(ERR_CAST(dto));

	fo_obj = lu_object_locate(dto->do_lu.lo_header,
				  ofd->ofd_dt_dev.dd_lu_dev.ld_type);
	RETURN(ofd_obj(fo_obj));
}

int ofd_object_ff_check(const struct lu_env *env, struct ofd_object *fo)
{
	int rc = 0;

	ENTRY;

	if (!fo->ofo_ff_exists) {
		/*
		 * This actually means that we don't know whether the object
		 * has the "fid" EA or not.
		 */
		rc = dt_xattr_get(env, ofd_object_child(fo), &LU_BUF_NULL,
				  XATTR_NAME_FID, BYPASS_CAPA);
		if (rc >= 0 || rc == -ENODATA) {
			/*
			 * Here we assume that, if the object doesn't have the
			 * "fid" EA, the caller will add one, unless a fatal
			 * error (e.g., a memory or disk failure) prevents it
			 * from doing so.
			 */
			fo->ofo_ff_exists = 1;
		}
		if (rc > 0)
			rc = 0;
	}
	RETURN(rc);
}

void ofd_object_put(const struct lu_env *env, struct ofd_object *fo)
{
	lu_object_put(env, &fo->ofo_obj.do_lu);
}

int ofd_precreate_objects(const struct lu_env *env, struct ofd_device *ofd,
			  obd_id id, struct ofd_seq *oseq, int nr, int sync)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object	*fo = NULL;
	struct dt_object	*next;
	struct thandle		*th;
	struct ofd_object	**batch;
	obd_id			 tmp;
	int			 rc;
	int			 i;
	int			 objects = 0;
	int			 nr_saved = nr;

	ENTRY;

	/* Don't create objects beyond the valid range for this SEQ */
	if (unlikely(fid_seq_is_mdt0(ostid_seq(&oseq->os_oi)) &&
		     (id + nr) >= IDIF_MAX_OID)) {
		CERROR("%s:"DOSTID" hit the IDIF_MAX_OID (1<<48)!\n",
		       ofd_name(ofd), id, ostid_seq(&oseq->os_oi));
		RETURN(rc = -ENOSPC);
	} else if (unlikely(!fid_seq_is_mdt0(ostid_seq(&oseq->os_oi)) &&
			    (id + nr) >= OBIF_MAX_OID)) {
		CERROR("%s:"DOSTID" hit the OBIF_MAX_OID (1<<32)!\n",
		       ofd_name(ofd), id, ostid_seq(&oseq->os_oi));
		RETURN(rc = -ENOSPC);
	}

	OBD_ALLOC(batch, nr_saved * sizeof(struct ofd_object *));
	if (batch == NULL)
		RETURN(-ENOMEM);

	info->fti_attr.la_valid = LA_TYPE | LA_MODE;
	/*
	 * We mark object SUID+SGID to flag it for accepting UID+GID from
	 * client on first write.  Currently the permission bits on the OST are
	 * never used, so this is OK.
	 */
	info->fti_attr.la_mode = S_IFREG | S_ISUID | S_ISGID | 0666;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	/* Initialize a/c/m time so any client timestamp will always
	 * be newer and update the inode. ctime = 0 is also handled
	 * specially in osd_inode_setattr(). See LU-221, LU-1042 */
	info->fti_attr.la_valid |= LA_ATIME | LA_MTIME | LA_CTIME;
	info->fti_attr.la_atime = 0;
	info->fti_attr.la_mtime = 0;
	info->fti_attr.la_ctime = 0;

	/* prepare objects */
	ostid_set_seq(&info->fti_ostid, ostid_seq(&oseq->os_oi));
	for (i = 0; i < nr; i++) {
		ostid_set_id(&info->fti_ostid, id + i);
		rc = ostid_to_fid(&info->fti_fid, &info->fti_ostid, 0);
		if (rc) {
			if (i == 0)
				GOTO(out, rc);

			nr = i;
			break;
		}

		fo = ofd_object_find(env, ofd, &info->fti_fid);
		if (IS_ERR(fo)) {
			if (i == 0)
				GOTO(out, rc = PTR_ERR(fo));

			nr = i;
			break;
		}

		ofd_write_lock(env, fo);
		batch[i] = fo;
	}
	info->fti_buf.lb_buf = &tmp;
	info->fti_buf.lb_len = sizeof(tmp);
	info->fti_off = 0;

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	th->th_sync |= sync;

	rc = dt_declare_record_write(env, oseq->os_lastid_obj, sizeof(tmp),
				     info->fti_off, th);
	if (rc)
		GOTO(trans_stop, rc);

	for (i = 0; i < nr; i++) {
		fo = batch[i];
		LASSERT(fo);

		if (unlikely(ofd_object_exists(fo))) {
			/* object may exist being re-created by write replay */
			CDEBUG(D_INODE, "object "LPX64"/"LPX64" exists: "
			       DFID"\n", ostid_seq(&oseq->os_oi), id,
			       PFID(&info->fti_fid));
			continue;
		}

		next = ofd_object_child(fo);
		LASSERT(next != NULL);

		rc = dt_declare_create(env, next, &info->fti_attr, NULL,
				       &info->fti_dof, th);
		if (rc) {
			nr = i;
			break;
		}
	}

	rc = dt_trans_start_local(env, ofd->ofd_osd, th);
	if (rc)
		GOTO(trans_stop, rc);

	CDEBUG(D_OTHER, "%s: create new object "DFID" nr %d\n",
	       ofd_name(ofd), PFID(&info->fti_fid), nr);

	for (i = 0; i < nr; i++) {
		fo = batch[i];
		LASSERT(fo);

		if (likely(!ofd_object_exists(fo))) {
			next = ofd_object_child(fo);
			LASSERT(next != NULL);

			rc = dt_create(env, next, &info->fti_attr, NULL,
				       &info->fti_dof, th);
			if (rc)
				break;
			LASSERT(ofd_object_exists(fo));
		}
		ofd_seq_last_oid_set(oseq, id + i);
	}

	objects = i;
	if (objects > 0) {
		tmp = cpu_to_le64(ofd_seq_last_oid(oseq));
		rc = dt_record_write(env, oseq->os_lastid_obj,
				     &info->fti_buf, &info->fti_off, th);
	}
trans_stop:
	ofd_trans_stop(env, ofd, th, rc);
out:
	for (i = 0; i < nr_saved; i++) {
		fo = batch[i];
		if (fo) {
			ofd_write_unlock(env, fo);
			ofd_object_put(env, fo);
		}
	}
	OBD_FREE(batch, nr_saved * sizeof(struct ofd_object *));

	CDEBUG((objects == 0 && rc == 0) ? D_ERROR : D_OTHER,
	       "created %d/%d objects: %d\n", objects, nr_saved, rc);

	LASSERT(ergo(objects == 0, rc < 0));
	RETURN(objects > 0 ? objects : rc);
}

/*
 * If the object still has SUID+SGID bits set (see ofd_precreate_object()) then
 * we will accept the UID+GID if sent by the client for initializing the
 * ownership of this object.  We only allow this to happen once (so clear these
 * bits) and later only allow setattr.
 */
int ofd_attr_handle_ugid(const struct lu_env *env, struct ofd_object *fo,
			 struct lu_attr *la, int is_setattr)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct lu_attr		*ln = &info->fti_attr2;
	__u32			 mask = 0;
	int			 rc;

	ENTRY;

	if (!(la->la_valid & LA_UID) && !(la->la_valid & LA_GID))
		RETURN(0);

	rc = dt_attr_get(env, ofd_object_child(fo), ln, BYPASS_CAPA);
	if (rc != 0)
		RETURN(rc);

	LASSERT(ln->la_valid & LA_MODE);

	if (!is_setattr) {
		if (!(ln->la_mode & S_ISUID))
			la->la_valid &= ~LA_UID;
		if (!(ln->la_mode & S_ISGID))
			la->la_valid &= ~LA_GID;
	}

	if ((la->la_valid & LA_UID) && (ln->la_mode & S_ISUID))
		mask |= S_ISUID;
	if ((la->la_valid & LA_GID) && (ln->la_mode & S_ISGID))
		mask |= S_ISGID;
	if (mask != 0) {
		if (!(la->la_valid & LA_MODE) || !is_setattr) {
			la->la_mode = ln->la_mode;
			la->la_valid |= LA_MODE;
		}
		la->la_mode &= ~mask;
	}

	RETURN(0);
}

int ofd_attr_set(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la, struct filter_fid *ff)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_device	*ofd = ofd_obj2dev(fo);
	struct thandle		*th;
	struct ofd_mod_data	*fmd;
	int			 ff_needed = 0;
	int			 rc;
	ENTRY;

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME)) {
		fmd = ofd_fmd_get(info->fti_exp, &fo->ofo_header.loh_fid);
		if (fmd && fmd->fmd_mactime_xid < info->fti_xid)
			fmd->fmd_mactime_xid = info->fti_xid;
		ofd_fmd_put(info->fti_exp, fmd);
	}

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc)
		GOTO(unlock, rc);

	rc = ofd_attr_handle_ugid(env, fo, la, 1 /* is_setattr */);
	if (rc != 0)
		GOTO(unlock, rc);

	if (ff != NULL) {
		rc = ofd_object_ff_check(env, fo);
		if (rc == -ENODATA)
			ff_needed = 1;
		else if (rc < 0)
			GOTO(unlock, rc);
	}

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_attr_set(env, ofd_object_child(fo), la, th);
	if (rc)
		GOTO(stop, rc);

	if (ff_needed) {
		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_declare_xattr_set(env, ofd_object_child(fo),
					  &info->fti_buf, XATTR_NAME_FID, 0,
					  th);
		if (rc)
			GOTO(stop, rc);
	}

	rc = ofd_trans_start(env, ofd, la->la_valid & LA_SIZE ? fo : NULL, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_attr_set(env, ofd_object_child(fo), la, th,
			 ofd_object_capa(env, fo));
	if (rc)
		GOTO(stop, rc);

	if (ff_needed)
		rc = dt_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, 0, th, BYPASS_CAPA);

stop:
	ofd_trans_stop(env, ofd, th, rc);
unlock:
	ofd_write_unlock(env, fo);
	RETURN(rc);
}

int ofd_object_punch(const struct lu_env *env, struct ofd_object *fo,
		     __u64 start, __u64 end, struct lu_attr *la,
		     struct filter_fid *ff)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_device	*ofd = ofd_obj2dev(fo);
	struct ofd_mod_data	*fmd;
	struct dt_object	*dob = ofd_object_child(fo);
	struct thandle		*th;
	int			 ff_needed = 0;
	int			 rc;

	ENTRY;

	/* we support truncate, not punch yet */
	LASSERT(end == OBD_OBJECT_EOF);

	ofd_write_lock(env, fo);
	fmd = ofd_fmd_get(info->fti_exp, &fo->ofo_header.loh_fid);
	if (fmd && fmd->fmd_mactime_xid < info->fti_xid)
		fmd->fmd_mactime_xid = info->fti_xid;
	ofd_fmd_put(info->fti_exp, fmd);

	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc)
		GOTO(unlock, rc);

	rc = ofd_attr_handle_ugid(env, fo, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(unlock, rc);

	if (ff != NULL) {
		rc = ofd_object_ff_check(env, fo);
		if (rc == -ENODATA)
			ff_needed = 1;
		else if (rc < 0)
			GOTO(unlock, rc);
	}

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_attr_set(env, dob, la, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(stop, rc);

	if (ff_needed) {
		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_declare_xattr_set(env, ofd_object_child(fo),
					  &info->fti_buf, XATTR_NAME_FID, 0,
					  th);
		if (rc)
			GOTO(stop, rc);
	}

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_punch(env, dob, start, OBD_OBJECT_EOF, th,
		      ofd_object_capa(env, fo));
	if (rc)
		GOTO(stop, rc);

	rc = dt_attr_set(env, dob, la, th, ofd_object_capa(env, fo));
	if (rc)
		GOTO(stop, rc);

	if (ff_needed)
		rc = dt_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, 0, th, BYPASS_CAPA);

stop:
	ofd_trans_stop(env, ofd, th, rc);
unlock:
	ofd_write_unlock(env, fo);
	RETURN(rc);
}

int ofd_object_destroy(const struct lu_env *env, struct ofd_object *fo,
		       int orphan)
{
	struct ofd_device	*ofd = ofd_obj2dev(fo);
	struct thandle		*th;
	int			 rc = 0;

	ENTRY;

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	dt_declare_ref_del(env, ofd_object_child(fo), th);
	dt_declare_destroy(env, ofd_object_child(fo), th);
	if (orphan)
		rc = dt_trans_start_local(env, ofd->ofd_osd, th);
	else
		rc = ofd_trans_start(env, ofd, NULL, th);
	if (rc)
		GOTO(stop, rc);

	ofd_fmd_drop(ofd_info(env)->fti_exp, &fo->ofo_header.loh_fid);

	dt_ref_del(env, ofd_object_child(fo), th);
	dt_destroy(env, ofd_object_child(fo), th);
stop:
	ofd_trans_stop(env, ofd, th, rc);
unlock:
	ofd_write_unlock(env, fo);
	RETURN(rc);
}

int ofd_attr_get(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la)
{
	int rc = 0;

	ENTRY;

	if (ofd_object_exists(fo)) {
		rc = dt_attr_get(env, ofd_object_child(fo), la,
				 ofd_object_capa(env, fo));

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 7, 50, 0)
		/* Try to correct for a bug in 2.1.0 (LU-221) that caused
		 * negative timestamps to appear to be in the far future,
		 * due old timestamp being stored on disk as an unsigned value.
		 * This fixes up any bad values stored on disk before
		 * returning them to the client, and ensures any timestamp
		 * updates are correct.  LU-1042 */
		if (unlikely(la->la_atime == LU221_BAD_TIME))
			la->la_atime = 0;
		if (unlikely(la->la_mtime == LU221_BAD_TIME))
			la->la_mtime = 0;
		if (unlikely(la->la_ctime == LU221_BAD_TIME))
			la->la_ctime = 0;
#else
#warning "remove old LU-221/LU-1042 workaround code"
#endif
	} else {
		rc = -ENOENT;
	}
	RETURN(rc);
}
