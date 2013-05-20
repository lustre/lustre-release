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
 * lustre/ofd/ofd_io.c
 *
 * Author: Alex Tomas <bzzz@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

static int ofd_preprw_read(const struct lu_env *env, struct obd_export *exp,
			   struct ofd_device *ofd, struct lu_fid *fid,
			   struct lu_attr *la, int niocount,
			   struct niobuf_remote *rnb, int *nr_local,
			   struct niobuf_local *lnb,
			   struct obd_trans_info *oti)
{
	struct ofd_object	*fo;
	int			 i, j, rc, tot_bytes = 0;

	ENTRY;
	LASSERT(env != NULL);

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	LASSERT(fo != NULL);

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	/* parse remote buffers to local buffers and prepare the latter */
	*nr_local = 0;
	for (i = 0, j = 0; i < niocount; i++) {
		rc = dt_bufs_get(env, ofd_object_child(fo), rnb + i,
				 lnb + j, 0, ofd_object_capa(env, fo));
		if (unlikely(rc < 0))
			GOTO(buf_put, rc);
		LASSERT(rc <= PTLRPC_MAX_BRW_PAGES);
		/* correct index for local buffers to continue with */
		j += rc;
		*nr_local += rc;
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}

	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);
	rc = dt_attr_get(env, ofd_object_child(fo), la,
			 ofd_object_capa(env, fo));
	if (unlikely(rc))
		GOTO(buf_put, rc);

	rc = dt_read_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc))
		GOTO(buf_put, rc);
	lprocfs_counter_add(ofd_obd(ofd)->obd_stats,
			    LPROC_OFD_READ_BYTES, tot_bytes);
	ofd_counter_incr(exp, LPROC_OFD_STATS_READ,
			 oti->oti_jobid, tot_bytes);
	RETURN(0);

buf_put:
	dt_bufs_put(env, ofd_object_child(fo), lnb, *nr_local);
unlock:
	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	return rc;
}

static int ofd_preprw_write(const struct lu_env *env, struct obd_export *exp,
			    struct ofd_device *ofd, struct lu_fid *fid,
			    struct lu_attr *la, struct obdo *oa,
			    int objcount, struct obd_ioobj *obj,
			    struct niobuf_remote *rnb, int *nr_local,
			    struct niobuf_local *lnb,
			    struct obd_trans_info *oti)
{
	struct ofd_object	*fo;
	int			 i, j, k, rc = 0, tot_bytes = 0;

	ENTRY;
	LASSERT(env != NULL);
	LASSERT(objcount == 1);

	if (unlikely(exp->exp_obd->obd_recovering)) {
		struct ofd_thread_info *info = ofd_info(env);

		/* copied from ofd_precreate_object */
		/* XXX this should be consolidated to use the same code
		 *     instead of a copy, due to the ongoing risk of bugs. */
		memset(&info->fti_attr, 0, sizeof(info->fti_attr));
		info->fti_attr.la_valid = LA_TYPE | LA_MODE;
		info->fti_attr.la_mode = S_IFREG | S_ISUID | S_ISGID | 0666;
		info->fti_attr.la_valid |= LA_ATIME | LA_MTIME | LA_CTIME;
		/* Initialize a/c/m time so any client timestamp will always
		 * be newer and update the inode. ctime = 0 is also handled
		 * specially in osd_inode_setattr().  See LU-221, LU-1042 */
		info->fti_attr.la_atime = 0;
		info->fti_attr.la_mtime = 0;
		info->fti_attr.la_ctime = 0;

		fo = ofd_object_find_or_create(env, ofd, fid, &info->fti_attr);
	} else {
		fo = ofd_object_find(env, ofd, fid);
	}

	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));
	LASSERT(fo != NULL);

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo)) {
		CERROR("%s: BRW to missing obj "DOSTID"\n",
		       exp->exp_obd->obd_name, POSTID(&obj->ioo_oid));
		ofd_read_unlock(env, fo);
		ofd_object_put(env, fo);
		GOTO(out, rc = -ENOENT);
	}

	/* Always sync if syncjournal parameter is set */
	oti->oti_sync_write = ofd->ofd_syncjournal;

	/* Process incoming grant info, set OBD_BRW_GRANTED flag and grant some
	 * space back if possible */
	ofd_grant_prepare_write(env, exp, oa, rnb, obj->ioo_bufcnt);

	/* parse remote buffers to local buffers and prepare the latter */
	*nr_local = 0;
	for (i = 0, j = 0; i < obj->ioo_bufcnt; i++) {
		rc = dt_bufs_get(env, ofd_object_child(fo),
				 rnb + i, lnb + j, 1,
				 ofd_object_capa(env, fo));
		if (unlikely(rc < 0))
			GOTO(err, rc);
		LASSERT(rc <= PTLRPC_MAX_BRW_PAGES);
		/* correct index for local buffers to continue with */
		for (k = 0; k < rc; k++) {
			lnb[j+k].lnb_flags = rnb[i].rnb_flags;
			if (!(rnb[i].rnb_flags & OBD_BRW_GRANTED))
				lnb[j+k].lnb_rc = -ENOSPC;
			if (!(rnb[i].rnb_flags & OBD_BRW_ASYNC))
				oti->oti_sync_write = 1;
			/* remote client can't break through quota */
			if (exp_connect_rmtclient(exp))
				lnb[j+k].lnb_flags &= ~OBD_BRW_NOQUOTA;
		}
		j += rc;
		*nr_local += rc;
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}
	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);

	rc = dt_write_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc != 0))
		GOTO(err, rc);

	lprocfs_counter_add(ofd_obd(ofd)->obd_stats,
			    LPROC_OFD_WRITE_BYTES, tot_bytes);
	ofd_counter_incr(exp, LPROC_OFD_STATS_WRITE,
			 oti->oti_jobid, tot_bytes);
	RETURN(0);
err:
	dt_bufs_put(env, ofd_object_child(fo), lnb, *nr_local);
	ofd_read_unlock(env, fo);
	/* ofd_grant_prepare_write() was called, so we must commit */
	ofd_grant_commit(env, exp, rc);
out:
	/* let's still process incoming grant information packed in the oa,
	 * but without enforcing grant since we won't proceed with the write.
	 * Just like a read request actually. */
	ofd_grant_prepare_read(env, exp, oa);
	return rc;
}

int ofd_preprw(const struct lu_env* env, int cmd, struct obd_export *exp,
	       struct obdo *oa, int objcount, struct obd_ioobj *obj,
	       struct niobuf_remote *rnb, int *nr_local,
	       struct niobuf_local *lnb, struct obd_trans_info *oti,
	       struct lustre_capa *capa)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	int			 rc = 0;

	if (*nr_local > PTLRPC_MAX_BRW_PAGES) {
		CERROR("%s: bulk has too many pages %d, which exceeds the"
		       "maximum pages per RPC of %d\n",
		       exp->exp_obd->obd_name, *nr_local, PTLRPC_MAX_BRW_PAGES);
		RETURN(-EPROTO);
	}

	rc = lu_env_refill((struct lu_env *)env);
	LASSERT(rc == 0);
	info = ofd_info_init(env, exp);

	LASSERT(oa != NULL);

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT)) {
		struct ofd_seq		*oseq;
		oseq = ofd_seq_load(env, ofd, ostid_seq(&oa->o_oi));
		if (IS_ERR(oseq)) {
			CERROR("%s: Can not find seq for "DOSTID
			       ": rc = %ld\n", ofd_name(ofd), POSTID(&oa->o_oi),
			       PTR_ERR(oseq));
			RETURN(-EINVAL);
		}

		if (oseq->os_destroys_in_progress == 0) {
			/* don't fail lookups for orphan recovery, it causes
			 * later LBUGs when objects still exist during
			 * precreate */
			ofd_seq_put(env, oseq);
			RETURN(-ENOENT);
		}
		ofd_seq_put(env, oseq);
	}

	LASSERT(objcount == 1);
	LASSERT(obj->ioo_bufcnt > 0);

	rc = ostid_to_fid(&info->fti_fid, &oa->o_oi, 0);
	if (unlikely(rc != 0))
		RETURN(rc);

	if (cmd == OBD_BRW_WRITE) {
		rc = ofd_auth_capa(exp, &info->fti_fid, ostid_seq(&oa->o_oi),
				   capa, CAPA_OPC_OSS_WRITE);
		if (rc == 0) {
			la_from_obdo(&info->fti_attr, oa, OBD_MD_FLGETATTR);
			rc = ofd_preprw_write(env, exp, ofd, &info->fti_fid,
					      &info->fti_attr, oa, objcount,
					      obj, rnb, nr_local, lnb, oti);
		}
	} else if (cmd == OBD_BRW_READ) {
		rc = ofd_auth_capa(exp, &info->fti_fid, ostid_seq(&oa->o_oi),
				   capa, CAPA_OPC_OSS_READ);
		if (rc == 0) {
			ofd_grant_prepare_read(env, exp, oa);
			rc = ofd_preprw_read(env, exp, ofd, &info->fti_fid,
					     &info->fti_attr, obj->ioo_bufcnt,
					     rnb, nr_local, lnb, oti);
			obdo_from_la(oa, &info->fti_attr, LA_ATIME);
		}
	} else {
		CERROR("%s: wrong cmd %d received!\n",
		       exp->exp_obd->obd_name, cmd);
		rc = -EPROTO;
	}
	RETURN(rc);
}

static int
ofd_commitrw_read(const struct lu_env *env, struct ofd_device *ofd,
		  struct lu_fid *fid, int objcount, int niocount,
		  struct niobuf_local *lnb)
{
	struct ofd_object *fo;

	ENTRY;

	LASSERT(niocount > 0);

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	LASSERT(fo != NULL);
	LASSERT(ofd_object_exists(fo));
	dt_bufs_put(env, ofd_object_child(fo), lnb, niocount);

	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	/* second put is pair to object_get in ofd_preprw_read */
	ofd_object_put(env, fo);

	RETURN(0);
}

static int
ofd_write_attr_set(const struct lu_env *env, struct ofd_device *ofd,
		   struct ofd_object *ofd_obj, struct lu_attr *la,
		   struct filter_fid *ff)
{
	struct ofd_thread_info	*info = ofd_info(env);
	__u64			 valid = la->la_valid;
	int			 rc;
	struct thandle		*th;
	struct dt_object	*dt_obj;
	int			 ff_needed = 0;

	ENTRY;

	LASSERT(la);

	dt_obj = ofd_object_child(ofd_obj);
	LASSERT(dt_obj != NULL);

	la->la_valid &= LA_UID | LA_GID;

	rc = ofd_attr_handle_ugid(env, ofd_obj, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	if (ff != NULL) {
		rc = ofd_object_ff_check(env, ofd_obj);
		if (rc == -ENODATA)
			ff_needed = 1;
		else if (rc < 0)
			GOTO(out, rc);
	}

	if (!la->la_valid && !ff_needed)
		/* no attributes to set */
		GOTO(out, rc = 0);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	if (la->la_valid) {
		rc = dt_declare_attr_set(env, dt_obj, la, th);
		if (rc)
			GOTO(out_tx, rc);
	}

	if (ff_needed) {
		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_declare_xattr_set(env, dt_obj, &info->fti_buf,
					  XATTR_NAME_FID, 0, th);
		if (rc)
			GOTO(out_tx, rc);
	}

	/* We don't need a transno for this operation which will be re-executed
	 * anyway when the OST_WRITE (with a transno assigned) is replayed */
	rc = dt_trans_start_local(env, ofd->ofd_osd , th);
	if (rc)
		GOTO(out_tx, rc);

	/* set uid/gid */
	if (la->la_valid) {
		rc = dt_attr_set(env, dt_obj, la, th,
				 ofd_object_capa(env, ofd_obj));
		if (rc)
			GOTO(out_tx, rc);
	}

	/* set filter fid EA */
	if (ff_needed) {
		rc = dt_xattr_set(env, dt_obj, &info->fti_buf, XATTR_NAME_FID,
				  0, th, BYPASS_CAPA);
		if (rc)
			GOTO(out_tx, rc);
	}

	EXIT;
out_tx:
	dt_trans_stop(env, ofd->ofd_osd, th);
out:
	la->la_valid = valid;
	return rc;
}

static int
ofd_commitrw_write(const struct lu_env *env, struct ofd_device *ofd,
		   struct lu_fid *fid, struct lu_attr *la,
		   struct filter_fid *ff, int objcount,
		   int niocount, struct niobuf_local *lnb,
		   struct obd_trans_info *oti, int old_rc)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object	*fo;
	struct dt_object	*o;
	struct thandle		*th;
	int			 rc = 0;
	int			 retries = 0;

	ENTRY;

	LASSERT(objcount == 1);

	fo = ofd_object_find(env, ofd, fid);
	LASSERT(fo != NULL);
	LASSERT(ofd_object_exists(fo));

	o = ofd_object_child(fo);
	LASSERT(o != NULL);

	if (old_rc)
		GOTO(out, rc = old_rc);

	/*
	 * The first write to each object must set some attributes.  It is
	 * important to set the uid/gid before calling
	 * dt_declare_write_commit() since quota enforcement is now handled in
	 * declare phases.
	 */
	rc = ofd_write_attr_set(env, ofd, fo, la, ff);
	if (rc)
		GOTO(out, rc);

	la->la_valid &= LA_ATIME | LA_MTIME | LA_CTIME;

retry:
	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	th->th_sync |= oti->oti_sync_write;

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_DQACQ_NET))
		GOTO(out_stop, rc = -EINPROGRESS);

	rc = dt_declare_write_commit(env, o, lnb, niocount, th);
	if (rc)
		GOTO(out_stop, rc);

	if (la->la_valid) {
		/* update [mac]time if needed */
		rc = dt_declare_attr_set(env, o, la, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(out_stop, rc);

	rc = dt_write_commit(env, o, lnb, niocount, th);
	if (rc)
		GOTO(out_stop, rc);

	if (la->la_valid) {
		rc = dt_attr_set(env, o, la, th, ofd_object_capa(env, fo));
		if (rc)
			GOTO(out_stop, rc);
	}

	/* get attr to return */
	rc = dt_attr_get(env, o, la, ofd_object_capa(env, fo));

out_stop:
	/* Force commit to make the just-deleted blocks
	 * reusable. LU-456 */
	if (rc == -ENOSPC)
		th->th_sync = 1;

	ofd_trans_stop(env, ofd, th, rc);
	if (rc == -ENOSPC && retries++ < 3) {
		CDEBUG(D_INODE, "retry after force commit, retries:%d\n",
		       retries);
		goto retry;
	}

out:
	dt_bufs_put(env, o, lnb, niocount);
	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	/* second put is pair to object_get in ofd_preprw_write */
	ofd_object_put(env, fo);
	ofd_grant_commit(env, info->fti_exp, old_rc);
	RETURN(rc);
}

int ofd_commitrw(const struct lu_env *env, int cmd, struct obd_export *exp,
		 struct obdo *oa, int objcount, struct obd_ioobj *obj,
		 struct niobuf_remote *rnb, int npages,
		 struct niobuf_local *lnb, struct obd_trans_info *oti,
		 int old_rc)
{
	struct ofd_thread_info	*info;
	struct ofd_mod_data	*fmd;
	__u64			 valid;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct filter_fid	*ff = NULL;
	int			 rc = 0;

	info = ofd_info(env);
	ofd_oti2info(info, oti);

	LASSERT(npages > 0);

	rc = ostid_to_fid(&info->fti_fid, &oa->o_oi, 0);
	if (unlikely(rc != 0))
		RETURN(rc);
	if (cmd == OBD_BRW_WRITE) {
		/* Don't update timestamps if this write is older than a
		 * setattr which modifies the timestamps. b=10150 */

		/* XXX when we start having persistent reservations this needs
		 * to be changed to ofd_fmd_get() to create the fmd if it
		 * doesn't already exist so we can store the reservation handle
		 * there. */
		valid = OBD_MD_FLUID | OBD_MD_FLGID;
		fmd = ofd_fmd_find(exp, &info->fti_fid);
		if (!fmd || fmd->fmd_mactime_xid < info->fti_xid)
			valid |= OBD_MD_FLATIME | OBD_MD_FLMTIME |
				 OBD_MD_FLCTIME;
		ofd_fmd_put(exp, fmd);
		la_from_obdo(&info->fti_attr, oa, valid);

		if (oa->o_valid & OBD_MD_FLFID) {
			ff = &info->fti_mds_fid;
			ofd_prepare_fidea(ff, oa);
		}

		rc = ofd_commitrw_write(env, ofd, &info->fti_fid,
					&info->fti_attr, ff, objcount, npages,
					lnb, oti, old_rc);
		if (rc == 0)
			obdo_from_la(oa, &info->fti_attr,
				     OFD_VALID_FLAGS | LA_GID | LA_UID);
		else
			obdo_from_la(oa, &info->fti_attr, LA_GID | LA_UID);

		/* don't report overquota flag if we failed before reaching
		 * commit */
		if (old_rc == 0 && (rc == 0 || rc == -EDQUOT)) {
			/* return the overquota flags to client */
			if (lnb[0].lnb_flags & OBD_BRW_OVER_USRQUOTA) {
				if (oa->o_valid & OBD_MD_FLFLAGS)
					oa->o_flags |= OBD_FL_NO_USRQUOTA;
				else
					oa->o_flags = OBD_FL_NO_USRQUOTA;
			}

			if (lnb[0].lnb_flags & OBD_BRW_OVER_GRPQUOTA) {
				if (oa->o_valid & OBD_MD_FLFLAGS)
					oa->o_flags |= OBD_FL_NO_GRPQUOTA;
				else
					oa->o_flags = OBD_FL_NO_GRPQUOTA;
			}

			oa->o_valid |= OBD_MD_FLFLAGS;
			oa->o_valid |= OBD_MD_FLUSRQUOTA | OBD_MD_FLGRPQUOTA;
		}
	} else if (cmd == OBD_BRW_READ) {
		struct ldlm_namespace *ns = ofd->ofd_namespace;

		/* If oa != NULL then ofd_preprw_read updated the inode
		 * atime and we should update the lvb so that other glimpses
		 * will also get the updated value. bug 5972 */
		if (oa && ns && ns->ns_lvbo && ns->ns_lvbo->lvbo_update) {
			 struct ldlm_resource *rs = NULL;

			ost_fid_build_resid(&info->fti_fid, &info->fti_resid);
			rs = ldlm_resource_get(ns, NULL, &info->fti_resid,
					       LDLM_EXTENT, 0);
			if (rs != NULL) {
				ns->ns_lvbo->lvbo_update(rs, NULL, 1);
				ldlm_resource_putref(rs);
			}
		}
		rc = ofd_commitrw_read(env, ofd, &info->fti_fid, objcount,
					  npages, lnb);
		if (old_rc)
			rc = old_rc;
	} else {
		LBUG();
		rc = -EPROTO;
	}

	ofd_info2oti(info, oti);
	RETURN(rc);
}
