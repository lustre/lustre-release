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
 * Copyright (c) 2012, 2017 Intel Corporation.
 */
/*
 * lustre/mdt/mdt_io.c
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <dt_object.h>
#include "mdt_internal.h"

/* --------------- MDT grant code ---------------- */

long mdt_grant_connect(const struct lu_env *env,
		       struct obd_export *exp,
		       u64 want, bool conservative)
{
	struct mdt_device *mdt = mdt_exp2dev(exp);
	u64 left;
	long grant;

	ENTRY;

	dt_statfs(env, mdt->mdt_bottom, &mdt->mdt_osfs);

	left = (mdt->mdt_osfs.os_bavail * mdt->mdt_osfs.os_bsize) / 2;

	grant = left;

	CDEBUG(D_CACHE, "%s: cli %s/%p ocd_grant: %ld want: %llu left: %llu\n",
	       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, grant, want, left);

	return grant;
}

void mdt_grant_prepare_write(const struct lu_env *env,
			     struct obd_export *exp, struct obdo *oa,
			     struct niobuf_remote *rnb, int niocount)
{
	struct mdt_device *mdt = mdt_exp2dev(exp);
	u64 left;

	ENTRY;

	left = (mdt->mdt_osfs.os_bavail * mdt->mdt_osfs.os_bsize) / 2;

	/* grant more space back to the client if possible */
	oa->o_grant = left;
}
/* ---------------- end of MDT grant code ---------------- */

/* functions below are stubs for now, they will be implemented with
 * grant support on MDT */
static inline void mdt_io_counter_incr(struct obd_export *exp, int opcode,
				       char *jobid, long amount)
{
	return;
}

void mdt_grant_prepare_read(const struct lu_env *env,
			    struct obd_export *exp, struct obdo *oa)
{
	return;
}

void mdt_grant_commit(struct obd_export *exp, unsigned long pending,
		      int rc)
{
	return;

}

static inline void mdt_dom_read_lock(struct mdt_object *mo)
{
	down_read(&mo->mot_dom_sem);
}

static inline void mdt_dom_read_unlock(struct mdt_object *mo)
{
	up_read(&mo->mot_dom_sem);
}

static inline void mdt_dom_write_lock(struct mdt_object *mo)
{
	down_write(&mo->mot_dom_sem);
}

static inline void mdt_dom_write_unlock(struct mdt_object *mo)
{
	up_write(&mo->mot_dom_sem);
}

static int mdt_preprw_read(const struct lu_env *env, struct obd_export *exp,
			   struct mdt_device *mdt, struct mdt_object *mo,
			   struct lu_attr *la, int niocount,
			   struct niobuf_remote *rnb, int *nr_local,
			   struct niobuf_local *lnb, char *jobid)
{
	struct dt_object *dob;
	int i, j, rc, tot_bytes = 0;

	ENTRY;

	mdt_dom_read_lock(mo);
	if (!mdt_object_exists(mo))
		GOTO(unlock, rc = -ENOENT);

	dob = mdt_obj2dt(mo);
	/* parse remote buffers to local buffers and prepare the latter */
	*nr_local = 0;
	for (i = 0, j = 0; i < niocount; i++) {
		rc = dt_bufs_get(env, dob, rnb + i, lnb + j, 0);
		if (unlikely(rc < 0))
			GOTO(buf_put, rc);
		/* correct index for local buffers to continue with */
		j += rc;
		*nr_local += rc;
		tot_bytes += rnb[i].rnb_len;
	}

	rc = dt_attr_get(env, dob, la);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	rc = dt_read_prep(env, dob, lnb, *nr_local);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	mdt_io_counter_incr(exp, LPROC_MDT_IO_READ, jobid, tot_bytes);
	RETURN(0);
buf_put:
	dt_bufs_put(env, dob, lnb, *nr_local);
unlock:
	mdt_dom_read_unlock(mo);
	return rc;
}

static int mdt_preprw_write(const struct lu_env *env, struct obd_export *exp,
			    struct mdt_device *mdt, struct mdt_object *mo,
			    struct lu_attr *la, struct obdo *oa,
			    int objcount, struct obd_ioobj *obj,
			    struct niobuf_remote *rnb, int *nr_local,
			    struct niobuf_local *lnb, char *jobid)
{
	struct dt_object *dob;
	int i, j, k, rc = 0, tot_bytes = 0;

	ENTRY;

	/* Process incoming grant info, set OBD_BRW_GRANTED flag and grant some
	 * space back if possible */
	mdt_grant_prepare_write(env, exp, oa, rnb, obj->ioo_bufcnt);

	mdt_dom_read_lock(mo);
	if (!mdt_object_exists(mo)) {
		CDEBUG(D_ERROR, "%s: BRW to missing obj "DFID"\n",
		       exp->exp_obd->obd_name, PFID(mdt_object_fid(mo)));
		GOTO(unlock, rc = -ENOENT);
	}

	dob = mdt_obj2dt(mo);
	/* parse remote buffers to local buffers and prepare the latter */
	*nr_local = 0;
	for (i = 0, j = 0; i < obj->ioo_bufcnt; i++) {
		rc = dt_bufs_get(env, dob, rnb + i, lnb + j, 1);
		if (unlikely(rc < 0))
			GOTO(err, rc);
		/* correct index for local buffers to continue with */
		for (k = 0; k < rc; k++)
			lnb[j+k].lnb_flags = rnb[i].rnb_flags;
		j += rc;
		*nr_local += rc;
		tot_bytes += rnb[i].rnb_len;
	}

	rc = dt_write_prep(env, dob, lnb, *nr_local);
	if (likely(rc))
		GOTO(err, rc);

	mdt_io_counter_incr(exp, LPROC_MDT_IO_WRITE, jobid, tot_bytes);
	RETURN(0);
err:
	dt_bufs_put(env, dob, lnb, *nr_local);
unlock:
	mdt_dom_read_unlock(mo);
	/* tgt_grant_prepare_write() was called, so we must commit */
	mdt_grant_commit(exp, oa->o_grant_used, rc);
	/* let's still process incoming grant information packed in the oa,
	 * but without enforcing grant since we won't proceed with the write.
	 * Just like a read request actually. */
	mdt_grant_prepare_read(env, exp, oa);
	return rc;
}

int mdt_obd_preprw(const struct lu_env *env, int cmd, struct obd_export *exp,
		   struct obdo *oa, int objcount, struct obd_ioobj *obj,
		   struct niobuf_remote *rnb, int *nr_local,
		   struct niobuf_local *lnb)
{
	struct tgt_session_info *tsi = tgt_ses_info(env);
	struct mdt_thread_info *info = tsi2mdt_info(tsi);
	struct lu_attr *la = &info->mti_attr.ma_attr;
	struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
	struct mdt_object *mo;
	char *jobid;
	int rc = 0;

	/* The default value PTLRPC_MAX_BRW_PAGES is set in tgt_brw_write()
	 * but for MDT it is different, correct it here. */
	if (*nr_local > MD_MAX_BRW_PAGES)
		*nr_local = MD_MAX_BRW_PAGES;

	jobid = tsi->tsi_jobid;

	if (!oa || objcount != 1 || obj->ioo_bufcnt == 0) {
		CERROR("%s: bad parameters %p/%i/%i\n",
		       exp->exp_obd->obd_name, oa, objcount, obj->ioo_bufcnt);
		rc = -EPROTO;
	}

	mo = mdt_object_find(env, mdt, &tsi->tsi_fid);
	if (IS_ERR(mo))
		GOTO(out, rc = PTR_ERR(mo));

	LASSERT(info->mti_object == NULL);
	info->mti_object = mo;

	if (cmd == OBD_BRW_WRITE) {
		la_from_obdo(la, oa, OBD_MD_FLGETATTR);
		rc = mdt_preprw_write(env, exp, mdt, mo, la, oa,
				      objcount, obj, rnb, nr_local, lnb,
				      jobid);
	} else if (cmd == OBD_BRW_READ) {
		mdt_grant_prepare_read(env, exp, oa);
		rc = mdt_preprw_read(env, exp, mdt, mo, la,
				     obj->ioo_bufcnt, rnb, nr_local, lnb,
				     jobid);
		obdo_from_la(oa, la, LA_ATIME);
	} else {
		CERROR("%s: wrong cmd %d received!\n",
		       exp->exp_obd->obd_name, cmd);
		rc = -EPROTO;
	}
	if (rc) {
		lu_object_put(env, &mo->mot_obj);
		info->mti_object = NULL;
	}
out:
	RETURN(rc);
}

static int mdt_commitrw_read(const struct lu_env *env, struct mdt_device *mdt,
			     struct mdt_object *mo, int objcount, int niocount,
			     struct niobuf_local *lnb)
{
	struct dt_object *dob;
	int rc = 0;

	ENTRY;

	LASSERT(niocount > 0);

	dob = mdt_obj2dt(mo);

	dt_bufs_put(env, dob, lnb, niocount);

	mdt_dom_read_unlock(mo);
	RETURN(rc);
}

static int mdt_commitrw_write(const struct lu_env *env, struct obd_export *exp,
			      struct mdt_device *mdt, struct mdt_object *mo,
			      struct lu_attr *la, int objcount, int niocount,
			      struct niobuf_local *lnb, unsigned long granted,
			      int old_rc)
{
	struct dt_device *dt = mdt->mdt_bottom;
	struct dt_object *dob;
	struct thandle *th;
	int rc = 0;
	int retries = 0;
	int i;

	ENTRY;

	dob = mdt_obj2dt(mo);

	if (old_rc)
		GOTO(out, rc = old_rc);

	la->la_valid &= LA_ATIME | LA_MTIME | LA_CTIME;
retry:
	if (!dt_object_exists(dob))
		GOTO(out, rc = -ENOENT);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	for (i = 0; i < niocount; i++) {
		if (!(lnb[i].lnb_flags & OBD_BRW_ASYNC)) {
			th->th_sync = 1;
			break;
		}
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_DQACQ_NET))
		GOTO(out_stop, rc = -EINPROGRESS);

	rc = dt_declare_write_commit(env, dob, lnb, niocount, th);
	if (rc)
		GOTO(out_stop, rc);

	if (la->la_valid) {
		/* update [mac]time if needed */
		rc = dt_declare_attr_set(env, dob, la, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	rc = dt_trans_start(env, dt, th);
	if (rc)
		GOTO(out_stop, rc);

	dt_write_lock(env, dob, 0);
	rc = dt_write_commit(env, dob, lnb, niocount, th);
	if (rc)
		GOTO(unlock, rc);

	if (la->la_valid) {
		rc = dt_attr_set(env, dob, la, th);
		if (rc)
			GOTO(unlock, rc);
	}
	/* get attr to return */
	rc = dt_attr_get(env, dob, la);
unlock:
	dt_write_unlock(env, dob);

out_stop:
	/* Force commit to make the just-deleted blocks
	 * reusable. LU-456 */
	if (rc == -ENOSPC)
		th->th_sync = 1;

	th->th_result = rc;
	dt_trans_stop(env, dt, th);
	if (rc == -ENOSPC && retries++ < 3) {
		CDEBUG(D_INODE, "retry after force commit, retries:%d\n",
		       retries);
		goto retry;
	}

out:
	dt_bufs_put(env, dob, lnb, niocount);
	mdt_dom_read_unlock(mo);
	mdt_grant_commit(exp, granted, old_rc);
	RETURN(rc);
}

int mdt_obd_commitrw(const struct lu_env *env, int cmd, struct obd_export *exp,
		     struct obdo *oa, int objcount, struct obd_ioobj *obj,
		     struct niobuf_remote *rnb, int npages,
		     struct niobuf_local *lnb, int old_rc)
{
	struct mdt_thread_info *info = mdt_th_info(env);
	struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
	struct mdt_object *mo = info->mti_object;
	struct lu_attr *la = &info->mti_attr.ma_attr;
	__u64 valid;
	int rc = 0;

	if (npages == 0) {
		CERROR("%s: no pages to commit\n",
		       exp->exp_obd->obd_name);
		rc = -EPROTO;
	}

	LASSERT(mo);

	if (cmd == OBD_BRW_WRITE) {
		/* Don't update timestamps if this write is older than a
		 * setattr which modifies the timestamps. b=10150 */

		/* XXX when we start having persistent reservations this needs
		 * to be changed to ofd_fmd_get() to create the fmd if it
		 * doesn't already exist so we can store the reservation handle
		 * there. */
		valid = OBD_MD_FLUID | OBD_MD_FLGID;
		valid |= OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME;

		la_from_obdo(la, oa, valid);

		rc = mdt_commitrw_write(env, exp, mdt, mo, la, objcount,
					npages, lnb, oa->o_grant_used, old_rc);
		if (rc == 0)
			obdo_from_la(oa, la, VALID_FLAGS | LA_GID | LA_UID);
		else
			obdo_from_la(oa, la, LA_GID | LA_UID);

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

			oa->o_valid |= OBD_MD_FLFLAGS | OBD_MD_FLUSRQUOTA |
				       OBD_MD_FLGRPQUOTA;
		}
	} else if (cmd == OBD_BRW_READ) {
		rc = mdt_commitrw_read(env, mdt, mo, objcount, npages, lnb);
		if (old_rc)
			rc = old_rc;
	} else {
		rc = -EPROTO;
	}
	/* this put is pair to object_get in ofd_preprw_write */
	mdt_thread_info_fini(info);
	RETURN(rc);
}

int mdt_object_punch(const struct lu_env *env, struct dt_device *dt,
		     struct dt_object *dob, __u64 start, __u64 end,
		     struct lu_attr *la)
{
	struct thandle *th;
	int rc;

	ENTRY;

	/* we support truncate, not punch yet */
	LASSERT(end == OBD_OBJECT_EOF);

	if (!dt_object_exists(dob))
		RETURN(-ENOENT);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_attr_set(env, dob, la, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(stop, rc);

	tgt_vbr_obj_set(env, dob);
	rc = dt_trans_start(env, dt, th);
	if (rc)
		GOTO(stop, rc);

	dt_write_lock(env, dob, 0);
	rc = dt_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(unlock, rc);
	rc = dt_attr_set(env, dob, la, th);
	if (rc)
		GOTO(unlock, rc);
unlock:
	dt_write_unlock(env, dob);
stop:
	th->th_result = rc;
	dt_trans_stop(env, dt, th);
	RETURN(rc);
}

int mdt_punch_hdl(struct tgt_session_info *tsi)
{
	const struct obdo *oa = &tsi->tsi_ost_body->oa;
	struct ost_body *repbody;
	struct mdt_thread_info *info;
	struct lu_attr *la;
	struct ldlm_namespace *ns = tsi->tsi_tgt->lut_obd->obd_namespace;
	struct obd_export *exp = tsi->tsi_exp;
	struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
	struct mdt_object *mo;
	struct dt_object *dob;
	__u64 flags = 0;
	struct lustre_handle lh = { 0, };
	__u64 start, end;
	int rc;
	bool srvlock;

	ENTRY;

	/* check that we do support OBD_CONNECT_TRUNCLOCK. */
	CLASSERT(OST_CONNECT_SUPPORTED & OBD_CONNECT_TRUNCLOCK);

	if ((oa->o_valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) !=
	    (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
		RETURN(err_serious(-EPROTO));

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-ENOMEM));

	/* punch start,end are passed in o_size,o_blocks throught wire */
	start = oa->o_size;
	end = oa->o_blocks;

	if (end != OBD_OBJECT_EOF) /* Only truncate is supported */
		RETURN(-EPROTO);

	info = tsi2mdt_info(tsi);
	la = &info->mti_attr.ma_attr;
	/* standard truncate optimization: if file body is completely
	 * destroyed, don't send data back to the server. */
	if (start == 0)
		flags |= LDLM_FL_AST_DISCARD_DATA;

	repbody->oa.o_oi = oa->o_oi;
	repbody->oa.o_valid = OBD_MD_FLID;

	srvlock = (exp_connect_flags(exp) & OBD_CONNECT_SRVLOCK) &&
		  oa->o_valid & OBD_MD_FLFLAGS &&
		  oa->o_flags & OBD_FL_SRVLOCK;

	if (srvlock) {
		rc = tgt_mdt_data_lock(ns, &tsi->tsi_resid, &lh, LCK_PW,
				       &flags);
		if (rc != 0)
			GOTO(out, rc);
	}

	CDEBUG(D_INODE, "calling punch for object "DFID", valid = %#llx"
	       ", start = %lld, end = %lld\n", PFID(&tsi->tsi_fid),
	       oa->o_valid, start, end);

	mo = mdt_object_find(tsi->tsi_env, mdt, &tsi->tsi_fid);
	if (IS_ERR(mo))
		GOTO(out_unlock, rc = PTR_ERR(mo));

	mdt_dom_write_lock(mo);
	if (!mdt_object_exists(mo))
		GOTO(out_put, rc = -ENOENT);
	dob = mdt_obj2dt(mo);

	la_from_obdo(la, oa, OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME);
	la->la_size = start;
	la->la_valid |= LA_SIZE;

	rc = mdt_object_punch(tsi->tsi_env, mdt->mdt_bottom, dob,
			      start, end, la);
	mdt_dom_write_unlock(mo);
	if (rc)
		GOTO(out_put, rc);

	mdt_io_counter_incr(tsi->tsi_exp, LPROC_MDT_IO_PUNCH,
			    tsi->tsi_jobid, 1);
	EXIT;
out_put:
	lu_object_put(tsi->tsi_env, &mo->mot_obj);
out_unlock:
	if (srvlock)
		mdt_save_lock(info, &lh, LCK_PW, rc);
out:
	mdt_thread_info_fini(info);
	if (rc == 0) {
		struct ldlm_resource *res;

		/* we do not call this before to avoid lu_object_find() in
		 *  ->lvbo_update() holding another reference on the object.
		 * otherwise concurrent destroy can make the object unavailable
		 * for 2nd lu_object_find() waiting for the first reference
		 * to go... deadlock! */
		res = ldlm_resource_get(ns, NULL, &tsi->tsi_resid,
					LDLM_IBITS, 0);
		if (!IS_ERR(res)) {
			ldlm_res_lvbo_update(res, NULL, 0);
			ldlm_resource_putref(res);
		}
	}
	return rc;
}

