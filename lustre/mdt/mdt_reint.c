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
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdt/mdt_reint.c
 *
 * Lustre Metadata Target (mdt) reintegration routines
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

static inline void mdt_reint_init_ma(struct mdt_thread_info *info,
                                     struct md_attr *ma)
{
	ma->ma_need = MA_INODE;
        ma->ma_valid = 0;
}

static int mdt_create_pack_capa(struct mdt_thread_info *info, int rc,
                                struct mdt_object *object,
                                struct mdt_body *repbody)
{
        ENTRY;

        /* for cross-ref mkdir, mds capa has been fetched from remote obj, then
         * we won't go to below*/
        if (repbody->valid & OBD_MD_FLMDSCAPA)
                RETURN(rc);

	if (rc == 0 && info->mti_mdt->mdt_opts.mo_mds_capa &&
	    exp_connect_flags(info->mti_exp) & OBD_CONNECT_MDS_CAPA) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                rc = mo_capa_get(info->mti_env, mdt_object_child(object), capa,
                                 0);
                if (rc == 0)
                        repbody->valid |= OBD_MD_FLMDSCAPA;
        }

        RETURN(rc);
}

/**
 * Get version of object by fid.
 *
 * Return real version or ENOENT_VERSION if object doesn't exist
 */
static void mdt_obj_version_get(struct mdt_thread_info *info,
                                struct mdt_object *o, __u64 *version)
{
        LASSERT(o);
	if (mdt_object_exists(o) && !mdt_object_remote(o) &&
	    !fid_is_obf(mdt_object_fid(o)))
                *version = dt_version_get(info->mti_env, mdt_obj2dt(o));
        else
                *version = ENOENT_VERSION;
        CDEBUG(D_INODE, "FID "DFID" version is "LPX64"\n",
               PFID(mdt_object_fid(o)), *version);
}

/**
 * Check version is correct.
 *
 * Should be called only during replay.
 */
static int mdt_version_check(struct ptlrpc_request *req,
                             __u64 version, int idx)
{
        __u64 *pre_ver = lustre_msg_get_versions(req->rq_reqmsg);
        ENTRY;

        if (!exp_connect_vbr(req->rq_export))
                RETURN(0);

        LASSERT(req_is_replay(req));
        /** VBR: version is checked always because costs nothing */
        LASSERT(idx < PTLRPC_NUM_VERSIONS);
        /** Sanity check for malformed buffers */
        if (pre_ver == NULL) {
                CERROR("No versions in request buffer\n");
		spin_lock(&req->rq_export->exp_lock);
		req->rq_export->exp_vbr_failed = 1;
		spin_unlock(&req->rq_export->exp_lock);
		RETURN(-EOVERFLOW);
	} else if (pre_ver[idx] != version) {
		CDEBUG(D_INODE, "Version mismatch "LPX64" != "LPX64"\n",
		       pre_ver[idx], version);
		spin_lock(&req->rq_export->exp_lock);
		req->rq_export->exp_vbr_failed = 1;
		spin_unlock(&req->rq_export->exp_lock);
		RETURN(-EOVERFLOW);
	}
	RETURN(0);
}

/**
 * Save pre-versions in reply.
 */
static void mdt_version_save(struct ptlrpc_request *req, __u64 version,
                             int idx)
{
        __u64 *reply_ver;

        if (!exp_connect_vbr(req->rq_export))
                return;

        LASSERT(!req_is_replay(req));
        LASSERT(req->rq_repmsg != NULL);
        reply_ver = lustre_msg_get_versions(req->rq_repmsg);
        if (reply_ver)
                reply_ver[idx] = version;
}

/**
 * Save enoent version, it is needed when it is obvious that object doesn't
 * exist, e.g. child during create.
 */
static void mdt_enoent_version_save(struct mdt_thread_info *info, int idx)
{
        /* save version of file name for replay, it must be ENOENT here */
        if (!req_is_replay(mdt_info_req(info))) {
                info->mti_ver[idx] = ENOENT_VERSION;
                mdt_version_save(mdt_info_req(info), info->mti_ver[idx], idx);
        }
}

/**
 * Get version from disk and save in reply buffer.
 *
 * Versions are saved in reply only during normal operations not replays.
 */
void mdt_version_get_save(struct mdt_thread_info *info,
                          struct mdt_object *mto, int idx)
{
        /* don't save versions during replay */
        if (!req_is_replay(mdt_info_req(info))) {
                mdt_obj_version_get(info, mto, &info->mti_ver[idx]);
                mdt_version_save(mdt_info_req(info), info->mti_ver[idx], idx);
        }
}

/**
 * Get version from disk and check it, no save in reply.
 */
int mdt_version_get_check(struct mdt_thread_info *info,
                          struct mdt_object *mto, int idx)
{
        /* only check versions during replay */
        if (!req_is_replay(mdt_info_req(info)))
                return 0;

        mdt_obj_version_get(info, mto, &info->mti_ver[idx]);
        return mdt_version_check(mdt_info_req(info), info->mti_ver[idx], idx);
}

/**
 * Get version from disk and check if recovery or just save.
 */
int mdt_version_get_check_save(struct mdt_thread_info *info,
                               struct mdt_object *mto, int idx)
{
        int rc = 0;

        mdt_obj_version_get(info, mto, &info->mti_ver[idx]);
        if (req_is_replay(mdt_info_req(info)))
                rc = mdt_version_check(mdt_info_req(info), info->mti_ver[idx],
                                       idx);
        else
                mdt_version_save(mdt_info_req(info), info->mti_ver[idx], idx);
        return rc;
}

/**
 * Lookup with version checking.
 *
 * This checks version of 'name'. Many reint functions uses 'name' for child not
 * FID, therefore we need to get object by name and check its version.
 */
int mdt_lookup_version_check(struct mdt_thread_info *info,
                             struct mdt_object *p, struct lu_name *lname,
                             struct lu_fid *fid, int idx)
{
        int rc, vbrc;

        rc = mdo_lookup(info->mti_env, mdt_object_child(p), lname, fid,
                        &info->mti_spec);
        /* Check version only during replay */
        if (!req_is_replay(mdt_info_req(info)))
                return rc;

        info->mti_ver[idx] = ENOENT_VERSION;
        if (rc == 0) {
                struct mdt_object *child;
                child = mdt_object_find(info->mti_env, info->mti_mdt, fid);
                if (likely(!IS_ERR(child))) {
                        mdt_obj_version_get(info, child, &info->mti_ver[idx]);
                        mdt_object_put(info->mti_env, child);
                }
        }
        vbrc = mdt_version_check(mdt_info_req(info), info->mti_ver[idx], idx);
        return vbrc ? vbrc : rc;

}

/*
 * VBR: we save three versions in reply:
 * 0 - parent. Check that parent version is the same during replay.
 * 1 - name. Version of 'name' if file exists with the same name or
 * ENOENT_VERSION, it is needed because file may appear due to missed replays.
 * 2 - child. Version of child by FID. Must be ENOENT. It is mostly sanity
 * check.
 */
static int mdt_md_create(struct mdt_thread_info *info)
{
        struct mdt_device       *mdt = info->mti_mdt;
        struct mdt_object       *parent;
        struct mdt_object       *child;
        struct mdt_lock_handle  *lh;
        struct mdt_body         *repbody;
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct lu_name          *lname;
        int rc;
        ENTRY;

        DEBUG_REQ(D_INODE, mdt_info_req(info), "Create  (%s->"DFID") in "DFID,
                  rr->rr_name, PFID(rr->rr_fid2), PFID(rr->rr_fid1));

	if (fid_is_obf(rr->rr_fid1) || fid_is_dot_lustre(rr->rr_fid1))
		RETURN(-EPERM);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        lh = &info->mti_lh[MDT_LH_PARENT];
        mdt_lock_pdo_init(lh, LCK_PW, rr->rr_name, rr->rr_namelen);

        parent = mdt_object_find_lock(info, rr->rr_fid1, lh,
                                      MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                RETURN(PTR_ERR(parent));

        rc = mdt_version_get_check_save(info, parent, 0);
        if (rc)
                GOTO(out_put_parent, rc);

        /*
         * Check child name version during replay.
         * During create replay a file may exist with same name.
         */
        lname = mdt_name(info->mti_env, (char *)rr->rr_name, rr->rr_namelen);
        rc = mdt_lookup_version_check(info, parent, lname,
                                      &info->mti_tmp_fid1, 1);
	if (rc == 0)
		GOTO(out_put_parent, rc = -EEXIST);

	/* -ENOENT is expected here */
	if (rc != -ENOENT)
		GOTO(out_put_parent, rc);

	/* save version of file name for replay, it must be ENOENT here */
	mdt_enoent_version_save(info, 1);

	child = mdt_object_new(info->mti_env, mdt, rr->rr_fid2);
        if (likely(!IS_ERR(child))) {
                struct md_object *next = mdt_object_child(parent);

		if (mdt_object_remote(child)) {
			struct seq_server_site *ss;
			struct lu_ucred *uc  = mdt_ucred(info);

			if (!md_capable(uc, CFS_CAP_SYS_ADMIN)) {
				if (uc->uc_gid !=
				    mdt->mdt_enable_remote_dir_gid &&
				    mdt->mdt_enable_remote_dir_gid != -1) {
					CERROR("%s: Creating remote dir is only"
					       " permitted for administrator or"
					       " set mdt_enable_remote_dir_gid:"
					       " rc = %d\n",
						mdt_obd_name(mdt), -EPERM);
					GOTO(out_put_child, rc = -EPERM);
				}
			}

			ss = mdt_seq_site(mdt);
			if (ss->ss_node_id != 0 &&
			    mdt->mdt_enable_remote_dir == 0) {
				CERROR("%s: remote dir is only permitted on"
				       " MDT0 or set_param"
				       " mdt.*.enable_remote_dir=1\n",
				       mdt_obd_name(mdt));
				GOTO(out_put_child, rc = -EPERM);
			}
			if (!mdt_is_dne_client(mdt_info_req(info)->rq_export)) {
				/* Return -EIO for old client */
				GOTO(out_put_child, rc = -EIO);
			}

		}
                ma->ma_need = MA_INODE;
                ma->ma_valid = 0;
                /* capa for cross-ref will be stored here */
                ma->ma_capa = req_capsule_server_get(info->mti_pill,
                                                     &RMF_CAPA1);
                LASSERT(ma->ma_capa);

                mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
                               OBD_FAIL_MDS_REINT_CREATE_WRITE);

                /* Version of child will be updated on disk. */
                info->mti_mos = child;
                rc = mdt_version_get_check_save(info, child, 2);
                if (rc)
                        GOTO(out_put_child, rc);

                /* Let lower layer know current lock mode. */
                info->mti_spec.sp_cr_mode =
                        mdt_dlm_mode2mdl_mode(lh->mlh_pdo_mode);

		/*
		 * Do not perform lookup sanity check. We know that name does
		 * not exist.
		 */
		info->mti_spec.sp_cr_lookup = 0;
                info->mti_spec.sp_feat = &dt_directory_features;

                rc = mdo_create(info->mti_env, next, lname,
                                mdt_object_child(child),
                                &info->mti_spec, ma);
		if (rc == 0)
			rc = mdt_attr_get_complex(info, child, ma);

                if (rc == 0) {
                        /* Return fid & attr to client. */
                        if (ma->ma_valid & MA_INODE)
                                mdt_pack_attr2body(info, repbody, &ma->ma_attr,
                                                   mdt_object_fid(child));
                }
out_put_child:
                mdt_object_put(info->mti_env, child);
        } else {
                rc = PTR_ERR(child);
        }
        mdt_create_pack_capa(info, rc, child, repbody);
out_put_parent:
        mdt_object_unlock_put(info, parent, lh, rc);
        RETURN(rc);
}

int mdt_attr_set(struct mdt_thread_info *info, struct mdt_object *mo,
                 struct md_attr *ma, int flags)
{
        struct mdt_lock_handle  *lh;
        int do_vbr = ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID|LA_FLAGS);
        __u64 lockpart = MDS_INODELOCK_UPDATE;
        int rc;
        ENTRY;

	/* attr shouldn't be set on remote object */
	LASSERT(!mdt_object_remote(mo));

        lh = &info->mti_lh[MDT_LH_PARENT];
        mdt_lock_reg_init(lh, LCK_PW);

	/* Even though the new MDT will grant PERM lock to the old
	 * client, but the old client will almost ignore that during
	 * So it needs to revoke both LOOKUP and PERM lock here, so
	 * both new and old client can cancel the dcache */
	if (ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID))
		lockpart |= MDS_INODELOCK_LOOKUP | MDS_INODELOCK_PERM;

        rc = mdt_object_lock(info, mo, lh, lockpart, MDT_LOCAL_LOCK);
        if (rc != 0)
                RETURN(rc);

        if (mdt_object_exists(mo) == 0)
                GOTO(out_unlock, rc = -ENOENT);

        /* all attrs are packed into mti_attr in unpack_setattr */
        mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_SETATTR_WRITE);

        /* This is only for set ctime when rename's source is on remote MDS. */
        if (unlikely(ma->ma_attr.la_valid == LA_CTIME))
                ma->ma_attr_flags |= MDS_VTX_BYPASS;

        /* VBR: update version if attr changed are important for recovery */
        if (do_vbr) {
                /* update on-disk version of changed object */
                info->mti_mos = mo;
                rc = mdt_version_get_check_save(info, mo, 0);
                if (rc)
                        GOTO(out_unlock, rc);
        }

        /* all attrs are packed into mti_attr in unpack_setattr */
        rc = mo_attr_set(info->mti_env, mdt_object_child(mo), ma);
        if (rc != 0)
                GOTO(out_unlock, rc);

        EXIT;
out_unlock:
        mdt_object_unlock(info, mo, lh, rc);
        return rc;
}

/**
 * Check HSM flags and add HS_DIRTY flag if relevant.
 *
 * A file could be set dirty only if it has a copy in the backend (HS_EXISTS)
 * and is not RELEASED.
 */
int mdt_add_dirty_flag(struct mdt_thread_info *info, struct mdt_object *mo,
			struct md_attr *ma)
{
	int rc;
	ENTRY;

	/* If the file was modified, add the dirty flag */
	ma->ma_need = MA_HSM;
	rc = mdt_attr_get_complex(info, mo, ma);
	if (rc) {
		CERROR("file attribute read error for "DFID": %d.\n",
			PFID(mdt_object_fid(mo)), rc);
		RETURN(rc);
	}

	/* If an up2date copy exists in the backend, add dirty flag */
	if ((ma->ma_valid & MA_HSM) && (ma->ma_hsm.mh_flags & HS_EXISTS)
	    && !(ma->ma_hsm.mh_flags & (HS_DIRTY|HS_RELEASED))) {
		struct mdt_lock_handle  *lh = &info->mti_lh[MDT_LH_CHILD];

		ma->ma_hsm.mh_flags |= HS_DIRTY;

		mdt_lock_reg_init(lh, LCK_PW);
		rc = mdt_object_lock(info, mo, lh, MDS_INODELOCK_XATTR,
				     MDT_LOCAL_LOCK);
		if (rc != 0)
			RETURN(rc);

		rc = mdt_hsm_attr_set(info, mo, &ma->ma_hsm);
		if (rc)
			CERROR("file attribute change error for "DFID": %d\n",
				PFID(mdt_object_fid(mo)), rc);
		mdt_object_unlock(info, mo, lh, rc);
	}

	RETURN(rc);
}

static int mdt_reint_setattr(struct mdt_thread_info *info,
                             struct mdt_lock_handle *lhc)
{
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = &req->rq_export->exp_mdt_data;
        struct mdt_file_data    *mfd;
        struct mdt_object       *mo;
        struct mdt_body         *repbody;
        int                      som_au, rc, rc2;
        ENTRY;

        DEBUG_REQ(D_INODE, req, "setattr "DFID" %x", PFID(rr->rr_fid1),
                  (unsigned int)ma->ma_attr.la_valid);

        if (info->mti_dlm_req)
                ldlm_request_cancel(req, info->mti_dlm_req, 0);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        mo = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
        if (IS_ERR(mo))
                GOTO(out, rc = PTR_ERR(mo));

        /* start a log jounal handle if needed */
        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM)) {
                if ((ma->ma_attr.la_valid & LA_SIZE) ||
                    (rr->rr_flags & MRF_OPEN_TRUNC)) {
                        /* Check write access for the O_TRUNC case */
                        if (mdt_write_read(mo) < 0)
                                GOTO(out_put, rc = -ETXTBSY);
                }
        } else if (info->mti_ioepoch &&
                   (info->mti_ioepoch->flags & MF_EPOCH_OPEN)) {
                /* Truncate case. IOEpoch is opened. */
                rc = mdt_write_get(mo);
                if (rc)
                        GOTO(out_put, rc);

		mfd = mdt_mfd_new(med);
                if (mfd == NULL) {
                        mdt_write_put(mo);
                        GOTO(out_put, rc = -ENOMEM);
                }

                mdt_ioepoch_open(info, mo, 0);
                repbody->ioepoch = mo->mot_ioepoch;

                mdt_object_get(info->mti_env, mo);
                mdt_mfd_set_mode(mfd, MDS_FMODE_TRUNC);
                mfd->mfd_object = mo;
                mfd->mfd_xid = req->rq_xid;

		spin_lock(&med->med_open_lock);
		cfs_list_add(&mfd->mfd_list, &med->med_open_head);
		spin_unlock(&med->med_open_lock);
                repbody->handle.cookie = mfd->mfd_handle.h_cookie;
        }

        som_au = info->mti_ioepoch && info->mti_ioepoch->flags & MF_SOM_CHANGE;
        if (som_au) {
                /* SOM Attribute update case. Find the proper mfd and update
                 * SOM attributes on the proper object. */
                LASSERT(mdt_conn_flags(info) & OBD_CONNECT_SOM);
                LASSERT(info->mti_ioepoch);

		spin_lock(&med->med_open_lock);
		mfd = mdt_handle2mfd(med, &info->mti_ioepoch->handle,
				     req_is_replay(req));
		if (mfd == NULL) {
			spin_unlock(&med->med_open_lock);
                        CDEBUG(D_INODE, "no handle for file close: "
                               "fid = "DFID": cookie = "LPX64"\n",
                               PFID(info->mti_rr.rr_fid1),
                               info->mti_ioepoch->handle.cookie);
                        GOTO(out_put, rc = -ESTALE);
                }
                LASSERT(mfd->mfd_mode == MDS_FMODE_SOM);
                LASSERT(!(info->mti_ioepoch->flags & MF_EPOCH_CLOSE));

                class_handle_unhash(&mfd->mfd_handle);
                cfs_list_del_init(&mfd->mfd_list);
		spin_unlock(&med->med_open_lock);

                mdt_mfd_close(info, mfd);
	} else if ((ma->ma_valid & MA_INODE) && ma->ma_attr.la_valid) {
		LASSERT((ma->ma_valid & MA_LOV) == 0);
                rc = mdt_attr_set(info, mo, ma, rr->rr_flags);
                if (rc)
                        GOTO(out_put, rc);
	} else if ((ma->ma_valid & MA_LOV) && (ma->ma_valid & MA_INODE)) {
		struct lu_buf *buf  = &info->mti_buf;
		LASSERT(ma->ma_attr.la_valid == 0);
		buf->lb_buf = ma->ma_lmm;
		buf->lb_len = ma->ma_lmm_size;
		rc = mo_xattr_set(info->mti_env, mdt_object_child(mo),
				  buf, XATTR_NAME_LOV, 0);
		if (rc)
			GOTO(out_put, rc);
	} else
		LBUG();

	/* If file data is modified, add the dirty flag */
	if (ma->ma_attr_flags & MDS_DATA_MODIFIED)
		rc = mdt_add_dirty_flag(info, mo, ma);

        ma->ma_need = MA_INODE;
        ma->ma_valid = 0;
	rc = mdt_attr_get_complex(info, mo, ma);
        if (rc != 0)
                GOTO(out_put, rc);

        mdt_pack_attr2body(info, repbody, &ma->ma_attr, mdt_object_fid(mo));

	if (info->mti_mdt->mdt_opts.mo_oss_capa &&
	    exp_connect_flags(info->mti_exp) & OBD_CONNECT_OSS_CAPA &&
	    S_ISREG(lu_object_attr(&mo->mot_obj)) &&
	    (ma->ma_attr.la_valid & LA_SIZE) && !som_au) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA2);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_OSS_DEFAULT | CAPA_OPC_OSS_TRUNC;
                rc = mo_capa_get(info->mti_env, mdt_object_child(mo), capa, 0);
                if (rc)
                        GOTO(out_put, rc);
                repbody->valid |= OBD_MD_FLOSSCAPA;
        }

        EXIT;
out_put:
        mdt_object_put(info->mti_env, mo);
out:
        if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_SETATTR);

        mdt_client_compatibility(info);
        rc2 = mdt_fix_reply(info);
        if (rc == 0)
                rc = rc2;
        return rc;
}

static int mdt_reint_create(struct mdt_thread_info *info,
                            struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        int                     rc;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
                RETURN(err_serious(-ESTALE));

        if (info->mti_dlm_req)
                ldlm_request_cancel(mdt_info_req(info), info->mti_dlm_req, 0);

	LASSERT(info->mti_rr.rr_namelen > 0);
        switch (info->mti_attr.ma_attr.la_mode & S_IFMT) {
	case S_IFDIR:
		mdt_counter_incr(req, LPROC_MDT_MKDIR);
		break;
        case S_IFREG:
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
	case S_IFSOCK:
		/* Special file should stay on the same node as parent. */
		mdt_counter_incr(req, LPROC_MDT_MKNOD);
		break;
	default:
		CERROR("%s: Unsupported mode %o\n",
		       mdt_obd_name(info->mti_mdt),
		       info->mti_attr.ma_attr.la_mode);
		RETURN(err_serious(-EOPNOTSUPP));
	}

	rc = mdt_md_create(info);
	RETURN(rc);
}

/*
 * VBR: save parent version in reply and child version getting by its name.
 * Version of child is getting and checking during its lookup. If
 */
static int mdt_reint_unlink(struct mdt_thread_info *info,
                            struct mdt_lock_handle *lhc)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct lu_fid           *child_fid = &info->mti_tmp_fid1;
        struct mdt_object       *mp;
        struct mdt_object       *mc;
        struct mdt_lock_handle  *parent_lh;
        struct mdt_lock_handle  *child_lh;
        struct lu_name          *lname;
        int                      rc;
	int			 no_name = 0;
	ENTRY;

        DEBUG_REQ(D_INODE, req, "unlink "DFID"/%s", PFID(rr->rr_fid1),
                  rr->rr_name);

        if (info->mti_dlm_req)
                ldlm_request_cancel(req, info->mti_dlm_req, 0);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                RETURN(err_serious(-ENOENT));

	if (fid_is_obf(rr->rr_fid1) || fid_is_dot_lustre(rr->rr_fid1))
		RETURN(-EPERM);
        /*
	 * step 1: Found the parent.
         */
	mp = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(mp)) {
		rc = PTR_ERR(mp);
		GOTO(out, rc);
	}

	parent_lh = &info->mti_lh[MDT_LH_PARENT];
	lname = mdt_name(info->mti_env, (char *)rr->rr_name, rr->rr_namelen);
	if (mdt_object_remote(mp)) {
		mdt_lock_reg_init(parent_lh, LCK_EX);
		rc = mdt_remote_object_lock(info, mp, &parent_lh->mlh_rreg_lh,
					    parent_lh->mlh_rreg_mode,
					    MDS_INODELOCK_UPDATE);
		if (rc != ELDLM_OK)
			GOTO(put_parent, rc);

	} else {
		mdt_lock_pdo_init(parent_lh, LCK_PW, rr->rr_name,
				  rr->rr_namelen);
		rc = mdt_object_lock(info, mp, parent_lh, MDS_INODELOCK_UPDATE,
				     MDT_LOCAL_LOCK);
		if (rc)
			GOTO(put_parent, rc);

		rc = mdt_version_get_check_save(info, mp, 0);
		if (rc)
			GOTO(unlock_parent, rc);
	}

	/* step 2: find & lock the child */
	/* lookup child object along with version checking */
	fid_zero(child_fid);
	rc = mdt_lookup_version_check(info, mp, lname, child_fid, 1);
	if (rc != 0) {
		/* Name might not be able to find during resend of
		 * remote unlink, considering following case.
		 * dir_A is a remote directory, the name entry of
		 * dir_A is on MDT0, the directory is on MDT1,
		 *
		 * 1. client sends unlink req to MDT1.
		 * 2. MDT1 sends name delete update to MDT0.
		 * 3. name entry is being deleted in MDT0 synchronously.
		 * 4. MDT1 is restarted.
		 * 5. client resends unlink req to MDT1. So it can not
		 *    find the name entry on MDT0 anymore.
		 * In this case, MDT1 only needs to destory the local
		 * directory.
		 * */
		if (mdt_object_remote(mp) && rc == -ENOENT &&
		    !fid_is_zero(rr->rr_fid2) &&
		    lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
			no_name = 1;
			*child_fid = *rr->rr_fid2;
		 } else {
			GOTO(unlock_parent, rc);
		 }
	}

	if (fid_is_obf(child_fid) || fid_is_dot_lustre(child_fid))
		GOTO(unlock_parent, rc = -EPERM);

        mdt_reint_init_ma(info, ma);

	/* We will lock the child regardless it is local or remote. No harm. */
	mc = mdt_object_find(info->mti_env, info->mti_mdt, child_fid);
	if (IS_ERR(mc))
		GOTO(unlock_parent, rc = PTR_ERR(mc));

        child_lh = &info->mti_lh[MDT_LH_CHILD];
        mdt_lock_reg_init(child_lh, LCK_EX);
	if (mdt_object_remote(mc)) {
		struct mdt_body	 *repbody;

		if (!fid_is_zero(rr->rr_fid2)) {
			CDEBUG(D_INFO, "%s: name %s can not find "DFID"\n",
			       mdt_obd_name(info->mti_mdt),
			       (char *)rr->rr_name, PFID(mdt_object_fid(mc)));
			GOTO(put_child, rc = -ENOENT);
		}
		CDEBUG(D_INFO, "%s: name %s: "DFID" is another MDT\n",
		       mdt_obd_name(info->mti_mdt),
		       (char *)rr->rr_name, PFID(mdt_object_fid(mc)));

		if (!mdt_is_dne_client(req->rq_export))
			/* Return -EIO for old client */
			GOTO(put_child, rc = -EIO);

		if (info->mti_spec.sp_rm_entry) {
			struct lu_ucred *uc  = mdt_ucred(info);

			if (!md_capable(uc, CFS_CAP_SYS_ADMIN)) {
				CERROR("%s: unlink remote entry is only "
				       "permitted for administrator: rc = %d\n",
					mdt_obd_name(info->mti_mdt),
					-EPERM);
				GOTO(put_child, rc = -EPERM);
			}

			ma->ma_need = MA_INODE;
			ma->ma_valid = 0;
			mdt_set_capainfo(info, 1, child_fid, BYPASS_CAPA);
			rc = mdo_unlink(info->mti_env, mdt_object_child(mp),
					NULL, lname, ma, no_name);
			GOTO(put_child, rc);
		}
		/* Revoke the LOOKUP lock of the remote object granted by
		 * this MDT. Since the unlink will happen on another MDT,
		 * it will release the LOOKUP lock right away. Then What
		 * would happen if another client try to grab the LOOKUP
		 * lock at the same time with unlink XXX */
		mdt_object_lock(info, mc, child_lh, MDS_INODELOCK_LOOKUP,
				MDT_CROSS_LOCK);
		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		LASSERT(repbody != NULL);
		repbody->fid1 = *mdt_object_fid(mc);
		repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
		GOTO(unlock_child, rc = -EREMOTE);
	} else if (info->mti_spec.sp_rm_entry) {
		rc = -EPERM;
		CDEBUG(D_INFO, "%s: no rm_entry on local dir '%s': rc = %d\n",
		       mdt_obd_name(info->mti_mdt), (char *)rr->rr_name, rc);
		GOTO(put_child, rc);
	}

	/* We used to acquire MDS_INODELOCK_FULL here but we can't do
	 * this now because a running HSM restore on the child (unlink
	 * victim) will hold the layout lock. See LU-4002. */
	rc = mdt_object_lock(info, mc, child_lh,
			     MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE,
			     MDT_CROSS_LOCK);
	if (rc != 0)
		GOTO(put_child, rc);

        mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_UNLINK_WRITE);
        /* save version when object is locked */
        mdt_version_get_save(info, mc, 1);
	/*
	 * Now we can only make sure we need MA_INODE, in mdd layer, will check
	 * whether need MA_LOV and MA_COOKIE.
	 */
	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;
	mdt_set_capainfo(info, 1, child_fid, BYPASS_CAPA);

	mutex_lock(&mc->mot_lov_mutex);

	rc = mdo_unlink(info->mti_env, mdt_object_child(mp),
			mdt_object_child(mc), lname, ma, no_name);

	mutex_unlock(&mc->mot_lov_mutex);

	if (rc == 0 && !lu_object_is_dying(&mc->mot_header))
		rc = mdt_attr_get_complex(info, mc, ma);
	if (rc == 0)
		mdt_handle_last_unlink(info, mc, ma);

        if (ma->ma_valid & MA_INODE) {
                switch (ma->ma_attr.la_mode & S_IFMT) {
                case S_IFDIR:
			mdt_counter_incr(req, LPROC_MDT_RMDIR);
                        break;
                case S_IFREG:
                case S_IFLNK:
                case S_IFCHR:
                case S_IFBLK:
                case S_IFIFO:
                case S_IFSOCK:
			mdt_counter_incr(req, LPROC_MDT_UNLINK);
                        break;
                default:
                        LASSERTF(0, "bad file type %o unlinking\n",
                                 ma->ma_attr.la_mode);
                }
        }

        EXIT;
unlock_child:
	mdt_object_unlock(info, mc, child_lh, rc);
put_child:
	mdt_object_put(info->mti_env, mc);
unlock_parent:
	mdt_object_unlock(info, mp, parent_lh, rc);
put_parent:
	mdt_object_put(info->mti_env, mp);
out:
        return rc;
}

/*
 * VBR: save versions in reply: 0 - parent; 1 - child by fid; 2 - target by
 * name.
 */
static int mdt_reint_link(struct mdt_thread_info *info,
                          struct mdt_lock_handle *lhc)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_object       *ms;
        struct mdt_object       *mp;
        struct mdt_lock_handle  *lhs;
        struct mdt_lock_handle  *lhp;
        struct lu_name          *lname;
        int rc;
        ENTRY;

        DEBUG_REQ(D_INODE, req, "link "DFID" to "DFID"/%s",
                  PFID(rr->rr_fid1), PFID(rr->rr_fid2), rr->rr_name);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
                RETURN(err_serious(-ENOENT));

        if (info->mti_dlm_req)
                ldlm_request_cancel(req, info->mti_dlm_req, 0);

        /* Invalid case so return error immediately instead of
         * processing it */
        if (lu_fid_eq(rr->rr_fid1, rr->rr_fid2))
                RETURN(-EPERM);

	if (fid_is_obf(rr->rr_fid1) || fid_is_dot_lustre(rr->rr_fid1) ||
	    fid_is_obf(rr->rr_fid2) || fid_is_dot_lustre(rr->rr_fid2))
		RETURN(-EPERM);

        /* step 1: find & lock the target parent dir */
        lhp = &info->mti_lh[MDT_LH_PARENT];
        mdt_lock_pdo_init(lhp, LCK_PW, rr->rr_name,
                          rr->rr_namelen);
        mp = mdt_object_find_lock(info, rr->rr_fid2, lhp,
                                  MDS_INODELOCK_UPDATE);
        if (IS_ERR(mp))
                RETURN(PTR_ERR(mp));

        rc = mdt_version_get_check_save(info, mp, 0);
        if (rc)
                GOTO(out_unlock_parent, rc);

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME3, 5);

        /* step 2: find & lock the source */
        lhs = &info->mti_lh[MDT_LH_CHILD];
        mdt_lock_reg_init(lhs, LCK_EX);

        ms = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
        if (IS_ERR(ms))
                GOTO(out_unlock_parent, rc = PTR_ERR(ms));

	if (!mdt_object_exists(ms)) {
		mdt_object_put(info->mti_env, ms);
		CDEBUG(D_INFO, "%s: "DFID" does not exist.\n",
		       mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1));
		GOTO(out_unlock_parent, rc = -ENOENT);
	}

	if (mdt_object_remote(ms)) {
		mdt_object_put(info->mti_env, ms);
		CERROR("%s: source inode "DFID" on remote MDT from "DFID"\n",
		       mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
		       PFID(rr->rr_fid2));
		GOTO(out_unlock_parent, rc = -EXDEV);
	}

	rc = mdt_object_lock(info, ms, lhs, MDS_INODELOCK_UPDATE |
			     MDS_INODELOCK_XATTR, MDT_CROSS_LOCK);
        if (rc != 0) {
                mdt_object_put(info->mti_env, ms);
                GOTO(out_unlock_parent, rc);
        }

        /* step 3: link it */
        mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_LINK_WRITE);

        info->mti_mos = ms;
        rc = mdt_version_get_check_save(info, ms, 1);
        if (rc)
                GOTO(out_unlock_child, rc);

        lname = mdt_name(info->mti_env, (char *)rr->rr_name, rr->rr_namelen);
        /** check target version by name during replay */
        rc = mdt_lookup_version_check(info, mp, lname, &info->mti_tmp_fid1, 2);
        if (rc != 0 && rc != -ENOENT)
                GOTO(out_unlock_child, rc);
        /* save version of file name for replay, it must be ENOENT here */
        if (!req_is_replay(mdt_info_req(info))) {
		if (rc != -ENOENT) {
			CDEBUG(D_INFO, "link target %.*s existed!\n",
			       rr->rr_namelen, (char *)rr->rr_name);
			GOTO(out_unlock_child, rc = -EEXIST);
		}
                info->mti_ver[2] = ENOENT_VERSION;
                mdt_version_save(mdt_info_req(info), info->mti_ver[2], 2);
        }

        rc = mdo_link(info->mti_env, mdt_object_child(mp),
                      mdt_object_child(ms), lname, ma);

        if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_LINK);

        EXIT;
out_unlock_child:
        mdt_object_unlock_put(info, ms, lhs, rc);
out_unlock_parent:
        mdt_object_unlock_put(info, mp, lhp, rc);
        return rc;
}
/**
 * lock the part of the directory according to the hash of the name
 * (lh->mlh_pdo_hash) in parallel directory lock.
 */
static int mdt_pdir_hash_lock(struct mdt_thread_info *info,
			      struct mdt_lock_handle *lh,
			      struct mdt_object *obj, __u64 ibits)
{
	struct ldlm_res_id *res = &info->mti_res_id;
	struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
	ldlm_policy_data_t *policy = &info->mti_policy;
	int rc;

	/*
	 * Finish res_id initializing by name hash marking part of
	 * directory which is taking modification.
	 */
	LASSERT(lh->mlh_pdo_hash != 0);
	fid_build_pdo_res_name(mdt_object_fid(obj), lh->mlh_pdo_hash, res);
	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = ibits;
	/*
	 * Use LDLM_FL_LOCAL_ONLY for this lock. We do not know yet if it is
	 * going to be sent to client. If it is - mdt_intent_policy() path will
	 * fix it up and turn FL_LOCAL flag off.
	 */
	rc = mdt_fid_lock(ns, &lh->mlh_reg_lh, lh->mlh_reg_mode, policy,
			  res, LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB,
			  &info->mti_exp->exp_handle.h_cookie);
	return rc;
}

static int mdt_rename_lock(struct mdt_thread_info *info,
                           struct lustre_handle *lh)
{
	struct ldlm_namespace	*ns = info->mti_mdt->mdt_namespace;
	ldlm_policy_data_t	*policy = &info->mti_policy;
	struct ldlm_res_id	*res_id = &info->mti_res_id;
	__u64			flags = 0;
	int rc;
	ENTRY;

	fid_build_reg_res_name(&LUSTRE_BFL_FID, res_id);

	memset(policy, 0, sizeof *policy);
	policy->l_inodebits.bits = MDS_INODELOCK_UPDATE;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 5, 53, 0)
	/* In phase I, we will not do cross-rename, so local BFL lock would
	 * be enough
	 */
	flags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
	/*
	 * Current node is controller, that is mdt0, where we should
	 * take BFL lock.
	 */
	rc = ldlm_cli_enqueue_local(ns, res_id, LDLM_IBITS, policy,
				    LCK_EX, &flags, ldlm_blocking_ast,
				    ldlm_completion_ast, NULL, NULL, 0,
				    LVB_T_NONE,
				    &info->mti_exp->exp_handle.h_cookie,
				    lh);
#else
#warning "Local rename lock is invalid for DNE phase II."
#endif
        RETURN(rc);
}

static void mdt_rename_unlock(struct lustre_handle *lh)
{
        ENTRY;
        LASSERT(lustre_handle_is_used(lh));
        ldlm_lock_decref(lh, LCK_EX);
        EXIT;
}

/*
 * This is is_subdir() variant, it is CMD if cmm forwards it to correct
 * target. Source should not be ancestor of target dir. May be other rename
 * checks can be moved here later.
 */
static int mdt_is_subdir_internal(struct mdt_thread_info *info,
			 struct mdt_object *dir,
			 const struct lu_fid *fid)
{
	struct lu_fid dir_fid = dir->mot_header.loh_fid;
        int rc = 0;
        ENTRY;

	/* If the source and target are in the same directory, they can not
	 * be parent/child relationship, so subdir check is not needed */
	if (lu_fid_eq(&dir_fid, fid))
		RETURN(0);

	if (!mdt_object_exists(dir))
		RETURN(-ENOENT);

	rc = mdo_is_subdir(info->mti_env, mdt_object_child(dir),
			   fid, &dir_fid);
	if (rc < 0) {
		CERROR("%s: failed subdir check in "DFID" for "DFID
		       ": rc = %d\n", mdt_obd_name(info->mti_mdt),
		       PFID(&dir_fid), PFID(fid), rc);
		/* Return EINVAL only if a parent is the @fid */
		if (rc == -EINVAL)
			rc = -EIO;
	} else {
		/* check the found fid */
		if (lu_fid_eq(&dir_fid, fid))
			rc = -EINVAL;
	}

        RETURN(rc);
}

static struct mdt_object *mdt_object_find_check(struct mdt_thread_info *info,
						const struct lu_fid *fid,
						int idx)
{
	struct mdt_object *dir;
	int rc;
	ENTRY;

	dir = mdt_object_find(info->mti_env, info->mti_mdt, fid);
	if (IS_ERR(dir))
		RETURN(dir);

	/* check early, the real version will be saved after locking */
	rc = mdt_version_get_check(info, dir, idx);
	if (rc)
		GOTO(out_put, rc);

	RETURN(dir);
out_put:
	mdt_object_put(info->mti_env, dir);
	return ERR_PTR(rc);
}

static int mdt_object_lock_save(struct mdt_thread_info *info,
				struct mdt_object *dir,
				struct mdt_lock_handle *lh,
				int idx)
{
	int rc;

	/* we lock the target dir if it is local */
	rc = mdt_object_lock(info, dir, lh, MDS_INODELOCK_UPDATE,
			     MDT_LOCAL_LOCK);
	if (rc != 0)
		return rc;

	/* get and save correct version after locking */
	mdt_version_get_save(info, dir, idx);
	return 0;
}


static int mdt_rename_parents_lock(struct mdt_thread_info *info,
				   struct mdt_object **srcp,
				   struct mdt_object **tgtp)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	const struct lu_fid     *fid_src = rr->rr_fid1;
	const struct lu_fid     *fid_tgt = rr->rr_fid2;
	struct mdt_lock_handle  *lh_src = &info->mti_lh[MDT_LH_PARENT];
	struct mdt_lock_handle  *lh_tgt = &info->mti_lh[MDT_LH_CHILD];
	struct mdt_object       *src;
	struct mdt_object       *tgt;
	int                      reverse = 0;
	int                      rc;
	ENTRY;

	/* find both parents. */
	src = mdt_object_find_check(info, fid_src, 0);
	if (IS_ERR(src))
		RETURN(PTR_ERR(src));

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME3, 5);

	if (lu_fid_eq(fid_src, fid_tgt)) {
		tgt = src;
		mdt_object_get(info->mti_env, tgt);
	} else {
		/* Check if the @src is not a child of the @tgt, otherwise a
		 * reverse locking must take place. */
		rc = mdt_is_subdir_internal(info, src, fid_tgt);
		if (rc == -EINVAL)
			reverse = 1;
		else if (rc)
			GOTO(err_src_put, rc);

		tgt = mdt_object_find_check(info, fid_tgt, 1);
		if (IS_ERR(tgt))
			GOTO(err_src_put, rc = PTR_ERR(tgt));

		if (unlikely(mdt_object_remote(tgt))) {
			CDEBUG(D_INFO, "Source dir "DFID" target dir "DFID
			       "on different MDTs\n", PFID(fid_src),
			       PFID(fid_tgt));
			GOTO(err_tgt_put, rc = -EXDEV);
		}
	}

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME4, 5);

	/* lock parents in the proper order. */
	if (reverse) {
		rc = mdt_object_lock_save(info, tgt, lh_tgt, 1);
		if (rc)
			GOTO(err_tgt_put, rc);

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME, 5);

		rc = mdt_object_lock_save(info, src, lh_src, 0);
	} else {
		rc = mdt_object_lock_save(info, src, lh_src, 0);
		if (rc)
			GOTO(err_tgt_put, rc);

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME, 5);

		if (tgt != src)
			rc = mdt_object_lock_save(info, tgt, lh_tgt, 1);
		else if (lh_src->mlh_pdo_hash != lh_tgt->mlh_pdo_hash) {
			rc = mdt_pdir_hash_lock(info, lh_tgt, tgt,
						MDS_INODELOCK_UPDATE);
			OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PDO_LOCK2, 10);
		}
	}
	if (rc)
		GOTO(err_unlock, rc);

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME4, 5);

	*srcp = src;
	*tgtp = tgt;
	RETURN(0);

err_unlock:
	/* The order does not matter as the handle is checked inside,
	 * as well as not used handle. */
	mdt_object_unlock(info, src, lh_src, rc);
	mdt_object_unlock(info, tgt, lh_tgt, rc);
err_tgt_put:
	mdt_object_put(info->mti_env, tgt);
err_src_put:
	mdt_object_put(info->mti_env, src);
	RETURN(rc);
}

/*
 * VBR: rename versions in reply: 0 - src parent; 1 - tgt parent;
 * 2 - src child; 3 - tgt child.
 * Update on disk version of src child.
 */
/**
 * For DNE phase I, only these renames are allowed
 *	mv src_p/src_c tgt_p/tgt_c
 * 1. src_p/src_c/tgt_p/tgt_c are in the same MDT.
 * 2. src_p and tgt_p are same directory, and tgt_c does not
 *    exists. In this case, all of modification will happen
 *    in the MDT where ithesource parent is, only one remote
 *    update is needed, i.e. set c_time/m_time on the child.
 *    And tgt_c will be still in the same MDT as the original
 *    src_c.
 */
static int mdt_reint_rename(struct mdt_thread_info *info,
                            struct mdt_lock_handle *lhc)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct md_attr          *ma = &info->mti_attr;
        struct ptlrpc_request   *req = mdt_info_req(info);
	struct mdt_object       *msrcdir = NULL;
	struct mdt_object       *mtgtdir = NULL;
        struct mdt_object       *mold;
        struct mdt_object       *mnew = NULL;
        struct mdt_lock_handle  *lh_srcdirp;
        struct mdt_lock_handle  *lh_tgtdirp;
        struct mdt_lock_handle  *lh_oldp;
        struct mdt_lock_handle  *lh_newp;
        struct lu_fid           *old_fid = &info->mti_tmp_fid1;
        struct lu_fid           *new_fid = &info->mti_tmp_fid2;
        struct lustre_handle     rename_lh = { 0 };
        struct lu_name           slname = { 0 };
        struct lu_name          *lname;
        int                      rc;
        ENTRY;

        if (info->mti_dlm_req)
                ldlm_request_cancel(req, info->mti_dlm_req, 0);

        DEBUG_REQ(D_INODE, req, "rename "DFID"/%s to "DFID"/%s",
                  PFID(rr->rr_fid1), rr->rr_name,
                  PFID(rr->rr_fid2), rr->rr_tgt);

	if (fid_is_obf(rr->rr_fid1) || fid_is_dot_lustre(rr->rr_fid1) ||
	    fid_is_obf(rr->rr_fid2) || fid_is_dot_lustre(rr->rr_fid2))
		RETURN(-EPERM);

	rc = mdt_rename_lock(info, &rename_lh);
	if (rc) {
		CERROR("Can't lock FS for rename, rc %d\n", rc);
		RETURN(rc);
	}

        lh_newp = &info->mti_lh[MDT_LH_NEW];

        lh_srcdirp = &info->mti_lh[MDT_LH_PARENT];
        mdt_lock_pdo_init(lh_srcdirp, LCK_PW, rr->rr_name,
                          rr->rr_namelen);
        lh_tgtdirp = &info->mti_lh[MDT_LH_CHILD];
        mdt_lock_pdo_init(lh_tgtdirp, LCK_PW, rr->rr_tgt,
                          rr->rr_tgtlen);

	/* step 1&2: lock the source and target dirs. */
	rc = mdt_rename_parents_lock(info, &msrcdir, &mtgtdir);
	if (rc)
		GOTO(out_rename_lock, rc);

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME2, 5);

	/* step 3: find & lock the old object. */
	lname = mdt_name(info->mti_env, (char *)rr->rr_name, rr->rr_namelen);
	mdt_name_copy(&slname, lname);
	fid_zero(old_fid);
	rc = mdt_lookup_version_check(info, msrcdir, &slname, old_fid, 2);
	if (rc != 0)
		GOTO(out_unlock_parents, rc);

	if (lu_fid_eq(old_fid, rr->rr_fid1) || lu_fid_eq(old_fid, rr->rr_fid2))
		GOTO(out_unlock_parents, rc = -EINVAL);

	if (fid_is_obf(old_fid) || fid_is_dot_lustre(old_fid))
		GOTO(out_unlock_parents, rc = -EPERM);

	mold = mdt_object_find(info->mti_env, info->mti_mdt, old_fid);
	if (IS_ERR(mold))
		GOTO(out_unlock_parents, rc = PTR_ERR(mold));

	/* Check if @mtgtdir is subdir of @mold, before locking child
	 * to avoid reverse locking. */
	rc = mdt_is_subdir_internal(info, mtgtdir, old_fid);
	if (rc)
		GOTO(out_put_old, rc);

        lh_oldp = &info->mti_lh[MDT_LH_OLD];
        mdt_lock_reg_init(lh_oldp, LCK_EX);
	rc = mdt_object_lock(info, mold, lh_oldp, MDS_INODELOCK_LOOKUP |
			     MDS_INODELOCK_XATTR, MDT_CROSS_LOCK);
	if (rc != 0)
		GOTO(out_put_old, rc);

        info->mti_mos = mold;
        /* save version after locking */
        mdt_version_get_save(info, mold, 2);
        mdt_set_capainfo(info, 2, old_fid, BYPASS_CAPA);

        /* step 4: find & lock the new object. */
        /* new target object may not exist now */
        lname = mdt_name(info->mti_env, (char *)rr->rr_tgt, rr->rr_tgtlen);
        /* lookup with version checking */
        fid_zero(new_fid);
        rc = mdt_lookup_version_check(info, mtgtdir, lname, new_fid, 3);
        if (rc == 0) {
                /* the new_fid should have been filled at this moment */
                if (lu_fid_eq(old_fid, new_fid))
                       GOTO(out_unlock_old, rc);

                if (lu_fid_eq(new_fid, rr->rr_fid1) ||
                    lu_fid_eq(new_fid, rr->rr_fid2))
                        GOTO(out_unlock_old, rc = -EINVAL);

		if (fid_is_obf(new_fid) || fid_is_dot_lustre(new_fid))
			GOTO(out_unlock_old, rc = -EPERM);

		if (mdt_object_remote(mold)) {
			CDEBUG(D_INFO, "Src child "DFID" is on another MDT\n",
			       PFID(old_fid));
			GOTO(out_unlock_old, rc = -EXDEV);
		}

                mdt_lock_reg_init(lh_newp, LCK_EX);
                mnew = mdt_object_find(info->mti_env, info->mti_mdt, new_fid);
                if (IS_ERR(mnew))
                        GOTO(out_unlock_old, rc = PTR_ERR(mnew));

		if (mdt_object_remote(mnew)) {
			CDEBUG(D_INFO, "src child "DFID" is on another MDT\n",
			       PFID(new_fid));
			GOTO(out_put_new, rc = -EXDEV);
		}

		/* Before locking the target dir, check we do not replace
		* a dir with a non-dir, otherwise it may deadlock with
		* link op which tries to create a link in this dir
		* back to this non-dir. */
		if (S_ISDIR(lu_object_attr(&mnew->mot_obj)) &&
		    !S_ISDIR(lu_object_attr(&mold->mot_obj)))
			GOTO(out_put_new, rc = -EISDIR);

		/* Check if @msrcdir is subdir of @mnew, before locking child
		 * to avoid reverse locking. */
		rc = mdt_is_subdir_internal(info, msrcdir, new_fid);
		if (rc)
			GOTO(out_put_new, rc);

		/* We used to acquire MDS_INODELOCK_FULL here but we
		 * can't do this now because a running HSM restore on
		 * the rename onto victim will hold the layout
		 * lock. See LU-4002. */
		rc = mdt_object_lock(info, mnew, lh_newp,
				     MDS_INODELOCK_LOOKUP |
				     MDS_INODELOCK_UPDATE,
				     MDT_CROSS_LOCK);
		if (rc != 0)
			GOTO(out_put_new, rc);

                /* get and save version after locking */
                mdt_version_get_save(info, mnew, 3);
                mdt_set_capainfo(info, 3, new_fid, BYPASS_CAPA);
        } else if (rc != -EREMOTE && rc != -ENOENT) {
		GOTO(out_unlock_new, rc);
        } else {
		/* If mnew does not exist and mold are remote directory,
		 * it only allows rename if they are under same directory */
		if (mtgtdir != msrcdir && mdt_object_remote(mold)) {
			CDEBUG(D_INFO, "Src child "DFID" is on another MDT\n",
			       PFID(old_fid));
			GOTO(out_unlock_new, rc = -EXDEV);
		}
		mdt_enoent_version_save(info, 3);
        }

        /* step 5: rename it */
        mdt_reint_init_ma(info, ma);

        mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_RENAME_WRITE);

	if (mnew != NULL)
		mutex_lock(&mnew->mot_lov_mutex);

	rc = mdo_rename(info->mti_env, mdt_object_child(msrcdir),
			mdt_object_child(mtgtdir), old_fid, &slname,
			(mnew ? mdt_object_child(mnew) : NULL),
			lname, ma);

	if (mnew != NULL)
		mutex_unlock(&mnew->mot_lov_mutex);

	/* handle last link of tgt object */
	if (rc == 0) {
		mdt_counter_incr(req, LPROC_MDT_RENAME);
		if (mnew)
			mdt_handle_last_unlink(info, mnew, ma);

		mdt_rename_counter_tally(info, info->mti_mdt, req,
					 msrcdir, mtgtdir);
        }

        EXIT;
out_unlock_new:
        if (mnew)
		mdt_object_unlock(info, mnew, lh_newp, rc);
out_put_new:
	if (mnew)
		mdt_object_put(info->mti_env, mnew);
out_unlock_old:
	mdt_object_unlock(info, mold, lh_oldp, rc);
out_put_old:
	mdt_object_put(info->mti_env, mold);
out_unlock_parents:
	mdt_object_unlock_put(info, mtgtdir, lh_tgtdirp, rc);
        mdt_object_unlock_put(info, msrcdir, lh_srcdirp, rc);
out_rename_lock:
	mdt_rename_unlock(&rename_lh);
	RETURN(rc);
}

typedef int (*mdt_reinter)(struct mdt_thread_info *info,
                           struct mdt_lock_handle *lhc);

static mdt_reinter reinters[REINT_MAX] = {
	[REINT_SETATTR]  = mdt_reint_setattr,
	[REINT_CREATE]   = mdt_reint_create,
	[REINT_LINK]     = mdt_reint_link,
	[REINT_UNLINK]   = mdt_reint_unlink,
	[REINT_RENAME]   = mdt_reint_rename,
	[REINT_OPEN]     = mdt_reint_open,
	[REINT_SETXATTR] = mdt_reint_setxattr,
	[REINT_RMENTRY]  = mdt_reint_unlink
};

int mdt_reint_rec(struct mdt_thread_info *info,
                  struct mdt_lock_handle *lhc)
{
        int rc;
        ENTRY;

        rc = reinters[info->mti_rr.rr_opcode](info, lhc);

        RETURN(rc);
}
