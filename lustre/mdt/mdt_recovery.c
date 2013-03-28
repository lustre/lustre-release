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
 * lustre/mdt/mdt_recovery.c
 *
 * Lustre Metadata Target (mdt) recovery-related methods
 *
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Pershin Mike <tappro@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

struct lu_buf *mdt_buf(const struct lu_env *env, void *area, ssize_t len)
{
        struct lu_buf *buf;
        struct mdt_thread_info *mti;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        buf = &mti->mti_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

const struct lu_buf *mdt_buf_const(const struct lu_env *env,
                                   const void *area, ssize_t len)
{
        struct lu_buf *buf;
        struct mdt_thread_info *mti;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        buf = &mti->mti_buf;

        buf->lb_buf = (void *)area;
        buf->lb_len = len;
        return buf;
}

void mdt_trans_stop(const struct lu_env *env,
                    struct mdt_device *mdt, struct thandle *th)
{
        dt_trans_stop(env, mdt->mdt_bottom, th);
}

static int mdt_clients_data_init(const struct lu_env *env,
                                 struct mdt_device *mdt,
                                 unsigned long last_size)
{
        struct lr_server_data  *lsd = &mdt->mdt_lut.lut_lsd;
        struct lsd_client_data *lcd;
        struct obd_device      *obd = mdt2obd_dev(mdt);
        loff_t off;
        int cl_idx;
        int rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(lcd);
        if (!lcd)
                RETURN(-ENOMEM);

        /* When we do a clean MDS shutdown, we save the last_transno into
         * the header.  If we find clients with higher last_transno values
         * then those clients may need recovery done. */
        LASSERT(cfs_atomic_read(&obd->obd_req_replay_clients) == 0);
        for (cl_idx = 0, off = lsd->lsd_client_start;
             off < last_size; cl_idx++) {
                __u64 last_transno;
                struct obd_export *exp;
                struct mdt_thread_info *mti;

                off = lsd->lsd_client_start +
                        cl_idx * lsd->lsd_client_size;

		rc = tgt_client_data_read(env, &mdt->mdt_lut, lcd, &off, cl_idx);
                if (rc) {
                        CERROR("error reading MDS %s idx %d, off %llu: rc %d\n",
                               LAST_RCVD, cl_idx, off, rc);
                        rc = 0;
                        break; /* read error shouldn't cause startup to fail */
                }

                if (lcd->lcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_transno = lcd_last_transno(lcd);

                /* These exports are cleaned up by mdt_obd_disconnect(), so
                 * they need to be set up like real exports as
                 * mdt_obd_connect() does.
                 */
                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64" lx: "LPU64"\n", lcd->lcd_uuid, cl_idx,
                       last_transno, lsd->lsd_last_transno,
                       lcd_last_xid(lcd));

                exp = class_new_export(obd, (struct obd_uuid *)lcd->lcd_uuid);
                if (IS_ERR(exp)) {
                        if (PTR_ERR(exp) == -EALREADY) {
                                /* export already exists, zero out this one */
                                CERROR("Duplicate export %s!\n", lcd->lcd_uuid);
                                continue;
                        }
                        GOTO(err_client, rc = PTR_ERR(exp));
                }

                mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
                LASSERT(mti != NULL);
                mti->mti_exp = exp;
                /* copy on-disk lcd to the export */
                *exp->exp_target_data.ted_lcd = *lcd;
		rc = tgt_client_add(env, exp, cl_idx);
                /* can't fail existing */
                LASSERTF(rc == 0, "rc = %d\n", rc);
                /* VBR: set export last committed version */
                exp->exp_last_committed = last_transno;
		spin_lock(&exp->exp_lock);
		exp->exp_connecting = 0;
		exp->exp_in_recovery = 0;
		spin_unlock(&exp->exp_lock);
		obd->obd_max_recoverable_clients++;
		class_export_put(exp);

		CDEBUG(D_OTHER, "client at idx %d has last_transno ="LPU64"\n",
		       cl_idx, last_transno);
		/* protect __u64 value update */
		spin_lock(&mdt->mdt_lut.lut_translock);
		mdt->mdt_lut.lut_last_transno = max(last_transno,
						mdt->mdt_lut.lut_last_transno);
		spin_unlock(&mdt->mdt_lut.lut_translock);
        }

err_client:
        OBD_FREE_PTR(lcd);
        RETURN(rc);
}

static int mdt_server_data_init(const struct lu_env *env,
                                struct mdt_device *mdt,
                                struct lustre_sb_info *lsi)
{
        struct lr_server_data  *lsd = &mdt->mdt_lut.lut_lsd;
        struct lsd_client_data *lcd = NULL;
        struct obd_device      *obd = mdt2obd_dev(mdt);
        struct mdt_thread_info *mti;
        struct dt_object       *obj;
        struct lu_attr         *la;
        unsigned long last_rcvd_size;
	__u32			index;
        __u64 mount_count;
        int rc;
        ENTRY;

        /* ensure padding in the struct is the correct size */
        CLASSERT(offsetof(struct lr_server_data, lsd_padding) +
                sizeof(lsd->lsd_padding) == LR_SERVER_SIZE);
        CLASSERT(offsetof(struct lsd_client_data, lcd_padding) +
                sizeof(lcd->lcd_padding) == LR_CLIENT_SIZE);

	rc = server_name2index(mdt_obd_name(mdt), &index, NULL);
	if (rc < 0) {
		CERROR("%s: Can not get index from obd_name: rc = %d\n",
		       mdt_obd_name(mdt), rc);
		RETURN(rc);
	}

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(mti != NULL);
        la = &mti->mti_attr.ma_attr;

        obj = mdt->mdt_lut.lut_last_rcvd;
	rc = dt_attr_get(env, obj, la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

	last_rcvd_size = (unsigned long)la->la_size;

	if (last_rcvd_size == 0) {
		LCONSOLE_WARN("%s: new disk, initializing\n",
			      mdt_obd_name(mdt));

		memcpy(lsd->lsd_uuid, obd->obd_uuid.uuid,
		       sizeof(lsd->lsd_uuid));
		lsd->lsd_last_transno = 0;
		lsd->lsd_mount_count = 0;
		lsd->lsd_server_size = LR_SERVER_SIZE;
		lsd->lsd_client_start = LR_CLIENT_START;
		lsd->lsd_client_size = LR_CLIENT_SIZE;
		lsd->lsd_feature_compat = OBD_COMPAT_MDT;
		lsd->lsd_feature_rocompat = OBD_ROCOMPAT_LOVOBJID;
		lsd->lsd_feature_incompat = OBD_INCOMPAT_MDT |
					    OBD_INCOMPAT_COMMON_LR |
					    OBD_INCOMPAT_MULTI_OI;
		lsd->lsd_osd_index = index;
	} else {
		LCONSOLE_WARN("%s: used disk, loading\n", mdt_obd_name(mdt));
		rc = tgt_server_data_read(env, &mdt->mdt_lut);
		if (rc) {
			CERROR("error reading MDS %s: rc %d\n", LAST_RCVD, rc);
			GOTO(out, rc);
		}
		if (strcmp(lsd->lsd_uuid, obd->obd_uuid.uuid) != 0) {
			LCONSOLE_ERROR_MSG(0x157, "Trying to start OBD %s using"
					   "the wrong disk %s. Were the /dev/ "
					   "assignments rearranged?\n",
					   obd->obd_uuid.uuid, lsd->lsd_uuid);
			GOTO(out, rc = -EINVAL);
		}
		lsd->lsd_feature_compat |= OBD_COMPAT_MDT;
		lsd->lsd_feature_incompat |= OBD_INCOMPAT_MDT |
						OBD_INCOMPAT_COMMON_LR;
		if (lsd->lsd_osd_index != index) {
			LCONSOLE_ERROR_MSG(0x157, "%s: index %d in last rcvd is"
					   "different with the index %d in"
					   "config log, It might be disk"
					   "corruption!\n", mdt_obd_name(mdt),
					   lsd->lsd_osd_index, index);
			GOTO(out, rc = -EINVAL);
		}
	}
	mount_count = lsd->lsd_mount_count;

	if (lsd->lsd_feature_incompat & ~MDT_INCOMPAT_SUPP) {
		CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
		       mdt_obd_name(mdt),
		       lsd->lsd_feature_incompat & ~MDT_INCOMPAT_SUPP);
		GOTO(out, rc = -EINVAL);
	}
	if (lsd->lsd_feature_rocompat & ~MDT_ROCOMPAT_SUPP) {
		CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
		       mdt_obd_name(mdt),
		       lsd->lsd_feature_rocompat & ~MDT_ROCOMPAT_SUPP);
		/* XXX: Do something like remount filesystem read-only */
		GOTO(out, rc = -EINVAL);
	}
	/** Interop: evict all clients at first boot with 1.8 last_rcvd */
	if (!(lsd->lsd_feature_compat & OBD_COMPAT_20)) {
		if (last_rcvd_size > lsd->lsd_client_start) {
			LCONSOLE_WARN("Mounting %s at first time on 1.8 FS, "
				      "remove all clients for interop needs\n",
				      mdt_obd_name(mdt));
			rc = tgt_truncate_last_rcvd(env, &mdt->mdt_lut,
						    lsd->lsd_client_start);
			if (rc)
				GOTO(out, rc);
			last_rcvd_size = lsd->lsd_client_start;
		}
		/** set 2.0 flag to upgrade/downgrade between 1.8 and 2.0 */
		lsd->lsd_feature_compat |= OBD_COMPAT_20;
	}

	lsd->lsd_feature_incompat |= OBD_INCOMPAT_FID;

	spin_lock(&mdt->mdt_lut.lut_translock);
	mdt->mdt_lut.lut_last_transno = lsd->lsd_last_transno;
	spin_unlock(&mdt->mdt_lut.lut_translock);

	CDEBUG(D_INODE, "=======,=BEGIN DUMPING LAST_RCVD========\n");
	CDEBUG(D_INODE, "%s: server last_transno: "LPU64"\n",
	       mdt_obd_name(mdt), mdt->mdt_lut.lut_last_transno);
	CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
	       mdt_obd_name(mdt), mount_count + 1);
	CDEBUG(D_INODE, "%s: server data size: %u\n",
	       mdt_obd_name(mdt), lsd->lsd_server_size);
	CDEBUG(D_INODE, "%s: per-client data start: %u\n",
	       mdt_obd_name(mdt), lsd->lsd_client_start);
	CDEBUG(D_INODE, "%s: per-client data size: %u\n",
	       mdt_obd_name(mdt), lsd->lsd_client_size);
	CDEBUG(D_INODE, "%s: last_rcvd size: %lu\n",
	       mdt_obd_name(mdt), last_rcvd_size);
	CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", mdt_obd_name(mdt),
	       last_rcvd_size <= lsd->lsd_client_start ? 0 :
	       (last_rcvd_size - lsd->lsd_client_start) /
		lsd->lsd_client_size);
	CDEBUG(D_INODE, "========END DUMPING LAST_RCVD========\n");

        if (!lsd->lsd_server_size || !lsd->lsd_client_start ||
            !lsd->lsd_client_size) {
                CERROR("Bad last_rcvd contents!\n");
                GOTO(out, rc = -EINVAL);
        }

        rc = mdt_clients_data_init(env, mdt, last_rcvd_size);
        if (rc)
                GOTO(err_client, rc);

	spin_lock(&mdt->mdt_lut.lut_translock);
	/* obd_last_committed is used for compatibility
	 * with other lustre recovery code */
	obd->obd_last_committed = mdt->mdt_lut.lut_last_transno;
	spin_unlock(&mdt->mdt_lut.lut_translock);

        obd->u.obt.obt_mount_count = mount_count + 1;
        obd->u.obt.obt_instance = (__u32)obd->u.obt.obt_mount_count;
        lsd->lsd_mount_count = obd->u.obt.obt_mount_count;

        /* save it, so mount count and last_transno is current */
	rc = tgt_server_data_update(env, &mdt->mdt_lut, 0);
        if (rc)
                GOTO(err_client, rc);

        RETURN(0);

err_client:
        class_disconnect_exports(obd);
out:
        return rc;
}

/*
 * last_rcvd & last_committed update callbacks
 */
static int mdt_last_rcvd_update(struct mdt_thread_info *mti,
                                struct thandle *th)
{
        struct mdt_device *mdt = mti->mti_mdt;
        struct ptlrpc_request *req = mdt_info_req(mti);
        struct tg_export_data *ted;
        struct lsd_client_data *lcd;
        loff_t off;
        int err;
        __s32 rc = th->th_result;

        ENTRY;
        LASSERT(req);
        LASSERT(req->rq_export);
        LASSERT(mdt);
        ted = &req->rq_export->exp_target_data;
        LASSERT(ted);

	mutex_lock(&ted->ted_lcd_lock);
	lcd = ted->ted_lcd;
	/* if the export has already been disconnected, we have no last_rcvd
	 * slot, update server data with latest transno then */
	if (lcd == NULL) {
		mutex_unlock(&ted->ted_lcd_lock);
                CWARN("commit transaction for disconnected client %s: rc %d\n",
                      req->rq_export->exp_client_uuid.uuid, rc);
		err = tgt_server_data_write(mti->mti_env, &mdt->mdt_lut, th);
                RETURN(err);
        }

        off = ted->ted_lr_off;
        LASSERT(ergo(mti->mti_transno == 0, rc != 0));
        if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE ||
            lustre_msg_get_opc(req->rq_reqmsg) == MDS_DONE_WRITING) {
                if (mti->mti_transno != 0) {
                        if (lcd->lcd_last_close_transno > mti->mti_transno) {
                                CERROR("Trying to overwrite bigger transno:"
                                       "on-disk: "LPU64", new: "LPU64" "
                                       "replay: %d. see LU-617.\n",
                                       lcd->lcd_last_close_transno,
                                       mti->mti_transno, req_is_replay(req));
                                if (req_is_replay(req)) {
					spin_lock(&req->rq_export->exp_lock);
					req->rq_export->exp_vbr_failed = 1;
					spin_unlock(&req->rq_export->exp_lock);
				}
				mutex_unlock(&ted->ted_lcd_lock);
                                RETURN(req_is_replay(req) ? -EOVERFLOW : 0);
                        }
                        lcd->lcd_last_close_transno = mti->mti_transno;
                }
                lcd->lcd_last_close_xid = req->rq_xid;
                lcd->lcd_last_close_result = rc;
        } else {
                /* VBR: save versions in last_rcvd for reconstruct. */
                __u64 *pre_versions = lustre_msg_get_versions(req->rq_repmsg);
                if (pre_versions) {
                        lcd->lcd_pre_versions[0] = pre_versions[0];
                        lcd->lcd_pre_versions[1] = pre_versions[1];
                        lcd->lcd_pre_versions[2] = pre_versions[2];
                        lcd->lcd_pre_versions[3] = pre_versions[3];
                }
                if (mti->mti_transno != 0) {
                        if (lcd->lcd_last_transno > mti->mti_transno) {
                                CERROR("Trying to overwrite bigger transno:"
                                       "on-disk: "LPU64", new: "LPU64" "
                                       "replay: %d. see LU-617.\n",
                                       lcd->lcd_last_transno,
                                       mti->mti_transno, req_is_replay(req));
                                if (req_is_replay(req)) {
					spin_lock(&req->rq_export->exp_lock);
					req->rq_export->exp_vbr_failed = 1;
					spin_unlock(&req->rq_export->exp_lock);
				}
				mutex_unlock(&ted->ted_lcd_lock);
                                RETURN(req_is_replay(req) ? -EOVERFLOW : 0);
                        }
                        lcd->lcd_last_transno = mti->mti_transno;
                }
                lcd->lcd_last_xid = req->rq_xid;
                lcd->lcd_last_result = rc;
                /*XXX: save intent_disposition in mdt_thread_info?
                 * also there is bug - intent_dispostion is __u64,
                 * see struct ldlm_reply->lock_policy_res1; */
                lcd->lcd_last_data = mti->mti_opdata;
        }

	if (exp_connect_flags(mti->mti_exp) & OBD_CONNECT_LIGHTWEIGHT) {
		/* Although lightweight (LW) connections have no slot in
		 * last_rcvd, we still want to maintain the in-memory
		 * lsd_client_data structure in order to properly handle reply
		 * reconstruction. */
		struct lu_target	*tg = &mdt->mdt_lut;
		bool			 update = false;

		mutex_unlock(&ted->ted_lcd_lock);
		err = 0;

		/* All operations performed by LW clients are synchronous and
		 * we store the committed transno in the last_rcvd header */
		spin_lock(&tg->lut_translock);
		if (mti->mti_transno > tg->lut_lsd.lsd_last_transno) {
			tg->lut_lsd.lsd_last_transno = mti->mti_transno;
			update = true;
		}
		spin_unlock(&tg->lut_translock);

		if (update)
			err = tgt_server_data_write(mti->mti_env, tg, th);
	} else if (off <= 0) {
		CERROR("%s: client idx %d has offset %lld\n",
		       mdt_obd_name(mdt), ted->ted_lr_idx, off);
		mutex_unlock(&ted->ted_lcd_lock);
		err = -EINVAL;
	} else {
		err = tgt_client_data_write(mti->mti_env, &mdt->mdt_lut, lcd,
					    &off, th);
		mutex_unlock(&ted->ted_lcd_lock);
	}
	RETURN(err);
}

extern struct lu_context_key mdt_thread_key;

/* add credits for last_rcvd update */
static int mdt_txn_start_cb(const struct lu_env *env,
			    struct thandle *th, void *cookie)
{
	struct mdt_device *mdt = cookie;
	struct mdt_thread_info *mti;
	int rc;
	ENTRY;

	mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);

	LASSERT(mdt->mdt_lut.lut_last_rcvd);
	if (mti->mti_exp == NULL)
		RETURN(0);

	rc = dt_declare_record_write(env, mdt->mdt_lut.lut_last_rcvd,
				     sizeof(struct lsd_client_data),
				     mti->mti_exp->exp_target_data.ted_lr_off,
				     th);
	if (rc)
		return rc;

	rc = dt_declare_record_write(env, mdt->mdt_lut.lut_last_rcvd,
				     sizeof(struct lr_server_data), 0, th);
	if (rc)
		return rc;

	/* we probably should not set local transno to the remote object
	 * on another storage, What about VBR on remote object? XXX */
	if (mti->mti_mos != NULL && !mdt_object_remote(mti->mti_mos))
		rc = dt_declare_version_set(env, mdt_obj2dt(mti->mti_mos), th);

	return rc;
}

/* Update last_rcvd records with latests transaction data */
static int mdt_txn_stop_cb(const struct lu_env *env,
                           struct thandle *txn, void *cookie)
{
        struct mdt_device *mdt = cookie;
        struct mdt_thread_info *mti;
        struct ptlrpc_request *req;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        req = mdt_info_req(mti);

	if (mti->mti_mdt == NULL || req == NULL)
		return 0;

        if (mti->mti_has_trans) {
                /* XXX: currently there are allowed cases, but the wrong cases
                 * are also possible, so better check is needed here */
                CDEBUG(D_INFO, "More than one transaction "LPU64"\n",
                       mti->mti_transno);
                return 0;
        }

        mti->mti_has_trans = 1;
	spin_lock(&mdt->mdt_lut.lut_translock);
        if (txn->th_result != 0) {
                if (mti->mti_transno != 0) {
			CERROR("Replay transno "LPU64" failed: rc %d\n",
				mti->mti_transno, txn->th_result);
			spin_unlock(&mdt->mdt_lut.lut_translock);
			return 0;
                }
        } else if (mti->mti_transno == 0) {
                mti->mti_transno = ++ mdt->mdt_lut.lut_last_transno;
        } else {
                /* should be replay */
                if (mti->mti_transno > mdt->mdt_lut.lut_last_transno)
                        mdt->mdt_lut.lut_last_transno = mti->mti_transno;
        }
	spin_unlock(&mdt->mdt_lut.lut_translock);
        /* sometimes the reply message has not been successfully packed */
        LASSERT(req != NULL && req->rq_repmsg != NULL);

        /** VBR: set new versions */
	/* we probably should not set local transno to the remote object
	 * on another storage, What about VBR on remote object? XXX */
	if (txn->th_result == 0 && mti->mti_mos != NULL &&
	    !mdt_object_remote(mti->mti_mos)) {

                dt_version_set(env, mdt_obj2dt(mti->mti_mos),
                               mti->mti_transno, txn);
                mti->mti_mos = NULL;
        }

        /* filling reply data */
        CDEBUG(D_INODE, "transno = "LPU64", last_committed = "LPU64"\n",
               mti->mti_transno, req->rq_export->exp_obd->obd_last_committed);

        req->rq_transno = mti->mti_transno;
        lustre_msg_set_transno(req->rq_repmsg, mti->mti_transno);
        /* if can't add callback, do sync write */
        txn->th_sync |= !!tgt_last_commit_cb_add(txn, &mdt->mdt_lut,
                                                 mti->mti_exp,
                                                 mti->mti_transno);
        return mdt_last_rcvd_update(mti, txn);
}

int mdt_fs_setup(const struct lu_env *env, struct mdt_device *mdt,
                 struct obd_device *obd,
                 struct lustre_sb_info *lsi)
{
        int rc = 0;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FS_SETUP))
                RETURN(-ENOENT);

        /* prepare transactions callbacks */
        mdt->mdt_txn_cb.dtc_txn_start = mdt_txn_start_cb;
        mdt->mdt_txn_cb.dtc_txn_stop = mdt_txn_stop_cb;
        mdt->mdt_txn_cb.dtc_txn_commit = NULL;
        mdt->mdt_txn_cb.dtc_cookie = mdt;
        mdt->mdt_txn_cb.dtc_tag = LCT_MD_THREAD;
        CFS_INIT_LIST_HEAD(&mdt->mdt_txn_cb.dtc_linkage);

        dt_txn_callback_add(mdt->mdt_bottom, &mdt->mdt_txn_cb);

        rc = mdt_server_data_init(env, mdt, lsi);

	RETURN(rc);
}

void mdt_fs_cleanup(const struct lu_env *env, struct mdt_device *mdt)
{
        ENTRY;

        /* Remove transaction callback */
        dt_txn_callback_del(mdt->mdt_bottom, &mdt->mdt_txn_cb);
        if (mdt->mdt_ck_obj)
                lu_object_put(env, &mdt->mdt_ck_obj->do_lu);
        mdt->mdt_ck_obj = NULL;
        EXIT;
}

/* reconstruction code */
static void mdt_steal_ack_locks(struct ptlrpc_request *req)
{
	struct ptlrpc_service_part *svcpt;
        struct obd_export         *exp = req->rq_export;
        cfs_list_t                *tmp;
        struct ptlrpc_reply_state *oldrep;
        int                        i;

        /* CAVEAT EMPTOR: spinlock order */
	spin_lock(&exp->exp_lock);
        cfs_list_for_each (tmp, &exp->exp_outstanding_replies) {
                oldrep = cfs_list_entry(tmp, struct ptlrpc_reply_state,
                                        rs_exp_list);

                if (oldrep->rs_xid != req->rq_xid)
                        continue;

                if (oldrep->rs_opc != lustre_msg_get_opc(req->rq_reqmsg))
                        CERROR ("Resent req xid "LPU64" has mismatched opc: "
                                "new %d old %d\n", req->rq_xid,
                                lustre_msg_get_opc(req->rq_reqmsg),
                                oldrep->rs_opc);

		svcpt = oldrep->rs_svcpt;
		spin_lock(&svcpt->scp_rep_lock);

                cfs_list_del_init (&oldrep->rs_exp_list);

		CDEBUG(D_HA, "Stealing %d locks from rs %p x"LPD64".t"LPD64
		       " o%d NID %s\n",
		       oldrep->rs_nlocks, oldrep,
		       oldrep->rs_xid, oldrep->rs_transno, oldrep->rs_opc,
		       libcfs_nid2str(exp->exp_connection->c_peer.nid));

                for (i = 0; i < oldrep->rs_nlocks; i++)
                        ptlrpc_save_lock(req, &oldrep->rs_locks[i],
                                         oldrep->rs_modes[i], 0);
                oldrep->rs_nlocks = 0;

                DEBUG_REQ(D_HA, req, "stole locks for");
		spin_lock(&oldrep->rs_lock);
		ptlrpc_schedule_difficult_reply(oldrep);
		spin_unlock(&oldrep->rs_lock);

		spin_unlock(&svcpt->scp_rep_lock);
		break;
	}
	spin_unlock(&exp->exp_lock);
}

/**
 * VBR: restore versions
 */
void mdt_vbr_reconstruct(struct ptlrpc_request *req,
                         struct lsd_client_data *lcd)
{
        __u64 pre_versions[4] = {0};
        pre_versions[0] = lcd->lcd_pre_versions[0];
        pre_versions[1] = lcd->lcd_pre_versions[1];
        pre_versions[2] = lcd->lcd_pre_versions[2];
        pre_versions[3] = lcd->lcd_pre_versions[3];
        lustre_msg_set_versions(req->rq_repmsg, pre_versions);
}

void mdt_req_from_lcd(struct ptlrpc_request *req,
                      struct lsd_client_data *lcd)
{
        DEBUG_REQ(D_HA, req, "restoring transno "LPD64"/status %d",
                  lcd->lcd_last_transno, lcd->lcd_last_result);

        if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE ||
            lustre_msg_get_opc(req->rq_repmsg) == MDS_DONE_WRITING) {
                req->rq_transno = lcd->lcd_last_close_transno;
                req->rq_status = lcd->lcd_last_close_result;
        } else {
                req->rq_transno = lcd->lcd_last_transno;
                req->rq_status = lcd->lcd_last_result;
                mdt_vbr_reconstruct(req, lcd);
        }
        if (req->rq_status != 0)
                req->rq_transno = 0;
        lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
        lustre_msg_set_status(req->rq_repmsg, req->rq_status);
        DEBUG_REQ(D_RPCTRACE, req, "restoring transno "LPD64"/status %d",
                  req->rq_transno, req->rq_status);

        mdt_steal_ack_locks(req);
}

void mdt_reconstruct_generic(struct mdt_thread_info *mti,
                             struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request *req = mdt_info_req(mti);
        struct tg_export_data *ted = &req->rq_export->exp_target_data;

        return mdt_req_from_lcd(req, ted->ted_lcd);
}

static void mdt_reconstruct_create(struct mdt_thread_info *mti,
                                   struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request  *req = mdt_info_req(mti);
        struct obd_export *exp = req->rq_export;
        struct tg_export_data *ted = &exp->exp_target_data;
        struct mdt_device *mdt = mti->mti_mdt;
        struct mdt_object *child;
        struct mdt_body *body;
        int rc;

        mdt_req_from_lcd(req, ted->ted_lcd);
        if (req->rq_status)
                return;

        /* if no error, so child was created with requested fid */
        child = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid2);
        if (IS_ERR(child)) {
                rc = PTR_ERR(child);
                LCONSOLE_WARN("Child "DFID" lookup error %d."
                              " Evicting client %s with export %s.\n",
                              PFID(mdt_object_fid(child)), rc,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp));
                mdt_export_evict(exp);
                EXIT;
                return;
        }

        body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
        mti->mti_attr.ma_need = MA_INODE;
        mti->mti_attr.ma_valid = 0;
	rc = mdt_attr_get_complex(mti, child, &mti->mti_attr);
	if (rc == -EREMOTE) {
		/* object was created on remote server */
		if (!mdt_is_dne_client(exp))
			/* Return -EIO for old client */
			rc = -EIO;

		req->rq_status = rc;
		body->valid |= OBD_MD_MDS;
	}
	mdt_pack_attr2body(mti, body, &mti->mti_attr.ma_attr,
			   mdt_object_fid(child));
	mdt_object_put(mti->mti_env, child);
}

static void mdt_reconstruct_setattr(struct mdt_thread_info *mti,
                                    struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request  *req = mdt_info_req(mti);
        struct obd_export *exp = req->rq_export;
        struct mdt_export_data *med = &exp->exp_mdt_data;
        struct mdt_device *mdt = mti->mti_mdt;
        struct mdt_object *obj;
        struct mdt_body *body;

        mdt_req_from_lcd(req, med->med_ted.ted_lcd);
        if (req->rq_status)
                return;

        body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
        obj = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid1);
        if (IS_ERR(obj)) {
                int rc = PTR_ERR(obj);
                LCONSOLE_WARN(""DFID" lookup error %d."
                              " Evicting client %s with export %s.\n",
                              PFID(mdt_object_fid(obj)), rc,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp));
                mdt_export_evict(exp);
                EXIT;
                return;
        }
        mti->mti_attr.ma_need = MA_INODE;
        mti->mti_attr.ma_valid = 0;
	mdt_attr_get_complex(mti, obj, &mti->mti_attr);
        mdt_pack_attr2body(mti, body, &mti->mti_attr.ma_attr,
                           mdt_object_fid(obj));
        if (mti->mti_ioepoch && (mti->mti_ioepoch->flags & MF_EPOCH_OPEN)) {
                struct mdt_file_data *mfd;
                struct mdt_body *repbody;

                repbody = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
                repbody->ioepoch = obj->mot_ioepoch;
		spin_lock(&med->med_open_lock);
		cfs_list_for_each_entry(mfd, &med->med_open_head, mfd_list) {
			if (mfd->mfd_xid == req->rq_xid)
				break;
		}
		LASSERT(&mfd->mfd_list != &med->med_open_head);
		spin_unlock(&med->med_open_lock);
		repbody->handle.cookie = mfd->mfd_handle.h_cookie;
	}

	mdt_object_put(mti->mti_env, obj);
}

typedef void (*mdt_reconstructor)(struct mdt_thread_info *mti,
                                  struct mdt_lock_handle *lhc);

static mdt_reconstructor reconstructors[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_reconstruct_setattr,
        [REINT_CREATE]   = mdt_reconstruct_create,
        [REINT_LINK]     = mdt_reconstruct_generic,
        [REINT_UNLINK]   = mdt_reconstruct_generic,
        [REINT_RENAME]   = mdt_reconstruct_generic,
        [REINT_OPEN]     = mdt_reconstruct_open,
        [REINT_SETXATTR] = mdt_reconstruct_generic
};

void mdt_reconstruct(struct mdt_thread_info *mti,
                     struct mdt_lock_handle *lhc)
{
        ENTRY;
        reconstructors[mti->mti_rr.rr_opcode](mti, lhc);
        EXIT;
}
