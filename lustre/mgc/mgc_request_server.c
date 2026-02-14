// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MGC
#define D_MGC D_CONFIG /*|D_WARNING*/

#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/random.h>

#include <dt_object.h>
#include <lprocfs_status.h>
#include <lustre_dlm.h>
#include <lustre_disk.h>
#include <lustre_log.h>
#include <lustre_nodemap.h>
#include <lustre_swab.h>
#include <obd_class.h>
#include <lustre_barrier.h>

#include "mgc_internal.h"

static int mgc_local_llog_init(const struct lu_env *env,
			       struct obd_device *obd,
			       struct obd_device *disk,
			       struct obd_llog_group *olg,
			       struct dt_object *dto)
{
	struct llog_ctxt *ctxt;
	int rc;

	ENTRY;
	rc = llog_setup(env, obd, olg, LLOG_CONFIG_REPL_CTXT, obd,
			&llog_client_ops);
	if (rc)
		RETURN(rc);

	ctxt = llog_group_get_ctxt(olg, LLOG_CONFIG_REPL_CTXT);
	LASSERT(ctxt);
	llog_initiator_connect(ctxt);

	rc = llog_setup(env, obd, olg, LLOG_CONFIG_ORIG_CTXT, disk,
			&llog_osd_ops);
	if (rc) {
		llog_cleanup(env, ctxt);
		RETURN(rc);
	}
	llog_ctxt_put(ctxt);

	ctxt = llog_group_get_ctxt(olg, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt);
	ctxt->loc_dir = dto;
	llog_ctxt_put(ctxt);

	RETURN(0);
}

static int mgc_local_llog_fini(const struct lu_env *env,
			       struct obd_llog_group *olg)
{
	struct llog_ctxt *ctxt;
	struct dt_object *dto;

	ENTRY;
	ctxt = llog_group_get_ctxt(olg, LLOG_CONFIG_REPL_CTXT);
	if (ctxt)
		llog_cleanup(env, ctxt);

	ctxt = llog_group_get_ctxt(olg, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt);
	dto = ctxt->loc_dir;
	ctxt->loc_dir = NULL;
	llog_cleanup(env, ctxt);
	dt_object_put_nocache(env, dto);

	RETURN(0);
}

/* Configure the cld to fetch config logs from the MGS to a local
 * filesystem device during mount.
 */
int mgc_fs_setup(const struct lu_env *env, struct obd_device *obd,
		 struct super_block *sb, struct config_llog_data *cld)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct lu_fid rfid, fid;
	struct dt_object *root, *dto;
	int rc = 0;

	ENTRY;
	LASSERT(lsi);
	LASSERT(lsi->lsi_dt_dev);

	CDEBUG(D_MGC, "%s: setup %s\n", obd->obd_name, lsi->lsi_osd_obdname);

	/* Setup the configs dir */
	fid.f_seq = FID_SEQ_LOCAL_NAME;
	fid.f_oid = 1;
	fid.f_ver = 0;
	rc = local_oid_storage_init(env, lsi->lsi_dt_dev, &fid, &cld->cld_los);
	if (rc)
		RETURN(rc);

	rc = dt_root_get(env, lsi->lsi_dt_dev, &rfid);
	if (rc)
		GOTO(out, rc);

	root = dt_locate_at(env, lsi->lsi_dt_dev, &rfid,
			    &cld->cld_los->los_dev->dd_lu_dev, NULL);
	if (unlikely(IS_ERR(root)))
		GOTO(out, rc = PTR_ERR(root));

	dto = local_file_find_or_create(env, cld->cld_los, root,
					MOUNT_CONFIGS_DIR, S_IFDIR | 0755);
	dt_object_put_nocache(env, root);
	if (IS_ERR(dto))
		GOTO(out, rc = PTR_ERR(dto));

	LASSERT(lsi->lsi_osd_exp->exp_obd->obd_lvfs_ctxt.dt);
	rc = mgc_local_llog_init(env, obd, lsi->lsi_osd_exp->exp_obd,
				 &cld->cld_olg, dto);
	if (rc) {
		dt_object_put(env, dto);
		GOTO(out, rc);
	}

	/* We take an obd ref to insure that we can't get to mgc_cleanup
	 * without calling mgc_fs_clear() first.
	 */
	class_incref(obd, "mgc_fs", obd);
	EXIT;
out:
	if (rc < 0) {
		local_oid_storage_fini(env, cld->cld_los);
		cld->cld_los = NULL;
	}
	return rc;
}

/* Unconfigure the cld from fetching config logs to the local device */
int mgc_fs_clear(const struct lu_env *env, struct obd_device *obd,
		 struct config_llog_data *cld)
{
	ENTRY;
	if (!cld->cld_los)
		RETURN(0);

	mgc_local_llog_fini(env, &cld->cld_olg);
	local_oid_storage_fini(env, cld->cld_los);
	cld->cld_los = NULL;

	class_decref(obd, "mgc_fs", obd);
	CDEBUG(D_MGC, "%s: clear %s\n", obd->obd_name, cld->cld_logname);

	RETURN(0);
}

/* Send target_reg message to MGS */
static int mgc_target_register(struct obd_export *exp,
			       struct mgs_target_info *mti)
{
	struct ptlrpc_request *req;
	struct mgs_target_info *request_mti, *reply_mti;
	struct mgs_target_nidlist *mtn;
	struct ptlrpc_bulk_desc *desc;
	size_t nidlist_size = NIDLIST_SIZE(mti->mti_nid_count);
	int pages = 0;
	unsigned int avail = 0;
	size_t bufsize;
	int rc;
	bool nidlist, large_nids;

	ENTRY;

	server_mti_print("mgc_target_register: req", mti);

	nidlist = exp_connect_flags(exp) & OBD_CONNECT_MGS_NIDLIST;
	large_nids = target_supports_large_nid(mti);

	if (CFS_FAIL_CHECK(OBD_FAIL_MGC_REG_BEFORE_CONN))
		nidlist = false;

	/* it is OK to use new protocol with an old MGS, mti buffer is the
	 * same in both cases
	 */
	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_MGS_TARGET_REG_NIDLIST);
	if (!req)
		RETURN(-ENOMEM);

	if (large_nids) {
		bufsize = MGS_MAXREQSIZE - sizeof(struct ptlrpc_body) -
			  sizeof(*mti) - sizeof(*mtn);
		avail = bufsize / MTN_NIDSTR_SIZE;
	} else {
		nidlist_size = 0;
	}

	if (nidlist && large_nids) {
		if (mti->mti_nid_count <= avail) { /* inline buffer */
			req_capsule_set_size(&req->rq_pill,
					     &RMF_MGS_TARGET_NIDLIST,
					     RCL_CLIENT,
					     sizeof(*mtn) + nidlist_size);
		} else { /* use bulk for big NID lists */
			pages = DIV_ROUND_UP((sizeof(*mti) & ~PAGE_MASK) +
					     nidlist_size, PAGE_SIZE);
		}
	} else if (large_nids) {
		if (mti->mti_nid_count > avail) {
			/* can't fit, send all we can */
			CDEBUG(D_MGC, "can fit only %u NIDs from %u\n",
			       avail, mti->mti_nid_count);
			mti->mti_nid_count = avail;
			nidlist_size = NIDLIST_SIZE(avail);
		}
		req_capsule_set_size(&req->rq_pill, &RMF_MGS_TARGET_INFO,
				     RCL_CLIENT, sizeof(*mti) + nidlist_size);
	}

	rc = ptlrpc_request_pack(req, LUSTRE_MGS_VERSION, MGS_TARGET_REG);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	request_mti = req_capsule_client_get(&req->rq_pill,
					     &RMF_MGS_TARGET_INFO);
	if (!request_mti) {
		ptlrpc_req_put(req);
		RETURN(-ENOMEM);
	}
	*request_mti = *mti;

	mtn = req_capsule_client_get(&req->rq_pill, &RMF_MGS_TARGET_NIDLIST);
	if (!mtn) {
		ptlrpc_req_put(req);
		RETURN(-ENOMEM);
	}
	mtn->mtn_nids = 0;
	mtn->mtn_flags = 0;

	if (pages) {
		LASSERT(nidlist);
		mtn->mtn_flags |= NIDLIST_IN_BULK;
		mtn->mtn_nids = mti->mti_nid_count;
		req->rq_bulk_write = 1;
		desc = ptlrpc_prep_bulk_imp(req, pages,
					    MD_MAX_BRW_SIZE >> LNET_MTU_BITS,
					    PTLRPC_BULK_GET_SOURCE,
					    MGS_BULK_PORTAL,
					    &ptlrpc_bulk_kiov_nopin_ops);
		if (!desc) {
			ptlrpc_req_put(req);
			RETURN(-ENOMEM);
		}
		desc->bd_frag_ops->add_iov_frag(desc, mti->mti_nidlist,
						nidlist_size);
	} else if (nidlist && large_nids) {
		mtn->mtn_nids = mti->mti_nid_count;
		memcpy(mtn->mtn_inline_list, mti->mti_nidlist, nidlist_size);
	} else if (large_nids) {
		memcpy(request_mti, mti, sizeof(*mti) + nidlist_size);
	}

	ptlrpc_request_set_replen(req);
	CDEBUG(D_MGC, "register %s\n", mti->mti_svname);
	/* Limit how long we will wait for the enqueue to complete */
	req->rq_delay_limit_ns = ktime_set(MGC_TARGET_REG_LIMIT, 0);

	/* if the target needs to regenerate the config log in MGS, it's better
	 * to use some longer limit to let MGC have time to change connection to
	 * another MGS (or try again with the same MGS) for the target (server)
	 * will fail and exit if the request expired due to delay limit.
	 */
	if (mti->mti_flags & (LDD_F_UPDATE | LDD_F_NEED_INDEX))
		req->rq_delay_limit_ns = ktime_set(MGC_TARGET_REG_LIMIT_MAX, 0);

	rc = ptlrpc_queue_wait(req);
	if (ptlrpc_client_replied(req)) {
		reply_mti = req_capsule_server_get(&req->rq_pill,
						   &RMF_MGS_TARGET_INFO);
		if (reply_mti)
			*mti = *reply_mti;
	}
	if (!rc) {
		CDEBUG(D_MGC, "register %s got index = %d\n",
		       mti->mti_svname, mti->mti_stripe_index);
		server_mti_print("mgc_target_register: rep", mti);
	}
	ptlrpc_req_put(req);

	RETURN(rc);
}

static int mgc_nid_notify_interpret(const struct lu_env *env,
				    struct ptlrpc_request *req,
				    void *args, int rc)
{
	struct mgs_target_info *mti;

	if (!ptlrpc_client_replied(req) ||
	    lustre_msg_get_type(req->rq_repmsg) == PTL_RPC_MSG_ERR) {
		CDEBUG(D_MGC, "fail to send NID notify, rc = %d\n", rc);
		return rc;
	}

	mti = req_capsule_server_get(&req->rq_pill, &RMF_MGS_TARGET_INFO);
	if (!mti)
		return -EPROTO;

	server_mti_print("mgc_nid_notify: rep", mti);

	if (rc)
		CDEBUG(D_MGC, "%s: NID notify failed, rc = %d\n",
		       mti->mti_svname, rc);
	return rc;
}

static int mgc_nid_notify(struct obd_export *exp,
			  struct mgs_target_info *mti,
			  struct ptlrpc_request_set *set)
{
	struct ptlrpc_request *req;
	struct mgs_target_info *request_mti;
	struct mgs_target_nidlist *mtn;
	struct ptlrpc_bulk_desc *desc;
	size_t bufsize, nidlist_size;
	unsigned int avail;
	int pages = 0;
	int rc;

	server_mti_print("mgc_nid_notify: req", mti);

	if (!(exp_connect_flags(exp) & OBD_CONNECT_MGS_NIDLIST))
		RETURN(-ENOPROTOOPT);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_MGS_TARGET_REG_NIDLIST);
	if (!req)
		RETURN(-ENOMEM);

	bufsize = MGS_MAXREQSIZE - sizeof(struct ptlrpc_body) -
		  sizeof(*mti) - sizeof(*mtn);
	avail = bufsize / MTN_NIDSTR_SIZE;

	nidlist_size = NIDLIST_SIZE(mti->mti_nid_count);
	if (mti->mti_nid_count <= avail) {
		/* inline buffer fits NIDs */
		req_capsule_set_size(&req->rq_pill, &RMF_MGS_TARGET_NIDLIST,
				     RCL_CLIENT, sizeof(*mtn) + nidlist_size);
	} else { /* use bulk for big NID lists */
		pages = DIV_ROUND_UP((sizeof(*mti) & ~PAGE_MASK) +
				     nidlist_size, PAGE_SIZE);
	}

	rc = ptlrpc_request_pack(req, LUSTRE_MGS_VERSION, MGS_TARGET_REG);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	request_mti = req_capsule_client_get(&req->rq_pill,
					     &RMF_MGS_TARGET_INFO);
	if (!request_mti) {
		ptlrpc_req_put(req);
		RETURN(-ENOMEM);
	}
	*request_mti = *mti;

	mtn = req_capsule_client_get(&req->rq_pill, &RMF_MGS_TARGET_NIDLIST);
	if (!mtn) {
		ptlrpc_req_put(req);
		RETURN(-ENOMEM);
	}

	mtn->mtn_nids = mti->mti_nid_count;
	mtn->mtn_flags = NIDLIST_APPEND;
	if (pages) {
		mtn->mtn_flags |= NIDLIST_IN_BULK;
		req->rq_bulk_write = 1;
		desc = ptlrpc_prep_bulk_imp(req, pages,
					    MD_MAX_BRW_SIZE >> LNET_MTU_BITS,
					    PTLRPC_BULK_GET_SOURCE,
					    MGS_BULK_PORTAL,
					    &ptlrpc_bulk_kiov_nopin_ops);
		if (!desc) {
			ptlrpc_req_put(req);
			RETURN(-ENOMEM);
		}
		desc->bd_frag_ops->add_iov_frag(desc, mti->mti_nidlist,
						nidlist_size);
	} else {
		memcpy(mtn->mtn_inline_list, mti->mti_nidlist, nidlist_size);
	}

	ptlrpc_request_set_replen(req);
	req->rq_interpret_reply = mgc_nid_notify_interpret;

	if (!pages) {
		ptlrpcd_add_req(req);
	} else if (set) {
		ptlrpc_set_add_req(set, req);
		ptlrpc_check_set(NULL, set);
	} else {
		/* caller provides no set but bulk is used, wait for
		 * RPC reply to make sure mti is not freed by caller
		 */
		rc = ptlrpc_queue_wait(req);
		ptlrpc_req_put(req);
	}

	return 0;
}

int mgc_set_info_async_server(const struct lu_env *env,
			      struct obd_export *exp,
			      u32 keylen, void *key,
			      u32 vallen, void *val,
			      struct ptlrpc_request_set *set)
{
	int rc = -EINVAL;

	ENTRY;
	/* FIXME move this to mgc_process_config */
	if (KEY_IS(KEY_REGISTER_TARGET)) {
		size_t mti_len = offsetof(struct mgs_target_info, mti_nidlist);
		struct mgs_target_info *mti = val;

		if (target_supports_large_nid(mti))
			mti_len += mti->mti_nid_count * LNET_NIDSTR_SIZE;

		if (vallen != mti_len)
			RETURN(-EINVAL);

		CDEBUG(D_MGC, "register_target %s %#x\n",
		       mti->mti_svname, mti->mti_flags);
		rc =  mgc_target_register(exp, mti);
		RETURN(rc);
	}
	if (KEY_IS(KEY_NID_NOTIFY)) {
		size_t mti_len = offsetof(struct mgs_target_info, mti_nidlist);
		struct mgs_target_info *mti = val;

		mti_len += NIDLIST_SIZE(mti->mti_nid_count);
		if (vallen != mti_len)
			RETURN(-EINVAL);

		CDEBUG(D_MGC, "NID notify for %s about %d new NIDs\n",
		       mti->mti_svname, mti->mti_nid_count);
		rc =  mgc_nid_notify(exp, mti, set);
		RETURN(rc);
	}

	RETURN(rc);
}

int mgc_process_nodemap_log(struct obd_device *obd,
			    struct config_llog_data *cld)
{
	struct ptlrpc_connection *mgc_conn;
	struct ptlrpc_request *req = NULL;
	struct mgs_config_body *body;
	struct mgs_config_res *res;
	struct nodemap_config *new_config = NULL;
	struct lu_nodemap *recent_nodemap = NULL;
	struct ptlrpc_bulk_desc *desc;
	struct folio **folios = NULL;
	u64 config_read_offset = 0;
	u8 nodemap_cur_pass = 0;
	int nrpages = 0;
	bool eof = true;
	int i;
	int ealen;
	int rc;

	ENTRY;
	mgc_conn = class_exp2cliimp(cld->cld_mgcexp)->imp_connection;

	/* don't need to get local config */
	if (LNetIsPeerLocal(&mgc_conn->c_peer.nid))
		GOTO(out, rc = 0);

	/* allocate buffer for bulk transfer.
	 * if this is the first time for this mgs to read logs,
	 * CONFIG_READ_NRPAGES_INIT will be used since it will read all logs
	 * once; otherwise, it only reads increment of logs, this should be
	 * small and CONFIG_READ_NRPAGES will be used.
	 */
	nrpages = CONFIG_READ_NRPAGES_INIT;

	OBD_ALLOC_PTR_ARRAY(folios, nrpages);
	if (!folios)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < nrpages; i++) {
		folios[i] = folio_alloc(GFP_KERNEL, 0);
		if (IS_ERR_OR_NULL(folios[i])) {
			folios[i] = NULL;
			GOTO(out, rc = -ENOMEM);
		}
	}

again:
	if (config_read_offset == 0) {
		new_config = nodemap_config_alloc();
		if (IS_ERR(new_config)) {
			rc = PTR_ERR(new_config);
			new_config = NULL;
			GOTO(out, rc);
		}
	}
	LASSERT(mutex_is_locked(&cld->cld_lock));
	req = ptlrpc_request_alloc(class_exp2cliimp(cld->cld_mgcexp),
				   &RQF_MGS_CONFIG_READ);
	if (!req)
		GOTO(out, rc = -ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_MGS_VERSION, MGS_CONFIG_READ);
	if (rc)
		GOTO(out, rc);

	/* pack request */
	body = req_capsule_client_get(&req->rq_pill, &RMF_MGS_CONFIG_BODY);
	LASSERT(body);
	LASSERT(sizeof(body->mcb_name) > strlen(cld->cld_logname));
	rc = strscpy(body->mcb_name, cld->cld_logname, sizeof(body->mcb_name));
	if (rc < 0)
		GOTO(out, rc);
	body->mcb_offset = config_read_offset;
	body->mcb_type   = cld->cld_type;
	body->mcb_bits   = PAGE_SHIFT;
	body->mcb_units  = nrpages;
	body->mcb_nm_cur_pass = nodemap_cur_pass;

	/* allocate bulk transfer descriptor */
	desc = ptlrpc_prep_bulk_imp(req, nrpages, 1,
				    PTLRPC_BULK_PUT_SINK,
				    MGS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_pin_ops);
	if (!desc)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < nrpages; i++)
		desc->bd_frag_ops->add_kiov_frag(desc, folio_page(folios[i], 0),
						 0, PAGE_SIZE);

	ptlrpc_request_set_replen(req);
	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	res = req_capsule_server_get(&req->rq_pill, &RMF_MGS_CONFIG_RES);
	if (!res)
		GOTO(out, rc = -EPROTO);

	config_read_offset = res->mcr_offset;
	eof = config_read_offset == II_END_OFF;
	nodemap_cur_pass = res->mcr_nm_cur_pass;

	ealen = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk, 0);
	if (ealen < 0)
		GOTO(out, rc = ealen);

	if (ealen > nrpages << PAGE_SHIFT)
		GOTO(out, rc = -EINVAL);

	if (ealen == 0) { /* no logs transferred */
		/* config changed since first read RPC */
		if (config_read_offset == 0) {
			CDEBUG(D_INFO, "nodemap config changed in transit, retrying\n");
			GOTO(out, rc = -EAGAIN);
		}
		if (!eof)
			rc = -EINVAL;
		GOTO(out, rc);
	}

	/* When a nodemap config is received, we build a new nodemap config,
	 * with new nodemap structs. We keep track of the most recently added
	 * nodemap since the config is read ordered by nodemap_id, and so it
	 * is likely that the next record will be related. Because access to
	 * the nodemaps is single threaded until the nodemap_config is active,
	 * we don't need to reference count with recent_nodemap, though
	 * recent_nodemap should be set to NULL when the nodemap_config
	 * is either destroyed or set active.
	 */
	if (new_config)
		nodemap_config_set_loading_mgc(true);
	for (i = 0; i < nrpages && ealen > 0; i++) {
		union lu_page *ptr;
		int rc2;

		ptr = ll_kmap_local_folio(folios[i], 0);
		rc2 = nodemap_process_idx_pages(new_config, ptr,
						&recent_nodemap);
		ll_kunmap_local(ptr);
		if (rc2 < 0) {
			CWARN("%s: error processing %s log nodemap: rc = %d\n",
			      obd->obd_name,
			      cld->cld_logname,
			      rc2);
			GOTO(out, rc = rc2);
		}

		ealen -= PAGE_SIZE;
	}

out:
	if (new_config)
		nodemap_config_set_loading_mgc(false);

	if (req) {
		ptlrpc_req_put(req);
		req = NULL;
	}

	if (rc == 0 && !eof)
		goto again;

	if (new_config) {
		/* recent_nodemap cannot be used after set_active/dealloc */
		if (rc == 0)
			nodemap_config_set_active_mgc(new_config);
		else
			nodemap_config_dealloc(new_config);
	}

	if (folios) {
		for (i = 0; i < nrpages; i++) {
			if (!folios[i])
				break;
			folio_put(folios[i]);
		}
		OBD_FREE_PTR_ARRAY(folios, nrpages);
	}
	return rc;
}

int mgc_process_config_server(const struct lu_env *env, struct lu_device *lu,
			      struct lustre_cfg *lcfg)
{
	struct obd_device *obd = lu->ld_obd;
	int rc = -ENOENT;

	ENTRY;
	switch (lcfg->lcfg_command) {
	case LCFG_LOV_ADD_OBD: {
		/* Overloading this cfg command: register a new target */
		struct mgs_target_info *mti;

		if (LUSTRE_CFG_BUFLEN(lcfg, 1) !=
		    sizeof(struct mgs_target_info))
			GOTO(out, rc = -EINVAL);

		mti = lustre_cfg_buf(lcfg, 1);
		CDEBUG(D_MGC, "add_target %s %#x\n",
		       mti->mti_svname, mti->mti_flags);
		rc = mgc_target_register(obd->u.cli.cl_mgc_mgsexp, mti);
		break;
	}
	case LCFG_LOV_DEL_OBD:
		/* Unregister has no meaning at the moment. */
		CERROR("lov_del_obd unimplemented\n");
		rc = -EINVAL;
		break;
	}
out:
	return rc;
}

int mgc_barrier_glimpse_ast(struct ldlm_lock *lock, void *data)
{
	struct config_llog_data *cld = lock->l_ast_data;
	int rc;

	ENTRY;
	if (cld->cld_stopping)
		RETURN(-ENODEV);

	rc = barrier_handler(s2lsi(cld->cld_cfg.cfg_sb)->lsi_dt_dev,
			     (struct ptlrpc_request *)data);

	RETURN(rc);
}

/* Copy a remote log locally */
static int mgc_llog_local_copy(const struct lu_env *env,
			       struct llog_ctxt *rctxt,
			       struct llog_ctxt *lctxt, char *logname)
{
	struct obd_device *obd = lctxt->loc_obd;
	char *temp_log;
	int rc;

	ENTRY;
	/*
	 * NB: mgc_get_server_cfg_log() prefers local copy first
	 * and works on it if valid, so that defines the process:
	 * - copy current local copy to temp_log using llog_backup()
	 * - copy remote llog to logname using llog_backup()
	 * - if failed then restore logname from backup
	 * That guarantees valid local copy only after successful step #2
	 */

	OBD_ALLOC(temp_log, strlen(logname) + 2);
	if (!temp_log)
		RETURN(-ENOMEM);
	sprintf(temp_log, "%sT", logname);

	/* check current local llog is valid */
	rc = llog_validate(env, lctxt, logname);
	if (!rc) {
		/* copy current local llog to temp_log */
		rc = llog_backup(env, obd, lctxt, lctxt, logname, temp_log);
		if (rc < 0)
			CWARN("%s: can't backup local config %s: rc = %d\n",
			      obd->obd_name, logname, rc);
	} else if (rc < 0 && rc != -ENOENT) {
		CWARN("%s: invalid local config log %s: rc = %d\n",
		      obd->obd_name, logname, rc);
		rc = llog_erase(env, lctxt, NULL, logname);
	}

	/* don't ignore errors like -EROFS and -ENOSPC, don't try to
	 * refresh local config in that case but mount using remote one
	 */
	if (rc == -ENOSPC || rc == -EROFS)
		GOTO(out_free, rc);

	/* build new local llog */
	rc = llog_backup(env, obd, rctxt, lctxt, logname, logname);
	if (rc == -ENOENT) {
		CDEBUG_LIMIT(strstr(logname, "sptlrpc") ? D_MGC : D_WARNING,
			     "%s: no remote llog for %s, check MGS config\n",
			     obd->obd_name, logname);
		llog_erase(env, lctxt, NULL, logname);
	} else if (rc < 0) {
		/* error during backup, get local one back from the copy */
		CWARN("%s: failed to copy new config %s: rc = %d\n",
		       obd->obd_name, logname, rc);
		llog_backup(env, obd, lctxt, lctxt, temp_log, logname);
	}
	llog_erase(env, lctxt, NULL, temp_log);
out_free:
	OBD_FREE(temp_log, strlen(logname) + 2);
	return rc;
}

int mgc_process_server_cfg_log(struct lu_env *env, struct llog_ctxt **ctxt,
			       struct lustre_sb_info *lsi,
			       struct obd_device *mgc,
			       struct config_llog_data *cld, int mgslock)
{
	struct llog_ctxt *lctxt;
	int rc = mgslock ? 0 : -EIO;

	lctxt = llog_group_get_ctxt(&cld->cld_olg, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(lctxt);
	if (lsi->lsi_dt_dev->dd_rdonly) {
		rc = -EROFS;
	} else if (mgslock) {
		/* Only try to copy log if we have the MGS lock. */
		CDEBUG(D_INFO, "%s: copy local log %s\n", mgc->obd_name,
		       cld->cld_logname);

		rc = mgc_llog_local_copy(env, *ctxt, lctxt, cld->cld_logname);
		if (!rc)
			lsi->lsi_flags &= ~LDD_F_NO_LOCAL_LOGS;
	}

	if (!mgslock) {
		if (unlikely(lsi->lsi_flags & LDD_F_NO_LOCAL_LOGS)) {
			rc = -EIO;
			CWARN("%s: failed to get MGS log %s and no_local_log flag is set: rc = %d\n",
			      mgc->obd_name, cld->cld_logname, rc);
			GOTO(out_pop, rc);
		}

		rc = llog_validate(env, lctxt, cld->cld_logname);
		if (rc && strcmp(cld->cld_logname, PARAMS_FILENAME)) {
			LCONSOLE_ERROR("Failed to get MGS log %s and no local copy.\n",
				       cld->cld_logname);
			GOTO(out_pop, rc);
		}
		CDEBUG(D_MGC,
		       "%s: Failed to get MGS log %s, using local copy for now, will try to update later.\n",
		       mgc->obd_name, cld->cld_logname);
	} else if (rc) {
		/* In case of error we may have empty or incomplete local
		 * config. In both cases proceed with remote llog first.
		 *
		 * mgs_write_log_target() handles positive EALREADY specially.
		 */
		if (cld_is_sptlrpc(cld)) {
			/* <fsname>-sptlrpc is parsed once per host, and this
			 * is the second place that parses it
			 */
			mutex_lock(&cld->cld_llog->cfl_lock);
			if (test_bit(CFL_PROCESSED, &cld->cld_llog->cfl_flags))
				rc = 0;
			else
				rc = class_config_parse_llog(env, *ctxt,
							     cld->cld_logname,
							     &cld->cld_cfg);
			mutex_unlock(&cld->cld_llog->cfl_lock);
		} else {
			rc = class_config_parse_llog(env, *ctxt,
						     cld->cld_logname,
						     &cld->cld_cfg);
		}
		if (!rc)
			GOTO(out_pop, rc = EALREADY);
		/* in case of an error while parsing remote MGS config
		 * just try local copy whatever it is as last attempt
		 */
	}
	llog_ctxt_put(*ctxt);
	*ctxt = lctxt;
	RETURN(0);
out_pop:
	__llog_ctxt_put(env, lctxt);
	return rc;
}
