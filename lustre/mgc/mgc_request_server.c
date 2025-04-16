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
			       struct obd_device *disk)
{
	struct llog_ctxt *ctxt;
	int rc;

	ENTRY;
	rc = llog_setup(env, obd, &obd->obd_olg, LLOG_CONFIG_ORIG_CTXT, disk,
			&llog_osd_ops);
	if (rc)
		RETURN(rc);

	ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt);
	ctxt->loc_dir = obd->u.cli.cl_mgc_configs_dir;
	llog_ctxt_put(ctxt);

	RETURN(0);
}

static int mgc_local_llog_fini(const struct lu_env *env,
			       struct obd_device *obd)
{
	struct llog_ctxt *ctxt;

	ENTRY;
	ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
	llog_cleanup(env, ctxt);

	RETURN(0);
}

/* Configure the MGC to fetch config logs from the MGS to a local
 * filesystem device during mount.
 */
static int mgc_fs_setup(const struct lu_env *env, struct obd_device *obd,
			struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct client_obd *cli = &obd->u.cli;
	struct lu_fid rfid, fid;
	struct dt_object *root, *dto;
	int rc = 0;

	ENTRY;
	LASSERT(lsi);
	LASSERT(lsi->lsi_dt_dev);

	/* MGC can currently only fetch config logs for one fs at a time.
	 * Allow this mount to be killed if it is hung for some reason.
	 */
	rc = mutex_lock_interruptible(&cli->cl_mgc_mutex);
	CDEBUG(D_MGC, "%s: cl_mgc_mutex %s for %s: rc = %d\n", obd->obd_name,
	       lsi->lsi_osd_obdname, rc ? "interrupted" : "locked", rc);
	if (rc)
		RETURN(rc);

	/* Setup the configs dir */
	fid.f_seq = FID_SEQ_LOCAL_NAME;
	fid.f_oid = 1;
	fid.f_ver = 0;
	rc = local_oid_storage_init(env, lsi->lsi_dt_dev, &fid,
				    &cli->cl_mgc_los);
	if (rc)
		GOTO(out_mutex, rc);

	rc = dt_root_get(env, lsi->lsi_dt_dev, &rfid);
	if (rc)
		GOTO(out_los, rc);

	root = dt_locate_at(env, lsi->lsi_dt_dev, &rfid,
			    &cli->cl_mgc_los->los_dev->dd_lu_dev, NULL);
	if (unlikely(IS_ERR(root)))
		GOTO(out_los, rc = PTR_ERR(root));

	dto = local_file_find_or_create(env, cli->cl_mgc_los, root,
					MOUNT_CONFIGS_DIR,
					S_IFDIR | 0755);
	dt_object_put_nocache(env, root);
	if (IS_ERR(dto))
		GOTO(out_los, rc = PTR_ERR(dto));

	cli->cl_mgc_configs_dir = dto;

	LASSERT(lsi->lsi_osd_exp->exp_obd->obd_lvfs_ctxt.dt);
	rc = mgc_local_llog_init(env, obd, lsi->lsi_osd_exp->exp_obd);
	if (rc)
		GOTO(out_llog, rc);

	/* We take an obd ref to insure that we can't get to mgc_cleanup
	 * without calling mgc_fs_clear() first.
	 */
	class_incref(obd, "mgc_fs", obd);

	/* We hold the cl_mgc_mutex until mgc_fs_clear() is called */
	EXIT;
out_llog:
	if (rc) {
		dt_object_put(env, cli->cl_mgc_configs_dir);
		cli->cl_mgc_configs_dir = NULL;
	}
out_los:
	if (rc < 0) {
		local_oid_storage_fini(env, cli->cl_mgc_los);
out_mutex:
		cli->cl_mgc_los = NULL;
		CDEBUG(D_MGC, "%s: cl_mgc_mutex unlock for %s: rc = %d\n",
		       obd->obd_name, lsi->lsi_osd_obdname, rc);
		mutex_unlock(&cli->cl_mgc_mutex);
	}
	return rc;
}

/* Unconfigure the MGC from fetching config logs to the local device */
static int mgc_fs_clear(const struct lu_env *env, struct obd_device *obd)
{
	struct client_obd *cli = &obd->u.cli;

	ENTRY;
	LASSERT(cli->cl_mgc_los);

	mgc_local_llog_fini(env, obd);

	dt_object_put_nocache(env, cli->cl_mgc_configs_dir);
	cli->cl_mgc_configs_dir = NULL;

	local_oid_storage_fini(env, cli->cl_mgc_los);
	cli->cl_mgc_los = NULL;

	class_decref(obd, "mgc_fs", obd);
	CDEBUG(D_MGC, "%s: cl_mgc_mutex unlock\n", obd->obd_name);
	mutex_unlock(&cli->cl_mgc_mutex);

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
	large_nids = exp_connect_flags2(exp) & OBD_CONNECT2_LARGE_NID;

	/* it is OK to use new protocol with an old MGS, mti buffer is the
	 * same in both cases
	 */
	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_MGS_TARGET_REG_NIDLIST);
	if (!req)
		RETURN(-ENOMEM);

	if (large_nids || nidlist) {
		bufsize = MGS_MAXREQSIZE - sizeof(struct ptlrpc_body) -
			  sizeof(*mti) - sizeof(*mtn);
		avail = bufsize / MTN_NIDSTR_SIZE;
	} else {
		nidlist_size = 0;
	}

	if (nidlist) {
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
	mtn->mtn_nids = mti->mti_nid_count;
	mtn->mtn_flags = 0;

	if (pages) {
		LASSERT(nidlist);
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
	} else if (nidlist) {
		memcpy(mtn->mtn_inline_list, mti->mti_nidlist, nidlist_size);
	} else if (large_nids) {
		memcpy(request_mti, mti, sizeof(*mti) + nidlist_size);
	}

	ptlrpc_request_set_replen(req);
	CDEBUG(D_MGC, "register %s\n", mti->mti_svname);
	/* Limit how long we will wait for the enqueue to complete */
	req->rq_delay_limit = MGC_TARGET_REG_LIMIT;

	/* if the target needs to regenerate the config log in MGS, it's better
	 * to use some longer limit to let MGC have time to change connection to
	 * another MGS (or try again with the same MGS) for the target (server)
	 * will fail and exit if the request expired due to delay limit.
	 */
	if (mti->mti_flags & (LDD_F_UPDATE | LDD_F_NEED_INDEX))
		req->rq_delay_limit = MGC_TARGET_REG_LIMIT_MAX;

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
	if (KEY_IS(KEY_SET_FS)) {
		struct super_block *sb = (struct super_block *)val;

		if (vallen != sizeof(struct super_block))
			RETURN(-EINVAL);

		rc = mgc_fs_setup(env, exp->exp_obd, sb);
		RETURN(rc);
	}
	if (KEY_IS(KEY_CLEAR_FS)) {
		if (vallen != 0)
			RETURN(-EINVAL);
		rc = mgc_fs_clear(env, exp->exp_obd);
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
	struct page **pages = NULL;
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

	OBD_ALLOC_PTR_ARRAY(pages, nrpages);
	if (!pages)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < nrpages; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i])
			GOTO(out, rc = -ENOMEM);
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
		desc->bd_frag_ops->add_kiov_frag(desc, pages[i], 0,
						 PAGE_SIZE);

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

		ptr = kmap(pages[i]);
		rc2 = nodemap_process_idx_pages(new_config, ptr,
						&recent_nodemap);
		kunmap(pages[i]);
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

	if (pages) {
		for (i = 0; i < nrpages; i++) {
			if (!pages[i])
				break;
			__free_page(pages[i]);
		}
		OBD_FREE_PTR_ARRAY(pages, nrpages);
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
			       struct config_llog_data *cld, int mgslock,
			       bool copy_only)
{
	struct llog_ctxt *lctxt = llog_get_context(mgc, LLOG_CONFIG_ORIG_CTXT);
	struct client_obd *cli = &mgc->u.cli;
	struct dt_object *configs_dir = cli->cl_mgc_configs_dir;
	int rc = mgslock ? 0 : -EIO;

	/* requeue might happen in nowhere state */
	if (!lctxt)
		RETURN(rc);
	if (!configs_dir ||
	    lu2dt_dev(configs_dir->do_lu.lo_dev) != lsi->lsi_dt_dev)
		GOTO(out_pop, rc);

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
	if (copy_only)
		GOTO(out_pop, rc);

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
		 * config. In both cases proceed with remote llog first
		 */
		rc = class_config_parse_llog(env, *ctxt, cld->cld_logname,
					     &cld->cld_cfg);
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

int mgc_get_local_copy(struct obd_device *mgc, struct super_block *sb,
		       struct config_llog_data *cld)
{
	struct llog_ctxt *ctxt;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct lu_env *env;
	struct lustre_handle lockh = { .cookie = 0, };
	__u64 flags = 0;
	int rc;

	ENTRY;

	LASSERT(cld);
	if (!mgc->u.cli.cl_mgc_los || IS_MGS(lsi))
		return 0;

	mutex_lock(&cld->cld_lock);
	if (!cld->cld_processed)
		GOTO(out_mutex, rc = -ENODATA);

	if (cld->cld_stopping)
		GOTO(out_mutex, rc = -ENODEV);

	CDEBUG(D_MGC, "Get log %s-%016lx local copy\n", cld->cld_logname,
	       cld->cld_cfg.cfg_instance);

	if (ldlm_lock_addref_try(&cld->cld_lockh, LCK_CR)) {
		rc = mgc_enqueue(mgc->u.cli.cl_mgc_mgsexp, LDLM_PLAIN, NULL,
				 LCK_CR, &flags, NULL, cld, 0, NULL, &lockh);
		if (rc)
			GOTO(out_mutex, rc);
	}

	OBD_ALLOC_PTR(env);
	if (!env)
		GOTO(out_mutex, rc = -ENOMEM);

	rc = lu_env_init(env, LCT_MG_THREAD);
	if (rc)
		GOTO(out_free, rc);

	ctxt = llog_get_context(mgc, LLOG_CONFIG_REPL_CTXT);
	LASSERT(ctxt);

	rc = mgc_process_server_cfg_log(env, &ctxt, lsi, mgc, cld, 1, true);
	if (rc)
		CDEBUG(D_MGC, "%s: can't save local copy of '%s': rc = %d.\n",
		       mgc->obd_name, cld->cld_logname, rc);

	/* release lock */
	if (lustre_handle_is_used(&lockh))
		ldlm_lock_decref_and_cancel(&lockh, LCK_CR);
	else
		ldlm_lock_decref(&cld->cld_lockh, LCK_CR);

	EXIT;

	__llog_ctxt_put(env, ctxt);
	lu_env_fini(env);
out_free:
	OBD_FREE_PTR(env);
out_mutex:
	mutex_unlock(&cld->cld_lock);
	return rc;
}
