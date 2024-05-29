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
#include <linux/random.h>

#include <lprocfs_status.h>
#include <lustre_dlm.h>
#include <lustre_disk.h>
#include <lustre_log.h>
#include <lustre_swab.h>
#include <obd_class.h>

#include "mgc_internal.h"

static int mgc_name2resid(char *name, int len, struct ldlm_res_id *res_id,
			  enum mgs_cfg_type type)
{
	__u64 resname = 0;

	if (len > sizeof(resname)) {
		CERROR("name too long: %s\n", name);
		return -EINVAL;
	}
	if (len <= 0) {
		CERROR("missing name: %s\n", name);
		return -EINVAL;
	}
	memcpy(&resname, name, len);

	/* Always use the same endianness for the resid */
	memset(res_id, 0, sizeof(*res_id));
	res_id->name[0] = cpu_to_le64(resname);
	/* XXX: unfortunately, sptlprc and config llog share one lock */
	switch (type) {
	case MGS_CFG_T_CONFIG:
	case MGS_CFG_T_SPTLRPC:
		resname = 0;
		break;
	case MGS_CFG_T_RECOVER:
	case MGS_CFG_T_PARAMS:
#ifdef HAVE_SERVER_SUPPORT
	case MGS_CFG_T_NODEMAP:
	case MGS_CFG_T_BARRIER:
#endif
		resname = type;
		break;
	default:
		LBUG();
	}
	res_id->name[1] = cpu_to_le64(resname);
	CDEBUG(D_MGC, "log %s to resid %#llx/%#llx (%.8s)\n", name,
	       res_id->name[0], res_id->name[1], (char *)&res_id->name[0]);
	return 0;
}

int mgc_fsname2resid(char *fsname, struct ldlm_res_id *res_id,
		     enum mgs_cfg_type type)
{
	/* fsname is at most 8 chars long, can contain "-". eg. lustre, lu-0 */
	return mgc_name2resid(fsname, strlen(fsname), res_id, type);
}
EXPORT_SYMBOL(mgc_fsname2resid);

int mgc_logname2resid(char *logname, struct ldlm_res_id *res_id,
		      enum mgs_cfg_type type)
{
	char *name_end;
	int len;

	/* logname consists of "fsname-nodetype". eg. "lustre-MDT0001",
	 * "SUN-000-client" there is an exception: llog "params"
	 */
	name_end = strrchr(logname, '-');
	if (!name_end)
		len = strlen(logname);
	else
		len = name_end - logname;
	return mgc_name2resid(logname, len, res_id, type);
}
EXPORT_SYMBOL(mgc_logname2resid);

/********************** config llog list **********************/
static LIST_HEAD(config_llog_list);
static DEFINE_SPINLOCK(config_list_lock);	/* protects config_llog_list */

/* Take a reference to a config log */
static int config_log_get(struct config_llog_data *cld)
{
	ENTRY;
	refcount_inc(&cld->cld_refcount);
	CDEBUG(D_INFO, "log %s (%p) refs %d\n", cld->cld_logname, cld,
		refcount_read(&cld->cld_refcount));
	RETURN(0);
}

/* Drop a reference to a config log. When no longer referenced, We can free the
 * config log data
 */
static void config_log_put(struct config_llog_data *cld)
{
	ENTRY;

	if (unlikely(!cld))
		RETURN_EXIT;

	CDEBUG(D_INFO, "log %s(%p) refs %d\n", cld->cld_logname, cld,
		refcount_read(&cld->cld_refcount));

	/* spinlock to make sure no item with 0 refcount in the list */
	if (refcount_dec_and_lock(&cld->cld_refcount, &config_list_lock)) {
		list_del(&cld->cld_list_chain);
		spin_unlock(&config_list_lock);

		CDEBUG(D_MGC, "dropping config log %s\n", cld->cld_logname);
#ifdef HAVE_SERVER_SUPPORT
		config_log_put(cld->cld_barrier);
		config_log_put(cld->cld_nodemap);
#endif
		config_log_put(cld->cld_recover);
		config_log_put(cld->cld_params);
		config_log_put(cld->cld_sptlrpc);
		if (cld_is_sptlrpc(cld)) {
			cld->cld_stopping = 1;
			sptlrpc_conf_log_stop(cld->cld_logname);
		}

		class_export_put(cld->cld_mgcexp);
		OBD_FREE(cld, sizeof(*cld) + strlen(cld->cld_logname) + 1);
	}

	EXIT;
}

/* Find a config log by name */
static
struct config_llog_data *config_log_find(char *logname,
					 struct config_llog_instance *cfg)
{
	struct config_llog_data *cld;
	struct config_llog_data *found = NULL;
	unsigned long cfg_instance;

	ENTRY;
	LASSERT(logname != NULL);

	cfg_instance = cfg ? cfg->cfg_instance : 0;
	spin_lock(&config_list_lock);
	list_for_each_entry(cld, &config_llog_list, cld_list_chain) {
		/* check if cfg_instance is the one we want */
		if (cfg_instance != cld->cld_cfg.cfg_instance)
			continue;

		/* instance may be NULL, should check name */
		if (strcmp(logname, cld->cld_logname) == 0) {
			found = cld;
			config_log_get(found);
			break;
		}
	}
	spin_unlock(&config_list_lock);
	RETURN(found);
}

static
struct config_llog_data *do_config_log_add(struct obd_device *obd,
					   char *logname,
					   enum mgs_cfg_type type,
					   struct config_llog_instance *cfg,
					   struct super_block *sb)
{
	struct config_llog_data *cld;
	int rc;
	int logname_size;

	ENTRY;

	CDEBUG(D_MGC, "do adding config log %s-%016lx\n", logname,
	       cfg ? cfg->cfg_instance : 0);

	logname_size = strlen(logname) + 1;
	OBD_ALLOC(cld, sizeof(*cld) + logname_size);
	if (!cld)
		RETURN(ERR_PTR(-ENOMEM));

	rc = mgc_logname2resid(logname, &cld->cld_resid, type);
	if (rc) {
		OBD_FREE(cld, sizeof(*cld) + logname_size);
		RETURN(ERR_PTR(rc));
	}

	strscpy(cld->cld_logname, logname, logname_size);
	if (cfg)
		cld->cld_cfg = *cfg;
	else
		cld->cld_cfg.cfg_callback = class_config_llog_handler;
	mutex_init(&cld->cld_lock);
	cld->cld_cfg.cfg_last_idx = 0;
	cld->cld_cfg.cfg_flags = 0;
	cld->cld_cfg.cfg_sb = sb;
	cld->cld_type = type;
	refcount_set(&cld->cld_refcount, 1);

	/* Keep the mgc around until we are done */
	cld->cld_mgcexp = class_export_get(obd->obd_self_export);

	if (cld_is_sptlrpc(cld))
		sptlrpc_conf_log_start(logname);

	spin_lock(&config_list_lock);
	list_add(&cld->cld_list_chain, &config_llog_list);
	spin_unlock(&config_list_lock);

	if (cld_is_sptlrpc(cld) || cld_is_nodemap(cld) || cld_is_barrier(cld)) {
		rc = mgc_process_log(obd, cld);
		if (rc && rc != -ENOENT)
			CERROR("%s: failed processing log, type %d: rc = %d\n",
			       obd->obd_name, type, rc);
	}

	RETURN(cld);
}

static struct config_llog_data *
config_recover_log_add(struct obd_device *obd, char *fsname,
		       struct config_llog_instance *cfg,
		       struct super_block *sb)
{
	struct config_llog_instance lcfg = *cfg;
	struct config_llog_data *cld;
	bool is_server = IS_SERVER(s2lsi(sb));
	char logname[32];

#ifdef HAVE_SERVER_SUPPORT
	if (IS_OST(s2lsi(sb)))
		return NULL;

	/* for osp-on-ost, see lustre_start_osp() */
	if (IS_MDT(s2lsi(sb)) && lcfg.cfg_instance)
		return NULL;
#endif
	/* We have to use different llog for clients and MDTs for DNE,
	 * where only clients are notified if one of DNE server restarts.
	 */
	LASSERT(strlen(fsname) < sizeof(logname) / 2);
	strncpy(logname, fsname, sizeof(logname));

	LASSERT(is_server ? lcfg.cfg_instance == 0 : lcfg.cfg_instance != 0);
	if (is_server)
		lcfg.cfg_instance = ll_get_cfg_instance(sb);
	scnprintf(logname, sizeof(logname), "%s-%s", fsname,
		  is_server ? "mdtir" : "cliir");

	cld = do_config_log_add(obd, logname, MGS_CFG_T_RECOVER, &lcfg, sb);
	return cld;
}

static struct config_llog_data *
config_log_find_or_add(struct obd_device *obd, char *logname,
		       struct super_block *sb, enum mgs_cfg_type type,
		       struct config_llog_instance *cfg)
{
	struct config_llog_instance lcfg = *cfg;
	struct config_llog_data *cld;

	/* Note class_config_llog_handler() depends on getting "obd" back */
	/* for sptlrpc, sb is only provided to be able to make a local copy,
	 * not for the instance
	 */
	if (sb && type != MGS_CFG_T_SPTLRPC)
		lcfg.cfg_instance = ll_get_cfg_instance(sb);
	else
		lcfg.cfg_instance = (unsigned long)obd;

	cld = config_log_find(logname, &lcfg);
	if (unlikely(cld != NULL))
		return cld;

	return do_config_log_add(obd, logname, type, &lcfg, sb);
}

/** Add this log to the list of active logs watched by an MGC.
 * Active means we're watching for updates.
 * We have one active log per "mount" - client instance or servername.
 * Each instance may be at a different point in the log.
 */
static struct config_llog_data *
config_log_add(struct obd_device *obd, char *logname,
	       struct config_llog_instance *cfg, struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct config_llog_data *cld = NULL;
	struct config_llog_data *sptlrpc_cld = NULL;
	struct config_llog_data *params_cld = NULL;
#ifdef HAVE_SERVER_SUPPORT
	struct config_llog_data *nodemap_cld = NULL;
	struct config_llog_data *barrier_cld = NULL;
#endif
	char seclogname[32];
	char *ptr;
	int rc;
	bool locked = false;

	ENTRY;

	CDEBUG(D_MGC, "add config log %s-%016lx\n", logname,
	       cfg->cfg_instance);

	/*
	 * for each regular log, the depended sptlrpc log name is
	 * <fsname>-sptlrpc. multiple regular logs may share one sptlrpc log.
	 */
	ptr = strrchr(logname, '-');
	if (ptr == NULL || ptr - logname > 8) {
		CERROR("logname %s is too long\n", logname);
		RETURN(ERR_PTR(-EINVAL));
	}

	memcpy(seclogname, logname, ptr - logname);
	strcpy(seclogname + (ptr - logname), "-sptlrpc");

	if (cfg->cfg_sub_clds & CONFIG_SUB_SPTLRPC) {
		sptlrpc_cld = config_log_find_or_add(obd, seclogname, sb,
						     MGS_CFG_T_SPTLRPC, cfg);
		if (IS_ERR(sptlrpc_cld)) {
			rc = PTR_ERR(sptlrpc_cld);
			CERROR("%s: can't create sptlrpc log %s: rc = %d\n",
			       obd->obd_name, seclogname, rc);
			GOTO(out_err, rc);
		}
	}

	if (cfg->cfg_sub_clds & CONFIG_SUB_PARAMS) {
		params_cld = config_log_find_or_add(obd, PARAMS_FILENAME, sb,
						    MGS_CFG_T_PARAMS, cfg);
		if (IS_ERR(params_cld)) {
			rc = PTR_ERR(params_cld);
			CERROR("%s: can't create params log: rc = %d\n",
			       obd->obd_name, rc);
			GOTO(out_sptlrpc, rc);
		}
	}

#ifdef HAVE_SERVER_SUPPORT
	if (!IS_MGS(lsi) && cfg->cfg_sub_clds & CONFIG_SUB_NODEMAP) {
		nodemap_cld = config_log_find_or_add(obd, LUSTRE_NODEMAP_NAME,
						     NULL, MGS_CFG_T_NODEMAP,
						     cfg);
		if (IS_ERR(nodemap_cld)) {
			rc = PTR_ERR(nodemap_cld);
			CERROR("%s: cannot create nodemap log: rc = %d\n",
			       obd->obd_name, rc);
			GOTO(out_params, rc);
		}
	}

	if (IS_MDT(s2lsi(sb)) && cfg->cfg_sub_clds & CONFIG_SUB_BARRIER) {
		snprintf(seclogname + (ptr - logname), sizeof(seclogname) - 1,
			 "-%s", BARRIER_FILENAME);
		barrier_cld = config_log_find_or_add(obd, seclogname, sb,
						     MGS_CFG_T_BARRIER, cfg);
		if (IS_ERR(barrier_cld)) {
			rc = PTR_ERR(barrier_cld);
			CERROR("%s: can't create barrier log: rc = %d\n",
			       obd->obd_name, rc);
			GOTO(out_nodemap, rc);
		}
	}
#endif
	cld = do_config_log_add(obd, logname, MGS_CFG_T_CONFIG, cfg, sb);
	if (IS_ERR(cld)) {
		rc = PTR_ERR(cld);
		CERROR("%s: can't create log: rc = %d\n",
		       obd->obd_name, rc);
#ifdef HAVE_SERVER_SUPPORT
		GOTO(out_barrier, rc);
#else
		GOTO(out_params, rc);
#endif
	}

	LASSERT(lsi->lsi_lmd);
	if (!test_bit(LMD_FLG_NOIR, lsi->lsi_lmd->lmd_flags) &&
	    cfg->cfg_sub_clds & CONFIG_SUB_RECOVER) {
		struct config_llog_data *recover_cld;

		ptr = strrchr(seclogname, '-');
		if (ptr != NULL) {
			*ptr = 0;
		} else {
			CERROR("%s: sptlrpc log name not correct, %s: rc = %d\n",
			       obd->obd_name, seclogname, -EINVAL);
			GOTO(out_cld, rc = -EINVAL);
		}

		recover_cld = config_recover_log_add(obd, seclogname, cfg, sb);
		if (IS_ERR(recover_cld)) {
			rc = PTR_ERR(recover_cld);
			CERROR("%s: can't create recover log: rc = %d\n",
			       obd->obd_name, rc);
			GOTO(out_cld, rc);
		}

		mutex_lock(&cld->cld_lock);
		locked = true;
		cld->cld_recover = recover_cld;
	}

	if (!locked)
		mutex_lock(&cld->cld_lock);
#ifdef HAVE_SERVER_SUPPORT
	cld->cld_barrier = barrier_cld;
	cld->cld_nodemap = nodemap_cld;
#endif
	cld->cld_params = params_cld;
	cld->cld_sptlrpc = sptlrpc_cld;
	mutex_unlock(&cld->cld_lock);

	RETURN(cld);

out_cld:
	config_log_put(cld);
#ifdef HAVE_SERVER_SUPPORT
out_barrier:
	config_log_put(barrier_cld);
out_nodemap:
	config_log_put(nodemap_cld);
#endif
out_params:
	config_log_put(params_cld);
out_sptlrpc:
	config_log_put(sptlrpc_cld);
out_err:
	return ERR_PTR(rc);
}

DEFINE_MUTEX(llog_process_lock);

static inline void config_mark_cld_stop_nolock(struct config_llog_data *cld)
{
	ENTRY;

	spin_lock(&config_list_lock);
	cld->cld_stopping = 1;
	spin_unlock(&config_list_lock);

	CDEBUG(D_INFO, "lockh %#llx\n", cld->cld_lockh.cookie);
	if (!ldlm_lock_addref_try(&cld->cld_lockh, LCK_CR))
		ldlm_lock_decref_and_cancel(&cld->cld_lockh, LCK_CR);
}

static inline void config_mark_cld_stop(struct config_llog_data *cld)
{
	if (cld) {
		mutex_lock(&cld->cld_lock);
		config_mark_cld_stop_nolock(cld);
		mutex_unlock(&cld->cld_lock);
	}
}

/** Stop watching for updates on this log.
 */
static int config_log_end(char *logname, struct config_llog_instance *cfg)
{
	struct config_llog_data *cld;
	struct config_llog_data *cld_sptlrpc = NULL;
	struct config_llog_data *cld_params = NULL;
	struct config_llog_data *cld_recover = NULL;
	struct config_llog_data *cld_nodemap = NULL;
	struct config_llog_data *cld_barrier = NULL;
	int rc = 0;

	ENTRY;

	cld = config_log_find(logname, cfg);
	if (cld == NULL)
		RETURN(-ENOENT);

	mutex_lock(&cld->cld_lock);
	/*
	 * if cld_stopping is set, it means we didn't start the log thus
	 * not owning the start ref. this can happen after previous umount:
	 * the cld still hanging there waiting for lock cancel, and we
	 * remount again but failed in the middle and call log_end without
	 * calling start_log.
	 */
	if (unlikely(cld->cld_stopping)) {
		mutex_unlock(&cld->cld_lock);
		/* drop the ref from the find */
		config_log_put(cld);
		RETURN(rc);
	}

	cld_recover = cld->cld_recover;
	cld->cld_recover = NULL;
	cld_params = cld->cld_params;
	cld->cld_params = NULL;
	cld_nodemap = cld->cld_nodemap;
	cld->cld_nodemap = NULL;
	cld_barrier = cld->cld_barrier;
	cld->cld_barrier = NULL;
	cld_sptlrpc = cld->cld_sptlrpc;
	cld->cld_sptlrpc = NULL;

	config_mark_cld_stop_nolock(cld);
	mutex_unlock(&cld->cld_lock);

	config_mark_cld_stop(cld_recover);
	config_log_put(cld_recover);
	config_mark_cld_stop(cld_params);
	config_log_put(cld_params);
	config_mark_cld_stop(cld_barrier);
	config_log_put(cld_barrier);
	/* don't explicitly set cld_stopping on sptlrpc lock here, as other
	 * targets may be active, it will be done in config_log_put if necessary
	 */
	config_log_put(cld_sptlrpc);
	/* don't set cld_stopping on nm lock as other targets may be active */
	config_log_put(cld_nodemap);

	/* drop the ref from the find */
	config_log_put(cld);
	/* drop the start ref */
	config_log_put(cld);

	CDEBUG(D_MGC, "end config log %s (%d)\n", logname ? logname : "client",
	       rc);
	RETURN(rc);
}

int lprocfs_mgc_rd_ir_state(struct seq_file *m, void *data)
{
	struct obd_device       *obd = data;
	struct obd_import       *imp;
	struct obd_connect_data *ocd;
	struct config_llog_data *cld;
	int rc = 0;

	ENTRY;
	LASSERT(obd);
	with_imp_locked(obd, imp, rc) {
		ocd = &imp->imp_connect_data;

		seq_printf(m, "imperative_recovery: %s\n",
			   OCD_HAS_FLAG(ocd, IMP_RECOV) ?
			   "ENABLED" : "DISABLED");
	}
	if (rc)
		RETURN(rc);

	seq_puts(m, "client_state:\n");

	spin_lock(&config_list_lock);
	list_for_each_entry(cld, &config_llog_list, cld_list_chain) {
		if (cld->cld_recover == NULL)
			continue;
		seq_printf(m,  "    - { client: %s, nidtbl_version: %u }\n",
			   cld->cld_logname,
			   cld->cld_recover->cld_cfg.cfg_last_idx);
	}
	spin_unlock(&config_list_lock);

	RETURN(0);
}

/* reenqueue any lost locks */
#define RQ_RUNNING	0x1
#define RQ_NOW		0x2
#define RQ_LATER	0x4
#define RQ_STOP		0x8
#define RQ_PRECLEANUP	0x10
static int                    rq_state;
static wait_queue_head_t      rq_waitq;
static DECLARE_COMPLETION(rq_exit);
static DECLARE_COMPLETION(rq_start);

static void do_requeue(struct config_llog_data *cld)
{
	int rc = 0;

	ENTRY;

	/*
	 * Do not run mgc_process_log on a disconnected export or an
	 * export which is being disconnected. Take the client
	 * semaphore to make the check non-racy.
	 */
	down_read_nested(&cld->cld_mgcexp->exp_obd->u.cli.cl_sem,
			 OBD_CLI_SEM_MGC);
	if (cld->cld_mgcexp->exp_obd->u.cli.cl_conn_count != 0) {
		CDEBUG(D_MGC, "updating log %s\n", cld->cld_logname);
		rc = mgc_process_log(cld->cld_mgcexp->exp_obd, cld);
		if (rc && rc != -ENOENT)
			CERROR("failed processing log: %d\n", rc);
	} else {
		CDEBUG(D_MGC, "disconnecting, won't update log %s\n",
		       cld->cld_logname);
	}
	up_read(&cld->cld_mgcexp->exp_obd->u.cli.cl_sem);

	EXIT;
}

static int mgc_requeue_thread(void *data)
{
	int rc = 0;
	bool first = true;

	ENTRY;

	CDEBUG(D_MGC, "Starting requeue thread\n");

	/* Keep trying failed locks periodically */
	spin_lock(&config_list_lock);
	rq_state |= RQ_RUNNING;
	while (!(rq_state & RQ_STOP)) {
		struct config_llog_data *cld, *cld_prev;
		int to;

		/* Any new or requeued lostlocks will change the state */
		rq_state &= ~(RQ_NOW | RQ_LATER);
		spin_unlock(&config_list_lock);

		if (first) {
			first = false;
			complete(&rq_start);
		}

		/* Always wait a few seconds to allow the server who
		 * caused the lock revocation to finish its setup, plus some
		 * random so everyone doesn't try to reconnect at once.
		 */
		to = mgc_requeue_timeout_min == 0 ? 1 : mgc_requeue_timeout_min;
		to = cfs_time_seconds(mgc_requeue_timeout_min) +
			get_random_u32_below(cfs_time_seconds(to));
		wait_event_idle_timeout(rq_waitq,
					rq_state & (RQ_STOP | RQ_PRECLEANUP),
					to);

		/*
		 * iterate & processing through the list. for each cld, process
		 * its depending sptlrpc cld firstly (if any) and then itself.
		 *
		 * it's guaranteed any item in the list must have
		 * reference > 0; and if cld_lostlock is set, at
		 * least one reference is taken by the previous enqueue.
		 */
		cld_prev = NULL;

		spin_lock(&config_list_lock);
		rq_state &= ~RQ_PRECLEANUP;
		list_for_each_entry(cld, &config_llog_list,
				    cld_list_chain) {
			if (!cld->cld_lostlock || cld->cld_stopping)
				continue;

			/* hold reference to avoid being freed during
			 * subsequent processing.
			 */
			config_log_get(cld);
			cld->cld_lostlock = 0;
			spin_unlock(&config_list_lock);

			config_log_put(cld_prev);
			cld_prev = cld;

			if (likely(!(rq_state & RQ_STOP))) {
				do_requeue(cld);
				spin_lock(&config_list_lock);
			} else {
				spin_lock(&config_list_lock);
				break;
			}
		}
		spin_unlock(&config_list_lock);
		config_log_put(cld_prev);

		/* Wait a bit to see if anyone else needs a requeue */
		wait_event_idle(rq_waitq, rq_state & (RQ_NOW | RQ_STOP));
		spin_lock(&config_list_lock);
	}

	/* spinlock and while guarantee RQ_NOW and RQ_LATER are not set */
	rq_state &= ~RQ_RUNNING;
	spin_unlock(&config_list_lock);

	complete(&rq_exit);

	CDEBUG(D_MGC, "Ending requeue thread\n");
	RETURN(rc);
}

/* Add a cld to the list to requeue.  Start the requeue thread if needed.
 * We are responsible for dropping the config log reference from here on out.
 */
static void mgc_requeue_add(struct config_llog_data *cld)
{
	bool wakeup = false;

	ENTRY;

	CDEBUG(D_INFO, "log %s: requeue (r=%d sp=%d st=%x)\n",
		cld->cld_logname, refcount_read(&cld->cld_refcount),
		cld->cld_stopping, rq_state);

	/* lets cancel an existent lock to mark cld as "lostlock" */
	CDEBUG(D_INFO, "lockh %#llx\n", cld->cld_lockh.cookie);
	if (!ldlm_lock_addref_try(&cld->cld_lockh, LCK_CR))
		ldlm_lock_decref_and_cancel(&cld->cld_lockh, LCK_CR);

	mutex_lock(&cld->cld_lock);
	spin_lock(&config_list_lock);
	if (!(rq_state & RQ_STOP) && !cld->cld_stopping) {
		cld->cld_lostlock = 1;
		rq_state |= RQ_NOW;
		wakeup = true;
	}
	spin_unlock(&config_list_lock);
	mutex_unlock(&cld->cld_lock);
	if (wakeup)
		wake_up(&rq_waitq);

	EXIT;
}

/********************** class fns **********************/
static int mgc_llog_init(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_ctxt	*ctxt;
	int			 rc;

	ENTRY;

	/* setup only remote ctxt, the local disk context is switched per each
	 * filesystem during mgc_fs_setup()
	 */
	rc = llog_setup(env, obd, &obd->obd_olg, LLOG_CONFIG_REPL_CTXT, obd,
			&llog_client_ops);
	if (rc)
		RETURN(rc);

	ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
	LASSERT(ctxt);

	llog_initiator_connect(ctxt);
	llog_ctxt_put(ctxt);

	RETURN(0);
}

static int mgc_llog_fini(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_ctxt *ctxt;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
	if (ctxt)
		llog_cleanup(env, ctxt);

	RETURN(0);
}


static atomic_t mgc_count = ATOMIC_INIT(0);
static int mgc_precleanup(struct obd_device *obd)
{
	int	rc = 0;
	int	temp;

	ENTRY;

	if (atomic_dec_and_test(&mgc_count)) {
		LASSERT(rq_state & RQ_RUNNING);
		/* stop requeue thread */
		temp = RQ_STOP;
	} else {
		/* wakeup requeue thread to clean our cld */
		temp = RQ_NOW | RQ_PRECLEANUP;
	}

	spin_lock(&config_list_lock);
	rq_state |= temp;
	spin_unlock(&config_list_lock);
	wake_up(&rq_waitq);

	if (temp & RQ_STOP)
		wait_for_completion(&rq_exit);
	obd_cleanup_client_import(obd);

	rc = mgc_llog_fini(NULL, obd);
	if (rc != 0)
		CERROR("failed to cleanup llogging subsystems\n");

	RETURN(rc);
}

static int mgc_cleanup(struct obd_device *obd)
{
	int rc;

	ENTRY;

	/* COMPAT_146 - old config logs may have added profiles secretly */
	if (atomic_read(&obd->obd_type->typ_refcnt) <= 1)
		/* Only for the last mgc */
		class_del_profiles();

	lprocfs_obd_cleanup(obd);
	ptlrpcd_decref();

	rc = client_obd_cleanup(obd);
	RETURN(rc);
}

static int mgc_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct task_struct	*task;
	int			 rc;

	ENTRY;

	rc = ptlrpcd_addref();
	if (rc < 0)
		RETURN(rc);

	rc = client_obd_setup(obd, lcfg);
	if (rc)
		GOTO(err_decref, rc);

	rc = mgc_llog_init(NULL, obd);
	if (rc) {
		CERROR("failed to setup llogging subsystems\n");
		GOTO(err_cleanup, rc);
	}

	rc = mgc_tunables_init(obd);
	if (rc)
		GOTO(err_sysfs, rc);

	if (atomic_inc_return(&mgc_count) == 1) {
		rq_state = 0;
		init_waitqueue_head(&rq_waitq);

		/* start requeue thread */
		task = kthread_run(mgc_requeue_thread, NULL, "ll_cfg_requeue");
		if (IS_ERR(task)) {
			rc = PTR_ERR(task);
			CERROR("%s: cannot start requeue thread: rc = %d; "
			       "no more log updates\n",
			       obd->obd_name, rc);
			GOTO(err_sysfs, rc);
		}
		/* rc is the task_struct pointer of mgc_requeue_thread. */
		rc = 0;
		wait_for_completion(&rq_start);
	}

	RETURN(rc);

err_sysfs:
	lprocfs_obd_cleanup(obd);
err_cleanup:
	client_obd_cleanup(obd);
err_decref:
	ptlrpcd_decref();
	RETURN(rc);
}

/* based on ll_mdc_blocking_ast */
static int mgc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
			    void *data, int flag)
{
	struct lustre_handle lockh;
	struct config_llog_data *cld = (struct config_llog_data *)data;
	int rc = 0;

	ENTRY;

	switch (flag) {
	case LDLM_CB_BLOCKING:
		/* mgs wants the lock, give it up... */
		LDLM_DEBUG(lock, "MGC blocking CB");
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		break;
	case LDLM_CB_CANCELING:
		/* We've given up the lock, prepare ourselves to update. */
		LDLM_DEBUG(lock, "MGC cancel CB");

		CDEBUG(D_MGC, "Lock res "DLDLMRES" (%.8s)\n",
		       PLDLMRES(lock->l_resource),
		       (char *)&lock->l_resource->lr_name.name[0]);

		if (!cld) {
			CDEBUG(D_INFO, "missing data, won't requeue\n");
			break;
		}

		lock->l_ast_data = NULL;
		cld->cld_lockh.cookie = 0;
		/* Are we done with this log? */
		if (cld->cld_stopping) {
			CDEBUG(D_MGC, "log %s: stopping, won't requeue\n",
				cld->cld_logname);
			config_log_put(cld);
			break;
		}
		/* Make sure not to re-enqueue when the mgc is stopping
		 * (we get called from client_disconnect_export)
		 */
		if (lock->l_conn_export == NULL ||
		    lock->l_conn_export->exp_obd->u.cli.cl_conn_count == 0) {
			CDEBUG(D_MGC, "log %.8s: disconnecting, won't requeue\n",
				cld->cld_logname);
			config_log_put(cld);
			break;
		}

		/* Re-enqueue now */
		mgc_requeue_add(cld);
		config_log_put(cld);
		break;
	default:
		LBUG();
	}

	RETURN(rc);
}

/* Take a config lock so we can get cancel notifications */
static int mgc_enqueue(struct obd_export *exp, enum ldlm_type type,
		       union ldlm_policy_data *policy, enum ldlm_mode mode,
		       __u64 *flags, ldlm_glimpse_callback glimpse_callback,
		       void *data, __u32 lvb_len, void *lvb_swabber,
		       struct lustre_handle *lockh)
{
	struct config_llog_data *cld = (struct config_llog_data *)data;
	struct ldlm_enqueue_info einfo = {
		.ei_type	= type,
		.ei_mode	= mode,
		.ei_cb_bl	= mgc_blocking_ast,
		.ei_cb_cp	= ldlm_completion_ast,
		.ei_cb_gl	= glimpse_callback,
	};
	struct ptlrpc_request *req;
	int short_limit = cld_is_sptlrpc(cld);
	int rc;

	ENTRY;

	if (!exp)
		RETURN(-EBADR);

	CDEBUG(D_MGC, "Enqueue for %s (res %#llx)\n", cld->cld_logname,
	       cld->cld_resid.name[0]);

	/* We need a callback for every lockholder, so don't try to
	 * ldlm_lock_match (see rev 1.1.2.11.2.47)
	 */
	req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
					&RQF_LDLM_ENQUEUE, LUSTRE_DLM_VERSION,
					LDLM_ENQUEUE);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER, 0);
	ptlrpc_request_set_replen(req);

	/* check if this is server or client */
	if (cld->cld_cfg.cfg_sb &&
	    IS_SERVER(s2lsi(cld->cld_cfg.cfg_sb)))
		short_limit = 1;

	/* Limit how long we will wait for the enqueue to complete */
	req->rq_delay_limit = short_limit ? 5 : MGC_ENQUEUE_LIMIT(exp->exp_obd);
	rc = ldlm_cli_enqueue(exp, &req, &einfo, &cld->cld_resid, NULL, flags,
			      NULL, 0, LVB_T_NONE, lockh, 0);
	/* A failed enqueue should still call the mgc_blocking_ast,
	 * where it will be requeued if needed ("grant failed").
	 */
	ptlrpc_req_put(req);
	RETURN(rc);
}

static int mgc_cancel(struct obd_export *exp, enum ldlm_mode mode,
		      struct lustre_handle *lockh)
{
	ENTRY;

	ldlm_lock_decref(lockh, mode);

	RETURN(0);
}

static void mgc_notify_active(struct obd_device *unused)
{
	/* wakeup mgc_requeue_thread to requeue mgc lock */
	spin_lock(&config_list_lock);
	rq_state |= RQ_NOW;
	spin_unlock(&config_list_lock);
	wake_up(&rq_waitq);

	/* TODO: Help the MGS rebuild nidtbl. -jay */
}

static int mgc_set_info_async(const struct lu_env *env, struct obd_export *exp,
			      u32 keylen, void *key,
			      u32 vallen, void *val,
			      struct ptlrpc_request_set *set)
{
	int rc = -EINVAL;

	ENTRY;

	/* Turn off initial_recov after we try all backup servers once */
	if (KEY_IS(KEY_INIT_RECOV_BACKUP)) {
		struct obd_import *imp = class_exp2cliimp(exp);
		int value;

		if (vallen != sizeof(int))
			RETURN(-EINVAL);
		value = *(int *)val;
		CDEBUG(D_MGC, "InitRecov %s %d/d%d:i%d:r%d:or%d:%s\n",
		       imp->imp_obd->obd_name, value,
		       imp->imp_deactive, imp->imp_invalid,
		       imp->imp_replayable, imp->imp_obd->obd_replayable,
		       ptlrpc_import_state_name(imp->imp_state));
		/* Resurrect the import immediately if
		 * 1. we previously got disconnected,
		 * 2. value > 1 (at the same node with MGS)
		 */
		if (value > 1) {
			struct adaptive_timeout *at;

			at = &imp->imp_at.iat_net_latency;
			at_reset(at, INITIAL_CONNECT_TIMEOUT);
		}

		if (imp->imp_state == LUSTRE_IMP_DISCON || value > 1)
			ptlrpc_reconnect_import(imp);

		RETURN(0);
	}

	if (KEY_IS(KEY_MGSSEC)) {
		struct client_obd     *cli = &exp->exp_obd->u.cli;
		struct sptlrpc_flavor  flvr;

		/*
		 * empty string means using current flavor, if which haven't
		 * been set yet, set it as null.
		 *
		 * if flavor has been set previously, check the asking flavor
		 * must match the existing one.
		 */
		if (vallen == 0) {
			if (cli->cl_flvr_mgc.sf_rpc != SPTLRPC_FLVR_INVALID)
				RETURN(0);
			val = "null";
			vallen = 4;
		}

		rc = sptlrpc_parse_flavor(val, &flvr);
		if (rc) {
			CERROR("invalid sptlrpc flavor %s to MGS\n",
			       (char *) val);
			RETURN(rc);
		}

		/* caller already hold a mutex */
		if (cli->cl_flvr_mgc.sf_rpc == SPTLRPC_FLVR_INVALID) {
			cli->cl_flvr_mgc = flvr;
		} else if (memcmp(&cli->cl_flvr_mgc, &flvr,
				  sizeof(flvr)) != 0) {
			char    str[20];

			sptlrpc_flavor2name(&cli->cl_flvr_mgc, str,
					    sizeof(str));
			LCONSOLE_ERROR("asking sptlrpc flavor %s to MGS but currently %s is in use\n",
				       (char *) val, str);
			rc = -EPERM;
		}
		RETURN(rc);
	}

	if (KEY_IS(KEY_FLUSH_CTX)) {
		struct obd_import *imp = class_exp2cliimp(exp);

		sptlrpc_import_flush_my_ctx(imp);
		RETURN(0);
	}

#ifdef HAVE_SERVER_SUPPORT
	rc = mgc_set_info_async_server(env, exp, keylen, key, vallen, val, set);
#endif
	RETURN(rc);
}

static int mgc_get_info(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 *vallen, void *val)
{
	int rc = -EINVAL;

	if (KEY_IS(KEY_CONN_DATA)) {
		struct obd_import *imp = class_exp2cliimp(exp);
		struct obd_connect_data *data = val;

		if (*vallen == sizeof(*data)) {
			*data = imp->imp_connect_data;
			rc = 0;
		}
	}

	return rc;
}

static int mgc_import_event(struct obd_device *obd,
			    struct obd_import *imp,
			    enum obd_import_event event)
{
	int rc = 0;

	LASSERT(imp->imp_obd == obd);
	CDEBUG(D_MGC, "import event %#x\n", event);

	switch (event) {
	case IMP_EVENT_DISCON:
		/* MGC imports should not wait for recovery */
		if (OCD_HAS_FLAG(&imp->imp_connect_data, IMP_RECOV))
			ptlrpc_pinger_ir_down();
		break;
	case IMP_EVENT_INACTIVE:
		break;
	case IMP_EVENT_INVALIDATE: {
		struct ldlm_namespace *ns = obd->obd_namespace;

		ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);
		break;
	}
	case IMP_EVENT_ACTIVE:
		CDEBUG(D_INFO, "%s: Reactivating import\n", obd->obd_name);
		/* Clearing obd_no_recov allows us to continue pinging */
		obd->obd_no_recov = 0;
		mgc_notify_active(obd);
		if (OCD_HAS_FLAG(&imp->imp_connect_data, IMP_RECOV))
			ptlrpc_pinger_ir_up();
		break;
	case IMP_EVENT_OCD:
		break;
	case IMP_EVENT_DEACTIVATE:
	case IMP_EVENT_ACTIVATE:
		break;
	default:
		CERROR("Unknown import event %#x\n", event);
		LBUG();
	}
	RETURN(rc);
}

static int mgc_apply_recover_logs(struct obd_device *mgc,
				  struct config_llog_data *cld,
				  __u64 max_version,
				  void *data, int datalen, bool mne_swab)
{
	struct config_llog_instance *cfg = &cld->cld_cfg;
	struct lustre_cfg *lcfg;
	struct lustre_cfg_bufs bufs;
	u64 prev_version = 0;
	char inst[MTI_NAME_MAXLEN + 1];
	char *buf;
	int bufsz;
	int pos = 0;
	int rc  = 0;
	int off = 0;
	unsigned long dynamic_nids;

	ENTRY;
	LASSERT(cfg->cfg_instance != 0);
	LASSERT(ll_get_cfg_instance(cfg->cfg_sb) == cfg->cfg_instance);

	/* get dynamic nids setting */
	dynamic_nids = mgc->obd_dynamic_nids;

	if (!IS_SERVER(s2lsi(cfg->cfg_sb))) {
		pos = snprintf(inst, sizeof(inst), "%016lx", cfg->cfg_instance);
		if (pos >= PAGE_SIZE)
			return -E2BIG;
#ifdef HAVE_SERVER_SUPPORT
	} else {
		struct lustre_sb_info *lsi = s2lsi(cfg->cfg_sb);

		LASSERT(IS_MDT(lsi));
		rc = server_name2svname(lsi->lsi_svname, inst, NULL,
					sizeof(inst));
		if (rc)
			RETURN(-EINVAL);
#endif /* HAVE_SERVER_SUPPORT */
	}

	OBD_ALLOC(buf, PAGE_SIZE);
	if (!buf)
		return -ENOMEM;
	bufsz = PAGE_SIZE;
	pos = 0;

	while (datalen > 0) {
		struct mgs_nidtbl_entry *entry = (data + off);
		struct lnet_nid *nidlist = NULL;
		int entry_len = sizeof(*entry);
		struct obd_device *obd;
		struct obd_import *imp;
		struct obd_uuid *uuid;
		char *obdname;
		char *cname;
		char *params;
		bool is_ost;

		rc = -EINVAL;
		/* sanity checks */
		if (datalen < entry_len) /* really short on data */
			break;

		/* swab non nid data */
		if (mne_swab)
			lustre_swab_mgs_nidtbl_entry_header(entry);

		if (entry->mne_nid_count == 0) /* at least one nid entry */
			break;

		entry_len += entry->mne_nid_count * entry->mne_nid_size;
		if (datalen < entry_len) /* must have entry_len at least */
			break;

		if (entry->mne_length > PAGE_SIZE) {
			CERROR("MNE too large (%u)\n", entry->mne_length);
			break;
		}

		/* improper mne_lenth */
		if (entry->mne_length < entry_len)
			break;

		/* entry length reports larger than all the data passed in */
		if (datalen < entry->mne_length)
			break;

		/* Looks OK. Can process this entry? else move to next entry */
		off += entry->mne_length;
		datalen -= entry->mne_length;
		if (datalen < 0)
			break;

		if (entry->mne_version > max_version) {
			CERROR("entry index(%lld) is over max_index(%lld)\n",
			       entry->mne_version, max_version);
			break;
		}

		if (prev_version >= entry->mne_version) {
			CERROR("index unsorted, prev %lld, now %lld\n",
			       prev_version, entry->mne_version);
			break;
		}
		prev_version = entry->mne_version;

		if (entry->mne_nid_type == 0) {
			struct lnet_nid *nid;
			int i;

			OBD_ALLOC_PTR_ARRAY(nidlist, entry->mne_nid_count);
			if (!nidlist) {
				rc = -ENOMEM;
				break;
			}

			/* Keep this nid data swab for normal mixed
			 * endian handling. LU-1644
			 */
			if (mne_swab)
				lustre_swab_mgs_nidtbl_entry_content(entry);

			/* Turn old NID format to newer format. */
			nid = nidlist;
			for (i = 0; i < entry->mne_nid_count; i++) {
				lnet_nid4_to_nid(entry->u.nids[i], nid);
				nid += sizeof(struct lnet_nid);
			}
		} else {
			/* Handle the case if struct lnet_nid is expanded in
			 * the future. The MGS should prevent this but just
			 * in case.
			 */
			if (entry->mne_nid_size > sizeof(struct lnet_nid))
				continue;

			nidlist = entry->u.nidlist;
		}

		/*
		 * Write a string with format "nid::instance" to
		 * lustre/<osc|mdc>/<target>-<osc|mdc>-<instance>/import.
		 */
		is_ost = entry->mne_type == LDD_F_SV_TYPE_OST;
		memset(buf, 0, bufsz);
		obdname = buf;
		pos = 0;

		/* lustre-OST0001-osc-<instance #> */
		strcpy(obdname, cld->cld_logname);
		cname = strrchr(obdname, '-');
		if (cname == NULL) {
			CERROR("mgc %s: invalid logname %s\n",
			       mgc->obd_name, obdname);
			if (entry->mne_nid_type == 0)
				OBD_FREE_PTR_ARRAY(nidlist,
						   entry->mne_nid_count);
			break;
		}

		pos = cname - obdname;
		obdname[pos] = 0;
		pos += sprintf(obdname + pos, "-%s%04x",
			       is_ost ? "OST" : "MDT", entry->mne_index);

		cname = is_ost ? "osc" : "mdc",
			pos += snprintf(obdname + pos, bufsz, "-%s-%s", cname,
					inst);
		lustre_cfg_bufs_reset(&bufs, obdname);

		/* find the obd by obdname */
		obd = class_name2obd(obdname);
		if (obd == NULL) {
			CDEBUG(D_INFO, "mgc %s: cannot find obdname %s\n",
			       mgc->obd_name, obdname);
			rc = 0;
			/* this is a safe race, when the ost is starting up...*/
			continue;
		}

		/* osc.import = "connection=<Conn UUID>::<target instance>" */
		++pos;
		params = buf + pos;
		pos += sprintf(params, "%s.import=%s", cname, "connection=");
		uuid = (struct obd_uuid *)(buf + pos);

		with_imp_locked(obd, imp, rc) {
			struct obd_uuid server_uuid;
			char *primary_nid;
			int prim_nid_len;

			/* iterate all nids to find one */
			/* find uuid by nid */
			/* create import entries if they don't exist */
			rc = client_import_add_nids_to_conn(imp, nidlist,
							   entry->mne_nid_count,
							   entry->mne_nid_size,
							   uuid);
			if (rc != -ENOENT || !dynamic_nids)
				continue;

			/* create a new connection for this import */
			primary_nid = libcfs_nidstr(&nidlist[0]);
			prim_nid_len = strlen(primary_nid) + 1;
			if (prim_nid_len > UUID_MAX)
				goto fail;

			strncpy(server_uuid.uuid, primary_nid,
				prim_nid_len);

			CDEBUG(D_INFO, "Adding a connection for %s\n",
			       primary_nid);

			rc = client_import_dyn_add_conn(imp, &server_uuid,
							&nidlist[0], 1);
			if (rc < 0) {
				CERROR("%s: Failed to add new connection with NID '%s' to import: rc = %d\n",
				       obd->obd_name, primary_nid, rc);
				goto fail;
			}

			rc = client_import_add_nids_to_conn(imp, nidlist,
							   entry->mne_nid_count,
							   entry->mne_nid_size,
							   uuid);
			if (rc < 0)
				CERROR("%s: failed to lookup UUID: rc = %d\n",
				       obd->obd_name, rc);
fail:;
		}

		if (rc == -ENODEV) {
			/* client does not connect to the OST yet */
			rc = 0;
			goto free_nids;
		}

		if (rc < 0 && rc != -ENOSPC) {
			CERROR("mgc: cannot find UUID by nid '%s': rc = %d\n",
			       libcfs_nidstr(&nidlist[0]), rc);

			/* For old NID format case the nidlist was allocated. */
			if (entry->mne_nid_type == 0)
				OBD_FREE_PTR_ARRAY(nidlist,
						   entry->mne_nid_count);
			break;
		}

		CDEBUG(D_INFO, "Found UUID '%s' by NID '%s'\n",
		       uuid->uuid, libcfs_nidstr(&nidlist[0]));

		pos += strlen(uuid->uuid);
		pos += sprintf(buf + pos, "::%u", entry->mne_instance);
		LASSERT(pos < bufsz);

		lustre_cfg_bufs_set_string(&bufs, 1, params);

		OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount,
					       bufs.lcfg_buflen));
		if (!lcfg) {
			rc = -ENOMEM;
			break;
		}
		lustre_cfg_init(lcfg, LCFG_PARAM, &bufs);

		CDEBUG(D_INFO, "ir apply logs %lld/%lld for %s -> %s\n",
		       prev_version, max_version, obdname, params);

		rc = class_process_config(lcfg);
		OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount,
					      lcfg->lcfg_buflens));
		if (rc)
			CDEBUG(D_INFO, "process config for %s error %d\n",
			       obdname, rc);

		/* continue, even one with error */
free_nids:
		/* For old NID format case the nidlist was allocated. */
		if (entry->mne_nid_type == 0)
			OBD_FREE_PTR_ARRAY(nidlist, entry->mne_nid_count);
	}

	OBD_FREE(buf, PAGE_SIZE);

	RETURN(rc);
}

/**
 * This function is called if this client was notified for target restarting
 * by the MGS. A CONFIG_READ RPC is going to send to fetch recovery or
 * nodemap logs.
 */
static int mgc_process_recover_log(struct obd_device *obd,
					   struct config_llog_data *cld)
{
	struct ptlrpc_request *req = NULL;
	struct config_llog_instance *cfg = &cld->cld_cfg;
	struct mgs_config_body *body;
	struct mgs_config_res *res;
	struct ptlrpc_bulk_desc *desc;
	struct page **pages = NULL;
	int nrpages = 0;
	bool eof = true;
	bool mne_swab = false;
	int i;
	int ealen;
	int rc;

	ENTRY;

	/* allocate buffer for bulk transfer.
	 * if this is the first time for this mgs to read logs,
	 * CONFIG_READ_NRPAGES_INIT will be used since it will read all logs
	 * once; otherwise, it only reads increment of logs, this should be
	 * small and CONFIG_READ_NRPAGES will be used.
	 */
	nrpages = CONFIG_READ_NRPAGES;
	if (cfg->cfg_last_idx == 0)
		nrpages = CONFIG_READ_NRPAGES_INIT;

	OBD_ALLOC_PTR_ARRAY_LARGE(pages, nrpages);
	if (pages == NULL)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < nrpages; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (pages[i] == NULL)
			GOTO(out, rc = -ENOMEM);
	}

again:
	LASSERT(cld_is_recover(cld));
	LASSERT(mutex_is_locked(&cld->cld_lock));
	req = ptlrpc_request_alloc(class_exp2cliimp(cld->cld_mgcexp),
				   &RQF_MGS_CONFIG_READ);
	if (req == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_MGS_VERSION, MGS_CONFIG_READ);
	if (rc)
		GOTO(out, rc);

	/* pack request */
	body = req_capsule_client_get(&req->rq_pill, &RMF_MGS_CONFIG_BODY);
	LASSERT(body != NULL);
	LASSERT(sizeof(body->mcb_name) > strlen(cld->cld_logname));
	rc = strscpy(body->mcb_name, cld->cld_logname, sizeof(body->mcb_name));
	if (rc < 0)
		GOTO(out, rc);
	body->mcb_offset = cfg->cfg_last_idx + 1;
	body->mcb_type = cld->cld_type;
	body->mcb_bits = PAGE_SHIFT;
	body->mcb_units = nrpages;
	body->mcb_rec_nid_size = sizeof(struct lnet_nid);

	/* allocate bulk transfer descriptor */
	desc = ptlrpc_prep_bulk_imp(req, nrpages, 1,
				    PTLRPC_BULK_PUT_SINK,
				    MGS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_pin_ops);
	if (desc == NULL)
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

	if (res->mcr_size < res->mcr_offset)
		GOTO(out, rc = -EINVAL);

	/* always update the index even though it might have errors with
	 * handling the recover logs
	 */
	cfg->cfg_last_idx = res->mcr_offset;
	eof = res->mcr_offset == res->mcr_size;

	CDEBUG(D_INFO, "Latest version %lld, more %d.\n",
	       res->mcr_offset, eof == false);

	ealen = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk, 0);
	if (ealen < 0)
		GOTO(out, rc = ealen);

	if (ealen > nrpages << PAGE_SHIFT)
		GOTO(out, rc = -EINVAL);

	if (ealen == 0) { /* no logs transferred */
		if (!eof)
			rc = -EINVAL;
		GOTO(out, rc);
	}

	mne_swab = req_capsule_rep_need_swab(&req->rq_pill);

	for (i = 0; i < nrpages && ealen > 0; i++) {
		int rc2;
		union lu_page *ptr;

		ptr = kmap(pages[i]);
		rc2 = mgc_apply_recover_logs(obd, cld, res->mcr_offset, ptr,
					     min_t(int, ealen, PAGE_SIZE),
					     mne_swab);
		kunmap(pages[i]);
		if (rc2 < 0) {
			CWARN("%s: error processing %s log recovery: rc = %d\n",
			      obd->obd_name,
			      cld->cld_logname,
			      rc2);
			GOTO(out, rc = rc2);
		}

		ealen -= PAGE_SIZE;
	}

out:
	if (req) {
		ptlrpc_req_put(req);
		req = NULL;
	}

	if (rc == 0 && !eof)
		goto again;

	if (pages) {
		for (i = 0; i < nrpages; i++) {
			if (pages[i] == NULL)
				break;
			__free_page(pages[i]);
		}
		OBD_FREE_PTR_ARRAY_LARGE(pages, nrpages);
	}
	return rc;
}

/* local_only means it cannot get remote llogs */
static int mgc_process_cfg_log(struct obd_device *mgc,
			       struct config_llog_data *cld, int local_only)
{
	struct llog_ctxt *ctxt;
	struct lustre_sb_info *lsi = NULL;
	int rc = 0;
	struct lu_env *env;

	ENTRY;
	LASSERT(cld);
	LASSERT(mutex_is_locked(&cld->cld_lock));

#ifndef HAVE_SERVER_SUPPORT
	if (local_only)
		RETURN(-EIO);
#endif
	if (cld->cld_cfg.cfg_sb)
		lsi = s2lsi(cld->cld_cfg.cfg_sb);
	/* sptlrpc llog must not keep ref to sb,
	 * it was just needed to get lsi
	 */
	if (cld_is_sptlrpc(cld))
		cld->cld_cfg.cfg_sb = NULL;

	OBD_ALLOC_PTR(env);
	if (!env)
		RETURN(-ENOMEM);

	rc = lu_env_init(env, LCT_MG_THREAD);
	if (rc)
		GOTO(out_free, rc);

	ctxt = llog_get_context(mgc, LLOG_CONFIG_REPL_CTXT);
	LASSERT(ctxt);

#ifdef HAVE_SERVER_SUPPORT
	/* IS_SERVER(lsi) doesn't work if MGC is shared between client/server
	 * distinguish server mount by local storage set by server_mgc_set_fs()
	 */
	if (lsi && mgc->u.cli.cl_mgc_los) {
		if (!IS_MGS(lsi))
			rc = mgc_process_server_cfg_log(env, &ctxt, lsi, mgc,
							cld, !local_only);
	} else if (local_only) {
		rc = -EIO;
	}
#endif
	/* When returned from mgc_process_server_cfg_log() the rc can be:
	 *   0 - config llog context is returned for parsing below
	 *   EALREADY - config was parsed already
	 *   rc < 0 - fatal error, local and remote parsing are not available
	 */
	if (!rc)
		rc = class_config_parse_llog(env, ctxt, cld->cld_logname,
					     &cld->cld_cfg);
	if (rc < 0)
		GOTO(out_pop, rc);
	/*
	 * update settings on existing OBDs.
	 * the logname must be <fsname>-sptlrpc
	 */
	if (cld_is_sptlrpc(cld))
		class_notify_sptlrpc_conf(cld->cld_logname,
					  strlen(cld->cld_logname) -
					  strlen("-sptlrpc"));
	rc = 0;
	EXIT;

out_pop:
	__llog_ctxt_put(env, ctxt);
	lu_env_fini(env);
out_free:
	OBD_FREE_PTR(env);
	return rc;
}

static bool mgc_import_in_recovery(struct obd_import *imp)
{
	bool in_recovery = true;

	spin_lock(&imp->imp_lock);
	if (imp->imp_state == LUSTRE_IMP_FULL ||
	    imp->imp_state == LUSTRE_IMP_CLOSED)
		in_recovery = false;
	spin_unlock(&imp->imp_lock);

	return in_recovery;
}

/**
 * Get a configuration log from the MGS and process it.
 *
 * This function is called for both clients and servers to process the
 * configuration log from the MGS.  The MGC enqueues a DLM lock on the
 * log from the MGS, and if the lock gets revoked the MGC will be notified
 * by the lock cancellation callback that the config log has changed,
 * and will enqueue another MGS lock on it, and then continue processing
 * the new additions to the end of the log.
 *
 * Since the MGC import is not replayable, if the import is being evicted
 * (rcl == -ESHUTDOWN, \see ptlrpc_import_delay_req()), retry to process
 * the log until recovery is finished or the import is closed.
 *
 * Make a local copy of the log before parsing it if appropriate (non-MGS
 * server) so that the server can start even when the MGS is down.
 *
 * There shouldn't be multiple processes running process_log at once --
 * sounds like badness.  It actually might be fine, as long as they're not
 * trying to update from the same log simultaneously, in which case we
 * should use a per-log semaphore instead of cld_lock.
 *
 * \param[in] mgc	MGC device by which to fetch the configuration log
 * \param[in] cld	log processing state (stored in lock callback data)
 *
 * \retval		0 on success
 * \retval		negative errno on failure
 */
int mgc_process_log(struct obd_device *mgc, struct config_llog_data *cld)
{
	struct lustre_handle lockh = { 0 };
	__u64 flags = LDLM_FL_NO_LRU;
	int rc = 0, rcl;
	bool retry = false;

	ENTRY;

	LASSERT(cld != NULL);

	/* I don't want multiple processes running process_log at once --
	 * sounds like badness.  It actually might be fine, as long as
	 * we're not trying to update from the same log
	 * simultaneously (in which case we should use a per-log sem.)
	 */
restart:
	mutex_lock(&cld->cld_lock);
	if (cld->cld_stopping) {
		mutex_unlock(&cld->cld_lock);
		RETURN(0);
	}

	CFS_FAIL_TIMEOUT(OBD_FAIL_MGC_PAUSE_PROCESS_LOG, 20);

	CDEBUG(D_MGC, "Process log %s-%016lx from %d\n", cld->cld_logname,
	       cld->cld_cfg.cfg_instance, cld->cld_cfg.cfg_last_idx + 1);

	/* Get the cfg lock on the llog */
	rcl = mgc_enqueue(mgc->u.cli.cl_mgc_mgsexp, LDLM_PLAIN, NULL,
			  LCK_CR, &flags,
			  cld_is_barrier(cld) ? mgc_barrier_glimpse_ast : NULL,
			  cld, 0, NULL, &lockh);
	if (rcl == 0) {
		/* Get the cld, it will be released in mgc_blocking_ast. */
		config_log_get(cld);
		rc = ldlm_lock_set_data(&lockh, (void *)cld);
		LASSERT(!lustre_handle_is_used(&cld->cld_lockh));
		LASSERT(rc == 0);
		cld->cld_lockh = lockh;
	} else {
		CDEBUG(D_MGC, "Can't get cfg lock: %d\n", rcl);
		cld->cld_lockh.cookie = 0;

		if (rcl == -ESHUTDOWN &&
		    atomic_read(&mgc->u.cli.cl_mgc_refcount) > 0 && !retry) {
			struct obd_import *imp;
			long timeout = cfs_time_seconds(obd_timeout);

			mutex_unlock(&cld->cld_lock);
			imp = class_exp2cliimp(mgc->u.cli.cl_mgc_mgsexp);

			/* Let's force the pinger, and wait the import to be
			 * connected, note: since mgc import is non-replayable,
			 * and even the import state is disconnected, it does
			 * not mean the "recovery" is stopped, so we will keep
			 * waitting until timeout or the import state is
			 * FULL or closed
			 */
			ptlrpc_pinger_force(imp);

			wait_event_idle_timeout(imp->imp_recovery_waitq,
						!mgc_import_in_recovery(imp),
						timeout);

			if (imp->imp_state == LUSTRE_IMP_FULL) {
				retry = true;
				goto restart;
			} else {
				mutex_lock(&cld->cld_lock);
				/* unlock/lock mutex, so check stopping again */
				if (cld->cld_stopping) {
					mutex_unlock(&cld->cld_lock);
					RETURN(0);
				}
				spin_lock(&config_list_lock);
				cld->cld_lostlock = 1;
				spin_unlock(&config_list_lock);
			}
		} else {
			/* mark cld_lostlock so that it will requeue
			 * after MGC becomes available.
			 */
			spin_lock(&config_list_lock);
			cld->cld_lostlock = 1;
			spin_unlock(&config_list_lock);
		}
	}

	if (cld_is_recover(cld) && !rcl)
		rc = mgc_process_recover_log(mgc, cld);
#ifdef HAVE_SERVER_SUPPORT
	else if (cld_is_nodemap(cld)) {
		if (rcl)
			rc = rcl;
		else
			rc = mgc_process_nodemap_log(mgc, cld);
	}
#endif
	else if (!cld_is_barrier(cld))
		rc = mgc_process_cfg_log(mgc, cld, rcl != 0);

	CDEBUG(D_MGC, "%s: configuration from log '%s' %sed (%d).\n",
	       mgc->obd_name, cld->cld_logname, rc ? "fail" : "succeed", rc);
	if (rc != -ETIMEDOUT && rc != -EIO && rc != -EAGAIN) {
		cld->cld_processed = 1;
		wake_up(&rq_waitq);
	}

	/* Now drop the lock so MGS can revoke it */
	if (!rcl) {
		rcl = mgc_cancel(mgc->u.cli.cl_mgc_mgsexp, LCK_CR, &lockh);
		if (rcl)
			CERROR("Can't drop cfg lock: %d\n", rcl);
	}
	mutex_unlock(&cld->cld_lock);

	/* requeue nodemap lock immediately if transfer was interrupted */
	if ((cld_is_nodemap(cld) && rc == -EAGAIN) ||
	    (cld_is_recover(cld) && rc)) {
		if (cld_is_recover(cld))
			CWARN("%s: IR log %s failed, not fatal: rc = %d\n",
			      mgc->obd_name, cld->cld_logname, rc);
		mgc_requeue_add(cld);
		rc = 0;
	}

	RETURN(rc);
}


/* Called from lustre_process_log.
 * LCFG_LOG_START gets the config log from the MGS, processes it to start
 * any services, and adds it to the list logs to watch (follow).
 */
static int mgc_process_config(struct obd_device *obd, size_t len, void *buf)
{
	struct lustre_cfg *lcfg = buf;
	struct config_llog_instance *cfg = NULL;
	char *logname;
	int rc;

	ENTRY;
#ifdef HAVE_SERVER_SUPPORT
	rc = mgc_process_config_server(obd, len, buf);
	if (rc != -ENOENT)
		RETURN(rc);
#endif

	switch (lcfg->lcfg_command) {
	case LCFG_SPTLRPC_CONF: {
		rc = sptlrpc_process_config(lcfg);
		break;
	}
	case LCFG_LOG_START: {
		struct config_llog_data *cld;
		struct super_block *sb;

		logname = lustre_cfg_string(lcfg, 1);
		cfg = (struct config_llog_instance *)lustre_cfg_buf(lcfg, 2);
		sb = *(struct super_block **)lustre_cfg_buf(lcfg, 3);

		CDEBUG(D_MGC, "parse_log %s from %d\n", logname,
		       cfg->cfg_last_idx);

		/* We're only called through here on the initial mount */
		cld = config_log_add(obd, logname, cfg, sb);
		if (IS_ERR(cld)) {
			rc = PTR_ERR(cld);
			break;
		}

		/* if it exists, the sptlrpc config log really needs to be
		 * correctly processed before processing other logs,
		 * otherwise client might use incorrect sec flavor
		 */
		if (cld->cld_sptlrpc && !cld->cld_sptlrpc->cld_processed) {
			unsigned int timeout = 120;

			/* we do not want to wait forever,
			 * we prefer a (excessively) long timeout
			 */
			timeout = max(20 * mgc_requeue_timeout_min, timeout);
			wait_event_idle_timeout(rq_waitq,
						cld->cld_sptlrpc->cld_processed,
						cfs_time_seconds(timeout));
		}

		rc = mgc_process_log(obd, cld);
		if (rc == 0 && cld->cld_recover != NULL) {
			if (OCD_HAS_FLAG(&obd->u.cli.cl_import->
					 imp_connect_data, IMP_RECOV)) {
				rc = mgc_process_log(obd, cld->cld_recover);
			} else {
				struct config_llog_data *cir;

				mutex_lock(&cld->cld_lock);
				cir = cld->cld_recover;
				cld->cld_recover = NULL;
				mutex_unlock(&cld->cld_lock);
				config_log_put(cir);
			}

			if (rc)
				CERROR("Cannot process recover llog %d\n", rc);
		}

		if (rc == 0 && cld->cld_params != NULL) {
			rc = mgc_process_log(obd, cld->cld_params);
			if (rc == -ENOENT) {
				CDEBUG(D_MGC,
				       "There is no params config file yet\n");
				rc = 0;
			}
			/* params log is optional */
			if (rc)
				CERROR("%s: can't process params llog: rc = %d\n",
				       obd->obd_name, rc);
		}

		break;
	}
	case LCFG_LOG_END: {
		logname = lustre_cfg_string(lcfg, 1);

		if (lcfg->lcfg_bufcount >= 2)
			cfg = (struct config_llog_instance *)lustre_cfg_buf(lcfg, 2);
		rc = config_log_end(logname, cfg);
		break;
	}
	default:
		CERROR("Unknown command: %d\n", lcfg->lcfg_command);
		rc = -EINVAL;
		break;
	}

	RETURN(rc);
}

static const struct obd_ops mgc_obd_ops = {
	.o_owner        = THIS_MODULE,
	.o_setup        = mgc_setup,
	.o_precleanup   = mgc_precleanup,
	.o_cleanup      = mgc_cleanup,
	.o_add_conn     = client_import_add_conn,
	.o_del_conn     = client_import_del_conn,
	.o_connect      = client_connect_import,
	.o_disconnect   = client_disconnect_export,
	.o_set_info_async = mgc_set_info_async,
	.o_get_info       = mgc_get_info,
	.o_import_event = mgc_import_event,
	.o_process_config = mgc_process_config,
};

static int mgc_param_requeue_timeout_min_set(const char *val,
				     cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned int num;

	rc = kstrtouint(val, 0, &num);
	if (rc < 0)
		return rc;
	if (num > 120)
		return -EINVAL;

	mgc_requeue_timeout_min = num;

	return 0;
}

static const struct kernel_param_ops param_ops_requeue_timeout_min = {
	.set = mgc_param_requeue_timeout_min_set,
	.get = param_get_uint,
};

#define param_check_requeue_timeout_min(name, p) \
		__param_check(name, p, unsigned int)

unsigned int mgc_requeue_timeout_min = MGC_TIMEOUT_MIN_SECONDS;
#ifdef HAVE_KERNEL_PARAM_OPS
module_param(mgc_requeue_timeout_min, requeue_timeout_min, 0644);
#else
module_param_call(mgc_requeue_timeout_min, mgc_param_requeue_timeout_min_set,
		  param_get_uint, &param_ops_requeue_timeout_min, 0644);
#endif
MODULE_PARM_DESC(mgc_requeue_timeout_min, "Minimal requeue time to refresh logs");

static int __init mgc_init(void)
{
	int rc;

	rc = libcfs_setup();
	if (rc)
		return rc;

	return class_register_type(&mgc_obd_ops, NULL, false,
				   LUSTRE_MGC_NAME, NULL);
}

static void __exit mgc_exit(void)
{
	class_unregister_type(LUSTRE_MGC_NAME);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Management Client");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(mgc_init);
module_exit(mgc_exit);
