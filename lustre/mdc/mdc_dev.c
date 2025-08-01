// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_device, cl_req for MDC layer.
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <obd_class.h>
#include <lustre_osc.h>
#include <linux/falloc.h>
#include <uapi/linux/lustre/lustre_param.h>

#include "mdc_internal.h"

static void mdc_lock_build_policy(const struct lu_env *env,
				  const struct cl_lock *lock,
				  union ldlm_policy_data *policy)
{
	memset(policy, 0, sizeof *policy);
	policy->l_inodebits.bits = MDS_INODELOCK_DOM;
	if (lock) {
		policy->l_inodebits.li_gid = lock->cll_descr.cld_gid;
	}
}

int mdc_ldlm_glimpse_ast(struct ldlm_lock *dlmlock, void *data)
{
	return osc_ldlm_glimpse_ast(dlmlock, data);
}

static void mdc_lock_build_einfo(const struct lu_env *env,
				 const struct cl_lock *lock,
				 struct osc_object *osc,
				 struct ldlm_enqueue_info *einfo)
{
	einfo->ei_type = LDLM_IBITS;
	einfo->ei_mode = osc_cl_lock2ldlm(lock->cll_descr.cld_mode);
	einfo->ei_cb_bl = mdc_ldlm_blocking_ast;
	einfo->ei_cb_cp = ldlm_completion_ast;
	einfo->ei_cb_gl = mdc_ldlm_glimpse_ast;
	einfo->ei_cbdata = osc; /* value to be put into ->l_ast_data */
	einfo->ei_req_slot = 1;
}

static void mdc_lock_lvb_update(const struct lu_env *env,
				struct osc_object *osc,
				struct ldlm_lock *dlmlock,
				struct ost_lvb *lvb);

static int mdc_set_dom_lock_data(struct ldlm_lock *lock, void *data)
{
	int set = 0;

	LASSERT(lock != NULL);
	LASSERT(lock->l_glimpse_ast == mdc_ldlm_glimpse_ast);

	lock_res_and_lock(lock);

	if (lock->l_ast_data == NULL)
		lock->l_ast_data = data;
	if (lock->l_ast_data == data)
		set = 1;

	unlock_res_and_lock(lock);

	return set;
}

static int mdc_dom_lock_match(const struct lu_env *env, struct obd_export *exp,
			      struct ldlm_res_id *res_id, enum ldlm_type type,
			      union ldlm_policy_data *policy,
			      enum ldlm_mode mode, __u64 *flags,
			      struct osc_object *obj,
			      enum ldlm_match_flags match_flags,
			      struct lustre_handle *lockh)
{
	struct obd_device *obd = exp->exp_obd;
	__u64 lflags = *flags;
	enum ldlm_mode rc;

	ENTRY;

	rc = ldlm_lock_match_with_skip(obd->obd_namespace, lflags, 0,
			     res_id, type, policy, mode, match_flags, lockh);
	if (rc == 0 || lflags & LDLM_FL_TEST_LOCK)
		RETURN(rc);

	if (obj != NULL) {
		struct ldlm_lock *lock = ldlm_handle2lock(lockh);

		LASSERT(lock != NULL);
		if (mdc_set_dom_lock_data(lock, obj)) {
			lock_res_and_lock(lock);
			if (!(lock->l_flags & LDLM_FL_LVB_CACHED)) {
				LASSERT(lock->l_ast_data == obj);
				mdc_lock_lvb_update(env, obj, lock, NULL);
				(lock->l_flags |= LDLM_FL_LVB_CACHED);
			}
			unlock_res_and_lock(lock);
		} else {
			ldlm_lock_decref(lockh, rc);
			rc = 0;
		}
		ldlm_lock_put(lock);
	}
	RETURN(rc);
}

/**
 * Finds an existing lock covering a page with given index.
 * Copy of osc_obj_dlmlock_at_pgoff() but for DoM IBITS lock.
 */
static struct ldlm_lock *mdc_dlmlock_at_pgoff(const struct lu_env *env,
					      struct osc_object *obj,
					      pgoff_t index,
					      enum osc_dap_flags dap_flags)
{
	struct osc_thread_info *info = osc_env_info(env);
	struct ldlm_res_id *resname = &info->oti_resname;
	union ldlm_policy_data *policy = &info->oti_policy;
	struct lustre_handle lockh;
	struct ldlm_lock *lock = NULL;
	enum ldlm_mode mode;
	__u64 flags;
	enum ldlm_match_flags match_flags = 0;

	ENTRY;

	fid_build_reg_res_name(lu_object_fid(osc2lu(obj)), resname);
	mdc_lock_build_policy(env, NULL, policy);
	policy->l_inodebits.li_gid = LDLM_GID_ANY;

	flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING;
	if (dap_flags & OSC_DAP_FL_TEST_LOCK)
		flags |= LDLM_FL_TEST_LOCK;

	if (dap_flags & OSC_DAP_FL_AST)
		match_flags |= LDLM_MATCH_AST;

	if (dap_flags & OSC_DAP_FL_CANCELING)
		match_flags |= LDLM_MATCH_UNREF;

again:
	/* Next, search for already existing extent locks that will cover us */
	/* If we're trying to read, we also search for an existing PW lock.  The
	 * VFS and page cache already protect us locally, so lots of readers/
	 * writers can share a single PW lock. */
	mode = mdc_dom_lock_match(env, osc_export(obj), resname, LDLM_IBITS,
				  policy, LCK_PR | LCK_PW | LCK_GROUP, &flags,
				  obj, match_flags, &lockh);
	if (mode != 0) {
		lock = ldlm_handle2lock(&lockh);
		/* RACE: the lock is cancelled so let's try again */
		if (unlikely(lock == NULL))
			goto again;
	}

	RETURN(lock);
}

/**
 * Check if page @page is covered by an extra lock or discard it.
 */
static bool mdc_check_and_discard_cb(const struct lu_env *env, struct cl_io *io,
				     void **pvec, int count, void *cbdata)
{
	struct osc_thread_info *info = osc_env_info(env);
	struct osc_object *osc = cbdata;
	pgoff_t index;
	int i;

	for (i = 0; i < count; i++) {
		struct osc_page *ops = pvec[i];

		index = osc_index(ops);
		if (index >= info->oti_fn_index) {
			struct ldlm_lock *tmp;
			struct cl_page *page = ops->ops_cl.cpl_page;

			/* refresh non-overlapped index */
			tmp = mdc_dlmlock_at_pgoff(env, osc, index,
					OSC_DAP_FL_TEST_LOCK | OSC_DAP_FL_AST);
			if (tmp != NULL) {
				info->oti_fn_index = CL_PAGE_EOF;
				ldlm_lock_put(tmp);
			} else if (cl_page_own(env, io, page) == 0) {
				/* discard the page */
				cl_page_discard(env, io, page);
				cl_page_disown(env, io, page);
			} else {
				if (page->cp_type != CPT_TRANSIENT)
					LASSERT(page->cp_state == CPS_FREEING);
			}
		}

		info->oti_next_index = index + 1;
	}
	return true;
}

/**
 * Discard pages protected by the given lock. This function traverses radix
 * tree to find all covering pages and discard them. If a page is being covered
 * by other locks, it should remain in cache.
 *
 * If error happens on any step, the process continues anyway (the reasoning
 * behind this being that lock cancellation cannot be delayed indefinitely).
 */
static int mdc_lock_discard_pages(const struct lu_env *env,
				  struct osc_object *osc,
				  pgoff_t start, pgoff_t end,
				  bool discard)
{
	struct osc_thread_info *info = osc_env_info(env);
	struct cl_io *io = &info->oti_io;
	osc_page_gang_cbt cb;
	int result;

	ENTRY;

	io->ci_obj = cl_object_top(osc2cl(osc));
	io->ci_ignore_layout = 1;
	io->u.ci_misc.lm_next_rpc_time = 0;

	result = cl_io_init(env, io, CIT_MISC, io->ci_obj);
	if (result != 0)
		GOTO(out, result);

	cb = discard ? osc_discard_cb : mdc_check_and_discard_cb;
	info->oti_fn_index = info->oti_next_index = start;

	osc_page_gang_lookup(env, io, osc, info->oti_next_index,
			     end, cb, (void *)osc);
out:
	cl_io_fini(env, io);
	RETURN(result);
}

static int mdc_lock_flush(const struct lu_env *env, struct osc_object *obj,
			  pgoff_t start, pgoff_t end, enum cl_lock_mode mode,
			  bool discard)
{
	int result = 0;
	int rc;

	ENTRY;

	if (mode == CLM_WRITE) {
		result = osc_cache_writeback_range(env, obj, start, end, 1,
						   discard, IO_PRIO_NORMAL);
		CDEBUG(D_CACHE, "object %p: [%lu -> %lu] %d pages were %s.\n",
		       obj, start, end, result,
		       discard ? "discarded" : "written back");
		if (result > 0)
			result = 0;
	}

	/* Avoid lock matching with CLM_WRITE, there can be no other locks */
	rc = mdc_lock_discard_pages(env, obj, start, end,
				    mode == CLM_WRITE || discard);
	if (result == 0 && rc < 0)
		result = rc;

	RETURN(result);
}

static void mdc_lock_lockless_cancel(const struct lu_env *env,
				     const struct cl_lock_slice *slice)
{
	struct osc_lock *ols = cl2osc_lock(slice);
	struct osc_object *osc = cl2osc(slice->cls_obj);
	struct cl_lock_descr *descr = &slice->cls_lock->cll_descr;
	int rc;

	LASSERT(ols->ols_dlmlock == NULL);
	rc = mdc_lock_flush(env, osc, descr->cld_start, descr->cld_end,
			    descr->cld_mode, 0);
	if (rc != 0)
		CERROR("Pages for lockless lock %p were not purged(%d)\n",
		       ols, rc);

	osc_lock_wake_waiters(env, osc, ols);
}

/**
 * Helper for osc_dlm_blocking_ast() handling discrepancies between cl_lock
 * and ldlm_lock caches.
 */
static int mdc_dlm_canceling(const struct lu_env *env,
			     struct ldlm_lock *dlmlock)
{
	struct cl_object *obj = NULL;
	int result = 0;
	bool discard;
	enum cl_lock_mode mode = CLM_READ;

	ENTRY;

	lock_res_and_lock(dlmlock);
	if (!ldlm_is_granted(dlmlock)) {
		dlmlock->l_ast_data = NULL;
		unlock_res_and_lock(dlmlock);
		RETURN(0);
	}

	discard = (dlmlock->l_flags & LDLM_FL_DISCARD_DATA);
	if (dlmlock->l_granted_mode & (LCK_PW | LCK_GROUP))
		mode = CLM_WRITE;

	if (dlmlock->l_ast_data != NULL) {
		obj = osc2cl(dlmlock->l_ast_data);
		cl_object_get(obj);
	}
	unlock_res_and_lock(dlmlock);

	/* if l_ast_data is NULL, the dlmlock was enqueued by AGL or
	 * the object has been destroyed. */
	if (obj != NULL) {
		struct cl_attr *attr = &osc_env_info(env)->oti_attr;

		/* Destroy pages covered by the extent of the DLM lock */
		result = mdc_lock_flush(env, cl2osc(obj), 0,
					CL_PAGE_EOF, mode, discard);
		/* Losing a lock, set KMS to 0.
		 * NB: assumed that DOM lock covers whole data on MDT.
		 */
		/* losing a lock, update kms */
		lock_res_and_lock(dlmlock);
		dlmlock->l_ast_data = NULL;
		cl_object_attr_lock(obj);
		attr->cat_kms = 0;
		cl_object_attr_update(env, obj, attr, CAT_KMS);
		cl_object_attr_unlock(obj);
		unlock_res_and_lock(dlmlock);
		cl_object_put(env, obj);
	}
	RETURN(result);
}

int mdc_ldlm_blocking_ast(struct ldlm_lock *dlmlock,
			  struct ldlm_lock_desc *new, void *data, int reason)
{
	int rc = 0;

	ENTRY;

	switch (reason) {
	case LDLM_CB_BLOCKING: {
		struct lustre_handle lockh;

		ldlm_lock2handle(dlmlock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		if (rc == -ENODATA)
			rc = 0;
		break;
	}
	case LDLM_CB_CANCELING: {
		struct lu_env *env;
		__u16 refcheck;

		/*
		 * This can be called in the context of outer IO, e.g.,
		 *
		 *    osc_enqueue_base()->...
		 *      ->ldlm_prep_elc_req()->...
		 *        ->ldlm_cancel_callback()->...
		 *          ->osc_ldlm_blocking_ast()
		 *
		 * new environment has to be created to not corrupt outer
		 * context.
		 */
		env = cl_env_get(&refcheck);
		if (IS_ERR(env)) {
			rc = PTR_ERR(env);
			break;
		}

		rc = mdc_dlm_canceling(env, dlmlock);
		cl_env_put(env, &refcheck);
		break;
	}
	default:
		LBUG();
	}
	RETURN(rc);
}

/**
 * Updates object attributes from a lock value block (lvb) received together
 * with the DLM lock reply from the server.
 * This can be optimized to not update attributes when lock is a result of a
 * local match.
 *
 * Called under lock and resource spin-locks.
 */
void mdc_lock_lvb_update(const struct lu_env *env, struct osc_object *osc,
			 struct ldlm_lock *dlmlock, struct ost_lvb *lvb)
{
	struct cl_object *obj = osc2cl(osc);
	struct lov_oinfo *oinfo = osc->oo_oinfo;
	struct cl_attr *attr = &osc_env_info(env)->oti_attr;
	enum cl_attr_valid valid = CAT_BLOCKS | CAT_ATIME | CAT_CTIME |
				   CAT_MTIME | CAT_SIZE;
	unsigned int setkms = 0;

	ENTRY;

	if (lvb == NULL) {
		LASSERT(dlmlock != NULL);
		/* l_ost_lvb is only in the LDLM_IBITS union **/
		LASSERT(dlmlock->l_resource->lr_type == LDLM_IBITS);
		lvb = &dlmlock->l_ost_lvb;
	}
	cl_lvb2attr(attr, lvb);

	cl_object_attr_lock(obj);
	if (dlmlock != NULL) {
		__u64 size;

		check_res_locked(dlmlock->l_resource);
		size = lvb->lvb_size;

		if (size >= oinfo->loi_kms) {
			valid |= CAT_KMS;
			attr->cat_kms = size;
			setkms = 1;
		}
		ldlm_lock_allow_match_locked(dlmlock);
	}

	/* The size should not be less than the kms */
	if (attr->cat_size < oinfo->loi_kms)
		attr->cat_size = oinfo->loi_kms;

	LDLM_DEBUG(dlmlock, "acquired size %llu, setting rss=%llu;%s "
		   "kms=%llu, end=%llu", lvb->lvb_size, attr->cat_size,
		   setkms ? "" : " leaving",
		   setkms ? attr->cat_kms : oinfo->loi_kms,
		   dlmlock ? dlmlock->l_policy_data.l_extent.end : -1ull);

	cl_object_attr_update(env, obj, attr, valid);
	cl_object_attr_unlock(obj);
	EXIT;
}

static void mdc_lock_granted(const struct lu_env *env, struct osc_lock *oscl,
			     struct lustre_handle *lockh)
{
	struct osc_object *osc = cl2osc(oscl->ols_cl.cls_obj);
	struct ldlm_lock *dlmlock;

	ENTRY;

	dlmlock = ldlm_handle2lock_long(lockh, 0);
	LASSERT(dlmlock != NULL);

	/* lock reference taken by ldlm_handle2lock_long() is
	 * owned by osc_lock and released in osc_lock_detach()
	 */
	oscl->ols_has_ref = 1;

	LASSERT(oscl->ols_dlmlock == NULL);
	oscl->ols_dlmlock = dlmlock;

	/* This may be a matched lock for glimpse request, do not hold
	 * lock reference in that case. */
	if (!oscl->ols_glimpse) {
		/* hold a refc for non glimpse lock which will
		 * be released in osc_lock_cancel() */
		lustre_handle_copy(&oscl->ols_handle, lockh);
		ldlm_lock_addref(lockh, oscl->ols_einfo.ei_mode);
		oscl->ols_hold = 1;
	}

	/* Lock must have been granted. */
	lock_res_and_lock(dlmlock);
	if (ldlm_is_granted(dlmlock)) {
		struct cl_lock_descr *descr = &oscl->ols_cl.cls_lock->cll_descr;

		/* extend the lock extent, otherwise it will have problem when
		 * we decide whether to grant a lockless lock. */
		descr->cld_mode = osc_ldlm2cl_lock(dlmlock->l_granted_mode);
		descr->cld_start = 0;
		descr->cld_end = CL_PAGE_EOF;

		/* no lvb update for matched lock */
		if (!(dlmlock->l_flags & LDLM_FL_LVB_CACHED)) {
			LASSERT(oscl->ols_flags & LDLM_FL_LVB_READY);
			LASSERT(osc == dlmlock->l_ast_data);
			mdc_lock_lvb_update(env, osc, dlmlock, NULL);
			(dlmlock->l_flags |= LDLM_FL_LVB_CACHED);
		}
	}
	unlock_res_and_lock(dlmlock);

	LASSERT(oscl->ols_state != OLS_GRANTED);
	oscl->ols_state = OLS_GRANTED;
	EXIT;
}

/**
 * Lock upcall function that is executed either when a reply to ENQUEUE rpc is
 * received from a server, or after mdc_enqueue_send() matched a local DLM
 * lock.
 */
static int mdc_lock_upcall(void *cookie, struct lustre_handle *lockh,
			   int errcode)
{
	struct osc_lock *oscl = cookie;
	struct cl_lock_slice *slice = &oscl->ols_cl;
	struct lu_env *env;
	int rc;

	ENTRY;

	env = cl_env_percpu_get();
	/* should never happen, similar to osc_ldlm_blocking_ast(). */
	LASSERT(!IS_ERR(env));

	rc = ldlm_error2errno(errcode);
	if (oscl->ols_state == OLS_ENQUEUED) {
		oscl->ols_state = OLS_UPCALL_RECEIVED;
	} else if (oscl->ols_state == OLS_CANCELLED) {
		rc = -EIO;
	} else {
		CERROR("Impossible state: %d\n", oscl->ols_state);
		LBUG();
	}

	CDEBUG(D_INODE, "rc %d, err %d\n", rc, errcode);
	if (rc == 0)
		mdc_lock_granted(env, oscl, lockh);

	/* Error handling, some errors are tolerable. */
	if (oscl->ols_glimpse && rc == -ENAVAIL) {
		LASSERT(oscl->ols_flags & LDLM_FL_LVB_READY);
		mdc_lock_lvb_update(env, cl2osc(slice->cls_obj),
				    NULL, &oscl->ols_lvb);
		/* Hide the error. */
		rc = 0;
	}

	if (oscl->ols_owner != NULL)
		cl_sync_io_note(env, oscl->ols_owner, rc);
	cl_env_percpu_put(env);

	RETURN(rc);
}

/* This is needed only for old servers (before 2.14) support */
int mdc_fill_lvb(struct req_capsule *pill, struct ost_lvb *lvb)
{
	struct mdt_body *body;

	/* get LVB data from mdt_body otherwise */
	body = req_capsule_server_get(pill, &RMF_MDT_BODY);
	if (!body)
		RETURN(-EPROTO);

	if (!(body->mbo_valid & OBD_MD_DOM_SIZE))
		RETURN(-EPROTO);

	mdc_body2lvb(body, lvb);
	RETURN(0);
}

static int mdc_enqueue_fini(struct obd_export *exp, struct ptlrpc_request *req,
			    osc_enqueue_upcall_f upcall, void *cookie,
			    struct lustre_handle *lockh, enum ldlm_mode mode,
			    __u64 *flags, int errcode)
{
	struct osc_lock *ols = cookie;
	bool glimpse = *flags & LDLM_FL_HAS_INTENT;
	int rc = 0;

	ENTRY;

	/* needed only for glimpse from an old server (< 2.14) */
	if (glimpse && !exp_connect_dom_lvb(exp) && errcode >= 0)
		rc = mdc_fill_lvb(&req->rq_pill, &ols->ols_lvb);

	if (glimpse && errcode == ELDLM_LOCK_ABORTED) {
		struct ldlm_reply *rep;

		rep = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
		if (likely(rep)) {
			rep->lock_policy_res2 =
				ptlrpc_status_ntoh(rep->lock_policy_res2);
			if (rep->lock_policy_res2)
				errcode = rep->lock_policy_res2;
		} else {
			rc = -EPROTO;
		}
		*flags |= LDLM_FL_LVB_READY;
	} else if (errcode == ELDLM_OK) {
		struct ldlm_lock *lock;

		/* Callers have references, should be valid always */
		lock = ldlm_handle2lock(lockh);

		/* At this point ols_lvb must be filled with correct LVB either
		 * by mdc_fill_lvb() above or by ldlm_cli_enqueue_fini().
		 * DoM uses l_ost_lvb to store LVB data (only available with
		 * LDLM_IBITS locks), so copy it here from just updated ols_lvb.
		 */
		LASSERT(lock->l_resource->lr_type == LDLM_IBITS);
		lock_res_and_lock(lock);
		memcpy(&lock->l_ost_lvb, &ols->ols_lvb,
		       sizeof(lock->l_ost_lvb));
		unlock_res_and_lock(lock);
		ldlm_lock_put(lock);
		*flags |= LDLM_FL_LVB_READY;
	}

	/* Call the update callback. */
	rc = (*upcall)(cookie, lockh, rc < 0 ? rc : errcode);

	/* release the reference taken in ldlm_cli_enqueue() */
	if (errcode == ELDLM_LOCK_MATCHED)
		errcode = ELDLM_OK;
	if (errcode == ELDLM_OK && lustre_handle_is_used(lockh))
		ldlm_lock_decref(lockh, mode);

	RETURN(rc);
}

static int mdc_enqueue_interpret(const struct lu_env *env,
				 struct ptlrpc_request *req,
				 void *args, int rc)
{
	struct osc_enqueue_args *aa = args;
	struct ldlm_lock *lock;
	struct lustre_handle *lockh = &aa->oa_lockh;
	enum ldlm_mode mode = aa->oa_mode;
	struct ldlm_enqueue_info einfo = {
		.ei_type = aa->oa_type,
		.ei_mode = mode,
	};

	ENTRY;

	LASSERT(!aa->oa_speculative);

	/* ldlm_cli_enqueue is holding a reference on the lock, so it must
	 * be valid. */
	lock = ldlm_handle2lock(lockh);
	LASSERTF(lock != NULL,
		 "lockh %#llx, req %px, aa %px - client evicted?\n",
		 lockh->cookie, req, aa);

	/* Take an additional reference so that a blocking AST that
	 * ldlm_cli_enqueue_fini() might post for a failed lock, is guaranteed
	 * to arrive after an upcall has been executed by
	 * mdc_enqueue_fini().
	 */
	ldlm_lock_addref(lockh, mode);

	/* Let cl_lock_state_wait fail with -ERESTARTSYS to unuse sublocks. */
	CFS_FAIL_TIMEOUT(OBD_FAIL_LDLM_ENQUEUE_HANG, 2);

	/* Let CP AST to grant the lock first. */
	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_ENQ_RACE, 1);

	/* Complete obtaining the lock procedure. */
	rc = ldlm_cli_enqueue_fini(aa->oa_exp, &req->rq_pill, &einfo, 1,
				   aa->oa_flags, aa->oa_lvb, aa->oa_lvb ?
				   sizeof(*aa->oa_lvb) : 0, lockh, rc, true);
	/* Complete mdc stuff. */
	rc = mdc_enqueue_fini(aa->oa_exp, req, aa->oa_upcall, aa->oa_cookie,
			      lockh, mode, aa->oa_flags, rc);

	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_CANCEL_RACE, 10);

	ldlm_lock_decref(lockh, mode);
	ldlm_lock_put(lock);
	RETURN(rc);
}

/* When enqueuing asynchronously, locks are not ordered, we can obtain a lock
 * from the 2nd OSC before a lock from the 1st one. This does not deadlock with
 * other synchronous requests, however keeping some locks and trying to obtain
 * others may take a considerable amount of time in a case of ost failure; and
 * when other sync requests do not get released lock from a client, the client
 * is excluded from the cluster -- such scenarious make the life difficult, so
 * release locks just after they are obtained. */
static int mdc_enqueue_send(const struct lu_env *env, struct obd_export *exp,
			    struct ldlm_res_id *res_id, __u64 *flags,
			    union ldlm_policy_data *policy, struct ost_lvb *lvb,
			    osc_enqueue_upcall_f upcall, void *cookie,
			    struct ldlm_enqueue_info *einfo, int async)
{
	struct obd_device *obd = exp->exp_obd;
	struct lustre_handle lockh = { 0 };
	struct ptlrpc_request *req = NULL;
	struct ldlm_intent *lit;
	enum ldlm_mode mode;
	bool glimpse = *flags & LDLM_FL_HAS_INTENT;
	__u64 search_flags = *flags;
	__u64 match_flags = 0;
	LIST_HEAD(cancels);
	int rc, count;
	int lvb_size;
	bool compat_glimpse = glimpse && !exp_connect_dom_lvb(exp);

	ENTRY;

	mode = einfo->ei_mode;
	if (einfo->ei_mode == LCK_PR)
		mode |= LCK_PW;

	search_flags |= LDLM_FL_LVB_READY;
	if (glimpse)
		search_flags |= LDLM_FL_BLOCK_GRANTED;
	if (mode == LCK_GROUP)
		match_flags = LDLM_MATCH_GROUP;
	mode = ldlm_lock_match_with_skip(obd->obd_namespace, search_flags, 0,
					 res_id, einfo->ei_type, policy, mode,
					 match_flags, &lockh);
	if (mode) {
		struct ldlm_lock *matched;

		if (*flags & LDLM_FL_TEST_LOCK)
			RETURN(ELDLM_OK);

		matched = ldlm_handle2lock(&lockh);

		if (CFS_FAIL_CHECK(OBD_FAIL_MDC_GLIMPSE_DDOS))
			(matched->l_flags |= LDLM_FL_KMS_IGNORE);

		if (mdc_set_dom_lock_data(matched, einfo->ei_cbdata)) {
			*flags |= LDLM_FL_LVB_READY;

			/* We already have a lock, and it's referenced. */
			(*upcall)(cookie, &lockh, ELDLM_LOCK_MATCHED);

			ldlm_lock_decref(&lockh, mode);
			ldlm_lock_put(matched);
			RETURN(ELDLM_OK);
		}
		ldlm_lock_decref(&lockh, mode);
		ldlm_lock_put(matched);
	}

	if (*flags & (LDLM_FL_TEST_LOCK | LDLM_FL_MATCH_LOCK))
		RETURN(-ENOLCK);

	/* Glimpse is intent on old server */
	req = ptlrpc_request_alloc(class_exp2cliimp(exp), compat_glimpse ?
				   &RQF_LDLM_INTENT : &RQF_LDLM_ENQUEUE);
	if (req == NULL)
		RETURN(-ENOMEM);

	/* For WRITE lock cancel other locks on resource early if any */
	if (einfo->ei_mode & LCK_PW)
		count = mdc_resource_cancel_unused_res(exp, res_id, &cancels,
						       einfo->ei_mode,
						       MDS_INODELOCK_DOM);
	else
		count = 0;

	rc = ldlm_prep_enqueue_req(exp, req, &cancels, count);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	if (compat_glimpse) {
		/* pack the glimpse intent */
		lit = req_capsule_client_get(&req->rq_pill, &RMF_LDLM_INTENT);
		lit->opc = IT_GLIMPSE;
	}

	/* users of mdc_enqueue() can pass this flag for ldlm_lock_match() */
	*flags &= ~LDLM_FL_BLOCK_GRANTED;

	if (compat_glimpse) {
		req_capsule_set_size(&req->rq_pill, &RMF_MDT_MD, RCL_SERVER, 0);
		req_capsule_set_size(&req->rq_pill, &RMF_ACL, RCL_SERVER, 0);
		lvb_size = 0;
	} else {
		lvb_size = sizeof(*lvb);
		req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
				     lvb_size);
	}
	ptlrpc_request_set_replen(req);

	rc = ldlm_cli_enqueue(exp, &req, einfo, res_id, policy, flags, lvb,
			      lvb_size, LVB_T_OST, &lockh, async);
	if (async) {
		if (!rc) {
			struct osc_enqueue_args *aa;

			aa = ptlrpc_req_async_args(aa, req);
			aa->oa_exp = exp;
			aa->oa_mode = einfo->ei_mode;
			aa->oa_type = einfo->ei_type;
			lustre_handle_copy(&aa->oa_lockh, &lockh);
			aa->oa_upcall = upcall;
			aa->oa_cookie = cookie;
			aa->oa_speculative = false;
			aa->oa_flags = flags;
			aa->oa_lvb = compat_glimpse ? NULL : lvb;

			req->rq_interpret_reply = mdc_enqueue_interpret;
			ptlrpcd_add_req(req);
		} else {
			ptlrpc_req_put(req);
		}
		RETURN(rc);
	}

	rc = mdc_enqueue_fini(exp, req, upcall, cookie, &lockh, einfo->ei_mode,
			      flags, rc);
	ptlrpc_req_put(req);
	RETURN(rc);
}

/**
 * Implementation of cl_lock_operations::clo_enqueue() method for osc
 * layer. This initiates ldlm enqueue:
 *
 *     - cancels conflicting locks early (osc_lock_enqueue_wait());
 *
 *     - calls osc_enqueue_base() to do actual enqueue.
 *
 * osc_enqueue_base() is supplied with an upcall function that is executed
 * when lock is received either after a local cached ldlm lock is matched, or
 * when a reply from the server is received.
 *
 * This function does not wait for the network communication to complete.
 */
static int mdc_lock_enqueue(const struct lu_env *env,
			    const struct cl_lock_slice *slice,
			    struct cl_io *unused, struct cl_sync_io *anchor)
{
	struct osc_thread_info *info = osc_env_info(env);
	struct osc_io *oio = osc_env_io(env);
	struct osc_object *osc = cl2osc(slice->cls_obj);
	struct osc_lock *oscl = cl2osc_lock(slice);
	struct cl_lock *lock = slice->cls_lock;
	struct ldlm_res_id *resname = &info->oti_resname;
	union ldlm_policy_data *policy = &info->oti_policy;
	osc_enqueue_upcall_f upcall = mdc_lock_upcall;
	void *cookie = (void *)oscl;
	bool async = false;
	int result;

	ENTRY;

	LASSERTF(ergo(oscl->ols_glimpse, lock->cll_descr.cld_mode <= CLM_READ),
		"lock = %px, ols = %px\n", lock, oscl);

	if (oscl->ols_state == OLS_GRANTED)
		RETURN(0);

	/* Lockahead is not supported on MDT yet */
	if (oscl->ols_flags & LDLM_FL_NO_EXPANSION) {
		result = -EOPNOTSUPP;
		RETURN(result);
	}

	if (oscl->ols_flags & LDLM_FL_TEST_LOCK)
		GOTO(enqueue_base, 0);

	if (oscl->ols_glimpse) {
		LASSERT(equi(oscl->ols_speculative, anchor == NULL));
		async = true;
		GOTO(enqueue_base, 0);
	}

	result = osc_lock_enqueue_wait(env, osc, oscl);
	if (result < 0)
		GOTO(out, result);

	/* we can grant lockless lock right after all conflicting locks
	 * are canceled. */
	if (osc_lock_is_lockless(oscl)) {
		oscl->ols_state = OLS_GRANTED;
		oio->oi_lockless = 1;
		RETURN(0);
	}

enqueue_base:
	oscl->ols_state = OLS_ENQUEUED;
	if (anchor != NULL) {
		atomic_inc(&anchor->csi_sync_nr);
		oscl->ols_owner = anchor;
	}

	/**
	 * DLM lock's ast data must be osc_object;
	 * DLM's enqueue callback set to osc_lock_upcall() with cookie as
	 * osc_lock.
	 */
	fid_build_reg_res_name(lu_object_fid(osc2lu(osc)), resname);
	mdc_lock_build_policy(env, lock, policy);
	LASSERT(!oscl->ols_speculative);
	result = mdc_enqueue_send(env, osc_export(osc), resname,
				  &oscl->ols_flags, policy, &oscl->ols_lvb,
				  upcall, cookie, &oscl->ols_einfo, async);
	if (result == 0) {
		if (osc_lock_is_lockless(oscl)) {
			oio->oi_lockless = 1;
		} else if (!async) {
			LASSERT(oscl->ols_state == OLS_GRANTED);
			LASSERT(oscl->ols_hold);
			LASSERT(oscl->ols_dlmlock != NULL);
		}
	}
out:
	if (result < 0) {
		oscl->ols_state = OLS_CANCELLED;
		osc_lock_wake_waiters(env, osc, oscl);

		if (anchor != NULL)
			cl_sync_io_note(env, anchor, result);
	}
	RETURN(result);
}

static const struct cl_lock_operations mdc_lock_lockless_ops = {
	.clo_fini = osc_lock_fini,
	.clo_enqueue = mdc_lock_enqueue,
	.clo_cancel = mdc_lock_lockless_cancel,
	.clo_print = osc_lock_print
};

static const struct cl_lock_operations mdc_lock_ops = {
	.clo_fini	= osc_lock_fini,
	.clo_enqueue	= mdc_lock_enqueue,
	.clo_cancel	= osc_lock_cancel,
	.clo_print	= osc_lock_print,
};

static int mdc_lock_init(const struct lu_env *env, struct cl_object *obj,
			 struct cl_lock *lock, const struct cl_io *io)
{
	struct osc_lock *ols;
	__u32 enqflags = lock->cll_descr.cld_enq_flags;
	__u64 flags = osc_enq2ldlm_flags(enqflags);

	ENTRY;

	/* Ignore AGL for Data-on-MDT, stat returns size data */
	if ((enqflags & CEF_SPECULATIVE) != 0)
		RETURN(0);

	OBD_SLAB_ALLOC_PTR_GFP(ols, osc_lock_kmem, GFP_NOFS);
	if (unlikely(ols == NULL))
		RETURN(-ENOMEM);

	ols->ols_state = OLS_NEW;
	spin_lock_init(&ols->ols_lock);
	INIT_LIST_HEAD(&ols->ols_waiting_list);
	INIT_LIST_HEAD(&ols->ols_wait_entry);
	INIT_LIST_HEAD(&ols->ols_nextlock_oscobj);
	ols->ols_lockless_ops = &mdc_lock_lockless_ops;

	ols->ols_flags = flags;
	ols->ols_speculative = !!(enqflags & CEF_SPECULATIVE);

	if (ols->ols_flags & LDLM_FL_HAS_INTENT) {
		ols->ols_flags |= LDLM_FL_BLOCK_GRANTED;
		ols->ols_glimpse = 1;
	}
	mdc_lock_build_einfo(env, lock, cl2osc(obj), &ols->ols_einfo);

	cl_lock_slice_add(lock, &ols->ols_cl, obj, &mdc_lock_ops);

	if (!(enqflags & CEF_MUST))
		osc_lock_to_lockless(env, ols, (enqflags & CEF_NEVER));

	if (io->ci_type == CIT_WRITE || cl_io_is_mkwrite(io))
		osc_lock_set_writer(env, io, obj, ols);
	else if (io->ci_type == CIT_READ ||
		 (io->ci_type == CIT_FAULT && !io->u.ci_fault.ft_mkwrite))
		osc_lock_set_reader(env, io, obj, ols);

	LDLM_DEBUG_NOLOCK("lock %p, mdc lock %p, flags %llx",
			  lock, ols, ols->ols_flags);
	RETURN(0);
}

/**
 * IO operations.
 *
 * An implementation of cl_io_operations specific methods for MDC layer.
 *
 */
static int mdc_async_upcall(void *a, int rc)
{
	struct osc_async_cbargs *args = a;

	args->opc_rc = rc;
	complete(&args->opc_sync);
	return 0;
}

static int mdc_get_lock_handle(const struct lu_env *env, struct osc_object *osc,
			       pgoff_t index, struct lustre_handle *lh)
{
	struct ldlm_lock *lock;

	/* find DOM lock protecting object */
	lock = mdc_dlmlock_at_pgoff(env, osc, index,
				    OSC_DAP_FL_TEST_LOCK |
				    OSC_DAP_FL_CANCELING);
	if (lock == NULL) {
		struct ldlm_resource *res;
		struct ldlm_res_id *resname;

		resname = &osc_env_info(env)->oti_resname;
		fid_build_reg_res_name(lu_object_fid(osc2lu(osc)), resname);
		res = ldlm_resource_get(osc_export(osc)->
							exp_obd->obd_namespace,
					resname, LDLM_IBITS, 0);
		if (IS_ERR(res))
			CERROR("No lock resource for "DFID"\n",
				PFID(lu_object_fid(osc2lu(osc))));
		else
			ldlm_resource_dump(D_ERROR, res);
		dump_stack();
		return -ENOENT;
	} else {
		*lh = lock->l_remote_handle;
		ldlm_lock_put(lock);
	}
	return 0;
}

static int mdc_io_setattr_start(const struct lu_env *env,
				const struct cl_io_slice *slice)
{
	struct cl_io *io = slice->cis_io;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct cl_object *obj = slice->cis_obj;
	struct lov_oinfo *loi = cl2osc(obj)->oo_oinfo;
	struct cl_attr *attr = &osc_env_info(env)->oti_attr;
	struct obdo *oa = &oio->oi_oa;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	__u64 size = io->u.ci_setattr.sa_attr.lvb_size;
	unsigned int ia_avalid = io->u.ci_setattr.sa_avalid;
	enum op_xvalid ia_xvalid = io->u.ci_setattr.sa_xvalid;
	int rc = 0;

	/* silently ignore non-truncate setattr for Data-on-MDT object */
	if (cl_io_is_trunc(io)) {
		/* truncate cache dirty pages first */
		rc = osc_cache_truncate_start(env, cl2osc(obj), size,
					      &oio->oi_trunc);
	} else if (cl_io_is_fallocate(io) &&
		   (io->u.ci_setattr.sa_falloc_mode &
		    (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE))) {
		rc = osc_punch_start(env, io, obj);
	}
	if (rc < 0)
		return rc;

	if (oio->oi_lockless == 0) {
		cl_object_attr_lock(obj);
		rc = cl_object_attr_get(env, obj, attr);
		if (rc == 0) {
			struct ost_lvb *lvb = &io->u.ci_setattr.sa_attr;
			enum cl_attr_valid cl_valid = 0;

			if (ia_avalid & ATTR_SIZE) {
				attr->cat_size = size;
				attr->cat_kms = size;
				cl_valid = (CAT_SIZE | CAT_KMS);
			}
			if (ia_avalid & ATTR_MTIME_SET) {
				attr->cat_mtime = lvb->lvb_mtime;
				cl_valid |= CAT_MTIME;
			}
			if (ia_avalid & ATTR_ATIME_SET) {
				attr->cat_atime = lvb->lvb_atime;
				cl_valid |= CAT_ATIME;
			}
			if (ia_xvalid & OP_XVALID_CTIME_SET) {
				attr->cat_ctime = lvb->lvb_ctime;
				cl_valid |= CAT_CTIME;
			}
			rc = cl_object_attr_update(env, obj, attr, cl_valid);
		}
		cl_object_attr_unlock(obj);
		if (rc < 0)
			return rc;
	}

	if (!(ia_avalid & ATTR_SIZE) && !cl_io_is_fallocate(io))
		return 0;

	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_mtime = attr->cat_mtime;
	oa->o_atime = attr->cat_atime;
	oa->o_ctime = attr->cat_ctime;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLATIME |
		      OBD_MD_FLCTIME | OBD_MD_FLMTIME | OBD_MD_FLSIZE |
		      OBD_MD_FLBLOCKS;

	if (oio->oi_lockless) {
		oa->o_flags = OBD_FL_SRVLOCK;
		oa->o_valid |= OBD_MD_FLFLAGS;
	} else {
		rc = mdc_get_lock_handle(env, cl2osc(obj), CL_PAGE_EOF,
					 &oa->o_handle);
		if (!rc)
			oa->o_valid |= OBD_MD_FLHANDLE;
	}

	init_completion(&cbargs->opc_sync);
	if (cl_io_is_fallocate(io)) {
		int falloc_mode = io->u.ci_setattr.sa_falloc_mode;

		oa->o_size = io->u.ci_setattr.sa_falloc_offset;
		oa->o_blocks = io->u.ci_setattr.sa_falloc_end;
		rc = osc_fallocate_base(osc_export(cl2osc(obj)), oa,
					mdc_async_upcall, cbargs, falloc_mode);
	} else {
		oa->o_size = size;
		oa->o_blocks = OBD_OBJECT_EOF;
		rc = osc_punch_send(osc_export(cl2osc(obj)), oa,
				    mdc_async_upcall, cbargs);
	}
	cbargs->opc_rpc_sent = rc == 0;
	return rc;
}

static int mdc_io_read_ahead(const struct lu_env *env,
			     const struct cl_io_slice *ios,
			     pgoff_t start, struct cl_read_ahead *ra)
{
	struct osc_object *osc = cl2osc(ios->cis_obj);
	struct osc_io *oio = cl2osc_io(env, ios);
	struct ldlm_lock *dlmlock;

	ENTRY;

	dlmlock = mdc_dlmlock_at_pgoff(env, osc, start, 0);
	if (dlmlock == NULL)
		RETURN(-ENODATA);

	oio->oi_is_readahead = 1;
	if (dlmlock->l_req_mode != LCK_PR) {
		struct lustre_handle lockh;

		ldlm_lock2handle(dlmlock, &lockh);
		ldlm_lock_addref(&lockh, LCK_PR);
		ldlm_lock_decref(&lockh, dlmlock->l_req_mode);
	}

	ra->cra_rpc_pages = osc_cli(osc)->cl_max_pages_per_rpc;
	ra->cra_end_idx = CL_PAGE_EOF;
	ra->cra_release = osc_read_ahead_release;
	ra->cra_dlmlock = dlmlock;
	ra->cra_oio = oio;

	RETURN(0);
}

static int mdc_io_fsync_start(const struct lu_env *env,
			      const struct cl_io_slice *slice)
{
	struct cl_io *io = slice->cis_io;
	struct cl_fsync_io *fio = &io->u.ci_fsync;
	struct cl_object *obj = slice->cis_obj;
	struct osc_object *osc = cl2osc(obj);
	int result = 0;

	ENTRY;

	if (fio->fi_mode == CL_FSYNC_RECLAIM) {
		struct client_obd *cli = osc_cli(osc);

		if (!atomic_read(&osc->oo_nr_ios) &&
		    !atomic_read(&osc->oo_nr_writes) &&
		    !atomic_long_read(&cli->cl_unstable_count)) {
			/*
			 * No active IO, no dirty pages needing to write and no
			 * unstable pages needing to commit.
			 */
			CDEBUG(D_CACHE,
			       "%s: dirty/unstable counts are both zero\n",
			       cli_name(cli));
			RETURN(0);
		}
	}

	/* a MDC lock always covers whole object, do sync for whole
	 * possible range despite of supplied start/end values.
	 */
	result = osc_cache_writeback_range(env, osc, 0, CL_PAGE_EOF, 0,
					   fio->fi_mode == CL_FSYNC_DISCARD,
					   fio->fi_prio);
	if (result > 0) {
		fio->fi_nr_written += result;
		result = 0;
	}
	if (fio->fi_mode == CL_FSYNC_ALL || fio->fi_mode == CL_FSYNC_RECLAIM) {
		struct osc_io *oio = cl2osc_io(env, slice);
		struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
		int rc;

		if (fio->fi_mode == CL_FSYNC_ALL) {
			rc = osc_cache_wait_range(env, osc, 0, CL_PAGE_EOF);
			if (result == 0)
				result = rc;
		}
		/* Use OSC sync code because it is asynchronous.
		 * It is to be added into MDC and avoid the using of
		 * OST_SYNC at both MDC and MDT.
		 */
		rc = osc_fsync_ost(env, osc, fio);
		if (result == 0) {
			cbargs->opc_rpc_sent = 1;
			result = rc;
		}
	}

	RETURN(result);
}

struct mdc_data_version_args {
	struct osc_io *dva_oio;
};

static int
mdc_data_version_interpret(const struct lu_env *env, struct ptlrpc_request *req,
			   void *args, int rc)
{
	struct mdc_data_version_args *dva = args;
	struct osc_io *oio = dva->dva_oio;
	const struct mdt_body *body;

	ENTRY;
	if (rc < 0)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	/* Prepare OBDO from mdt_body for CLIO */
	oio->oi_oa.o_valid = body->mbo_valid;
	oio->oi_oa.o_flags = body->mbo_flags;
	oio->oi_oa.o_data_version = body->mbo_version;
	oio->oi_oa.o_layout_version = body->mbo_layout_gen;
	EXIT;
out:
	oio->oi_cbarg.opc_rc = rc;
	complete(&oio->oi_cbarg.opc_sync);
	return 0;
}

static int mdc_io_data_version_start(const struct lu_env *env,
				     const struct cl_io_slice *slice)
{
	struct cl_data_version_io *dv = &slice->cis_io->u.ci_data_version;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	struct osc_object *obj = cl2osc(slice->cis_obj);
	struct obd_export *exp = osc_export(obj);
	struct ptlrpc_request *req;
	struct mdt_body *body;
	struct mdc_data_version_args *dva;
	int rc;

	ENTRY;

	memset(&oio->oi_oa, 0, sizeof(oio->oi_oa));
	oio->oi_oa.o_oi.oi_fid = *lu_object_fid(osc2lu(obj));
	oio->oi_oa.o_valid = OBD_MD_FLID;

	init_completion(&cbargs->opc_sync);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_MDS_GETATTR);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, MDS_GETATTR);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	body = req_capsule_client_get(&req->rq_pill, &RMF_MDT_BODY);
	body->mbo_fid1 = *lu_object_fid(osc2lu(obj));
	body->mbo_valid = OBD_MD_FLID;
	/* Indicate that data version is needed */
	body->mbo_valid |= OBD_MD_FLDATAVERSION;
	body->mbo_flags = 0;

	if (dv->dv_flags & (LL_DV_RD_FLUSH | LL_DV_WR_FLUSH)) {
		body->mbo_valid |= OBD_MD_FLFLAGS;
		body->mbo_flags |= OBD_FL_SRVLOCK;
		if (dv->dv_flags & LL_DV_WR_FLUSH)
			body->mbo_flags |= OBD_FL_FLUSH;
	}

	req_capsule_set_size(&req->rq_pill, &RMF_ACL, RCL_SERVER, 0);
	req_capsule_set_size(&req->rq_pill, &RMF_MDT_MD, RCL_SERVER, 0);
	req_capsule_set_size(&req->rq_pill, &RMF_FILE_ENCCTX, RCL_SERVER, 0);
	ptlrpc_request_set_replen(req);

	req->rq_interpret_reply = mdc_data_version_interpret;
	dva = ptlrpc_req_async_args(dva, req);
	dva->dva_oio = oio;

	ptlrpcd_add_req(req);

	RETURN(0);
}

static void mdc_io_data_version_end(const struct lu_env *env,
				    const struct cl_io_slice *slice)
{
	struct cl_data_version_io *dv = &slice->cis_io->u.ci_data_version;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;

	ENTRY;
	wait_for_completion(&cbargs->opc_sync);

	if (cbargs->opc_rc != 0) {
		slice->cis_io->ci_result = cbargs->opc_rc;
	} else {
		slice->cis_io->ci_result = 0;
		if (!(oio->oi_oa.o_valid &
		      (OBD_MD_LAYOUT_VERSION | OBD_MD_FLDATAVERSION)))
			slice->cis_io->ci_result = -EOPNOTSUPP;

		if (oio->oi_oa.o_valid & OBD_MD_LAYOUT_VERSION)
			dv->dv_layout_version = oio->oi_oa.o_layout_version;
		if (oio->oi_oa.o_valid & OBD_MD_FLDATAVERSION)
			dv->dv_data_version = oio->oi_oa.o_data_version;
	}

	EXIT;
}

static const struct cl_io_operations mdc_io_ops = {
	.op = {
		[CIT_READ] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_rw_iter_fini,
			.cio_start     = osc_io_read_start,
		},
		[CIT_WRITE] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_rw_iter_fini,
			.cio_start     = osc_io_write_start,
			.cio_end       = osc_io_end,
		},
		[CIT_SETATTR] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start     = mdc_io_setattr_start,
			.cio_end       = osc_io_setattr_end,
		},
		[CIT_DATA_VERSION] = {
			.cio_start = mdc_io_data_version_start,
			.cio_end   = mdc_io_data_version_end,
		},
		[CIT_FAULT] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start     = osc_io_fault_start,
			.cio_end       = osc_io_end,
		},
		[CIT_FSYNC] = {
			.cio_start = mdc_io_fsync_start,
			.cio_end   = osc_io_fsync_end,
		},
		[CIT_LSEEK] = {
			.cio_start  = osc_io_lseek_start,
			.cio_end    = osc_io_lseek_end,
		},
	},
	.cio_read_ahead   = mdc_io_read_ahead,
	.cio_lru_reserve  = osc_io_lru_reserve,
	.cio_submit	  = osc_io_submit,
	.cio_dio_submit	  = osc_dio_submit,
	.cio_commit_async = osc_io_commit_async,
	.cio_extent_release = osc_io_extent_release,
};

static int mdc_io_init(const struct lu_env *env, struct cl_object *obj,
		       struct cl_io *io)
{
	struct osc_io *oio = osc_env_io(env);

	CL_IO_SLICE_CLEAN(oio, oi_cl);
	cl_io_slice_add(io, &oio->oi_cl, obj, &mdc_io_ops);
	return 0;
}

static void mdc_build_res_name(struct osc_object *osc,
			       struct ldlm_res_id *resname)
{
	fid_build_reg_res_name(lu_object_fid(osc2lu(osc)), resname);
}

/**
 * Implementation of struct cl_req_operations::cro_attr_set() for MDC
 * layer. MDC is responsible for struct obdo::o_id and struct obdo::o_seq
 * fields.
 */
static void mdc_req_attr_set(const struct lu_env *env, struct cl_object *obj,
			     struct cl_req_attr *attr)
{
	u64 flags = attr->cra_flags;

	/* Copy object FID to cl_attr */
	attr->cra_oa->o_oi.oi_fid = *lu_object_fid(&obj->co_lu);

	if (flags & OBD_MD_FLGROUP)
		attr->cra_oa->o_valid |= OBD_MD_FLGROUP;

	if (flags & OBD_MD_FLID)
		attr->cra_oa->o_valid |= OBD_MD_FLID;

	if (flags & OBD_MD_FLHANDLE) {
		struct osc_page *opg;

		opg = osc_cl_page_osc(attr->cra_page, cl2osc(obj));
		if (!opg->ops_srvlock) {
			int rc;

			rc = mdc_get_lock_handle(env, cl2osc(obj),
						 osc_index(opg),
						 &attr->cra_oa->o_handle);
			if (rc) {
				CL_PAGE_DEBUG(D_ERROR, env, attr->cra_page,
					      "uncovered page!\n");
				LBUG();
			} else {
				attr->cra_oa->o_valid |= OBD_MD_FLHANDLE;
			}
		}
	}
}

static int mdc_attr_get(const struct lu_env *env, struct cl_object *obj,
			struct cl_attr *attr)
{
	struct lov_oinfo *oinfo = cl2osc(obj)->oo_oinfo;

	if (OST_LVB_IS_ERR(oinfo->loi_lvb.lvb_blocks))
		return OST_LVB_GET_ERR(oinfo->loi_lvb.lvb_blocks);

	return osc_attr_get(env, obj, attr);
}

static int mdc_object_ast_clear(struct ldlm_lock *lock, void *data)
{
	struct osc_object *osc = (struct osc_object *)data;
	struct ost_lvb *lvb = &lock->l_ost_lvb;
	struct lov_oinfo *oinfo;
	ENTRY;

	if (lock->l_ast_data != data)
		RETURN(LDLM_ITER_CONTINUE);

	lock->l_ast_data = NULL;

	LASSERT(osc != NULL);
	LASSERT(osc->oo_oinfo != NULL);

	/* Updates lvb in lock by the cached oinfo */
	oinfo = osc->oo_oinfo;

	LDLM_DEBUG(lock,
		   "update lock size %llu blocks %llu [cma]time: %llu %llu %llu by oinfo size %llu blocks %llu [cma]time %llu %llu %llu",
		   lvb->lvb_size, lvb->lvb_blocks, lvb->lvb_ctime,
		   lvb->lvb_mtime, lvb->lvb_atime, oinfo->loi_lvb.lvb_size,
		   oinfo->loi_lvb.lvb_blocks, oinfo->loi_lvb.lvb_ctime,
		   oinfo->loi_lvb.lvb_mtime, oinfo->loi_lvb.lvb_atime);
	LASSERT(oinfo->loi_lvb.lvb_size >= oinfo->loi_kms);

	cl_object_attr_lock(&osc->oo_cl);
	/* l_ost_lvb is only in the LDLM_IBITS union **/
	LASSERT(lock->l_resource->lr_type == LDLM_IBITS);
	memcpy(lvb, &oinfo->loi_lvb, sizeof(oinfo->loi_lvb));
	cl_object_attr_unlock(&osc->oo_cl);
	(lock->l_flags &= ~LDLM_FL_LVB_CACHED);

	RETURN(LDLM_ITER_CONTINUE);
}

static int mdc_object_prune(const struct lu_env *env, struct cl_object *obj)
{
	struct osc_object *osc = cl2osc(obj);
	struct ldlm_res_id *resname = &osc_env_info(env)->oti_resname;

	/* DLM locks don't hold a reference of osc_object so we have to
	 * clear it before the object is being destroyed. */
	osc_build_res_name(osc, resname);
	ldlm_resource_iterate(osc_export(osc)->exp_obd->obd_namespace, resname,
			      mdc_object_ast_clear, osc);
	return 0;
}

static int mdc_object_flush(const struct lu_env *env, struct cl_object *obj,
			    struct ldlm_lock *lock)
{
	/* if lock cancel is initiated from llite then it is combined
	 * lock with DOM bit and it may have no l_ast_data initialized yet,
	 * so init it here with given osc_object.
	 */
	mdc_set_dom_lock_data(lock, cl2osc(obj));
	RETURN(mdc_dlm_canceling(env, lock));
}

static int mdc_object_fiemap(const struct lu_env *env, struct cl_object *obj,
			     struct ll_fiemap_info_key *fmkey,
			     struct fiemap *fiemap, size_t *buflen)
{
	struct osc_thread_info *info = osc_env_info(env);
	struct osc_object *osc = cl2osc(obj);
	struct obd_export *exp = osc_export(osc);
	struct lustre_handle lockh;
	enum ldlm_mode mode = LCK_MINMODE;
	struct ptlrpc_request *req;
	struct fiemap *repbuf;
	struct ll_fiemap_info_key *rq_fmkey;
	char *fmbuf;
	__u64 flags;
	int rc;

	ENTRY;

	fmkey->lfik_oa.o_oi = osc->oo_oinfo->loi_oi;

	if (fmkey->lfik_fiemap.fm_flags & FIEMAP_FLAG_SYNC) {
		struct ldlm_res_id *resid = &osc_env_info(env)->oti_resname;
		union ldlm_policy_data *policy = &info->oti_policy;

		mdc_build_res_name(osc, resid);
		mdc_lock_build_policy(env, NULL, policy);
		flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_LVB_READY;
		mode = mdc_dom_lock_match(env, exp, resid, LDLM_IBITS, policy,
					  LCK_PR | LCK_PW | LCK_GROUP,
					  &flags, osc, 0, &lockh);
		fmkey->lfik_oa.o_valid |= OBD_MD_FLFLAGS;
		if (mode) { /* lock is cached on client */
			fmkey->lfik_oa.o_flags &= ~OBD_FL_SRVLOCK;
			if (mode != LCK_PR) {
				ldlm_lock_addref(&lockh, LCK_PR);
				ldlm_lock_decref(&lockh, mode);
			}
		} else {
			/* no cached lock, needs acquire lock on server side */
			fmkey->lfik_oa.o_flags |= OBD_FL_SRVLOCK;
		}
	}

	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_OST_GET_INFO_FIEMAP);
	if (!req)
		GOTO(drop_lock, rc = -ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_FIEMAP_KEY, RCL_CLIENT,
			     sizeof(*fmkey));
	req_capsule_set_size(&req->rq_pill, &RMF_FIEMAP_VAL, RCL_CLIENT,
			     *buflen);
	req_capsule_set_size(&req->rq_pill, &RMF_FIEMAP_VAL, RCL_SERVER,
			     *buflen);

	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, MDS_GET_INFO);
	if (rc != 0) {
		ptlrpc_request_free(req);
		GOTO(drop_lock, rc);
	}
	rq_fmkey = req_capsule_client_get(&req->rq_pill, &RMF_FIEMAP_KEY);
	*rq_fmkey = *fmkey;
	fmbuf = req_capsule_client_get(&req->rq_pill, &RMF_FIEMAP_VAL);
	memcpy(fmbuf, fiemap, *buflen);
	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(fini_req, rc);

	repbuf = req_capsule_server_get(&req->rq_pill, &RMF_FIEMAP_VAL);
	if (!repbuf)
		GOTO(fini_req, rc = -EPROTO);
	memcpy(fiemap, repbuf, *buflen);

fini_req:
	ptlrpc_req_put(req);
drop_lock:
	if (mode)
		ldlm_lock_decref(&lockh, LCK_PR);
	RETURN(rc);
}

static const struct cl_object_operations mdc_ops = {
	.coo_page_init = osc_page_init,
	.coo_lock_init = mdc_lock_init,
	.coo_io_init = mdc_io_init,
	.coo_attr_get = mdc_attr_get,
	.coo_attr_update = osc_attr_update,
	.coo_glimpse = osc_object_glimpse,
	.coo_req_attr_set = mdc_req_attr_set,
	.coo_prune = mdc_object_prune,
	.coo_object_flush = mdc_object_flush,
	.coo_fiemap = mdc_object_fiemap,
};

static const struct osc_object_operations mdc_object_ops = {
	.oto_build_res_name = mdc_build_res_name,
	.oto_dlmlock_at_pgoff = mdc_dlmlock_at_pgoff,
};

static int mdc_object_init(const struct lu_env *env, struct lu_object *obj,
			   const struct lu_object_conf *conf)
{
	struct osc_object *osc = lu2osc(obj);

	if (osc->oo_initialized)
		return 0;

	osc->oo_initialized = true;

	return osc_object_init(env, obj, conf);
}

static void mdc_object_free(const struct lu_env *env, struct lu_object *obj)
{
	osc_object_free(env, obj);
}

static const struct lu_object_operations mdc_lu_obj_ops = {
	.loo_object_init = mdc_object_init,
	.loo_object_delete = NULL,
	.loo_object_release = NULL,
	.loo_object_free = mdc_object_free,
	.loo_object_print = osc_object_print,
	.loo_object_invariant = NULL
};

static struct lu_object *mdc_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *unused,
					  struct lu_device *dev)
{
	struct osc_object *osc;
	struct lu_object  *obj;

	OBD_SLAB_ALLOC_PTR_GFP(osc, osc_object_kmem, GFP_NOFS);
	if (osc != NULL) {
		obj = osc2lu(osc);
		lu_object_init(obj, NULL, dev);
		osc->oo_cl.co_ops = &mdc_ops;
		obj->lo_ops = &mdc_lu_obj_ops;
		osc->oo_obj_ops = &mdc_object_ops;
		osc->oo_initialized = false;
	} else {
		obj = NULL;
	}
	return obj;
}

static int mdc_process_config(const struct lu_env *env, struct lu_device *d,
			      struct lustre_cfg *cfg)
{
	size_t count  = class_modify_config(cfg, PARAM_MDC,
					    &d->ld_obd->obd_kset.kobj);
	return count > 0 ? 0 : count;
}

static const struct lu_device_operations mdc_lu_ops = {
	.ldo_object_alloc = mdc_object_alloc,
	.ldo_process_config = mdc_process_config,
	.ldo_recovery_complete = NULL,
};

static struct lu_device *mdc_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct obd_device *obd = lu->ld_obd;
	struct client_obd *cli = &obd->u.cli;
	struct osc_device *osc = lu2osc_dev(lu);

	LASSERT(cli->cl_mod_rpcs_in_flight == 0);
	cl_device_fini(lu2cl_dev(lu));
	osc_cleanup_common(obd);
	OBD_FREE_PTR(osc);

	return NULL;
}

static struct lu_device *mdc_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct lu_device *d;
	struct osc_device *osc;
	struct obd_device *obd;
	int rc;

	OBD_ALLOC_PTR(osc);
	if (osc == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	cl_device_init(&osc->osc_cl, t);
	d = osc2lu_dev(osc);
	d->ld_ops = &mdc_lu_ops;

	/* Setup MDC OBD */
	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (obd == NULL)
		RETURN(ERR_PTR(-ENODEV));

	rc = mdc_setup(obd, cfg);
	if (rc < 0) {
		mdc_device_free(env, d);
		RETURN(ERR_PTR(rc));
	}
	osc->osc_exp = obd->obd_self_export;
	osc->osc_stats.os_init = ktime_get_real();
	RETURN(d);
}

static int mdc_device_init(const struct lu_env *env, struct lu_device *d,
			   const char *name, struct lu_device *next)
{
	RETURN(0);
}

static struct lu_device *mdc_device_fini(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct obd_device *obd = lu->ld_obd;

	ENTRY;

	osc_precleanup_common(obd);
	mdc_changelog_cdev_finish(obd);
	mdc_llog_finish(obd);
	lprocfs_free_md_stats(obd);
	ptlrpc_lprocfs_unregister_obd(obd);

	RETURN(NULL);
}

static const struct lu_device_type_operations mdc_device_type_ops = {
	.ldto_device_alloc = mdc_device_alloc,
	.ldto_device_free = mdc_device_free,
	.ldto_device_init = mdc_device_init,
	.ldto_device_fini = mdc_device_fini
};

struct lu_device_type mdc_device_type = {
	.ldt_tags = LU_DEVICE_CL,
	.ldt_name = LUSTRE_MDC_NAME,
	.ldt_ops = &mdc_device_type_ops,
	.ldt_ctx_tags = LCT_CL_THREAD
};

/** @} osc */
