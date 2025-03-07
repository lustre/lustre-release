// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LOG


#include <obd_class.h>
#include <lustre_log.h>
#include "llog_internal.h"

/* helper functions for calling the llog obd methods */
static struct llog_ctxt* llog_new_ctxt(struct obd_device *obd)
{
	struct llog_ctxt *ctxt;

	OBD_ALLOC_PTR(ctxt);
	if (!ctxt)
		return NULL;

	ctxt->loc_obd = obd;
	atomic_set(&ctxt->loc_refcount, 1);

	return ctxt;
}

static void llog_ctxt_destroy(struct llog_ctxt *ctxt)
{
	if (ctxt->loc_exp) {
		class_export_put(ctxt->loc_exp);
		ctxt->loc_exp = NULL;
	}
	if (ctxt->loc_imp) {
		class_import_put(ctxt->loc_imp);
		ctxt->loc_imp = NULL;
	}
	OBD_FREE_PTR(ctxt);
}

int __llog_ctxt_put(const struct lu_env *env, struct llog_ctxt *ctxt)
{
	struct obd_llog_group *olg = ctxt->loc_olg;
	struct obd_device *obd;
	int rc = 0;

	spin_lock(&olg->olg_lock);
	if (!atomic_dec_and_test(&ctxt->loc_refcount)) {
		spin_unlock(&olg->olg_lock);
		return rc;
	}
	olg->olg_ctxts[ctxt->loc_idx] = NULL;
	spin_unlock(&olg->olg_lock);

	obd = ctxt->loc_obd;
	spin_lock(&obd->obd_dev_lock);
	/* sync with llog ctxt user thread */
	spin_unlock(&obd->obd_dev_lock);

	/*
	 * obd->obd_starting is needed for the case of cleanup
	 * in error case while obd is starting up.
	 */
	LASSERTF(obd->obd_starting == 1 ||
		 obd->obd_stopping == 1 ||
		 !test_bit(OBDF_SET_UP, obd->obd_flags),
		 "wrong obd state: %d/%d/%d\n", !!obd->obd_starting,
		 !!obd->obd_stopping, test_bit(OBDF_SET_UP, obd->obd_flags));

	/* cleanup the llog ctxt here */
	if (ctxt->loc_logops->lop_cleanup)
		rc = ctxt->loc_logops->lop_cleanup(env, ctxt);

	llog_ctxt_destroy(ctxt);
	wake_up(&olg->olg_waitq);
	return rc;
}
EXPORT_SYMBOL(__llog_ctxt_put);

int llog_cleanup(const struct lu_env *env, struct llog_ctxt *ctxt)
{
	struct obd_llog_group *olg;
	int rc, idx;

	ENTRY;

	LASSERT(ctxt != NULL);
	LASSERT(ctxt != LP_POISON);

	olg = ctxt->loc_olg;
	LASSERT(olg != NULL);
	LASSERT(olg != LP_POISON);

	idx = ctxt->loc_idx;

	/*
	 * Banlance the ctxt get when calling llog_cleanup()
	 */
	LASSERT(atomic_read(&ctxt->loc_refcount) < LI_POISON);
	LASSERT(atomic_read(&ctxt->loc_refcount) > 1);
	llog_ctxt_put(ctxt);

	/*
	 * Try to free the ctxt.
	 */
	rc = __llog_ctxt_put(env, ctxt);
	if (rc)
		CERROR("Error %d while cleaning up ctxt %p\n",
			rc, ctxt);

	l_wait_event_abortable(olg->olg_waitq,
			       llog_group_ctxt_null(olg, idx));

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cleanup);

int llog_setup(const struct lu_env *env, struct obd_device *obd,
	       struct obd_llog_group *olg, int index,
	       struct obd_device *disk_obd, const struct llog_operations *op)
{
	struct llog_ctxt *ctxt;
	int rc = 0;

	ENTRY;

	if (index < 0 || index >= LLOG_MAX_CTXTS)
		RETURN(-EINVAL);

	LASSERT(olg != NULL);

	ctxt = llog_new_ctxt(obd);
	if (!ctxt)
		RETURN(-ENOMEM);

	ctxt->loc_obd = obd;
	ctxt->loc_olg = olg;
	ctxt->loc_idx = index;
	ctxt->loc_logops = op;
	mutex_init(&ctxt->loc_mutex);
	if (disk_obd != NULL)
		ctxt->loc_exp = class_export_get(disk_obd->obd_self_export);
	else
		ctxt->loc_exp = class_export_get(obd->obd_self_export);

	ctxt->loc_flags = LLOG_CTXT_FLAG_UNINITIALIZED;
	ctxt->loc_chunk_size = LLOG_MIN_CHUNK_SIZE;

	rc = llog_group_set_ctxt(olg, ctxt, index);
	if (rc) {
		llog_ctxt_destroy(ctxt);
		if (rc == -EEXIST) {
			ctxt = llog_group_get_ctxt(olg, index);
			if (ctxt) {
				CDEBUG(D_CONFIG, "%s: ctxt %d already set up\n",
				       obd->obd_name, index);
				LASSERT(ctxt->loc_olg == olg);
				LASSERT(ctxt->loc_obd == obd);
				if (disk_obd != NULL)
					LASSERT(ctxt->loc_exp ==
						disk_obd->obd_self_export);
				else
					LASSERT(ctxt->loc_exp ==
						obd->obd_self_export);
				LASSERT(ctxt->loc_logops == op);
				llog_ctxt_put(ctxt);
			}
			rc = 0;
		}
		RETURN(rc);
	}

	if (op->lop_setup) {
		if (CFS_FAIL_CHECK(OBD_FAIL_OBD_LLOG_SETUP))
			rc = -EOPNOTSUPP;
		else
			rc = op->lop_setup(env, obd, olg, index, disk_obd);
	}

	if (rc) {
		CERROR("%s: ctxt %d lop_setup=%p failed: rc = %d\n",
		       obd->obd_name, index, op->lop_setup, rc);
		llog_group_clear_ctxt(olg, index);
		llog_ctxt_destroy(ctxt);
	} else {
		CDEBUG(D_CONFIG, "obd %s ctxt %d is initialized\n",
		       obd->obd_name, index);
		ctxt->loc_flags &= ~LLOG_CTXT_FLAG_UNINITIALIZED;
	}

	RETURN(rc);
}
EXPORT_SYMBOL(llog_setup);

int llog_sync(struct llog_ctxt *ctxt, struct obd_export *exp, int flags)
{
	int rc = 0;

	ENTRY;
	if (ctxt && ctxt->loc_logops->lop_sync)
		rc = ctxt->loc_logops->lop_sync(ctxt, exp, flags);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_sync);

/* context key constructor/destructor: llog_key_init, llog_key_fini */
LU_KEY_INIT_FINI(llog, struct llog_thread_info);
/* context key: llog_thread_key */
LU_CONTEXT_KEY_DEFINE(llog, LCT_MD_THREAD | LCT_MG_THREAD | LCT_LOCAL);
LU_KEY_INIT_GENERIC(llog);

int llog_info_init(void)
{
	llog_key_init_generic(&llog_thread_key, NULL);
	lu_context_key_register(&llog_thread_key);
	return 0;
}

void llog_info_fini(void)
{
	lu_context_key_degister(&llog_thread_key);
}
