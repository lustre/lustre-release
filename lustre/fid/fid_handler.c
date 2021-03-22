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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/fid/fid_handler.c
 *
 * Lustre Sequence Manager
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FID

#include <libcfs/libcfs.h>
#include <linux/module.h>
#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <obd_support.h>
#include <lustre_req_layout.h>
#include <lustre_fid.h>
#include "fid_internal.h"

/* Assigns client to sequence controller node. */
int seq_server_set_cli(const struct lu_env *env, struct lu_server_seq *seq,
		       struct lu_client_seq *cli)
{
	int rc = 0;
	ENTRY;

	/*
	 * Ask client for new range, assign that range to ->seq_space and write
	 * seq state to backing store should be atomic.
	 */
	mutex_lock(&seq->lss_mutex);

	if (!cli) {
		CDEBUG(D_INFO, "%s: Detached sequence client\n", seq->lss_name);
		seq->lss_cli = NULL;
		GOTO(out_up, rc = 0);
	}

	if (seq->lss_cli) {
		CDEBUG(D_HA, "%s: Sequence controller is already assigned\n",
		       seq->lss_name);
		GOTO(out_up, rc = -EEXIST);
	}

	CDEBUG(D_INFO, "%s: Attached sequence controller %s\n",
	       seq->lss_name, cli->lcs_name);

	seq->lss_cli = cli;
	cli->lcs_space.lsr_index = seq->lss_site->ss_node_id;
	EXIT;
out_up:
	mutex_unlock(&seq->lss_mutex);
	return rc;
}
EXPORT_SYMBOL(seq_server_set_cli);
/*
 * allocate \a w units of sequence from range \a from.
 */
static inline void range_alloc(struct lu_seq_range *to,
			       struct lu_seq_range *from,
			       __u64 width)
{
	width = min(lu_seq_range_space(from), width);
	to->lsr_start = from->lsr_start;
	to->lsr_end = from->lsr_start + width;
	from->lsr_start += width;
}

/**
 * On controller node, allocate new super sequence for regular sequence server.
 * As this super sequence controller, this node suppose to maintain fld
 * and update index.
 * \a out range always has currect mds node number of requester.
 */

static int __seq_server_alloc_super(struct lu_server_seq *seq,
				    struct lu_seq_range *out,
				    const struct lu_env *env)
{
	struct lu_seq_range *space = &seq->lss_space;
	int rc;
	ENTRY;

	LASSERT(lu_seq_range_is_sane(space));

	if (lu_seq_range_is_exhausted(space)) {
		CERROR("%s: Sequences space is exhausted\n",
		       seq->lss_name);
		RETURN(-ENOSPC);
	} else {
		range_alloc(out, space, seq->lss_width);
	}

	rc = seq_store_update(env, seq, out, 1 /* sync */);

	LCONSOLE_INFO("%s: super-sequence allocation rc = %d " DRANGE"\n",
		      seq->lss_name, rc, PRANGE(out));

	RETURN(rc);
}

int seq_server_alloc_super(struct lu_server_seq *seq,
			   struct lu_seq_range *out,
			   const struct lu_env *env)
{
	int rc;
	ENTRY;

	mutex_lock(&seq->lss_mutex);
	rc = __seq_server_alloc_super(seq, out, env);
	mutex_unlock(&seq->lss_mutex);

	RETURN(rc);
}

int seq_server_alloc_spec(struct lu_server_seq *seq,
			  struct lu_seq_range *spec,
			  const struct lu_env *env)
{
	struct lu_seq_range *space = &seq->lss_space;
	int rc = -ENOSPC;
	ENTRY;

	/*
	 * In some cases (like recovery after a disaster)
	 * we may need to allocate sequences manually
	 * Notice some sequences can be lost if requested
	 * range doesn't start at the beginning of current
	 * free space. Also notice it's not possible now
	 * to allocate sequences out of natural order.
	 */
	if (spec->lsr_start >= spec->lsr_end)
		RETURN(-EINVAL);
	if (spec->lsr_flags != LU_SEQ_RANGE_MDT &&
	    spec->lsr_flags != LU_SEQ_RANGE_OST)
		RETURN(-EINVAL);

	mutex_lock(&seq->lss_mutex);
	if (spec->lsr_start >= space->lsr_start) {
		space->lsr_start = spec->lsr_end;
		rc = seq_store_update(env, seq, spec, 1 /* sync */);

		LCONSOLE_INFO("%s: "DRANGE" sequences allocated: rc = %d \n",
			      seq->lss_name, PRANGE(spec), rc);
	}
	mutex_unlock(&seq->lss_mutex);

	RETURN(rc);
}

static int __seq_set_init(const struct lu_env *env,
			  struct lu_server_seq *seq)
{
	struct lu_seq_range *space = &seq->lss_space;
	int rc;

	range_alloc(&seq->lss_lowater_set, space, seq->lss_set_width);
	range_alloc(&seq->lss_hiwater_set, space, seq->lss_set_width);

	rc = seq_store_update(env, seq, NULL, 1);

	return rc;
}

/*
 * This function implements new seq allocation algorithm using async
 * updates to seq file on disk. ref bug 18857 for details.
 * there are four variable to keep track of this process
 *
 * lss_space; - available lss_space
 * lss_lowater_set; - lu_seq_range for all seqs before barrier, i.e. safe to use
 * lss_hiwater_set; - lu_seq_range after barrier, i.e. allocated but may be
 *                    not yet committed
 *
 * when lss_lowater_set reaches the end it is replaced with hiwater one and
 * a write operation is initiated to allocate new hiwater range.
 * if last seq write opearion is still not committed, current operation is
 * flaged as sync write op.
 */
static int range_alloc_set(const struct lu_env *env,
			   struct lu_seq_range *out,
			   struct lu_server_seq *seq)
{
	struct lu_seq_range *space = &seq->lss_space;
	struct lu_seq_range *loset = &seq->lss_lowater_set;
	struct lu_seq_range *hiset = &seq->lss_hiwater_set;
	int rc = 0;

	if (lu_seq_range_is_zero(loset))
		__seq_set_init(env, seq);

	if (OBD_FAIL_CHECK(OBD_FAIL_SEQ_ALLOC)) /* exhaust set */
		loset->lsr_start = loset->lsr_end;

	if (lu_seq_range_is_exhausted(loset)) {
		/* reached high water mark. */
		struct lu_device *dev = seq->lss_site->ss_lu->ls_top_dev;
		int obd_num_clients = dev->ld_obd->obd_num_exports;
		__u64 set_sz;

		/* calculate new seq width based on number of clients */
		set_sz = max(seq->lss_set_width,
			     obd_num_clients * seq->lss_width);
		set_sz = min(lu_seq_range_space(space), set_sz);

		/* Switch to hiwater range now */
		*loset = *hiset;
		/* allocate new hiwater range */
		range_alloc(hiset, space, set_sz);

		/* update ondisk seq with new *space */
		rc = seq_store_update(env, seq, NULL, seq->lss_need_sync);
	}

	LASSERTF(!lu_seq_range_is_exhausted(loset) ||
		 lu_seq_range_is_sane(loset),
		 DRANGE"\n", PRANGE(loset));

	if (rc == 0)
		range_alloc(out, loset, seq->lss_width);

	RETURN(rc);
}

/**
 * Check if the sequence server has sequence avaible
 *
 * Check if the sequence server has sequence avaible, if not, then
 * allocating super sequence from sequence manager (MDT0).
 *
 * \param[in] env	execution environment
 * \param[in] seq	server sequence
 *
 * \retval		negative errno if allocating new sequence fails
 * \retval		0 if there is enough sequence or allocating
 *                      new sequence succeeds
 */
int seq_server_check_and_alloc_super(const struct lu_env *env,
				     struct lu_server_seq *seq)
{
	struct lu_seq_range *space = &seq->lss_space;
	int rc = 0;

	ENTRY;

	/* Check if available space ends and allocate new super seq */
	if (lu_seq_range_is_exhausted(space)) {
		if (!seq->lss_cli) {
			CERROR("%s: No sequence controller is attached.\n",
			       seq->lss_name);
			RETURN(-ENODEV);
		}

		rc = seq_client_alloc_super(seq->lss_cli, env);
		if (rc) {
			CDEBUG(D_HA,
			       "%s: Can't allocate super-sequence: rc = %d\n",
			       seq->lss_name, rc);
			RETURN(rc);
		}

		/* Saving new range to allocation space. */
		*space = seq->lss_cli->lcs_space;
		LASSERT(lu_seq_range_is_sane(space));
		if (!seq->lss_cli->lcs_srv) {
			struct lu_server_fld *fld;

			/* Insert it to the local FLDB */
			fld = seq->lss_site->ss_server_fld;
			mutex_lock(&fld->lsf_lock);
			rc = fld_insert_entry(env, fld, space);
			mutex_unlock(&fld->lsf_lock);
		}
	}

	if (lu_seq_range_is_zero(&seq->lss_lowater_set))
		__seq_set_init(env, seq);

	RETURN(rc);
}
EXPORT_SYMBOL(seq_server_check_and_alloc_super);

static int __seq_server_alloc_meta(struct lu_server_seq *seq,
				   struct lu_seq_range *out,
				   const struct lu_env *env)
{
	struct lu_seq_range *space = &seq->lss_space;
	int rc = 0;

	ENTRY;

	LASSERT(lu_seq_range_is_sane(space));

	rc = seq_server_check_and_alloc_super(env, seq);
	if (rc < 0) {
		if (rc == -EINPROGRESS) {
			static int printed;

			if (printed++ % 8 == 0)
				LCONSOLE_INFO("%s: Waiting to contact MDT0000 to allocate super-sequence: rc = %d\n",
					      seq->lss_name, rc);
		} else {
			CERROR("%s: Allocated super-sequence failed: rc = %d\n",
			       seq->lss_name, rc);
		}
		RETURN(rc);
	}

	rc = range_alloc_set(env, out, seq);
	if (rc != 0) {
		CERROR("%s: Allocated meta-sequence failed: rc = %d\n",
		       seq->lss_name, rc);
		RETURN(rc);
	}

	CDEBUG(D_INFO, "%s: Allocated meta-sequence " DRANGE"\n",
	       seq->lss_name, PRANGE(out));

	RETURN(rc);
}

int seq_server_alloc_meta(struct lu_server_seq *seq,
			  struct lu_seq_range *out,
			  const struct lu_env *env)
{
	int rc;
	ENTRY;

	mutex_lock(&seq->lss_mutex);
	rc = __seq_server_alloc_meta(seq, out, env);
	mutex_unlock(&seq->lss_mutex);

	RETURN(rc);
}
EXPORT_SYMBOL(seq_server_alloc_meta);

static int seq_server_handle(struct lu_site *site,
			     const struct lu_env *env,
			     __u32 opc, struct lu_seq_range *out)
{
	int rc;
	struct seq_server_site *ss_site;
	struct dt_device *dev;
	ENTRY;

	ss_site = lu_site2seq(site);

	switch (opc) {
	case SEQ_ALLOC_META:
		if (!ss_site->ss_server_seq) {
			rc = -EINVAL;
			CERROR("Sequence server is not initialized: rc = %d\n",
			       rc);
			RETURN(rc);
		}

		dev = lu2dt_dev(ss_site->ss_server_seq->lss_obj->do_lu.lo_dev);
		if (dev->dd_rdonly)
			RETURN(-EROFS);

		rc = seq_server_alloc_meta(ss_site->ss_server_seq, out, env);
		break;
	case SEQ_ALLOC_SUPER:
		if (!ss_site->ss_control_seq) {
			rc = -EINVAL;
			CERROR("Sequence controller is not initialized: rc = %d\n",
			       rc);
			RETURN(rc);
		}

		dev = lu2dt_dev(ss_site->ss_control_seq->lss_obj->do_lu.lo_dev);
		if (dev->dd_rdonly)
			RETURN(-EROFS);

		rc = seq_server_alloc_super(ss_site->ss_control_seq, out, env);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	RETURN(rc);
}

static int seq_handler(struct tgt_session_info *tsi)
{
	struct lu_seq_range	*out, *tmp;
	struct lu_site		*site;
	int			 rc;
	__u32			*opc;

	ENTRY;

	LASSERT(!(lustre_msg_get_flags(tgt_ses_req(tsi)->rq_reqmsg) & MSG_REPLAY));
	site = tsi->tsi_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(site != NULL);

	opc = req_capsule_client_get(tsi->tsi_pill, &RMF_SEQ_OPC);
	if (opc) {
		out = req_capsule_server_get(tsi->tsi_pill, &RMF_SEQ_RANGE);
		if (!out)
			RETURN(err_serious(-EPROTO));

		tmp = req_capsule_client_get(tsi->tsi_pill, &RMF_SEQ_RANGE);

		/*
		 * seq client passed mdt id, we need to pass that using out
		 * range parameter
		 */
		out->lsr_index = tmp->lsr_index;
		out->lsr_flags = tmp->lsr_flags;
		rc = seq_server_handle(site, tsi->tsi_env, *opc, out);
	} else {
		rc = err_serious(-EPROTO);
	}

	RETURN(rc);
}

struct tgt_handler seq_handlers[] = {
TGT_SEQ_HDL(HAS_REPLY,	SEQ_QUERY,	seq_handler),
};
EXPORT_SYMBOL(seq_handlers);

/* context key constructor/destructor: seq_key_init, seq_key_fini */
LU_KEY_INIT_FINI(seq, struct seq_thread_info);

/* context key: seq_thread_key */
LU_CONTEXT_KEY_DEFINE(seq, LCT_MD_THREAD | LCT_DT_THREAD);

static void seq_server_debugfs_fini(struct lu_server_seq *seq)
{
	debugfs_remove_recursive(seq->lss_debugfs_entry);
}

static void seq_server_debugfs_init(struct lu_server_seq *seq)
{
	ENTRY;

	seq->lss_debugfs_entry = debugfs_create_dir(seq->lss_name,
						    seq_debugfs_dir);

	ldebugfs_add_vars(seq->lss_debugfs_entry,
			  seq_server_debugfs_list, seq);

	if (seq->lss_type == LUSTRE_SEQ_CONTROLLER)
		debugfs_create_file("fldb", 0644, seq->lss_debugfs_entry,
				    seq, &seq_fld_debugfs_seq_fops);
}

int seq_server_init(const struct lu_env *env,
		    struct lu_server_seq *seq,
		    struct dt_device *dev,
		    const char *prefix,
		    enum lu_mgr_type type,
		    struct seq_server_site *ss)
{
	int rc, is_srv = (type == LUSTRE_SEQ_SERVER);
	ENTRY;

	LASSERT(dev != NULL);
	LASSERT(prefix != NULL);
	LASSERT(ss != NULL);
	LASSERT(ss->ss_lu != NULL);

	/*
	 * Check all lu_fid fields are converted in fid_cpu_to_le() and friends
	 * and that there is no padding added by compiler to the struct.
	 */
	{
		struct lu_fid tst;

		BUILD_BUG_ON(sizeof(tst) != sizeof(tst.f_seq) +
			     sizeof(tst.f_oid) + sizeof(tst.f_ver));
	}

	seq->lss_cli = NULL;
	seq->lss_type = type;
	seq->lss_site = ss;
	lu_seq_range_init(&seq->lss_space);

	lu_seq_range_init(&seq->lss_lowater_set);
	lu_seq_range_init(&seq->lss_hiwater_set);
	seq->lss_set_width = LUSTRE_SEQ_BATCH_WIDTH;

	mutex_init(&seq->lss_mutex);

	seq->lss_width = is_srv ?
		LUSTRE_SEQ_META_WIDTH : LUSTRE_SEQ_SUPER_WIDTH;

	snprintf(seq->lss_name, sizeof(seq->lss_name),
		 "%s-%s", (is_srv ? "srv" : "ctl"), prefix);

	rc = seq_store_init(seq, env, dev);
	if (rc)
		GOTO(out, rc);
	/* Request backing store for saved sequence info. */
	rc = seq_store_read(seq, env);
	if (rc == -ENODATA) {

		/* Nothing is read, init by default value. */
		seq->lss_space = is_srv ?
			LUSTRE_SEQ_ZERO_RANGE :
			LUSTRE_SEQ_SPACE_RANGE;

		seq->lss_space.lsr_index = ss->ss_node_id;
		LCONSOLE_INFO("%s: No data found on store. Initialize space: rc = %d\n",
			      seq->lss_name, rc);

		rc = seq_store_update(env, seq, NULL, 0);
		if (rc) {
			CERROR("%s: Can't write space data: rc = %d\n",
			       seq->lss_name, rc);
		}
	} else if (rc) {
		CERROR("%s: Can't read space data: rc = %d\n",
		       seq->lss_name, rc);
		GOTO(out, rc);
	}

	if (is_srv) {
		LASSERT(lu_seq_range_is_sane(&seq->lss_space));
	} else {
		LASSERT(!lu_seq_range_is_zero(&seq->lss_space) &&
			lu_seq_range_is_sane(&seq->lss_space));
	}

	seq_server_debugfs_init(seq);

	EXIT;
out:
	if (rc)
		seq_server_fini(seq, env);
	return rc;
}
EXPORT_SYMBOL(seq_server_init);

void seq_server_fini(struct lu_server_seq *seq,
		     const struct lu_env *env)
{
	ENTRY;

	seq_server_debugfs_fini(seq);
	seq_store_fini(seq, env);

	EXIT;
}
EXPORT_SYMBOL(seq_server_fini);

int seq_site_fini(const struct lu_env *env, struct seq_server_site *ss)
{
	if (!ss)
		RETURN(0);

	if (ss->ss_server_seq) {
		seq_server_fini(ss->ss_server_seq, env);
		OBD_FREE_PTR(ss->ss_server_seq);
		ss->ss_server_seq = NULL;
	}

	if (ss->ss_control_seq) {
		seq_server_fini(ss->ss_control_seq, env);
		OBD_FREE_PTR(ss->ss_control_seq);
		ss->ss_control_seq = NULL;
	}

	if (ss->ss_client_seq) {
		seq_client_fini(ss->ss_client_seq);
		OBD_FREE_PTR(ss->ss_client_seq);
		ss->ss_client_seq = NULL;
	}

	RETURN(0);
}
EXPORT_SYMBOL(seq_site_fini);

int fid_server_mod_init(void)
{
	LU_CONTEXT_KEY_INIT(&seq_thread_key);
	return lu_context_key_register(&seq_thread_key);
}

void fid_server_mod_exit(void)
{
	lu_context_key_degister(&seq_thread_key);
}
