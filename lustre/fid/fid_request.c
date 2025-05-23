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
 * Lustre Sequence Manager
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FID

#include <linux/err.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>
/* mdc RPC locks */
#include <lustre_mdc.h>
#include "fid_internal.h"

struct dentry *seq_debugfs_dir;

static int seq_client_rpc(struct lu_client_seq *seq,
			  struct lu_seq_range *output, __u32 opc,
			  const char *opcname)
{
	struct obd_export     *exp = seq->lcs_exp;
	struct ptlrpc_request *req;
	struct lu_seq_range   *out, *in;
	__u32                 *op;
	unsigned int           debug_mask;
	int                    rc;
	ENTRY;

	LASSERT(exp != NULL && !IS_ERR(exp));
	req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp), &RQF_SEQ_QUERY,
					LUSTRE_MDS_VERSION, SEQ_QUERY);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	/* Init operation code */
	op = req_capsule_client_get(&req->rq_pill, &RMF_SEQ_OPC);
	*op = opc;

	/* Zero out input range, this is not recovery yet. */
	in = req_capsule_client_get(&req->rq_pill, &RMF_SEQ_RANGE);
	lu_seq_range_init(in);

	ptlrpc_request_set_replen(req);

	in->lsr_index = seq->lcs_space.lsr_index;
	if (seq->lcs_type == LUSTRE_SEQ_METADATA)
		fld_range_set_mdt(in);
	else
		fld_range_set_ost(in);

	if (opc == SEQ_ALLOC_SUPER) {
		req->rq_request_portal = SEQ_CONTROLLER_PORTAL;
		req->rq_reply_portal = MDC_REPLY_PORTAL;
		/*
		 * During allocating super sequence for data object,
		 * the current thread might hold the export of MDT0(MDT0
		 * precreating objects on this OST), and it will send the
		 * request to MDT0 here, so we can not keep resending the
		 * request here, otherwise if MDT0 is failed(umounted),
		 * it can not release the export of MDT0
		 */
		if (seq->lcs_type == LUSTRE_SEQ_DATA) {
			req->rq_no_resend = 1;
			req->rq_no_delay = 1;
		}
		debug_mask = D_CONSOLE;
	} else {
		if (seq->lcs_type == LUSTRE_SEQ_METADATA) {
			req->rq_reply_portal = MDC_REPLY_PORTAL;
			req->rq_request_portal = SEQ_METADATA_PORTAL;
		} else {
			req->rq_reply_portal = OSC_REPLY_PORTAL;
			req->rq_request_portal = SEQ_DATA_PORTAL;
		}

		debug_mask = D_INFO;
	}

	/* Allow seq client RPC during recovery time. */
	req->rq_allow_replay = 1;

	ptlrpc_at_set_req_timeout(req);

	rc = ptlrpc_queue_wait(req);

	if (rc)
		GOTO(out_req, rc);

	out = req_capsule_server_get(&req->rq_pill, &RMF_SEQ_RANGE);
	*output = *out;

	if (!lu_seq_range_is_sane(output)) {
		CERROR("%s: Invalid range received from server: "
		       DRANGE"\n", seq->lcs_name, PRANGE(output));
		GOTO(out_req, rc = -EINVAL);
	}

	if (lu_seq_range_is_exhausted(output)) {
		CERROR("%s: Range received from server is exhausted: "
		       DRANGE"]\n", seq->lcs_name, PRANGE(output));
		GOTO(out_req, rc = -EINVAL);
	}

	CDEBUG_LIMIT(debug_mask, "%s: Allocated %s-sequence "DRANGE"]\n",
		     seq->lcs_name, opcname, PRANGE(output));

	EXIT;
out_req:
	ptlrpc_req_put(req);
	return rc;
}

/* Request sequence-controller node to allocate new super-sequence. */
int seq_client_alloc_super(struct lu_client_seq *seq,
			   const struct lu_env *env)
{
	int rc;
	ENTRY;

	mutex_lock(&seq->lcs_mutex);

	if (seq->lcs_srv) {
#ifdef HAVE_SEQ_SERVER
		LASSERT(env != NULL);
		rc = seq_server_alloc_super(seq->lcs_srv, &seq->lcs_space, env);
#else
		rc = 0;
#endif
	} else {
		/*
		 * Check whether the connection to seq controller has been
		 * setup (lcs_exp != NULL)
		 */
		if (!seq->lcs_exp) {
			mutex_unlock(&seq->lcs_mutex);
			RETURN(-EINPROGRESS);
		}

		rc = seq_client_rpc(seq, &seq->lcs_space,
				    SEQ_ALLOC_SUPER, "super");
	}
	mutex_unlock(&seq->lcs_mutex);
	RETURN(rc);
}

/* Request sequence-controller node to allocate new meta-sequence. */
static int seq_client_alloc_meta(const struct lu_env *env,
				 struct lu_client_seq *seq)
{
	int rc;
	ENTRY;

	if (seq->lcs_srv) {
#ifdef HAVE_SEQ_SERVER
		LASSERT(env);
		rc = seq_server_alloc_meta(seq->lcs_srv, &seq->lcs_space, env);
#else
		rc = 0;
#endif
	} else {
		do {
			/*
			 * If meta server return -EINPROGRESS or EAGAIN,
			 * it means meta server might not be ready to
			 * allocate super sequence from sequence controller
			 * (MDT0)yet
			 */
			rc = seq_client_rpc(seq, &seq->lcs_space,
					    SEQ_ALLOC_META, "meta");
			if (rc == -EINPROGRESS || rc == -EAGAIN)
				/*
				 * MDT0 is not ready, let's wait for 2
				 * seconds and retry.
				 */
				ssleep(2);

		} while (rc == -EINPROGRESS || rc == -EAGAIN);
	}

	RETURN(rc);
}

/* Allocate new sequence for client. */
static int seq_client_alloc_seq(const struct lu_env *env,
				struct lu_client_seq *seq, u64 *seqnr)
{
	int rc;
	ENTRY;

	LASSERT(lu_seq_range_is_sane(&seq->lcs_space));

	if (lu_seq_range_is_exhausted(&seq->lcs_space)) {
		rc = seq_client_alloc_meta(env, seq);
		if (rc) {
			if (rc != -EINPROGRESS)
				CERROR("%s: Cannot allocate new meta-sequence: rc = %d\n",
				       seq->lcs_name, rc);
			RETURN(rc);
		} else {
			CDEBUG(D_INFO, "%s: New range - "DRANGE"\n",
			       seq->lcs_name, PRANGE(&seq->lcs_space));
		}
	} else {
		rc = 0;
	}

	LASSERT(!lu_seq_range_is_exhausted(&seq->lcs_space));
	*seqnr = seq->lcs_space.lsr_start;
	seq->lcs_space.lsr_start += 1;

	CDEBUG(D_INFO, "%s: Allocated sequence [%#llx]\n", seq->lcs_name,
	       *seqnr);

	RETURN(rc);
}

/**
 * seq_client_get_seq() - Allocate the whole non-used seq to the caller
 * @env: pointer to the thread context
 * @seq: pointer to the client sequence manager
 * @seqnr: to hold the new allocated sequence
 *
 * Return:
 * * %0: Success (for new sequence allocated)
 * * %-ERRNO: On Failure
 */
int seq_client_get_seq(const struct lu_env *env,
		       struct lu_client_seq *seq, u64 *seqnr)
{
	int rc;

	LASSERT(seqnr != NULL);

	mutex_lock(&seq->lcs_mutex);

	rc = seq_client_alloc_seq(env, seq, seqnr);
	if (rc) {
		CERROR("%s: Can't allocate new sequence: rc = %d\n",
		       seq->lcs_name, rc);
	} else {
		CDEBUG(D_INFO, "%s: New sequence [0x%16.16llx]\n",
		       seq->lcs_name, *seqnr);
		seq->lcs_fid.f_seq = *seqnr;
		seq->lcs_fid.f_ver = 0;
		/*
		 *  The caller require the whole seq,
		 * so marked this seq to be used
		 */
		if (seq->lcs_type == LUSTRE_SEQ_METADATA)
			seq->lcs_fid.f_oid =
				LUSTRE_METADATA_SEQ_MAX_WIDTH;
		else
			seq->lcs_fid.f_oid = LUSTRE_DATA_SEQ_MAX_WIDTH;
	}
	mutex_unlock(&seq->lcs_mutex);

	return rc;
}
EXPORT_SYMBOL(seq_client_get_seq);

/**
 * seq_client_alloc_fid() - Allocate new FID on passed client @seq and save
 * it to @fid.
 * @env: pointer to the thread context
 * @seq: pointer to the client sequence manager
 * @fid: to hold the new allocated FID
 *
 * Return:
 * * %1: notify the caller that sequence switch is performed to allow it to
 * setup FLD for it.
 * * %0: new FID allocated in current sequence.
 * * %negative: On failure
 */
int seq_client_alloc_fid(const struct lu_env *env,
			 struct lu_client_seq *seq, struct lu_fid *fid)
{
	int rc;
	ENTRY;

	LASSERT(seq != NULL);
	LASSERT(fid != NULL);

	mutex_lock(&seq->lcs_mutex);

	if (CFS_FAIL_CHECK(OBD_FAIL_SEQ_EXHAUST))
		seq->lcs_fid.f_oid = seq->lcs_width;

	if (unlikely(!fid_is_zero(&seq->lcs_fid) &&
		     fid_oid(&seq->lcs_fid) < seq->lcs_width)) {
		/* Just bump last allocated fid and return to caller. */
		seq->lcs_fid.f_oid++;
		rc = 0;
	} else {
		u64 seqnr;

		rc = seq_client_alloc_seq(env, seq, &seqnr);
		if (rc) {
			if (rc != -EINPROGRESS)
				CERROR("%s: Can't allocate new sequence: rc = %d\n",
				       seq->lcs_name, rc);
		} else {
			CDEBUG(D_INFO, "%s: New sequence [0x%16.16llx]\n",
			       seq->lcs_name, seqnr);

			seq->lcs_fid.f_seq = seqnr;
			seq->lcs_fid.f_oid = LUSTRE_FID_INIT_OID;
			seq->lcs_fid.f_ver = 0;
			rc = 1;
		}
	}

	if (rc >= 0) {
		*fid = seq->lcs_fid;
		CDEBUG(D_INFO, "%s: Allocated FID "DFID"\n", seq->lcs_name,
		       PFID(fid));
	}
	mutex_unlock(&seq->lcs_mutex);

	RETURN(rc);
}
EXPORT_SYMBOL(seq_client_alloc_fid);

/*
 * Finish the current sequence due to disconnect.
 * See mdc_import_event()
 */
void seq_client_flush(struct lu_client_seq *seq)
{
	LASSERT(seq != NULL);
	mutex_lock(&seq->lcs_mutex);

	fid_zero(&seq->lcs_fid);
	/**
	 * this id shld not be used for seq range allocation.
	 * set to -1 for dgb check.
	 */
	seq->lcs_space.lsr_index = -1;

	lu_seq_range_init(&seq->lcs_space);
	mutex_unlock(&seq->lcs_mutex);
}
EXPORT_SYMBOL(seq_client_flush);

static void seq_client_debugfs_fini(struct lu_client_seq *seq)
{
	debugfs_remove_recursive(seq->lcs_debugfs_entry);
}

static void seq_client_debugfs_init(struct lu_client_seq *seq)
{
	seq->lcs_debugfs_entry = debugfs_create_dir(seq->lcs_name,
						    seq_debugfs_dir);

	ldebugfs_add_vars(seq->lcs_debugfs_entry,
			  seq_client_debugfs_list, seq);
}

void seq_client_fini(struct lu_client_seq *seq)
{
	ENTRY;

	seq_client_debugfs_fini(seq);

	if (seq->lcs_exp) {
		class_export_put(seq->lcs_exp);
		seq->lcs_exp = NULL;
	}

	seq->lcs_srv = NULL;
	EXIT;
}
EXPORT_SYMBOL(seq_client_fini);

void seq_client_init(struct lu_client_seq *seq,
		     struct obd_export *exp,
		     enum lu_cli_type type,
		     const char *prefix,
		     struct lu_server_seq *srv)
{
	ENTRY;

	LASSERT(seq != NULL);
	LASSERT(prefix != NULL);

	seq->lcs_srv = srv;
	seq->lcs_type = type;

	mutex_init(&seq->lcs_mutex);
	if (type == LUSTRE_SEQ_METADATA)
		seq->lcs_width = LUSTRE_METADATA_SEQ_MAX_WIDTH;
	else
		seq->lcs_width = LUSTRE_DATA_SEQ_MAX_WIDTH;

	/* Make sure that things are clear before work is started. */
	seq_client_flush(seq);

	if (exp)
		seq->lcs_exp = class_export_get(exp);

	snprintf(seq->lcs_name, sizeof(seq->lcs_name),
		 "cli-%s", prefix);

	seq_client_debugfs_init(seq);
}
EXPORT_SYMBOL(seq_client_init);

int client_fid_init(struct obd_device *obd,
		    struct obd_export *exp, enum lu_cli_type type)
{
	struct client_obd *cli = &obd->u.cli;
	char *prefix;
	int rc = 0;
	ENTRY;

	down_write(&cli->cl_seq_rwsem);
	OBD_ALLOC_PTR(cli->cl_seq);
	if (!cli->cl_seq)
		GOTO(out, rc = -ENOMEM);

	OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
	if (!prefix)
		GOTO(out, rc = -ENOMEM);

	snprintf(prefix, MAX_OBD_NAME + 5, "cli-%s", obd->obd_name);

	/* Init client side sequence-manager */
	seq_client_init(cli->cl_seq, exp, type, prefix, NULL);
	OBD_FREE(prefix, MAX_OBD_NAME + 5);

out:
	if (rc && cli->cl_seq) {
		OBD_FREE_PTR(cli->cl_seq);
		cli->cl_seq = NULL;
	}
	up_write(&cli->cl_seq_rwsem);

	RETURN(rc);
}
EXPORT_SYMBOL(client_fid_init);

int client_fid_fini(struct obd_device *obd)
{
	struct client_obd *cli = &obd->u.cli;
	ENTRY;

	down_write(&cli->cl_seq_rwsem);
	if (cli->cl_seq) {
		seq_client_fini(cli->cl_seq);
		OBD_FREE_PTR(cli->cl_seq);
		cli->cl_seq = NULL;
	}
	up_write(&cli->cl_seq_rwsem);

	RETURN(0);
}
EXPORT_SYMBOL(client_fid_fini);

static int __init fid_init(void)
{
	struct dentry *de;
	int rc;

	rc = libcfs_setup();
	if (rc)
		return rc;
#ifdef HAVE_SERVER_SUPPORT
	rc = fid_server_mod_init();

	if (rc)
		return rc;
#endif
	de = debugfs_create_dir(LUSTRE_SEQ_NAME,
				debugfs_lustre_root);
	if (!IS_ERR(de))
		seq_debugfs_dir = de;
	return PTR_ERR_OR_ZERO(de);
}

static void __exit fid_exit(void)
{
# ifdef HAVE_SERVER_SUPPORT
	fid_server_mod_exit();
# endif
	debugfs_remove_recursive(seq_debugfs_dir);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre File IDentifier");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(fid_init);
module_exit(fid_exit);
