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
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/fld/fld_handler.c
 *
 * FLD (Fids Location Database)
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 * Author: WangDi <wangdi@clusterfs.com>
 * Author: Pravin Shelar <pravin.shelar@sun.com>
 */

#define DEBUG_SUBSYSTEM S_FLD

#include <libcfs/libcfs.h>
#include <linux/module.h>

#include <obd.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_req_layout.h>
#include <lprocfs_status.h>
#include "fld_internal.h"

/* context key constructor/destructor: fld_key_init, fld_key_fini */
LU_KEY_INIT_FINI(fld, struct fld_thread_info);

/* context key: fld_thread_key */
/* MGS thread may create llog file causing FLD lookup */
LU_CONTEXT_KEY_DEFINE(fld, LCT_MD_THREAD | LCT_DT_THREAD | LCT_MG_THREAD);

int fld_server_mod_init(void)
{
	LU_CONTEXT_KEY_INIT(&fld_thread_key);
	return lu_context_key_register(&fld_thread_key);
}

void fld_server_mod_exit(void)
{
	lu_context_key_degister(&fld_thread_key);
}

int fld_declare_server_create(const struct lu_env *env,
			      struct lu_server_fld *fld,
			      const struct lu_seq_range *range,
			      struct thandle *th)
{
	int rc;

	rc = fld_declare_index_create(env, fld, range, th);
	RETURN(rc);
}
EXPORT_SYMBOL(fld_declare_server_create);

/**
 * Insert FLD index entry and update FLD cache.
 *
 * This function is called from the sequence allocator when a super-sequence
 * is granted to a server.
 */
int fld_server_create(const struct lu_env *env, struct lu_server_fld *fld,
		      const struct lu_seq_range *range, struct thandle *th)
{
	int rc;

	mutex_lock(&fld->lsf_lock);
	rc = fld_index_create(env, fld, range, th);
	mutex_unlock(&fld->lsf_lock);

	RETURN(rc);
}
EXPORT_SYMBOL(fld_server_create);

/**
 * Extract index information from fld name like srv-fsname-MDT0000
 **/
int fld_name_to_index(const char *name, __u32 *index)
{
	char *dash;
	int rc;
	ENTRY;

	CDEBUG(D_INFO, "get index from %s\n", name);
	dash = strrchr(name, '-');
	if (dash == NULL)
		RETURN(-EINVAL);
	dash++;
	rc = target_name2index(dash, index, NULL);
	RETURN(rc);
}

/**
 * Retrieve fldb entry from MDT0 and add to local FLDB and cache.
 **/
int fld_update_from_controller(const struct lu_env *env,
			       struct lu_server_fld *fld)
{
	struct fld_thread_info	  *info;
	struct lu_seq_range	  *range;
	struct lu_seq_range_array *lsra;
	__u32			  index;
	struct ptlrpc_request	  *req;
	int			  rc;
	int			  i;
	ENTRY;

	/* Update only happens during initalization, i.e. local FLDB
	 * does not exist yet */
	if (!fld->lsf_new)
		RETURN(0);

	rc = fld_name_to_index(fld->lsf_name, &index);
	if (rc < 0)
		RETURN(rc);

	/* No need update fldb for MDT0 */
	if (index == 0)
		RETURN(0);

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
	LASSERT(info != NULL);
	range = &info->fti_lrange;
	memset(range, 0, sizeof(*range));
	range->lsr_index = index;
	fld_range_set_mdt(range);

	do {
		rc = fld_client_rpc(fld->lsf_control_exp, range, FLD_READ,
				    &req);
		if (rc != 0 && rc != -EAGAIN)
			GOTO(out, rc);

		LASSERT(req != NULL);
		lsra = (struct lu_seq_range_array *)req_capsule_server_get(
					  &req->rq_pill, &RMF_GENERIC_DATA);
		if (lsra == NULL)
			GOTO(out, rc = -EPROTO);

		range_array_le_to_cpu(lsra, lsra);
		for (i = 0; i < lsra->lsra_count; i++) {
			int rc1;

			if (lsra->lsra_lsr[i].lsr_flags != LU_SEQ_RANGE_MDT)
				GOTO(out, rc = -EINVAL);

			if (lsra->lsra_lsr[i].lsr_index != index)
				GOTO(out, rc = -EINVAL);

			mutex_lock(&fld->lsf_lock);
			rc1 = fld_insert_entry(env, fld, &lsra->lsra_lsr[i]);
			mutex_unlock(&fld->lsf_lock);

			if (rc1 != 0)
				GOTO(out, rc = rc1);
		}
		if (rc == -EAGAIN)
			*range = lsra->lsra_lsr[lsra->lsra_count - 1];
	} while (rc == -EAGAIN);

	fld->lsf_new = 1;
out:
	if (req != NULL)
		ptlrpc_req_finished(req);

	RETURN(rc);
}
EXPORT_SYMBOL(fld_update_from_controller);

/**
 * Lookup sequece in local cache/fldb.
 **/
int fld_local_lookup(const struct lu_env *env, struct lu_server_fld *fld,
		     u64 seq, struct lu_seq_range *range)
{
	struct lu_seq_range *erange;
	struct fld_thread_info *info;
	int rc;
	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
	LASSERT(info != NULL);
	erange = &info->fti_lrange;

	/* Lookup it in the cache. */
	rc = fld_cache_lookup(fld->lsf_cache, seq, erange);
	if (rc == 0) {
		if (unlikely(fld_range_type(erange) != fld_range_type(range) &&
			     !fld_range_is_any(range))) {
			CERROR("%s: FLD cache range "DRANGE" does not match"
			       "requested flag %x: rc = %d\n", fld->lsf_name,
			       PRANGE(erange), range->lsr_flags, -EIO);
			RETURN(-EIO);
		}
		*range = *erange;
		RETURN(0);
	}
	RETURN(rc);
}
EXPORT_SYMBOL(fld_local_lookup);

/**
 *  Lookup MDT/OST by seq, returns a range for given seq.
 *
 *  If that entry is not cached in fld cache, request is sent to super
 *  sequence controller node (MDT0). All other MDT[1...N] and client
 *  cache fld entries, but this cache is not persistent.
 */
int fld_server_lookup(const struct lu_env *env, struct lu_server_fld *fld,
		      u64 seq, struct lu_seq_range *range)
{
	__u32 index;
	int rc;
	ENTRY;

	rc = fld_local_lookup(env, fld, seq, range);
	if (likely(rc == 0))
		RETURN(rc);

	rc = fld_name_to_index(fld->lsf_name, &index);
	if (rc < 0)
		RETURN(rc);

	if (index == 0 && rc == LDD_F_SV_TYPE_MDT) {
		/* On server side, all entries should be in cache.
		 * If we can not find it in cache, just return error */
		CERROR("%s: Cannot find sequence %#llx: rc = %d\n",
		       fld->lsf_name, seq, -ENOENT);
		RETURN(-ENOENT);
	} else {
		if (fld->lsf_control_exp == NULL) {
			CERROR("%s: lookup %#llx, but not connects to MDT0"
			       "yet: rc = %d.\n", fld->lsf_name, seq, -EIO);
			RETURN(-EIO);
		}
		/* send request to mdt0 i.e. super seq. controller.
		 * This is temporary solution, long term solution is fld
		 * replication on all mdt servers.
		 */
		range->lsr_start = seq;
		rc = fld_client_rpc(fld->lsf_control_exp,
				    range, FLD_QUERY, NULL);
		if (rc == 0)
			fld_cache_insert(fld->lsf_cache, range);
	}
	RETURN(rc);
}
EXPORT_SYMBOL(fld_server_lookup);

/**
 * All MDT server handle fld lookup operation. But only MDT0 has fld index.
 * if entry is not found in cache we need to forward lookup request to MDT0
 */
static int fld_handle_lookup(struct tgt_session_info *tsi)
{
	struct obd_export	*exp = tsi->tsi_exp;
	struct lu_site		*site = exp->exp_obd->obd_lu_dev->ld_site;
	struct lu_server_fld	*fld;
	struct lu_seq_range	*in;
	struct lu_seq_range	*out;
	int			rc;

	ENTRY;

	in = req_capsule_client_get(tsi->tsi_pill, &RMF_FLD_MDFLD);
	if (in == NULL)
		RETURN(err_serious(-EPROTO));

	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (unlikely(rc != 0))
		RETURN(err_serious(rc));

	out = req_capsule_server_get(tsi->tsi_pill, &RMF_FLD_MDFLD);
	if (out == NULL)
		RETURN(err_serious(-EPROTO));
	*out = *in;

	fld = lu_site2seq(site)->ss_server_fld;

	rc = fld_server_lookup(tsi->tsi_env, fld, in->lsr_start, out);

	CDEBUG(D_INFO, "%s: FLD req handle: error %d (range: "DRANGE")\n",
	       fld->lsf_name, rc, PRANGE(out));

	RETURN(rc);
}

static int fld_handle_read(struct tgt_session_info *tsi)
{
	struct obd_export	*exp = tsi->tsi_exp;
	struct lu_site		*site = exp->exp_obd->obd_lu_dev->ld_site;
	struct lu_seq_range	*in;
	void			*data;
	int			rc;

	ENTRY;

	req_capsule_set(tsi->tsi_pill, &RQF_FLD_READ);

	in = req_capsule_client_get(tsi->tsi_pill, &RMF_FLD_MDFLD);
	if (in == NULL)
		RETURN(err_serious(-EPROTO));

	req_capsule_set_size(tsi->tsi_pill, &RMF_GENERIC_DATA, RCL_SERVER,
			     PAGE_SIZE);

	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (unlikely(rc != 0))
		RETURN(err_serious(rc));

	data = req_capsule_server_get(tsi->tsi_pill, &RMF_GENERIC_DATA);

	rc = fld_server_read(tsi->tsi_env, lu_site2seq(site)->ss_server_fld,
			     in, data, PAGE_SIZE);
	RETURN(rc);
}

static int fld_handle_query(struct tgt_session_info *tsi)
{
	int	rc;

	ENTRY;

	req_capsule_set(tsi->tsi_pill, &RQF_FLD_QUERY);

	rc = fld_handle_lookup(tsi);

	RETURN(rc);
}

/*
 * Returns true, if fid is local to this server node.
 *
 * WARNING: this function is *not* guaranteed to return false if fid is
 * remote: it makes an educated conservative guess only.
 *
 * fid_is_local() is supposed to be used in assertion checks only.
 */
int fid_is_local(const struct lu_env *env,
                 struct lu_site *site, const struct lu_fid *fid)
{
	int result;
	struct seq_server_site *ss_site;
	struct lu_seq_range *range;
	struct fld_thread_info *info;
	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
	range = &info->fti_lrange;

	result = 1; /* conservatively assume fid is local */
	ss_site = lu_site2seq(site);
	if (ss_site->ss_client_fld != NULL) {
		int rc;

		rc = fld_cache_lookup(ss_site->ss_client_fld->lcf_cache,
				      fid_seq(fid), range);
		if (rc == 0)
			result = (range->lsr_index == ss_site->ss_node_id);
	}
	return result;
}

static void fld_server_proc_fini(struct lu_server_fld *fld);

#ifdef CONFIG_PROC_FS
static int fld_server_proc_init(struct lu_server_fld *fld)
{
        int rc = 0;
        ENTRY;

	fld->lsf_proc_dir = lprocfs_register(fld->lsf_name, fld_type_proc_dir,
					     fld_server_proc_list, fld);
	if (IS_ERR(fld->lsf_proc_dir)) {
		rc = PTR_ERR(fld->lsf_proc_dir);
		RETURN(rc);
	}

	rc = lprocfs_seq_create(fld->lsf_proc_dir, "fldb", 0444,
				&fld_proc_seq_fops, fld);
	if (rc) {
		lprocfs_remove(&fld->lsf_proc_dir);
		fld->lsf_proc_dir = NULL;
	}

	RETURN(rc);
}

static void fld_server_proc_fini(struct lu_server_fld *fld)
{
        ENTRY;
        if (fld->lsf_proc_dir != NULL) {
                if (!IS_ERR(fld->lsf_proc_dir))
                        lprocfs_remove(&fld->lsf_proc_dir);
                fld->lsf_proc_dir = NULL;
        }
        EXIT;
}
#else
static int fld_server_proc_init(struct lu_server_fld *fld)
{
        return 0;
}

static void fld_server_proc_fini(struct lu_server_fld *fld)
{
        return;
}
#endif

int fld_server_init(const struct lu_env *env, struct lu_server_fld *fld,
		    struct dt_device *dt, const char *prefix, int type)
{
	int cache_size, cache_threshold;
	int rc;

	ENTRY;

	snprintf(fld->lsf_name, sizeof(fld->lsf_name), "srv-%s", prefix);

	cache_size = FLD_SERVER_CACHE_SIZE / sizeof(struct fld_cache_entry);

	cache_threshold = cache_size * FLD_SERVER_CACHE_THRESHOLD / 100;

	mutex_init(&fld->lsf_lock);
	fld->lsf_cache = fld_cache_init(fld->lsf_name, cache_size,
					cache_threshold);
	if (IS_ERR(fld->lsf_cache)) {
		rc = PTR_ERR(fld->lsf_cache);
		fld->lsf_cache = NULL;
		RETURN(rc);
	}

	rc = fld_index_init(env, fld, dt, type);
	if (rc)
		GOTO(out_cache, rc);

	rc = fld_server_proc_init(fld);
	if (rc)
		GOTO(out_index, rc);

	fld->lsf_control_exp = NULL;
	fld->lsf_seq_lookup = fld_server_lookup;

	fld->lsf_seq_lookup = fld_server_lookup;
	RETURN(0);
out_index:
	fld_index_fini(env, fld);
out_cache:
	fld_cache_fini(fld->lsf_cache);
	return rc;
}
EXPORT_SYMBOL(fld_server_init);

void fld_server_fini(const struct lu_env *env, struct lu_server_fld *fld)
{
	ENTRY;

	fld_server_proc_fini(fld);
	fld_index_fini(env, fld);

	if (fld->lsf_cache != NULL) {
		if (!IS_ERR(fld->lsf_cache))
			fld_cache_fini(fld->lsf_cache);
		fld->lsf_cache = NULL;
	}

	EXIT;
}
EXPORT_SYMBOL(fld_server_fini);

struct tgt_handler fld_handlers[] = {
TGT_FLD_HDL_VAR(0,	FLD_QUERY,	fld_handle_query),
TGT_FLD_HDL_VAR(0,	FLD_READ,	fld_handle_read),
};
EXPORT_SYMBOL(fld_handlers);
