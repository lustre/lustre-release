/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2013, 2017, Intel Corporation.
 *
 * Copyright 2012 Xyratex Technology Limited
 */
/*
 * lustre/ptlrpc/nrs_orr.c
 *
 * Network Request Scheduler (NRS) ORR and TRR policies
 *
 * Request scheduling in a Round-Robin manner over backend-fs objects and OSTs
 * respectively
 *
 * Author: Liang Zhen <liang@whamcloud.com>
 * Author: Nikitas Angelinas <nikitas_angelinas@xyratex.com>
 */

/**
 * \addtogoup nrs
 * @{
 */
#define DEBUG_SUBSYSTEM S_RPC
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_req_layout.h>
#include "ptlrpc_internal.h"

/**
 * \name ORR/TRR policy
 *
 * ORR/TRR (Object-based Round Robin/Target-based Round Robin) NRS policies
 *
 * ORR performs batched Round Robin shceduling of brw RPCs, based on the FID of
 * the backend-fs object that the brw RPC pertains to; the TRR policy performs
 * batched Round Robin scheduling of brw RPCs, based on the OST index that the
 * RPC pertains to. Both policies also order RPCs in each batch in ascending
 * offset order, which is lprocfs-tunable between logical file offsets, and
 * physical disk offsets, as reported by fiemap.
 *
 * The TRR policy reuses much of the functionality of ORR. These two scheduling
 * algorithms could alternatively be implemented under a single NRS policy, that
 * uses an lprocfs tunable in order to switch between the two types of
 * scheduling behaviour. The two algorithms have been implemented as separate
 * policies for reasons of clarity to the user, and to avoid issues that would
 * otherwise arise at the point of switching between behaviours in the case of
 * having a single policy, such as resource cleanup for nrs_orr_object
 * instances. It is possible that this may need to be re-examined in the future,
 * along with potentially coalescing other policies that perform batched request
 * scheduling in a Round-Robin manner, all into one policy.
 *
 * @{
 */

#define NRS_POL_NAME_ORR	"orr"
#define NRS_POL_NAME_TRR	"trr"

/**
 * Checks if the RPC type of \a nrq is currently handled by an ORR/TRR policy
 *
 * \param[in]  orrd   the ORR/TRR policy scheduler instance
 * \param[in]  nrq    the request
 * \param[out] opcode the opcode is saved here, just in order to avoid calling
 *		      lustre_msg_get_opc() again later
 *
 * \retval true  request type is supported by the policy instance
 * \retval false request type is not supported by the policy instance
 */
static bool nrs_orr_req_supported(struct nrs_orr_data *orrd,
				  struct ptlrpc_nrs_request *nrq, __u32 *opcode)
{
	struct ptlrpc_request  *req = container_of(nrq, struct ptlrpc_request,
						   rq_nrq);
	__u32			opc = lustre_msg_get_opc(req->rq_reqmsg);
	bool			rc = false;

	/**
	 * XXX: nrs_orr_data::od_supp accessed unlocked.
	 */
	switch (opc) {
	case OST_READ:
		rc = orrd->od_supp & NOS_OST_READ;
		break;
	case OST_WRITE:
		rc = orrd->od_supp & NOS_OST_WRITE;
		break;
	}

	if (rc)
		*opcode = opc;

	return rc;
}

/**
 * Returns the ORR/TRR key fields for the request \a nrq in \a key.
 *
 * \param[in]  orrd the ORR/TRR policy scheduler instance
 * \param[in]  nrq  the request
 * \param[in]  opc  the request's opcode
 * \param[in]  name the policy name
 * \param[out] key  fields of the key are returned here.
 *
 * \retval 0   key filled successfully
 * \retval < 0 error
 */
static int nrs_orr_key_fill(struct nrs_orr_data *orrd,
			    struct ptlrpc_nrs_request *nrq, __u32 opc,
			    char *name, struct nrs_orr_key *key)
{
	struct ptlrpc_request  *req = container_of(nrq, struct ptlrpc_request,
						   rq_nrq);
	struct ost_body        *body;
	__u32			ost_idx;
	bool			is_orr = strncmp(name, NRS_POL_NAME_ORR,
						 NRS_POL_NAME_MAX) == 0;

	LASSERT(req != NULL);

	/**
	 * This is an attempt to fill in the request key fields while
	 * moving a request from the regular to the high-priority NRS
	 * head (via ldlm_lock_reorder_req()), but the request key has
	 * been adequately filled when nrs_orr_res_get() was called through
	 * ptlrpc_nrs_req_initialize() for the regular NRS head's ORR/TRR
	 * policy, so there is nothing to do.
	 */
	if ((is_orr && nrq->nr_u.orr.or_orr_set) ||
	    (!is_orr && nrq->nr_u.orr.or_trr_set)) {
		*key = nrq->nr_u.orr.or_key;
		return 0;
	}

	/* Bounce unconnected requests to the default policy. */
	if (req->rq_export == NULL)
		return -ENOTCONN;

	if (nrq->nr_u.orr.or_orr_set || nrq->nr_u.orr.or_trr_set)
		memset(&nrq->nr_u.orr.or_key, 0, sizeof(nrq->nr_u.orr.or_key));

	ost_idx = class_server_data(req->rq_export->exp_obd)->lsd_osd_index;

	if (is_orr) {
		int	rc;
		/**
		 * The request pill for OST_READ and OST_WRITE requests is
		 * initialized in the ost_io service's
		 * ptlrpc_service_ops::so_hpreq_handler, ost_io_hpreq_handler(),
		 * so no need to redo it here.
		 */
		body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
		if (body == NULL)
			RETURN(-EFAULT);

		rc = ostid_to_fid(&key->ok_fid, &body->oa.o_oi, ost_idx);
		if (rc < 0)
			return rc;

		nrq->nr_u.orr.or_orr_set = 1;
	} else {
		key->ok_idx = ost_idx;
		nrq->nr_u.orr.or_trr_set = 1;
	}

	return 0;
}

/**
 * Populates the range values in \a range with logical offsets obtained via
 * \a nb.
 *
 * \param[in]  nb	niobuf_remote struct array for this request
 * \param[in]  niocount	count of niobuf_remote structs for this request
 * \param[out] range	the offset range is returned here
 */
static void nrs_orr_range_fill_logical(struct niobuf_remote *nb, int niocount,
				       struct nrs_orr_req_range *range)
{
	/* Should we do this at page boundaries ? */
	range->or_start = nb[0].rnb_offset & PAGE_MASK;
	range->or_end = (nb[niocount - 1].rnb_offset +
			 nb[niocount - 1].rnb_len - 1) | ~PAGE_MASK;
}

/**
 * We obtain information just for a single extent, as the request can only be in
 * a single place in the binary heap anyway.
 */
#define ORR_NUM_EXTENTS 1

/**
 * Converts the logical file offset range in \a range, to a physical disk offset
 * range in \a range, for a request. Uses obd_get_info() in order to carry out a
 * fiemap call and obtain backend-fs extent information. The returned range is
 * in physical block numbers.
 *
 * \param[in]	  nrq	the request
 * \param[in]	  oa	obdo struct for this request
 * \param[in,out] range	the offset range in bytes; logical range in, physical
 *			range out
 *
 * \retval 0	physical offsets obtained successfully
 * \retvall < 0 error
 */
static int nrs_orr_range_fill_physical(struct ptlrpc_nrs_request *nrq,
				       struct obdo *oa,
				       struct nrs_orr_req_range *range)
{
	struct ptlrpc_request     *req = container_of(nrq,
						      struct ptlrpc_request,
						      rq_nrq);
	char			   fiemap_buf[offsetof(struct fiemap,
						  fm_extents[ORR_NUM_EXTENTS])];
	struct fiemap              *fiemap = (struct fiemap *)fiemap_buf;
	struct ll_fiemap_info_key  key;
	loff_t			   start;
	loff_t			   end;
	int			   rc;

	key = (typeof(key)) {
		.lfik_name = KEY_FIEMAP,
		.lfik_oa = *oa,
		.lfik_fiemap = {
			.fm_start = range->or_start,
			.fm_length = range->or_end - range->or_start,
			.fm_extent_count = ORR_NUM_EXTENTS
		}
	};

	rc = obd_get_info(req->rq_svc_thread->t_env, req->rq_export,
			  sizeof(key), &key, NULL, fiemap);
	if (rc < 0)
		GOTO(out, rc);

	if (fiemap->fm_mapped_extents == 0 ||
	    fiemap->fm_mapped_extents > ORR_NUM_EXTENTS)
		GOTO(out, rc = -EFAULT);

	/**
	 * Calculate the physical offset ranges for the request from the extent
	 * information and the logical request offsets.
	 */
	start = fiemap->fm_extents[0].fe_physical + range->or_start -
		fiemap->fm_extents[0].fe_logical;
	end = start + range->or_end - range->or_start;

	range->or_start = start;
	range->or_end = end;

	nrq->nr_u.orr.or_physical_set = 1;
out:
	return rc;
}

/**
 * Sets the offset range the request covers; either in logical file
 * offsets or in physical disk offsets.
 *
 * \param[in] nrq	 the request
 * \param[in] orrd	 the ORR/TRR policy scheduler instance
 * \param[in] opc	 the request's opcode
 * \param[in] moving_req is the request in the process of moving onto the
 *			 high-priority NRS head?
 *
 * \retval 0	range filled successfully
 * \retval != 0 error
 */
static int nrs_orr_range_fill(struct ptlrpc_nrs_request *nrq,
			      struct nrs_orr_data *orrd, __u32 opc,
			      bool moving_req)
{
	struct ptlrpc_request	    *req = container_of(nrq,
							struct ptlrpc_request,
							rq_nrq);
	struct obd_ioobj	    *ioo;
	struct niobuf_remote	    *nb;
	struct ost_body		    *body;
	struct nrs_orr_req_range     range;
	int			     niocount;
	int			     rc = 0;

	/**
	 * If we are scheduling using physical disk offsets, but we have filled
	 * the offset information in the request previously
	 * (i.e. ldlm_lock_reorder_req() is moving the request to the
	 * high-priority NRS head), there is no need to do anything, and we can
	 * exit. Moreover than the lack of need, we would be unable to perform
	 * the obd_get_info() call required in nrs_orr_range_fill_physical(),
	 * because ldlm_lock_reorder_lock() calls into here while holding a
	 * spinlock, and retrieving fiemap information via obd_get_info() is a
	 * potentially sleeping operation.
	 */
	if (orrd->od_physical && nrq->nr_u.orr.or_physical_set)
		return 0;

	ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
	if (ioo == NULL)
		GOTO(out, rc = -EFAULT);

	niocount = ioo->ioo_bufcnt;

	nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
	if (nb == NULL)
		GOTO(out, rc = -EFAULT);

	/**
	 * Use logical information from niobuf_remote structures.
	 */
	nrs_orr_range_fill_logical(nb, niocount, &range);

	/**
	 * Obtain physical offsets if selected, and this is an OST_READ RPC
	 * RPC. We do not enter this block if moving_req is set which indicates
	 * that the request is being moved to the high-priority NRS head by
	 * ldlm_lock_reorder_req(), as that function calls in here while holding
	 * a spinlock, and nrs_orr_range_physical() can sleep, so we just use
	 * logical file offsets for the range values for such requests.
	 */
	if (orrd->od_physical && opc == OST_READ && !moving_req) {
		body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
		if (body == NULL)
			GOTO(out, rc = -EFAULT);

		/**
		 * Translate to physical block offsets from backend filesystem
		 * extents.
		 * Ignore return values; if obtaining the physical offsets
		 * fails, use the logical offsets.
		 */
		nrs_orr_range_fill_physical(nrq, &body->oa, &range);
	}

	nrq->nr_u.orr.or_range = range;
out:
	return rc;
}

/**
 * Generates a character string that can be used in order to register uniquely
 * named libcfs_hash and slab objects for ORR/TRR policy instances. The
 * character string is unique per policy instance, as it includes the policy's
 * name, the CPT number, and a {reg|hp} token, and there is one policy instance
 * per NRS head on each CPT, and the policy is only compatible with the ost_io
 * service.
 *
 * \param[in] policy the policy instance
 * \param[out] name  the character array that will hold the generated name
 */
static void nrs_orr_genobjname(struct ptlrpc_nrs_policy *policy, char *name)
{
	snprintf(name, NRS_ORR_OBJ_NAME_MAX, "%s%s%s%d",
		 "nrs_", policy->pol_desc->pd_name,
		 policy->pol_nrs->nrs_queue_type == PTLRPC_NRS_QUEUE_REG ?
		 "_reg_" : "_hp_", nrs_pol2cptid(policy));
}

/**
 * ORR/TRR hash operations
 */
#define NRS_ORR_BITS		24
#define NRS_ORR_BKT_BITS	12
#define NRS_ORR_HASH_FLAGS	(CFS_HASH_SPIN_BKTLOCK | CFS_HASH_ASSERT_EMPTY)

#define NRS_TRR_BITS		4
#define NRS_TRR_BKT_BITS	2
#define NRS_TRR_HASH_FLAGS	CFS_HASH_SPIN_BKTLOCK

static unsigned
nrs_orr_hop_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
	return cfs_hash_djb2_hash(key, sizeof(struct nrs_orr_key), mask);
}

static void *nrs_orr_hop_key(struct hlist_node *hnode)
{
	struct nrs_orr_object *orro = hlist_entry(hnode,
						      struct nrs_orr_object,
						      oo_hnode);
	return &orro->oo_key;
}

static int nrs_orr_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	struct nrs_orr_object *orro = hlist_entry(hnode,
						      struct nrs_orr_object,
						      oo_hnode);

	return lu_fid_eq(&orro->oo_key.ok_fid,
			 &((struct nrs_orr_key *)key)->ok_fid);
}

static void *nrs_orr_hop_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct nrs_orr_object, oo_hnode);
}

static void nrs_orr_hop_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_orr_object *orro = hlist_entry(hnode,
						      struct nrs_orr_object,
						      oo_hnode);
	orro->oo_ref++;
}

/**
 * Removes an nrs_orr_object the hash and frees its memory, if the object has
 * no active users.
 */
static void nrs_orr_hop_put_free(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_orr_object *orro = hlist_entry(hnode,
						      struct nrs_orr_object,
						      oo_hnode);
	struct nrs_orr_data   *orrd = container_of(orro->oo_res.res_parent,
						   struct nrs_orr_data, od_res);
	struct cfs_hash_bd     bd;

	cfs_hash_bd_get_and_lock(hs, &orro->oo_key, &bd, 1);

	if (--orro->oo_ref > 1) {
		cfs_hash_bd_unlock(hs, &bd, 1);

		return;
	}
	LASSERT(orro->oo_ref == 1);

	cfs_hash_bd_del_locked(hs, &bd, hnode);
	cfs_hash_bd_unlock(hs, &bd, 1);

	OBD_SLAB_FREE_PTR(orro, orrd->od_cache);
}

static void nrs_orr_hop_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_orr_object *orro = hlist_entry(hnode,
						      struct nrs_orr_object,
						      oo_hnode);
	orro->oo_ref--;
}

static int nrs_trr_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	struct nrs_orr_object *orro = hlist_entry(hnode,
						      struct nrs_orr_object,
						      oo_hnode);

	return orro->oo_key.ok_idx == ((struct nrs_orr_key *)key)->ok_idx;
}

static void nrs_trr_hop_exit(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_orr_object *orro = hlist_entry(hnode,
						      struct nrs_orr_object,
						      oo_hnode);
	struct nrs_orr_data   *orrd = container_of(orro->oo_res.res_parent,
						   struct nrs_orr_data, od_res);

	LASSERTF(orro->oo_ref == 0,
		 "Busy NRS TRR policy object for OST with index %u, with %ld "
		 "refs\n", orro->oo_key.ok_idx, orro->oo_ref);

	OBD_SLAB_FREE_PTR(orro, orrd->od_cache);
}

static struct cfs_hash_ops nrs_orr_hash_ops = {
	.hs_hash	= nrs_orr_hop_hash,
	.hs_key		= nrs_orr_hop_key,
	.hs_keycmp	= nrs_orr_hop_keycmp,
	.hs_object	= nrs_orr_hop_object,
	.hs_get		= nrs_orr_hop_get,
	.hs_put		= nrs_orr_hop_put_free,
	.hs_put_locked	= nrs_orr_hop_put,
};

static struct cfs_hash_ops nrs_trr_hash_ops = {
	.hs_hash	= nrs_orr_hop_hash,
	.hs_key		= nrs_orr_hop_key,
	.hs_keycmp	= nrs_trr_hop_keycmp,
	.hs_object	= nrs_orr_hop_object,
	.hs_get		= nrs_orr_hop_get,
	.hs_put		= nrs_orr_hop_put,
	.hs_put_locked	= nrs_orr_hop_put,
	.hs_exit	= nrs_trr_hop_exit,
};

#define NRS_ORR_QUANTUM_DFLT	256

/**
 * Binary heap predicate.
 *
 * Uses
 * ptlrpc_nrs_request::nr_u::orr::or_round,
 * ptlrpc_nrs_request::nr_u::orr::or_sequence, and
 * ptlrpc_nrs_request::nr_u::orr::or_range to compare two binheap nodes and
 * produce a binary predicate that indicates their relative priority, so that
 * the binary heap can perform the necessary sorting operations.
 *
 * \param[in] e1 the first binheap node to compare
 * \param[in] e2 the second binheap node to compare
 *
 * \retval 0 e1 > e2
 * \retval 1 e1 < e2
 */
static int
orr_req_compare(struct binheap_node *e1, struct binheap_node *e2)
{
	struct ptlrpc_nrs_request *nrq1;
	struct ptlrpc_nrs_request *nrq2;

	nrq1 = container_of(e1, struct ptlrpc_nrs_request, nr_node);
	nrq2 = container_of(e2, struct ptlrpc_nrs_request, nr_node);

	/**
	 * Requests have been scheduled against a different scheduling round.
	 */
	if (nrq1->nr_u.orr.or_round < nrq2->nr_u.orr.or_round)
		return 1;
	else if (nrq1->nr_u.orr.or_round > nrq2->nr_u.orr.or_round)
		return 0;

	/**
	 * Requests have been scheduled against the same scheduling round, but
	 * belong to a different batch, i.e. they pertain to a different
	 * backend-fs object (for ORR policy instances) or OST (for TRR policy
	 * instances).
	 */
	if (nrq1->nr_u.orr.or_sequence < nrq2->nr_u.orr.or_sequence)
		return 1;
	else if (nrq1->nr_u.orr.or_sequence > nrq2->nr_u.orr.or_sequence)
		return 0;

	/**
	 * If round numbers and sequence numbers are equal, the two requests
	 * have been scheduled on the same round, and belong to the same batch,
	 * which means they pertain to the same backend-fs object (if this is an
	 * ORR policy instance), or to the same OST (if this is a TRR policy
	 * instance), so these requests should be sorted by ascending offset
	 * order.
	 */
	if (nrq1->nr_u.orr.or_range.or_start <
	    nrq2->nr_u.orr.or_range.or_start) {
		return 1;
	} else if (nrq1->nr_u.orr.or_range.or_start >
		 nrq2->nr_u.orr.or_range.or_start) {
		return 0;
	} else {
		/**
		 * Requests start from the same offset; Dispatch the shorter one
		 * first; perhaps slightly more chances of hitting caches like
		 * this.
		 */
		return nrq1->nr_u.orr.or_range.or_end <
		       nrq2->nr_u.orr.or_range.or_end;
	}
}

/**
 * ORR binary heap operations
 */
static struct binheap_ops nrs_orr_heap_ops = {
	.hop_enter	= NULL,
	.hop_exit	= NULL,
	.hop_compare	= orr_req_compare,
};

/**
 * Prints a warning message if an ORR/TRR policy is started on a service with
 * more than one CPT.  Not printed on the console for now, since we don't
 * have any performance metrics in the first place, and it is annoying.
 *
 * \param[in] policy the policy instance
 *
 * \retval 0 success
 */
static int nrs_orr_init(struct ptlrpc_nrs_policy *policy)
{
	if (policy->pol_nrs->nrs_svcpt->scp_service->srv_ncpts > 1)
		CDEBUG(D_CONFIG, "%s: The %s NRS policy was registered on a "
		      "service with multiple service partitions. This policy "
		      "may perform better with a single partition.\n",
		      policy->pol_nrs->nrs_svcpt->scp_service->srv_name,
		      policy->pol_desc->pd_name);

	return 0;
}

/**
 * Called when an ORR policy instance is started.
 *
 * \param[in] policy the policy
 *
 * \retval -ENOMEM OOM error
 * \retval 0	   success
 */
static int nrs_orr_start(struct ptlrpc_nrs_policy *policy, char *arg)
{
	struct nrs_orr_data    *orrd;
	struct cfs_hash_ops	       *ops;
	unsigned		cur_bits;
	unsigned		max_bits;
	unsigned		bkt_bits;
	unsigned		flags;
	int			rc = 0;
	ENTRY;

	OBD_CPT_ALLOC_PTR(orrd, nrs_pol2cptab(policy), nrs_pol2cptid(policy));
	if (orrd == NULL)
		RETURN(-ENOMEM);

	/*
	 * Binary heap instance for sorted incoming requests.
	 */
	orrd->od_binheap = binheap_create(&nrs_orr_heap_ops,
					      CBH_FLAG_ATOMIC_GROW, 4096, NULL,
					      nrs_pol2cptab(policy),
					      nrs_pol2cptid(policy));
	if (orrd->od_binheap == NULL)
		GOTO(out_orrd, rc = -ENOMEM);

	nrs_orr_genobjname(policy, orrd->od_objname);

	/**
	 * Slab cache for NRS ORR/TRR objects.
	 */
	orrd->od_cache = kmem_cache_create(orrd->od_objname,
					   sizeof(struct nrs_orr_object),
					   0, 0, NULL);
	if (orrd->od_cache == NULL)
		GOTO(out_binheap, rc = -ENOMEM);

	if (strncmp(policy->pol_desc->pd_name, NRS_POL_NAME_ORR,
		    NRS_POL_NAME_MAX) == 0) {
		ops = &nrs_orr_hash_ops;
		cur_bits = NRS_ORR_BITS;
		max_bits = NRS_ORR_BITS;
		bkt_bits = NRS_ORR_BKT_BITS;
		flags = NRS_ORR_HASH_FLAGS;
	} else {
		ops = &nrs_trr_hash_ops;
		cur_bits = NRS_TRR_BITS;
		max_bits = NRS_TRR_BITS;
		bkt_bits = NRS_TRR_BKT_BITS;
		flags = NRS_TRR_HASH_FLAGS;
	}

	/**
	 * Hash for finding objects by struct nrs_orr_key.
	 * XXX: For TRR, it might be better to avoid using libcfs_hash?
	 * All that needs to be resolved are OST indices, and they
	 * will stay relatively stable during an OSS node's lifetime.
	 */
	orrd->od_obj_hash = cfs_hash_create(orrd->od_objname, cur_bits,
					    max_bits, bkt_bits, 0,
					    CFS_HASH_MIN_THETA,
					    CFS_HASH_MAX_THETA, ops, flags);
	if (orrd->od_obj_hash == NULL)
		GOTO(out_cache, rc = -ENOMEM);

	/* XXX: Fields accessed unlocked */
	orrd->od_quantum = NRS_ORR_QUANTUM_DFLT;
	orrd->od_supp = NOS_DFLT;
	orrd->od_physical = true;
	/**
	 * Set to 1 so that the test inside nrs_orr_req_add() can evaluate to
	 * true.
	 */
	orrd->od_sequence = 1;

	policy->pol_private = orrd;

	RETURN(rc);

out_cache:
	kmem_cache_destroy(orrd->od_cache);
out_binheap:
	binheap_destroy(orrd->od_binheap);
out_orrd:
	OBD_FREE_PTR(orrd);

	RETURN(rc);
}

/**
 * Called when an ORR/TRR policy instance is stopped.
 *
 * Called when the policy has been instructed to transition to the
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state and has no more
 * pending requests to serve.
 *
 * \param[in] policy the policy
 */
static void nrs_orr_stop(struct ptlrpc_nrs_policy *policy)
{
	struct nrs_orr_data *orrd = policy->pol_private;
	ENTRY;

	LASSERT(orrd != NULL);
	LASSERT(orrd->od_binheap != NULL);
	LASSERT(orrd->od_obj_hash != NULL);
	LASSERT(orrd->od_cache != NULL);
	LASSERT(binheap_is_empty(orrd->od_binheap));

	binheap_destroy(orrd->od_binheap);
	cfs_hash_putref(orrd->od_obj_hash);
	kmem_cache_destroy(orrd->od_cache);

	OBD_FREE_PTR(orrd);
}

/**
 * Performs a policy-specific ctl function on ORR/TRR policy instances; similar
 * to ioctl.
 *
 * \param[in]	  policy the policy instance
 * \param[in]	  opc	 the opcode
 * \param[in,out] arg	 used for passing parameters and information
 *
 * \pre assert_spin_locked(&policy->pol_nrs->->nrs_lock)
 * \post assert_spin_locked(&policy->pol_nrs->->nrs_lock)
 *
 * \retval 0   operation carried successfully
 * \retval -ve error
 */
static int nrs_orr_ctl(struct ptlrpc_nrs_policy *policy,
		       enum ptlrpc_nrs_ctl opc, void *arg)
{
	assert_spin_locked(&policy->pol_nrs->nrs_lock);

	switch((enum nrs_ctl_orr)opc) {
	default:
		RETURN(-EINVAL);

	case NRS_CTL_ORR_RD_QUANTUM: {
		struct nrs_orr_data	*orrd = policy->pol_private;

		*(__u16 *)arg = orrd->od_quantum;
		}
		break;

	case NRS_CTL_ORR_WR_QUANTUM: {
		struct nrs_orr_data	*orrd = policy->pol_private;

		orrd->od_quantum = *(__u16 *)arg;
		LASSERT(orrd->od_quantum != 0);
		}
		break;

	case NRS_CTL_ORR_RD_OFF_TYPE: {
		struct nrs_orr_data	*orrd = policy->pol_private;

		*(bool *)arg = orrd->od_physical;
		}
		break;

	case NRS_CTL_ORR_WR_OFF_TYPE: {
		struct nrs_orr_data	*orrd = policy->pol_private;

		orrd->od_physical = *(bool *)arg;
		}
		break;

	case NRS_CTL_ORR_RD_SUPP_REQ: {
		struct nrs_orr_data	*orrd = policy->pol_private;

		*(enum nrs_orr_supp *)arg = orrd->od_supp;
		}
		break;

	case NRS_CTL_ORR_WR_SUPP_REQ: {
		struct nrs_orr_data	*orrd = policy->pol_private;

		orrd->od_supp = *(enum nrs_orr_supp *)arg;
		LASSERT((orrd->od_supp & NOS_OST_RW) != 0);
		}
		break;
	}
	RETURN(0);
}

/**
 * Obtains resources for ORR/TRR policy instances. The top-level resource lives
 * inside \e nrs_orr_data and the second-level resource inside
 * \e nrs_orr_object instances.
 *
 * \param[in]  policy	  the policy for which resources are being taken for
 *			  request \a nrq
 * \param[in]  nrq	  the request for which resources are being taken
 * \param[in]  parent	  parent resource, embedded in nrs_orr_data for the
 *			  ORR/TRR policies
 * \param[out] resp	  used to return resource references
 * \param[in]  moving_req signifies limited caller context; used to perform
 *			  memory allocations in an atomic context in this
 *			  policy
 *
 * \retval 0   we are returning a top-level, parent resource, one that is
 *	       embedded in an nrs_orr_data object
 * \retval 1   we are returning a bottom-level resource, one that is embedded
 *	       in an nrs_orr_object object
 *
 * \see nrs_resource_get_safe()
 */
static int nrs_orr_res_get(struct ptlrpc_nrs_policy *policy,
			   struct ptlrpc_nrs_request *nrq,
			   const struct ptlrpc_nrs_resource *parent,
			   struct ptlrpc_nrs_resource **resp, bool moving_req)
{
	struct nrs_orr_data	       *orrd;
	struct nrs_orr_object	       *orro;
	struct nrs_orr_object	       *tmp;
	struct nrs_orr_key		key = { { { 0 } } };
	__u32				opc;
	int				rc = 0;

	/**
	 * struct nrs_orr_data is requested.
	 */
	if (parent == NULL) {
		*resp = &((struct nrs_orr_data *)policy->pol_private)->od_res;
		return 0;
	}

	orrd = container_of(parent, struct nrs_orr_data, od_res);

	/**
	 * If the request type is not supported, fail the enqueuing; the RPC
	 * will be handled by the fallback NRS policy.
	 */
	if (!nrs_orr_req_supported(orrd, nrq, &opc))
		return -1;

	/**
	 * Fill in the key for the request; OST FID for ORR policy instances,
	 * and OST index for TRR policy instances.
	 */
	rc = nrs_orr_key_fill(orrd, nrq, opc, policy->pol_desc->pd_name, &key);
	if (rc < 0)
		RETURN(rc);

	/**
	 * Set the offset range the request covers
	 */
	rc = nrs_orr_range_fill(nrq, orrd, opc, moving_req);
	if (rc < 0)
		RETURN(rc);

	orro = cfs_hash_lookup(orrd->od_obj_hash, &key);
	if (orro != NULL)
		goto out;

	OBD_SLAB_CPT_ALLOC_PTR_GFP(orro, orrd->od_cache,
				   nrs_pol2cptab(policy), nrs_pol2cptid(policy),
				   moving_req ? GFP_ATOMIC : GFP_NOFS);
	if (orro == NULL)
		RETURN(-ENOMEM);

	orro->oo_key = key;
	orro->oo_ref = 1;

	tmp = cfs_hash_findadd_unique(orrd->od_obj_hash, &orro->oo_key,
				      &orro->oo_hnode);
	if (tmp != orro) {
		OBD_SLAB_FREE_PTR(orro, orrd->od_cache);
		orro = tmp;
	}
out:
	/**
	 * For debugging purposes
	 */
	nrq->nr_u.orr.or_key = orro->oo_key;

	*resp = &orro->oo_res;

	return 1;
}

/**
 * Called when releasing references to the resource hierachy obtained for a
 * request for scheduling using ORR/TRR policy instances
 *
 * \param[in] policy   the policy the resource belongs to
 * \param[in] res      the resource to be released
 */
static void nrs_orr_res_put(struct ptlrpc_nrs_policy *policy,
			    const struct ptlrpc_nrs_resource *res)
{
	struct nrs_orr_data	*orrd;
	struct nrs_orr_object	*orro;

	/**
	 * Do nothing for freeing parent, nrs_orr_data resources.
	 */
	if (res->res_parent == NULL)
		return;

	orro = container_of(res, struct nrs_orr_object, oo_res);
	orrd = container_of(res->res_parent, struct nrs_orr_data, od_res);

	cfs_hash_put(orrd->od_obj_hash, &orro->oo_hnode);
}

/**
 * Called when polling an ORR/TRR policy instance for a request so that it can
 * be served. Returns the request that is at the root of the binary heap, as
 * that is the lowest priority one (i.e. libcfs_heap is an implementation of a
 * min-heap)
 *
 * \param[in] policy the policy instance being polled
 * \param[in] peek   when set, signifies that we just want to examine the
 *		     request, and not handle it, so the request is not removed
 *		     from the policy.
 * \param[in] force  force the policy to return a request; unused in this policy
 *
 * \retval the request to be handled
 * \retval NULL no request available
 *
 * \see ptlrpc_nrs_req_get_nolock()
 * \see nrs_request_get()
 */
static
struct ptlrpc_nrs_request *nrs_orr_req_get(struct ptlrpc_nrs_policy *policy,
					   bool peek, bool force)
{
	struct nrs_orr_data	  *orrd = policy->pol_private;
	struct binheap_node	  *node = binheap_root(orrd->od_binheap);
	struct ptlrpc_nrs_request *nrq;

	nrq = unlikely(node == NULL) ? NULL :
	      container_of(node, struct ptlrpc_nrs_request, nr_node);

	if (likely(!peek && nrq != NULL)) {
		struct nrs_orr_object *orro;

		orro = container_of(nrs_request_resource(nrq),
				    struct nrs_orr_object, oo_res);

		LASSERT(nrq->nr_u.orr.or_round <= orro->oo_round);

		binheap_remove(orrd->od_binheap, &nrq->nr_node);
		orro->oo_active--;

		if (strncmp(policy->pol_desc->pd_name, NRS_POL_NAME_ORR,
				 NRS_POL_NAME_MAX) == 0)
			CDEBUG(D_RPCTRACE,
			       "NRS: starting to handle %s request for object "
			       "with FID "DFID", from OST with index %u, with "
			       "round %llu\n", NRS_POL_NAME_ORR,
			       PFID(&orro->oo_key.ok_fid),
			       nrq->nr_u.orr.or_key.ok_idx,
			       nrq->nr_u.orr.or_round);
		else
			CDEBUG(D_RPCTRACE,
			       "NRS: starting to handle %s request from OST "
			       "with index %u, with round %llu\n",
			       NRS_POL_NAME_TRR, nrq->nr_u.orr.or_key.ok_idx,
			       nrq->nr_u.orr.or_round);

		/** Peek at the next request to be served */
		node = binheap_root(orrd->od_binheap);

		/** No more requests */
		if (unlikely(node == NULL)) {
			orrd->od_round++;
		} else {
			struct ptlrpc_nrs_request *next;

			next = container_of(node, struct ptlrpc_nrs_request,
					    nr_node);

			if (orrd->od_round < next->nr_u.orr.or_round)
				orrd->od_round = next->nr_u.orr.or_round;
		}
	}

	return nrq;
}

/**
 * Sort-adds request \a nrq to an ORR/TRR \a policy instance's set of queued
 * requests in the policy's binary heap.
 *
 * A scheduling round is a stream of requests that have been sorted in batches
 * according to the backend-fs object (for ORR policy instances) or OST (for TRR
 * policy instances) that they pertain to (as identified by its IDIF FID or OST
 * index respectively); there can be only one batch for each object or OST in
 * each round. The batches are of maximum size nrs_orr_data:od_quantum. When a
 * new request arrives for scheduling for an object or OST that has exhausted
 * its quantum in its current round, the request will be scheduled on the next
 * scheduling round. Requests are allowed to be scheduled against a round until
 * all requests for the round are serviced, so an object or OST might miss a
 * round if requests are not scheduled for it for a long enough period of time.
 * Objects or OSTs that miss a round will continue with having their next
 * request scheduled, starting at the round that requests are being dispatched
 * for, at the time of arrival of this request.
 *
 * Requests are tagged with the round number and a sequence number; the sequence
 * number indicates the relative ordering amongst the batches of requests in a
 * round, and is identical for all requests in a batch, as is the round number.
 * The round and sequence numbers are used by orr_req_compare() in order to use
 * nrs_orr_data::od_binheap in order to maintain an ordered set of rounds, with
 * each round consisting of an ordered set of batches of requests, and each
 * batch consisting of an ordered set of requests according to their logical
 * file or physical disk offsets.
 *
 * \param[in] policy the policy
 * \param[in] nrq    the request to add
 *
 * \retval 0	request successfully added
 * \retval != 0 error
 */
static int nrs_orr_req_add(struct ptlrpc_nrs_policy *policy,
			   struct ptlrpc_nrs_request *nrq)
{
	struct nrs_orr_data	*orrd;
	struct nrs_orr_object	*orro;
	int			 rc;

	orro = container_of(nrs_request_resource(nrq),
			    struct nrs_orr_object, oo_res);
	orrd = container_of(nrs_request_resource(nrq)->res_parent,
			    struct nrs_orr_data, od_res);

	if (orro->oo_quantum == 0 || orro->oo_round < orrd->od_round ||
	    (orro->oo_active == 0 && orro->oo_quantum > 0)) {

		/**
		 * If there are no pending requests for the object/OST, but some
		 * of its quantum still remains unused, which implies we did not
		 * get a chance to schedule up to its maximum allowed batch size
		 * of requests in the previous round this object/OST
		 * participated in, schedule this next request on a new round;
		 * this avoids fragmentation of request batches caused by
		 * intermittent inactivity on the object/OST, at the expense of
		 * potentially slightly increased service time for the request
		 * batch this request will be a part of.
		 */
		if (orro->oo_active == 0 && orro->oo_quantum > 0)
			orro->oo_round++;

		/** A new scheduling round has commenced */
		if (orro->oo_round < orrd->od_round)
			orro->oo_round = orrd->od_round;

		/** I was not the last object/OST that scheduled a request */
		if (orro->oo_sequence < orrd->od_sequence)
			orro->oo_sequence = ++orrd->od_sequence;
		/**
		 * Reset the quantum if we have reached the maximum quantum
		 * size for this batch, or even if we have not managed to
		 * complete a batch size up to its maximum allowed size.
		 * XXX: Accessed unlocked
		 */
		orro->oo_quantum = orrd->od_quantum;
	}

	nrq->nr_u.orr.or_round = orro->oo_round;
	nrq->nr_u.orr.or_sequence = orro->oo_sequence;

	rc = binheap_insert(orrd->od_binheap, &nrq->nr_node);
	if (rc == 0) {
		orro->oo_active++;
		if (--orro->oo_quantum == 0)
			orro->oo_round++;
	}
	return rc;
}

/**
 * Removes request \a nrq from an ORR/TRR \a policy instance's set of queued
 * requests.
 *
 * \param[in] policy the policy
 * \param[in] nrq    the request to remove
 */
static void nrs_orr_req_del(struct ptlrpc_nrs_policy *policy,
			    struct ptlrpc_nrs_request *nrq)
{
	struct nrs_orr_data	*orrd;
	struct nrs_orr_object	*orro;
	bool			 is_root;

	orro = container_of(nrs_request_resource(nrq),
			    struct nrs_orr_object, oo_res);
	orrd = container_of(nrs_request_resource(nrq)->res_parent,
			    struct nrs_orr_data, od_res);

	LASSERT(nrq->nr_u.orr.or_round <= orro->oo_round);

	is_root = &nrq->nr_node == binheap_root(orrd->od_binheap);

	binheap_remove(orrd->od_binheap, &nrq->nr_node);
	orro->oo_active--;

	/**
	 * If we just deleted the node at the root of the binheap, we may have
	 * to adjust round numbers.
	 */
	if (unlikely(is_root)) {
		/** Peek at the next request to be served */
		struct binheap_node *node = binheap_root(orrd->od_binheap);

		/** No more requests */
		if (unlikely(node == NULL)) {
			orrd->od_round++;
		} else {
			nrq = container_of(node, struct ptlrpc_nrs_request,
					   nr_node);

			if (orrd->od_round < nrq->nr_u.orr.or_round)
				orrd->od_round = nrq->nr_u.orr.or_round;
		}
	}
}

/**
 * Called right after the request \a nrq finishes being handled by ORR policy
 * instance \a policy.
 *
 * \param[in] policy the policy that handled the request
 * \param[in] nrq    the request that was handled
 */
static void nrs_orr_req_stop(struct ptlrpc_nrs_policy *policy,
			     struct ptlrpc_nrs_request *nrq)
{
	/** NB: resource control, credits etc can be added here */
	if (strncmp(policy->pol_desc->pd_name, NRS_POL_NAME_ORR,
		    NRS_POL_NAME_MAX) == 0)
		CDEBUG(D_RPCTRACE,
		       "NRS: finished handling %s request for object with FID "
		       DFID", from OST with index %u, with round %llu\n",
		       NRS_POL_NAME_ORR, PFID(&nrq->nr_u.orr.or_key.ok_fid),
		       nrq->nr_u.orr.or_key.ok_idx, nrq->nr_u.orr.or_round);
	else
		CDEBUG(D_RPCTRACE,
		       "NRS: finished handling %s request from OST with index %u,"
		       " with round %llu\n",
		       NRS_POL_NAME_TRR, nrq->nr_u.orr.or_key.ok_idx,
		       nrq->nr_u.orr.or_round);
}

/**
 * debugfs interface
 */

/**
 * This allows to bundle the policy name into the lprocfs_vars::data pointer
 * so that lprocfs read/write functions can be used by both the ORR and TRR
 * policies.
 */
static struct nrs_lprocfs_orr_data {
	struct ptlrpc_service	*svc;
	char			*name;
} lprocfs_orr_data = {
	.name = NRS_POL_NAME_ORR
}, lprocfs_trr_data = {
	.name = NRS_POL_NAME_TRR
};

/**
 * Retrieves the value of the Round Robin quantum (i.e. the maximum batch size)
 * for ORR/TRR policy instances on both the regular and high-priority NRS head
 * of a service, as long as a policy instance is not in the
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state; policy instances in this
 * state are skipped later by nrs_orr_ctl().
 *
 * Quantum values are in # of RPCs, and the output is in YAML format.
 *
 * For example:
 *
 *	reg_quantum:256
 *	hp_quantum:8
 *
 * XXX: the CRR-N version of this, ptlrpc_lprocfs_rd_nrs_crrn_quantum() is
 * almost identical; it can be reworked and then reused for ORR/TRR.
 */
static int
ptlrpc_lprocfs_nrs_orr_quantum_seq_show(struct seq_file *m, void *data)
{
	struct nrs_lprocfs_orr_data *orr_data = m->private;
	struct ptlrpc_service	    *svc = orr_data->svc;
	__u16			     quantum;
	int			     rc;

	/**
	 * Perform two separate calls to this as only one of the NRS heads'
	 * policies may be in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STARTED or
	 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPING state.
	 */
	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
				       orr_data->name,
				       NRS_CTL_ORR_RD_QUANTUM,
				       true, &quantum);
	if (rc == 0) {
		seq_printf(m, NRS_LPROCFS_QUANTUM_NAME_REG "%-5d\n", quantum);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in the
		 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	} else if (rc != -ENODEV) {
		return rc;
	}

	/**
	 * We know the ost_io service which is the only one ORR/TRR policies are
	 * compatible with, do have an HP NRS head, but it may be best to guard
	 * against a possible change of this in the future.
	 */
	if (!nrs_svc_has_hp(svc))
		goto no_hp;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
				       orr_data->name, NRS_CTL_ORR_RD_QUANTUM,
				       true, &quantum);
	if (rc == 0) {
		seq_printf(m, NRS_LPROCFS_QUANTUM_NAME_HP"%-5d\n", quantum);
		/**
		 * Ignore -ENODEV as the high priority NRS head's policy may be
		 * in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	} else if (rc != -ENODEV) {
		return rc;
	}

no_hp:

	return rc;
}

/**
 * Sets the value of the Round Robin quantum (i.e. the maximum batch size)
 * for ORR/TRR policy instances of a service. The user can set the quantum size
 * for the regular and high priority NRS head separately by specifying each
 * value, or both together in a single invocation.
 *
 * For example:
 *
 * lctl set_param ost.OSS.ost_io.nrs_orr_quantum=req_quantum:64, to set the
 * request quantum size of the ORR policy instance on the regular NRS head of
 * the ost_io service to 64
 *
 * lctl set_param ost.OSS.ost_io.nrs_trr_quantum=hp_quantum:8 to set the request
 * quantum size of the TRR policy instance on the high priority NRS head of the
 * ost_io service to 8
 *
 * lctl set_param ost.OSS.ost_io.nrs_orr_quantum=32, to set both the request
 * quantum size of the ORR policy instance on both the regular and the high
 * priority NRS head of the ost_io service to 32
 *
 * policy instances in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state
 * are skipped later by nrs_orr_ctl().
 *
 * XXX: the CRR-N version of this, ptlrpc_lprocfs_wr_nrs_crrn_quantum() is
 * almost identical; it can be reworked and then reused for ORR/TRR.
 */
static ssize_t
ptlrpc_lprocfs_nrs_orr_quantum_seq_write(struct file *file,
					 const char __user *buffer,
					 size_t count, loff_t *off)
{
	struct seq_file		    *m = file->private_data;
	struct nrs_lprocfs_orr_data *orr_data = m->private;
	struct ptlrpc_service	    *svc = orr_data->svc;
	enum ptlrpc_nrs_queue_type   queue = 0;
	char			     kernbuf[LPROCFS_NRS_WR_QUANTUM_MAX_CMD];
	char			    *val;
	long			     quantum_reg;
	long			     quantum_hp;
	/** lprocfs_find_named_value() modifies its argument, so keep a copy */
	size_t			     count_copy;
	int			     rc = 0;
	int			     rc2 = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;

        kernbuf[count] = '\0';

	count_copy = count;

	/**
	 * Check if the regular quantum value has been specified
	 */
	val = lprocfs_find_named_value(kernbuf, NRS_LPROCFS_QUANTUM_NAME_REG,
				       &count_copy);
	if (val != kernbuf) {
		rc = kstrtol(val, 10, &quantum_reg);
		if (rc)
			return rc;
		queue |= PTLRPC_NRS_QUEUE_REG;
	}

	count_copy = count;

	/**
	 * Check if the high priority quantum value has been specified
	 */
	val = lprocfs_find_named_value(kernbuf, NRS_LPROCFS_QUANTUM_NAME_HP,
				       &count_copy);
	if (val != kernbuf) {
		if (!nrs_svc_has_hp(svc))
			return -ENODEV;

		rc = kstrtol(val, 10, &quantum_hp);
		if (rc)
			return rc;

		queue |= PTLRPC_NRS_QUEUE_HP;
	}

	/**
	 * If none of the queues has been specified, look for a valid numerical
	 * value
	 */
	if (queue == 0) {
		rc = kstrtol(kernbuf, 10, &quantum_reg);
		if (rc)
			return rc;

		queue = PTLRPC_NRS_QUEUE_REG;

		if (nrs_svc_has_hp(svc)) {
			queue |= PTLRPC_NRS_QUEUE_HP;
			quantum_hp = quantum_reg;
		}
	}

	if ((((queue & PTLRPC_NRS_QUEUE_REG) != 0) &&
	    ((quantum_reg > LPROCFS_NRS_QUANTUM_MAX || quantum_reg <= 0))) ||
	    (((queue & PTLRPC_NRS_QUEUE_HP) != 0) &&
	    ((quantum_hp > LPROCFS_NRS_QUANTUM_MAX || quantum_hp <= 0))))
		return -EINVAL;

	/**
	 * We change the values on regular and HP NRS heads separately, so that
	 * we do not exit early from ptlrpc_nrs_policy_control() with an error
	 * returned by nrs_policy_ctl_locked(), in cases where the user has not
	 * started the policy on either the regular or HP NRS head; i.e. we are
	 * ignoring -ENODEV within nrs_policy_ctl_locked(). -ENODEV is returned
	 * only if the operation fails with -ENODEV on all heads that have been
	 * specified by the command; if at least one operation succeeds,
	 * success is returned.
	 */
	if ((queue & PTLRPC_NRS_QUEUE_REG) != 0) {
		rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
					       orr_data->name,
					       NRS_CTL_ORR_WR_QUANTUM, false,
					       &quantum_reg);
		if ((rc < 0 && rc != -ENODEV) ||
		    (rc == -ENODEV && queue == PTLRPC_NRS_QUEUE_REG))
			return rc;
	}

	if ((queue & PTLRPC_NRS_QUEUE_HP) != 0) {
		rc2 = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
						orr_data->name,
						NRS_CTL_ORR_WR_QUANTUM, false,
						&quantum_hp);
		if ((rc2 < 0 && rc2 != -ENODEV) ||
		    (rc2 == -ENODEV && queue == PTLRPC_NRS_QUEUE_HP))
			return rc2;
	}

	return rc == -ENODEV && rc2 == -ENODEV ? -ENODEV : count;
}

LDEBUGFS_SEQ_FOPS(ptlrpc_lprocfs_nrs_orr_quantum);

#define LPROCFS_NRS_OFF_NAME_REG		"reg_offset_type:"
#define LPROCFS_NRS_OFF_NAME_HP			"hp_offset_type:"

#define LPROCFS_NRS_OFF_NAME_PHYSICAL		"physical"
#define LPROCFS_NRS_OFF_NAME_LOGICAL		"logical"

/**
 * Retrieves the offset type used by ORR/TRR policy instances on both the
 * regular and high-priority NRS head of a service, as long as a policy
 * instance is not in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state;
 * policy instances in this state are skipped later by nrs_orr_ctl().
 *
 * Offset type information is a (physical|logical) string, and output is
 * in YAML format.
 *
 * For example:
 *
 *	reg_offset_type:physical
 *	hp_offset_type:logical
 */
static int
ptlrpc_lprocfs_nrs_orr_offset_type_seq_show(struct seq_file *m, void *data)
{
	struct nrs_lprocfs_orr_data *orr_data = m->private;
	struct ptlrpc_service	    *svc = orr_data->svc;
	bool			     physical;
	int			     rc;

	/**
	 * Perform two separate calls to this as only one of the NRS heads'
	 * policies may be in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STARTED
	 * or ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPING state.
	 */
	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
				       orr_data->name, NRS_CTL_ORR_RD_OFF_TYPE,
				       true, &physical);
	if (rc == 0) {
		seq_printf(m, LPROCFS_NRS_OFF_NAME_REG"%s\n",
			   physical ? LPROCFS_NRS_OFF_NAME_PHYSICAL :
			   LPROCFS_NRS_OFF_NAME_LOGICAL);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in the
		 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	} else if (rc != -ENODEV) {
		return rc;
	}

	/**
	 * We know the ost_io service which is the only one ORR/TRR policies are
	 * compatible with, do have an HP NRS head, but it may be best to guard
	 * against a possible change of this in the future.
	 */
	if (!nrs_svc_has_hp(svc))
		goto no_hp;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
				       orr_data->name, NRS_CTL_ORR_RD_OFF_TYPE,
				       true, &physical);
	if (rc == 0) {
		seq_printf(m, LPROCFS_NRS_OFF_NAME_HP"%s\n",
			   physical ? LPROCFS_NRS_OFF_NAME_PHYSICAL :
			   LPROCFS_NRS_OFF_NAME_LOGICAL);
		/**
		 * Ignore -ENODEV as the high priority NRS head's policy may be
		 * in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	} else if (rc != -ENODEV) {
		return rc;
	}

no_hp:
	return rc;
}

/**
 * Max valid command string is the size of the labels, plus "physical" twice.
 * plus a separating ' '
 */
#define LPROCFS_NRS_WR_OFF_TYPE_MAX_CMD					       \
	sizeof(LPROCFS_NRS_OFF_NAME_REG LPROCFS_NRS_OFF_NAME_PHYSICAL " "      \
	       LPROCFS_NRS_OFF_NAME_HP LPROCFS_NRS_OFF_NAME_PHYSICAL)

/**
 * Sets the type of offsets used to order RPCs in ORR/TRR policy instances. The
 * user can set offset type for the regular or high priority NRS head
 * separately by specifying each value, or both together in a single invocation.
 *
 * For example:
 *
 * lctl set_param ost.OSS.ost_io.nrs_orr_offset_type=
 * reg_offset_type:physical, to enable the ORR policy instance on the regular
 * NRS head of the ost_io service to use physical disk offset ordering.
 *
 * lctl set_param ost.OSS.ost_io.nrs_trr_offset_type=logical, to enable the TRR
 * policy instances on both the regular ang high priority NRS heads of the
 * ost_io service to use logical file offset ordering.
 *
 * policy instances in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state are
 * are skipped later by nrs_orr_ctl().
 */
static ssize_t
ptlrpc_lprocfs_nrs_orr_offset_type_seq_write(struct file *file,
					     const char __user *buffer,
					      size_t count,
					     loff_t *off)
{
	struct seq_file		    *m = file->private_data;
	struct nrs_lprocfs_orr_data *orr_data = m->private;
	struct ptlrpc_service	    *svc = orr_data->svc;
	enum ptlrpc_nrs_queue_type   queue = 0;
	char			     kernbuf[LPROCFS_NRS_WR_OFF_TYPE_MAX_CMD];
	char			    *val_reg;
	char			    *val_hp;
	bool			     physical_reg;
	bool			     physical_hp;
	size_t			     count_copy;
	int			     rc = 0;
	int			     rc2 = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;

        kernbuf[count] = '\0';

	count_copy = count;

	/**
	 * Check if the regular offset type has been specified
	 */
	val_reg = lprocfs_find_named_value(kernbuf,
					   LPROCFS_NRS_OFF_NAME_REG,
					   &count_copy);
	if (val_reg != kernbuf)
		queue |= PTLRPC_NRS_QUEUE_REG;

	count_copy = count;

	/**
	 * Check if the high priority offset type has been specified
	 */
	val_hp = lprocfs_find_named_value(kernbuf, LPROCFS_NRS_OFF_NAME_HP,
					  &count_copy);
	if (val_hp != kernbuf) {
		if (!nrs_svc_has_hp(svc))
			return -ENODEV;

		queue |= PTLRPC_NRS_QUEUE_HP;
	}

	/**
	 * If none of the queues has been specified, there may be a valid
	 * command string at the start of the buffer.
	 */
	if (queue == 0) {
		queue = PTLRPC_NRS_QUEUE_REG;

		if (nrs_svc_has_hp(svc))
			queue |= PTLRPC_NRS_QUEUE_HP;
	}

	if ((queue & PTLRPC_NRS_QUEUE_REG) != 0) {
		if (strncmp(val_reg, LPROCFS_NRS_OFF_NAME_PHYSICAL,
			    sizeof(LPROCFS_NRS_OFF_NAME_PHYSICAL) - 1) == 0)
			physical_reg = true;
		else if (strncmp(val_reg, LPROCFS_NRS_OFF_NAME_LOGICAL,
			 sizeof(LPROCFS_NRS_OFF_NAME_LOGICAL) - 1) == 0)
			physical_reg = false;
		else
			return -EINVAL;
	}

	if ((queue & PTLRPC_NRS_QUEUE_HP) != 0) {
		if (strncmp(val_hp, LPROCFS_NRS_OFF_NAME_PHYSICAL,
			    sizeof(LPROCFS_NRS_OFF_NAME_PHYSICAL) - 1) == 0)
			physical_hp = true;
		else if (strncmp(val_hp, LPROCFS_NRS_OFF_NAME_LOGICAL,
				 sizeof(LPROCFS_NRS_OFF_NAME_LOGICAL) - 1) == 0)
			physical_hp = false;
		else
			return -EINVAL;
	}

	/**
	 * We change the values on regular and HP NRS heads separately, so that
	 * we do not exit early from ptlrpc_nrs_policy_control() with an error
	 * returned by nrs_policy_ctl_locked(), in cases where the user has not
	 * started the policy on either the regular or HP NRS head; i.e. we are
	 * ignoring -ENODEV within nrs_policy_ctl_locked(). -ENODEV is returned
	 * only if the operation fails with -ENODEV on all heads that have been
	 * specified by the command; if at least one operation succeeds,
	 * success is returned.
	 */
	if ((queue & PTLRPC_NRS_QUEUE_REG) != 0) {
		rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
					       orr_data->name,
					       NRS_CTL_ORR_WR_OFF_TYPE, false,
					       &physical_reg);
		if ((rc < 0 && rc != -ENODEV) ||
		    (rc == -ENODEV && queue == PTLRPC_NRS_QUEUE_REG))
			return rc;
	}

	if ((queue & PTLRPC_NRS_QUEUE_HP) != 0) {
		rc2 = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
						orr_data->name,
						NRS_CTL_ORR_WR_OFF_TYPE, false,
						&physical_hp);
		if ((rc2 < 0 && rc2 != -ENODEV) ||
		    (rc2 == -ENODEV && queue == PTLRPC_NRS_QUEUE_HP))
			return rc2;
	}

	return rc == -ENODEV && rc2 == -ENODEV ? -ENODEV : count;
}

LDEBUGFS_SEQ_FOPS(ptlrpc_lprocfs_nrs_orr_offset_type);

#define NRS_LPROCFS_REQ_SUPP_NAME_REG		"reg_supported:"
#define NRS_LPROCFS_REQ_SUPP_NAME_HP		"hp_supported:"

#define LPROCFS_NRS_SUPP_NAME_READS		"reads"
#define LPROCFS_NRS_SUPP_NAME_WRITES		"writes"
#define LPROCFS_NRS_SUPP_NAME_READWRITES	"reads_and_writes"

/**
 * Translates enum nrs_orr_supp values to a corresponding string.
 */
static const char *nrs_orr_supp2str(enum nrs_orr_supp supp)
{
	switch(supp) {
	default:
		LBUG();
	case NOS_OST_READ:
		return LPROCFS_NRS_SUPP_NAME_READS;
	case NOS_OST_WRITE:
		return LPROCFS_NRS_SUPP_NAME_WRITES;
	case NOS_OST_RW:
		return LPROCFS_NRS_SUPP_NAME_READWRITES;
	}
}

/**
 * Translates strings to the corresponding enum nrs_orr_supp value
 */
static enum nrs_orr_supp nrs_orr_str2supp(const char *val)
{
	if (strncmp(val, LPROCFS_NRS_SUPP_NAME_READWRITES,
		    sizeof(LPROCFS_NRS_SUPP_NAME_READWRITES) - 1) == 0)
		return NOS_OST_RW;
	else if (strncmp(val, LPROCFS_NRS_SUPP_NAME_READS,
			 sizeof(LPROCFS_NRS_SUPP_NAME_READS) - 1) == 0)
		return NOS_OST_READ;
	else if (strncmp(val, LPROCFS_NRS_SUPP_NAME_WRITES,
			 sizeof(LPROCFS_NRS_SUPP_NAME_WRITES) - 1) == 0)
		return NOS_OST_WRITE;
	else
		return -EINVAL;
}

/**
 * Retrieves the type of RPCs handled at the point of invocation by ORR/TRR
 * policy instances on both the regular and high-priority NRS head of a service,
 * as long as a policy instance is not in the
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state; policy instances in this
 * state are skipped later by nrs_orr_ctl().
 *
 * Supported RPC type information is a (reads|writes|reads_and_writes) string,
 * and output is in YAML format.
 *
 * For example:
 *
 *	reg_supported:reads
 *	hp_supported:reads_and_writes
 */
static int
ptlrpc_lprocfs_nrs_orr_supported_seq_show(struct seq_file *m, void *data)
{
	struct nrs_lprocfs_orr_data *orr_data = m->private;
	struct ptlrpc_service	    *svc = orr_data->svc;
	enum nrs_orr_supp	     supported;
	int			     rc;

	/**
	 * Perform two separate calls to this as only one of the NRS heads'
	 * policies may be in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STARTED
	 * or ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPING state.
	 */
	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
				       orr_data->name,
				       NRS_CTL_ORR_RD_SUPP_REQ, true,
				       &supported);

	if (rc == 0) {
		seq_printf(m, NRS_LPROCFS_REQ_SUPP_NAME_REG"%s\n",
			   nrs_orr_supp2str(supported));
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in the
		 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	} else if (rc != -ENODEV) {
		return rc;
	}

	/**
	 * We know the ost_io service which is the only one ORR/TRR policies are
	 * compatible with, do have an HP NRS head, but it may be best to guard
	 * against a possible change of this in the future.
	 */
	if (!nrs_svc_has_hp(svc))
		goto no_hp;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
				       orr_data->name,
				       NRS_CTL_ORR_RD_SUPP_REQ, true,
				       &supported);
	if (rc == 0) {
		seq_printf(m, NRS_LPROCFS_REQ_SUPP_NAME_HP"%s\n",
			   nrs_orr_supp2str(supported));
		/**
		 * Ignore -ENODEV as the high priority NRS head's policy may be
		 * in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	} else if (rc != -ENODEV) {
		return rc;
	}

no_hp:

	return rc;
}

/**
 * Max valid command string is the size of the labels, plus "reads_and_writes"
 * twice, plus a separating ' '
 */
#define LPROCFS_NRS_WR_REQ_SUPP_MAX_CMD					       \
	sizeof(NRS_LPROCFS_REQ_SUPP_NAME_REG LPROCFS_NRS_SUPP_NAME_READWRITES  \
	       NRS_LPROCFS_REQ_SUPP_NAME_HP LPROCFS_NRS_SUPP_NAME_READWRITES   \
	       " ")

/**
 * Sets the type of RPCs handled by ORR/TRR policy instances. The user can
 * modify this setting for the regular or high priority NRS heads separately, or
 * both together in a single invocation.
 *
 * For example:
 *
 * lctl set_param ost.OSS.ost_io.nrs_orr_supported=
 * "reg_supported:reads", to enable the ORR policy instance on the regular NRS
 * head of the ost_io service to handle OST_READ RPCs.
 *
 * lctl set_param ost.OSS.ost_io.nrs_trr_supported=reads_and_writes, to enable
 * the TRR policy instances on both the regular ang high priority NRS heads of
 * the ost_io service to use handle OST_READ and OST_WRITE RPCs.
 *
 * policy instances in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state are
 * are skipped later by nrs_orr_ctl().
 */
static ssize_t
ptlrpc_lprocfs_nrs_orr_supported_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count,
					   loff_t *off)
{
	struct seq_file		    *m = file->private_data;
	struct nrs_lprocfs_orr_data *orr_data = m->private;
	struct ptlrpc_service	    *svc = orr_data->svc;
	enum ptlrpc_nrs_queue_type   queue = 0;
	char			     kernbuf[LPROCFS_NRS_WR_REQ_SUPP_MAX_CMD];
	char			    *val_reg;
	char			    *val_hp;
	enum nrs_orr_supp	     supp_reg;
	enum nrs_orr_supp	     supp_hp;
	size_t			     count_copy;
	int			     rc = 0;
	int			     rc2 = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;

        kernbuf[count] = '\0';

	count_copy = count;

	/**
	 * Check if the regular supported requests setting has been specified
	 */
	val_reg = lprocfs_find_named_value(kernbuf,
					   NRS_LPROCFS_REQ_SUPP_NAME_REG,
					   &count_copy);
	if (val_reg != kernbuf)
		queue |= PTLRPC_NRS_QUEUE_REG;

	count_copy = count;

	/**
	 * Check if the high priority supported requests setting has been
	 * specified
	 */
	val_hp = lprocfs_find_named_value(kernbuf, NRS_LPROCFS_REQ_SUPP_NAME_HP,
					  &count_copy);
	if (val_hp != kernbuf) {
		if (!nrs_svc_has_hp(svc))
			return -ENODEV;

		queue |= PTLRPC_NRS_QUEUE_HP;
	}

	/**
	 * If none of the queues has been specified, there may be a valid
	 * command string at the start of the buffer.
	 */
	if (queue == 0) {
		queue = PTLRPC_NRS_QUEUE_REG;

		if (nrs_svc_has_hp(svc))
			queue |= PTLRPC_NRS_QUEUE_HP;
	}

	if ((queue & PTLRPC_NRS_QUEUE_REG) != 0) {
		supp_reg = nrs_orr_str2supp(val_reg);
		if (supp_reg == -EINVAL)
			return -EINVAL;
	}

	if ((queue & PTLRPC_NRS_QUEUE_HP) != 0) {
		supp_hp = nrs_orr_str2supp(val_hp);
		if (supp_hp == -EINVAL)
			return -EINVAL;
	}

	/**
	 * We change the values on regular and HP NRS heads separately, so that
	 * we do not exit early from ptlrpc_nrs_policy_control() with an error
	 * returned by nrs_policy_ctl_locked(), in cases where the user has not
	 * started the policy on either the regular or HP NRS head; i.e. we are
	 * ignoring -ENODEV within nrs_policy_ctl_locked(). -ENODEV is returned
	 * only if the operation fails with -ENODEV on all heads that have been
	 * specified by the command; if at least one operation succeeds,
	 * success is returned.
	 */
	if ((queue & PTLRPC_NRS_QUEUE_REG) != 0) {
		rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
					       orr_data->name,
					       NRS_CTL_ORR_WR_SUPP_REQ, false,
					       &supp_reg);
		if ((rc < 0 && rc != -ENODEV) ||
		    (rc == -ENODEV && queue == PTLRPC_NRS_QUEUE_REG))
			return rc;
	}

	if ((queue & PTLRPC_NRS_QUEUE_HP) != 0) {
		rc2 = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
						orr_data->name,
						NRS_CTL_ORR_WR_SUPP_REQ, false,
						&supp_hp);
		if ((rc2 < 0 && rc2 != -ENODEV) ||
		    (rc2 == -ENODEV && queue == PTLRPC_NRS_QUEUE_HP))
			return rc2;
	}

	return rc == -ENODEV && rc2 == -ENODEV ? -ENODEV : count;
}

LDEBUGFS_SEQ_FOPS(ptlrpc_lprocfs_nrs_orr_supported);

static int nrs_orr_lprocfs_init(struct ptlrpc_service *svc)
{
	int	i;

	struct ldebugfs_vars nrs_orr_lprocfs_vars[] = {
		{ .name		= "nrs_orr_quantum",
		  .fops		= &ptlrpc_lprocfs_nrs_orr_quantum_fops	},
		{ .name		= "nrs_orr_offset_type",
		  .fops		= &ptlrpc_lprocfs_nrs_orr_offset_type_fops },
		{ .name		= "nrs_orr_supported",
		  .fops		= &ptlrpc_lprocfs_nrs_orr_supported_fops },
		{ NULL }
	};

	if (!svc->srv_debugfs_entry)
		return 0;

	lprocfs_orr_data.svc = svc;

	for (i = 0; i < ARRAY_SIZE(nrs_orr_lprocfs_vars); i++)
		nrs_orr_lprocfs_vars[i].data = &lprocfs_orr_data;

	ldebugfs_add_vars(svc->srv_debugfs_entry, nrs_orr_lprocfs_vars, NULL);

	return 0;
}

static const struct ptlrpc_nrs_pol_ops nrs_orr_ops = {
	.op_policy_init		= nrs_orr_init,
	.op_policy_start	= nrs_orr_start,
	.op_policy_stop		= nrs_orr_stop,
	.op_policy_ctl		= nrs_orr_ctl,
	.op_res_get		= nrs_orr_res_get,
	.op_res_put		= nrs_orr_res_put,
	.op_req_get		= nrs_orr_req_get,
	.op_req_enqueue		= nrs_orr_req_add,
	.op_req_dequeue		= nrs_orr_req_del,
	.op_req_stop		= nrs_orr_req_stop,
	.op_lprocfs_init	= nrs_orr_lprocfs_init,
};

struct ptlrpc_nrs_pol_conf nrs_conf_orr = {
	.nc_name		= NRS_POL_NAME_ORR,
	.nc_ops			= &nrs_orr_ops,
	.nc_compat		= nrs_policy_compat_one,
	.nc_compat_svc_name	= "ost_io",
};

/**
 * TRR, Target-based Round Robin policy
 *
 * TRR reuses much of the functions and data structures of ORR
 */
static int nrs_trr_lprocfs_init(struct ptlrpc_service *svc)
{
	int	i;

	struct ldebugfs_vars nrs_trr_lprocfs_vars[] = {
		{ .name		= "nrs_trr_quantum",
		  .fops		= &ptlrpc_lprocfs_nrs_orr_quantum_fops },
		{ .name		= "nrs_trr_offset_type",
		  .fops		= &ptlrpc_lprocfs_nrs_orr_offset_type_fops },
		{ .name		= "nrs_trr_supported",
		  .fops		= &ptlrpc_lprocfs_nrs_orr_supported_fops },
		{ NULL }
	};

	if (!svc->srv_debugfs_entry)
		return 0;

	lprocfs_trr_data.svc = svc;

	for (i = 0; i < ARRAY_SIZE(nrs_trr_lprocfs_vars); i++)
		nrs_trr_lprocfs_vars[i].data = &lprocfs_trr_data;

	ldebugfs_add_vars(svc->srv_debugfs_entry, nrs_trr_lprocfs_vars, NULL);

	return 0;
}

/**
 * Reuse much of the ORR functionality for TRR.
 */
static const struct ptlrpc_nrs_pol_ops nrs_trr_ops = {
	.op_policy_init		= nrs_orr_init,
	.op_policy_start	= nrs_orr_start,
	.op_policy_stop		= nrs_orr_stop,
	.op_policy_ctl		= nrs_orr_ctl,
	.op_res_get		= nrs_orr_res_get,
	.op_res_put		= nrs_orr_res_put,
	.op_req_get		= nrs_orr_req_get,
	.op_req_enqueue		= nrs_orr_req_add,
	.op_req_dequeue		= nrs_orr_req_del,
	.op_req_stop		= nrs_orr_req_stop,
	.op_lprocfs_init	= nrs_trr_lprocfs_init,
};

struct ptlrpc_nrs_pol_conf nrs_conf_trr = {
	.nc_name		= NRS_POL_NAME_TRR,
	.nc_ops			= &nrs_trr_ops,
	.nc_compat		= nrs_policy_compat_one,
	.nc_compat_svc_name	= "ost_io",
};

/** @} ORR/TRR policy */

/** @} nrs */
