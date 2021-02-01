/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2014, Intel Corporation.
 *
 * Copyright 2012 Xyratex Technology Limited
 */
/*
 *
 * Network Request Scheduler (NRS) Object-based Round Robin and Target-based
 * Round Robin (ORR and TRR) policies
 *
 */

#ifndef _LUSTRE_NRS_ORR_H
#define _LUSTRE_NRS_ORR_H

/**
 * ORR policy operations
 */
enum nrs_ctl_orr {
	NRS_CTL_ORR_RD_QUANTUM = PTLRPC_NRS_CTL_1ST_POL_SPEC,
	NRS_CTL_ORR_WR_QUANTUM,
	NRS_CTL_ORR_RD_OFF_TYPE,
	NRS_CTL_ORR_WR_OFF_TYPE,
	NRS_CTL_ORR_RD_SUPP_REQ,
	NRS_CTL_ORR_WR_SUPP_REQ,
};

/**
 * \name ORR/TRR
 *
 * ORR/TRR (Object-based Round Robin/Target-based Round Robin) NRS policies
 * @{
 */

/**
 * Lower and upper byte offsets of a brw RPC
 */
struct nrs_orr_req_range {
	__u64		or_start;
	__u64		or_end;
};

/**
 * RPC types supported by the ORR/TRR policies
 */
enum nrs_orr_supp {
	NOS_OST_READ	= BIT(0),
	NOS_OST_WRITE	= BIT(1),
	NOS_OST_RW	= (NOS_OST_READ | NOS_OST_WRITE),
	/**
	 * Default value for policies.
	 */
	NOS_DFLT	= NOS_OST_READ
};

/**
 * As unique keys for grouping RPCs together, we use the object's OST FID for
 * the ORR policy, and the OST index for the TRR policy.
 *
 * XXX: We waste some space for TRR policy instances by using a union, but it
 *	allows to consolidate some of the code between ORR and TRR, and these
 *	policies will probably eventually merge into one anyway.
 */
struct nrs_orr_key {
	union {
		/** object FID for ORR */
		struct lu_fid	ok_fid;
		/** OST index for TRR */
		__u32		ok_idx;
	};
};

/**
 * The largest base string for unique hash/slab object names is
 * "nrs_orr_reg_", so 13 characters. We add 3 to this to be used for the CPT
 * id number, so this _should_ be more than enough for the maximum number of
 * CPTs on any system. If it does happen that this statement is incorrect,
 * nrs_orr_genobjname() will inevitably yield a non-unique name and cause
 * kmem_cache_create() to complain (on Linux), so the erroneous situation
 * will hopefully not go unnoticed.
 */
#define NRS_ORR_OBJ_NAME_MAX	(sizeof("nrs_orr_reg_") + 3)

/**
 * private data structure for ORR and TRR NRS
 */
struct nrs_orr_data {
	struct ptlrpc_nrs_resource	od_res;
	struct binheap	       *od_binheap;
	struct cfs_hash		       *od_obj_hash;
	struct kmem_cache	       *od_cache;
	/**
	 * Used when a new scheduling round commences, in order to synchronize
	 * all object or OST batches with the new round number.
	 */
	__u64				od_round;
	/**
	 * Determines the relevant ordering amongst request batches within a
	 * scheduling round.
	 */
	__u64				od_sequence;
	/**
	 * RPC types that are currently supported.
	 */
	enum nrs_orr_supp		od_supp;
	/**
	 * Round Robin quantum; the maxium number of RPCs that each request
	 * batch for each object or OST can have in a scheduling round.
	 */
	__u16				od_quantum;
	/**
	 * Whether to use physical disk offsets or logical file offsets.
	 */
	bool				od_physical;
	/**
	 * XXX: We need to provide a persistently allocated string to hold
	 * unique object names for this policy, since in currently supported
	 * versions of Linux by Lustre, kmem_cache_create() just sets a pointer
	 * to the name string provided. kstrdup() is used in the version of
	 * kmeme_cache_create() in current Linux mainline, so we may be able to
	 * remove this in the future.
	 */
	char				od_objname[NRS_ORR_OBJ_NAME_MAX];
};

/**
 * Represents a backend-fs object or OST in the ORR and TRR policies
 * respectively
 */
struct nrs_orr_object {
	struct ptlrpc_nrs_resource	oo_res;
	struct hlist_node		oo_hnode;
	/**
	 * The round number against which requests are being scheduled for this
	 * object or OST
	 */
	__u64				oo_round;
	/**
	 * The sequence number used for requests scheduled for this object or
	 * OST during the current round number.
	 */
	__u64				oo_sequence;
	/**
	 * The key of the object or OST for which this structure instance is
	 * scheduling RPCs
	 */
	struct nrs_orr_key		oo_key;
	long				oo_ref;
	/**
	 * Round Robin quantum; the maximum number of RPCs that are allowed to
	 * be scheduled for the object or OST in a single batch of each round.
	 */
	__u16				oo_quantum;
	/**
	 * # of pending requests for this object or OST, on all existing rounds
	 */
	__u16				oo_active;
};

/**
 * ORR/TRR NRS request definition
 */
struct nrs_orr_req {
	/**
	 * The offset range this request covers
	 */
	struct nrs_orr_req_range	or_range;
	/**
	 * Round number for this request; shared with all other requests in the
	 * same batch.
	 */
	__u64				or_round;
	/**
	 * Sequence number for this request; shared with all other requests in
	 * the same batch.
	 */
	__u64				or_sequence;
	/**
	 * For debugging purposes.
	 */
	struct nrs_orr_key		or_key;
	/**
	 * An ORR policy instance has filled in request information while
	 * enqueueing the request on the service partition's regular NRS head.
	 */
	unsigned int			or_orr_set:1;
	/**
	 * A TRR policy instance has filled in request information while
	 * enqueueing the request on the service partition's regular NRS head.
	 */
	unsigned int			or_trr_set:1;
	/**
	 * Request offset ranges have been filled in with logical offset
	 * values.
	 */
	unsigned int			or_logical_set:1;
	/**
	 * Request offset ranges have been filled in with physical offset
	 * values.
	 */
	unsigned int			or_physical_set:1;
};

/** @} ORR/TRR */
#endif
