/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2014, Intel Corporation.
 *
 * Copyright 2012 Xyratex Technology Limited
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Network Request Scheduler (NRS) First-in First-out (FIFO) policy
 */

#ifndef _LUSTRE_NRS_FIFO_H
#define _LUSTRE_NRS_FIFO_H

/* \name fifo
 *
 * FIFO policy
 *
 * This policy is a logical wrapper around previous, non-NRS functionality.
 * It dispatches RPCs in the same order as they arrive from the network. This
 * policy is currently used as the fallback policy, and the only enabled policy
 * on all NRS heads of all PTLRPC service partitions.
 * @{
 */

/**
 * Private data structure for the FIFO policy
 */
struct nrs_fifo_head {
	/**
	 * Resource object for policy instance.
	 */
	struct ptlrpc_nrs_resource	fh_res;
	/**
	 * List of queued requests.
	 */
	struct list_head		fh_list;
	/**
	 * For debugging purposes.
	 */
	__u64				fh_sequence;
};

struct nrs_fifo_req {
	struct list_head	fr_list;
	__u64			fr_sequence;
};

/** @} fifo */
#endif
