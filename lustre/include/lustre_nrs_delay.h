/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2015, Cray Inc. All Rights Reserved.
 *
 * Copyright (c) 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Network Request Scheduler (NRS) Delay policy
 */

#ifndef _LUSTRE_NRS_DELAY_H
#define _LUSTRE_NRS_DELAY_H

/* \name delay
 *
 * Delay policy
 * @{
 */

/**
 * Private data structure for the delay policy
 */
struct nrs_delay_data {
	struct ptlrpc_nrs_resource	 delay_res;

	/**
	 * Delayed requests are stored in this binheap until they are
	 * removed for handling.
	 */
	struct binheap		*delay_binheap;

	/**
	 * Minimum service time
	 */
	__u32				 min_delay;

	/**
	 * Maximum service time
	 */
	__u32				 max_delay;

	/**
	 * We'll delay this percent of requests
	 */
	__u32				 delay_pct;
};

struct nrs_delay_req {
	/**
	 * This is the time at which a request becomes eligible for handling
	 */
	time64_t	req_start_time;
};

#define NRS_CTL_DELAY_RD_MIN PTLRPC_NRS_CTL_POL_SPEC_01
#define NRS_CTL_DELAY_WR_MIN PTLRPC_NRS_CTL_POL_SPEC_02
#define NRS_CTL_DELAY_RD_MAX PTLRPC_NRS_CTL_POL_SPEC_03
#define NRS_CTL_DELAY_WR_MAX PTLRPC_NRS_CTL_POL_SPEC_04
#define NRS_CTL_DELAY_RD_PCT PTLRPC_NRS_CTL_POL_SPEC_05
#define NRS_CTL_DELAY_WR_PCT PTLRPC_NRS_CTL_POL_SPEC_06

/** @} delay */

#endif
