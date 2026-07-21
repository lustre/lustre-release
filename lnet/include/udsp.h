// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2018-2020 Data Direct Networks.
 */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Amir Shehata
 */

#ifndef UDSP_H
#define UDSP_H

#include <linux/lnet/lib-lnet.h>

/**
 * lnet_udsp_add_policy() - Add LNET UDSP policy to the policy list
 * @new: LNET UDSP policy to add
 * @idx: index to insert the policy
 *
 * Note: Must be called with api_mutex held
 */
int lnet_udsp_add_policy(struct lnet_udsp *new, int idx);

/**
 * lnet_udsp_get_policy() - Retrieve LNET UDSP policy at @idx
 * @idx: return LNET UDSP policy of this index
 *
 * Note: Must be called with api_mutex held
 */
struct lnet_udsp *lnet_udsp_get_policy(int idx);

/**
 * lnet_udsp_del_policy() - Delete LNET UDSP policy at the given @idx
 * @idx: Delete a policy from position @idx
 *
 * Must be called with api_mutex held
 */
int lnet_udsp_del_policy(int idx);

/**
 * lnet_udsp_apply_policies() - Apply/revert LNET UDSP policy (across system)
 * @udsp: UDSP to apply, or NULL to apply all existing UDSPs
 * @revert: true to revert policy application
 *
 * Apply all stored policies across the system.
 * Must be called with api_mutex held
 * Must NOT be called with lnet_net_lock held
 */
int lnet_udsp_apply_policies(struct lnet_udsp *udsp, bool revert);

/**
 * lnet_udsp_apply_policies_on_lpni() - Apply UDSP rules on specified LPNI
 * @lpni: peer NI to apply policies on
 *
 * Must be called with api_mutex held
 * Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_lpni(struct lnet_peer_ni *lpni);

/**
 * lnet_udsp_apply_policies_on_lpn() - Apply UDSP rules on specified LPN
 * @lpn: peer net to apply policies on
 *
 * Must be called with api_mutex held
 * Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_lpn(struct lnet_peer_net *lpn);

/**
 * lnet_udsp_apply_policies_on_ni() - apply stored policies on specified @ni
 * @ni: network interface structure to apply policy on
 *
 * Must be called with api_mutex held
 * Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_ni(struct lnet_ni *ni);

/**
 * lnet_udsp_apply_policies_on_net() - apply stored policies on specified @net
 * @net: Lnet to apply policy on
 *
 * Must be called with api_mutex held
 * Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_net(struct lnet_net *net);

/**
 * lnet_udsp_alloc() - Allocates a UDSP block and initializes it.
 *
 * Return %NULL if allocation fails else pointer to UDSP otherwise.
 */
struct lnet_udsp *lnet_udsp_alloc(void);

/**
 * lnet_udsp_free() - Free a UDSP and all its descriptors
 * @udsp: LNET UDSP policy to free
 */
void lnet_udsp_free(struct lnet_udsp *udsp);

/**
 * lnet_udsp_destroy() - Free all the UDSPs
 * @shutdown: true to indicate shutdown in progress
 */
void lnet_udsp_destroy(bool shutdown);

/**
 * lnet_get_udsp_size() - Return the size needed to store the marshalled UDSP
 * @udsp: LNET UDSP policy to get size
 */
size_t lnet_get_udsp_size(struct lnet_udsp *udsp);

/**
 * lnet_udsp_marshal() - Marshal the UDSP into the bulk memory provided.
 * @udsp: LNET UDSP policy to marshal
 * @ioc_udsp: UDSP descriptor
 */
int lnet_udsp_marshal(struct lnet_udsp *udsp,
		      struct lnet_ioctl_udsp *ioc_udsp);
/**
 * lnet_udsp_demarshal_add() - demarshal & fill UDSP structure then add policy
 *			       containing a single UDSP
 * @bulk: UDSP descriptor
 * @bulk_size: Bulk size
 */
int lnet_udsp_demarshal_add(void *bulk, __u32 bulk_size);

/**
 * lnet_udsp_get_construct_info() - get information of how the UDSP policies
 *				    impacted the given construct.
 * @info: UDSP instantiation information
 * @nid: NID
 */
void lnet_udsp_get_construct_info(struct lnet_ioctl_construct_udsp_info *info,
				  struct lnet_nid *nid);

#endif /* UDSP_H */
