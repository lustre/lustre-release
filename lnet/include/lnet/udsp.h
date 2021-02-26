/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2018-2020 Data Direct Networks.
 *
 *   This file is part of Lustre, https://wiki.whamcloud.com/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   version 2 along with this program; If not, see
 *   http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Author: Amir Shehata
 */

#ifndef UDSP_H
#define UDSP_H

#include <lnet/lib-lnet.h>

/**
 * lnet_udsp_add_policy
 *	Add a policy \new in position \idx
 *	Must be called with api_mutex held
 */
int lnet_udsp_add_policy(struct lnet_udsp *new, int idx);

/**
 * lnet_udsp_get_policy
 *	get a policy in position \idx
 *	Must be called with api_mutex held
 */
struct lnet_udsp *lnet_udsp_get_policy(int idx);

/**
 * lnet_udsp_del_policy
 *	Delete a policy from position \idx
 *	Must be called with api_mutex held
 */
int lnet_udsp_del_policy(int idx);

/**
 * lnet_udsp_apply_policies
 *	apply all stored policies across the system
 *	Must be called with api_mutex held
 *	Must NOT be called with lnet_net_lock held
 *	udsp: NULL to apply on all existing udsps
 *	      non-NULL to apply to specified udsp
 *	revert: true to revert policy application
 */
int lnet_udsp_apply_policies(struct lnet_udsp *udsp, bool revert);

/**
 * lnet_udsp_apply_policies_on_lpni
 *	apply all stored policies on specified \lpni
 *	Must be called with api_mutex held
 *	Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_lpni(struct lnet_peer_ni *lpni);

/**
 * lnet_udsp_apply_policies_on_lpn
 *	Must be called with api_mutex held
 *	apply all stored policies on specified \lpn
 *	Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_lpn(struct lnet_peer_net *lpn);

/**
 * lnet_udsp_apply_policies_on_ni
 *	apply all stored policies on specified \ni
 *	Must be called with api_mutex held
 *	Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_ni(struct lnet_ni *ni);

/**
 * lnet_udsp_apply_policies_on_net
 *	apply all stored policies on specified \net
 *	Must be called with api_mutex held
 *	Must be called with LNET_LOCK_EX
 */
int lnet_udsp_apply_policies_on_net(struct lnet_net *net);

/**
 * lnet_udsp_alloc
 *	Allocates a UDSP block and initializes it.
 *	Return NULL if allocation fails
 *	pointer to UDSP otherwise.
 */
struct lnet_udsp *lnet_udsp_alloc(void);

/**
 * lnet_udsp_free
 *	Free a UDSP and all its descriptors
 */
void lnet_udsp_free(struct lnet_udsp *udsp);

/**
 * lnet_udsp_destroy
 *	Free all the UDSPs
 *	force: true to indicate shutdown in progress
 */
void lnet_udsp_destroy(bool shutdown);

/**
 * lnet_get_udsp_size
 *	Return the size needed to store the marshalled UDSP
 */
size_t lnet_get_udsp_size(struct lnet_udsp *udsp);

/**
 * lnet_udsp_marshal
 *	Marshal the udsp into the bulk memory provided.
 *	Return success/failure.
 */
int lnet_udsp_marshal(struct lnet_udsp *udsp,
		      struct lnet_ioctl_udsp *ioc_udsp);
/**
 * lnet_udsp_demarshal_add
 *	Given a bulk containing a single UDSP,
 *	demarshal and populate a udsp structure then add policy
 */
int lnet_udsp_demarshal_add(void *bulk, __u32 bulk_size);

/**
 * lnet_udsp_get_construct_info
 *	get information of how the UDSP policies impacted the given
 *	construct.
 */
void lnet_udsp_get_construct_info(struct lnet_ioctl_construct_udsp_info *info);

#endif /* UDSP_H */
