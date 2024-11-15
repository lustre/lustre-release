/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MDC_H
#define _LUSTRE_MDC_H

/** \defgroup mdc mdc
 *
 * @{
 */

#include <linux/fs.h>
#include <linux/dcache.h>
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
# include <lustre_compat.h>
#endif /* CONFIG_LUSTRE_FS_POSIX_ACL */
#include <lustre_handles.h>
#include <lustre_intent.h>
#include <libcfs/libcfs.h>
#include <obd_class.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_export.h>

struct ptlrpc_client;
struct obd_export;
struct ptlrpc_request;
struct obd_device;

/**
 * Update the maximum possible easize.
 *
 * This value is learned from ptlrpc replies sent by the MDT.  The
 * default easize is initialized to the minimum value but allowed to
 * grow up to a single page in size if required to handle the common
 * case.
 *
 * \see client_obd::cl_default_mds_easize
 *
 * \param[in] exp	export for MDC device
 * \param[in] body	body of ptlrpc reply from MDT
 *
 */
static inline void mdc_update_max_ea_from_body(struct obd_export *exp,
					       struct mdt_body *body)
{
	if (body->mbo_valid & OBD_MD_FLMODEASIZE) {
		struct client_obd *cli = &exp->exp_obd->u.cli;
		__u32 def_easize;

		if (cli->cl_max_mds_easize < body->mbo_max_mdsize)
			cli->cl_max_mds_easize = body->mbo_max_mdsize;

		def_easize = min_t(__u32, body->mbo_max_mdsize,
				   OBD_MAX_DEFAULT_EA_SIZE);
		cli->cl_default_mds_easize = def_easize;
	}
}


/* mdc/mdc_locks.c */
int it_open_error(int phase, struct lookup_intent *it);

static inline bool cl_is_lov_delay_create(enum mds_open_flags flags)
{
	return (flags & O_LOV_DELAY_CREATE) == O_LOV_DELAY_CREATE;
}

static inline void cl_lov_delay_create_clear(unsigned int *flags)
{
	if ((*flags & O_LOV_DELAY_CREATE) == O_LOV_DELAY_CREATE)
		*flags &= ~O_LOV_DELAY_CREATE;
}

static inline unsigned long hash_x_index(__u64 hash, int hash64)
{
	if (BITS_PER_LONG == 32 && hash64)
		hash >>= 32;
	/* save hash 0 with hash 1 */
	return ~0UL - (hash + !hash);
}


/** @} mdc */

#endif
