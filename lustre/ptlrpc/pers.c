// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include <lustre_ha.h>
#include <lustre_import.h>

#include "ptlrpc_internal.h"


void ptlrpc_fill_bulk_md(struct lnet_md *md, struct ptlrpc_bulk_desc *desc,
			 int mdidx)
{
	unsigned int start;

	BUILD_BUG_ON(PTLRPC_MAX_BRW_PAGES >= LI_POISON);

	LASSERTF(mdidx < desc->bd_md_max_brw, "%d < max: %d\n",
		 mdidx, desc->bd_md_max_brw);
	LASSERT(desc->bd_iov_count <= PTLRPC_MAX_BRW_PAGES);

	/* just send a lnet header */
	if (mdidx >= desc->bd_md_count) {
		md->umd_options |= LNET_MD_KIOV;
		md->umd_length = 0;
		md->umd_start = NULL;
		return;
	}

	if (desc->bd_is_rdma)
		md->umd_options |= LNET_MD_GPU_ADDR;

	start = desc->bd_mds_off[mdidx];
	if (mdidx == (desc->bd_md_count - 1))
		md->umd_length = desc->bd_iov_count - start;
	else
		md->umd_length = desc->bd_mds_off[mdidx + 1] - start;

	md->umd_options |= LNET_MD_KIOV;
	if (desc->bd_enc_vec)
		md->umd_start = &desc->bd_enc_vec[start];
	else
		md->umd_start = &desc->bd_vec[start];
}


