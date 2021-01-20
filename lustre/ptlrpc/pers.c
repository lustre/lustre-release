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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
	unsigned int start = desc->bd_mds_off[mdidx];

	CLASSERT(PTLRPC_MAX_BRW_PAGES < LI_POISON);

	LASSERT(mdidx < desc->bd_md_max_brw);
	LASSERT(desc->bd_iov_count <= PTLRPC_MAX_BRW_PAGES);
	LASSERT(!(md->options & (LNET_MD_IOVEC | LNET_MD_KIOV |
				 LNET_MD_PHYS)));

	/* just send a lnet header */
	if (mdidx >= desc->bd_md_count) {
		if (ptlrpc_is_bulk_desc_kiov(desc->bd_type))
			md->options |= LNET_MD_KIOV;
		else if (ptlrpc_is_bulk_desc_kvec(desc->bd_type))
			md->options |= LNET_MD_IOVEC;
		md->length = 0;
		md->start = NULL;
		return;
	}

	if (mdidx == (desc->bd_md_count - 1))
		md->length = desc->bd_iov_count - start;
	else
		md->length = desc->bd_mds_off[mdidx + 1] - start;

	if (ptlrpc_is_bulk_desc_kiov(desc->bd_type)) {
		md->options |= LNET_MD_KIOV;
		if (GET_ENC_KIOV(desc))
			md->start = &BD_GET_ENC_KIOV(desc, start);
		else
			md->start = &BD_GET_KIOV(desc, start);
	} else if (ptlrpc_is_bulk_desc_kvec(desc->bd_type)) {
		md->options |= LNET_MD_IOVEC;
		if (GET_ENC_KVEC(desc))
			md->start = &BD_GET_ENC_KVEC(desc, start);
		else
			md->start = &BD_GET_KVEC(desc, start);
	}
}


