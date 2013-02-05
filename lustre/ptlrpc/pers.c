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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
#include <errno.h>
#include <signal.h>
#include <liblustre.h>
#endif

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include <lustre_ha.h>
#include <lustre_import.h>

#include "ptlrpc_internal.h"

#ifdef __KERNEL__

void ptlrpc_fill_bulk_md(lnet_md_t *md, struct ptlrpc_bulk_desc *desc,
			 int mdidx)
{
	CLASSERT(PTLRPC_MAX_BRW_PAGES < LI_POISON);

	LASSERT(mdidx < desc->bd_md_max_brw);
	LASSERT(desc->bd_iov_count <= PTLRPC_MAX_BRW_PAGES);
	LASSERT(!(md->options & (LNET_MD_IOVEC | LNET_MD_KIOV |
				 LNET_MD_PHYS)));

	md->options |= LNET_MD_KIOV;
	md->length = max(0, desc->bd_iov_count - mdidx * LNET_MAX_IOV);
	md->length = min_t(unsigned int, LNET_MAX_IOV, md->length);
	if (desc->bd_enc_iov)
		md->start = &desc->bd_enc_iov[mdidx * LNET_MAX_IOV];
	else
		md->start = &desc->bd_iov[mdidx * LNET_MAX_IOV];
}

void ptlrpc_add_bulk_page(struct ptlrpc_bulk_desc *desc, cfs_page_t *page,
                          int pageoffset, int len)
{
        lnet_kiov_t *kiov = &desc->bd_iov[desc->bd_iov_count];

        kiov->kiov_page = page;
        kiov->kiov_offset = pageoffset;
        kiov->kiov_len = len;

        desc->bd_iov_count++;
}

#else /* !__KERNEL__ */

void ptlrpc_fill_bulk_md(lnet_md_t *md, struct ptlrpc_bulk_desc *desc,
			 int mdidx)
{
	LASSERT(mdidx < desc->bd_md_max_brw);
	LASSERT(desc->bd_iov_count > mdidx * LNET_MAX_IOV);
	LASSERT(!(md->options & (LNET_MD_IOVEC | LNET_MD_KIOV | LNET_MD_PHYS)));

	if (desc->bd_iov_count == 1) {
		md->start = desc->bd_iov[0].iov_base;
		md->length = desc->bd_iov[0].iov_len;
		return;
	}

	md->options |= LNET_MD_IOVEC;
	md->start = &desc->bd_iov[mdidx * LNET_MAX_IOV];
	md->length = min(LNET_MAX_IOV, desc->bd_iov_count - mdidx *
				       LNET_MAX_IOV);
}

static int can_merge_iovs(lnet_md_iovec_t *existing, lnet_md_iovec_t *candidate)
{
        if (existing->iov_base + existing->iov_len == candidate->iov_base)
                return 1;
#if 0
        /* Enable this section to provide earlier evidence of fragmented bulk */
        CERROR("Can't merge iovs %p for %x, %p for %x\n",
               existing->iov_base, existing->iov_len,
               candidate->iov_base, candidate->iov_len);
#endif
        return 0;
}

void ptlrpc_add_bulk_page(struct ptlrpc_bulk_desc *desc, cfs_page_t *page,
                          int pageoffset, int len)
{
        lnet_md_iovec_t *iov = &desc->bd_iov[desc->bd_iov_count];

        iov->iov_base = page->addr + pageoffset;
        iov->iov_len = len;

        if (desc->bd_iov_count > 0 && can_merge_iovs(iov - 1, iov)) {
                (iov - 1)->iov_len += len;
        } else {
                desc->bd_iov_count++;
        }
}

#endif /* !__KERNEL__ */
