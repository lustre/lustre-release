/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
#include <errno.h>
#include <signal.h>
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_import.h>

#include "ptlrpc_internal.h"

#ifdef __KERNEL__
#ifndef CRAY_PORTALS
void pers_bulk_add_page(struct ptlrpc_bulk_desc *desc, struct page *page,
                        int pageoffset, int len)
{
        ptl_kiov_t *kiov = &desc->bd_iov[desc->bd_iov_count];

        kiov->kiov_page = page;
        kiov->kiov_offset = pageoffset;
        kiov->kiov_len = len;

        desc->bd_iov_count++;
}
#else
void pers_bulk_add_page(struct ptlrpc_bulk_desc *desc, struct page *page,
                        int pageoffset, int len)
{
        struct iovec *iov = &desc->bd_iov[desc->bd_iov_count];

        /* Should get a compiler warning if sizeof(physaddr) > sizeof(void *) */
        iov->iov_base = (void *)(page_to_phys(page) + pageoffset);
        iov->iov_len = len;

        desc->bd_iov_count++;
}
#endif

#else /* !__KERNEL__ */

int can_merge_iovs(struct iovec *existing, struct iovec *candidate)
{
        if (existing->iov_base + existing->iov_len == candidate->iov_base)
                return 1;
        return 0;
}
void pers_bulk_add_page(struct ptlrpc_bulk_desc *desc, struct page *page, 
                        int pageoffset, int len)
{
        struct iovec *iov = &desc->bd_iov[desc->bd_iov_count];

        iov->iov_base = page->addr + pageoffset;
        iov->iov_len = len;

        if (desc->bd_iov_count > 0 && can_merge_iovs(iov - 1, iov)) {
                (iov - 1)->iov_len += len;
        } else {
                desc->bd_iov_count++;
        }
}
#endif
