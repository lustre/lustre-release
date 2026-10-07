/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_COMPAT_H
#define _LUSTRE_COMPAT_H

#include <linux/aio.h>
#include <lustre_compat/linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/posix_acl_xattr.h>
#include <linux/bio.h>
#include <linux/xattr.h>
#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <lustre_compat/linux/folio_batch.h>
#include <linux/workqueue.h>
#include <lustre_compat/linux/shrinker.h>
#include <lustre_compat/linux/xarray.h>
#include <lustre_compat/linux/folio.h>
#include <lustre_compat/linux/blkdev.h>
#include <lustre_compat/linux/posix_acl_xattr.h>
#include <obd_support.h>

#ifndef HAVE_IOV_ITER_IOVEC
static inline struct iovec iov_iter_iovec(const struct iov_iter *iter)
{
	return (struct iovec) {
		.iov_base = iter->__iov->iov_base + iter->iov_offset,
		.iov_len = min(iter->count,
			       iter->__iov->iov_len - iter->iov_offset),
	};
}
#endif

#ifdef HAVE_AOPS_MIGRATE_FOLIO
#define folio_migr	folio
#else
#define folio_migr	page
#define migrate_folio	migratepage
#endif

#ifdef HAVE_IS_PCI_P2PDMA_PAGE
#include <linux/pci-p2pdma.h>
#endif

static inline bool lustre_is_p2prdma_page(struct page *page)
{
#ifdef HAVE_IS_PCI_P2PDMA_PAGE
	return is_pci_p2pdma_page(page);
#else
	return false;
#endif
}

#endif /* _LUSTRE_COMPAT_H */
