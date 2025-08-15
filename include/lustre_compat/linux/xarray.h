/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _LINUX_XARRAY_LUSTRE_H
#define _LINUX_XARRAY_LUSTRE_H
/*
 * eXtensible Arrays
 * Copyright (c) 2017 Microsoft Corporation
 * Author: Matthew Wilcox <willy@infradead.org>
 *
 * This is taken from kernel commit:
 *
 * 7b785645e ("mm: fix page cache convergence regression")
 *
 * at kernel verison 5.2-rc2
 *
 * See Documentation/core-api/xarray.rst for how to use the XArray.
 */
#include <linux/xarray.h>

/* Linux kernel version v5.0 commit fd9dc93e36231fb6d520e0edd467058fad4fd12d
 * ("XArray: Change xa_insert to return -EBUSY")
 * instead of -EEXIST
 */
static inline int __must_check ll_xa_insert(struct xarray *xa,
					    unsigned long index,
					    void *entry, gfp_t gpf)
{
	int rc = xa_insert(xa, index, entry, gpf);

	if (rc == -EEXIST)
		rc = -EBUSY;
	return rc;
}

#endif /* _LINUX_XARRAY_LUSTRE_H */
