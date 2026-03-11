/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_ACL_H
#define _LUSTRE_ACL_H

#include <linux/fs.h>
#include <linux/dcache.h>
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
#include <linux/posix_acl_xattr.h>

#define LUSTRE_POSIX_ACL_MAX_ENTRIES	32
#define LUSTRE_POSIX_ACL_MAX_SIZE_OLD					\
	(sizeof(struct posix_acl_xattr_header) +			\
	 LUSTRE_POSIX_ACL_MAX_ENTRIES * sizeof(struct posix_acl_xattr_entry))

#else /* ! CONFIG_LUSTRE_FS_POSIX_ACL */
#define LUSTRE_POSIX_ACL_MAX_SIZE_OLD 0
#endif /* CONFIG_LUSTRE_FS_POSIX_ACL */

#endif
