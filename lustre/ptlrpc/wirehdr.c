// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
# include <linux/fs.h>
# include <linux/posix_acl_xattr.h>
#endif /* CONFIG_LUSTRE_FS_POSIX_ACL */

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_access_log.h>
#include <uapi/linux/lustre/lustre_lfsck_user.h>
#include <uapi/linux/lustre/lustre_cfg.h>
#include <uapi/linux/lustre/lgss.h>

#include "ptlrpc_internal.h"
