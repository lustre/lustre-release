/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/*
 * Copyright (c) 2017, Intel Corporation.
 */

/*
 * Lustre write barrier (on MDT) userspace interfaces.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _LUSTRE_BARRIER_USER_H
# define _LUSTRE_BARRIER_USER_H

#include <linux/types.h>
#include <linux/lustre/lustre_user.h>

#define BARRIER_VERSION_V1	1
#define BARRIER_TIMEOUT_DEFAULT	30

enum barrier_commands {
	BC_FREEZE	= 1,
	BC_THAW		= 2,
	BC_STAT		= 3,
	BC_RESCAN	= 4,
};

enum barrier_status {
	BS_INIT		= 0,
	BS_FREEZING_P1	= 1,
	BS_FREEZING_P2	= 2,
	BS_FROZEN	= 3,
	BS_THAWING	= 4,
	BS_THAWED	= 5,
	BS_FAILED	= 6,
	BS_EXPIRED	= 7,
	BS_RESCAN	= 8,
};

struct barrier_ctl {
	__u32	bc_version;
	__u32	bc_cmd;
	union {
		__s32	bc_timeout;
		__u32	bc_total;
	};
	union {
		__u32	bc_status;
		__u32	bc_absence;
	};
	char	bc_name[12];
	__u32	bc_padding;
};

#endif /* _LUSTRE_BARRIER_USER_H */
