/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Intel Corporation.
 *
 * lustre/include/lustre/lustre_barrier_user.h
 *
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
