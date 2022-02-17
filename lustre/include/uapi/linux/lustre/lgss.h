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
 * Copyright (c) 2022, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LGSS_H
#define _LGSS_H

#include <linux/types.h>

/*
 * sparse kernel source annotations
 */
#ifndef __user
#define __user
#endif

struct lgssd_ioctl_param {
	/* in */
	__u32 version;
	__u32 secid;
	char __user *uuid;
	__u32 lustre_svc;
	__kernel_uid_t uid;
	__kernel_gid_t gid;
	__u64 send_token_size;
	char __user *send_token;
	__u64 reply_buf_size;
	char __user *reply_buf;
	/* out */
	__u64 status;
	__u64 reply_length;
};

#endif
