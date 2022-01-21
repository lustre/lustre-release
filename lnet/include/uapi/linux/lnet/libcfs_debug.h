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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/include/libcfs/libcfs_debug.h
 *
 * Debug messages and assertions
 *
 */

#ifndef __UAPI_LIBCFS_DEBUG_H__
#define __UAPI_LIBCFS_DEBUG_H__

#include <linux/types.h>

/**
 * Format for debug message headers
 */
struct ptldebug_header {
	__u32 ph_len;
	__u32 ph_flags;
	__u32 ph_subsys;
	__u32 ph_mask;
	__u16 ph_cpu_id;
	__u16 ph_type;
	/* time_t overflow in 2106 */
	__u32 ph_sec;
	__u64 ph_usec;
	__u32 ph_stack;
	__u32 ph_pid;
	__u32 ph_extern_pid;
	__u32 ph_line_num;
} __attribute__((packed));

#define PH_FLAG_FIRST_RECORD	1

/* Debugging subsystems (32 bits, non-overlapping) */
enum libcfs_debug_subsys {
	S_UNDEFINED	= 0x00000001,
	S_MDC		= 0x00000002,
	S_MDS		= 0x00000004,
	S_OSC		= 0x00000008,
	S_OST		= 0x00000010,
	S_CLASS		= 0x00000020,
	S_LOG		= 0x00000040,
	S_LLITE		= 0x00000080,
	S_RPC		= 0x00000100,
	S_MGMT		= 0x00000200,
	S_LNET		= 0x00000400,
	S_LND		= 0x00000800, /* ALL LNDs */
	S_PINGER	= 0x00001000,
	S_FILTER	= 0x00002000,
	S_LIBCFS	= 0x00004000,
	S_ECHO		= 0x00008000,
	S_LDLM		= 0x00010000,
	S_LOV		= 0x00020000,
	S_LQUOTA	= 0x00040000,
	S_OSD		= 0x00080000,
	S_LFSCK		= 0x00100000,
	S_SNAPSHOT	= 0x00200000,
/* unused */
	S_LMV		= 0x00800000,
/* unused */
	S_SEC		= 0x02000000, /* upcall cache */
	S_GSS		= 0x04000000,
/* unused */
	S_MGC		= 0x10000000,
	S_MGS		= 0x20000000,
	S_FID		= 0x40000000,
	S_FLD		= 0x80000000,
};
#define LIBCFS_S_DEFAULT (~0)

#define LIBCFS_DEBUG_SUBSYS_NAMES {					\
	"undefined", "mdc", "mds", "osc", "ost", "class", "log",	\
	"llite", "rpc", "mgmt", "lnet", "lnd", "pinger", "filter",	\
	"libcfs", "echo", "ldlm", "lov", "lquota", "osd", "lfsck",	\
	"snapshot", "", "lmv", "", "sec", "gss", "", "mgc", "mgs",	\
	"fid", "fld", NULL }

/* Debugging masks (32 bits, non-overlapping) */
enum libcfs_debug_masks {
	D_TRACE		= 0x00000001, /* ENTRY/EXIT markers */
	D_INODE		= 0x00000002,
	D_SUPER		= 0x00000004,
	D_IOTRACE	= 0x00000008, /* simple, low overhead io tracing */
	D_MALLOC	= 0x00000010, /* print malloc, free information */
	D_CACHE		= 0x00000020, /* cache-related items */
	D_INFO		= 0x00000040, /* general information */
	D_IOCTL		= 0x00000080, /* ioctl related information */
	D_NETERROR	= 0x00000100, /* network errors */
	D_NET		= 0x00000200, /* network communications */
	D_WARNING	= 0x00000400, /* CWARN(...) == CDEBUG(D_WARNING, ...) */
	D_BUFFS		= 0x00000800,
	D_OTHER		= 0x00001000,
	D_DENTRY	= 0x00002000,
	D_NETTRACE	= 0x00004000,
	D_PAGE		= 0x00008000, /* bulk page handling */
	D_DLMTRACE	= 0x00010000,
	D_ERROR		= 0x00020000, /* CERROR(...) == CDEBUG(D_ERROR, ...) */
	D_EMERG		= 0x00040000, /* CEMERG(...) == CDEBUG(D_EMERG, ...) */
	D_HA		= 0x00080000, /* recovery and failover */
	D_RPCTRACE	= 0x00100000, /* for distributed debugging */
	D_VFSTRACE	= 0x00200000,
	D_READA		= 0x00400000, /* read-ahead */
	D_MMAP		= 0x00800000,
	D_CONFIG	= 0x01000000,
	D_CONSOLE	= 0x02000000,
	D_QUOTA		= 0x04000000,
	D_SEC		= 0x08000000,
	D_LFSCK		= 0x10000000, /* For both OI scrub and LFSCK */
	D_HSM		= 0x20000000,
	D_SNAPSHOT	= 0x40000000,
	D_LAYOUT	= 0x80000000,
};
#define LIBCFS_D_DEFAULT (D_CANTMASK | D_NETERROR | D_HA | D_CONFIG | D_IOCTL |\
			  D_LFSCK)

#define LIBCFS_DEBUG_MASKS_NAMES {					\
	"trace", "inode", "super", "iotrace", "malloc", "cache", "info",\
	"ioctl", "neterror", "net", "warning", "buffs", "other",	\
	"dentry", "nettrace", "page", "dlmtrace", "error", "emerg",	\
	"ha", "rpctrace", "vfstrace", "reada", "mmap", "config",	\
	"console", "quota", "sec", "lfsck", "hsm", "snapshot", "layout",\
	NULL }

#define D_CANTMASK   (D_ERROR | D_EMERG | D_WARNING | D_CONSOLE)

#define LIBCFS_DEBUG_FILE_PATH_DEFAULT "/tmp/lustre-log"

#endif	/* __UAPI_LIBCFS_DEBUG_H__ */
