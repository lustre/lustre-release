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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * lustre/include/lustre/lustre_lfsck_user.h
 *
 * Lustre LFSCK userspace interfaces.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _LUSTRE_LFSCK_USER_H
# define _LUSTRE_LFSCK_USER_H
# include <lustre/lustre_user.h>

/**
 * state machine:
 *
 *					LS_INIT
 *					   |
 *				     (lfsck|start)
 *					   |
 *					   v
 *				   LS_SCANNING_PHASE1
 *					|	^
 *					|	:
 *					| (lfsck:restart)
 *					|	:
 *					v	:
 *	-----------------------------------------------------------------
 *	|		    |^		|^	   |^	      |^	|^
 *	|		    |:		|:	   |:	      |:	|:
 *	v		    v:		v:	   v:	      v:	v:
 * LS_SCANNING_PHASE2	LS_FAILED  LS_STOPPED  LS_PAUSED LS_CRASHED LS_PARTIAL
 *			  (CO_)       (CO_)	 (CO_)
 *	|	^	    ^:		^:	   ^:	      ^:	^:
 *	|	:	    |:		|:	   |:	      |:	|:
 *	| (lfsck:restart)   |:		|:	   |:	      |:	|:
 *	v	:	    |v		|v	   |v	      |v	|v
 *	-----------------------------------------------------------------
 *	    |
 *	    v
 *    LS_COMPLETED
 */
enum lfsck_status {
	/* The lfsck file is new created, for new MDT, upgrading from old disk,
	 * or re-creating the lfsck file manually. */
	LS_INIT			= 0,

	/* The first-step system scanning. The checked items during the phase1
	 * scanning depends on the LFSCK type. */
	LS_SCANNING_PHASE1	= 1,

	/* The second-step system scanning. The checked items during the phase2
	 * scanning depends on the LFSCK type. */
	LS_SCANNING_PHASE2	= 2,

	/* The LFSCK processing has completed for all objects. */
	LS_COMPLETED		= 3,

	/* The LFSCK exited automatically for failure, will not auto restart. */
	LS_FAILED		= 4,

	/* The LFSCK is stopped manually, will not auto restart. */
	LS_STOPPED		= 5,

	/* LFSCK is paused automatically when umount,
	 * will be restarted automatically when remount. */
	LS_PAUSED		= 6,

	/* System crashed during the LFSCK,
	 * will be restarted automatically after recovery. */
	LS_CRASHED		= 7,

	/* Some OST/MDT failed during the LFSCK, or not join the LFSCK. */
	LS_PARTIAL		= 8,

	/* The LFSCK is failed because its controller is failed. */
	LS_CO_FAILED		= 9,

	/* The LFSCK is stopped because its controller is stopped. */
	LS_CO_STOPPED		= 10,

	/* The LFSCK is paused because its controller is paused. */
	LS_CO_PAUSED		= 11,

	LS_MAX
};

static inline const char *lfsck_status2name(int status)
{
	static const char * const lfsck_status_names[] = {
		[LS_INIT]		= "init",
		[LS_SCANNING_PHASE1]	= "scanning-phase1",
		[LS_SCANNING_PHASE2]	= "scanning-phase2",
		[LS_COMPLETED]		= "completed",
		[LS_FAILED]		= "failed",
		[LS_STOPPED]		= "stopped",
		[LS_PAUSED]		= "paused",
		[LS_CRASHED]		= "crashed",
		[LS_PARTIAL]		= "partial",
		[LS_CO_FAILED]		= "co-failed",
		[LS_CO_STOPPED]		= "co-stopped",
		[LS_CO_PAUSED]		= "co-paused"
	};

	if (status < 0 || status >= LS_MAX)
		return "unknown";

	return lfsck_status_names[status];
}

enum lfsck_param_flags {
	/* Reset LFSCK iterator position to the device beginning. */
	LPF_RESET		= 0x0001,

	/* Exit when fail. */
	LPF_FAILOUT		= 0x0002,

	/* Dryrun mode, only check without modification */
	LPF_DRYRUN		= 0x0004,

	/* LFSCK runs on all targets. */
	LPF_ALL_TGT		= 0x0008,

	/* Broadcast the command to other MDTs. Only valid on the sponsor MDT */
	LPF_BROADCAST		= 0x0010,

	/* Handle orphan OST-objects. */
	LPF_OST_ORPHAN		= 0x0020,

	/* Create OST-object for dangling LOV EA. */
	LPF_CREATE_OSTOBJ	= 0x0040,

	/* Create MDT-object for dangling name entry. */
	LPF_CREATE_MDTOBJ	= 0x0080,

	/* Do not return until the LFSCK not running. */
	LPF_WAIT		= 0x0100,
};

enum lfsck_type {
	/* For MDT and OST internal OSD consistency check/repair. */
	LFSCK_TYPE_SCRUB	= 0x0000,

	/* For MDT-OST (layout, object) consistency check/repair. */
	LFSCK_TYPE_LAYOUT	= 0x0001,

	/* For MDT (FID-in-dirent, linkEA) consistency check/repair. */
	LFSCK_TYPE_NAMESPACE	= 0x0004,
	LFSCK_TYPES_SUPPORTED	= (LFSCK_TYPE_SCRUB | LFSCK_TYPE_LAYOUT |
				   LFSCK_TYPE_NAMESPACE),
	LFSCK_TYPES_DEF		= LFSCK_TYPES_SUPPORTED,
	LFSCK_TYPES_ALL		= ((__u16)(~0))
};

#define LFSCK_VERSION_V1	1
#define LFSCK_VERSION_V2	2

#define LFSCK_SPEED_NO_LIMIT	0
#define LFSCK_SPEED_LIMIT_DEF	LFSCK_SPEED_NO_LIMIT
#define LFSCK_ASYNC_WIN_DEFAULT 1024
#define LFSCK_ASYNC_WIN_MAX	((__u16)(~0))
#define LFSCK_TYPE_BITS		16

enum lfsck_start_valid {
	LSV_SPEED_LIMIT		= 0x00000001,
	LSV_ERROR_HANDLE	= 0x00000002,
	LSV_DRYRUN		= 0x00000004,
	LSV_ASYNC_WINDOWS	= 0x00000008,
	LSV_CREATE_OSTOBJ	= 0x00000010,
	LSV_CREATE_MDTOBJ	= 0x00000020,
};

/* Arguments for starting lfsck. */
struct lfsck_start {
	/* Which arguments are valid, see 'enum lfsck_start_valid'. */
	__u32   ls_valid;

	/* How many items can be scanned at most per second. */
	__u32   ls_speed_limit;

	/* For compatibility between user space tools and kernel service. */
	__u16   ls_version;

	/* Which LFSCK components to be (have been) started. */
	__u16   ls_active;

	/* Flags for the LFSCK, see 'enum lfsck_param_flags'. */
	__u16   ls_flags;

	/* The windows size for async requests pipeline. */
	__u16   ls_async_windows;
};

struct lfsck_stop {
	__u32	ls_status;
	__u16	ls_flags;
	__u16	ls_padding_1; /* For 64-bits aligned. */
	__u64	ls_padding_2;
};

struct lfsck_query {
	__u16	lu_types;
	__u16	lu_flags;
	__u32	lu_mdts_count[LFSCK_TYPE_BITS][LS_MAX + 1];
	__u32	lu_osts_count[LFSCK_TYPE_BITS][LS_MAX + 1];
	__u64	lu_repaired[LFSCK_TYPE_BITS];
};

#endif /* _LUSTRE_LFSCK_USER_H */
