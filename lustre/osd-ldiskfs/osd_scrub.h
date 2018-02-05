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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * lustre/osd-ldiskfs/osd_scrub.h
 *
 * Definitions and declarations for ldiskfs backend OI scrub.
 *
 * Author: Fan Yong <yong.fan@whamcloud.com>
 */

#ifndef _OSD_SCRUB_H
# define _OSD_SCRUB_H

#include <lustre_scrub.h>
#include "osd_oi.h"

/* The flags here are only used inside OSD, NOT be visible by dump(). */
enum scrub_internal_flags {
	/* This is a new formatted device. */
	SIF_NO_HANDLE_OLD_FID	= 0x0001,
};

struct osd_iit_param {
	struct super_block *sb;
	struct buffer_head *bitmap;
	ldiskfs_group_t bg;
	__u32 gbase;
	__u32 offset;
	__u32 start;
};

struct osd_scrub {
	struct lustre_scrub	os_scrub;
	struct lvfs_run_ctxt    os_ctxt;
	struct osd_idmap_cache  os_oic;
	struct osd_iit_param	os_iit_param;

	/* statistics for /lost+found are in ram only, it will be reset
	 * when each time the device remount. */

	/* How many objects have been scanned during initial OI scrub. */
	__u64			os_lf_scanned;
	/* How many objects have been repaired during initial OI scrub. */
	__u64			os_lf_repaired;
	/* How many objects failed to be processed during initial OI scrub. */
	__u64			os_lf_failed;

	__u64			os_bad_oimap_count;
	time64_t		os_bad_oimap_time;
};

#endif /* _OSD_SCRUB_H */
