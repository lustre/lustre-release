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
 * lustre/osd-ldiskfs/osd_scrub.h
 *
 * Shared definitions and declarations for OI scrub.
 *
 * Author: Fan Yong <yong.fan@whamcloud.com>
 */

#ifndef _OSD_SCRUB_H
# define _OSD_SCRUB_H

#include "osd_oi.h"

#define SCRUB_MAGIC_V1			0x4C5FD252
#define SCRUB_CHECKPOINT_INTERVAL	60
#define SCRUB_OI_BITMAP_SIZE		(OSD_OI_FID_NR_MAX >> 3)
#define SCRUB_WINDOW_SIZE		1024

enum scrub_status {
	/* The scrub file is new created, for new MDT, upgrading from old disk,
	 * or re-creating the scrub file manually. */
	SS_INIT		= 0,

	/* The scrub is checking/repairing the OI files. */
	SS_SCANNING	= 1,

	/* The scrub checked/repaired the OI files successfully. */
	SS_COMPLETED	= 2,

	/* The scrub failed to check/repair the OI files. */
	SS_FAILED	= 3,

	/* The scrub is stopped manually, the OI files may be inconsistent. */
	SS_STOPPED	= 4,

	/* The scrub is paused automatically when umount. */
	SS_PAUSED	= 5,

	/* The scrub crashed during the scanning, should be restarted. */
	SS_CRASHED	= 6,
};

enum scrub_flags {
	/* OI files have been recreated, OI mappings should be re-inserted. */
	SF_RECREATED	= 0x0000000000000001ULL,

	/* OI files are invalid, should be rebuild ASAP */
	SF_INCONSISTENT	= 0x0000000000000002ULL,

	/* OI scrub is triggered automatically. */
	SF_AUTO		= 0x0000000000000004ULL,

	/* The device is upgraded from 1.8 format. */
	SF_UPGRADE	= 0x0000000000000008ULL,
};

enum scrub_param {
	/* Exit when fail. */
	SP_FAILOUT	= 0x0001,

	/* Check only without repairing. */
	SP_DRYRUN	= 0x0002,
};

enum scrub_start {
	/* Set failout flag. */
	SS_SET_FAILOUT		= 0x00000001,

	/* Clear failout flag. */
	SS_CLEAR_FAILOUT	= 0x00000002,

	/* Reset scrub start position. */
	SS_RESET		= 0x00000004,

	/* Trigger full scrub automatically. */
	SS_AUTO_FULL		= 0x00000008,

	/* Trigger partial scrub automatically. */
	SS_AUTO_PARTIAL		= 0x00000010,

	/* Set dryrun flag. */
	SS_SET_DRYRUN		= 0x00000020,

	/* Clear dryrun flag. */
	SS_CLEAR_DRYRUN		= 0x00000040,
};

/* The flags here are only used inside OSD, NOT be visible by dump(). */
enum scrub_internal_flags {
	/* This is a new formatted device. */
	SIF_NO_HANDLE_OLD_FID	= 0x0001,
};

struct scrub_file {
	/* 128-bit uuid for volume. */
	__u8    sf_uuid[16];

	/* See 'enum scrub_flags'. */
	__u64   sf_flags;

	/* The scrub magic. */
	__u32   sf_magic;

	/* See 'enum scrub_status'. */
	__u16   sf_status;

	/* See 'enum scrub_param'. */
	__u16   sf_param;

	/* The time for the last OI scrub completed. */
	__u64   sf_time_last_complete;

	/* The time for the latest OI scrub ran. */
	__u64   sf_time_latest_start;

	/* The time for the last OI scrub checkpoint. */
	__u64   sf_time_last_checkpoint;

	/* The position for the latest OI scrub started from. */
	__u64   sf_pos_latest_start;

	/* The position for the last OI scrub checkpoint. */
	__u64   sf_pos_last_checkpoint;

	/* The position for the first should be updated object. */
	__u64   sf_pos_first_inconsistent;

	/* How many objects have been checked. */
	__u64   sf_items_checked;

	/* How many objects have been updated. */
	__u64   sf_items_updated;

	/* How many objects failed to be processed. */
	__u64   sf_items_failed;

	/* How many prior objects have been updated during scanning. */
	__u64   sf_items_updated_prior;

	/* How many objects marked as LDISKFS_STATE_LUSTRE_NOSCRUB. */
	__u64   sf_items_noscrub;

	/* How many IGIF objects. */
	__u64   sf_items_igif;

	/* How long the OI scrub has run. */
	__u32   sf_run_time;

	/* How many completed OI scrub ran on the device. */
	__u32   sf_success_count;

	/* How many OI files. */
	__u16   sf_oi_count;

	/* Keep the flags after scrub reset. See 'enum scrub_internal_flags' */
	__u16	sf_internal_flags;

	__u32	sf_reserved_1;
	__u64	sf_reserved_2[16];

	/* Bitmap for OI files recreated case. */
	__u8    sf_oi_bitmap[SCRUB_OI_BITMAP_SIZE];
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
	struct lvfs_run_ctxt    os_ctxt;
	struct ptlrpc_thread    os_thread;
	struct osd_idmap_cache  os_oic;
	struct osd_iit_param	os_iit_param;
	struct list_head	os_inconsistent_items;

	/* write lock for scrub prep/update/post/checkpoint,
	 * read lock for scrub dump. */
	struct rw_semaphore	os_rwsem;
	spinlock_t		os_lock;

	/* Scrub file in memory. */
	struct scrub_file       os_file;

	/* Buffer for scrub file load/store. */
	struct scrub_file       os_file_disk;

	/* Inode for the scrub file. */
	struct inode	       *os_inode;

	/* The time for last checkpoint, jiffies */
	cfs_time_t		os_time_last_checkpoint;

	/* The time for next checkpoint, jiffies */
	cfs_time_t		os_time_next_checkpoint;

	/* statistics for /lost+found are in ram only, it will be reset
	 * when each time the device remount. */

	/* How many objects have been scanned during initial OI scrub. */
	__u64			os_lf_scanned;
	/* How many objects have been repaired during initial OI scrub. */
	__u64			os_lf_repaired;
	/* How many objects failed to be processed during initial OI scrub. */
	__u64			os_lf_failed;

	/* How many objects have been checked since last checkpoint. */
	__u32			os_new_checked;
	__u32			os_pos_current;
	__u32			os_start_flags;
	unsigned int		os_in_prior:1, /* process inconsistent item
						* found by RPC prior */
				os_waiting:1, /* Waiting for scan window. */
				os_full_speed:1, /* run w/o speed limit */
				os_paused:1, /* The scrub is paused. */
				os_convert_igif:1,
				os_partial_scan:1,
				os_in_join:1,
				os_full_scrub:1;
	__u64			os_bad_oimap_count;
	__u64			os_bad_oimap_time;
};

#endif /* _OSD_SCRUB_H */
