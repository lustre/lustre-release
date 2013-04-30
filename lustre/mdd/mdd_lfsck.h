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
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * lustre/mdd/mdd_lfsck.h
 *
 * Shared definitions and declarations for the LFSCK.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _MDD_LFSCK_H
# define _MDD_LFSCK_H

#include <lustre/lustre_lfsck_user.h>

enum lfsck_status {
	/* The lfsck file is new created, for new MDT, upgrading from old disk,
	 * or re-creating the lfsck file manually. */
	LS_INIT			= 0,

	/* The first-step system scanning. */
	LS_SCANNING_PHASE1	= 1,

	/* The second-step system scanning. */
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
};

enum lfsck_flags {
	/* Finish to the cycle scanning. */
	LF_SCANNED_ONCE	= 0x00000001ULL,

	/* There is some namespace inconsistency. */
	LF_INCONSISTENT	= 0x00000002ULL,

	/* The device is upgraded from 1.8 format. */
	LF_UPGRADE	= 0x00000004ULL,
};

struct lfsck_position {
	/* local layer object table-based iteration position. */
	__u64	lp_oit_cookie;

	/* parent FID for directory traversal. */
	struct lu_fid lp_dir_parent;

	/* namespace-based directory traversal position. */
	__u64	lp_dir_cookie;
};

#define LFSCK_BOOKMARK_MAGIC	0x20130C1D

struct lfsck_bookmark {
	/* Magic number to detect that this struct contains valid data. */
	__u32	lb_magic;

	/* For compatible with old versions. */
	__u16	lb_version;

	/* See 'enum lfsck_param_flags' */
	__u16	lb_param;

	/* How many items can be scanned at most per second. */
	__u32	lb_speed_limit;

	/* For 64-bits aligned. */
	__u32	lb_padding;

	/* For future using. */
	__u64	lb_reserved[6];
};

#define LFSCK_NAMESPACE_MAGIC	0xA0629D03

struct lfsck_namespace {
	/* Magic number to detect that this struct contains valid data. */
	__u32	ln_magic;

	/* See 'enum lfsck_status'. */
	__u32	ln_status;

	/* See 'enum lfsck_flags'. */
	__u32	ln_flags;

	/* How many completed LFSCK runs on the device. */
	__u32	ln_success_count;

	/*  How long the LFSCK phase1 has run in seconds. */
	__u32	ln_run_time_phase1;

	/*  How long the LFSCK phase2 has run in seconds. */
	__u32	ln_run_time_phase2;

	/* Time for the last LFSCK completed in seconds since epoch. */
	__u64	ln_time_last_complete;

	/* Time for the latest LFSCK ran in seconds since epoch. */
	__u64	ln_time_latest_start;

	/* Time for the last LFSCK checkpoint in seconds since epoch. */
	__u64	ln_time_last_checkpoint;

	/* Position for the latest LFSCK started from. */
	struct lfsck_position	ln_pos_latest_start;

	/* Position for the last LFSCK checkpoint. */
	struct lfsck_position	ln_pos_last_checkpoint;

	/* Position for the first should be updated object. */
	struct lfsck_position	ln_pos_first_inconsistent;

	/* How many items (including dir) have been checked. */
	__u64	ln_items_checked;

	/* How many items have been repaired. */
	__u64	ln_items_repaired;

	/* How many items failed to be processed. */
	__u64	ln_items_failed;

	/* How many directories have been traversed. */
	__u64	ln_dirs_checked;

	/* How many multiple-linked objects have been checked. */
	__u64	ln_mlinked_checked;

	/* How many objects have been double scanned. */
	__u64	ln_objs_checked_phase2;

	/* How many objects have been reparied during double scan. */
	__u64	ln_objs_repaired_phase2;

	/* How many objects failed to be processed during double scan. */
	__u64	ln_objs_failed_phase2;

	/* How many objects with nlink fixed. */
	__u64	ln_objs_nlink_repaired;

	/* How many objects were lost before, but found back now. */
	__u64	ln_objs_lost_found;

	/* The latest object has been processed (failed) during double scan. */
	struct lu_fid	ln_fid_latest_scanned_phase2;

	/* For further using. 256-bytes aligned now. */
	__u64	ln_reserved[2];
};

struct lfsck_component;
struct mdd_object;

struct lfsck_operations {
	int (*lfsck_reset)(const struct lu_env *env,
			   struct lfsck_component *com,
			   bool init);

	void (*lfsck_fail)(const struct lu_env *env,
			   struct lfsck_component *com,
			   bool new_checked);

	int (*lfsck_checkpoint)(const struct lu_env *env,
				struct lfsck_component *com,
				bool init);

	int (*lfsck_prep)(const struct lu_env *env,
			  struct lfsck_component *com);

	int (*lfsck_exec_oit)(const struct lu_env *env,
			      struct lfsck_component *com,
			      struct mdd_object *obj);

	int (*lfsck_exec_dir)(const struct lu_env *env,
			      struct lfsck_component *com,
			      struct mdd_object *obj,
			      struct lu_dirent *ent);

	int (*lfsck_post)(const struct lu_env *env,
			  struct lfsck_component *com,
			  int result, bool init);

	int (*lfsck_dump)(const struct lu_env *env,
			  struct lfsck_component *com,
			  char *buf,
			  int len);

	int (*lfsck_double_scan)(const struct lu_env *env,
				 struct lfsck_component *com);
};

struct lfsck_component {
	/* into md_lfsck::ml_list_(scan,double_scan,idle} */
	cfs_list_t		 lc_link;

	/* into md_lfsck::ml_list_dir */
	cfs_list_t		 lc_link_dir;
	struct rw_semaphore	 lc_sem;
	cfs_atomic_t		 lc_ref;

	struct lfsck_position	 lc_pos_start;
	struct md_lfsck		*lc_lfsck;
	struct dt_object	*lc_obj;
	struct lfsck_operations *lc_ops;
	void			*lc_file_ram;
	void			*lc_file_disk;
	__u32			 lc_file_size;

	/* How many objects have been checked since last checkpoint. */
	__u32			 lc_new_checked;
	unsigned int		 lc_journal:1;
	__u16			 lc_type;
};

struct md_lfsck {
	struct mutex		 ml_mutex;
	spinlock_t		 ml_lock;

	/* For the components in (first) scanning via otable-based iteration. */
	cfs_list_t		 ml_list_scan;

	/* For the components in scanning via directory traversal. Because
	 * directory traversal cannot guarantee all the object be scanned,
	 * so the component in the ml_list_dir must be in ml_list_scan. */
	cfs_list_t		 ml_list_dir;

	/* For the components in double scanning. */
	cfs_list_t		 ml_list_double_scan;

	/* For the components those are not scanning now. */
	cfs_list_t		 ml_list_idle;

	struct ptlrpc_thread	 ml_thread;

	/* The time for last checkpoint, jiffies */
	cfs_time_t		 ml_time_last_checkpoint;

	/* The time for next checkpoint, jiffies */
	cfs_time_t		 ml_time_next_checkpoint;

	struct dt_object	*ml_bookmark_obj;
	struct lfsck_bookmark	 ml_bookmark_ram;
	struct lfsck_bookmark	 ml_bookmark_disk;
	struct lfsck_position	 ml_pos_current;

	/* Obj for otable-based iteration */
	struct dt_object	*ml_obj_oit;

	/* Obj for directory traversal */
	struct dt_object	*ml_obj_dir;

	/* It for otable-based iteration */
	struct dt_it		*ml_di_oit;

	/* It for directory traversal */
	struct dt_it		*ml_di_dir;

	/* Arguments for low layer otable-based iteration. */
	__u32			 ml_args_oit;

	/* Arugments for namespace-based directory traversal. */
	__u32			 ml_args_dir;

	/* Schedule for every N objects. */
	__u32			 ml_sleep_rate;

	/* Sleep N jiffies for each schedule. */
	__u32			 ml_sleep_jif;

	/* How many objects have been scanned since last sleep. */
	__u32			 ml_new_scanned;

	unsigned int		 ml_paused:1, /* The lfsck is paused. */
				 ml_oit_over:1, /* oit is finished. */
				 ml_drop_dryrun:1, /* Ever dryrun, not now. */
				 ml_initialized:1, /* lfsck_setup is called. */
				 ml_current_oit_processed:1;
};

enum lfsck_linkea_flags {
	/* The linkea entries does not match the object nlinks. */
	LLF_UNMATCH_NLINKS	= 0x01,

	/* Fail to repair the multiple-linked objects during the double scan. */
	LLF_REPAIR_FAILED	= 0x02,
};

#endif /* _MDD_LFSCK_H */
