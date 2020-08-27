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
 * Copyright (c) 2013, 2017, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_internal.h
 *
 * Shared definitions and declarations for the LFSCK.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _LFSCK_INTERNAL_H
# define _LFSCK_INTERNAL_H

#include <lustre_lfsck.h>
#include <obd.h>
#include <lu_object.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <lustre_fid.h>
#include <md_object.h>
#include <lustre_linkea.h>

#define LFSCK_CHECKPOINT_INTERVAL	60

enum lfsck_flags {
	/* Finish the first cycle scanning. */
	LF_SCANNED_ONCE		= 0x00000001ULL,

	/* There is some namespace inconsistency. */
	LF_INCONSISTENT		= 0x00000002ULL,

	/* The device is upgraded from 1.8 format. */
	LF_UPGRADE		= 0x00000004ULL,

	/* The server ever restarted during the LFSCK, and may miss to process
	 * some objects check/repair. */
	LF_INCOMPLETE		= 0x00000008ULL,

	/* The LAST_ID (file) crashed. */
	LF_CRASHED_LASTID	= 0x00000010ULL,
};

struct lfsck_position {
	/* low layer object table-based iteration position. */
	__u64	lp_oit_cookie;

	/* parent FID for directory traversal. */
	struct lu_fid lp_dir_parent;

	/* namespace-based directory traversal position. */
	__u64	lp_dir_cookie;
};

struct lfsck_bookmark {
	/* Magic number to detect that this struct contains valid data. */
	__u32	lb_magic;

	/* For compatible with old versions. */
	__u16	lb_version;

	/* See 'enum lfsck_param_flags' */
	__u16	lb_param;

	/* How many items can be scanned at most per second. */
	__u32	lb_speed_limit;

	/* The windows size for async requests pipeline. */
	__u16	lb_async_windows;

	/* For 64-bits aligned. */
	__u16	lb_padding;

	/* The FID for .lustre/lost+found/MDTxxxx */
	struct lu_fid	lb_lpf_fid;

	/* The FID for the last MDT-object created by the LFSCK repairing. */
	struct lu_fid	lb_last_fid;

	/* For future using. */
	__u64	lb_reserved[2];
};

enum lfsck_namespace_trace_flags {
	LNTF_CHECK_LINKEA	= 0x01,
	LNTF_CHECK_PARENT	= 0x02,
	LNTF_CHECK_ORPHAN	= 0x08,
	LNTF_UNCERTAIN_LMV	= 0x10,
	LNTF_RECHECK_NAME_HASH	= 0x20,
	LNTF_CHECK_AGENT_ENTRY	= 0x40,
	LNTF_ALL		= 0xff
};

enum lfsck_namespace_inconsistency_type {
	LNIT_NONE		= 0,
	LNIT_BAD_LINKEA		= 1,
	LNIT_UNMATCHED_PAIRS	= 2,
	LNIT_DANGLING		= 3,
	LNIT_MUL_REF		= 4,
	LNIT_BAD_TYPE		= 5,
	LNIT_BAD_DIRENT		= 6,
};

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
	time64_t ln_run_time_phase1;

	/*  How long the LFSCK phase2 has run in seconds. */
	time64_t ln_run_time_phase2;

	/* Time for the last LFSCK completed in seconds since epoch. */
	time64_t ln_time_last_complete;

	/* Time for the latest LFSCK ran in seconds since epoch. */
	time64_t ln_time_latest_start;

	/* Time for the last LFSCK checkpoint in seconds since epoch. */
	time64_t ln_time_last_checkpoint;

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

	/* How many objects have been double scanned. */
	__u64	ln_objs_checked_phase2;

	/* How many objects have been reparied during double scan. */
	__u64	ln_objs_repaired_phase2;

	/* How many objects failed to be processed during double scan. */
	__u64	ln_objs_failed_phase2;

	/* How many objects with nlink fixed. */
	__u64	ln_objs_nlink_repaired;

	/* The latest object has been processed (failed) during double scan. */
	struct lu_fid	ln_fid_latest_scanned_phase2;

	/* How many FID-in-dirent entries have been repaired. */
	__u64	ln_dirent_repaired;

	/* How many linkEA entries have been repaired. */
	__u64	ln_linkea_repaired;

	/* How many multiple-linked objects have been checked. */
	__u64	ln_mul_linked_checked;

	/* How many multiple-linked objects have been repaired. */
	__u64	ln_mul_linked_repaired;

	/* How many undefined inconsistency found in phase2. */
	__u64	ln_unknown_inconsistency;

	/* How many unmatched pairs have been repaired. */
	__u64	ln_unmatched_pairs_repaired;

	/* How many dangling name entries have been found/repaired. */
	__u64	ln_dangling_repaired;

	/* How many multiple referenced name entries have been
	 * found/repaired. */
	__u64	ln_mul_ref_repaired;

	/* How many name entries with bad file type have been repaired. */
	__u64	ln_bad_type_repaired;

	/* How many lost name entries have been re-inserted. */
	__u64	ln_lost_dirent_repaired;

	/* How many objects under /lost+found have been scanned. */
	__u64	ln_local_lpf_scanned;

	/* How many objects under /lost+found have been moved to
	 * namespace visible directory. */
	__u64	ln_local_lpf_moved;

	/* How many objects under /lost+found have been skipped. */
	__u64	ln_local_lpf_skipped;

	/* How many objects under /lost+found failed to be processed. */
	__u64	ln_local_lpf_failed;

	/* How many striped directories (master) have been scanned. */
	__u64	ln_striped_dirs_scanned;

	/* How many striped directories (master) have been repaired. */
	__u64	ln_striped_dirs_repaired;

	/* How many striped directories (master) failed verification. */
	__u64	ln_striped_dirs_failed;

	/* How many striped directories (master) has been disabled. */
	__u64	ln_striped_dirs_disabled;

	/* How many striped directory's (master) have been skipped
	 * (for shards verification) because of lost master LMV EA. */
	__u64	ln_striped_dirs_skipped;

	/* How many striped directory's shards (slave) have been scanned. */
	__u64	ln_striped_shards_scanned;

	/* How many striped directory's shards (slave) have been repaired. */
	__u64	ln_striped_shards_repaired;

	/* How many striped directory's shards (slave) failed verification. */
	__u64	ln_striped_shards_failed;

	/* How many striped directory's shards (slave) have been skipped
	 * (for name hash verification) because do not know whether the slave
	 * LMV EA is valid or not. */
	__u64	ln_striped_shards_skipped;

	/* How many name entries under striped directory with bad name
	 * hash have been repaired. */
	__u64	ln_name_hash_repaired;

	/* The size of MDT targets bitmap with nbits. Such bitmap records
	 * the MDTs that contain non-verified MDT-objects. */
	__u32	ln_bitmap_size;

	/* For further using. 256-bytes aligned now. */
	__u32	ln_reserved_1;

	/* Time for the latest LFSCK scan in seconds from the beginning. */
	time64_t ln_time_latest_reset;

	/* How many linkEA overflow timestamp have been cleared. */
	__u64	ln_linkea_overflow_cleared;

	/* How many agent entries have been repaired. */
	__u64	ln_agent_entries_repaired;

	/* For further using. 256-bytes aligned now. */
	__u64   ln_reserved[11];
};

enum lfsck_layout_inconsistency_type {
	LLIT_NONE			= 0,
	LLIT_DANGLING			= 1,
	LLIT_UNMATCHED_PAIR		= 2,
	LLIT_MULTIPLE_REFERENCED	= 3,
	LLIT_ORPHAN			= 4,
	LLIT_INCONSISTENT_OWNER 	= 5,
	LLIT_OTHERS			= 6,
	LLIT_MAX			= LLIT_OTHERS
};

struct lfsck_layout {
	/* Magic number to detect that this struct contains valid data. */
	__u32	ll_magic;

	/* See 'enum lfsck_status'. */
	__u32	ll_status;

	/* See 'enum lfsck_flags'. */
	__u32	ll_flags;

	/* How many completed LFSCK runs on the device. */
	__u32	ll_success_count;

	/*  How long the LFSCK phase1 has run in seconds. */
	time64_t ll_run_time_phase1;

	/*  How long the LFSCK phase2 has run in seconds. */
	time64_t ll_run_time_phase2;

	/* Time for the last LFSCK completed in seconds since epoch. */
	time64_t ll_time_last_complete;

	/* Time for the latest LFSCK ran in seconds since epoch. */
	time64_t ll_time_latest_start;

	/* Time for the last LFSCK checkpoint in seconds since epoch. */
	time64_t ll_time_last_checkpoint;

	/* Position for the latest LFSCK started from. */
	__u64	ll_pos_latest_start;

	/* Position for the last LFSCK checkpoint. */
	__u64	ll_pos_last_checkpoint;

	/* Position for the first object to be fixed or
	 * failed to be checked in the phase1. */
	__u64	ll_pos_first_inconsistent;

	/* How many objects have been checked. */
	__u64	ll_objs_checked_phase1;

	/* How many objects failed to be processed. */
	__u64	ll_objs_failed_phase1;

	/* How many objects have been double scanned. */
	__u64	ll_objs_checked_phase2;

	/* How many objects failed to be processed during double scan. */
	__u64	ll_objs_failed_phase2;

	/* kinds of inconsistency have been or to be repaired.
	 * ll_objs_repaired[type - 1] is the count for the given @type. */
	__u64	ll_objs_repaired[LLIT_MAX];

	/* How many objects have been skipped because of related
	 * MDT(s)/OST(s) do not participate in the LFSCK */
	__u64	ll_objs_skipped;

	/* The size of ll_ost_bitmap with nbits. */
	__u32	ll_bitmap_size;

	/* For further using. 256-bytes aligned now. */
	__u32	ll_reserved_1;

	/* The latest object has been processed (failed) during double scan. */
	struct lfsck_layout_dangling_key ll_lldk_latest_scanned_phase2;

	/* For further using */
	u64	ll_reserved_2[7];

	/* The OST targets bitmap to record the OSTs that contain
	 * non-verified OST-objects. */
	__u8	ll_ost_bitmap[0];
};

struct lfsck_assistant_object {
	struct lu_fid		lso_fid;
	__u64			lso_oit_cookie;
	struct lu_attr		lso_attr;
	atomic_t		lso_ref;
	unsigned int		lso_dead:1,
				lso_is_dir:1;
};

struct lfsck_component;
struct lfsck_tgt_descs;
struct lfsck_tgt_desc;

struct lfsck_operations {
	int (*lfsck_reset)(const struct lu_env *env,
			   struct lfsck_component *com,
			   bool init);

	void (*lfsck_fail)(const struct lu_env *env,
			   struct lfsck_component *com,
			   bool new_checked);

	void (*lfsck_close_dir)(const struct lu_env *env,
				struct lfsck_component *com);

	int (*lfsck_open_dir)(const struct lu_env *env,
			      struct lfsck_component *com);

	int (*lfsck_checkpoint)(const struct lu_env *env,
				struct lfsck_component *com,
				bool init);

	int (*lfsck_prep)(const struct lu_env *env,
			  struct lfsck_component *com,
			  struct lfsck_start_param *lsp);

	int (*lfsck_exec_oit)(const struct lu_env *env,
			      struct lfsck_component *com,
			      struct dt_object *obj);

	int (*lfsck_exec_dir)(const struct lu_env *env,
			      struct lfsck_component *com,
			      struct lfsck_assistant_object *lso,
			      struct lu_dirent *ent,
			      __u16 type);

	int (*lfsck_post)(const struct lu_env *env,
			  struct lfsck_component *com,
			  int result,
			  bool init);

	void (*lfsck_dump)(const struct lu_env *env,
			   struct lfsck_component *com,
			   struct seq_file *m);

	int (*lfsck_double_scan)(const struct lu_env *env,
				 struct lfsck_component *com);

	void (*lfsck_data_release)(const struct lu_env *env,
				   struct lfsck_component *com);

	void (*lfsck_quit)(const struct lu_env *env,
			   struct lfsck_component *com);

	int (*lfsck_in_notify_local)(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct lfsck_req_local *lrl,
				     struct thandle *th);

	int (*lfsck_in_notify)(const struct lu_env *env,
			       struct lfsck_component *com,
			       struct lfsck_request *lr);

	int (*lfsck_query)(const struct lu_env *env,
			   struct lfsck_component *com,
			   struct lfsck_request *req,
			   struct lfsck_reply *rep,
			   struct lfsck_query *que, int idx);

	int (*lfsck_join)(const struct lu_env *env,
			  struct lfsck_component *com,
			  struct lfsck_start_param *lsp);
};

struct lfsck_tgt_desc {
	struct list_head   ltd_orphan_list;
	struct dt_device  *ltd_tgt;
	struct dt_device  *ltd_key;
	struct obd_export *ltd_exp;
	struct list_head   ltd_layout_list;
	struct list_head   ltd_layout_phase_list;
	struct list_head   ltd_namespace_list;
	struct list_head   ltd_namespace_phase_list;
	__u32		   ltd_layout_status;
	__u32		   ltd_namespace_status;
	__u64		   ltd_layout_repaired;
	__u64		   ltd_namespace_repaired;
	atomic_t	   ltd_ref;
	__u32              ltd_index;
	__u32		   ltd_layout_gen;
	__u32		   ltd_namespace_gen;
	unsigned int	   ltd_dead:1,
			   ltd_retry_start:1,
			   ltd_layout_done:1,
			   ltd_namespace_done:1,
			   ltd_synced_failures:1;
};

struct lfsck_tgt_desc_idx {
	struct lfsck_tgt_desc *ldi_tgts[TGT_PTRS_PER_BLOCK];
};

struct lfsck_tgt_descs {
	/* list of known TGTs */
	struct lfsck_tgt_desc_idx	*ltd_tgts_idx[TGT_PTRS];

	/* bitmap of TGTs available */
	struct cfs_bitmap			*ltd_tgts_bitmap;

	/* for lfsck_tgt_desc::ltd_xxx_list */
	spinlock_t			 ltd_lock;

	/* for tgts table accessing and changes */
	struct rw_semaphore		 ltd_rw_sem;

	/* Temporary list for orphan targets. */
	struct list_head		 ltd_orphan;

	/* number of registered TGTs */
	__u32				 ltd_tgtnr;
};

static inline struct lfsck_tgt_desc *
lfsck_ltd2tgt(struct lfsck_tgt_descs *ltd, __u32 index)
{
	__u32 idx1 = index / TGT_PTRS_PER_BLOCK;
	__u32 idx2 = index % TGT_PTRS_PER_BLOCK;
	struct lfsck_tgt_desc *__tgt = NULL;

	if (unlikely(idx1 >= TGT_PTRS))
		CDEBUG(D_LFSCK, "The target idx %u is invalid.\n", index);
	else if (likely(ltd->ltd_tgts_idx[idx1] != NULL))
		__tgt = ltd->ltd_tgts_idx[idx1]->ldi_tgts[idx2];

	return __tgt;
}

static inline void lfsck_assign_tgt(struct lfsck_tgt_descs *ltd,
				    struct lfsck_tgt_desc *tgt, __u32 index)
{
	__u32 idx1 = index / TGT_PTRS_PER_BLOCK;
	__u32 idx2 = index % TGT_PTRS_PER_BLOCK;

	if (likely(idx1 < TGT_PTRS && ltd->ltd_tgts_idx[idx1] != NULL))
		ltd->ltd_tgts_idx[idx1]->ldi_tgts[idx2] = tgt;
}

#define LFSCK_STF_BITS	4
/* If want to adjust the LFSCK_STF_COUNT, please change LFSCK_STF_BITS. */
#define LFSCK_STF_COUNT	(1 << LFSCK_STF_BITS)

struct lfsck_sub_trace_obj {
	struct dt_object	*lsto_obj;
	struct mutex		 lsto_mutex;
};

struct lfsck_component {
	/* into lfsck_instance::li_list_(scan,double_scan,idle} */
	struct list_head	 lc_link;

	/* into lfsck_instance::li_list_dir */
	struct list_head	 lc_link_dir;

	struct rw_semaphore	 lc_sem;
	atomic_t		 lc_ref;

	struct lfsck_position	 lc_pos_start;
	struct lfsck_instance	*lc_lfsck;
	struct dt_object	*lc_obj;
	struct lfsck_sub_trace_obj lc_sub_trace_objs[LFSCK_STF_COUNT];
	const struct lfsck_operations *lc_ops;
	void			*lc_file_ram;
	void			*lc_file_disk;
	void			*lc_data;
	struct lu_fid		 lc_fid_latest_scanned_phase2;

	/* The time for last checkpoint, seconds */
	time64_t		 lc_time_last_checkpoint;

	/* The time for next checkpoint, seconds */
	time64_t		 lc_time_next_checkpoint;

	__u32			 lc_file_size;

	/* How many objects have been checked since last checkpoint. */
	__u32			 lc_new_checked;

	/* How many objects have been scanned since last sleep. */
	__u32			 lc_new_scanned;

	__u16			 lc_type;
};

#define LFSCK_LMV_MAX_STRIPES	LMV_MAX_STRIPE_COUNT
#define LFSCK_LMV_DEF_STRIPES	4

/* Warning: NOT change the lfsck_slave_lmv_flags members order,
 *	    otherwise the lfsck_record_lmv() may be wrong. */
enum lfsck_slave_lmv_flags {
	LSLF_NONE	= 0,
	LSLF_BAD_INDEX2	= 1,
	LSLF_NO_LMVEA	= 2,
	LSLF_DANGLING	= 3,
	LSLF_BAD_INDEX1	= 4,
};

/* When the namespace LFSCK scans a striped directory, it will record all
 * the known shards' information in the structure "lfsck_slave_lmv_rec",
 * including the shard's FID, index, slave LMV EA, and so on. Each shard
 * will take one lfsck_slave_lmv_rec slot. After the 1st cycle scanning
 * the striped directory, the LFSCK will get all the information about
 * whether there are some inconsistency, and then it can repair them in
 * the 2nd cycle scanning. */
struct lfsck_slave_lmv_rec {
	struct lu_fid	lslr_fid;
	__u32		lslr_stripe_count;
	__u32		lslr_index; /* the index in name or in slave lmv */
	__u32		lslr_hash_type;
	__u32		lslr_flags;
};

struct lfsck_lmv {
	struct lmv_mds_md_v1		 ll_lmv;
	atomic_t			 ll_ref;
	int				 ll_stripes_allocated;
	int				 ll_stripes_filled;
	int				 ll_exit_value;
	__u32				 ll_max_stripe_count;
	__u32				 ll_max_filled_off;
	__u32				 ll_hash_type;
	unsigned int			 ll_lmv_master:1,
					 ll_lmv_slave:1,
					 ll_lmv_verified:1,
					 ll_lmv_updated:1,
					 ll_inline:1,
					 ll_failed:1,
					 ll_ignore:1,
					 ll_counted:1;
	struct lfsck_slave_lmv_rec	*ll_lslr; /* may be vmalloc'd */
};

/* If the namespace LFSCK finds that the master MDT-object of a striped
 * directory lost its master LMV EA, it will re-generate the master LMV
 * EA and notify the LFSCK instance on the MDT on which the striped dir
 * master MDT-object resides to rescan the striped directory. To do that,
 * the notify handler will insert a "lfsck_lmv_unit" structure into the
 * lfsck::li_list_lmv. The LFSCK instance will scan such list from time
 * to time to check whether needs to rescan some stirped directories. */
struct lfsck_lmv_unit {
	struct list_head	 llu_link;
	struct lfsck_lmv	 llu_lmv;
	struct dt_object	*llu_obj;
	struct lfsck_instance	*llu_lfsck;
};

struct lfsck_rec_lmv_save {
	struct lu_fid		lrls_fid;
	struct lmv_mds_md_v1	lrls_lmv;
};

/* Allow lfsck_record_lmv() to be called recursively at most three times. */
#define LFSCK_REC_LMV_MAX_DEPTH 3

struct lfsck_instance {
	struct mutex		  li_mutex;
	spinlock_t		  li_lock;

	/* Link into the lfsck_instance_list. */
	struct list_head	  li_link;

	/* For the components in (first) scanning via otable-based iteration. */
	struct list_head	  li_list_scan;

	/* For the components in scanning via directory traversal. Because
	 * directory traversal cannot guarantee all the object be scanned,
	 * so the component in the li_list_dir must be in li_list_scan. */
	struct list_head	  li_list_dir;

	/* For the components in double scanning. */
	struct list_head	  li_list_double_scan;

	/* For the components those are not scanning now. */
	struct list_head	  li_list_idle;

	/* For the lfsck_lmv_unit to be handled. */
	struct list_head	  li_list_lmv;

	atomic_t		  li_ref;
	atomic_t		  li_double_scan_count;
	struct ptlrpc_thread	  li_thread;
	struct task_struct	 *li_task;

	/* The time for last checkpoint, seconds */
	time64_t		  li_time_last_checkpoint;

	/* The time for next checkpoint, seconds */
	time64_t		  li_time_next_checkpoint;

	lfsck_out_notify	  li_out_notify;
	void			 *li_out_notify_data;
	struct dt_device	 *li_next;
	struct dt_device	 *li_bottom;
	struct obd_device	 *li_obd;
	struct ldlm_namespace	 *li_namespace;
	struct local_oid_storage *li_los;
	struct lu_fid		  li_local_root_fid;  /* backend root "/" */
	struct lu_fid		  li_global_root_fid; /* /ROOT */
	struct dt_object	 *li_lfsck_dir;
	struct dt_object	 *li_bookmark_obj;
	struct dt_object	 *li_lpf_obj;
	struct dt_object	 *li_lpf_root_obj;
	struct lu_client_seq	 *li_seq;
	struct lfsck_bookmark	  li_bookmark_ram;
	struct lfsck_bookmark	  li_bookmark_disk;
	struct lfsck_position	  li_pos_current;
	struct lfsck_position	  li_pos_checkpoint;

	struct lfsck_lmv	 *li_lmv;

	/* Obj for otable-based iteration */
	struct dt_object	 *li_obj_oit;

	/* Obj for directory traversal */
	struct dt_object	 *li_obj_dir;

	/* It for otable-based iteration */
	struct dt_it		 *li_di_oit;

	/* It for directory traversal */
	struct dt_it		 *li_di_dir;

	/* Description of OST */
	struct lfsck_tgt_descs	  li_ost_descs;

	/* Description of MDT */
	struct lfsck_tgt_descs	  li_mdt_descs;

	/* namespace-based directory traversal position. */
	__u64			  li_cookie_dir;

	/* Arguments for low layer otable-based iteration. */
	__u32			  li_args_oit;

	/* Arugments for namespace-based directory traversal. */
	__u32			  li_args_dir;

	/* Schedule for every N objects. */
	__u32			  li_sleep_rate;

	/* Sleep N jiffies for each schedule. */
	__u32			  li_sleep_jif;

	/* How many objects have been scanned since last sleep. */
	__u32			  li_new_scanned;

	/* The status when the LFSCK stopped or paused. */
	__u32			  li_status;

	/* The flags when the lFSCK stopped or paused. */
	__u32			  li_flags;

	unsigned int		  li_oit_over:1, /* oit is finished. */
				  li_drop_dryrun:1, /* Ever dryrun, not now. */
				  li_master:1, /* Master instance or not. */
				  li_current_oit_processed:1,
				  li_start_unplug:1,
				  li_stopping:1;
	struct lfsck_rec_lmv_save li_rec_lmv_save[LFSCK_REC_LMV_MAX_DEPTH];
};

static inline bool lfsck_is_dryrun(struct lfsck_instance *lfsck)
{
	return lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN;
}

struct lfsck_async_interpret_args {
	struct lfsck_component		*laia_com;
	struct lfsck_tgt_descs		*laia_ltds;
	struct lfsck_tgt_desc		*laia_ltd;
	struct lfsck_request		*laia_lr;
	atomic_t			*laia_count;
	int				 laia_result;
	unsigned int			 laia_shared:1;
};

struct lfsck_thread_args {
	struct lu_env			 lta_env;
	struct lfsck_instance		*lta_lfsck;
	struct lfsck_component		*lta_com;
	struct lfsck_start_param	*lta_lsp;
};

struct lfsck_assistant_req {
	struct list_head		 lar_list;
	struct lfsck_assistant_object	*lar_parent;
};

struct lfsck_namespace_req {
	struct lfsck_assistant_req	 lnr_lar;
	struct lfsck_lmv		*lnr_lmv;
	struct lu_fid			 lnr_fid;
	__u64				 lnr_dir_cookie;
	__u32				 lnr_attr;
	__u32				 lnr_size;
	__u16				 lnr_type;
	__u16				 lnr_namelen;
	char				 lnr_name[0];
};

struct lfsck_layout_req {
	struct lfsck_assistant_req	 llr_lar;
	struct dt_object		*llr_child;
	__u32				 llr_comp_id;
	__u32				 llr_ost_idx;
	__u32				 llr_lov_idx; /* offset in LOV EA */
};

struct lfsck_assistant_operations {
	int (*la_handler_p1)(const struct lu_env *env,
			     struct lfsck_component *com,
			     struct lfsck_assistant_req *lar);

	int (*la_handler_p2)(const struct lu_env *env,
			     struct lfsck_component *com);

	void (*la_fill_pos)(const struct lu_env *env,
			    struct lfsck_component *com,
			    struct lfsck_position *pos);

	int (*la_double_scan_result)(const struct lu_env *env,
				     struct lfsck_component *com,
				     int rc);

	void (*la_req_fini)(const struct lu_env *env,
			    struct lfsck_assistant_req *lar);

	void (*la_sync_failures)(const struct lu_env *env,
				 struct lfsck_component *com,
				 struct lfsck_request *lr);
};

struct lfsck_assistant_data {
	spinlock_t				 lad_lock;
	struct list_head			 lad_req_list;

	/* list for the ost targets involve LFSCK. */
	struct list_head			 lad_ost_list;

	/* list for the ost targets in phase1 scanning. */
	struct list_head			 lad_ost_phase1_list;

	/* list for the ost targets in phase2 scanning. */
	struct list_head			 lad_ost_phase2_list;

	/* list for the mdt targets involve LFSCK. */
	struct list_head			 lad_mdt_list;

	/* list for the mdt targets in phase1 scanning. */
	struct list_head			 lad_mdt_phase1_list;

	/* list for the mdt targets in phase2 scanning. */
	struct list_head			 lad_mdt_phase2_list;

	const char				*lad_name;
	struct ptlrpc_thread			 lad_thread;
	struct task_struct			*lad_task;

	const struct lfsck_assistant_operations	*lad_ops;

	struct cfs_bitmap				*lad_bitmap;

	__u32					 lad_touch_gen;
	int					 lad_prefetched;
	int					 lad_assistant_status;
	int					 lad_post_result;
	unsigned long				 lad_flags;
	bool					 lad_advance_lock;
};
enum {
	LAD_TO_POST = 0,
	LAD_TO_DOUBLE_SCAN = 1,
	LAD_IN_DOUBLE_SCAN = 2,
	LAD_EXIT = 3,
	LAD_INCOMPLETE = 4,
};

#define LFSCK_TMPBUF_LEN	64

struct lfsck_lock_handle {
	struct lustre_handle	llh_pdo_lh;
	struct lustre_handle	llh_reg_lh;
	enum ldlm_mode		llh_pdo_mode;
	enum ldlm_mode		llh_reg_mode;
};

struct lfsck_thread_info {
	struct lu_name		lti_name_const;
	struct lu_name		lti_name;
	struct lu_name		lti_name2;
	struct lu_buf		lti_buf;
	struct lu_buf		lti_linkea_buf;
	struct lu_buf		lti_linkea_buf2;
	struct lu_buf		lti_big_buf;
	struct lu_fid		lti_fid;
	struct lu_fid		lti_fid2;
	struct lu_fid		lti_fid3;
	struct lu_fid		lti_fid4;
	struct lu_attr		lti_la;
	struct lu_attr		lti_la2;
	struct ost_id		lti_oi;
	struct lustre_ost_attrs lti_loa;
	struct dt_object_format lti_dof;
	/* There will be '\0' at the end of the name. */
	char		lti_key[sizeof(struct lu_dirent) + NAME_MAX + 1];
	char			lti_tmpbuf[LFSCK_TMPBUF_LEN];
	char			lti_tmpbuf2[LFSCK_TMPBUF_LEN];
	struct lfsck_request	lti_lr;
	struct lfsck_async_interpret_args lti_laia;
	struct lfsck_async_interpret_args lti_laia2;
	struct lfsck_start	lti_start;
	struct lfsck_stop	lti_stop;
	union ldlm_policy_data	lti_policy;
	struct ldlm_enqueue_info lti_einfo;
	struct ldlm_res_id	lti_resid;
	struct filter_fid	lti_ff;
	struct dt_allocation_hint lti_hint;
	struct lu_orphan_rec_v3	lti_rec;
	struct lov_user_md	lti_lum;
	struct dt_insert_rec	lti_dt_rec;
	struct lu_object_conf	lti_conf;
	struct lu_seq_range	lti_range;
	struct lmv_mds_md_v1	lti_lmv;
	struct lmv_mds_md_v1	lti_lmv2;
	struct lmv_mds_md_v1	lti_lmv3;
	struct lmv_mds_md_v1	lti_lmv4;
	struct lfsck_lock_handle lti_llh;
	struct lfsck_layout_dangling_key lti_lldk;
};

/* lfsck_lib.c */
int lfsck_fid_alloc(const struct lu_env *env, struct lfsck_instance *lfsck,
		    struct lu_fid *fid, bool locked);
int lfsck_ibits_lock(const struct lu_env *env, struct lfsck_instance *lfsck,
		     struct dt_object *obj, struct lustre_handle *lh,
		     __u64 bits, enum ldlm_mode mode);
void lfsck_ibits_unlock(struct lustre_handle *lh, enum ldlm_mode mode);
int lfsck_remote_lookup_lock(const struct lu_env *env,
			     struct lfsck_instance *lfsck,
			     struct dt_object *pobj, struct dt_object *obj,
			     struct lustre_handle *lh, enum ldlm_mode mode);
int lfsck_lock(const struct lu_env *env, struct lfsck_instance *lfsck,
	       struct dt_object *obj, const char *name,
	       struct lfsck_lock_handle *llh, __u64 bits, enum ldlm_mode mode);
void lfsck_unlock(struct lfsck_lock_handle *llh);
int lfsck_find_mdt_idx_by_fid(const struct lu_env *env,
			      struct lfsck_instance *lfsck,
			      const struct lu_fid *fid);
int lfsck_verify_lpf(const struct lu_env *env, struct lfsck_instance *lfsck);
struct lfsck_instance *lfsck_instance_find(struct dt_device *key, bool ref,
					   bool unlink);
struct lfsck_component *lfsck_component_find(struct lfsck_instance *lfsck,
					     __u16 type);
void lfsck_component_cleanup(const struct lu_env *env,
			     struct lfsck_component *com);
void lfsck_instance_cleanup(const struct lu_env *env,
			    struct lfsck_instance *lfsck);
void lfsck_bits_dump(struct seq_file *m, int bits, const char *const names[],
		     const char *prefix);
void lfsck_time_dump(struct seq_file *m, time64_t time, const char *name);
void lfsck_pos_dump(struct seq_file *m, struct lfsck_position *pos,
		    const char *prefix);
void lfsck_pos_fill(const struct lu_env *env, struct lfsck_instance *lfsck,
		    struct lfsck_position *pos, bool init);
bool __lfsck_set_speed(struct lfsck_instance *lfsck, __u32 limit);
void lfsck_control_speed(struct lfsck_instance *lfsck);
void lfsck_control_speed_by_self(struct lfsck_component *com);
void lfsck_thread_args_fini(struct lfsck_thread_args *lta);
struct lfsck_assistant_data *
lfsck_assistant_data_init(const struct lfsck_assistant_operations *lao,
			  const char *name);
struct lfsck_assistant_object *
lfsck_assistant_object_init(const struct lu_env *env, const struct lu_fid *fid,
			    const struct lu_attr *attr, __u64 cookie,
			    bool is_dir);
struct dt_object *
lfsck_assistant_object_load(const struct lu_env *env,
			    struct lfsck_instance *lfsck,
			    struct lfsck_assistant_object *lso);
int lfsck_async_interpret_common(const struct lu_env *env,
				 struct ptlrpc_request *req,
				 void *args, int rc);
int lfsck_async_request(const struct lu_env *env, struct obd_export *exp,
			struct lfsck_request *lr,
			struct ptlrpc_request_set *set,
			ptlrpc_interpterer_t interpterer,
			void *args, int request);
int lfsck_query_all(const struct lu_env *env, struct lfsck_component *com);
int lfsck_start_assistant(const struct lu_env *env, struct lfsck_component *com,
			  struct lfsck_start_param *lsp);
int lfsck_checkpoint_generic(const struct lu_env *env,
			     struct lfsck_component *com);
void lfsck_post_generic(const struct lu_env *env,
			struct lfsck_component *com, int *result);
int lfsck_double_scan_generic(const struct lu_env *env,
			      struct lfsck_component *com, int status);
void lfsck_quit_generic(const struct lu_env *env,
			struct lfsck_component *com);
int lfsck_load_one_trace_file(const struct lu_env *env,
			      struct lfsck_component *com,
			      struct dt_object *parent,
			      struct dt_object **child,
			      const struct dt_index_features *ft,
			      const char *name, bool reset);
int lfsck_load_sub_trace_files(const struct lu_env *env,
			       struct lfsck_component *com,
			       const struct dt_index_features *ft,
			       const char *prefix, bool reset);

/* lfsck_engine.c */
int lfsck_unpack_ent(struct lu_dirent *ent, __u64 *cookie, __u16 *type);
void lfsck_close_dir(const struct lu_env *env,
		     struct lfsck_instance *lfsck, int result);
int lfsck_open_dir(const struct lu_env *env,
		   struct lfsck_instance *lfsck, __u64 cookie);
int lfsck_master_engine(void *args);
int lfsck_assistant_engine(void *args);

/* lfsck_bookmark.c */
void lfsck_bookmark_cpu_to_le(struct lfsck_bookmark *des,
			      struct lfsck_bookmark *src);
int lfsck_bookmark_store(const struct lu_env *env,
			 struct lfsck_instance *lfsck);
int lfsck_bookmark_setup(const struct lu_env *env,
			 struct lfsck_instance *lfsck);
int lfsck_set_param(const struct lu_env *env, struct lfsck_instance *lfsck,
		    struct lfsck_start *start, bool reset);

/* lfsck_namespace.c */
int lfsck_namespace_trace_update(const struct lu_env *env,
				 struct lfsck_component *com,
				 const struct lu_fid *fid,
				 const __u8 flags, bool add);
int lfsck_namespace_check_exist(const struct lu_env *env,
				struct dt_object *dir,
				struct dt_object *obj, const char *name);
int __lfsck_links_read(const struct lu_env *env, struct dt_object *obj,
		       struct linkea_data *ldata, bool with_rec);
int lfsck_namespace_rebuild_linkea(const struct lu_env *env,
				   struct lfsck_component *com,
				   struct dt_object *obj,
				   struct linkea_data *ldata);
int lfsck_namespace_repair_dangling(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct dt_object *parent,
				    struct dt_object *child,
				    struct lfsck_namespace_req *lnr);
int lfsck_namespace_repair_dirent(const struct lu_env *env,
				  struct lfsck_component *com,
				  struct dt_object *parent,
				  struct dt_object *child,
				  const char *name, const char *name2,
				  __u16 type, bool update, bool dec);
int lfsck_verify_linkea(const struct lu_env *env, struct dt_object *obj,
			const struct lu_name *cname, const struct lu_fid *pfid);
int lfsck_links_get_first(const struct lu_env *env, struct dt_object *obj,
			  char *name, struct lu_fid *pfid);
int lfsck_update_name_entry(const struct lu_env *env,
			    struct lfsck_instance *lfsck,
			    struct dt_object *dir, const char *name,
			    const struct lu_fid *fid, __u32 type);
int lfsck_namespace_setup(const struct lu_env *env,
			  struct lfsck_instance *lfsck);

/* lfsck_striped_dir.c */
void lfsck_lmv_put(const struct lu_env *env, struct lfsck_lmv *llmv);
int lfsck_read_stripe_lmv(const struct lu_env *env,
			  struct lfsck_instance *lfsck,
			  struct dt_object *obj,
			  struct lmv_mds_md_v1 *lmv);
int lfsck_shard_name_to_index(const struct lu_env *env, const char *name,
			      int namelen, __u16 type,
			      const struct lu_fid *fid);
bool lfsck_is_valid_slave_name_entry(const struct lu_env *env,
				     struct lfsck_lmv *llmv,
				     const char *name, int namelen);
int lfsck_namespace_check_name(const struct lu_env *env,
			       struct lfsck_instance *lfsck,
			       struct dt_object *parent,
			       struct dt_object *child,
			       const struct lu_name *cname);
int lfsck_namespace_update_lmv(const struct lu_env *env,
			       struct lfsck_component *com,
			       struct dt_object *obj,
			       struct lmv_mds_md_v1 *lmv, bool locked);
int lfsck_namespace_verify_stripe_slave(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *obj,
					struct lfsck_lmv *llmv);
int lfsck_namespace_scan_shard(const struct lu_env *env,
			       struct lfsck_component *com,
			       struct dt_object *child);
int lfsck_namespace_notify_lmv_master_local(const struct lu_env *env,
					    struct lfsck_component *com,
					    struct dt_object *obj);
int lfsck_namespace_repair_bad_name_hash(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct dt_object *shard,
					 struct lfsck_lmv *llmv,
					 const char *name);
int lfsck_namespace_striped_dir_rescan(const struct lu_env *env,
				       struct lfsck_component *com,
				       struct lfsck_namespace_req *lnr);
int lfsck_namespace_handle_striped_master(const struct lu_env *env,
					  struct lfsck_component *com,
					  struct lfsck_namespace_req *lnr);

/* lfsck_layout.c */
int lfsck_layout_setup(const struct lu_env *env, struct lfsck_instance *lfsck);

extern const char dot[];
extern const char dotdot[];
extern const char *const lfsck_flags_names[];
extern const char *const lfsck_param_names[];
extern struct lu_context_key lfsck_thread_key;

static inline struct dt_device *lfsck_obj2dev(struct dt_object *obj)
{
	return container_of_safe(obj->do_lu.lo_dev, struct dt_device,
				 dd_lu_dev);
}

static inline struct lfsck_thread_info *
lfsck_env_info(const struct lu_env *env)
{
	struct lfsck_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &lfsck_thread_key);
	LASSERT(info != NULL);
	return info;
}

static inline const struct lu_name *
lfsck_name_get_const(const struct lu_env *env, const void *area, ssize_t len)
{
	struct lu_name *lname;

	lname = &lfsck_env_info(env)->lti_name_const;
	lname->ln_name = area;
	lname->ln_namelen = len;
	return lname;
}

static inline void
lfsck_buf_init(struct lu_buf *buf, void *area, ssize_t len)
{
	buf->lb_buf = area;
	buf->lb_len = len;
}

static inline struct lu_buf *
lfsck_buf_get(const struct lu_env *env, void *area, ssize_t len)
{
	struct lu_buf *buf;

	buf = &lfsck_env_info(env)->lti_buf;
	buf->lb_buf = area;
	buf->lb_len = len;
	return buf;
}

static inline const struct lu_buf *
lfsck_buf_get_const(const struct lu_env *env, const void *area, ssize_t len)
{
	struct lu_buf *buf;

	buf = &lfsck_env_info(env)->lti_buf;
	buf->lb_buf = (void *)area;
	buf->lb_len = len;
	return buf;
}

static inline char *lfsck_lfsck2name(struct lfsck_instance *lfsck)
{
	return lfsck->li_bottom->dd_lu_dev.ld_obd->obd_name;
}

static inline const struct lu_fid *lfsck_dto2fid(const struct dt_object *obj)
{
	return lu_object_fid(&obj->do_lu);
}

static inline void lfsck_pos_set_zero(struct lfsck_position *pos)
{
	memset(pos, 0, sizeof(*pos));
}

static inline int lfsck_pos_is_zero(const struct lfsck_position *pos)
{
	return pos->lp_oit_cookie == 0 && fid_is_zero(&pos->lp_dir_parent);
}

static inline int lfsck_pos_is_eq(const struct lfsck_position *pos1,
				  const struct lfsck_position *pos2)
{
	if (pos1->lp_oit_cookie < pos2->lp_oit_cookie)
		return -1;

	if (pos1->lp_oit_cookie > pos2->lp_oit_cookie)
		return 1;

	if (fid_is_zero(&pos1->lp_dir_parent) &&
	    !fid_is_zero(&pos2->lp_dir_parent))
		return -1;

	if (!fid_is_zero(&pos1->lp_dir_parent) &&
	    fid_is_zero(&pos2->lp_dir_parent))
		return 1;

	if (fid_is_zero(&pos1->lp_dir_parent) &&
	    fid_is_zero(&pos2->lp_dir_parent))
		return 0;

	LASSERT(lu_fid_eq(&pos1->lp_dir_parent, &pos2->lp_dir_parent));

	if (pos1->lp_dir_cookie < pos2->lp_dir_cookie)
		return -1;

	if (pos1->lp_dir_cookie > pos2->lp_dir_cookie)
		return 1;

	return 0;
}

static void inline lfsck_position_le_to_cpu(struct lfsck_position *des,
					    struct lfsck_position *src)
{
	des->lp_oit_cookie = le64_to_cpu(src->lp_oit_cookie);
	fid_le_to_cpu(&des->lp_dir_parent, &src->lp_dir_parent);
	des->lp_dir_cookie = le64_to_cpu(src->lp_dir_cookie);
}

static void inline lfsck_position_cpu_to_le(struct lfsck_position *des,
					    struct lfsck_position *src)
{
	des->lp_oit_cookie = cpu_to_le64(src->lp_oit_cookie);
	fid_cpu_to_le(&des->lp_dir_parent, &src->lp_dir_parent);
	des->lp_dir_cookie = cpu_to_le64(src->lp_dir_cookie);
}

static inline umode_t lfsck_object_type(const struct dt_object *obj)
{
	return lu_object_attr(&obj->do_lu);
}

static inline int lfsck_is_dead_obj(const struct dt_object *obj)
{
	return lu_object_is_dying(obj->do_lu.lo_header);
}

static inline struct dt_object *lfsck_object_get(struct dt_object *obj)
{
	lu_object_get(&obj->do_lu);
	return obj;
}

static inline void lfsck_object_put(const struct lu_env *env,
				    struct dt_object *obj)
{
	dt_object_put(env, obj);
}

static inline struct seq_server_site
*lfsck_dev_site(struct lfsck_instance *lfsck)
{
	return lu_site2seq(lfsck->li_bottom->dd_lu_dev.ld_site);
}

static inline u32 lfsck_dev_idx(struct lfsck_instance *lfsck)
{
	return lfsck_dev_site(lfsck)->ss_node_id;
}

static inline struct dt_object *
lfsck_object_find_by_dev_new(const struct lu_env *env, struct dt_device *dev,
			     const struct lu_fid *fid)
{
	struct lu_object_conf	*conf = &lfsck_env_info(env)->lti_conf;

	conf->loc_flags = LOC_F_NEW;
	return lu2dt(lu_object_find_slice(env, dt2lu_dev(dev), fid, conf));
}

static inline struct dt_object *
lfsck_object_find_by_dev(const struct lu_env *env, struct dt_device *dev,
			 const struct lu_fid *fid)
{
	return lu2dt(lu_object_find_slice(env, dt2lu_dev(dev), fid, NULL));
}

static inline struct dt_device *
lfsck_find_dev_by_fid(const struct lu_env *env, struct lfsck_instance *lfsck,
		      const struct lu_fid *fid)
{
	struct dt_device *dev;
	int		  idx;

	if (!lfsck->li_master)
		return lfsck->li_bottom;

	idx = lfsck_find_mdt_idx_by_fid(env, lfsck, fid);
	if (idx < 0)
		return ERR_PTR(idx);

	if (idx == lfsck_dev_idx(lfsck)) {
		dev = lfsck->li_bottom;
	} else {
		struct lfsck_tgt_desc *ltd;

		ltd = lfsck_ltd2tgt(&lfsck->li_mdt_descs, idx);
		if (unlikely(ltd == NULL))
			return ERR_PTR(-ENODEV);

		dev = ltd->ltd_tgt;
	}

	return dev;
}

static inline struct dt_object *
lfsck_object_find_bottom(const struct lu_env *env, struct lfsck_instance *lfsck,
			 const struct lu_fid *fid)
{
	struct dt_device *dev;

	dev = lfsck_find_dev_by_fid(env, lfsck, fid);
	if (IS_ERR(dev))
		return (struct dt_object *)dev;

	return lfsck_object_find_by_dev(env, dev, fid);
}

static inline struct dt_object *
lfsck_object_find_bottom_new(const struct lu_env *env,
			     struct lfsck_instance *lfsck,
			     const struct lu_fid *fid)
{
	struct dt_device *dev;

	dev = lfsck_find_dev_by_fid(env, lfsck, fid);
	if (IS_ERR(dev))
		return (struct dt_object *)dev;

	return lfsck_object_find_by_dev_new(env, dev, fid);
}

static inline struct dt_object *
lfsck_object_locate(struct dt_device *dev, struct dt_object *obj)
{
	if (lfsck_obj2dev(obj) == dev) {
		return obj;
	} else {
		struct lu_object *lo;

		lo = lu_object_locate(obj->do_lu.lo_header,
				      dev->dd_lu_dev.ld_type);
		if (unlikely(lo == NULL))
			return ERR_PTR(-ENOENT);

		return lu2dt(lo);
	}
}

static inline struct lfsck_tgt_desc *lfsck_tgt_get(struct lfsck_tgt_descs *ltds,
						   __u32 index)
{
	struct lfsck_tgt_desc *ltd;

	ltd = lfsck_ltd2tgt(ltds, index);
	if (ltd != NULL)
		atomic_inc(&ltd->ltd_ref);

	return ltd;
}

static inline void lfsck_tgt_put(struct lfsck_tgt_desc *ltd)
{
	if (atomic_dec_and_test(&ltd->ltd_ref))
		OBD_FREE_PTR(ltd);
}

static inline struct lfsck_component *
lfsck_component_get(struct lfsck_component *com)
{
	atomic_inc(&com->lc_ref);

	return com;
}

static inline void lfsck_component_put(const struct lu_env *env,
				       struct lfsck_component *com)
{
	if (atomic_dec_and_test(&com->lc_ref)) {
		struct lfsck_sub_trace_obj *lsto;
		int			    i;

		for (i = 0, lsto = &com->lc_sub_trace_objs[0];
		     i < LFSCK_STF_COUNT; i++, lsto++) {
			if (lsto->lsto_obj != NULL)
				lfsck_object_put(env, lsto->lsto_obj);
		}

		if (com->lc_obj != NULL)
			lfsck_object_put(env, com->lc_obj);
		if (com->lc_file_ram != NULL)
			OBD_FREE(com->lc_file_ram, com->lc_file_size);
		if (com->lc_file_disk != NULL)
			OBD_FREE(com->lc_file_disk, com->lc_file_size);
		if (com->lc_data != NULL) {
			LASSERT(com->lc_ops->lfsck_data_release != NULL);

			com->lc_ops->lfsck_data_release(env, com);
		}

		OBD_FREE_PTR(com);
	}
}

static inline struct lfsck_instance *
lfsck_instance_get(struct lfsck_instance *lfsck)
{
	atomic_inc(&lfsck->li_ref);

	return lfsck;
}

static inline void lfsck_instance_put(const struct lu_env *env,
				      struct lfsck_instance *lfsck)
{
	if (atomic_dec_and_test(&lfsck->li_ref))
		lfsck_instance_cleanup(env, lfsck);
}

static inline bool lfsck_phase2_next_ready(struct lfsck_assistant_data *lad)
{
	return list_empty(&lad->lad_mdt_phase1_list) &&
	       (!list_empty(&lad->lad_ost_phase2_list) ||
		list_empty(&lad->lad_ost_phase1_list));
}

static inline void lfsck_lad_set_bitmap(const struct lu_env *env,
					struct lfsck_component *com,
					__u32 index)
{
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct cfs_bitmap		*bitmap	= lad->lad_bitmap;

	LASSERT(com->lc_lfsck->li_master);
	LASSERT(bitmap != NULL);

	if (likely(bitmap->size > index)) {
		cfs_bitmap_set(bitmap, index);
		set_bit(LAD_INCOMPLETE, &lad->lad_flags);
	} else if (com->lc_type == LFSCK_TYPE_NAMESPACE) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCOMPLETE;
	}

	CDEBUG(D_LFSCK, "%s: %s LFSCK set bitmap (%p/%u) for idx %u\n",
	       lfsck_lfsck2name(com->lc_lfsck), lad->lad_name, bitmap,
	       bitmap->size, index);
}

static inline int lfsck_links_read(const struct lu_env *env,
				   struct dt_object *obj,
				   struct linkea_data *ldata)
{
	ldata->ld_buf =
		lu_buf_check_and_alloc(&lfsck_env_info(env)->lti_linkea_buf,
				       MAX_LINKEA_SIZE);

	return __lfsck_links_read(env, obj, ldata, false);
}

/* Read linkEA for the given object, the linkEA should contain
 * at least one entry, otherwise, -ENODATA will be returned. */
static inline int lfsck_links_read_with_rec(const struct lu_env *env,
					    struct dt_object *obj,
					    struct linkea_data *ldata)
{
	ldata->ld_buf =
		lu_buf_check_and_alloc(&lfsck_env_info(env)->lti_linkea_buf,
				       MAX_LINKEA_SIZE);

	return __lfsck_links_read(env, obj, ldata, true);
}

static inline int lfsck_links_read2_with_rec(const struct lu_env *env,
					     struct dt_object *obj,
					     struct linkea_data *ldata)
{
	ldata->ld_buf =
		lu_buf_check_and_alloc(&lfsck_env_info(env)->lti_linkea_buf2,
				       MAX_LINKEA_SIZE);

	return __lfsck_links_read(env, obj, ldata, true);
}

static inline struct lfsck_lmv *lfsck_lmv_get(struct lfsck_lmv *llmv)
{
	if (llmv != NULL)
		atomic_inc(&llmv->ll_ref);

	return llmv;
}

static inline int lfsck_sub_trace_file_fid2idx(const struct lu_fid *fid)
{
	return fid->f_oid & (LFSCK_STF_COUNT - 1);
}

static inline void lfsck_lmv_header_le_to_cpu(struct lmv_mds_md_v1 *dst,
					      const struct lmv_mds_md_v1 *src)
{
	dst->lmv_magic = le32_to_cpu(src->lmv_magic);
	dst->lmv_stripe_count = le32_to_cpu(src->lmv_stripe_count);
	dst->lmv_master_mdt_index = le32_to_cpu(src->lmv_master_mdt_index);
	dst->lmv_hash_type = le32_to_cpu(src->lmv_hash_type);
	dst->lmv_layout_version = le32_to_cpu(src->lmv_layout_version);
	dst->lmv_migrate_offset = le32_to_cpu(src->lmv_migrate_offset);
	dst->lmv_migrate_hash = le32_to_cpu(src->lmv_migrate_hash);
}

static inline void lfsck_lmv_header_cpu_to_le(struct lmv_mds_md_v1 *dst,
					      const struct lmv_mds_md_v1 *src)
{
	dst->lmv_magic = cpu_to_le32(src->lmv_magic);
	dst->lmv_stripe_count = cpu_to_le32(src->lmv_stripe_count);
	dst->lmv_master_mdt_index = cpu_to_le32(src->lmv_master_mdt_index);
	dst->lmv_hash_type = cpu_to_le32(src->lmv_hash_type);
	dst->lmv_layout_version = cpu_to_le32(src->lmv_layout_version);
	dst->lmv_migrate_offset = cpu_to_le32(src->lmv_migrate_offset);
	dst->lmv_migrate_hash = cpu_to_le32(src->lmv_migrate_hash);
}

static inline struct lfsck_assistant_object *
lfsck_assistant_object_get(struct lfsck_assistant_object *lso)
{
	atomic_inc(&lso->lso_ref);

	return lso;
}

static inline void
lfsck_assistant_object_put(const struct lu_env *env,
			   struct lfsck_assistant_object *lso)
{
	if (atomic_dec_and_test(&lso->lso_ref))
		OBD_FREE_PTR(lso);
}
#endif /* _LFSCK_INTERNAL_H */
