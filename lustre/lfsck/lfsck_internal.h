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
 * lustre/lfsck/lfsck_internal.h
 *
 * Shared definitions and declarations for the LFSCK.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _LFSCK_INTERNAL_H
# define _LFSCK_INTERNAL_H

#include <lustre/lustre_lfsck_user.h>
#include <lustre/lustre_user.h>
#include <lustre/lustre_idl.h>
#include <lustre_lfsck.h>
#include <obd.h>
#include <lu_object.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <lustre_fid.h>
#include <md_object.h>

#define HALF_SEC			(HZ >> 1)
#define LFSCK_CHECKPOINT_INTERVAL	60

#define LFSCK_NAMEENTRY_DEAD    	1 /* The object has been unlinked. */
#define LFSCK_NAMEENTRY_REMOVED 	2 /* The entry has been removed. */
#define LFSCK_NAMEENTRY_RECREATED	3 /* The entry has been recreated. */

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

	/* For future using. */
	__u64	lb_reserved[6];
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
	__u32	ll_run_time_phase1;

	/*  How long the LFSCK phase2 has run in seconds. */
	__u32	ll_run_time_phase2;

	/* Time for the last LFSCK completed in seconds since epoch. */
	__u64	ll_time_last_complete;

	/* Time for the latest LFSCK ran in seconds since epoch. */
	__u64	ll_time_latest_start;

	/* Time for the last LFSCK checkpoint in seconds since epoch. */
	__u64	ll_time_last_checkpoint;

	/* Position for the latest LFSCK started from. */
	__u64	ll_pos_latest_start;

	/* Position for the last LFSCK checkpoint. */
	__u64	ll_pos_last_checkpoint;

	/* Position for the first should be updated object. */
	__u64	ll_pos_first_inconsistent;

	/* How many objects have been checked. */
	__u64	ll_objs_checked_phase1;

	/* How many objects failed to be processed. */
	__u64	ll_objs_failed_phase1;

	/* How many objects have been double scanned. */
	__u64	ll_objs_checked_phase2;

	/* How many objects failed to be processed during double scan. */
	__u64	ll_objs_failed_phase2;

	/* kinds of inconsistency have been repaired.
	 * ll_objs_repaired[type - 1] is the count for the given @type. */
	__u64	ll_objs_repaired[LLIT_MAX];

	/* How many objects have been skipped because of related
	 * MDT(s)/OST(s) do not participate in the LFSCK */
	__u64	ll_objs_skipped;

	/* For further using. 256-bytes aligned now. */
	__u64	ll_reserved[12];
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
			      struct dt_object *obj,
			      struct lu_dirent *ent);

	int (*lfsck_post)(const struct lu_env *env,
			  struct lfsck_component *com,
			  int result,
			  bool init);

	int (*lfsck_interpret)(const struct lu_env *env,
			       struct ptlrpc_request *req,
			       void *args,
			       int rc);

	int (*lfsck_dump)(const struct lu_env *env,
			  struct lfsck_component *com,
			  char *buf,
			  int len);

	int (*lfsck_double_scan)(const struct lu_env *env,
				 struct lfsck_component *com);

	void (*lfsck_data_release)(const struct lu_env *env,
				   struct lfsck_component *com);

	void (*lfsck_quit)(const struct lu_env *env,
			   struct lfsck_component *com);

	int (*lfsck_in_notify)(const struct lu_env *env,
			       struct lfsck_component *com,
			       struct lfsck_request *lr);

	int (*lfsck_query)(const struct lu_env *env,
			   struct lfsck_component *com);

	int (*lfsck_stop_notify)(const struct lu_env *env,
				 struct lfsck_component *com,
				 struct lfsck_tgt_descs *ltds,
				 struct lfsck_tgt_desc *ltd,
				 struct ptlrpc_request_set *set);

	int (*lfsck_join)(const struct lu_env *env,
			  struct lfsck_component *com,
			  struct lfsck_start_param *lsp);
};

#define TGT_PTRS		256     /* number of pointers at 1st level */
#define TGT_PTRS_PER_BLOCK	256     /* number of pointers at 2nd level */

struct lfsck_tgt_desc {
	struct list_head   ltd_orphan_list;
	struct dt_device  *ltd_tgt;
	struct dt_device  *ltd_key;
	struct obd_export *ltd_exp;
	struct list_head   ltd_layout_list;
	struct list_head   ltd_layout_phase_list;
	atomic_t	   ltd_ref;
	__u32              ltd_index;
	__u32		   ltd_layout_gen;
	unsigned int	   ltd_dead:1,
			   ltd_layout_done:1;
};

struct lfsck_tgt_desc_idx {
	struct lfsck_tgt_desc *ldi_tgts[TGT_PTRS_PER_BLOCK];
};

struct lfsck_tgt_descs {
	/* list of known TGTs */
	struct lfsck_tgt_desc_idx	*ltd_tgts_idx[TGT_PTRS];

	/* bitmap of TGTs available */
	cfs_bitmap_t			*ltd_tgts_bitmap;

	/* for lfsck_tgt_desc::ltd_xxx_list */
	spinlock_t			 ltd_lock;

	/* for tgts table accessing and changes */
	struct rw_semaphore		 ltd_rw_sem;

	/* Temporary list for orphan targets. */
	struct list_head		 ltd_orphan;

	/* number of registered TGTs */
	int				 ltd_tgtnr;
};

#define LTD_TGT(ltd, index)	\
	((ltd)->ltd_tgts_idx[(index) / TGT_PTRS_PER_BLOCK]->\
	 ldi_tgts[(index) % TGT_PTRS_PER_BLOCK])

#define OST_TGT(lfsck, index)   LTD_TGT(&lfsck->li_ost_descs, index)
#define MDT_TGT(lfsck, index)   LTD_TGT(&lfsck->li_mdt_descs, index)

struct lfsck_component {
	/* into lfsck_instance::li_list_(scan,double_scan,idle} */
	cfs_list_t		 lc_link;

	/* into lfsck_instance::li_list_dir */
	cfs_list_t		 lc_link_dir;

	struct rw_semaphore	 lc_sem;
	atomic_t		 lc_ref;

	struct lfsck_position	 lc_pos_start;
	struct lfsck_instance	*lc_lfsck;
	struct dt_object	*lc_obj;
	struct lfsck_operations *lc_ops;
	void			*lc_file_ram;
	void			*lc_file_disk;
	void			*lc_data;

	/* The time for last checkpoint, jiffies */
	cfs_time_t		 lc_time_last_checkpoint;

	/* The time for next checkpoint, jiffies */
	cfs_time_t		 lc_time_next_checkpoint;

	__u32			 lc_file_size;

	/* How many objects have been checked since last checkpoint. */
	__u32			 lc_new_checked;

	/* How many objects have been scanned since last sleep. */
	__u32			 lc_new_scanned;

	unsigned int		 lc_journal:1;
	__u16			 lc_type;
};

struct lfsck_instance {
	struct mutex		  li_mutex;
	spinlock_t		  li_lock;

	/* Link into the lfsck_instance_list. */
	cfs_list_t		  li_link;

	/* For the components in (first) scanning via otable-based iteration. */
	cfs_list_t		  li_list_scan;

	/* For the components in scanning via directory traversal. Because
	 * directory traversal cannot guarantee all the object be scanned,
	 * so the component in the li_list_dir must be in li_list_scan. */
	cfs_list_t		  li_list_dir;

	/* For the components in double scanning. */
	cfs_list_t		  li_list_double_scan;

	/* For the components those are not scanning now. */
	cfs_list_t		  li_list_idle;

	atomic_t		  li_ref;
	atomic_t		  li_double_scan_count;
	struct ptlrpc_thread	  li_thread;

	/* The time for last checkpoint, jiffies */
	cfs_time_t		  li_time_last_checkpoint;

	/* The time for next checkpoint, jiffies */
	cfs_time_t		  li_time_next_checkpoint;

	lfsck_out_notify	  li_out_notify;
	void			 *li_out_notify_data;
	struct dt_device	 *li_next;
	struct dt_device	 *li_bottom;
	struct obd_device	 *li_obd;
	struct ldlm_namespace	 *li_namespace;
	struct local_oid_storage *li_los;
	struct lu_fid		  li_local_root_fid;  /* backend root "/" */
	struct lu_fid		  li_global_root_fid; /* /ROOT */
	struct dt_object	 *li_bookmark_obj;
	struct lfsck_bookmark	  li_bookmark_ram;
	struct lfsck_bookmark	  li_bookmark_disk;
	struct lfsck_position	  li_pos_current;

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
				  li_start_unplug:1;
};

enum lfsck_linkea_flags {
	/* The linkea entries does not match the object nlinks. */
	LLF_UNMATCH_NLINKS	= 0x01,

	/* Fail to repair the multiple-linked objects during the double scan. */
	LLF_REPAIR_FAILED	= 0x02,
};

struct lfsck_async_interpret_args {
	struct lfsck_component		*laia_com;
	struct lfsck_tgt_descs		*laia_ltds;
	struct lfsck_tgt_desc		*laia_ltd;
	struct lfsck_request		*laia_lr;
	int				 laia_result;
	unsigned int			 laia_shared:1;
};

struct lfsck_thread_args {
	struct lu_env			 lta_env;
	struct lfsck_instance		*lta_lfsck;
	struct lfsck_component		*lta_com;
	struct lfsck_start_param	*lta_lsp;
};

struct lfsck_thread_info {
	struct lu_name		lti_name;
	struct lu_buf		lti_buf;
	struct lu_buf		lti_linkea_buf;
	struct lu_buf		lti_big_buf;
	struct lu_fid		lti_fid;
	struct lu_fid		lti_fid2;
	struct lu_attr		lti_la;
	struct lu_attr		lti_la2;
	struct lu_attr		lti_la3;
	struct ost_id		lti_oi;
	union {
		struct lustre_mdt_attrs lti_lma;
		/* old LMA for compatibility */
		char			lti_lma_old[LMA_OLD_SIZE];
	};
	struct dt_object_format lti_dof;
	/* lti_ent and lti_key must be conjoint,
	 * then lti_ent::lde_name will be lti_key. */
	struct lu_dirent	lti_ent;
	char			lti_key[NAME_MAX + 16];
	struct lfsck_request	lti_lr;
	struct lfsck_async_interpret_args lti_laia;
	struct lfsck_start	lti_start;
	struct lfsck_stop	lti_stop;
	ldlm_policy_data_t	lti_policy;
	struct ldlm_res_id	lti_resid;
	union {
		struct filter_fid_old	lti_old_pfid;
		struct filter_fid	lti_new_pfid;
	};
	struct dt_allocation_hint lti_hint;
};

/* lfsck_lib.c */
const char *lfsck_status2names(enum lfsck_status status);
void lfsck_component_cleanup(const struct lu_env *env,
			     struct lfsck_component *com);
void lfsck_instance_cleanup(const struct lu_env *env,
			    struct lfsck_instance *lfsck);
int lfsck_bits_dump(char **buf, int *len, int bits, const char *names[],
		    const char *prefix);
int lfsck_time_dump(char **buf, int *len, __u64 time, const char *prefix);
int lfsck_pos_dump(char **buf, int *len, struct lfsck_position *pos,
		   const char *prefix);
void lfsck_pos_fill(const struct lu_env *env, struct lfsck_instance *lfsck,
		    struct lfsck_position *pos, bool init);
void lfsck_control_speed(struct lfsck_instance *lfsck);
void lfsck_control_speed_by_self(struct lfsck_component *com);
int lfsck_reset(const struct lu_env *env, struct lfsck_instance *lfsck,
		bool init);
struct lfsck_thread_args *lfsck_thread_args_init(struct lfsck_instance *lfsck,
						 struct lfsck_component *com,
						 struct lfsck_start_param *lsp);
void lfsck_thread_args_fini(struct lfsck_thread_args *lta);
void lfsck_fail(const struct lu_env *env, struct lfsck_instance *lfsck,
		bool new_checked);
int lfsck_checkpoint(const struct lu_env *env, struct lfsck_instance *lfsck);
int lfsck_prep(const struct lu_env *env, struct lfsck_instance *lfsck,
	       struct lfsck_start_param *lsp);
int lfsck_exec_oit(const struct lu_env *env, struct lfsck_instance *lfsck,
		   struct dt_object *obj);
int lfsck_exec_dir(const struct lu_env *env, struct lfsck_instance *lfsck,
		   struct dt_object *obj, struct lu_dirent *ent);
int lfsck_post(const struct lu_env *env, struct lfsck_instance *lfsck,
	       int result);
int lfsck_double_scan(const struct lu_env *env, struct lfsck_instance *lfsck);
void lfsck_quit(const struct lu_env *env, struct lfsck_instance *lfsck);
int lfsck_async_request(const struct lu_env *env, struct obd_export *exp,
			struct lfsck_request *lr,
			struct ptlrpc_request_set *set,
			ptlrpc_interpterer_t interpterer,
			void *args, int request);

/* lfsck_engine.c */
int lfsck_master_engine(void *args);

/* lfsck_bookmark.c */
int lfsck_bookmark_store(const struct lu_env *env,
			 struct lfsck_instance *lfsck);
int lfsck_bookmark_setup(const struct lu_env *env,
			 struct lfsck_instance *lfsck);

/* lfsck_namespace.c */
int lfsck_namespace_setup(const struct lu_env *env,
			  struct lfsck_instance *lfsck);

/* lfsck_layout.c */
int lfsck_layout_setup(const struct lu_env *env, struct lfsck_instance *lfsck);

extern const char *lfsck_flags_names[];
extern const char *lfsck_param_names[];
extern struct lu_context_key lfsck_thread_key;

static inline struct dt_device *lfsck_obj2dt_dev(struct dt_object *obj)
{
	return container_of0(obj->do_lu.lo_dev, struct dt_device, dd_lu_dev);
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

	lname = &lfsck_env_info(env)->lti_name;
	lname->ln_name = area;
	lname->ln_namelen = len;
	return lname;
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
	struct lu_object_header *loh = obj->do_lu.lo_header;

	return !!test_bit(LU_OBJECT_HEARD_BANSHEE, &loh->loh_flags);
}

static inline struct dt_object *lfsck_object_find(const struct lu_env *env,
						  struct lfsck_instance *lfsck,
						  const struct lu_fid *fid)
{
	return lu2dt(lu_object_find_slice(env, dt2lu_dev(lfsck->li_next),
		     fid, NULL));
}

static inline struct dt_object *lfsck_object_get(struct dt_object *obj)
{
	lu_object_get(&obj->do_lu);
	return obj;
}

static inline void lfsck_object_put(const struct lu_env *env,
				    struct dt_object *obj)
{
	lu_object_put(env, &obj->do_lu);
}

static inline struct dt_object *
lfsck_object_find_by_dev(const struct lu_env *env, struct dt_device *dev,
			 const struct lu_fid *fid)
{
	struct dt_object *obj;

	obj = lu2dt(lu_object_find_slice(env, dt2lu_dev(dev), fid, NULL));
	if (unlikely(obj == NULL))
		return ERR_PTR(-ENOENT);

	return obj;
}

static inline struct lfsck_tgt_desc *lfsck_tgt_get(struct lfsck_tgt_descs *ltds,
						   __u32 index)
{
	struct lfsck_tgt_desc *ltd;

	ltd = LTD_TGT(ltds, index);
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
		if (com->lc_obj != NULL)
			lu_object_put_nocache(env, &com->lc_obj->do_lu);
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

static inline mdsno_t lfsck_dev_idx(struct dt_device *dev)
{
	return dev->dd_lu_dev.ld_site->ld_seq_site->ss_node_id;
}

#endif /* _LFSCK_INTERNAL_H */
