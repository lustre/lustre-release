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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * lustre/target/tgt_internal.h
 *
 * Lustre Unified Target header file
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#ifndef _TG_INTERNAL_H
#define _TG_INTERNAL_H

#include <lustre_net.h>
#include <lu_target.h>
#include <lustre_export.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_req_layout.h>
#include <lustre_sec.h>

extern int (*tgt_lfsck_in_notify_local)(const struct lu_env *env,
					struct dt_device *key,
					struct lfsck_req_local *lrl,
					struct thandle *th);
/**
 * Common data shared by tg-level handlers. This is allocated per-thread to
 * reduce stack consumption.
 */
struct tgt_thread_info {
	/* server and client data buffers */
	struct lr_server_data	 tti_lsd;
	struct lsd_client_data	 tti_lcd;
	struct lsd_reply_data	 tti_lrd;
	struct lu_buf		 tti_buf;
	loff_t			 tti_off;

	struct lu_attr		 tti_attr;
	struct lu_fid		 tti_fid1;

	/* transno storage during last_rcvd update */
	__u64			 tti_transno;
	__u32			 tti_has_trans:1,
				 tti_mult_trans:1;

	/* Updates data for OUT target */
	struct thandle_exec_args tti_tea;
	union {
		struct {
			/* for tgt_readpage()      */
			struct lu_rdpg     tti_rdpg;
			/* for tgt_sendpage()      */
			struct l_wait_info tti_wait_info;
		} rdpg;
		struct {
			struct dt_object_format	   tti_update_dof;
			struct object_update_reply *tti_update_reply;
			struct object_update	   *tti_update;
			int			   tti_update_reply_index;
			struct obdo		   tti_obdo;
			struct dt_object	   *tti_dt_object;
			struct l_wait_info tti_wait_info;
		} update;
		struct obd_statfs osfs; /* for obd_statfs() in OFD/MDT */
	} tti_u;
	struct lfsck_req_local tti_lrl;
	struct dt_insert_rec tti_rec;
};

extern struct lu_context_key tgt_thread_key;

static inline struct tgt_thread_info *tgt_th_info(const struct lu_env *env)
{
	struct tgt_thread_info *tti;

	tti = lu_context_key_get(&env->le_ctx, &tgt_thread_key);
	LASSERT(tti);
	return tti;
}

#define MGS_SERVICE_WATCHDOG_FACTOR      (2)

int tgt_request_handle(struct ptlrpc_request *req);

/* check if request's xid is equal to last one or not*/
static inline int req_xid_is_last(struct ptlrpc_request *req)
{
	struct lsd_client_data *lcd = req->rq_export->exp_target_data.ted_lcd;

	LASSERT(lcd != NULL);
	return (req->rq_xid == lcd->lcd_last_xid ||
		req->rq_xid == lcd->lcd_last_close_xid);
}

static inline char *dt_obd_name(struct dt_device *dt)
{
	return dt->dd_lu_dev.ld_obd->obd_name;
}

/* out_lib.c */
int out_tx_create_exec(const struct lu_env *env, struct thandle *th,
		       struct tx_arg *arg);
struct tx_arg *tx_add_exec(struct thandle_exec_args *ta,
			   tx_exec_func_t func, tx_exec_func_t undo,
			   const char *file, int line);

int out_create_add_exec(const struct lu_env *env, struct dt_object *obj,
			struct lu_attr *attr, struct lu_fid *parent_fid,
			struct dt_object_format *dof,
			struct thandle_exec_args *ta, struct thandle *th,
			struct object_update_reply *reply,
			int index, const char *file, int line);

int out_attr_set_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			  const struct lu_attr *attr,
			  struct thandle_exec_args *ta, struct thandle *th,
			  struct object_update_reply *reply, int index,
			  const char *file, int line);

int out_write_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
		       const struct lu_buf *buf, loff_t pos,
		       struct thandle_exec_args *ta, struct thandle *th,
		       struct object_update_reply *reply, int index,
		       const char *file, int line);

int out_xattr_set_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			   const struct lu_buf *buf, const char *name,
			   int flags, struct thandle_exec_args *ta,
			   struct thandle *th,
			   struct object_update_reply *reply, int index,
			   const char *file, int line);

int out_xattr_del_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			   const char *name, struct thandle_exec_args *ta,
			   struct thandle *th,
			   struct object_update_reply *reply, int index,
			   const char *file, int line);

int out_ref_add_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			 struct thandle_exec_args *ta, struct thandle *th,
			 struct object_update_reply *reply, int index,
			 const char *file, int line);

int out_ref_del_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			 struct thandle_exec_args *ta, struct thandle *th,
			 struct object_update_reply *reply, int index,
			 const char *file, int line);

int out_index_insert_add_exec(const struct lu_env *env,
			      struct dt_object *dt_obj,
			      const struct dt_rec *rec,
			      const struct dt_key *key,
			      struct thandle_exec_args *ta,
			      struct thandle *th,
			      struct object_update_reply *reply,
			      int index, const char *file, int line);

int out_index_delete_add_exec(const struct lu_env *env,
			      struct dt_object *dt_obj,
			      const struct dt_key *key,
			      struct thandle_exec_args *ta,
			      struct thandle *th,
			      struct object_update_reply *reply,
			      int index, const char *file, int line);

int out_destroy_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			 struct thandle_exec_args *ta, struct thandle *th,
			 struct object_update_reply *reply,
			 int index, const char *file, int line);

/* Update handlers */
int out_handle(struct tgt_session_info *tsi);

#define out_tx_create(env, obj, attr, fid, dof, ta, th, reply, idx) \
	out_create_add_exec(env, obj, attr, fid, dof, ta, th, reply, idx, \
			    __FILE__, __LINE__)

#define out_tx_attr_set(env, obj, attr, ta, th, reply, idx) \
	out_attr_set_add_exec(env, obj, attr, ta, th, reply, idx, \
			      __FILE__, __LINE__)

#define out_tx_xattr_set(env, obj, buf, name, fl, ta, th, reply, idx)	\
	out_xattr_set_add_exec(env, obj, buf, name, fl, ta, th, reply, idx, \
			       __FILE__, __LINE__)

#define out_tx_xattr_del(env, obj, name, ta, th, reply, idx)	\
	out_xattr_del_add_exec(env, obj, name, ta, th, reply, idx,	\
			       __FILE__, __LINE__)

#define out_tx_ref_add(env, obj, ta, th, reply, idx) \
	out_ref_add_add_exec(env, obj, ta, th, reply, idx,	\
			     __FILE__, __LINE__)

#define out_tx_ref_del(env, obj, ta, th, reply, idx) \
	out_ref_del_add_exec(env, obj, ta, th, reply, idx,	\
			     __FILE__, __LINE__)

#define out_tx_index_insert(env, obj, rec, key, ta, th, reply, idx) \
	out_index_insert_add_exec(env, obj, rec, key, ta, th, reply, idx, \
				  __FILE__, __LINE__)

#define out_tx_index_delete(env, obj, key, ta, th, reply, idx) \
	out_index_delete_add_exec(env, obj, key, ta, th, reply, idx, \
				  __FILE__, __LINE__)

#define out_tx_destroy(env, obj, ta, th, reply, idx) \
	out_destroy_add_exec(env, obj, ta, th, reply, idx,	\
			     __FILE__, __LINE__)

#define out_tx_write(env, obj, buf, pos, ta, th, reply, idx) \
	out_write_add_exec(env, obj, buf, pos, ta, th, reply, idx,\
			   __FILE__, __LINE__)

const char *update_op_str(__u16 opcode);

extern struct page *tgt_page_to_corrupt;

int tgt_server_data_init(const struct lu_env *env, struct lu_target *tgt);
int tgt_txn_start_cb(const struct lu_env *env, struct thandle *th,
		     void *cookie);
int tgt_txn_stop_cb(const struct lu_env *env, struct thandle *th,
		    void *cookie);
int tgt_handle_received_xid(struct obd_export *exp, __u64 rcvd_xid);
int tgt_handle_tag(struct obd_export *exp, __u16 tag);

void update_records_dump(const struct update_records *records,
			 unsigned int mask, bool dump_updates);
int check_and_prepare_update_record(const struct lu_env *env,
				    struct thandle_update_records *tur);
struct update_thread_info {
	struct lu_attr			uti_attr;
	struct lu_fid			uti_fid;
	struct lu_buf			uti_buf;
	struct thandle_update_records	uti_tur;
	struct obdo			uti_obdo;
	struct thandle_exec_args	uti_tea;
	struct dt_insert_rec		uti_rec;
	struct distribute_txn_replay_req *uti_dtrq;
};

extern struct lu_context_key update_thread_key;

static inline struct update_thread_info *
update_env_info(const struct lu_env *env)
{
	struct update_thread_info *uti;

	uti = lu_context_key_get(&env->le_ctx, &update_thread_key);
	LASSERT(uti != NULL);
	return uti;
}

void update_info_init(void);
void update_info_fini(void);
struct sub_thandle *create_sub_thandle(struct top_multiple_thandle *tmt,
				       struct dt_device *dt_dev);
int sub_thandle_trans_create(const struct lu_env *env,
			     struct top_thandle *top_th,
			     struct sub_thandle *st);
void distribute_txn_insert_by_batchid(struct top_multiple_thandle *new);
int top_trans_create_tmt(const struct lu_env *env,
			 struct top_thandle *top_th);

void tgt_cancel_slc_locks(struct lu_target *tgt, __u64 transno);
void barrier_init(void);
void barrier_fini(void);

/* FMD tracking data */
struct tgt_fmd_data {
	struct list_head fmd_list;	  /* linked to tgt_fmd_list */
	struct lu_fid	 fmd_fid;	  /* FID being written to */
	__u64		 fmd_mactime_xid; /* xid highest {m,a,c}time setattr */
	time64_t	 fmd_expire;	  /* time when the fmd should expire */
	int		 fmd_refcount;	  /* reference counter - list holds 1 */
};

/* tgt_fmd.c */
extern struct kmem_cache *tgt_fmd_kmem;
void tgt_fmd_expire(struct obd_export *exp);
void tgt_fmd_cleanup(struct obd_export *exp);

#endif /* _TG_INTERNAL_H */
