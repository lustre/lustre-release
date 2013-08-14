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
 * Copyright (c) 2012, Intel Corporation.
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
#include <lustre/lustre_idl.h>
#include <lu_target.h>
#include <lustre_export.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_req_layout.h>
#include <lustre_sec.h>

struct tx_arg;
typedef int (*tx_exec_func_t)(const struct lu_env *env, struct thandle *th,
			      struct tx_arg *ta);

struct tx_arg {
	tx_exec_func_t		 exec_fn;
	tx_exec_func_t		 undo_fn;
	struct dt_object	*object;
	char			*file;
	struct update_reply	*reply;
	int			 line;
	int			 index;
	union {
		struct {
			const struct dt_rec	*rec;
			const struct dt_key	*key;
		} insert;
		struct {
		} ref;
		struct {
			struct lu_attr	 attr;
		} attr_set;
		struct {
			struct lu_buf	 buf;
			const char	*name;
			int		 flags;
			__u32		 csum;
		} xattr_set;
		struct {
			struct lu_attr			attr;
			struct dt_allocation_hint	hint;
			struct dt_object_format		dof;
			struct lu_fid			fid;
		} create;
		struct {
			struct lu_buf	buf;
			loff_t		pos;
		} write;
		struct {
			struct ost_body	    *body;
		} destroy;
	} u;
};

#define TX_MAX_OPS	  10
struct thandle_exec_args {
	struct thandle		*ta_handle;
	struct dt_device	*ta_dev;
	int			 ta_err;
	struct tx_arg		 ta_args[TX_MAX_OPS];
	int			 ta_argno;   /* used args */
};

/**
 * Common data shared by tg-level handlers. This is allocated per-thread to
 * reduce stack consumption.
 */
struct tgt_thread_info {
	/* server and client data buffers */
	struct lr_server_data	 tti_lsd;
	struct lsd_client_data	 tti_lcd;
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
			struct dt_object_format	 tti_update_dof;
			struct update_reply	*tti_update_reply;
			struct update		*tti_update;
			int			 tti_update_reply_index;
			struct obdo		 tti_obdo;
			struct dt_object	*tti_dt_object;
		} update;
	} tti_u;
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

/* Update handlers */
int out_handle(struct tgt_session_info *tsi);

#define out_tx_create(info, obj, attr, fid, dof, th, reply, idx) \
	__out_tx_create(info, obj, attr, fid, dof, th, reply, idx, \
			__FILE__, __LINE__)

#define out_tx_attr_set(info, obj, attr, th, reply, idx) \
	__out_tx_attr_set(info, obj, attr, th, reply, idx, \
			  __FILE__, __LINE__)

#define out_tx_xattr_set(info, obj, buf, name, fl, th, reply, idx)	\
	__out_tx_xattr_set(info, obj, buf, name, fl, th, reply, idx,	\
			   __FILE__, __LINE__)

#define out_tx_ref_add(info, obj, th, reply, idx) \
	__out_tx_ref_add(info, obj, th, reply, idx, __FILE__, __LINE__)

#define out_tx_ref_del(info, obj, th, reply, idx) \
	__out_tx_ref_del(info, obj, th, reply, idx, __FILE__, __LINE__)

#define out_tx_index_insert(info, obj, th, name, fid, reply, idx) \
	__out_tx_index_insert(info, obj, th, name, fid, reply, idx, \
			      __FILE__, __LINE__)

#define out_tx_index_delete(info, obj, th, name, reply, idx) \
	__out_tx_index_delete(info, obj, th, name, reply, idx, \
			      __FILE__, __LINE__)

#define out_tx_destroy(info, obj, th, reply, idx) \
	__out_tx_destroy(info, obj, th, reply, idx, __FILE__, __LINE__)

extern struct page *tgt_page_to_corrupt;

struct tgt_thread_big_cache {
	struct niobuf_local	local[PTLRPC_MAX_BRW_PAGES];
};

int tgt_server_data_init(const struct lu_env *env, struct lu_target *tgt);
int tgt_txn_start_cb(const struct lu_env *env, struct thandle *th,
		     void *cookie);
int tgt_txn_stop_cb(const struct lu_env *env, struct thandle *th,
		    void *cookie);

#endif /* _TG_INTERNAL_H */
