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

extern struct lu_context_key tgt_thread_key;

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
};

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

#endif /* _TG_INTERNAL_H */
