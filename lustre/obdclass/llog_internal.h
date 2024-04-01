/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LLOG_INTERNAL_H__
#define __LLOG_INTERNAL_H__

#include <lustre_log.h>

struct llog_process_info {
	struct llog_handle	*lpi_loghandle;
	llog_cb_t		 lpi_cb;
	void			*lpi_cbdata;
	void			*lpi_catdata;
	int			 lpi_rc;
	struct completion	 lpi_completion;
	struct task_struct      *lpi_reftask;
};

struct llog_thread_info {
	struct lu_attr			 lgi_attr;
	struct lu_fid			 lgi_fid;
	struct dt_object_format		 lgi_dof;
	struct lu_buf			 lgi_buf;
	loff_t				 lgi_off;
	struct llog_logid_rec		 lgi_logid;
	struct dt_insert_rec		 lgi_dt_rec;
	struct lu_seq_range		 lgi_range;
	struct llog_cookie		 lgi_cookie;
	struct obd_statfs		 lgi_statfs;
	char				 lgi_name[32];
};

extern struct lu_context_key llog_thread_key;

static inline struct llog_thread_info *llog_info(const struct lu_env *env)
{
	struct llog_thread_info *lgi;

	lgi = lu_context_key_get(&env->le_ctx, &llog_thread_key);
	LASSERT(lgi);
	return lgi;
}

int llog_info_init(void);
void llog_info_fini(void);

struct llog_handle *llog_handle_get(struct llog_handle *loghandle);
int llog_handle_put(const struct lu_env *env, struct llog_handle *loghandle);
int llog_cat_id2handle(const struct lu_env *env, struct llog_handle *cathandle,
		       struct llog_handle **res, struct llog_logid *logid);
void llog_get_marker_cfg_flags(struct llog_rec_hdr *rec,
			       unsigned int *cfg_flags);
int class_config_dump_handler(const struct lu_env *env,
			      struct llog_handle *handle,
			      struct llog_rec_hdr *rec, void *data);
int class_config_yaml_output(struct llog_rec_hdr *rec, char *buf, int size,
			     unsigned int *cfg_flags, bool raw);
int llog_process_or_fork(const struct lu_env *env,
			 struct llog_handle *loghandle,
			 llog_cb_t cb, void *data, void *catdata, bool fork);
int llog_cat_cleanup(const struct lu_env *env, struct llog_handle *cathandle,
		     struct llog_handle *loghandle, int index);

static inline struct llog_rec_hdr *llog_rec_hdr_next(struct llog_rec_hdr *rec)
{
	return (struct llog_rec_hdr *)((char *)rec + rec->lrh_len);
}
int llog_verify_record(const struct llog_handle *llh, struct llog_rec_hdr *rec);
static inline char *loghandle2name(const struct llog_handle *lgh)
{
	return lgh->lgh_ctxt->loc_obd->obd_name;
}
#endif
