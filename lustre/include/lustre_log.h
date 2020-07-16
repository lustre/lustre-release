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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/include/lustre_log.h
 *
 * Generic infrastructure for managing a collection of logs.
 * These logs are used for:
 *
 * - orphan recovery: OST adds record on create
 * - mtime/size consistency: the OST adds a record on first write
 * - open/unlinked objects: OST adds a record on destroy
 *
 * - mds unlink log: the MDS adds an entry upon delete
 *
 * - raid1 replication log between OST's
 * - MDS replication logs
 */

#ifndef _LUSTRE_LOG_H
#define _LUSTRE_LOG_H

/** \defgroup log log
 *
 * @{
 */

#include <obd_class.h>
#include <dt_object.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_log_user.h>

#define LOG_NAME_LIMIT(logname, name)                   \
        snprintf(logname, sizeof(logname), "LOGS/%s", name)
#define LLOG_EEMPTY 4711

enum llog_open_param {
	LLOG_OPEN_EXISTS	= 0x0000,
	LLOG_OPEN_NEW		= 0x0001,
};

struct plain_handle_data {
	struct list_head	phd_entry;
	struct llog_handle	*phd_cat_handle;
	/* cookie of this log in its cat */
	struct llog_cookie	phd_cookie;
};

struct cat_handle_data {
	struct list_head	chd_head;
	struct llog_handle     *chd_current_log;/* currently open log */
	struct llog_handle     *chd_next_log;	/* llog to be used next */
};

struct llog_handle;

/* llog.c  -  general API */
int llog_init_handle(const struct lu_env *env, struct llog_handle *handle,
		     int flags, struct obd_uuid *uuid);
int llog_copy_handler(const struct lu_env *env, struct llog_handle *llh,
		      struct llog_rec_hdr *rec, void *data);
int llog_process(const struct lu_env *env, struct llog_handle *loghandle,
		 llog_cb_t cb, void *data, void *catdata);
int llog_process_or_fork(const struct lu_env *env,
			 struct llog_handle *loghandle,
			 llog_cb_t cb, void *data, void *catdata, bool fork);
int llog_reverse_process(const struct lu_env *env,
			 struct llog_handle *loghandle, llog_cb_t cb,
			 void *data, void *catdata);
int llog_cancel_rec(const struct lu_env *env, struct llog_handle *loghandle,
		    int index);
int llog_cancel_arr_rec(const struct lu_env *env, struct llog_handle *loghandle,
		    int num, int *index);
int llog_open(const struct lu_env *env, struct llog_ctxt *ctxt,
	      struct llog_handle **lgh, struct llog_logid *logid,
	      char *name, enum llog_open_param open_param);
int llog_close(const struct lu_env *env, struct llog_handle *cathandle);
int llog_is_empty(const struct lu_env *env, struct llog_ctxt *ctxt,
		  char *name);
int llog_backup(const struct lu_env *env, struct obd_device *obd,
		struct llog_ctxt *ctxt, struct llog_ctxt *bak_ctxt,
		char *name, char *backup);
int llog_read_header(const struct lu_env *env, struct llog_handle *handle,
		     const struct obd_uuid *uuid);
__u64 llog_size(const struct lu_env *env, struct llog_handle *llh);

/* llog_process flags */
#define LLOG_FLAG_NODEAMON 0x0001

/* llog_cat.c - catalog api */
struct llog_process_data {
        /**
         * Any useful data needed while processing catalog. This is
         * passed later to process callback.
         */
        void                *lpd_data;
        /**
         * Catalog process callback function, called for each record
         * in catalog.
         */
        llog_cb_t            lpd_cb;
        /**
         * Start processing the catalog from startcat/startidx
         */
        int                  lpd_startcat;
        int                  lpd_startidx;
};

struct llog_process_cat_data {
        /**
         * Temporary stored first_idx while scanning log.
         */
        int                  lpcd_first_idx;
        /**
         * Temporary stored last_idx while scanning log.
         */
        int                  lpcd_last_idx;
};

int llog_cat_close(const struct lu_env *env, struct llog_handle *cathandle);
int llog_cat_add_rec(const struct lu_env *env, struct llog_handle *cathandle,
		     struct llog_rec_hdr *rec, struct llog_cookie *reccookie,
		     struct thandle *th);
int llog_cat_declare_add_rec(const struct lu_env *env,
			     struct llog_handle *cathandle,
			     struct llog_rec_hdr *rec, struct thandle *th);
int llog_cat_add(const struct lu_env *env, struct llog_handle *cathandle,
		 struct llog_rec_hdr *rec, struct llog_cookie *reccookie);
int llog_cat_cancel_arr_rec(const struct lu_env *env,
			    struct llog_handle *cathandle,
			    struct llog_logid *lgl, int count, int *index);
int llog_cat_cancel_records(const struct lu_env *env,
			    struct llog_handle *cathandle, int count,
			    struct llog_cookie *cookies);
int llog_cat_process_or_fork(const struct lu_env *env,
			     struct llog_handle *cat_llh, llog_cb_t cat_cb,
			     llog_cb_t cb, void *data, int startcat,
			     int startidx, bool fork);
int llog_cat_process(const struct lu_env *env, struct llog_handle *cat_llh,
		     llog_cb_t cb, void *data, int startcat, int startidx);
__u64 llog_cat_size(const struct lu_env *env, struct llog_handle *cat_llh);
__u32 llog_cat_free_space(struct llog_handle *cat_llh);
int llog_cat_reverse_process(const struct lu_env *env,
			     struct llog_handle *cat_llh, llog_cb_t cb,
			     void *data);
/* llog_obd.c */
int llog_setup(const struct lu_env *env, struct obd_device *obd,
	       struct obd_llog_group *olg, int index,
	       struct obd_device *disk_obd, const struct llog_operations *op);
int __llog_ctxt_put(const struct lu_env *env, struct llog_ctxt *ctxt);
int llog_cleanup(const struct lu_env *env, struct llog_ctxt *);
int llog_sync(struct llog_ctxt *ctxt, struct obd_export *exp, int flags);

/* llog_ioctl.c */
struct obd_ioctl_data;
int llog_ioctl(const struct lu_env *env, struct llog_ctxt *ctxt, int cmd,
	       struct obd_ioctl_data *data);
int llog_catalog_list(const struct lu_env *env, struct dt_device *d,
		      int count, struct obd_ioctl_data *data,
		      const struct lu_fid *fid);

/* llog_net.c */
int llog_initiator_connect(struct llog_ctxt *ctxt);

struct llog_operations {
	int (*lop_declare_destroy)(const struct lu_env *env,
			   struct llog_handle *handle, struct thandle *th);
	int (*lop_destroy)(const struct lu_env *env,
			   struct llog_handle *handle, struct thandle *th);
	int (*lop_next_block)(const struct lu_env *env, struct llog_handle *h,
			      int *curr_idx, int next_idx, __u64 *offset,
			      void *buf, int len);
	int (*lop_prev_block)(const struct lu_env *env, struct llog_handle *h,
			      int prev_idx, void *buf, int len);
	int (*lop_read_header)(const struct lu_env *env,
			       struct llog_handle *handle);
	int (*lop_setup)(const struct lu_env *env, struct obd_device *obd,
			 struct obd_llog_group *olg, int ctxt_idx,
			 struct obd_device *disk_obd);
	int (*lop_sync)(struct llog_ctxt *ctxt, struct obd_export *exp,
			int flags);
	int (*lop_cleanup)(const struct lu_env *env, struct llog_ctxt *ctxt);
	int (*lop_connect)(struct llog_ctxt *ctxt, struct llog_logid *logid,
			   struct llog_gen *gen, struct obd_uuid *uuid);
	/**
	 * Any llog file must be opened first using llog_open().  Llog can be
	 * opened by name, logid or without both, in last case the new logid
	 * will be generated.
	 */
	int (*lop_open)(const struct lu_env *env, struct llog_handle *lgh,
			struct llog_logid *logid, char *name,
			enum llog_open_param);
	/**
	 * Opened llog may not exist and this must be checked where needed using
	 * the llog_exist() call.
	 */
	int (*lop_exist)(struct llog_handle *lgh);
	/**
	 * Close llog file and calls llog_free_handle() implicitly.
	 * Any opened llog must be closed by llog_close() call.
	 */
	int (*lop_close)(const struct lu_env *env, struct llog_handle *handle);
	/**
	 * Create new llog file. The llog must be opened.
	 * Must be used only for local llog operations.
	 */
	int (*lop_declare_create)(const struct lu_env *env,
				  struct llog_handle *handle,
				  struct thandle *th);
	int (*lop_create)(const struct lu_env *env, struct llog_handle *handle,
			  struct thandle *th);
	/**
	 * write new record in llog. It appends records usually but can edit
	 * existing records too.
	 */
	int (*lop_declare_write_rec)(const struct lu_env *env,
				     struct llog_handle *lgh,
				     struct llog_rec_hdr *rec,
				     int idx, struct thandle *th);
	int (*lop_write_rec)(const struct lu_env *env,
			     struct llog_handle *loghandle,
			     struct llog_rec_hdr *rec,
			     struct llog_cookie *cookie,
			     int idx, struct thandle *th);
	/**
	 * Add new record in llog catalog. Does the same as llog_write_rec()
	 * but using llog catalog.
	 */
	int (*lop_declare_add)(const struct lu_env *env,
			       struct llog_handle *lgh,
			       struct llog_rec_hdr *rec, struct thandle *th);
	int (*lop_add)(const struct lu_env *env, struct llog_handle *lgh,
		       struct llog_rec_hdr *rec, struct llog_cookie *cookie,
		       struct thandle *th);
};

/* In-memory descriptor for a log object or log catalog */
struct llog_handle {
	struct rw_semaphore	 lgh_lock;
	struct mutex		 lgh_hdr_mutex; /* protect lgh_hdr data */
	struct llog_logid	 lgh_id; /* id of this log */
	struct llog_log_hdr	*lgh_hdr; /* may be vmalloc'd */
	size_t			lgh_hdr_size;
	struct dt_object	*lgh_obj;
	/* For a Catalog, is the last/newest used index for a plain slot.
	 * Used in conjunction with llh_cat_idx to handle Catalog wrap-around
	 * case, after it will have reached LLOG_HDR_BITMAP_SIZE, llh_cat_idx
	 * will become its upper limit */
	int			 lgh_last_idx;
	struct rw_semaphore	 lgh_last_sem;
	__u64			 lgh_cur_offset; /* used for test only */
	struct llog_ctxt	*lgh_ctxt;
	union {
		struct plain_handle_data	 phd;
		struct cat_handle_data		 chd;
	} u;
	char			*lgh_name;
	void			*private_data;
	const struct llog_operations	*lgh_logops;
	refcount_t		 lgh_refcount;

	int			lgh_max_size;
	bool			lgh_destroyed;
};

/* llog_osd.c */
extern const struct llog_operations llog_osd_ops;
extern const struct llog_operations llog_common_cat_ops;
int llog_osd_get_cat_list(const struct lu_env *env, struct dt_device *d,
			  int idx, int count, struct llog_catid *idarray,
			  const struct lu_fid *fid);
int llog_osd_put_cat_list(const struct lu_env *env, struct dt_device *d,
			  int idx, int count, struct llog_catid *idarray,
			  const struct lu_fid *fid);

#define LLOG_CTXT_FLAG_UNINITIALIZED     0x00000001
#define LLOG_CTXT_FLAG_STOP		 0x00000002

/* Indicate the llog objects under this context are normal FID objects,
 * instead of objects with local FID. */
#define LLOG_CTXT_FLAG_NORMAL_FID	 0x00000004

struct llog_ctxt {
	int			 loc_idx; /* my index the obd array of ctxt's */
	struct obd_device	*loc_obd; /* points back to the containing obd*/
	struct obd_llog_group	*loc_olg; /* group containing that ctxt */
	struct obd_export	*loc_exp; /* parent "disk" export (e.g. MDS) */
	struct obd_import	*loc_imp; /* to use in RPC's: can be backward
					   * pointing import */
	const struct llog_operations  *loc_logops;
	struct llog_handle	*loc_handle;
	struct mutex		 loc_mutex; /* protect loc_imp */
	atomic_t		 loc_refcount;
	long			 loc_flags; /* flags, see above defines */
	struct dt_object	*loc_dir;
	struct local_oid_storage *loc_los_nameless;
	struct local_oid_storage *loc_los_named;
	/* llog chunk size, and llog record size can not be bigger than
	 * loc_chunk_size */
	__u32			 loc_chunk_size;
};

#define LLOG_PROC_BREAK 0x0001
#define LLOG_DEL_RECORD 0x0002
#define LLOG_DEL_PLAIN  0x0003

static inline int llog_obd2ops(struct llog_ctxt *ctxt,
			       const struct llog_operations **lop)
{
	if (ctxt == NULL)
		return -ENOTCONN;

	*lop = ctxt->loc_logops;
	if (*lop == NULL)
		return -EOPNOTSUPP;

	return 0;
}

static inline int llog_handle2ops(struct llog_handle *loghandle,
				  const struct llog_operations **lop)
{
	if (loghandle == NULL || loghandle->lgh_logops == NULL)
		return -EINVAL;

	*lop = loghandle->lgh_logops;
	return 0;
}

static inline int llog_data_len(int len)
{
	return cfs_size_round(len);
}

static inline int llog_get_size(struct llog_handle *loghandle)
{
	if (loghandle && loghandle->lgh_hdr)
		return loghandle->lgh_hdr->llh_count;
	return 0;
}

static inline struct llog_ctxt *llog_ctxt_get(struct llog_ctxt *ctxt)
{
	atomic_inc(&ctxt->loc_refcount);
	CDEBUG(D_INFO, "GETting ctxt %p : new refcount %d\n", ctxt,
	       atomic_read(&ctxt->loc_refcount));
	return ctxt;
}

static inline void llog_ctxt_put(struct llog_ctxt *ctxt)
{
	if (ctxt == NULL)
		return;
	LASSERT_ATOMIC_GT_LT(&ctxt->loc_refcount, 0, LI_POISON);
	CDEBUG(D_INFO, "PUTting ctxt %p : new refcount %d\n", ctxt,
	       atomic_read(&ctxt->loc_refcount) - 1);
	__llog_ctxt_put(NULL, ctxt);
}

static inline void llog_group_init(struct obd_llog_group *olg)
{
	init_waitqueue_head(&olg->olg_waitq);
	spin_lock_init(&olg->olg_lock);
}

static inline int llog_group_set_ctxt(struct obd_llog_group *olg,
                                      struct llog_ctxt *ctxt, int index)
{
	LASSERT(index >= 0 && index < LLOG_MAX_CTXTS);

	spin_lock(&olg->olg_lock);
	if (olg->olg_ctxts[index] != NULL) {
		spin_unlock(&olg->olg_lock);
		return -EEXIST;
	}
	olg->olg_ctxts[index] = ctxt;
	spin_unlock(&olg->olg_lock);
	return 0;
}

static inline struct llog_ctxt *llog_group_get_ctxt(struct obd_llog_group *olg,
                                                    int index)
{
	struct llog_ctxt *ctxt;

	LASSERT(index >= 0 && index < LLOG_MAX_CTXTS);

	spin_lock(&olg->olg_lock);
	if (olg->olg_ctxts[index] == NULL)
		ctxt = NULL;
	else
		ctxt = llog_ctxt_get(olg->olg_ctxts[index]);
	spin_unlock(&olg->olg_lock);
	return ctxt;
}

static inline void llog_group_clear_ctxt(struct obd_llog_group *olg, int index)
{
	LASSERT(index >= 0 && index < LLOG_MAX_CTXTS);
	spin_lock(&olg->olg_lock);
	olg->olg_ctxts[index] = NULL;
	spin_unlock(&olg->olg_lock);
}

static inline struct llog_ctxt *llog_get_context(struct obd_device *obd,
                                                 int index)
{
        return llog_group_get_ctxt(&obd->obd_olg, index);
}

static inline int llog_group_ctxt_null(struct obd_llog_group *olg, int index)
{
        return (olg->olg_ctxts[index] == NULL);
}

static inline int llog_ctxt_null(struct obd_device *obd, int index)
{
        return (llog_group_ctxt_null(&obd->obd_olg, index));
}

static inline int llog_next_block(const struct lu_env *env,
				  struct llog_handle *loghandle, int *cur_idx,
				  int next_idx, __u64 *cur_offset, void *buf,
				  int len)
{
	const struct llog_operations *lop;
	int rc;

	ENTRY;

	rc = llog_handle2ops(loghandle, &lop);
	if (rc)
		RETURN(rc);
	if (lop->lop_next_block == NULL)
		RETURN(-EOPNOTSUPP);

	rc = lop->lop_next_block(env, loghandle, cur_idx, next_idx,
				 cur_offset, buf, len);
	RETURN(rc);
}

static inline int llog_prev_block(const struct lu_env *env,
				  struct llog_handle *loghandle,
				  int prev_idx, void *buf, int len)
{
	const struct llog_operations *lop;
	int rc;

	ENTRY;

	rc = llog_handle2ops(loghandle, &lop);
	if (rc)
		RETURN(rc);
	if (lop->lop_prev_block == NULL)
		RETURN(-EOPNOTSUPP);

	rc = lop->lop_prev_block(env, loghandle, prev_idx, buf, len);
	RETURN(rc);
}

static inline int llog_connect(struct llog_ctxt *ctxt,
			       struct llog_logid *logid, struct llog_gen *gen,
			       struct obd_uuid *uuid)
{
	const struct llog_operations *lop;
	int rc;

	ENTRY;

	rc = llog_obd2ops(ctxt, &lop);
	if (rc)
		RETURN(rc);
	if (lop->lop_connect == NULL)
		RETURN(-EOPNOTSUPP);

	rc = lop->lop_connect(ctxt, logid, gen, uuid);
	RETURN(rc);
}

static inline int llog_is_full(struct llog_handle *llh)
{
	return llh->lgh_last_idx >= LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr) - 1;
}

struct llog_cfg_rec {
	struct llog_rec_hdr	lcr_hdr;
	struct lustre_cfg	lcr_cfg;
	struct llog_rec_tail	lcr_tail;
};

struct llog_cfg_rec *lustre_cfg_rec_new(int cmd, struct lustre_cfg_bufs *bufs);
void lustre_cfg_rec_free(struct llog_cfg_rec *lcr);

enum {
	LLOG_NEXT_IDX = -1,
	LLOG_HEADER_IDX = 0,
};

/* llog.c */
int llog_exist(struct llog_handle *loghandle);
int llog_declare_create(const struct lu_env *env,
			struct llog_handle *loghandle, struct thandle *th);
int llog_create(const struct lu_env *env, struct llog_handle *handle,
		struct thandle *th);
int llog_trans_destroy(const struct lu_env *env, struct llog_handle *handle,
		       struct thandle *th);
int llog_destroy(const struct lu_env *env, struct llog_handle *handle);

int llog_declare_write_rec(const struct lu_env *env,
			   struct llog_handle *handle,
			   struct llog_rec_hdr *rec, int idx,
			   struct thandle *th);
int llog_write_rec(const struct lu_env *env, struct llog_handle *handle,
		   struct llog_rec_hdr *rec, struct llog_cookie *logcookies,
		   int idx, struct thandle *th);
int llog_add(const struct lu_env *env, struct llog_handle *lgh,
	     struct llog_rec_hdr *rec, struct llog_cookie *logcookies,
	     struct thandle *th);
int llog_declare_add(const struct lu_env *env, struct llog_handle *lgh,
		     struct llog_rec_hdr *rec, struct thandle *th);
int lustre_process_log(struct super_block *sb, char *logname,
		       struct config_llog_instance *cfg);
int lustre_end_log(struct super_block *sb, char *logname,
		   struct config_llog_instance *cfg);
int llog_open_create(const struct lu_env *env, struct llog_ctxt *ctxt,
		     struct llog_handle **res, struct llog_logid *logid,
		     char *name);
int llog_erase(const struct lu_env *env, struct llog_ctxt *ctxt,
	       struct llog_logid *logid, char *name);
int llog_write(const struct lu_env *env, struct llog_handle *loghandle,
	       struct llog_rec_hdr *rec, int idx);

/** @} log */

#endif
