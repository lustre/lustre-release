/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _LMV_INTERNAL_H_
#define _LMV_INTERNAL_H_

#include <lustre/lustre_idl.h>
#include <obd.h>

#ifndef __KERNEL__
/* XXX: dirty hack, needs to be fixed more clever way. */
struct qstr {
        const char *name;
        size_t      len;
        unsigned    hashval;
};
#endif

#define LMV_MAX_TGT_COUNT 128

#define lmv_init_lock(lmv)   down(&lmv->init_sem);
#define lmv_init_unlock(lmv) up(&lmv->init_sem);

#define LL_IT2STR(it)				        \
	((it) ? ldlm_it2str((it)->it_op) : "0")

struct lmv_inode {
        struct lu_fid      li_fid;        /* id of dirobj */
        unsigned long      li_size;       /* slave size value */
        int                li_flags;
};

#define O_FREEING          (1 << 0)

struct lmv_obj {
        struct list_head   lo_list;
	struct semaphore   lo_guard;
	int                lo_state;      /* object state. */
        atomic_t           lo_count;      /* ref counter. */
        struct lu_fid      lo_fid;        /* master id of dir */
        void              *lo_update;     /* bitmap of status (up-to-date) */
	__u32		   lo_hashtype;
        int                lo_objcount;   /* number of slaves */
        struct lmv_inode  *lo_inodes;     /* array of sub-objs */
        struct obd_device *lo_obd;        /* pointer to LMV itself */
};

int lmv_mgr_setup(struct obd_device *obd);
void lmv_mgr_cleanup(struct obd_device *obd);

static inline void
lmv_obj_lock(struct lmv_obj *obj)
{
        LASSERT(obj);
        down(&obj->lo_guard);
}

static inline void
lmv_obj_unlock(struct lmv_obj *obj)
{
        LASSERT(obj);
        up(&obj->lo_guard);
}

void lmv_obj_add(struct lmv_obj *obj);
void lmv_obj_del(struct lmv_obj *obj);

void lmv_obj_put(struct lmv_obj *obj);
void lmv_obj_free(struct lmv_obj *obj);

struct lmv_obj *lmv_obj_get(struct lmv_obj *obj);

struct lmv_obj *lmv_obj_grab(struct obd_device *obd,
			     const struct lu_fid *fid);

struct lmv_obj *lmv_obj_alloc(struct obd_device *obd,
			      const struct lu_fid *fid,
			      struct lmv_stripe_md *mea);

struct lmv_obj *lmv_obj_create(struct obd_export *exp,
			       const struct lu_fid *fid,
			       struct lmv_stripe_md *mea);

int lmv_obj_delete(struct obd_export *exp,
                   const struct lu_fid *fid);

int lmv_check_connect(struct obd_device *obd);

int lmv_intent_lock(struct obd_export *exp, struct md_op_data *op_data,
                    void *lmm, int lmmsize, struct lookup_intent *it,
                    int flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking,
                    int extra_lock_flags);

int lmv_intent_lookup(struct obd_export *, const struct lu_fid *, 
		      const char *, int, void *, int,
		      const struct lu_fid *, struct lookup_intent *, int,
		      struct ptlrpc_request **, ldlm_blocking_callback,
                      int extra_lock_flags);

int lmv_intent_getattr(struct obd_export *, const struct lu_fid *, const char *,
                       int, void *, int, const struct lu_fid *, struct lookup_intent *,
                       int, struct ptlrpc_request **, ldlm_blocking_callback,
                       int extra_lock_flags);

int lmv_intent_open(struct obd_export *, const struct lu_fid *, const char *, 
		    int, void *, int, const struct lu_fid *, struct lookup_intent *, 
		    int, struct ptlrpc_request **, ldlm_blocking_callback,
                    int extra_lock_flags);

int lmv_revalidate_slaves(struct obd_export *, struct ptlrpc_request **,
                          const struct lu_fid *, struct lookup_intent *, int,
			  ldlm_blocking_callback cb_blocking,
                          int extra_lock_flags);

int lmv_handle_split(struct obd_export *, const struct lu_fid *);
int lmv_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
		     void *, int);
int lmv_fld_lookup(struct lmv_obd *lmv, const struct lu_fid *fid,
                   mdsno_t *mds);

static inline struct lmv_stripe_md * 
lmv_get_mea(struct ptlrpc_request *req, int offset)
{
	struct mdt_body *body;
	struct lmv_stripe_md *mea;

	LASSERT(req);

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));

	if (!body || !S_ISDIR(body->mode) || !body->eadatasize)
		return NULL;

        mea = lustre_msg_buf(req->rq_repmsg, offset + 1,
			     body->eadatasize);
	LASSERT(mea);

	if (mea->mea_count == 0)
		return NULL;
	
	return mea;
}

static inline int lmv_get_easize(struct lmv_obd *lmv)
{
        return sizeof(struct lmv_stripe_md) +
                lmv->desc.ld_tgt_count *
                sizeof(struct lu_fid);
}

static inline struct obd_export *
lmv_get_export(struct lmv_obd *lmv, const struct lu_fid *fid)
{
        mdsno_t mds;
        int rc;
        
        rc = lmv_fld_lookup(lmv, fid, &mds);
        if (rc)
                return ERR_PTR(rc);

        return lmv->tgts[mds].ltd_exp;
}

/* lproc_lmv.c */
extern struct file_operations lmv_proc_target_fops;

#endif

