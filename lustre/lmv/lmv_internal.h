/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003, 2004 Cluster File Systems, Inc.
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

#define LMV_MAX_TGT_COUNT 128

#define lmv_init_lock(lmv)   down(&lmv->init_sem);
#define lmv_init_unlock(lmv) up(&lmv->init_sem);

#define LL_IT2STR(it)				        \
	((it) ? ldlm_it2str((it)->it_op) : "0")

#define MEA_SIZE_LMV(lmv)				\
        ((lmv)->desc.ld_tgt_count *			\
	 sizeof(struct lu_fid) + sizeof(struct mea))
        
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
        struct lmv_inode  *lo_objs;       /* array of dirobjs */
        struct obd_device *lo_obd;        /* pointer to LMV itself */
};

static inline void
lmv_lock_obj(struct lmv_obj *obj)
{
        LASSERT(obj);
        down(&obj->guard);
}

static inline void
lmv_unlock_obj(struct lmv_obj *obj)
{
        LASSERT(obj);
        up(&obj->guard);
}

void lmv_add_obj(struct lmv_obj *obj);
void lmv_del_obj(struct lmv_obj *obj);

void lmv_put_obj(struct lmv_obj *obj);
void lmv_free_obj(struct lmv_obj *obj);

int lmv_setup_mgr(struct obd_device *obd);
void lmv_cleanup_mgr(struct obd_device *obd);
int lmv_check_connect(struct obd_device *obd);

struct lmv_obj *lmv_get_obj(struct lmv_obj *obj);

struct lmv_obj *lmv_grab_obj(struct obd_device *obd,
			     struct lu_fid *fid);

struct lmv_obj *lmv_alloc_obj(struct obd_device *obd,
			      struct lu_fid *fid,
			      struct mea *mea);

struct lmv_obj *lmv_create_obj(struct obd_export *exp,
			       struct lu_fid *fid,
			       struct mea *mea);

int lmv_delete_obj(struct obd_export *exp, struct lu_fid *fid);

int lmv_intent_lock(struct obd_export *, struct lu_fid *, 
		    const char *, int, void *, int,
		    struct lu_fid *, struct lookup_intent *, int,
		    struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_lookup(struct obd_export *, struct lu_fid *, 
		      const char *, int, void *, int,
		      struct lu_fid *, struct lookup_intent *, int,
		      struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_getattr(struct obd_export *, struct lu_fid *, 
		       const char *, int, void *, int,
		       struct lu_fid *, struct lookup_intent *, int,
		       struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_open(struct obd_export *, struct lu_fid *, const char *, 
		    int, void *, int, struct lu_fid *, struct lookup_intent *, 
		    int, struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_revalidate_slaves(struct obd_export *, struct ptlrpc_request **,
                          struct lu_fid *, struct lookup_intent *, int,
			  ldlm_blocking_callback cb_blocking);

int lmv_get_mea_and_update_object(struct obd_export *, struct lu_fid *);
int lmv_dirobj_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
			    void *, int);
int lmv_fld_lookup(struct obd_device *obd, struct lu_fid *fid)

static inline struct mea * 
lmv_splitted_dir_body(struct ptlrpc_request *req, int offset)
{
	struct mdt_body *body;
	struct mea *mea;

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

/* lproc_lmv.c */
extern struct file_operations lmv_proc_target_fops;

#endif

