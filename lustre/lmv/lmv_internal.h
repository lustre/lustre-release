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

#define LL_IT2STR(it)				        \
	((it) ? ldlm_it2str((it)->it_op) : "0")

#define MEA_SIZE_LMV(lmv)				\
        ((lmv)->desc.ld_tgt_count *			\
	 sizeof(struct lustre_id) + sizeof(struct mea))
        
struct lmv_inode {
        struct lustre_id   id;             /* id of dirobj */
        unsigned long      size;           /* slave size value */
        int                flags;
};

#define O_FREEING          (1 << 0)

struct lmv_obj {
        struct list_head   list;
	struct semaphore   guard;
	int                state;          /* object state. */
        atomic_t           count;          /* ref counter. */
        struct lustre_id   id;             /* master id of dir */
        void               *update;        /* bitmap of status (up-to-date) */
	__u32		   hashtype;
        int                objcount;       /* number of slaves */
        struct lmv_inode   *objs;          /* array of dirobjs */
        struct obd_device  *obd;           /* pointer to LMV itself */
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
			     struct lustre_id *id);

struct lmv_obj *lmv_alloc_obj(struct obd_device *obd,
			      struct lustre_id *id,
			      struct mea *mea);

struct lmv_obj *lmv_create_obj(struct obd_export *exp,
			       struct lustre_id *id,
			       struct mea *mea);

int lmv_delete_obj(struct obd_export *exp, struct lustre_id *id);

int lmv_intent_lock(struct obd_export *, struct lustre_id *, 
		    const char *, int, void *, int,
		    struct lustre_id *, struct lookup_intent *, int,
		    struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_lookup(struct obd_export *, struct lustre_id *, 
		      const char *, int, void *, int,
		      struct lustre_id *, struct lookup_intent *, int,
		      struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_getattr(struct obd_export *, struct lustre_id *, 
		       const char *, int, void *, int,
		       struct lustre_id *, struct lookup_intent *, int,
		       struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_open(struct obd_export *, struct lustre_id *, const char *, 
		    int, void *, int, struct lustre_id *, struct lookup_intent *, 
		    int, struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_revalidate_slaves(struct obd_export *, struct ptlrpc_request **,
                          struct lustre_id *, struct lookup_intent *, int,
			  ldlm_blocking_callback cb_blocking);

int lmv_get_mea_and_update_object(struct obd_export *, struct lustre_id *);
int lmv_dirobj_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
			    void *, int);

static inline struct mea * 
lmv_splitted_dir_body(struct ptlrpc_request *req, int offset)
{
	struct mds_body *body;
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

