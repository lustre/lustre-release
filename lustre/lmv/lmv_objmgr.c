/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LMV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#include <linux/seq_file.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>
#include "lmv_internal.h"

/* objects cache. */
extern kmem_cache_t *obj_cache;
extern atomic_t obj_cache_count;

/* object list and its guard. */
static LIST_HEAD(obj_list);
static spinlock_t obj_list_lock = SPIN_LOCK_UNLOCKED;

/* creates new obj on passed @fid and @mea. */
struct lmv_obj *
lmv_alloc_obj(struct obd_device *obd,
              struct lu_fid *fid,
              struct mea *mea)
{
        int i;
        struct lmv_obj *obj;
        unsigned int obj_size;
        struct lmv_obd *lmv = &obd->u.lmv;

        LASSERT(mea->mea_magic == MEA_MAGIC_LAST_CHAR
                || mea->mea_magic == MEA_MAGIC_ALL_CHARS);

        OBD_SLAB_ALLOC(obj, obj_cache, GFP_NOFS,
                       sizeof(*obj));
        if (!obj)
                return NULL;

        atomic_inc(&obj_cache_count);
        
        obj->lo_fid = *fid;
        obj->lo_obd = obd;
        obj->lo_state = 0;
        obj->lo_hashtype = mea->mea_magic;

        init_MUTEX(&obj->lo_guard);
        atomic_set(&obj->lo_count, 0);
        obj->lo_objcount = mea->mea_count;

        obj_size = sizeof(struct lmv_inode) *
                lmv->desc.ld_tgt_count;
        
        OBD_ALLOC(obj->lo_objs, obj_size);
        if (!obj->lo_objs)
                goto err_obj;

        memset(obj->lo_objs, 0, obj_size);

        /* put all ids in */
        for (i = 0; i < mea->mea_count; i++) {
                CDEBUG(D_OTHER, "subobj "DFID3"\n",
                       PFID3(&mea->mea_ids[i]));
                obj->lo_objs[i].li_fid = mea->mea_ids[i];
                LASSERT(fid_num(&obj->lo_objs[i].li_fid));
        }

        return obj;
        
err_obj:
        OBD_FREE(obj, sizeof(*obj));
        return NULL;
}

/* destroy passed @obj. */
void
lmv_free_obj(struct lmv_obj *obj)
{
        struct lmv_obd *lmv = &obj->lo_obd->u.lmv;
        unsigned int obj_size;
        
        LASSERT(!atomic_read(&obj->lo_count));
        
        obj_size = sizeof(struct lmv_inode) *
                lmv->desc.ld_tgt_count;
        
        OBD_FREE(obj->lo_objs, obj_size);
        OBD_SLAB_FREE(obj, obj_cache, sizeof(*obj));
        atomic_dec(&obj_cache_count);
}

static void
__add_obj(struct lmv_obj *obj)
{
        atomic_inc(&obj->lo_count);
        list_add(&obj->lo_list, &obj_list);
}

void
lmv_add_obj(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __add_obj(obj);
        spin_unlock(&obj_list_lock);
}

static void
__del_obj(struct lmv_obj *obj)
{
        list_del(&obj->lo_list);
        lmv_free_obj(obj);
}

void
lmv_del_obj(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __del_obj(obj);
        spin_unlock(&obj_list_lock);
}

static struct lmv_obj *
__get_obj(struct lmv_obj *obj)
{
        LASSERT(obj != NULL);
        atomic_inc(&obj->lo_count);
        return obj;
}

struct lmv_obj *
lmv_get_obj(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __get_obj(obj);
        spin_unlock(&obj_list_lock);
        return obj;
}

static void
__put_obj(struct lmv_obj *obj)
{
        LASSERT(obj);

        if (atomic_dec_and_test(&obj->lo_count)) {
                struct lu_fid *fid = &obj->lo_fid;
                CDEBUG(D_OTHER, "last reference to "DFID3" - "
                       "destroying\n", PFID3(fid));
                __del_obj(obj);
        }
}

void
lmv_put_obj(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __put_obj(obj);
        spin_unlock(&obj_list_lock);
}

static struct lmv_obj *
__grab_obj(struct obd_device *obd, struct lu_fid *fid)
{
        struct lmv_obj *obj;
        struct list_head *cur;

        list_for_each(cur, &obj_list) {
                obj = list_entry(cur, struct lmv_obj, lo_list);

                /* check if object is in progress of destroying. If so - skip
                 * it. */
                if (obj->lo_state & O_FREEING)
                        continue;

                /* 
                 * we should make sure, that we have found object belong to
                 * passed obd. It is possible that, object manager will have two
                 * objects with the same fid belong to different obds, if client
                 * and mds runs on the same host. May be it is good idea to have
                 * objects list assosiated with obd.
                 */
                if (obj->lo_obd != obd)
                        continue;

                /* check if this is what we're looking for. */
                if (lu_fid_eq(&obj->lo_fid, fid))
                        return __get_obj(obj);
        }

        return NULL;
}

struct lmv_obj *
lmv_grab_obj(struct obd_device *obd, struct lu_fid *fid)
{
        struct lmv_obj *obj;
        ENTRY;
        
        spin_lock(&obj_list_lock);
        obj = __grab_obj(obd, fid);
        spin_unlock(&obj_list_lock);
        
        RETURN(obj);
}

/* looks in objects list for an object that matches passed @fid. If it is not
 * found -- creates it using passed @mea and puts onto list. */
static struct lmv_obj *
__create_obj(struct obd_device *obd, struct lu_fid *fid, struct mea *mea)
{
        struct lmv_obj *new, *obj;
        ENTRY;

        obj = lmv_grab_obj(obd, fid);
        if (obj)
                RETURN(obj);

        /* no such object yet, allocate and initialize it. */
        new = lmv_alloc_obj(obd, fid, mea);
        if (!new)
                RETURN(NULL);

        /* check if someone create it already while we were dealing with
         * allocating @obj. */
        spin_lock(&obj_list_lock);
        obj = __grab_obj(obd, fid);
        if (obj) {
                /* someone created it already - put @obj and getting out. */
                lmv_free_obj(new);
                spin_unlock(&obj_list_lock);
                RETURN(obj);
        }

        __add_obj(new);
        __get_obj(new);
        
        spin_unlock(&obj_list_lock);

        CDEBUG(D_OTHER, "new obj in lmv cache: "DFID3"\n",
               PFID3(fid));

        RETURN(new);
        
}

/* creates object from passed @fid and @mea. If @mea is NULL, it will be
 * obtained from correct MDT and used for constructing the object. */
struct lmv_obj *
lmv_create_obj(struct obd_export *exp, struct lu_fid *fid, struct mea *mea)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req = NULL;
        struct lmv_obj *obj;
        struct lustre_md md;
        int mealen, rc, mds;
        ENTRY;

        CDEBUG(D_OTHER, "get mea for "DFID3" and create lmv obj\n",
               PFID3(fid));

        md.mea = NULL;
	
        if (mea == NULL) {
                __u64 valid;
                
                CDEBUG(D_OTHER, "mea isn't passed in, get it now\n");
                mealen = MEA_SIZE_LMV(lmv);
                
                /* time to update mea of parent fid */
                md.mea = NULL;
                valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA | OBD_MD_MEA;

                mds = lmv_fld_lookup(obd, fid);

                rc = md_getattr(lmv->tgts[mds].ltd_exp,
                                fid, valid, NULL, NULL, 0, mealen, NULL, &req);
                if (rc) {
                        CERROR("md_getattr() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                rc = mdc_req2lustre_md(exp, req, 0, NULL, &md);
                if (rc) {
                        CERROR("mdc_req2lustre_md() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                if (md.mea == NULL)
                        GOTO(cleanup, obj = ERR_PTR(-ENODATA));
                        
                mea = md.mea;
        }

        /* got mea, now create obj for it. */
        obj = __create_obj(obd, fid, mea);
        if (!obj) {
                CERROR("Can't create new object "DFID3"\n",
                       PFID3(fid));
                GOTO(cleanup, obj = ERR_PTR(-ENOMEM));
        }
	
	if (md.mea != NULL)
		obd_free_memmd(exp, (struct lov_stripe_md **)&md.mea);
        
	EXIT;
cleanup:
        if (req)
                ptlrpc_req_finished(req);
        return obj;
}

/*
 * looks for object with @fid and orders to destroy it. It is possible the object
 * will not be destroyed right now, because it is still using by someone. In
 * this case it will be marked as "freeing" and will not be accessible anymore
 * for subsequent callers of lmv_grab_obj().
 */
int
lmv_delete_obj(struct obd_export *exp, struct lu_fid *fid)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obj *obj;
        int rc = 0;
        ENTRY;

        spin_lock(&obj_list_lock);
        obj = __grab_obj(obd, fid);
        if (obj) {
                obj->lo_state |= O_FREEING;
                __put_obj(obj);
                __put_obj(obj);
                rc = 1;
        }
        spin_unlock(&obj_list_lock);

        RETURN(rc);
}

int
lmv_setup_mgr(struct obd_device *obd)
{
        ENTRY;
        LASSERT(obd != NULL);
        
        CDEBUG(D_INFO, "LMV object manager setup (%s)\n",
               obd->obd_uuid.uuid);

        RETURN(0);
}

void
lmv_cleanup_mgr(struct obd_device *obd)
{
        struct list_head *cur, *tmp;
        struct lmv_obj *obj;
        ENTRY;

        CDEBUG(D_INFO, "LMV object manager cleanup (%s)\n",
               obd->obd_uuid.uuid);
        
        spin_lock(&obj_list_lock);
        list_for_each_safe(cur, tmp, &obj_list) {
                obj = list_entry(cur, struct lmv_obj, lo_list);
                
                if (obj->lo_obd != obd)
                        continue;

                obj->lo_state |= O_FREEING;
                if (atomic_read(&obj->lo_count) > 1) {
                        CERROR("obj "DFID3" has count > 1 (%d)\n",
                               PFID3(&obj->lo_fid), atomic_read(&obj->lo_count));
                }
                __put_obj(obj);
        }
        spin_unlock(&obj_list_lock);
        EXIT;
}
