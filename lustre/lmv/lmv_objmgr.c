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
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_ost.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd_lmv.h>
#include "lmv_internal.h"

static LIST_HEAD(lmv_obj_list);
static spinlock_t lmv_obj_list_lock = SPIN_LOCK_UNLOCKED;

/* creates new obj on passed @fid and @mea. */
struct lmv_obj *
lmv_alloc_obj(struct obd_device *obd, struct ll_fid *fid,
              struct mea *mea)
{
        int i;
        struct lmv_obj *obj;
        unsigned int obj_size;
        struct lmv_obd *lmv = &obd->u.lmv;

        OBD_ALLOC(obj, sizeof(*obj));
        if (!obj)
                return NULL;

        obj->obd = obd;
        obj->fid = *fid;
        obj->freeing = 0;
          
        init_MUTEX(&obj->guard);
        atomic_set(&obj->count, 0);
        obj->objcount = mea->mea_count;

        obj_size = sizeof(struct lmv_inode) *
                lmv->desc.ld_tgt_count;
        
        OBD_ALLOC(obj->objs, obj_size);
        if (!obj->objs)
                goto err_obj;

        memset(obj->objs, 0, obj_size);

        /* put all fids in */
        for (i = 0; i < mea->mea_count; i++) {
                CDEBUG(D_OTHER, "subobj %lu/%lu/%lu\n",
                       (unsigned long)mea->mea_fids[i].mds,
                       (unsigned long)mea->mea_fids[i].id,
                       (unsigned long)mea->mea_fids[i].generation);
                obj->objs[i].fid = mea->mea_fids[i];
        }

        return obj;
        
err_obj:
        OBD_FREE(obj, sizeof(*obj));
        return NULL;
}

/* destroys passed @obj. */
void
lmv_free_obj(struct lmv_obj *obj)
{
        unsigned int obj_size;
        struct lmv_obd *lmv = &obj->obd->u.lmv;
        
        obj_size = sizeof(struct lmv_inode) *
                lmv->desc.ld_tgt_count;
        
        OBD_FREE(obj->objs, obj_size);
        OBD_FREE(obj, sizeof(*obj));
}

static void
__add_obj(struct lmv_obj *obj)
{
        atomic_inc(&obj->count);
        list_add(&obj->list, &lmv_obj_list);
}

void
lmv_add_obj(struct lmv_obj *obj)
{
        spin_lock(&lmv_obj_list_lock);
        __add_obj(obj);
        spin_unlock(&lmv_obj_list_lock);
}

static void
__del_obj(struct lmv_obj *obj)
{
        list_del(&obj->list);
        lmv_free_obj(obj);
}

void
lmv_del_obj(struct lmv_obj *obj)
{
        spin_lock(&lmv_obj_list_lock);
        __del_obj(obj);
        spin_unlock(&lmv_obj_list_lock);
}

static struct lmv_obj *
__get_obj(struct lmv_obj *obj)
{
        LASSERT(obj);
        atomic_inc(&obj->count);
        return obj;
}

struct lmv_obj *
lmv_get_obj(struct lmv_obj *obj)
{
        spin_lock(&lmv_obj_list_lock);
        __get_obj(obj);
        spin_unlock(&lmv_obj_list_lock);

        return obj;
}

static void
__put_obj(struct lmv_obj *obj)
{
        LASSERT(obj);

        if (atomic_dec_and_test(&obj->count)) {
                struct ll_fid *fid = &obj->fid;
                CDEBUG(D_OTHER, "last reference to %lu/%lu/%lu - destroying\n",
                       (unsigned long)fid->mds, (unsigned long)fid->id,
                       (unsigned long)fid->generation);
                __del_obj(obj);
        }
}

void
lmv_put_obj(struct lmv_obj *obj)
{
        spin_lock(&lmv_obj_list_lock);
        __put_obj(obj);
        spin_unlock(&lmv_obj_list_lock);
}

static struct lmv_obj *
__grab_obj(struct obd_device *obd, struct ll_fid *fid)
{
        struct lmv_obj *obj;
        struct list_head *cur;

        list_for_each(cur, &lmv_obj_list) {
                obj = list_entry(cur, struct lmv_obj, list);

                /* check if object is in progress of destroying. If so - skip
                 * it. */
                if (obj->freeing)
                        continue;

                /* check if this is waht we're looking for. */
                if (fid_equal(&obj->fid, fid))
                        return __get_obj(obj);
        }

        return NULL;
}

struct lmv_obj *
lmv_grab_obj(struct obd_device *obd, struct ll_fid *fid)
{
        struct lmv_obj *obj;
        ENTRY;
        
        spin_lock(&lmv_obj_list_lock);
        obj = __grab_obj(obd, fid);
        spin_unlock(&lmv_obj_list_lock);
        
        RETURN(obj);
}

/* looks in objects list for an object that matches passed @fid. If it is not
 * found -- creates it using passed @mea and puts onto list. */
static struct lmv_obj *
__create_obj(struct obd_device *obd, struct ll_fid *fid, struct mea *mea)
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
        spin_lock(&lmv_obj_list_lock);
        obj = __grab_obj(obd, fid);
        if (obj) {
                /* someone created it already - put @obj and getting out. */
                lmv_free_obj(new);
                spin_unlock(&lmv_obj_list_lock);
                RETURN(obj);
        }

        __add_obj(new);
        __get_obj(new);
        
        spin_unlock(&lmv_obj_list_lock);

        CDEBUG(D_OTHER, "new obj in lmv cache: %lu/%lu/%lu\n",
               (unsigned long)fid->mds, (unsigned long)fid->id,
               (unsigned long)fid->generation);

        RETURN(new);
        
}

/* creates object from passed @fid and @mea. If @mea is NULL, it will be
 * obtained from correct MDT and used for constructing the object. */
struct lmv_obj *
lmv_create_obj(struct obd_export *exp, struct ll_fid *fid, struct mea *mea)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req = NULL;
        struct lmv_obj *obj;
        struct lustre_md md;
        int mealen, i, rc;
        ENTRY;

        CDEBUG(D_OTHER, "get mea for %lu/%lu/%lu and create lmv obj\n",
               (unsigned long)fid->mds, (unsigned long)fid->id,
               (unsigned long)fid->generation);

        if (!mea) {
                unsigned long valid;
                
                CDEBUG(D_OTHER, "mea isn't passed in, get it now\n");
                mealen = MEA_SIZE_LMV(lmv);
                
                /* time to update mea of parent fid */
                i = fid->mds;
                md.mea = NULL;
                
                valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;
                rc = md_getattr(lmv->tgts[fid->mds].ltd_exp, fid,
                                valid, mealen, &req);
                if (rc) {
                        CERROR("md_getattr() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                rc = mdc_req2lustre_md(exp, req, 0, NULL, &md);
                if (rc) {
                        CERROR("mdc_req2lustre_md() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                if (!md.mea)
                        GOTO(cleanup, obj = ERR_PTR(-ENODATA));
                        
                mea = md.mea;
        }

        /* got mea, now create obj for it. */
        obj = __create_obj(obd, fid, mea);
        if (!obj) {
                CERROR("Can't create new object %lu/%lu/%lu\n",
                       (unsigned long)fid->mds, (unsigned long)fid->id,
                       (unsigned long)fid->generation);
                GOTO(cleanup, obj = ERR_PTR(-ENOMEM));
        }
        
        lmv_put_obj(obj);
cleanup:
        if (req)       
                ptlrpc_req_finished(req);
        RETURN(obj);
}

/* looks for object with @fid and orders to destroy it. It possible the object
 * will not be destroyed right now, because it is still using by someone. In
 * this case it will be marked as "freeing" and will not be accessible anymore
 * for subsequent callers of lmv_grab_obj(). */
int
lmv_delete_obj(struct obd_export *exp, struct ll_fid *fid)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obj *obj;
        int rc = 0;
        ENTRY;

        spin_lock(&lmv_obj_list_lock);
        
        obj = __grab_obj(obd, fid);
        if (obj) {
                obj->freeing = 1;
                __put_obj(obj);
                __put_obj(obj);
                rc = 1;
        }

        spin_unlock(&lmv_obj_list_lock);
        RETURN(rc);
}

int
lmv_setup_mgr(struct obd_device *obd)
{
        CWARN("LMV object manager setup (%s)\n",
              obd->obd_uuid.uuid);
        return 0;
}

void
lmv_cleanup_mgr(struct obd_device *obd)
{
        struct lmv_obj *obj;
        struct list_head *cur, *tmp;

        CWARN("LMV object manager cleanup (%s)\n",
              obd->obd_uuid.uuid);
        
        spin_lock(&lmv_obj_list_lock);
        list_for_each_safe(cur, tmp, &lmv_obj_list) {
                obj = list_entry(cur, struct lmv_obj, list);
                
                if (obj->obd != obd)
                        continue;

                __put_obj(obj);
        }
        spin_unlock(&lmv_obj_list_lock);
}
