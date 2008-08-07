/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

#include <lustre/lustre_idl.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "lmv_internal.h"

/* objects cache. */
extern cfs_mem_cache_t *obj_cache;
extern atomic_t obj_cache_count;

/* object list and its guard. */
static CFS_LIST_HEAD(obj_list);
static spinlock_t obj_list_lock = SPIN_LOCK_UNLOCKED;

/* creates new obj on passed @fid and @mea. */
struct lmv_obj *
lmv_obj_alloc(struct obd_device *obd,
              const struct lu_fid *fid,
              struct lmv_stripe_md *mea)
{
        int i;
        struct lmv_obj *obj;
        unsigned int obj_size;
        struct lmv_obd *lmv = &obd->u.lmv;

        LASSERT(mea->mea_magic == MEA_MAGIC_LAST_CHAR
                || mea->mea_magic == MEA_MAGIC_ALL_CHARS
                || mea->mea_magic == MEA_MAGIC_HASH_SEGMENT);

        OBD_SLAB_ALLOC(obj, obj_cache, CFS_ALLOC_STD,
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

        OBD_ALLOC(obj->lo_inodes, obj_size);
        if (!obj->lo_inodes)
                goto err_obj;

        memset(obj->lo_inodes, 0, obj_size);

        /* put all ids in */
        for (i = 0; i < mea->mea_count; i++) {
                int rc;

                CDEBUG(D_OTHER, "subobj "DFID"\n",
                       PFID(&mea->mea_ids[i]));
                obj->lo_inodes[i].li_fid = mea->mea_ids[i];
                LASSERT(fid_is_sane(&obj->lo_inodes[i].li_fid));

                /*
                 * Cache slave mds number to use it in all cases it is needed
                 * instead of constant lookup.
                 */
                rc = lmv_fld_lookup(lmv, &obj->lo_inodes[i].li_fid,
                                    &obj->lo_inodes[i].li_mds);
                if (rc)
                        goto err_obj;
        }

        return obj;

err_obj:
        OBD_FREE(obj, sizeof(*obj));
        return NULL;
}

/* destroy passed @obj. */
void
lmv_obj_free(struct lmv_obj *obj)
{
        struct lmv_obd *lmv = &obj->lo_obd->u.lmv;
        unsigned int obj_size;

        LASSERT(!atomic_read(&obj->lo_count));

        obj_size = sizeof(struct lmv_inode) *
                lmv->desc.ld_tgt_count;

        OBD_FREE(obj->lo_inodes, obj_size);
        OBD_SLAB_FREE(obj, obj_cache, sizeof(*obj));
        atomic_dec(&obj_cache_count);
}

static void
__lmv_obj_add(struct lmv_obj *obj)
{
        atomic_inc(&obj->lo_count);
        list_add(&obj->lo_list, &obj_list);
}

void
lmv_obj_add(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __lmv_obj_add(obj);
        spin_unlock(&obj_list_lock);
}

static void
__lmv_obj_del(struct lmv_obj *obj)
{
        list_del(&obj->lo_list);
        lmv_obj_free(obj);
}

void
lmv_obj_del(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __lmv_obj_del(obj);
        spin_unlock(&obj_list_lock);
}

static struct lmv_obj *
__lmv_obj_get(struct lmv_obj *obj)
{
        LASSERT(obj != NULL);
        atomic_inc(&obj->lo_count);
        return obj;
}

struct lmv_obj *
lmv_obj_get(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __lmv_obj_get(obj);
        spin_unlock(&obj_list_lock);
        return obj;
}

static void
__lmv_obj_put(struct lmv_obj *obj)
{
        LASSERT(obj);

        if (atomic_dec_and_test(&obj->lo_count)) {
                CDEBUG(D_OTHER, "last reference to "DFID" - "
                       "destroying\n", PFID(&obj->lo_fid));
                __lmv_obj_del(obj);
        }
}

void
lmv_obj_put(struct lmv_obj *obj)
{
        spin_lock(&obj_list_lock);
        __lmv_obj_put(obj);
        spin_unlock(&obj_list_lock);
}

static struct lmv_obj *
__lmv_obj_grab(struct obd_device *obd, const struct lu_fid *fid)
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
                 * objects list associated with obd.
                 */
                if (obj->lo_obd != obd)
                        continue;

                /* check if this is what we're looking for. */
                if (lu_fid_eq(&obj->lo_fid, fid))
                        return __lmv_obj_get(obj);
        }

        return NULL;
}

struct lmv_obj *
lmv_obj_grab(struct obd_device *obd, const struct lu_fid *fid)
{
        struct lmv_obj *obj;
        ENTRY;

        spin_lock(&obj_list_lock);
        obj = __lmv_obj_grab(obd, fid);
        spin_unlock(&obj_list_lock);

        RETURN(obj);
}

/* looks in objects list for an object that matches passed @fid. If it is not
 * found -- creates it using passed @mea and puts onto list. */
static struct lmv_obj *
__lmv_obj_create(struct obd_device *obd, const struct lu_fid *fid,
                 struct lmv_stripe_md *mea)
{
        struct lmv_obj *new, *obj;
        ENTRY;

        obj = lmv_obj_grab(obd, fid);
        if (obj)
                RETURN(obj);

        /* no such object yet, allocate and initialize it. */
        new = lmv_obj_alloc(obd, fid, mea);
        if (!new)
                RETURN(NULL);

        /* check if someone create it already while we were dealing with
         * allocating @obj. */
        spin_lock(&obj_list_lock);
        obj = __lmv_obj_grab(obd, fid);
        if (obj) {
                /* someone created it already - put @obj and getting out. */
                spin_unlock(&obj_list_lock);
                lmv_obj_free(new);
                RETURN(obj);
        }

        __lmv_obj_add(new);
        __lmv_obj_get(new);

        spin_unlock(&obj_list_lock);

        CDEBUG(D_OTHER, "new obj in lmv cache: "DFID"\n",
               PFID(fid));

        RETURN(new);

}

/* creates object from passed @fid and @mea. If @mea is NULL, it will be
 * obtained from correct MDT and used for constructing the object. */
struct lmv_obj *
lmv_obj_create(struct obd_export *exp, const struct lu_fid *fid,
               struct lmv_stripe_md *mea)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req = NULL;
        struct obd_export *tgt_exp;
        struct lmv_obj *obj;
        struct lustre_md md;
        int mealen, rc;
        ENTRY;

        CDEBUG(D_OTHER, "get mea for "DFID" and create lmv obj\n",
               PFID(fid));

        md.mea = NULL;
	
        if (mea == NULL) {
                __u64 valid;

                CDEBUG(D_OTHER, "mea isn't passed in, get it now\n");
                mealen = lmv_get_easize(lmv);

                /* time to update mea of parent fid */
                md.mea = NULL;
                valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA | OBD_MD_MEA;

                tgt_exp = lmv_find_export(lmv, fid);
                if (IS_ERR(tgt_exp))
                        GOTO(cleanup, obj = (void *)tgt_exp);

                rc = md_getattr(tgt_exp, fid, NULL, valid, mealen, &req);
                if (rc) {
                        CERROR("md_getattr() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                rc = md_get_lustre_md(exp, req, NULL, exp, &md);
                if (rc) {
                        CERROR("mdc_get_lustre_md() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                if (md.mea == NULL)
                        GOTO(cleanup, obj = ERR_PTR(-ENODATA));

                mea = md.mea;
        }

        /* got mea, now create obj for it. */
        obj = __lmv_obj_create(obd, fid, mea);
        if (!obj) {
                CERROR("Can't create new object "DFID"\n",
                       PFID(fid));
                GOTO(cleanup, obj = ERR_PTR(-ENOMEM));
        }

        /* XXX LOV STACKING */
	if (md.mea != NULL)
		obd_free_memmd(exp, (void *)&md.mea);

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
 * for subsequent callers of lmv_obj_grab().
 */
int
lmv_obj_delete(struct obd_export *exp, const struct lu_fid *fid)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obj *obj;
        int rc = 0;
        ENTRY;

        spin_lock(&obj_list_lock);
        obj = __lmv_obj_grab(obd, fid);
        if (obj) {
                obj->lo_state |= O_FREEING;
                __lmv_obj_put(obj);
                __lmv_obj_put(obj);
                rc = 1;
        }
        spin_unlock(&obj_list_lock);

        RETURN(rc);
}

int
lmv_obj_setup(struct obd_device *obd)
{
        ENTRY;
        LASSERT(obd != NULL);

        CDEBUG(D_INFO, "LMV object manager setup (%s)\n",
               obd->obd_uuid.uuid);

        RETURN(0);
}

void
lmv_obj_cleanup(struct obd_device *obd)
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
                        CERROR("obj "DFID" has count > 1 (%d)\n",
                               PFID(&obj->lo_fid), atomic_read(&obj->lo_count));
                }
                __lmv_obj_put(obj);
        }
        spin_unlock(&obj_list_lock);
        EXIT;
}
