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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
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

#include <obd_support.h>
#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "lmv_internal.h"

extern cfs_mem_cache_t *lmv_object_cache;
extern cfs_atomic_t lmv_object_count;

static CFS_LIST_HEAD(obj_list);
static cfs_spinlock_t obj_list_lock = CFS_SPIN_LOCK_UNLOCKED;

struct lmv_object *lmv_object_alloc(struct obd_device *obd,
                                    const struct lu_fid *fid,
                                    struct lmv_stripe_md *mea)
{
        struct lmv_obd          *lmv = &obd->u.lmv;
        unsigned int             obj_size;
        struct lmv_object       *obj;
        int                      i;

        LASSERT(mea->mea_magic == MEA_MAGIC_LAST_CHAR
                || mea->mea_magic == MEA_MAGIC_ALL_CHARS
                || mea->mea_magic == MEA_MAGIC_HASH_SEGMENT);

        OBD_SLAB_ALLOC_PTR(obj, lmv_object_cache);
        if (!obj)
                return NULL;

        cfs_atomic_inc(&lmv_object_count);

        obj->lo_fid = *fid;
        obj->lo_obd = obd;
        obj->lo_state = 0;
        obj->lo_hashtype = mea->mea_magic;

        cfs_init_mutex(&obj->lo_guard);
        cfs_atomic_set(&obj->lo_count, 0);
        obj->lo_objcount = mea->mea_count;

        obj_size = sizeof(struct lmv_stripe) * 
                lmv->desc.ld_tgt_count;

        OBD_ALLOC_LARGE(obj->lo_stripes, obj_size);
        if (!obj->lo_stripes)
                goto err_obj;

        CDEBUG(D_INODE, "Allocate object for "DFID"\n", 
               PFID(fid));
        for (i = 0; i < mea->mea_count; i++) {
                int rc;

                CDEBUG(D_INODE, "Process subobject "DFID"\n", 
                       PFID(&mea->mea_ids[i]));
                obj->lo_stripes[i].ls_fid = mea->mea_ids[i];
                LASSERT(fid_is_sane(&obj->lo_stripes[i].ls_fid));

                /*
                 * Cache slave mds number to use it in all cases it is needed
                 * instead of constant lookup.
                 */
                rc = lmv_fld_lookup(lmv, &obj->lo_stripes[i].ls_fid,
                                    &obj->lo_stripes[i].ls_mds);
                if (rc)
                        goto err_obj;
        }

        return obj;
err_obj:
        OBD_FREE(obj, sizeof(*obj));
        return NULL;
}

void lmv_object_free(struct lmv_object *obj)
{
        struct lmv_obd          *lmv = &obj->lo_obd->u.lmv;
        unsigned int             obj_size;

        LASSERT(!cfs_atomic_read(&obj->lo_count));

        obj_size = sizeof(struct lmv_stripe) *
                lmv->desc.ld_tgt_count;

        OBD_FREE_LARGE(obj->lo_stripes, obj_size);
        OBD_SLAB_FREE(obj, lmv_object_cache, sizeof(*obj));
        cfs_atomic_dec(&lmv_object_count);
}

static void __lmv_object_add(struct lmv_object *obj)
{
        cfs_atomic_inc(&obj->lo_count);
        cfs_list_add(&obj->lo_list, &obj_list);
}

void lmv_object_add(struct lmv_object *obj)
{
        cfs_spin_lock(&obj_list_lock);
        __lmv_object_add(obj);
        cfs_spin_unlock(&obj_list_lock);
}

static void __lmv_object_del(struct lmv_object *obj)
{
        cfs_list_del(&obj->lo_list);
        lmv_object_free(obj);
}

void lmv_object_del(struct lmv_object *obj)
{
        cfs_spin_lock(&obj_list_lock);
        __lmv_object_del(obj);
        cfs_spin_unlock(&obj_list_lock);
}

static struct lmv_object *__lmv_object_get(struct lmv_object *obj)
{
        LASSERT(obj != NULL);
        cfs_atomic_inc(&obj->lo_count);
        return obj;
}

struct lmv_object *lmv_object_get(struct lmv_object *obj)
{
        cfs_spin_lock(&obj_list_lock);
        __lmv_object_get(obj);
        cfs_spin_unlock(&obj_list_lock);
        return obj;
}

static void __lmv_object_put(struct lmv_object *obj)
{
        LASSERT(obj);

        if (cfs_atomic_dec_and_test(&obj->lo_count)) {
                CDEBUG(D_INODE, "Last reference to "DFID" - "
                       "destroying\n", PFID(&obj->lo_fid));
                __lmv_object_del(obj);
        }
}

void lmv_object_put(struct lmv_object *obj)
{
        cfs_spin_lock(&obj_list_lock);
        __lmv_object_put(obj);
        cfs_spin_unlock(&obj_list_lock);
}

void lmv_object_put_unlock(struct lmv_object *obj)
{
        lmv_object_unlock(obj);
        lmv_object_put(obj);
}

static struct lmv_object *__lmv_object_find(struct obd_device *obd, const struct lu_fid *fid)
{
        struct lmv_object       *obj;
        cfs_list_t              *cur;

        cfs_list_for_each(cur, &obj_list) {
                obj = cfs_list_entry(cur, struct lmv_object, lo_list);

                /*
                 * Check if object is in destroying phase. If so - skip
                 * it.
                 */
                if (obj->lo_state & O_FREEING)
                        continue;

                /*
                 * We should make sure, that we have found object belong to
                 * passed obd. It is possible that, object manager will have two
                 * objects with the same fid belong to different obds, if client
                 * and mds runs on the same host. May be it is good idea to have
                 * objects list associated with obd.
                 */
                if (obj->lo_obd != obd)
                        continue;

                /*
                 * Check if this is what we're looking for.
                 */
                if (lu_fid_eq(&obj->lo_fid, fid))
                        return __lmv_object_get(obj);
        }

        return NULL;
}

struct lmv_object *lmv_object_find(struct obd_device *obd, 
                                   const struct lu_fid *fid)
{
        struct lmv_object       *obj;
        ENTRY;

        cfs_spin_lock(&obj_list_lock);
        obj = __lmv_object_find(obd, fid);
        cfs_spin_unlock(&obj_list_lock);

        RETURN(obj);
}

struct lmv_object *lmv_object_find_lock(struct obd_device *obd, 
                                        const struct lu_fid *fid)
{
        struct lmv_object       *obj;
        ENTRY;

        obj = lmv_object_find(obd, fid);
        if (obj)
                lmv_object_lock(obj);

        RETURN(obj);
}

static struct lmv_object *__lmv_object_create(struct obd_device *obd, 
                                              const struct lu_fid *fid,
                                              struct lmv_stripe_md *mea)
{
        struct lmv_object       *new;
        struct lmv_object       *obj;
        ENTRY;

        obj = lmv_object_find(obd, fid);
        if (obj)
                RETURN(obj);

        new = lmv_object_alloc(obd, fid, mea);
        if (!new)
                RETURN(NULL);

        /* 
         * Check if someone created it already while we were dealing with
         * allocating @obj. 
         */
        cfs_spin_lock(&obj_list_lock);
        obj = __lmv_object_find(obd, fid);
        if (obj) {
                /* 
                 * Someone created it already - put @obj and getting out. 
                 */
                cfs_spin_unlock(&obj_list_lock);
                lmv_object_free(new);
                RETURN(obj);
        }

        __lmv_object_add(new);
        __lmv_object_get(new);

        cfs_spin_unlock(&obj_list_lock);

        CDEBUG(D_INODE, "New obj in lmv cache: "DFID"\n",
               PFID(fid));

        RETURN(new);
}

struct lmv_object *lmv_object_create(struct obd_export *exp, 
                                     const struct lu_fid *fid,
                                     struct lmv_stripe_md *mea)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct ptlrpc_request   *req = NULL;
        struct lmv_tgt_desc     *tgt;
        struct lmv_object       *obj;
        struct lustre_md         md;
        int                      mealen;
        int                      rc;
        ENTRY;

        CDEBUG(D_INODE, "Get mea for "DFID" and create lmv obj\n",
               PFID(fid));

        md.mea = NULL;

        if (mea == NULL) {
                struct md_op_data *op_data;
                __u64 valid;

                CDEBUG(D_INODE, "Mea isn't passed in, get it now\n");
                mealen = lmv_get_easize(lmv);

                /*
                 * Time to update mea of parent fid.
                 */
                md.mea = NULL;
                valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA | OBD_MD_MEA;

                tgt = lmv_find_target(lmv, fid);
                if (IS_ERR(tgt))
                        GOTO(cleanup, obj = (void *)tgt);

                OBD_ALLOC_PTR(op_data);
                if (op_data == NULL)
                        GOTO(cleanup, obj = ERR_PTR(-ENOMEM));

                op_data->op_fid1 = *fid;
                op_data->op_mode = mealen;
                op_data->op_valid = valid;
                rc = md_getattr(tgt->ltd_exp, op_data, &req);
                OBD_FREE_PTR(op_data);
                if (rc) {
                        CERROR("md_getattr() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                rc = md_get_lustre_md(exp, req, NULL, exp, &md);
                if (rc) {
                        CERROR("md_get_lustre_md() failed, error %d\n", rc);
                        GOTO(cleanup, obj = ERR_PTR(rc));
                }

                if (md.mea == NULL)
                        GOTO(cleanup, obj = ERR_PTR(-ENODATA));

                mea = md.mea;
        }

        /*
         * Got mea, now create obj for it.
         */
        obj = __lmv_object_create(obd, fid, mea);
        if (!obj) {
                CERROR("Can't create new object "DFID"\n",
                       PFID(fid));
                GOTO(cleanup, obj = ERR_PTR(-ENOMEM));
        }

	if (md.mea != NULL)
		obd_free_memmd(exp, (void *)&md.mea);

	EXIT;
cleanup:
        if (req)
                ptlrpc_req_finished(req);
        return obj;
}

int lmv_object_delete(struct obd_export *exp, const struct lu_fid *fid)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_object       *obj;
        int                      rc = 0;
        ENTRY;

        cfs_spin_lock(&obj_list_lock);
        obj = __lmv_object_find(obd, fid);
        if (obj) {
                obj->lo_state |= O_FREEING;
                __lmv_object_put(obj);
                __lmv_object_put(obj);
                rc = 1;
        }
        cfs_spin_unlock(&obj_list_lock);
        RETURN(rc);
}

int lmv_object_setup(struct obd_device *obd)
{
        ENTRY;
        LASSERT(obd != NULL);

        CDEBUG(D_INFO, "LMV object manager setup (%s)\n",
               obd->obd_uuid.uuid);

        RETURN(0);
}

void lmv_object_cleanup(struct obd_device *obd)
{
        cfs_list_t              *cur;
        cfs_list_t              *tmp;
        struct lmv_object       *obj;
        ENTRY;

        CDEBUG(D_INFO, "LMV object manager cleanup (%s)\n",
               obd->obd_uuid.uuid);

        cfs_spin_lock(&obj_list_lock);
        cfs_list_for_each_safe(cur, tmp, &obj_list) {
                obj = cfs_list_entry(cur, struct lmv_object, lo_list);

                if (obj->lo_obd != obd)
                        continue;

                obj->lo_state |= O_FREEING;
                if (cfs_atomic_read(&obj->lo_count) > 1) {
                        CERROR("Object "DFID" has count (%d)\n", 
                               PFID(&obj->lo_fid),
                               cfs_atomic_read(&obj->lo_count));
                }
                __lmv_object_put(obj);
        }
        cfs_spin_unlock(&obj_list_lock);
        EXIT;
}
