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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Implementation of cl_object for LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov
 *  @{
 */

/*****************************************************************************
 *
 * Layout operations.
 *
 */

struct lov_layout_operations {
        int (*llo_init)(const struct lu_env *env, struct lov_device *dev,
                        struct lov_object *lov,
                        const struct cl_object_conf *conf,
                        union lov_layout_state *state);
        void (*llo_delete)(const struct lu_env *env, struct lov_object *lov,
                           union lov_layout_state *state);
        void (*llo_fini)(const struct lu_env *env, struct lov_object *lov,
                         union lov_layout_state *state);
        void (*llo_install)(const struct lu_env *env, struct lov_object *lov,
                            union lov_layout_state *state);
        int  (*llo_print)(const struct lu_env *env, void *cookie,
                          lu_printer_t p, const struct lu_object *o);
        struct cl_page *(*llo_page_init)(const struct lu_env *env,
                                         struct cl_object *obj,
                                         struct cl_page *page,
                                         cfs_page_t *vmpage);
        int  (*llo_lock_init)(const struct lu_env *env,
                              struct cl_object *obj, struct cl_lock *lock,
                              const struct cl_io *io);
        int  (*llo_io_init)(const struct lu_env *env,
                            struct cl_object *obj, struct cl_io *io);
        int  (*llo_getattr)(const struct lu_env *env, struct cl_object *obj,
                            struct cl_attr *attr);
};

/*****************************************************************************
 *
 * Lov object layout operations.
 *
 */

static void lov_install_empty(const struct lu_env *env,
                              struct lov_object *lov,
                              union  lov_layout_state *state)
{
        /*
         * File without objects.
         */
}

static int lov_init_empty(const struct lu_env *env,
                          struct lov_device *dev, struct lov_object *lov,
                          const struct cl_object_conf *conf,
                          union  lov_layout_state *state)
{
        return 0;
}

static void lov_install_raid0(const struct lu_env *env,
                              struct lov_object *lov,
                              union  lov_layout_state *state)
{
        lov->u = *state;
}

static struct cl_object *lov_sub_find(const struct lu_env *env,
                                      struct cl_device *dev,
                                      const struct lu_fid *fid,
                                      const struct cl_object_conf *conf)
{
        struct lu_object *o;

        ENTRY;
        o = lu_object_find_at(env, cl2lu_dev(dev), fid, &conf->coc_lu);
        LASSERT(ergo(!IS_ERR(o), o->lo_dev->ld_type == &lovsub_device_type));
        RETURN(lu2cl(o));
}

static int lov_init_sub(const struct lu_env *env, struct lov_object *lov,
                        struct cl_object *stripe,
                        struct lov_layout_raid0 *r0, int idx)
{
        struct cl_object_header *hdr;
        struct cl_object_header *subhdr;
        struct cl_object_header *parent;
        struct lov_oinfo        *oinfo;
        int result;

        hdr    = cl_object_header(lov2cl(lov));
        subhdr = cl_object_header(stripe);
        parent = subhdr->coh_parent;

        oinfo = r0->lo_lsm->lsm_oinfo[idx];
        CDEBUG(D_INODE, DFID"@%p[%d] -> "DFID"@%p: id: "LPU64" seq: "LPU64
               " idx: %d gen: %d\n",
               PFID(&subhdr->coh_lu.loh_fid), subhdr, idx,
               PFID(&hdr->coh_lu.loh_fid), hdr,
               oinfo->loi_id, oinfo->loi_seq,
               oinfo->loi_ost_idx, oinfo->loi_ost_gen);

        if (parent == NULL) {
                subhdr->coh_parent = hdr;
                subhdr->coh_nesting = hdr->coh_nesting + 1;
                lu_object_ref_add(&stripe->co_lu, "lov-parent", lov);
                r0->lo_sub[idx] = cl2lovsub(stripe);
                r0->lo_sub[idx]->lso_super = lov;
                r0->lo_sub[idx]->lso_index = idx;
                result = 0;
        } else {
                CERROR("Stripe is already owned by other file (%d).\n", idx);
                LU_OBJECT_DEBUG(D_ERROR, env, &stripe->co_lu, "\n");
                LU_OBJECT_DEBUG(D_ERROR, env, lu_object_top(&parent->coh_lu),
                                "old\n");
                LU_OBJECT_HEADER(D_ERROR, env, lov2lu(lov), "new\n");
                cl_object_put(env, stripe);
                result = -EIO;
        }
        return result;
}

static int lov_init_raid0(const struct lu_env *env,
                          struct lov_device *dev, struct lov_object *lov,
                          const struct cl_object_conf *conf,
                          union  lov_layout_state *state)
{
        int result;
        int i;

        struct cl_object        *stripe;
        struct lov_thread_info  *lti     = lov_env_info(env);
        struct cl_object_conf   *subconf = &lti->lti_stripe_conf;
        struct lov_stripe_md    *lsm     = conf->u.coc_md->lsm;
        struct lu_fid           *ofid    = &lti->lti_fid;
        struct lov_layout_raid0 *r0      = &state->raid0;

        ENTRY;
        r0->lo_nr  = conf->u.coc_md->lsm->lsm_stripe_count;
        r0->lo_lsm = conf->u.coc_md->lsm;
        LASSERT(r0->lo_nr <= lov_targets_nr(dev));

        OBD_ALLOC_LARGE(r0->lo_sub, r0->lo_nr * sizeof r0->lo_sub[0]);
        if (r0->lo_sub != NULL) {
                result = 0;
                subconf->coc_inode = conf->coc_inode;
                cfs_spin_lock_init(&r0->lo_sub_lock);
                /*
                 * Create stripe cl_objects.
                 */
                for (i = 0; i < r0->lo_nr && result == 0; ++i) {
                        struct cl_device *subdev;
                        struct lov_oinfo *oinfo = lsm->lsm_oinfo[i];
                        int ost_idx = oinfo->loi_ost_idx;

                        fid_ostid_unpack(ofid, &oinfo->loi_oi,
                                         oinfo->loi_ost_idx);
                        subdev = lovsub2cl_dev(dev->ld_target[ost_idx]);
                        subconf->u.coc_oinfo = oinfo;
                        LASSERTF(subdev != NULL, "not init ost %d\n", ost_idx);
                        stripe = lov_sub_find(env, subdev, ofid, subconf);
                        if (!IS_ERR(stripe))
                                result = lov_init_sub(env, lov, stripe, r0, i);
                        else
                                result = PTR_ERR(stripe);
                }
        } else
                result = -ENOMEM;
        RETURN(result);
}

static void lov_delete_empty(const struct lu_env *env, struct lov_object *lov,
                             union lov_layout_state *state)
{
        LASSERT(lov->lo_type == LLT_EMPTY);
}

static void lov_subobject_kill(const struct lu_env *env, struct lov_object *lov,
                               struct lovsub_object *los, int idx)
{
        struct cl_object        *sub;
        struct lov_layout_raid0 *r0;
        struct lu_site          *site;
        struct lu_site_bkt_data *bkt;
        cfs_waitlink_t          *waiter;

        r0  = &lov->u.raid0;
        LASSERT(r0->lo_sub[idx] == los);

        sub  = lovsub2cl(los);
        site = sub->co_lu.lo_dev->ld_site;
        bkt  = lu_site_bkt_from_fid(site, &sub->co_lu.lo_header->loh_fid);

        cl_object_kill(env, sub);
        /* release a reference to the sub-object and ... */
        lu_object_ref_del(&sub->co_lu, "lov-parent", lov);
        cl_object_put(env, sub);

        /* ... wait until it is actually destroyed---sub-object clears its
         * ->lo_sub[] slot in lovsub_object_fini() */
        if (r0->lo_sub[idx] == los) {
                waiter = &lov_env_info(env)->lti_waiter;
                cfs_waitlink_init(waiter);
                cfs_waitq_add(&bkt->lsb_marche_funebre, waiter);
                cfs_set_current_state(CFS_TASK_UNINT);
                while (1) {
                        /* this wait-queue is signaled at the end of
                         * lu_object_free(). */
                        cfs_set_current_state(CFS_TASK_UNINT);
                        cfs_spin_lock(&r0->lo_sub_lock);
                        if (r0->lo_sub[idx] == los) {
                                cfs_spin_unlock(&r0->lo_sub_lock);
                                cfs_waitq_wait(waiter, CFS_TASK_UNINT);
                        } else {
                                cfs_spin_unlock(&r0->lo_sub_lock);
                                cfs_set_current_state(CFS_TASK_RUNNING);
                                break;
                        }
                }
                cfs_waitq_del(&bkt->lsb_marche_funebre, waiter);
        }
        LASSERT(r0->lo_sub[idx] == NULL);
}

static void lov_delete_raid0(const struct lu_env *env, struct lov_object *lov,
                             union lov_layout_state *state)
{
        struct lov_layout_raid0 *r0 = &state->raid0;
        int                      i;

        ENTRY;
        if (r0->lo_sub != NULL) {
                for (i = 0; i < r0->lo_nr; ++i) {
                        struct lovsub_object *los = r0->lo_sub[i];

                        if (los != NULL)
                                /*
                                 * If top-level object is to be evicted from
                                 * the cache, so are its sub-objects.
                                 */
                                lov_subobject_kill(env, lov, los, i);
                }
        }
        EXIT;
}

static void lov_fini_empty(const struct lu_env *env, struct lov_object *lov,
                           union lov_layout_state *state)
{
        LASSERT(lov->lo_type == LLT_EMPTY);
}

static void lov_fini_raid0(const struct lu_env *env, struct lov_object *lov,
                           union lov_layout_state *state)
{
        struct lov_layout_raid0 *r0 = &state->raid0;

        ENTRY;
        if (r0->lo_sub != NULL) {
                OBD_FREE_LARGE(r0->lo_sub, r0->lo_nr * sizeof r0->lo_sub[0]);
                r0->lo_sub = NULL;
        }
        EXIT;
}

static int lov_print_empty(const struct lu_env *env, void *cookie,
                           lu_printer_t p, const struct lu_object *o)
{
        (*p)(env, cookie, "empty\n");
        return 0;
}

static int lov_print_raid0(const struct lu_env *env, void *cookie,
                           lu_printer_t p, const struct lu_object *o)
{
        struct lov_object       *lov = lu2lov(o);
        struct lov_layout_raid0 *r0  = lov_r0(lov);
        int i;

        (*p)(env, cookie, "stripes: %d:\n", r0->lo_nr);
        for (i = 0; i < r0->lo_nr; ++i) {
                struct lu_object *sub;

                if (r0->lo_sub[i] != NULL) {
                        sub = lovsub2lu(r0->lo_sub[i]);
                        lu_object_print(env, cookie, p, sub);
                } else
                        (*p)(env, cookie, "sub %d absent\n", i);
        }
        return 0;
}

/**
 * Implements cl_object_operations::coo_attr_get() method for an object
 * without stripes (LLT_EMPTY layout type).
 *
 * The only attributes this layer is authoritative in this case is
 * cl_attr::cat_blocks---it's 0.
 */
static int lov_attr_get_empty(const struct lu_env *env, struct cl_object *obj,
                              struct cl_attr *attr)
{
        attr->cat_blocks = 0;
        return 0;
}

static int lov_attr_get_raid0(const struct lu_env *env, struct cl_object *obj,
                              struct cl_attr *attr)
{
        struct lov_object       *lov = cl2lov(obj);
        struct lov_layout_raid0 *r0 = lov_r0(lov);
        struct lov_stripe_md    *lsm = lov->u.raid0.lo_lsm;
        struct ost_lvb          *lvb = &lov_env_info(env)->lti_lvb;
        __u64                    kms;
        int                      result = 0;

        ENTRY;
        if (!r0->lo_attr_valid) {
                /*
                 * Fill LVB with attributes already initialized by the upper
                 * layer.
                 */
                cl_attr2lvb(lvb, attr);
                kms = attr->cat_kms;

                /*
                 * XXX that should be replaced with a loop over sub-objects,
                 * doing cl_object_attr_get() on them. But for now, let's
                 * reuse old lov code.
                 */

                /*
                 * XXX take lsm spin-lock to keep lov_merge_lvb_kms()
                 * happy. It's not needed, because new code uses
                 * ->coh_attr_guard spin-lock to protect consistency of
                 * sub-object attributes.
                 */
                lov_stripe_lock(lsm);
                result = lov_merge_lvb_kms(lsm, lvb, &kms);
                lov_stripe_unlock(lsm);
                if (result == 0) {
                        cl_lvb2attr(attr, lvb);
                        attr->cat_kms = kms;
                        r0->lo_attr_valid = 1;
                        r0->lo_attr = *attr;
                }
        } else
                *attr = r0->lo_attr;
        RETURN(result);
}

const static struct lov_layout_operations lov_dispatch[] = {
        [LLT_EMPTY] = {
                .llo_init      = lov_init_empty,
                .llo_delete    = lov_delete_empty,
                .llo_fini      = lov_fini_empty,
                .llo_install   = lov_install_empty,
                .llo_print     = lov_print_empty,
                .llo_page_init = lov_page_init_empty,
                .llo_lock_init = NULL,
                .llo_io_init   = lov_io_init_empty,
                .llo_getattr   = lov_attr_get_empty
        },
        [LLT_RAID0] = {
                .llo_init      = lov_init_raid0,
                .llo_delete    = lov_delete_raid0,
                .llo_fini      = lov_fini_raid0,
                .llo_install   = lov_install_raid0,
                .llo_print     = lov_print_raid0,
                .llo_page_init = lov_page_init_raid0,
                .llo_lock_init = lov_lock_init_raid0,
                .llo_io_init   = lov_io_init_raid0,
                .llo_getattr   = lov_attr_get_raid0
        }
};


/**
 * Performs a double-dispatch based on the layout type of an object.
 */
#define LOV_2DISPATCH_NOLOCK(obj, op, ...)                              \
({                                                                      \
        struct lov_object                      *__obj = (obj);          \
        enum lov_layout_type                    __llt;                  \
                                                                        \
        __llt = __obj->lo_type;                                         \
        LASSERT(0 <= __llt && __llt < ARRAY_SIZE(lov_dispatch));        \
        lov_dispatch[__llt].op(__VA_ARGS__);                            \
})

#define LOV_2DISPATCH_MAYLOCK(obj, op, lock, ...)                       \
({                                                                      \
        struct lov_object                      *__obj = (obj);          \
        int                                     __lock = !!(lock);      \
        typeof(lov_dispatch[0].op(__VA_ARGS__)) __result;               \
                                                                        \
        __lock &= __obj->lo_owner != cfs_current();                     \
        if (__lock)                                                     \
                cfs_down_read(&__obj->lo_type_guard);                   \
        __result = LOV_2DISPATCH_NOLOCK(obj, op, __VA_ARGS__);          \
        if (__lock)                                                     \
                cfs_up_read(&__obj->lo_type_guard);                     \
        __result;                                                       \
})

/**
 * Performs a locked double-dispatch based on the layout type of an object.
 */
#define LOV_2DISPATCH(obj, op, ...)                     \
        LOV_2DISPATCH_MAYLOCK(obj, op, 1, __VA_ARGS__)

#define LOV_2DISPATCH_VOID(obj, op, ...)                                \
do {                                                                    \
        struct lov_object                      *__obj = (obj);          \
        enum lov_layout_type                    __llt;                  \
                                                                        \
        if (__obj->lo_owner != cfs_current())                           \
                cfs_down_read(&__obj->lo_type_guard);                   \
        __llt = __obj->lo_type;                                         \
        LASSERT(0 <= __llt && __llt < ARRAY_SIZE(lov_dispatch));        \
        lov_dispatch[__llt].op(__VA_ARGS__);                            \
        if (__obj->lo_owner != cfs_current())                           \
                cfs_up_read(&__obj->lo_type_guard);                     \
} while (0)

static int lov_layout_change(const struct lu_env *env,
                             struct lov_object *obj, enum lov_layout_type llt,
                             const struct cl_object_conf *conf)
{
        int result;
        union lov_layout_state       *state = &lov_env_info(env)->lti_state;
        const struct lov_layout_operations *old_ops;
        const struct lov_layout_operations *new_ops;

        LASSERT(0 <= obj->lo_type && obj->lo_type < ARRAY_SIZE(lov_dispatch));
        LASSERT(0 <= llt && llt < ARRAY_SIZE(lov_dispatch));
        ENTRY;

        old_ops = &lov_dispatch[obj->lo_type];
        new_ops = &lov_dispatch[llt];

        result = new_ops->llo_init(env, lu2lov_dev(obj->lo_cl.co_lu.lo_dev),
                                   obj, conf, state);
        if (result == 0) {
                struct cl_object_header *hdr = cl_object_header(&obj->lo_cl);
                void                    *cookie;
                struct lu_env           *nested;
                int                      refcheck;

                cookie = cl_env_reenter();
                nested = cl_env_get(&refcheck);
                if (!IS_ERR(nested))
                        cl_object_prune(nested, &obj->lo_cl);
                else
                        result = PTR_ERR(nested);
                cl_env_put(nested, &refcheck);
                cl_env_reexit(cookie);

                old_ops->llo_fini(env, obj, &obj->u);
                LASSERT(cfs_list_empty(&hdr->coh_locks));
                LASSERT(hdr->coh_tree.rnode == NULL);
                LASSERT(hdr->coh_pages == 0);

                new_ops->llo_install(env, obj, state);
                obj->lo_type = llt;
        } else
                new_ops->llo_fini(env, obj, state);
        RETURN(result);
}

/*****************************************************************************
 *
 * Lov object operations.
 *
 */

int lov_object_init(const struct lu_env *env, struct lu_object *obj,
                    const struct lu_object_conf *conf)
{
        struct lov_device            *dev   = lu2lov_dev(obj->lo_dev);
        struct lov_object            *lov   = lu2lov(obj);
        const struct cl_object_conf  *cconf = lu2cl_conf(conf);
        union  lov_layout_state      *set   = &lov_env_info(env)->lti_state;
        const struct lov_layout_operations *ops;
        int result;

        ENTRY;
        cfs_init_rwsem(&lov->lo_type_guard);

        /* no locking is necessary, as object is being created */
        lov->lo_type = cconf->u.coc_md->lsm != NULL ? LLT_RAID0 : LLT_EMPTY;
        ops = &lov_dispatch[lov->lo_type];
        result = ops->llo_init(env, dev, lov, cconf, set);
        if (result == 0)
                ops->llo_install(env, lov, set);
        else
                ops->llo_fini(env, lov, set);
        RETURN(result);
}

static int lov_conf_set(const struct lu_env *env, struct cl_object *obj,
                        const struct cl_object_conf *conf)
{
        struct lov_object *lov = cl2lov(obj);
        int result;

        ENTRY;
        /*
         * Currently only LLT_EMPTY -> LLT_RAID0 transition is supported.
         */
        LASSERT(lov->lo_owner != cfs_current());
        cfs_down_write(&lov->lo_type_guard);
        LASSERT(lov->lo_owner == NULL);
        lov->lo_owner = cfs_current();
        if (lov->lo_type == LLT_EMPTY && conf->u.coc_md->lsm != NULL)
                result = lov_layout_change(env, lov, LLT_RAID0, conf);
        else
                result = -EOPNOTSUPP;
        lov->lo_owner = NULL;
        cfs_up_write(&lov->lo_type_guard);
        RETURN(result);
}

static void lov_object_delete(const struct lu_env *env, struct lu_object *obj)
{
        struct lov_object *lov = lu2lov(obj);

        ENTRY;
        LOV_2DISPATCH_VOID(lov, llo_delete, env, lov, &lov->u);
        EXIT;
}

static void lov_object_free(const struct lu_env *env, struct lu_object *obj)
{
        struct lov_object *lov = lu2lov(obj);

        ENTRY;
        LOV_2DISPATCH_VOID(lov, llo_fini, env, lov, &lov->u);
        lu_object_fini(obj);
        OBD_SLAB_FREE_PTR(lov, lov_object_kmem);
        EXIT;
}

static int lov_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        return LOV_2DISPATCH(lu2lov(o), llo_print, env, cookie, p, o);
}

struct cl_page *lov_page_init(const struct lu_env *env, struct cl_object *obj,
                              struct cl_page *page, cfs_page_t *vmpage)
{
        return LOV_2DISPATCH(cl2lov(obj),
                             llo_page_init, env, obj, page, vmpage);
}

/**
 * Implements cl_object_operations::clo_io_init() method for lov
 * layer. Dispatches to the appropriate layout io initialization method.
 */
int lov_io_init(const struct lu_env *env, struct cl_object *obj,
                struct cl_io *io)
{
        CL_IO_SLICE_CLEAN(lov_env_io(env), lis_cl);
        /*
         * Do not take lock in case of CIT_MISC io, because
         *
         *     - if this is an io for a glimpse, then we don't care;
         *
         *     - if this not a glimpse (writepage or lock cancellation), then
         *       layout change cannot happen because a page or a lock
         *       already exist; and
         *
         *     - lock ordering (lock mutex nests within layout rw-semaphore)
         *       is obeyed in case of lock cancellation.
         */
        return LOV_2DISPATCH_MAYLOCK(cl2lov(obj), llo_io_init,
                                     io->ci_type != CIT_MISC, env, obj, io);
}

/**
 * An implementation of cl_object_operations::clo_attr_get() method for lov
 * layer. For raid0 layout this collects and merges attributes of all
 * sub-objects.
 */
static int lov_attr_get(const struct lu_env *env, struct cl_object *obj,
                        struct cl_attr *attr)
{
        /* do not take lock, as this function is called under a
         * spin-lock. Layout is protected from changing by ongoing IO. */
        return LOV_2DISPATCH_NOLOCK(cl2lov(obj), llo_getattr, env, obj, attr);
}

static int lov_attr_set(const struct lu_env *env, struct cl_object *obj,
                        const struct cl_attr *attr, unsigned valid)
{
        /*
         * No dispatch is required here, as no layout implements this.
         */
        return 0;
}

int lov_lock_init(const struct lu_env *env, struct cl_object *obj,
                  struct cl_lock *lock, const struct cl_io *io)
{
        return LOV_2DISPATCH(cl2lov(obj), llo_lock_init, env, obj, lock, io);
}

static const struct cl_object_operations lov_ops = {
        .coo_page_init = lov_page_init,
        .coo_lock_init = lov_lock_init,
        .coo_io_init   = lov_io_init,
        .coo_attr_get  = lov_attr_get,
        .coo_attr_set  = lov_attr_set,
        .coo_conf_set  = lov_conf_set
};

static const struct lu_object_operations lov_lu_obj_ops = {
        .loo_object_init      = lov_object_init,
        .loo_object_delete    = lov_object_delete,
        .loo_object_release   = NULL,
        .loo_object_free      = lov_object_free,
        .loo_object_print     = lov_object_print,
        .loo_object_invariant = NULL
};

struct lu_object *lov_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *unused,
                                   struct lu_device *dev)
{
        struct lov_object *lov;
        struct lu_object  *obj;

        ENTRY;
        OBD_SLAB_ALLOC_PTR_GFP(lov, lov_object_kmem, CFS_ALLOC_IO);
        if (lov != NULL) {
                obj = lov2lu(lov);
                lu_object_init(obj, NULL, dev);
                lov->lo_cl.co_ops = &lov_ops;
                lov->lo_type = -1; /* invalid, to catch uninitialized type */
                /*
                 * object io operation vector (cl_object::co_iop) is installed
                 * later in lov_object_init(), as different vectors are used
                 * for object with different layouts.
                 */
                obj->lo_ops = &lov_lu_obj_ops;
        } else
                obj = NULL;
        RETURN(obj);
}

/** @} lov */
