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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Implementation of cl_page for LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov lov @{ */

/*****************************************************************************
 *
 * Lov page operations.
 *
 */

static int lov_page_invariant(const struct cl_page_slice *slice)
{
        const struct cl_page  *page = slice->cpl_page;
        const struct cl_page  *sub  = lov_sub_page(slice);

        return ergo(sub != NULL,
                    page->cp_child == sub &&
                    sub->cp_parent == page &&
                    page->cp_state == sub->cp_state);
}

static void lov_page_fini(const struct lu_env *env,
                          struct cl_page_slice *slice)
{
        struct lov_page *lp  = cl2lov_page(slice);
        struct cl_page  *sub = lov_sub_page(slice);

        LINVRNT(lov_page_invariant(slice));
        ENTRY;

        if (sub != NULL) {
                LASSERT(sub->cp_state == CPS_FREEING);
                lu_ref_del(&sub->cp_reference, "lov", sub->cp_parent);
                sub->cp_parent = NULL;
                slice->cpl_page->cp_child = NULL;
                cl_page_put(env, sub);
        }
        OBD_SLAB_FREE_PTR(lp, lov_page_kmem);
        EXIT;
}

static void lov_page_own(const struct lu_env *env,
                         const struct cl_page_slice *slice, struct cl_io *io)
{
        struct lov_io     *lio = lov_env_io(env);
        struct lov_io_sub *sub;

        LINVRNT(lov_page_invariant(slice));
        LINVRNT(!cl2lov_page(slice)->lps_invalid);
        ENTRY;

        sub = lov_page_subio(env, lio, slice);
        if (!IS_ERR(sub)) {
                lov_sub_page(slice)->cp_owner = sub->sub_io;
                lov_sub_put(sub);
        } else
                LBUG(); /* Arrgh */
        EXIT;
}

static void lov_page_assume(const struct lu_env *env,
                            const struct cl_page_slice *slice, struct cl_io *io)
{
        return lov_page_own(env, slice, io);
}

static int lov_page_print(const struct lu_env *env,
                          const struct cl_page_slice *slice,
                          void *cookie, lu_printer_t printer)
{
        struct lov_page *lp = cl2lov_page(slice);

        return (*printer)(env, cookie, LUSTRE_LOV_NAME"-page@%p\n", lp);
}

static const struct cl_page_operations lov_page_ops = {
        .cpo_fini   = lov_page_fini,
        .cpo_own    = lov_page_own,
        .cpo_assume = lov_page_assume,
        .cpo_print  = lov_page_print
};

static void lov_empty_page_fini(const struct lu_env *env,
                                struct cl_page_slice *slice)
{
        struct lov_page *lp  = cl2lov_page(slice);

        LASSERT(slice->cpl_page->cp_child == NULL);
        ENTRY;
        OBD_SLAB_FREE_PTR(lp, lov_page_kmem);
        EXIT;
}

struct cl_page *lov_page_init_raid0(const struct lu_env *env,
                                    struct cl_object *obj, struct cl_page *page,
                                    cfs_page_t *vmpage)
{
        struct lov_page   *lpg;
        struct lov_object *loo = cl2lov(obj);
        int result;

        ENTRY;
        OBD_SLAB_ALLOC_PTR(lpg, lov_page_kmem);
        if (lpg != NULL) {
                loff_t   offset;
                int      stripe;
                obd_off  suboff;
                struct cl_page          *subpage;
                struct cl_object        *subobj;
                struct lov_layout_raid0 *r0 = lov_r0(loo);

                offset = cl_offset(obj, page->cp_index);
                stripe = lov_stripe_number(r0->lo_lsm, offset);
                result = lov_stripe_offset(r0->lo_lsm, offset, stripe,
                                           &suboff);
                LASSERT(stripe < r0->lo_nr);
                LASSERT(result == 0);

                subobj  = lovsub2cl(r0->lo_sub[stripe]);
                subpage = cl_page_find(env, subobj,
                                       cl_index(subobj, suboff), vmpage,
                                       page->cp_type);
                if (!IS_ERR(subpage)) {
                        if (subpage->cp_parent != NULL) {
                                /*
                                 * This is only possible when TRANSIENT page
                                 * is being created, and CACHEABLE sub-page
                                 * (attached to already existing top-page) has
                                 * been found. Tell cl_page_find() to use
                                 * existing page.
                                 */
                                LASSERT(subpage->cp_type == CPT_CACHEABLE);
                                LASSERT(page->cp_type == CPT_TRANSIENT);
                                lpg->lps_invalid = 1;
                                cl_page_put(env, subpage);
                                /*
                                 * XXX This assumes that lov is in the topmost
                                 * cl_page.
                                 */
                                result = PTR_ERR(cl_page_top(subpage));
                        } else {
                                lu_ref_add(&subpage->cp_reference, "lov", page);
                                subpage->cp_parent = page;
                                page->cp_child = subpage;
                        }
                        cl_page_slice_add(page, &lpg->lps_cl,
                                          obj, &lov_page_ops);
                } else
                        result = PTR_ERR(subpage);
        } else
                result = -ENOMEM;
        RETURN(ERR_PTR(result));
}


static const struct cl_page_operations lov_empty_page_ops = {
        .cpo_fini   = lov_empty_page_fini,
        .cpo_print  = lov_page_print
};

struct cl_page *lov_page_init_empty(const struct lu_env *env,
                                    struct cl_object *obj, struct cl_page *page,
                                    cfs_page_t *vmpage)
{
        struct lov_page   *lpg;
        int result = -ENOMEM;
        ENTRY;

        OBD_SLAB_ALLOC_PTR(lpg, lov_page_kmem);
        if (lpg != NULL) {
                void *addr;
                cl_page_slice_add(page, &lpg->lps_cl,
                                  obj, &lov_empty_page_ops);
                addr = cfs_kmap(vmpage);
                memset(addr, 0, cl_page_size(obj));
                cfs_kunmap(vmpage);
                cl_page_export(env, page);
                result = 0;
        }
        RETURN(ERR_PTR(result));
}


/** @} lov */

