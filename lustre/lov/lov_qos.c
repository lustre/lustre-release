/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV

#ifdef __KERNEL__
#else
#include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/obd_lov.h>

#include "lov_internal.h"

void qos_shrink_lsm(struct lov_request_set *set)
{
        struct lov_stripe_md *lsm = set->set_md, *lsm_new;
        /* XXX LOV STACKING call into osc for sizes */
        unsigned oldsize, newsize;

        if (set->set_oti && set->set_cookies && set->set_cookie_sent) {
                struct llog_cookie *cookies;
                oldsize = lsm->lsm_stripe_count * sizeof(*cookies);
                newsize = set->set_count * sizeof(*cookies);

                cookies = set->set_cookies;
                oti_alloc_cookies(set->set_oti, set->set_count);
                if (set->set_oti->oti_logcookies) {
                        memcpy(set->set_oti->oti_logcookies, cookies, newsize);
                        OBD_FREE(cookies, oldsize);
                        set->set_cookies = set->set_oti->oti_logcookies;
                } else {
                        CWARN("'leaking' %d bytes\n", oldsize - newsize);
                }
        }

        CWARN("using fewer stripes for object "LPX64": old %u new %u\n",
              lsm->lsm_object_id, lsm->lsm_stripe_count, set->set_count);

        oldsize = lov_stripe_md_size(lsm->lsm_stripe_count);
        newsize = lov_stripe_md_size(set->set_count);
        OBD_ALLOC(lsm_new, newsize);
        if (lsm_new != NULL) {
                memcpy(lsm_new, lsm, newsize);
                lsm_new->lsm_stripe_count = set->set_count;
                OBD_FREE(lsm, oldsize);
                set->set_md = lsm_new;
        } else {
                CWARN("'leaking' %d bytes\n", oldsize - newsize);
        }
}

int qos_remedy_create(struct lov_request_set *set, struct lov_request *req)
{
        struct lov_stripe_md *lsm = set->set_md;
        struct lov_obd *lov = &set->set_exp->exp_obd->u.lov;
        unsigned ost_idx, ost_count = lov->desc.ld_tgt_count;
        int stripe, i, rc = -EIO;
        ENTRY;

        ost_idx = (req->rq_idx + lsm->lsm_stripe_count) % ost_count;
        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                if (lov->tgts[ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost_idx);
                        continue;
                }
                /* check if objects has been created on this ost */
                for (stripe = 0; stripe < lsm->lsm_stripe_count; stripe++) {
                        if (stripe == req->rq_stripe)
                                continue;
                        if (ost_idx == lsm->lsm_oinfo[stripe].loi_ost_idx)
                                break;
                }

                if (stripe >= lsm->lsm_stripe_count) {
                        req->rq_idx = ost_idx;
                        rc = obd_create(lov->tgts[ost_idx].ltd_exp, req->rq_oa,
                                        &req->rq_md, set->set_oti);
                        if (!rc)
                                break;
                }
        }
        RETURN(rc);
}

#define LOV_CREATE_RESEED_MULT 4
#define LOV_CREATE_RESEED_MIN  1000
/* FIXME use real qos data to prepare the lov create request */
int qos_prep_create(struct lov_obd *lov, struct lov_request_set *set, int newea)
{
        static int ost_start_idx, ost_start_count;
        unsigned ost_idx, ost_count = lov->desc.ld_tgt_count;
        unsigned ost_active_count = lov->desc.ld_active_tgt_count;
        struct lov_stripe_md *lsm = set->set_md;
        struct obdo *src_oa = set->set_oa;
        int i, rc = 0;
        ENTRY;

        LASSERT(src_oa->o_valid & OBD_MD_FLID);

        lsm->lsm_object_id = src_oa->o_id;
        if (!lsm->lsm_stripe_size)
                lsm->lsm_stripe_size = lov->desc.ld_default_stripe_size;
        if (!lsm->lsm_pattern) {
                lsm->lsm_pattern = lov->desc.ld_pattern ?
                        lov->desc.ld_pattern : LOV_PATTERN_RAID0;
        }

        if (newea || lsm->lsm_oinfo[0].loi_ost_idx >= ost_count) {
                if (--ost_start_count <= 0) {
                        ost_start_idx = ll_rand();
                        ost_start_count =
                          (LOV_CREATE_RESEED_MIN / max(ost_active_count, 1U) +
                           LOV_CREATE_RESEED_MULT) * max(ost_active_count, 1U);
                } else if (lsm->lsm_stripe_count >= ost_active_count) {
                        /* If we allocate from all of the stripes, make the
                         * next file start on the next OST. */
                        ++ost_start_idx;
                }
                ost_idx = ost_start_idx % ost_count;
        } else {
                ost_idx = lsm->lsm_oinfo[0].loi_ost_idx;
        }

        CDEBUG(D_INODE, "allocating %d subobjs for objid "LPX64" at idx %d\n",
               lsm->lsm_stripe_count, lsm->lsm_object_id, ost_idx);

        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                struct lov_request *req;

                ++ost_start_idx;
                if (lov->tgts[ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost_idx);
                        continue;
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out, rc = -ENOMEM);

                req->rq_buflen = sizeof(*req->rq_md);
                OBD_ALLOC(req->rq_md, req->rq_buflen);
                if (req->rq_md == NULL)
                        GOTO(out, rc = -ENOMEM);

                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out, rc = -ENOMEM);

                req->rq_idx = ost_idx;
                req->rq_stripe = i;
                /* create data objects with "parent" OA */
                memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));

                /* XXX When we start creating objects on demand, we need to
                 *     make sure that we always create the object on the
                 *     stripe which holds the existing file size.
                 */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        if (lov_stripe_offset(lsm, src_oa->o_size, i,
                                              &req->rq_oa->o_size) < 0 &&
                            req->rq_oa->o_size)
                                req->rq_oa->o_size--;

                        CDEBUG(D_INODE, "stripe %d has size "LPU64"/"LPU64"\n",
                               i, req->rq_oa->o_size, src_oa->o_size);
                }

                lov_set_add_req(req, set);

                /* If we have allocated enough objects, we are OK */
                if (set->set_count == lsm->lsm_stripe_count)
                        GOTO(out, rc = 0);
        }

        if (set->set_count == 0)
                GOTO(out, rc = -EIO);

        /* If we were passed specific striping params, then a failure to
         * meet those requirements is an error, since we can't reallocate
         * that memory (it might be part of a larger array or something).
         *
         * We can only get here if lsm_stripe_count was originally > 1.
         */
        if (!newea) {
                CERROR("can't lstripe objid "LPX64": have %u want %u, rc %d\n",
                       lsm->lsm_object_id, set->set_count,
                       lsm->lsm_stripe_count, rc);
                rc = rc ? rc : -EFBIG;
        } else {
                qos_shrink_lsm(set);
                rc = 0;
        }
out:
        RETURN(rc);
}
