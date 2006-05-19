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
#include <libcfs/libcfs.h>
#else
#include <liblustre.h>
#endif

#include <obd_class.h>
#include <obd_lov.h>
#include <lustre/lustre_idl.h>

#include "lov_internal.h"

static void lov_init_set(struct lov_request_set *set)
{
        set->set_count = 0;
        set->set_completes = 0;
        set->set_success = 0;
        CFS_INIT_LIST_HEAD(&set->set_list);
        atomic_set(&set->set_refcount, 1);
}

static void lov_finish_set(struct lov_request_set *set)
{
        struct list_head *pos, *n;
        ENTRY;

        LASSERT(set);
        list_for_each_safe(pos, n, &set->set_list) {
                struct lov_request *req = list_entry(pos, struct lov_request,
                                                     rq_link);
                list_del_init(&req->rq_link);

                if (req->rq_oa)
                        obdo_free(req->rq_oa);
                if (req->rq_md)
                        OBD_FREE(req->rq_md, req->rq_buflen);
                OBD_FREE(req, sizeof(*req));
        }

        if (set->set_pga) {
                int len = set->set_oabufs * sizeof(*set->set_pga);
                OBD_FREE(set->set_pga, len);
        }
        if (set->set_lockh)
                lov_llh_put(set->set_lockh);

        OBD_FREE(set, sizeof(*set));
        EXIT;
}

static void lov_update_set(struct lov_request_set *set,
                           struct lov_request *req, int rc)
{
        req->rq_complete = 1;
        req->rq_rc = rc;

        set->set_completes++;
        if (rc == 0)
                set->set_success++;
}

int lov_update_common_set(struct lov_request_set *set,
                          struct lov_request *req, int rc)
{
        struct lov_obd *lov = &set->set_exp->exp_obd->u.lov;
        ENTRY;

        lov_update_set(set, req, rc);

        /* grace error on inactive ost */
        if (rc && !lov->tgts[req->rq_idx].active)
                rc = 0;

        /* FIXME in raid1 regime, should return 0 */
        RETURN(rc);
}

void lov_set_add_req(struct lov_request *req, struct lov_request_set *set)
{
        list_add_tail(&req->rq_link, &set->set_list);
        set->set_count++;
}

int lov_update_enqueue_set(struct lov_request_set *set,
                           struct lov_request *req, int rc, int flags)
{
        struct lustre_handle *lov_lockhp;
        struct lov_oinfo *loi;
        ENTRY;

        lov_lockhp = set->set_lockh->llh_handles + req->rq_stripe;
        loi = &set->set_md->lsm_oinfo[req->rq_stripe];

        /* XXX FIXME: This unpleasantness doesn't belong here at *all*.
         * It belongs in the OSC, except that the OSC doesn't have
         * access to the real LOI -- it gets a copy, that we created
         * above, and that copy can be arbitrarily out of date.
         *
         * The LOV API is due for a serious rewriting anyways, and this
         * can be addressed then. */
        if (rc == ELDLM_OK) {
                struct ldlm_lock *lock = ldlm_handle2lock(lov_lockhp);
                __u64 tmp = req->rq_md->lsm_oinfo->loi_lvb.lvb_size;

                LASSERT(lock != NULL);
                lov_stripe_lock(set->set_md);
                loi->loi_lvb = req->rq_md->lsm_oinfo->loi_lvb;
                /* Extend KMS up to the end of this lock and no further
                 * A lock on [x,y] means a KMS of up to y + 1 bytes! */
                if (tmp > lock->l_policy_data.l_extent.end)
                        tmp = lock->l_policy_data.l_extent.end + 1;
                if (tmp >= loi->loi_kms) {
                        LDLM_DEBUG(lock, "lock acquired, setting rss="LPU64
                                   ", kms="LPU64, loi->loi_lvb.lvb_size, tmp);
                        loi->loi_kms = tmp;
                        loi->loi_kms_valid = 1;
                } else {
                        LDLM_DEBUG(lock, "lock acquired, setting rss="
                                   LPU64"; leaving kms="LPU64", end="LPU64,
                                   loi->loi_lvb.lvb_size, loi->loi_kms,
                                   lock->l_policy_data.l_extent.end);
                }
                lov_stripe_unlock(set->set_md);
                ldlm_lock_allow_match(lock);
                LDLM_LOCK_PUT(lock);
        } else if (rc == ELDLM_LOCK_ABORTED && flags & LDLM_FL_HAS_INTENT) {
                memset(lov_lockhp, 0, sizeof(*lov_lockhp));
                lov_stripe_lock(set->set_md);
                loi->loi_lvb = req->rq_md->lsm_oinfo->loi_lvb;
                lov_stripe_unlock(set->set_md);
                CDEBUG(D_INODE, "glimpsed, setting rss="LPU64"; leaving"
                       " kms="LPU64"\n", loi->loi_lvb.lvb_size, loi->loi_kms);
                rc = ELDLM_OK;
        } else {
                struct obd_export *exp = set->set_exp;
                struct lov_obd *lov = &exp->exp_obd->u.lov;

                memset(lov_lockhp, 0, sizeof(*lov_lockhp));
                if (lov->tgts[req->rq_idx].active) {
                        CERROR("error: enqueue objid "LPX64" subobj "
                                LPX64" on OST idx %d: rc = %d\n",
                                set->set_md->lsm_object_id, loi->loi_id,
                                loi->loi_ost_idx, rc);
                } else {
                        rc = ELDLM_OK;
                }
        }
        lov_update_set(set, req, rc);
        RETURN(rc);
}

static int enqueue_done(struct lov_request_set *set, __u32 mode)
{
        struct lov_request *req;
        struct lustre_handle *lov_lockhp = NULL;
        struct lov_obd *lov = &set->set_exp->exp_obd->u.lov;
        int rc = 0;
        ENTRY;

        LASSERT(set->set_completes);
        /* enqueue/match success, just return */
        if (set->set_completes == set->set_success)
                RETURN(0);

        /* cancel enqueued/matched locks */
        list_for_each_entry(req, &set->set_list, rq_link) {
                if (!req->rq_complete || req->rq_rc)
                        continue;

                lov_lockhp = set->set_lockh->llh_handles + req->rq_stripe;
                LASSERT(lov_lockhp);
                if (!lustre_handle_is_used(lov_lockhp))
                        continue;

                rc = obd_cancel(lov->tgts[req->rq_idx].ltd_exp, req->rq_md,
                                mode, lov_lockhp);
                if (rc && lov->tgts[req->rq_idx].active)
                        CERROR("cancelling obdjid "LPX64" on OST "
                               "idx %d error: rc = %d\n",
                               req->rq_md->lsm_object_id, req->rq_idx, rc);
        }
        lov_llh_put(set->set_lockh);
        RETURN(rc);
}

int lov_fini_enqueue_set(struct lov_request_set *set, __u32 mode)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes)
                rc = enqueue_done(set, mode);
        else
                lov_llh_put(set->set_lockh);

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_prep_enqueue_set(struct obd_export *exp, struct lov_stripe_md *lsm,
                         ldlm_policy_data_t *policy, __u32 mode,
                         struct lustre_handle *lockh,
                         struct lov_request_set **reqset)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_request_set *set;
        int i, rc = 0;
        struct lov_oinfo *loi;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_lockh = lov_llh_new(lsm);
        if (set->set_lockh == NULL)
                GOTO(out_set, rc = -ENOMEM);
        lockh->cookie = set->set_lockh->llh_handle.h_cookie;

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                struct lov_request *req;
                obd_off start, end;

                if (!lov_stripe_intersects(lsm, i, policy->l_extent.start,
                                           policy->l_extent.end, &start, &end))
                        continue;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_buflen = sizeof(*req->rq_md) +
                        sizeof(struct lov_oinfo);
                OBD_ALLOC(req->rq_md, req->rq_buflen);
                if (req->rq_md == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_extent.start = start;
                req->rq_extent.end = end;
                req->rq_extent.gid = policy->l_extent.gid;

                req->rq_idx = loi->loi_ost_idx;
                req->rq_stripe = i;

                /* XXX LOV STACKING: submd should be from the subobj */
                req->rq_md->lsm_object_id = loi->loi_id;
                req->rq_md->lsm_stripe_count = 0;
                req->rq_md->lsm_oinfo->loi_kms_valid = loi->loi_kms_valid;
                req->rq_md->lsm_oinfo->loi_kms = loi->loi_kms;
                req->rq_md->lsm_oinfo->loi_lvb = loi->loi_lvb;

                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(0);
out_set:
        lov_fini_enqueue_set(set, mode);
        RETURN(rc);
}

int lov_update_match_set(struct lov_request_set *set, struct lov_request *req,
                         int rc)
{
        int ret = rc;
        ENTRY;

        if (rc == 1)
                ret = 0;
        lov_update_set(set, req, ret);
        RETURN(rc);
}

int lov_fini_match_set(struct lov_request_set *set, __u32 mode, int flags)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes) {
                if (set->set_count == set->set_success &&
                    flags & LDLM_FL_TEST_LOCK)
                        lov_llh_put(set->set_lockh);
                rc = enqueue_done(set, mode);
        } else {
                lov_llh_put(set->set_lockh);
        }

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_prep_match_set(struct obd_export *exp, struct lov_stripe_md *lsm,
                       ldlm_policy_data_t *policy, __u32 mode,
                       struct lustre_handle *lockh,
                       struct lov_request_set **reqset)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_request_set *set;
        int i, rc = 0;
        struct lov_oinfo *loi;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_lockh = lov_llh_new(lsm);
        if (set->set_lockh == NULL)
                GOTO(out_set, rc = -ENOMEM);
        lockh->cookie = set->set_lockh->llh_handle.h_cookie;

        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++, loi++){
                struct lov_request *req;
                obd_off start, end;

                if (!lov_stripe_intersects(lsm, i, policy->l_extent.start,
                                           policy->l_extent.end, &start, &end))
                        continue;

                /* FIXME raid1 should grace this error */
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        GOTO(out_set, rc = -EIO);
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_buflen = sizeof(*req->rq_md);
                OBD_ALLOC(req->rq_md, req->rq_buflen);
                if (req->rq_md == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_extent.start = start;
                req->rq_extent.end = end;
                req->rq_extent.gid = policy->l_extent.gid;

                req->rq_idx = loi->loi_ost_idx;
                req->rq_stripe = i;

                /* XXX LOV STACKING: submd should be from the subobj */
                req->rq_md->lsm_object_id = loi->loi_id;
                req->rq_md->lsm_stripe_count = 0;

                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(rc);
out_set:
        lov_fini_match_set(set, mode, 0);
        RETURN(rc);
}

int lov_fini_cancel_set(struct lov_request_set *set)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);

        LASSERT(set->set_exp);
        if (set->set_lockh)
                lov_llh_put(set->set_lockh);

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_prep_cancel_set(struct obd_export *exp, struct lov_stripe_md *lsm,
                        __u32 mode, struct lustre_handle *lockh,
                        struct lov_request_set **reqset)
{
        struct lov_request_set *set;
        int i, rc = 0;
        struct lov_oinfo *loi;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_lockh = lov_handle2llh(lockh);
        if (set->set_lockh == NULL) {
                CERROR("LOV: invalid lov lock handle %p\n", lockh);
                GOTO(out_set, rc = -EINVAL);
        }
        lockh->cookie = set->set_lockh->llh_handle.h_cookie;

        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++, loi++){
                struct lov_request *req;
                struct lustre_handle *lov_lockhp;

                lov_lockhp = set->set_lockh->llh_handles + i;
                if (!lustre_handle_is_used(lov_lockhp)) {
                        CDEBUG(D_HA, "lov idx %d subobj "LPX64" no lock?\n",
                               loi->loi_ost_idx, loi->loi_id);
                        continue;
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_buflen = sizeof(*req->rq_md);
                OBD_ALLOC(req->rq_md, req->rq_buflen);
                if (req->rq_md == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_idx = loi->loi_ost_idx;
                req->rq_stripe = i;

                /* XXX LOV STACKING: submd should be from the subobj */
                req->rq_md->lsm_object_id = loi->loi_id;
                req->rq_md->lsm_stripe_count = 0;

                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(rc);
out_set:
        lov_fini_cancel_set(set);
        RETURN(rc);
}

static int create_done(struct obd_export *exp, struct lov_request_set *set,
                       struct lov_stripe_md **lsmp)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct obd_trans_info *oti = set->set_oti;
        struct obdo *src_oa = set->set_oa;
        struct lov_request *req;
        struct obdo *ret_oa = NULL;
        int attrset = 0, rc = 0;
        ENTRY;

        LASSERT(set->set_completes);

        /* try alloc objects on other osts if osc_create fails for
         * exceptions: RPC failure, ENOSPC, etc */
        if (set->set_count != set->set_success) {
                list_for_each_entry (req, &set->set_list, rq_link) {
                        if (req->rq_rc == 0)
                                continue;
                        
                        set->set_completes--;
                        req->rq_complete = 0;
                        
                        rc = qos_remedy_create(set, req);
                        lov_update_create_set(set, req, rc);

                        if (rc)
                                break;
                }
        }

        /* no successful creates */
        if (set->set_success == 0)
                GOTO(cleanup, rc);
        
        /* If there was an explicit stripe set, fail.  Otherwise, we
         * got some objects and that's not bad. */
        if (set->set_count != set->set_success) {
                if (*lsmp)
                        GOTO(cleanup, rc);
                set->set_count = set->set_success;
                qos_shrink_lsm(set);
        }

        ret_oa = obdo_alloc();
        if (ret_oa == NULL)
                GOTO(cleanup, rc = -ENOMEM);

        list_for_each_entry(req, &set->set_list, rq_link) {
                if (!req->rq_complete || req->rq_rc)
                        continue;
                lov_merge_attrs(ret_oa, req->rq_oa, req->rq_oa->o_valid,
                                set->set_md, req->rq_stripe, &attrset);
        }
        if (src_oa->o_valid & OBD_MD_FLSIZE &&
            ret_oa->o_size != src_oa->o_size) {
                CERROR("original size "LPU64" isn't new object size "LPU64"\n",
                       src_oa->o_size, ret_oa->o_size);
                LBUG();
        }
        ret_oa->o_id = src_oa->o_id;
        memcpy(src_oa, ret_oa, sizeof(*src_oa));
        obdo_free(ret_oa);

        *lsmp = set->set_md;
        GOTO(done, rc = 0);

cleanup:
        list_for_each_entry(req, &set->set_list, rq_link) {
                struct obd_export *sub_exp;
                int err = 0;

                if (!req->rq_complete || req->rq_rc)
                        continue;

                sub_exp = lov->tgts[req->rq_idx].ltd_exp;
                err = obd_destroy(sub_exp, req->rq_oa, NULL, oti, NULL);
                if (err)
                        CERROR("Failed to uncreate objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               set->set_oa->o_id, req->rq_oa->o_id,
                               req->rq_idx, rc);
        }
        if (*lsmp == NULL)
                obd_free_memmd(exp, &set->set_md);
done:
        if (oti && set->set_cookies) {
                oti->oti_logcookies = set->set_cookies;
                if (!set->set_cookie_sent) {
                        oti_free_cookies(oti);
                        src_oa->o_valid &= ~OBD_MD_FLCOOKIE;
                } else {
                        src_oa->o_valid |= OBD_MD_FLCOOKIE;
                }
        }
        RETURN(rc);
}

int lov_fini_create_set(struct lov_request_set *set,struct lov_stripe_md **lsmp)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes)
                rc = create_done(set->set_exp, set, lsmp);

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_update_create_set(struct lov_request_set *set,
                          struct lov_request *req, int rc)
{
        struct obd_trans_info *oti = set->set_oti;
        struct lov_stripe_md *lsm = set->set_md;
        struct lov_oinfo *loi;
        struct lov_obd *lov = &set->set_exp->exp_obd->u.lov;
        ENTRY;

        req->rq_stripe = set->set_success;
        loi = &lsm->lsm_oinfo[req->rq_stripe];

        if (rc && lov->tgts[req->rq_idx].active) {
                CERROR("error creating fid "LPX64" sub-object"
                       " on OST idx %d/%d: rc = %d\n",
                       set->set_oa->o_id, req->rq_idx,
                       lsm->lsm_stripe_count, rc);
                if (rc > 0) {
                        CERROR("obd_create returned invalid err %d\n", rc);
                        rc = -EIO;
                }
        }
        lov_update_set(set, req, rc);
        if (rc)
                RETURN(rc);

        if (oti && oti->oti_objid)
                oti->oti_objid[req->rq_idx] = req->rq_oa->o_id;

        loi->loi_id = req->rq_oa->o_id;
        loi->loi_ost_idx = req->rq_idx;
        CDEBUG(D_INODE, "objid "LPX64" has subobj "LPX64"/"LPX64" at idx %d\n",
               lsm->lsm_object_id, loi->loi_id, loi->loi_id, req->rq_idx);
        loi_init(loi);

        if (set->set_cookies)
                ++oti->oti_logcookies;
        if (req->rq_oa->o_valid & OBD_MD_FLCOOKIE)
                set->set_cookie_sent++;

        RETURN(0);
}

int lov_prep_create_set(struct obd_export *exp, struct lov_stripe_md **lsmp,
                        struct obdo *src_oa, struct obd_trans_info *oti,
                        struct lov_request_set **reqset)
{
        struct lov_request_set *set;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = *lsmp;
        set->set_oa = src_oa;
        set->set_oti = oti;

        rc = qos_prep_create(exp, set);
        if (rc)
                lov_fini_create_set(set, lsmp);
        else
                *reqset = set;
        RETURN(rc);
}

static int common_attr_done(struct lov_request_set *set)
{
        struct list_head *pos;
        struct lov_request *req;
        struct obdo *tmp_oa;
        int rc = 0, attrset = 0;
        ENTRY;

        if (set->set_oa == NULL)
                RETURN(0);

        if (!set->set_success)
                RETURN(-EIO);

        tmp_oa = obdo_alloc();
        if (tmp_oa == NULL)
                GOTO(out, rc = -ENOMEM);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                if (!req->rq_complete || req->rq_rc)
                        continue;
                if (req->rq_oa->o_valid == 0)   /* inactive stripe */
                        continue;
                lov_merge_attrs(tmp_oa, req->rq_oa, req->rq_oa->o_valid,
                                set->set_md, req->rq_stripe, &attrset);
        }
        if (!attrset) {
                CERROR("No stripes had valid attrs\n");
                rc = -EIO;
        }
        tmp_oa->o_id = set->set_oa->o_id;
        memcpy(set->set_oa, tmp_oa, sizeof(*set->set_oa));
out:
        if (tmp_oa)
                obdo_free(tmp_oa);
        RETURN(rc);

}

static int brw_done(struct lov_request_set *set)
{
        struct lov_stripe_md *lsm = set->set_md;
        struct lov_oinfo     *loi = NULL;
        struct list_head *pos;
        struct lov_request *req;
        ENTRY;

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                if (!req->rq_complete || req->rq_rc)
                        continue;

                loi = &lsm->lsm_oinfo[req->rq_stripe];

                if (req->rq_oa->o_valid & OBD_MD_FLBLOCKS)
                        loi->loi_lvb.lvb_blocks = req->rq_oa->o_blocks;
        }

        RETURN(0);
}

int lov_fini_brw_set(struct lov_request_set *set)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes) {
                rc = brw_done(set);
                /* FIXME update qos data here */
        }
        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_prep_brw_set(struct obd_export *exp, struct obdo *src_oa,
                     struct lov_stripe_md *lsm, obd_count oa_bufs,
                     struct brw_page *pga, struct obd_trans_info *oti,
                     struct lov_request_set **reqset)
{
        struct {
                obd_count       index;
                obd_count       count;
                obd_count       off;
        } *info = NULL;
        struct lov_request_set *set;
        struct lov_oinfo *loi = NULL;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, i, shift;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_oa = src_oa;
        set->set_oti = oti;
        set->set_oabufs = oa_bufs;
        OBD_ALLOC(set->set_pga, oa_bufs * sizeof(*set->set_pga));
        if (!set->set_pga)
                GOTO(out, rc = -ENOMEM);

        OBD_ALLOC(info, sizeof(*info) * lsm->lsm_stripe_count);
        if (!info)
                GOTO(out, rc = -ENOMEM);

        /* calculate the page count for each stripe */
        for (i = 0; i < oa_bufs; i++) {
                int stripe = lov_stripe_number(lsm, pga[i].off);
                info[stripe].count++;
        }

        /* alloc and initialize lov request */
        shift = 0;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++, loi++){
                struct lov_request *req;

                if (info[i].count == 0)
                        continue;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        GOTO(out, rc = -EIO);
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out, rc = -ENOMEM);

                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out, rc = -ENOMEM);

                if (src_oa)
                        memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));
                req->rq_oa->o_id = loi->loi_id;
                req->rq_oa->o_stripe_idx = i;

                req->rq_buflen = sizeof(*req->rq_md);
                OBD_ALLOC(req->rq_md, req->rq_buflen);
                if (req->rq_md == NULL)
                        GOTO(out, rc = -ENOMEM);

                req->rq_idx = loi->loi_ost_idx;
                req->rq_stripe = i;

                /* XXX LOV STACKING */
                req->rq_md->lsm_object_id = loi->loi_id;
                req->rq_md->lsm_object_gr = lsm->lsm_object_gr;
                req->rq_oabufs = info[i].count;
                req->rq_pgaidx = shift;
                shift += req->rq_oabufs;

                /* remember the index for sort brw_page array */
                info[i].index = req->rq_pgaidx;

                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out, rc = -EIO);

        /* rotate & sort the brw_page array */
        for (i = 0; i < oa_bufs; i++) {
                int stripe = lov_stripe_number(lsm, pga[i].off);

                shift = info[stripe].index + info[stripe].off;
                LASSERT(shift < oa_bufs);
                set->set_pga[shift] = pga[i];
                lov_stripe_offset(lsm, pga[i].off, stripe,
                                  &set->set_pga[shift].off);
                info[stripe].off++;
        }
out:
        if (info)
                OBD_FREE(info, sizeof(*info) * lsm->lsm_stripe_count);

        if (rc == 0)
                *reqset = set;
        else
                lov_fini_brw_set(set);

        RETURN(rc);
}

int lov_fini_getattr_set(struct lov_request_set *set)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes)
                rc = common_attr_done(set);

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_prep_getattr_set(struct obd_export *exp, struct obdo *src_oa,
                         struct lov_stripe_md *lsm,
                         struct lov_request_set **reqset)
{
        struct lov_request_set *set;
        struct lov_oinfo *loi = NULL;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, i;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_oa = src_oa;

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                struct lov_request *req;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_stripe = i;
                req->rq_idx = loi->loi_ost_idx;

                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));
                req->rq_oa->o_id = loi->loi_id;

                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(rc);
out_set:
        lov_fini_getattr_set(set);
        RETURN(rc);
}

int lov_fini_destroy_set(struct lov_request_set *set)
{
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes) {
                /* FIXME update qos data here */
        }

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(0);
}

int lov_prep_destroy_set(struct obd_export *exp, struct obdo *src_oa,
                         struct lov_stripe_md *lsm,
                         struct obd_trans_info *oti,
                         struct lov_request_set **reqset)
{
        struct lov_request_set *set;
        struct lov_oinfo *loi = NULL;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, cookie_set = 0, i;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_oa = src_oa;
        set->set_oti = oti;
        if (oti != NULL && src_oa->o_valid & OBD_MD_FLCOOKIE)
                set->set_cookies = oti->oti_logcookies;

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                struct lov_request *req;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);

                req->rq_stripe = i;
                req->rq_idx = loi->loi_ost_idx;

                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));
                req->rq_oa->o_id = loi->loi_id;

                /* Setup the first request's cookie position */
                if (!cookie_set && set->set_cookies) {
                        oti->oti_logcookies = set->set_cookies + i;
                        cookie_set = 1;
                }
                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(rc);
out_set:
        lov_fini_destroy_set(set);
        RETURN(rc);
}

int lov_fini_setattr_set(struct lov_request_set *set)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes) {
                rc = common_attr_done(set);
                /* FIXME update qos data here */
        }

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);
        RETURN(rc);
}

int lov_prep_setattr_set(struct obd_export *exp, struct obdo *src_oa,
                         struct lov_stripe_md *lsm, struct obd_trans_info *oti,
                         struct lov_request_set **reqset)
{
        struct lov_request_set *set;
        struct lov_oinfo *loi = NULL;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, i;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_oa = src_oa;

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                struct lov_request *req;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                req->rq_stripe = i;
                req->rq_idx = loi->loi_ost_idx;

                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));
                req->rq_oa->o_id = loi->loi_id;
                req->rq_oa->o_stripe_idx = i;

                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        if (lov_stripe_offset(lsm, src_oa->o_size, i,
                                              &req->rq_oa->o_size) < 0 &&
                            req->rq_oa->o_size)
                                req->rq_oa->o_size--;
                        CDEBUG(D_INODE, "stripe %d has size "LPU64"/"LPU64"\n",
                               i, req->rq_oa->o_size, src_oa->o_size);
                }
                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(rc);
out_set:
        lov_fini_setattr_set(set);
        RETURN(rc);
}

int lov_update_setattr_set(struct lov_request_set *set,
                           struct lov_request *req, int rc)
{
        struct lov_obd *lov = &set->set_exp->exp_obd->u.lov;
        struct lov_stripe_md *lsm = set->set_md;
        ENTRY;

        lov_update_set(set, req, rc);

        /* grace error on inactive ost */
        if (rc && !lov->tgts[req->rq_idx].active)
                rc = 0;

        /* FIXME: LOV STACKING update loi data should be done by OSC *
         * when this is gone we can go back to using lov_update_common_set() */
        if (rc == 0) {
                if (req->rq_oa->o_valid & OBD_MD_FLMTIME)
                        lsm->lsm_oinfo[req->rq_stripe].loi_lvb.lvb_ctime =
                                req->rq_oa->o_ctime;
                if (req->rq_oa->o_valid & OBD_MD_FLMTIME)
                        lsm->lsm_oinfo[req->rq_stripe].loi_lvb.lvb_mtime =
                                req->rq_oa->o_mtime;
                if (req->rq_oa->o_valid & OBD_MD_FLATIME)
                        lsm->lsm_oinfo[req->rq_stripe].loi_lvb.lvb_atime =
                                req->rq_oa->o_atime;
        }

        RETURN(rc);
}

int lov_update_punch_set(struct lov_request_set *set, struct lov_request *req,
                         int rc)
{
        struct lov_obd *lov = &set->set_exp->exp_obd->u.lov;
        ENTRY;

        lov_update_set(set, req, rc);
        if (rc && !lov->tgts[req->rq_idx].active)
                rc = 0;
        /* FIXME in raid1 regime, should return 0 */
        RETURN(rc);
}

int lov_fini_punch_set(struct lov_request_set *set)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes) {
                if (!set->set_success)
                        rc = -EIO;
                /* FIXME update qos data here */
        }

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_prep_punch_set(struct obd_export *exp, struct obdo *src_oa,
                       struct lov_stripe_md *lsm, obd_off start,
                       obd_off end, struct obd_trans_info *oti,
                       struct lov_request_set **reqset)
{
        struct lov_request_set *set;
        struct lov_oinfo *loi = NULL;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, i;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_oa = src_oa;

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                struct lov_request *req;
                obd_off rs, re;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                if (!lov_stripe_intersects(lsm, i, start, end, &rs, &re))
                        continue;

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                req->rq_stripe = i;
                req->rq_idx = loi->loi_ost_idx;

                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));
                req->rq_oa->o_id = loi->loi_id;
                req->rq_oa->o_stripe_idx = i;

                req->rq_extent.start = rs;
                req->rq_extent.end = re;
                req->rq_extent.gid = -1;

                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(rc);
out_set:
        lov_fini_punch_set(set);
        RETURN(rc);
}

int lov_fini_sync_set(struct lov_request_set *set)
{
        int rc = 0;
        ENTRY;

        if (set == NULL)
                RETURN(0);
        LASSERT(set->set_exp);
        if (set->set_completes) {
                if (!set->set_success)
                        rc = -EIO;
                /* FIXME update qos data here */
        }

        if (atomic_dec_and_test(&set->set_refcount))
                lov_finish_set(set);

        RETURN(rc);
}

int lov_prep_sync_set(struct obd_export *exp, struct obdo *src_oa,
                      struct lov_stripe_md *lsm, obd_off start,
                      obd_off end, struct lov_request_set **reqset)
{
        struct lov_request_set *set;
        struct lov_oinfo *loi = NULL;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, i;
        ENTRY;

        OBD_ALLOC(set, sizeof(*set));
        if (set == NULL)
                RETURN(-ENOMEM);
        lov_init_set(set);

        set->set_exp = exp;
        set->set_md = lsm;
        set->set_oa = src_oa;

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                struct lov_request *req;
                obd_off rs, re;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                if (!lov_stripe_intersects(lsm, i, start, end, &rs, &re))
                        continue;

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                req->rq_stripe = i;
                req->rq_idx = loi->loi_ost_idx;

                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out_set, rc = -ENOMEM);
                memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));
                req->rq_oa->o_id = loi->loi_id;
                req->rq_oa->o_stripe_idx = i;

                req->rq_extent.start = rs;
                req->rq_extent.end = re;
                req->rq_extent.gid = -1;

                lov_set_add_req(req, set);
        }
        if (!set->set_count)
                GOTO(out_set, rc = -EIO);
        *reqset = set;
        RETURN(rc);
out_set:
        lov_fini_sync_set(set);
        RETURN(rc);
}
