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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
#define DEBUG_SUBSYSTEM S_LOV

#ifdef __KERNEL__
#include <libcfs/libcfs.h>
#else
#include <liblustre.h>
#endif

#include <obd_class.h>
#include <obd_lov.h>
#include "lov_internal.h"

/* #define QOS_DEBUG 1 */
#define D_QOS D_OTHER

#define TGT_BAVAIL(i) (lov->lov_tgts[i]->ltd_exp->exp_obd->obd_osfs.os_bavail *\
                       lov->lov_tgts[i]->ltd_exp->exp_obd->obd_osfs.os_bsize)
#define TGT_FFREE(i)  (lov->lov_tgts[i]->ltd_exp->exp_obd->obd_osfs.os_ffree)


int qos_add_tgt(struct obd_device *obd, __u32 index)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_qos_oss *oss, *temposs;
        struct obd_export *exp = lov->lov_tgts[index]->ltd_exp;
        int rc = 0, found = 0;
        ENTRY;

        /* We only need this QOS struct on MDT, not clients - but we may not
         * have registered the LOV's observer yet, so there's no way to know */
        if (!exp || !exp->exp_connection) {
                CERROR("Missing connection\n");
                RETURN(-ENOTCONN);
        }

        down_write(&lov->lov_qos.lq_rw_sem);
        mutex_down(&lov->lov_lock);
        list_for_each_entry(oss, &lov->lov_qos.lq_oss_list, lqo_oss_list) {
                if (obd_uuid_equals(&oss->lqo_uuid,
                                    &exp->exp_connection->c_remote_uuid)) {
                        found++;
                        break;
                }
        }

        if (!found) {
                OBD_ALLOC_PTR(oss);
                if (!oss)
                        GOTO(out, rc = -ENOMEM);
                memcpy(&oss->lqo_uuid,
                       &exp->exp_connection->c_remote_uuid,
                       sizeof(oss->lqo_uuid));
        } else {
                /* Assume we have to move this one */
                list_del(&oss->lqo_oss_list);
        }

        oss->lqo_ost_count++;
        lov->lov_tgts[index]->ltd_qos.ltq_oss = oss;

        /* Add sorted by # of OSTs.  Find the first entry that we're
           bigger than... */
        list_for_each_entry(temposs, &lov->lov_qos.lq_oss_list, lqo_oss_list) {
                if (oss->lqo_ost_count > temposs->lqo_ost_count)
                        break;
        }
        /* ...and add before it.  If we're the first or smallest, temposs
           points to the list head, and we add to the end. */
        list_add_tail(&oss->lqo_oss_list, &temposs->lqo_oss_list);

        lov->lov_qos.lq_dirty = 1;
        lov->lov_qos.lq_dirty_rr = 1;

        CDEBUG(D_QOS, "add tgt %s to OSS %s (%d OSTs)\n",
               obd_uuid2str(&lov->lov_tgts[index]->ltd_uuid),
               obd_uuid2str(&oss->lqo_uuid),
               oss->lqo_ost_count);

out:
        mutex_up(&lov->lov_lock);
        up_write(&lov->lov_qos.lq_rw_sem);
        RETURN(rc);
}

int qos_del_tgt(struct obd_device *obd, __u32 index)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_qos_oss *oss;
        int rc = 0;
        ENTRY;

        if (!lov->lov_tgts[index])
                RETURN(0);

        down_write(&lov->lov_qos.lq_rw_sem);

        oss = lov->lov_tgts[index]->ltd_qos.ltq_oss;
        if (!oss)
                GOTO(out, rc = -ENOENT);

        oss->lqo_ost_count--;
        if (oss->lqo_ost_count == 0) {
                CDEBUG(D_QOS, "removing OSS %s\n",
                       obd_uuid2str(&oss->lqo_uuid));
                list_del(&oss->lqo_oss_list);
                OBD_FREE_PTR(oss);
        }

        lov->lov_qos.lq_dirty = 1;
        lov->lov_qos.lq_dirty_rr = 1;
out:
        up_write(&lov->lov_qos.lq_rw_sem);
        RETURN(rc);
}

/* Recalculate per-object penalties for OSSs and OSTs,
   depends on size of each ost in an oss */
static int qos_calc_ppo(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_qos_oss *oss;
        __u64 ba_max, ba_min, temp;
        __u32 num_active;
        int rc, i, prio_wide;
        ENTRY;

        if (!lov->lov_qos.lq_dirty)
                GOTO(out, rc = 0);

        num_active = lov->desc.ld_active_tgt_count - 1;
        if (num_active < 1)
                GOTO(out, rc = -EAGAIN);

        /* find bavail on each OSS */
        list_for_each_entry(oss, &lov->lov_qos.lq_oss_list, lqo_oss_list) {
                oss->lqo_bavail = 0;
        }
        lov->lov_qos.lq_active_oss_count = 0;

        /* How badly user wants to select osts "widely" (not recently chosen
           and not on recent oss's).  As opposed to "freely" (free space
           avail.) 0-256. */
        prio_wide = 256 - lov->lov_qos.lq_prio_free;

        ba_min = (__u64)(-1);
        ba_max = 0;
        /* Calculate OST penalty per object */
        /* (lov ref taken in alloc_qos) */
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_active)
                        continue;
                temp = TGT_BAVAIL(i);
                if (!temp)
                        continue;
                ba_min = min(temp, ba_min);
                ba_max = max(temp, ba_max);

                /* Count the number of usable OSS's */
                if (lov->lov_tgts[i]->ltd_qos.ltq_oss->lqo_bavail == 0)
                        lov->lov_qos.lq_active_oss_count++;
                lov->lov_tgts[i]->ltd_qos.ltq_oss->lqo_bavail += temp;

                /* per-OST penalty is prio * TGT_bavail / (num_ost - 1) / 2 */
                temp >>= 1;
                do_div(temp, num_active);
                lov->lov_tgts[i]->ltd_qos.ltq_penalty_per_obj =
                        (temp * prio_wide) >> 8;

                if (lov->lov_qos.lq_reset == 0)
                        lov->lov_tgts[i]->ltd_qos.ltq_penalty = 0;
        }

        num_active = lov->lov_qos.lq_active_oss_count - 1;
        if (num_active < 1) {
                /* If there's only 1 OSS, we can't penalize it, so instead
                   we have to double the OST penalty */
                num_active = 1;
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        if (lov->lov_tgts[i] == NULL)
                                continue;
                        lov->lov_tgts[i]->ltd_qos.ltq_penalty_per_obj <<= 1;
                }
        }

        /* Per-OSS penalty is prio * oss_avail / oss_osts / (num_oss - 1) / 2 */
        list_for_each_entry(oss, &lov->lov_qos.lq_oss_list, lqo_oss_list) {
                temp = oss->lqo_bavail >> 1;
                do_div(temp, oss->lqo_ost_count * num_active);
                oss->lqo_penalty_per_obj = (temp * prio_wide) >> 8;
                if (lov->lov_qos.lq_reset == 0)
                        oss->lqo_penalty = 0;
        }

        lov->lov_qos.lq_dirty = 0;
        lov->lov_qos.lq_reset = 0;

        /* If each ost has almost same free space,
         * do rr allocation for better creation performance */
        lov->lov_qos.lq_same_space = 0;
        temp = ba_max - ba_min;
        ba_min = (ba_min * 51) >> 8;     /* 51/256 = .20 */
        if (temp < ba_min) {
                /* Difference is less than 20% */
                lov->lov_qos.lq_same_space = 1;
                /* Reset weights for the next time we enter qos mode */
                lov->lov_qos.lq_reset = 0;
        }
        rc = 0;

out:
        if (!rc && lov->lov_qos.lq_same_space)
                RETURN(-EAGAIN);
        RETURN(rc);
}

static int qos_calc_weight(struct lov_obd *lov, int i)
{
        __u64 temp, temp2;

        /* Final ost weight = TGT_BAVAIL - ost_penalty - oss_penalty */
        temp = TGT_BAVAIL(i);
        temp2 = lov->lov_tgts[i]->ltd_qos.ltq_penalty +
                lov->lov_tgts[i]->ltd_qos.ltq_oss->lqo_penalty;
        if (temp < temp2)
                lov->lov_tgts[i]->ltd_qos.ltq_weight = 0;
        else
                lov->lov_tgts[i]->ltd_qos.ltq_weight = temp - temp2;
        return 0;
}

/* We just used this index for a stripe; adjust everyone's weights */
static int qos_used(struct lov_obd *lov, __u32 index, __u64 *total_wt)
{
        struct lov_qos_oss *oss;
        int i;
        ENTRY;

        /* Don't allocate from this stripe anymore, until the next alloc_qos */
        lov->lov_tgts[index]->ltd_qos.ltq_usable = 0;

        oss = lov->lov_tgts[index]->ltd_qos.ltq_oss;

        /* Decay old penalty by half (we're adding max penalty, and don't
           want it to run away.) */
        lov->lov_tgts[index]->ltd_qos.ltq_penalty >>= 1;
        oss->lqo_penalty >>= 1;

        /* Set max penalties for this OST and OSS */
        lov->lov_tgts[index]->ltd_qos.ltq_penalty +=
                lov->lov_tgts[index]->ltd_qos.ltq_penalty_per_obj *
                lov->desc.ld_active_tgt_count;
        oss->lqo_penalty += oss->lqo_penalty_per_obj *
                lov->lov_qos.lq_active_oss_count;

        /* Decrease all OSS penalties */
        list_for_each_entry(oss, &lov->lov_qos.lq_oss_list, lqo_oss_list) {
                if (oss->lqo_penalty < oss->lqo_penalty_per_obj)
                        oss->lqo_penalty = 0;
                else
                        oss->lqo_penalty -= oss->lqo_penalty_per_obj;
        }

        *total_wt = 0;
        /* Decrease all OST penalties */
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_active)
                        continue;
                if (lov->lov_tgts[i]->ltd_qos.ltq_penalty <
                    lov->lov_tgts[i]->ltd_qos.ltq_penalty_per_obj)
                        lov->lov_tgts[i]->ltd_qos.ltq_penalty = 0;
                else
                        lov->lov_tgts[i]->ltd_qos.ltq_penalty -=
                        lov->lov_tgts[i]->ltd_qos.ltq_penalty_per_obj;

                qos_calc_weight(lov, i);

                /* Recalc the total weight of usable osts */
                if (lov->lov_tgts[i]->ltd_qos.ltq_usable)
                        *total_wt += lov->lov_tgts[i]->ltd_qos.ltq_weight;

#ifdef QOS_DEBUG
                CDEBUG(D_QOS, "recalc tgt %d avail="LPU64
                       " ostppo="LPU64" ostp="LPU64" ossppo="LPU64
                       " ossp="LPU64" wt="LPU64"\n",
                       i, TGT_BAVAIL(i) >> 10,
                       lov->lov_tgts[i]->ltd_qos.ltq_penalty_per_obj >> 10,
                       lov->lov_tgts[i]->ltd_qos.ltq_penalty >> 10,
                       lov->lov_tgts[i]->ltd_qos.ltq_oss->lqo_penalty_per_obj>>10,
                       lov->lov_tgts[i]->ltd_qos.ltq_oss->lqo_penalty >> 10,
                       lov->lov_tgts[i]->ltd_qos.ltq_weight >> 10);
#endif
        }

        RETURN(0);
}

#define LOV_QOS_EMPTY ((__u32)-1)
/* compute optimal round-robin order, based on OSTs per OSS */
static int qos_calc_rr(struct lov_obd *lov)
{
        struct lov_qos_oss *oss;
        unsigned ost_count, placed, real_count;
        int i;
        ENTRY;

        if (!lov->lov_qos.lq_dirty_rr) {
                LASSERT(lov->lov_qos.lq_rr_size);
                RETURN(0);
        }

        /* Do actual allocation. */
        down_write(&lov->lov_qos.lq_rw_sem);

        /*
         * Check again. While we were sleeping on @lq_rw_sem something could
         * change.
         */
        if (!lov->lov_qos.lq_dirty_rr) {
                LASSERT(lov->lov_qos.lq_rr_size);
                up_write(&lov->lov_qos.lq_rw_sem);
                RETURN(0);
        }

        ost_count = lov->desc.ld_tgt_count;

        if (lov->lov_qos.lq_rr_size)
                OBD_FREE(lov->lov_qos.lq_rr_array, lov->lov_qos.lq_rr_size);
        lov->lov_qos.lq_rr_size = ost_count *
                sizeof(lov->lov_qos.lq_rr_array[0]);
        OBD_ALLOC(lov->lov_qos.lq_rr_array, lov->lov_qos.lq_rr_size);
        if (!lov->lov_qos.lq_rr_array) {
                lov->lov_qos.lq_rr_size = 0;
                up_write(&lov->lov_qos.lq_rw_sem);
                RETURN(-ENOMEM);
        }

        real_count = 0;
        for (i = 0; i < ost_count; i++) {
                lov->lov_qos.lq_rr_array[i] = LOV_QOS_EMPTY;
                if (lov->lov_tgts[i])
                        real_count++;
        }

        /* Place all the OSTs from 1 OSS at the same time. */
        placed = 0;
        list_for_each_entry(oss, &lov->lov_qos.lq_oss_list, lqo_oss_list) {
                int j = 0;
                for (i = 0; i < ost_count; i++) {
                        if (lov->lov_tgts[i] &&
                            lov->lov_tgts[i]->ltd_qos.ltq_oss == oss) {
                              /* Evenly space these OSTs across arrayspace */
                              int next = j * ost_count / oss->lqo_ost_count;
                              LASSERT(next < ost_count);
                              while (lov->lov_qos.lq_rr_array[next] !=
                                     LOV_QOS_EMPTY)
                                      next = (next + 1) % ost_count;
                              lov->lov_qos.lq_rr_array[next] = i;
                              j++;
                              placed++;
                        }
                }
                LASSERT(j == oss->lqo_ost_count);
        }

        lov->lov_qos.lq_dirty_rr = 0;
        up_write(&lov->lov_qos.lq_rw_sem);

        if (placed != real_count) {
                /* This should never happen */
                LCONSOLE_ERROR_MSG(0x14e, "Failed to place all OSTs in the "
                                   "round-robin list (%d of %d).\n",
                                   placed, real_count);
                for (i = 0; i < ost_count; i++) {
                        LCONSOLE(D_WARNING, "rr #%d ost idx=%d\n", i,
                                 lov->lov_qos.lq_rr_array[i]);
                }
                lov->lov_qos.lq_dirty_rr = 1;
                RETURN(-EAGAIN);
        }

#ifdef QOS_DEBUG
        for (i = 0; i < ost_count; i++) {
                LCONSOLE(D_QOS, "rr #%d ost idx=%d\n", i,
                         lov->lov_qos.lq_rr_array[i]);
        }
#endif

        RETURN(0);
}


void qos_shrink_lsm(struct lov_request_set *set)
{
        struct lov_stripe_md *lsm = set->set_oi->oi_md, *lsm_new;
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

        CWARN("using fewer stripes for object "LPU64": old %u new %u\n",
              lsm->lsm_object_id, lsm->lsm_stripe_count, set->set_count);
        LASSERT(lsm->lsm_stripe_count >= set->set_count);

        newsize = lov_stripe_md_size(set->set_count);
        OBD_ALLOC(lsm_new, newsize);
        if (lsm_new != NULL) {
                int i;
                memcpy(lsm_new, lsm, sizeof(*lsm));
                for (i = 0; i < lsm->lsm_stripe_count; i++) {
                        if (i < set->set_count) {
                                lsm_new->lsm_oinfo[i] = lsm->lsm_oinfo[i];
                                continue;
                        }
                        OBD_SLAB_FREE(lsm->lsm_oinfo[i], lov_oinfo_slab,
                                      sizeof(struct lov_oinfo));
                }
                lsm_new->lsm_stripe_count = set->set_count;
                OBD_FREE(lsm, sizeof(struct lov_stripe_md) +
                         lsm->lsm_stripe_count * sizeof(struct lov_oinfo *));
                set->set_oi->oi_md = lsm_new;
        } else {
                CWARN("'leaking' few bytes\n");
        }
}

int qos_remedy_create(struct lov_request_set *set, struct lov_request *req)
{
        struct lov_stripe_md *lsm = set->set_oi->oi_md;
        struct lov_obd *lov = &set->set_exp->exp_obd->u.lov;
        unsigned ost_idx, ost_count = lov->desc.ld_tgt_count;
        int stripe, i, rc = -EIO;
        ENTRY;

        ost_idx = (req->rq_idx + lsm->lsm_stripe_count) % ost_count;
        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                if (!lov->lov_tgts[ost_idx] ||
                    !lov->lov_tgts[ost_idx]->ltd_active)
                        continue;
                /* check if objects has been created on this ost */
                for (stripe = 0; stripe < lsm->lsm_stripe_count; stripe++) {
                        if (stripe == req->rq_stripe)
                                continue;
                        if (ost_idx == lsm->lsm_oinfo[stripe]->loi_ost_idx)
                                break;
                }

                if (stripe >= lsm->lsm_stripe_count) {
                        req->rq_idx = ost_idx;
                        rc = obd_create(lov->lov_tgts[ost_idx]->ltd_exp,
                                        req->rq_oi.oi_oa, &req->rq_oi.oi_md,
                                        set->set_oti);
                        if (!rc)
                                break;
                }
        }
        RETURN(rc);
}

static int min_stripe_count(int stripe_cnt, int flags)
{
        return (flags & LOV_USES_DEFAULT_STRIPE ?
                stripe_cnt - (stripe_cnt / 4) : stripe_cnt);
}

#define LOV_CREATE_RESEED_MULT 4
#define LOV_CREATE_RESEED_MIN  1000
/* Allocate objects on osts with round-robin algorithm */
static int alloc_rr(struct lov_obd *lov, int *idx_arr, int *stripe_cnt,
                    int flags)
{
        unsigned array_idx, ost_count = lov->desc.ld_tgt_count;
        unsigned ost_active_count = lov->desc.ld_active_tgt_count;
        int i, *idx_pos;
        __u32 ost_idx;
        int ost_start_idx_temp;
        int speed = 0;
        int stripe_cnt_min = min_stripe_count(*stripe_cnt, flags);
        ENTRY;

        i = qos_calc_rr(lov);
        if (i)
                RETURN(i);

        if (--lov->lov_start_count <= 0) {
                lov->lov_start_idx = ll_rand() % ost_count;
                lov->lov_start_count =
                        (LOV_CREATE_RESEED_MIN / max(ost_active_count, 1U) +
                         LOV_CREATE_RESEED_MULT) * max(ost_active_count, 1U);
        } else if (stripe_cnt_min >= ost_active_count ||
                   lov->lov_start_idx > ost_count) {
                /* If we have allocated from all of the OSTs, slowly
                 * precess the next start if the OST/stripe count isn't
                 * already doing this for us. */
                lov->lov_start_idx %= ost_count;
                if (*stripe_cnt > 1 && (ost_active_count % (*stripe_cnt)) != 1)
                        ++lov->lov_offset_idx;
        }
        down_read(&lov->lov_qos.lq_rw_sem);
        ost_start_idx_temp = lov->lov_start_idx;

repeat_find:
        array_idx = (lov->lov_start_idx + lov->lov_offset_idx) % ost_count;
        idx_pos = idx_arr;
#ifdef QOS_DEBUG
        CDEBUG(D_QOS, "want %d startidx %d startcnt %d offset %d active %d "
               "count %d arrayidx %d\n",
               stripe_cnt, lov->lov_start_idx, lov->lov_start_count,
               lov->lov_offset_idx, ost_active_count, ost_count, array_idx);
#endif

        for (i = 0; i < ost_count; i++, array_idx=(array_idx + 1) % ost_count) {
                ++lov->lov_start_idx;
                ost_idx = lov->lov_qos.lq_rr_array[array_idx];
#ifdef QOS_DEBUG
                CDEBUG(D_QOS, "#%d strt %d act %d strp %d ary %d idx %d\n",
                       i, lov->lov_start_idx,
                       ((ost_idx != LOV_QOS_EMPTY) && lov->lov_tgts[ost_idx]) ?
                       lov->lov_tgts[ost_idx]->ltd_active : 0,
                       idx_pos - idx_arr, array_idx, ost_idx);
#endif
                if ((ost_idx == LOV_QOS_EMPTY) || !lov->lov_tgts[ost_idx] ||
                    !lov->lov_tgts[ost_idx]->ltd_active)
                        continue;

                /* Fail Check before osc_precreate() is called
                   so we can only 'fail' single OSC. */
                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_PRECREATE) && ost_idx == 0)
                        continue;

                /* Drop slow OSCs if we can */
                if (obd_precreate(lov->lov_tgts[ost_idx]->ltd_exp) > speed)
                        continue;

                *idx_pos = ost_idx;
                idx_pos++;
                /* We have enough stripes */
                if (idx_pos - idx_arr == *stripe_cnt)
                        break;
        }
        if ((speed < 2) && (idx_pos - idx_arr < stripe_cnt_min)) {
                /* Try again, allowing slower OSCs */
                speed++;
                lov->lov_start_idx = ost_start_idx_temp;
                goto repeat_find;
        }

        up_read(&lov->lov_qos.lq_rw_sem);

        *stripe_cnt = idx_pos - idx_arr;
        RETURN(0);
}

/* alloc objects on osts with specific stripe offset */
static int alloc_specific(struct lov_obd *lov, struct lov_stripe_md *lsm,
                          int *idx_arr)
{
        unsigned ost_idx, ost_count = lov->desc.ld_tgt_count;
        int i, *idx_pos;
        int speed = 0;
        ENTRY;

repeat_find:
        ost_idx = lsm->lsm_oinfo[0]->loi_ost_idx;
        idx_pos = idx_arr;
        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                if (!lov->lov_tgts[ost_idx] ||
                    !lov->lov_tgts[ost_idx]->ltd_active) {
                        continue;
                }

                /* Fail Check before osc_precreate() is called
                   so we can only 'fail' single OSC. */
                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_PRECREATE) && ost_idx == 0)
                        continue;

                /* Drop slow OSCs if we can, but not for requested start idx */
                if ((obd_precreate(lov->lov_tgts[ost_idx]->ltd_exp) > speed) &&
                    (i != 0 || speed < 2))
                        continue;

                *idx_pos = ost_idx;
                idx_pos++;
                /* We have enough stripes */
                if (idx_pos - idx_arr == lsm->lsm_stripe_count)
                        RETURN(0);
        }
        if (speed < 2) {
                /* Try again, allowing slower OSCs */
                speed++;
                goto repeat_find;
        }

        /* If we were passed specific striping params, then a failure to
         * meet those requirements is an error, since we can't reallocate
         * that memory (it might be part of a larger array or something).
         *
         * We can only get here if lsm_stripe_count was originally > 1.
         */
        CERROR("can't lstripe objid "LPX64": have %d want %u\n",
               lsm->lsm_object_id, (int)(idx_pos - idx_arr),
               lsm->lsm_stripe_count);
        RETURN(-EFBIG);
}

/* Alloc objects on osts with optimization based on:
   - free space
   - network resources (shared OSS's)
*/
static int alloc_qos(struct obd_export *exp, int *idx_arr, int *stripe_cnt,
                     int flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        static time_t last_warn = 0;
        time_t now = cfs_time_current_sec();
        __u64 total_bavail, total_weight = 0;
        __u32 ost_count;
        int nfound, good_osts, i, warn = 0, rc = 0;
        int stripe_cnt_min = min_stripe_count(*stripe_cnt, flags);
        ENTRY;

        if (stripe_cnt_min < 1)
                GOTO(out_nolock, rc = -EINVAL);

        lov_getref(exp->exp_obd);

        /* Detect -EAGAIN early, before expensive lock is taken. */
        if (!lov->lov_qos.lq_dirty && lov->lov_qos.lq_same_space)
                GOTO(out_nolock, rc = -EAGAIN);

        /* Do actual allocation, use write lock here. */
        down_write(&lov->lov_qos.lq_rw_sem);

        /*
         * Check again, while we were sleeping on @lq_rw_sem things could
         * change.
         */
        if (!lov->lov_qos.lq_dirty && lov->lov_qos.lq_same_space)
                GOTO(out, rc = -EAGAIN);

        ost_count = lov->desc.ld_tgt_count;

        if (lov->desc.ld_active_tgt_count < 2)
                GOTO(out, rc = -EAGAIN);

        rc = qos_calc_ppo(exp->exp_obd);
        if (rc)
                GOTO(out, rc);

        total_bavail = 0;
        good_osts = 0;
        /* Warn users about zero available space/inode every 30 min */
        if (cfs_time_sub(now, last_warn) > 60 * 30)
                warn = 1;
        /* Find all the OSTs that are valid stripe candidates */
        for (i = 0; i < ost_count; i++) {
                __u64 bavail;

                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_active)
                        continue;
                bavail = TGT_BAVAIL(i);
                if (!bavail) {
                        if (warn) {
                                CDEBUG(D_QOS, "no free space on %s\n",
                                     obd_uuid2str(&lov->lov_tgts[i]->ltd_uuid));
                                last_warn = now;
                        }
                        continue;
                }
                if (!TGT_FFREE(i)) {
                        if (warn) {
                                CDEBUG(D_QOS, "no free inodes on %s\n",
                                     obd_uuid2str(&lov->lov_tgts[i]->ltd_uuid));
                                last_warn = now;
                        }
                        continue;
                }

                /* Fail Check before osc_precreate() is called
                   so we can only 'fail' single OSC. */
                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_PRECREATE) && i == 0)
                        continue;

                if (obd_precreate(lov->lov_tgts[i]->ltd_exp) > 2)
                        continue;

                lov->lov_tgts[i]->ltd_qos.ltq_usable = 1;
                qos_calc_weight(lov, i);
                total_bavail += bavail;
                total_weight += lov->lov_tgts[i]->ltd_qos.ltq_weight;

                good_osts++;
        }

        if (good_osts < stripe_cnt_min)
                GOTO(out, rc = -EAGAIN);

        if (!total_bavail)
                GOTO(out, rc = -ENOSPC);

        /* We have enough osts */
        if (good_osts < *stripe_cnt)
                *stripe_cnt = good_osts;

        if (!*stripe_cnt)
                GOTO(out, rc = -EAGAIN);

        /* Find enough OSTs with weighted random allocation. */
        nfound = 0;
        while (nfound < *stripe_cnt) {
                __u64 rand, cur_weight;

                cur_weight = 0;
                rc = -ENODEV;

                if (total_weight) {
#if BITS_PER_LONG == 32
                        rand = ll_rand() % (unsigned)total_weight;
                        /* If total_weight > 32-bit, first generate the high
                         * 32 bits of the random number, then add in the low
                         * 32 bits (truncated to the upper limit, if needed) */
                        if (total_weight > 0xffffffffULL)
                                rand = (__u64)(ll_rand() %
                                          (unsigned)(total_weight >> 32)) << 32;
                        else
                                rand = 0;

                        if (rand == (total_weight & 0xffffffff00000000ULL))
                                rand |= ll_rand() % (unsigned)total_weight;
                        else
                                rand |= ll_rand();

#else
                        rand = ((__u64)ll_rand() << 32 | ll_rand()) %
                                total_weight;
#endif
                } else {
                        rand = 0;
                }

                /* On average, this will hit larger-weighted osts more often.
                   0-weight osts will always get used last (only when rand=0).*/
                for (i = 0; i < ost_count; i++) {
                        if (!lov->lov_tgts[i] ||
                            !lov->lov_tgts[i]->ltd_qos.ltq_usable)
                                continue;

                        cur_weight += lov->lov_tgts[i]->ltd_qos.ltq_weight;
                        if (cur_weight >= rand) {
#ifdef QOS_DEBUG
                                CDEBUG(D_QOS, "assigned stripe=%d to idx=%d\n",
                                       nfound, i);
#endif
                                idx_arr[nfound++] = i;
                                qos_used(lov, i, &total_weight);
                                rc = 0;
                                break;
                        }
                }
                /* should never satisfy below condition */
                if (rc) {
                        CERROR("Didn't find any OSTs?\n");
                        break;
                }
        }
        LASSERT(nfound == *stripe_cnt);

out:
        up_write(&lov->lov_qos.lq_rw_sem);

out_nolock:
        if (rc == -EAGAIN)
                rc = alloc_rr(lov, idx_arr, stripe_cnt, flags);

        lov_putref(exp->exp_obd);
        RETURN(rc);
}

/* return new alloced stripe count on success */
static int alloc_idx_array(struct obd_export *exp, struct lov_stripe_md *lsm,
                           int newea, int **idx_arr, int *arr_cnt, int flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int stripe_cnt = lsm->lsm_stripe_count;
        int i, rc = 0;
        int *tmp_arr = NULL;
        ENTRY;

        *arr_cnt = stripe_cnt;
        OBD_ALLOC(tmp_arr, *arr_cnt * sizeof(int));
        if (tmp_arr == NULL)
                RETURN(-ENOMEM);
        for (i = 0; i < *arr_cnt; i++)
                tmp_arr[i] = -1;

        if (newea ||
            lsm->lsm_oinfo[0]->loi_ost_idx >= lov->desc.ld_tgt_count)
                rc = alloc_qos(exp, tmp_arr, &stripe_cnt, flags);
        else
                rc = alloc_specific(lov, lsm, tmp_arr);

        if (rc)
                GOTO(out_arr, rc);

        *idx_arr = tmp_arr;
        RETURN(stripe_cnt);
out_arr:
        OBD_FREE(tmp_arr, *arr_cnt * sizeof(int));
        *arr_cnt = 0;
        RETURN(rc);
}

static void free_idx_array(int *idx_arr, int arr_cnt)
{
        if (arr_cnt)
                OBD_FREE(idx_arr, arr_cnt * sizeof(int));
}

int qos_prep_create(struct obd_export *exp, struct lov_request_set *set)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_stripe_md *lsm;
        struct obdo *src_oa = set->set_oi->oi_oa;
        struct obd_trans_info *oti = set->set_oti;
        int i, stripes, rc = 0, newea = 0;
        int flag = LOV_USES_ASSIGNED_STRIPE;
        int *idx_arr = NULL, idx_cnt = 0;
        ENTRY;

        LASSERT(src_oa->o_valid & OBD_MD_FLID);
        LASSERT(src_oa->o_valid & OBD_MD_FLGROUP);
 
        if (set->set_oi->oi_md == NULL) {
                int stripes_def = lov_get_stripecnt(lov, 0);

                /* If the MDS file was truncated up to some size, stripe over
                 * enough OSTs to allow the file to be created at that size.
                 * This may mean we use more than the default # of stripes. */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        obd_size min_bavail = LUSTRE_STRIPE_MAXBYTES;

                        /* Find a small number of stripes we can use
                           (up to # of active osts). */
                        stripes = 1;
                        lov_getref(exp->exp_obd);
                        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                                if (!lov->lov_tgts[i] ||
                                    !lov->lov_tgts[i]->ltd_active)
                                        continue;
                                min_bavail = min(min_bavail, TGT_BAVAIL(i));
                                if (min_bavail * stripes > src_oa->o_size)
                                        break;
                                stripes++;
                        }
                        lov_putref(exp->exp_obd);

                        if (stripes < stripes_def)
                                stripes = stripes_def;
                } else {
                         flag = LOV_USES_DEFAULT_STRIPE;
                         stripes = stripes_def;
                }

                rc = lov_alloc_memmd(&set->set_oi->oi_md, stripes,
                                     lov->desc.ld_pattern ?
                                     lov->desc.ld_pattern : LOV_PATTERN_RAID0,
                                     LOV_MAGIC);
                if (rc < 0)
                        GOTO(out_err, rc);
                newea = 1;
                rc = 0;
        }

        lsm = set->set_oi->oi_md;
        lsm->lsm_object_id = src_oa->o_id;
        lsm->lsm_object_gr = src_oa->o_gr;

        if (!lsm->lsm_stripe_size)
                lsm->lsm_stripe_size = lov->desc.ld_default_stripe_size;
        if (!lsm->lsm_pattern) {
                LASSERT(lov->desc.ld_pattern);
                lsm->lsm_pattern = lov->desc.ld_pattern;
        }

        stripes = alloc_idx_array(exp, lsm, newea, &idx_arr, &idx_cnt, flag);
        if (stripes <= 0)
                GOTO(out_err, rc = stripes ? stripes : -EIO);
        LASSERTF(stripes <= lsm->lsm_stripe_count,"requested %d allocated %d\n",
                 lsm->lsm_stripe_count, stripes);

        for (i = 0; i < stripes; i++) {
                struct lov_request *req;
                int ost_idx = idx_arr[i];
                LASSERT(ost_idx >= 0);

                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_err, rc = -ENOMEM);
                lov_set_add_req(req, set);

                req->rq_buflen = sizeof(*req->rq_oi.oi_md);
                OBD_ALLOC(req->rq_oi.oi_md, req->rq_buflen);
                if (req->rq_oi.oi_md == NULL)
                        GOTO(out_err, rc = -ENOMEM);

                OBDO_ALLOC(req->rq_oi.oi_oa);
                if (req->rq_oi.oi_oa == NULL)
                        GOTO(out_err, rc = -ENOMEM);

                req->rq_idx = ost_idx;
                req->rq_stripe = i;
                /* create data objects with "parent" OA */
                memcpy(req->rq_oi.oi_oa, src_oa, sizeof(*req->rq_oi.oi_oa));

                /* XXX When we start creating objects on demand, we need to
                 *     make sure that we always create the object on the
                 *     stripe which holds the existing file size.
                 */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        req->rq_oi.oi_oa->o_size =
                                lov_size_to_stripe(lsm, src_oa->o_size, i);

                        CDEBUG(D_INODE, "stripe %d has size "LPU64"/"LPU64"\n",
                               i, req->rq_oi.oi_oa->o_size, src_oa->o_size);
                }
        }
        LASSERT(set->set_count == stripes);

        if (stripes < lsm->lsm_stripe_count)
                qos_shrink_lsm(set);

        if (oti && (src_oa->o_valid & OBD_MD_FLCOOKIE)) {
                oti_alloc_cookies(oti, set->set_count);
                if (!oti->oti_logcookies)
                        GOTO(out_err, rc = -ENOMEM);
                set->set_cookies = oti->oti_logcookies;
        }
out_err:
        if (newea && rc)
                obd_free_memmd(exp, &set->set_oi->oi_md);
        if (idx_arr)
                free_idx_array(idx_arr, idx_cnt);
        EXIT;
        return rc;
}

void qos_update(struct lov_obd *lov)
{
        ENTRY;
        lov->lov_qos.lq_dirty = 1;
}
