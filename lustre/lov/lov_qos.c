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
/* alloc objects on osts with round-robin algorithm */
static int alloc_rr(struct lov_obd *lov, int *idx_arr, int *stripe_cnt)
{
        static int ost_start_count, ost_start_idx;
        unsigned ost_idx, ost_count = lov->desc.ld_tgt_count;
        unsigned ost_active_count = lov->desc.ld_active_tgt_count;
        int i, *idx_pos = idx_arr;
        ENTRY;
        
        if (--ost_start_count <= 0) {
                ost_start_idx = ll_rand();
                ost_start_count = 
                        (LOV_CREATE_RESEED_MIN / max(ost_active_count, 1U) +
                         LOV_CREATE_RESEED_MULT) * max(ost_active_count, 1U);
        } else if (*stripe_cnt >= lov->desc.ld_active_tgt_count) {
                /* If we allocate from all of the stripes, make the
                 * next file start on the next OST. */
                ++ost_start_idx;
        }
        ost_idx = ost_start_idx % ost_count;

        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                ++ost_start_idx;
                
                if (lov->tgts[ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost_idx);
                        continue;
                }
                
                *idx_pos = ost_idx;
                idx_pos++;
                /* got enough ost */
                if (idx_pos - idx_arr == *stripe_cnt)
                        RETURN(0);
        }
        *stripe_cnt = idx_pos - idx_arr;
        RETURN(0);
}

/* alloc objects on osts with specific stripe offset */
static int alloc_specific(struct lov_obd *lov, struct lov_stripe_md *lsm,
                          int *idx_arr)
{
        unsigned ost_idx, ost_count = lov->desc.ld_tgt_count;
        int i, *idx_pos = idx_arr;
        ENTRY;

        ost_idx = lsm->lsm_oinfo[0].loi_ost_idx;
        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                if (lov->tgts[ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost_idx);
                        continue;
                }
                *idx_pos = ost_idx;
                idx_pos++;
                /* got enough ost */
                if (idx_pos - idx_arr == lsm->lsm_stripe_count)
                        RETURN(0);
        }
        /* If we were passed specific striping params, then a failure to
         * meet those requirements is an error, since we can't reallocate
         * that memory (it might be part of a larger array or something).
         *
         * We can only get here if lsm_stripe_count was originally > 1.
         */
        CERROR("can't lstripe objid "LPX64": have %u want %u\n",
               lsm->lsm_object_id, idx_pos - idx_arr, lsm->lsm_stripe_count);
        RETURN(-EFBIG);
}

/* free space OST must have to be used for object allocation. */
#define QOS_MIN                 (lov->desc.ld_qos_threshold << 20)

#define TGT_BAVAIL(tgt)         (tgt->ltd_exp->exp_obd->obd_osfs.os_bavail * \
                                 tgt->ltd_exp->exp_obd->obd_osfs.os_bsize) 
#define TGT_FFREE(tgt)          (tgt->ltd_exp->exp_obd->obd_osfs.os_ffree)

/* alloc objects on osts with free space weighted algorithm */
static int alloc_qos(struct obd_export *exp, int *idx_arr, int *stripe_cnt)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        unsigned ost_count = lov->desc.ld_tgt_count;
        __u64 cur_bavail, rand, *availspace, total_bavail = 0;
        int *indexes, nfound, good_osts, i, warn = 0, rc = 0;
        struct lov_tgt_desc *tgt;
        int shift, require_stripes = *stripe_cnt;
        static time_t last_warn = 0;
        time_t now = cfs_time_current_sec();
        ENTRY;
        
        availspace = NULL;
        indexes = NULL;
        OBD_ALLOC(availspace, sizeof(__u64) * ost_count);
        OBD_ALLOC(indexes, sizeof(int) * require_stripes);
        if (!availspace || !indexes)
                GOTO(out_free, rc = -EAGAIN);
        
        mutex_down(&lov->lov_lock);
 
        /* if free space is below some threshold, just go
         * to do round-robin allocation */
        total_bavail = (exp->exp_obd->obd_osfs.os_bavail * \
                        exp->exp_obd->obd_osfs.os_bsize);
        if (ost_count < 2 || total_bavail <= QOS_MIN) {
                mutex_up(&lov->lov_lock);
                GOTO(out_free, rc = -EAGAIN);
        }

        /* if each ost has almost same free space, go to 
         * do rr allocation for better creation performance */
        if (!list_empty(&lov->qos_bavail_list)) {
                __u64 max, min, val;
                tgt = list_entry(lov->qos_bavail_list.next, 
                                 struct lov_tgt_desc, qos_bavail_list);
                max = TGT_BAVAIL(tgt);
                tgt = list_entry(lov->qos_bavail_list.prev,
                                 struct lov_tgt_desc, qos_bavail_list);
                min = TGT_BAVAIL(tgt);

                val = (max >= min) ? (max - min) : (min - max);
                min = (min * 13) >> 8;          /* less than 5% of gap */ 

                if (val < min) {
                        mutex_up(&lov->lov_lock);
                        GOTO(out_free, rc = -EAGAIN);
                }
        } else {
                mutex_up(&lov->lov_lock);
                GOTO(out_free, rc = -EAGAIN);
        }
        
        total_bavail = 0;
        good_osts = 0;
        /* warn zero available space/inode every 30 min */
        if (cfs_time_sub(now, last_warn) > 60 * 30)
                warn = 1;
        /* Find all the OSTs big enough to be stripe candidates */
        list_for_each_entry(tgt, &lov->qos_bavail_list, qos_bavail_list) {
                if (!tgt->active)
                        continue;
                if (!TGT_BAVAIL(tgt)) {
                        if (warn) {
                                CWARN("no free space on %s\n", 
                                      tgt->uuid.uuid);
                                last_warn = now;
                        }
                        continue;
                }
                if (!TGT_FFREE(tgt)) {
                        if (warn) {
                                CWARN("no free inodes on %s\n", 
                                      tgt->uuid.uuid);
                                last_warn = now;
                        }
                        continue;
                }
                /* We can stop if we have enough good osts and our osts
                   are getting too small */ 
                if ((TGT_BAVAIL(tgt) <= QOS_MIN) && (good_osts >= *stripe_cnt))
                        break;
                availspace[good_osts] = TGT_BAVAIL(tgt);
                indexes[good_osts] = tgt->index;
                total_bavail += availspace[good_osts];
                good_osts++;
        }
        
        mutex_up(&lov->lov_lock);
        
        if (!total_bavail)
                GOTO(out_free, rc = -ENOSPC);
       
        /* if we don't have enough good OSTs, we reduce the stripe count. */
        if (good_osts < *stripe_cnt)
                *stripe_cnt = good_osts;

        if (!*stripe_cnt) 
                GOTO(out_free, rc = -EAGAIN);
        
        /* The point of all this shift and rand is to choose a 64-bit 
           random number between 0 and total_bavail. Apparently '%' doesn't
           work for 64bit numbers. */
        nfound = shift = 0;
        while ((total_bavail >> shift) > 0)
                shift++;
        shift++;
        /* Find enough OSTs with free space weighted random allocation */
        while (nfound < *stripe_cnt) {
                cur_bavail = 0;

                /* If the total storage left is < 4GB, don't use random order, 
                   store in biggest OST first. (Low storage situation.) 
                   Otherwise, choose a 64bit random number... */
                rand = (shift < 32 ? 0ULL : (__u64)ll_rand() << 32) | ll_rand();
                /* ... mask everything above shift... */
                if (shift < 64)
                        rand &= ((1ULL << shift) - 1);
                /* ... and this while should execute at most once... */
                while (rand > total_bavail)
                        rand -= total_bavail;
                /* ... leaving us a 64bit number between 0 and total_bavail. */
                
                /* Try to fit in bigger OSTs first. On average, this will
                   fill more toward the front of the OST array */
                for (i = 0; i < good_osts; i++) {
                        cur_bavail += availspace[i];
                        if (cur_bavail >= rand) {
                                total_bavail -= availspace[i];
                                availspace[i] = 0;
                                idx_arr[nfound] = indexes[i];
                                nfound++;
                                break;
                        }
                }
                /* should never satisfy below condition */
                if (cur_bavail == 0)
                        break;
        }
        LASSERT(nfound == *stripe_cnt);
        
out_free:
        if (availspace)
                OBD_FREE(availspace, sizeof(__u64) * ost_count);
        if (indexes)
                OBD_FREE(indexes, sizeof(int) * require_stripes);
        if (rc != -EAGAIN)
                /* rc == 0 or err */
                RETURN(rc);

        rc = alloc_rr(lov, idx_arr, stripe_cnt);
        RETURN(rc);
}

/* return new alloced stripe count on success */
static int alloc_idx_array(struct obd_export *exp, struct lov_stripe_md *lsm, 
                           int newea, int **idx_arr, int *arr_cnt)
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
            lsm->lsm_oinfo[0].loi_ost_idx >= lov->desc.ld_tgt_count) 
                rc = alloc_qos(exp, tmp_arr, &stripe_cnt);
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
        struct obdo *src_oa = set->set_oa;
        struct obd_trans_info *oti = set->set_oti;
        int i, stripes, rc = 0, newea = 0;
        int *idx_arr, idx_cnt = 0;
        ENTRY;

        LASSERT(src_oa->o_valid & OBD_MD_FLID);
 
        if (set->set_md == NULL) {
                int stripe_cnt = lov_get_stripecnt(lov, 0);

                /* If the MDS file was truncated up to some size, stripe over
                 * enough OSTs to allow the file to be created at that size. 
                 * This may mean we use more than the default # of stripes. */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        struct lov_tgt_desc *tgt;
                        
                        /* Find the smallest number of stripes we can use 
                           (up to # of active osts). */
                        stripes = 1;
                        mutex_down(&lov->lov_lock);
                        list_for_each_entry(tgt, &lov->qos_bavail_list, 
                                            qos_bavail_list) {
                                if (!tgt->active)
                                        continue;
                                /* All earlier tgts have at least this many 
                                   bytes available also, since our list is
                                   sorted by size  */
                                if (TGT_BAVAIL(tgt) * stripes > src_oa->o_size)
                                        break;
                                stripes++;
                        }
                        mutex_up(&lov->lov_lock);

                        if (stripes < stripe_cnt)
                                stripes = stripe_cnt;
                } else {
                        stripes = stripe_cnt;
                }

                rc = lov_alloc_memmd(&set->set_md, stripes, 
                                     lov->desc.ld_pattern ?
                                     lov->desc.ld_pattern : LOV_PATTERN_RAID0,
                                     LOV_MAGIC);
                if (rc < 0)
                        GOTO(out_err, rc);
                rc = 0;
                newea = 1;
        }
        lsm = set->set_md;
       
        lsm->lsm_object_id = src_oa->o_id;
        if (!lsm->lsm_stripe_size)
                lsm->lsm_stripe_size = lov->desc.ld_default_stripe_size;
        if (!lsm->lsm_pattern) {
                LASSERT(lov->desc.ld_pattern);
                lsm->lsm_pattern = lov->desc.ld_pattern;
        }

        stripes = alloc_idx_array(exp, lsm, newea, &idx_arr, &idx_cnt);
        LASSERT(stripes <= lsm->lsm_stripe_count);
        if (stripes <= 0)
                GOTO(out_err, rc = stripes ? stripes : -EIO);
        
        for (i = 0; i < stripes; i++) {
                struct lov_request *req;
                int ost_idx = idx_arr[i];
                LASSERT(ost_idx >= 0);
                
                OBD_ALLOC(req, sizeof(*req));
                if (req == NULL)
                        GOTO(out_err, rc = -ENOMEM);
                lov_set_add_req(req, set);

                req->rq_buflen = sizeof(*req->rq_md);
                OBD_ALLOC(req->rq_md, req->rq_buflen);
                if (req->rq_md == NULL)
                        GOTO(out_err, rc = -ENOMEM);
                
                req->rq_oa = obdo_alloc();
                if (req->rq_oa == NULL)
                        GOTO(out_err, rc = -ENOMEM);
                
                req->rq_idx = ost_idx;
                req->rq_stripe = i;
                /* create data objects with "parent" OA */
                memcpy(req->rq_oa, src_oa, sizeof(*req->rq_oa));

                /* XXX When we start creating objects on demand, we need to
                 *     make sure that we always create the object on the
                 *     stripe which holds the existing file size.
                 */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        req->rq_oa->o_size = 
                                lov_size_to_stripe(lsm, src_oa->o_size, i);

                        CDEBUG(D_INODE, "stripe %d has size "LPU64"/"LPU64"\n",
                               i, req->rq_oa->o_size, src_oa->o_size);
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
                obd_free_memmd(exp, &set->set_md);
        free_idx_array(idx_arr, idx_cnt);
        EXIT;
        return rc;
}

/* An caveat here is don't use list_move() on same list */
#define list_adjust(tgt, lov, list_name, value) \
{ \
        struct list_head *element; \
        struct lov_tgt_desc *tmp;  \
        if (list_empty(&(tgt)->list_name)) \
                list_add(&(tgt)->list_name, &(lov)->list_name); \
        element = (tgt)->list_name.next; \
        while((element != &(lov)->list_name) && \
              (tmp = list_entry(element, struct lov_tgt_desc, list_name)) && \
              (value(tgt) < value(tmp))) \
                element = element->next; \
        if (element != (tgt)->list_name.next) { \
                list_del_init(&(tgt)->list_name); \
                list_add(&(tgt)->list_name, element->prev); \
        } \
        element = (tgt)->list_name.prev; \
        while ((element != &(lov)->list_name) && \
               (tmp = list_entry(element, struct lov_tgt_desc, list_name)) && \
               (value(tgt) > value(tmp))) \
                element = element->prev; \
        if (element != (tgt)->list_name.prev) { \
                list_del_init(&(tgt)->list_name); \
                list_add_tail(&(tgt)->list_name, element->prev); \
        } \
}

void qos_update(struct lov_obd *lov, int idx, struct obd_statfs *osfs)
{
        struct lov_tgt_desc *tgt = &lov->tgts[idx];
        __u64 bavail;
        ENTRY;
        
        bavail = osfs->os_bavail * osfs->os_bsize;
        if (!bavail) 
                CWARN("ost %d has zero avail space!\n", idx);
        
        CDEBUG(D_OTHER, "QOS: bfree now "LPU64"\n", bavail);
        
        mutex_down(&lov->lov_lock);
        list_adjust(tgt, lov, qos_bavail_list, TGT_BAVAIL);
        mutex_up(&lov->lov_lock);
}

