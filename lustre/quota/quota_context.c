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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/quota/quota_context.c
 *
 * Lustre Quota Context
 *
 * Author: Niu YaWei <niu@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <linux/slab.h>
#include <linux/quotaops.h>
#include <linux/module.h>
#include <linux/init.h>

#include <obd_class.h>
#include <lustre_quota.h>
#include <lustre_fsfilt.h>
#include <class_hash.h>
#include <lprocfs_status.h>
#include "quota_internal.h"

static int hash_lqs_cur_bits = HASH_LQS_CUR_BITS;
CFS_MODULE_PARM(hash_lqs_cur_bits, "i", int, 0444,
                "the current bits of lqs hash");

#ifdef HAVE_QUOTA_SUPPORT

static lustre_hash_ops_t lqs_hash_ops;

unsigned long default_bunit_sz = 128 * 1024 * 1024; /* 128M bytes */
unsigned long default_btune_ratio = 50;             /* 50 percentage */
unsigned long default_iunit_sz = 5120;              /* 5120 inodes */
unsigned long default_itune_ratio = 50;             /* 50 percentage */

cfs_mem_cache_t *qunit_cachep = NULL;
struct list_head qunit_hash[NR_DQHASH];
spinlock_t qunit_hash_lock = SPIN_LOCK_UNLOCKED;

/* please sync qunit_state with qunit_state_names */
enum qunit_state {
        QUNIT_CREATED      = 0,   /* a qunit is created */
        QUNIT_IN_HASH      = 1,   /* a qunit is added into qunit hash, that means
                                   * a quota req will be sent or is flying */
        QUNIT_RM_FROM_HASH = 2,   /* a qunit is removed from qunit hash, that
                                   * means a quota req is handled and comes
                                   * back */
        QUNIT_FINISHED     = 3,   /* qunit can wake up all threads waiting
                                   * for it */
};

static const char *qunit_state_names[] = {
        [QUNIT_CREATED]      = "CREATED",
        [QUNIT_IN_HASH]      = "IN_HASH",
        [QUNIT_RM_FROM_HASH] = "RM_FROM_HASH",
        [QUNIT_FINISHED]     = "FINISHED",
};

struct lustre_qunit {
        struct list_head lq_hash;          /* Hash list in memory */
        atomic_t lq_refcnt;                /* Use count */
        struct lustre_quota_ctxt *lq_ctxt; /* Quota context this applies to */
        struct qunit_data lq_data;         /* See qunit_data */
        unsigned int lq_opc;               /* QUOTA_DQACQ, QUOTA_DQREL */
        cfs_waitq_t lq_waitq;              /* Threads waiting for this qunit */
        spinlock_t lq_lock;                /* Protect the whole structure */
        enum qunit_state lq_state;         /* Present the status of qunit */
        int lq_rc;                         /* The rc of lq_data */
};

#define QUNIT_SET_STATE(qunit, state)                                   \
do {                                                                    \
        spin_lock(&qunit->lq_lock);                                     \
        QDATA_DEBUG((&qunit->lq_data), "qunit(%p) lq_state(%s->%s), "   \
                    "lq_rc(%d)\n",                                      \
                    qunit, qunit_state_names[qunit->lq_state],          \
                    qunit_state_names[state], qunit->lq_rc);            \
        qunit->lq_state = state;                                        \
        spin_unlock(&qunit->lq_lock);                                   \
} while(0)

#define QUNIT_SET_STATE_AND_RC(qunit, state, rc)                        \
do {                                                                    \
        spin_lock(&qunit->lq_lock);                                     \
        qunit->lq_rc = rc;                                              \
        QDATA_DEBUG((&qunit->lq_data), "qunit(%p) lq_state(%s->%s), "   \
                    "lq_rc(%d)\n",                                      \
                    qunit, qunit_state_names[qunit->lq_state],          \
                    qunit_state_names[state], qunit->lq_rc);            \
        qunit->lq_state = state;                                        \
        spin_unlock(&qunit->lq_lock);                                   \
} while(0)

int should_translate_quota (struct obd_import *imp)
{
        ENTRY;

        LASSERT(imp);
        if (imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_QUOTA64)
                RETURN(0);
        else
                RETURN(1);
}

void qunit_cache_cleanup(void)
{
        int i;
        ENTRY;

        spin_lock(&qunit_hash_lock);
        for (i = 0; i < NR_DQHASH; i++)
                LASSERT(list_empty(qunit_hash + i));
        spin_unlock(&qunit_hash_lock);

        if (qunit_cachep) {
                int rc;
                rc = cfs_mem_cache_destroy(qunit_cachep);
                LASSERTF(rc == 0, "couldn't destory qunit_cache slab\n");
                qunit_cachep = NULL;
        }
        EXIT;
}

int qunit_cache_init(void)
{
        int i;
        ENTRY;

        LASSERT(qunit_cachep == NULL);
        qunit_cachep = cfs_mem_cache_create("ll_qunit_cache",
                                            sizeof(struct lustre_qunit),
                                            0, 0);
        if (!qunit_cachep)
                RETURN(-ENOMEM);

        spin_lock(&qunit_hash_lock);
        for (i = 0; i < NR_DQHASH; i++)
                INIT_LIST_HEAD(qunit_hash + i);
        spin_unlock(&qunit_hash_lock);
        RETURN(0);
}

static inline int
qunit_hashfn(struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata)
             __attribute__((__const__));

static inline int
qunit_hashfn(struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata)
{
        unsigned int id = qdata->qd_id;
        unsigned int type = QDATA_IS_GRP(qdata);

        unsigned long tmp = ((unsigned long)qctxt >> L1_CACHE_SHIFT) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

/* caller must hold qunit_hash_lock */
static inline struct lustre_qunit *find_qunit(unsigned int hashent,
                                              struct lustre_quota_ctxt *qctxt,
                                              struct qunit_data *qdata)
{
        struct lustre_qunit *qunit = NULL;
        struct qunit_data *tmp;

        LASSERT_SPIN_LOCKED(&qunit_hash_lock);
        list_for_each_entry(qunit, qunit_hash + hashent, lq_hash) {
                tmp = &qunit->lq_data;
                if (qunit->lq_ctxt == qctxt &&
                    qdata->qd_id == tmp->qd_id &&
                    (qdata->qd_flags & LQUOTA_QUNIT_FLAGS) ==
                    (tmp->qd_flags & LQUOTA_QUNIT_FLAGS))
                        return qunit;
        }
        return NULL;
}

/* check_cur_qunit - check the current usage of qunit.
 * @qctxt: quota context
 * @qdata: the type of quota unit to be checked
 *
 * return: 1 - need acquire qunit;
 * 	   2 - need release qunit;
 * 	   0 - need do nothing.
 * 	 < 0 - error.
 */
static int
check_cur_qunit(struct obd_device *obd,
                struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata)
{
        struct super_block *sb = qctxt->lqc_sb;
        unsigned long qunit_sz, tune_sz;
        __u64 usage, limit, limit_org, pending_write = 0;
        long long record = 0;
        struct obd_quotactl *qctl;
        struct lustre_qunit_size *lqs = NULL;
        int ret = 0;
        ENTRY;

        if (!ll_sb_has_quota_active(sb, QDATA_IS_GRP(qdata)))
                RETURN(0);

        spin_lock(&qctxt->lqc_lock);
        if (!qctxt->lqc_valid){
                spin_unlock(&qctxt->lqc_lock);
                RETURN(0);
        }
        spin_unlock(&qctxt->lqc_lock);

        OBD_ALLOC_PTR(qctl);
        if (qctl == NULL)
                RETURN(-ENOMEM);

        /* get fs quota usage & limit */
        qctl->qc_cmd = Q_GETQUOTA;
        qctl->qc_id = qdata->qd_id;
        qctl->qc_type = QDATA_IS_GRP(qdata);
        ret = fsfilt_quotactl(obd, sb, qctl);
        if (ret) {
                if (ret == -ESRCH)      /* no limit */
                        ret = 0;
                else
                        CERROR("can't get fs quota usage! (rc:%d)\n", ret);
                GOTO(out, ret);
        }

        if (QDATA_IS_BLK(qdata)) {
                usage = qctl->qc_dqblk.dqb_curspace;
                limit = qctl->qc_dqblk.dqb_bhardlimit << QUOTABLOCK_BITS;
        } else {
                usage = qctl->qc_dqblk.dqb_curinodes;
                limit = qctl->qc_dqblk.dqb_ihardlimit;
        }

        /* ignore the no quota limit case; and it can avoid creating
         * unnecessary lqs for uid/gid */
        if (!limit)
                GOTO(out, ret = 0);

        lqs = quota_search_lqs(LQS_KEY(QDATA_IS_GRP(qdata), qdata->qd_id),
                               qctxt, 0);
        if (IS_ERR(lqs) || lqs == NULL) {
                CERROR("fail to find a lqs for %sid: %u)!\n",
                       QDATA_IS_GRP(qdata) ? "g" : "u", qdata->qd_id);
                GOTO (out, ret = 0);
        }
        spin_lock(&lqs->lqs_lock);

        if (QDATA_IS_BLK(qdata)) {
                qunit_sz = lqs->lqs_bunit_sz;
                tune_sz  = lqs->lqs_btune_sz;
                pending_write = lqs->lqs_bwrite_pending;
                record   = lqs->lqs_blk_rec;
                LASSERT(!(qunit_sz % QUOTABLOCK_SIZE));
        } else {
                /* we didn't need change inode qunit size now */
                qunit_sz = lqs->lqs_iunit_sz;
                tune_sz  = lqs->lqs_itune_sz;
                pending_write = lqs->lqs_iwrite_pending;
                record   = lqs->lqs_ino_rec;
        }

        /* we don't count the MIN_QLIMIT */
        if ((limit == MIN_QLIMIT && !QDATA_IS_BLK(qdata)) ||
            (toqb(limit) == MIN_QLIMIT && QDATA_IS_BLK(qdata)))
                limit = 0;

        usage += pending_write;
        limit_org = limit;
        /* when a releasing quota req is sent, before it returned
           limit is assigned a small value. limit will overflow */
        if (record < 0)
                usage -= record;
        else
                limit += record;

        LASSERT(qdata->qd_count == 0);
        if (limit <= usage + tune_sz) {
                while (qdata->qd_count + limit <=
                       usage + tune_sz)
                        qdata->qd_count += qunit_sz;
                ret = 1;
        } else if (limit > usage + qunit_sz + tune_sz &&
                   limit_org > qdata->qd_count + qunit_sz) {
                while (limit - qdata->qd_count > usage + qunit_sz + tune_sz &&
                       limit_org > qdata->qd_count + qunit_sz)
                        qdata->qd_count += qunit_sz;
                ret = 2;
                /* if there are other pending writes for this uid/gid, releasing
                 * quota is put off until the last pending write b=16645 */
                /* if there is an ongoing quota request, a releasing request is aborted.
                 * That ongoing quota request will call this function again when
                 * it returned b=18630 */
                if (pending_write || record) {
                        CDEBUG(D_QUOTA, "delay quota release\n");
                        ret = 0;
                }
        }
        if (ret > 0)
                quota_compute_lqs(qdata, lqs, 1, (ret == 1) ? 1 : 0);

        CDEBUG(D_QUOTA, "type: %c, limit: "LPU64", usage: "LPU64
               ", pending_write: "LPU64", record: %lld"
               ", qunit_sz: %lu, tune_sz: %lu, ret: %d.\n",
               QDATA_IS_BLK(qdata) ? 'b' : 'i', limit, usage, pending_write,
               record, qunit_sz, tune_sz, ret);
        LASSERT(ret == 0 || qdata->qd_count);

        spin_unlock(&lqs->lqs_lock);
        lqs_putref(lqs);

        EXIT;
 out:
        OBD_FREE_PTR(qctl);
        return ret;
}

/* compute the remaining quota for certain gid or uid b=11693 */
int compute_remquota(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                     struct qunit_data *qdata, int isblk)
{
        struct super_block *sb = qctxt->lqc_sb;
        __u64 usage, limit;
        struct obd_quotactl *qctl;
        int ret = QUOTA_RET_OK;
        ENTRY;

        /* ignore root user */
        if (qdata->qd_id == 0 && QDATA_IS_GRP(qdata) == USRQUOTA)
                RETURN(QUOTA_RET_NOLIMIT);

        OBD_ALLOC_PTR(qctl);
        if (qctl == NULL)
                RETURN(-ENOMEM);

        /* get fs quota usage & limit */
        qctl->qc_cmd = Q_GETQUOTA;
        qctl->qc_id = qdata->qd_id;
        qctl->qc_type = QDATA_IS_GRP(qdata);
        ret = fsfilt_quotactl(obd, sb, qctl);
        if (ret) {
                if (ret == -ESRCH)      /* no limit */
                        ret = QUOTA_RET_NOLIMIT;
                else
                        CDEBUG(D_QUOTA, "can't get fs quota usage! (rc:%d)",
                               ret);
                GOTO(out, ret);
        }

        usage = isblk ? qctl->qc_dqblk.dqb_curspace :
                qctl->qc_dqblk.dqb_curinodes;
        limit = isblk ? qctl->qc_dqblk.dqb_bhardlimit << QUOTABLOCK_BITS :
                qctl->qc_dqblk.dqb_ihardlimit;
        if (!limit){            /* no limit */
                ret = QUOTA_RET_NOLIMIT;
                GOTO(out, ret);
        }

        if (limit >= usage)
                qdata->qd_count = limit - usage;
        else
                qdata->qd_count = 0;
        EXIT;
out:
        OBD_FREE_PTR(qctl);
        return ret;
}

static struct lustre_qunit *alloc_qunit(struct lustre_quota_ctxt *qctxt,
                                        struct qunit_data *qdata, int opc)
{
        struct lustre_qunit *qunit = NULL;
        ENTRY;

        OBD_SLAB_ALLOC(qunit, qunit_cachep, CFS_ALLOC_IO, sizeof(*qunit));
        if (qunit == NULL)
                RETURN(NULL);

        INIT_LIST_HEAD(&qunit->lq_hash);
        init_waitqueue_head(&qunit->lq_waitq);
        atomic_set(&qunit->lq_refcnt, 1);
        qunit->lq_ctxt = qctxt;
        memcpy(&qunit->lq_data, qdata, sizeof(*qdata));
        qunit->lq_opc = opc;
        qunit->lq_lock = SPIN_LOCK_UNLOCKED;
        QUNIT_SET_STATE_AND_RC(qunit, QUNIT_CREATED, 0);
        RETURN(qunit);
}

static inline void free_qunit(struct lustre_qunit *qunit)
{
        OBD_SLAB_FREE(qunit, qunit_cachep, sizeof(*qunit));
}

static inline void qunit_get(struct lustre_qunit *qunit)
{
        atomic_inc(&qunit->lq_refcnt);
}

static void qunit_put(struct lustre_qunit *qunit)
{
        LASSERT(atomic_read(&qunit->lq_refcnt));
        if (atomic_dec_and_test(&qunit->lq_refcnt))
                free_qunit(qunit);
}

/* caller must hold qunit_hash_lock and release ref of qunit after using it */
static struct lustre_qunit *dqacq_in_flight(struct lustre_quota_ctxt *qctxt,
                                            struct qunit_data *qdata)
{
        unsigned int hashent = qunit_hashfn(qctxt, qdata);
        struct lustre_qunit *qunit;
        ENTRY;

        LASSERT_SPIN_LOCKED(&qunit_hash_lock);
        qunit = find_qunit(hashent, qctxt, qdata);
        if (qunit)
                qunit_get(qunit);
        RETURN(qunit);
}

static void
insert_qunit_nolock(struct lustre_quota_ctxt *qctxt, struct lustre_qunit *qunit)
{
        struct list_head *head;

        LASSERT(list_empty(&qunit->lq_hash));
        qunit_get(qunit);
        head = qunit_hash + qunit_hashfn(qctxt, &qunit->lq_data);
        list_add(&qunit->lq_hash, head);
        QUNIT_SET_STATE(qunit, QUNIT_IN_HASH);
}

static void compute_lqs_after_removing_qunit(struct lustre_qunit *qunit)
{
        struct lustre_qunit_size *lqs;

        lqs = quota_search_lqs(LQS_KEY(QDATA_IS_GRP(&qunit->lq_data),
                                       qunit->lq_data.qd_id),
                               qunit->lq_ctxt, 0);
        if (lqs && !IS_ERR(lqs)) {
                spin_lock(&lqs->lqs_lock);
                if (qunit->lq_opc == QUOTA_DQACQ)
                        quota_compute_lqs(&qunit->lq_data, lqs, 0, 1);
                if (qunit->lq_opc == QUOTA_DQREL)
                        quota_compute_lqs(&qunit->lq_data, lqs, 0, 0);
                spin_unlock(&lqs->lqs_lock);
                /* this is for quota_search_lqs */
                lqs_putref(lqs);
                /* this is for schedule_dqacq */
                lqs_putref(lqs);
        }
}

static void remove_qunit_nolock(struct lustre_qunit *qunit)
{
        LASSERT(!list_empty(&qunit->lq_hash));
        LASSERT_SPIN_LOCKED(&qunit_hash_lock);

        list_del_init(&qunit->lq_hash);
        QUNIT_SET_STATE(qunit, QUNIT_RM_FROM_HASH);
        qunit_put(qunit);
}

void* quota_barrier(struct lustre_quota_ctxt *qctxt,
                    struct obd_quotactl *oqctl, int isblk)
{
        struct lustre_qunit *qunit, *find_qunit;
        int cycle = 1;

        OBD_SLAB_ALLOC(qunit, qunit_cachep, CFS_ALLOC_IO, sizeof(*qunit));
        if (qunit == NULL) {
                CERROR("locating %sunit failed for %sid %u\n",
                       isblk ? "b" : "i", oqctl->qc_type ? "g" : "u",
                       oqctl->qc_id);
                qctxt_wait_pending_dqacq(qctxt, oqctl->qc_id,
                                         oqctl->qc_type, isblk);
                return NULL;
        }

        INIT_LIST_HEAD(&qunit->lq_hash);
        qunit->lq_lock = SPIN_LOCK_UNLOCKED;
        init_waitqueue_head(&qunit->lq_waitq);
        atomic_set(&qunit->lq_refcnt, 1);
        qunit->lq_ctxt = qctxt;
        qunit->lq_data.qd_id = oqctl->qc_id;
        qunit->lq_data.qd_flags =  oqctl->qc_type;
        if (isblk)
                QDATA_SET_BLK(&qunit->lq_data);
        QUNIT_SET_STATE_AND_RC(qunit, QUNIT_CREATED, 0);
        /* it means it is only an invalid qunit for barrier */
        qunit->lq_opc = QUOTA_LAST_OPC;

        while (1) {
                spin_lock(&qunit_hash_lock);
                find_qunit = dqacq_in_flight(qctxt, &qunit->lq_data);
                if (find_qunit) {
                        spin_unlock(&qunit_hash_lock);
                        qunit_put(find_qunit);
                        qctxt_wait_pending_dqacq(qctxt, oqctl->qc_id,
                                                 oqctl->qc_type, isblk);
                        CDEBUG(D_QUOTA, "cycle=%d\n", cycle++);
                        continue;
                }
                break;
        }
        insert_qunit_nolock(qctxt, qunit);
        spin_unlock(&qunit_hash_lock);
        return qunit;
}

void quota_unbarrier(void *handle)
{
        struct lustre_qunit *qunit = (struct lustre_qunit *)handle;

        if (qunit == NULL) {
                CERROR("handle is NULL\n");
                return;
        }

        LASSERT(qunit->lq_opc == QUOTA_LAST_OPC);
        spin_lock(&qunit_hash_lock);
        remove_qunit_nolock(qunit);
        spin_unlock(&qunit_hash_lock);
        QUNIT_SET_STATE_AND_RC(qunit, QUNIT_FINISHED, QUOTA_REQ_RETURNED);
        wake_up(&qunit->lq_waitq);
        qunit_put(qunit);
}

#define INC_QLIMIT(limit, count) (limit == MIN_QLIMIT) ? \
                                 (limit = count) : (limit += count)


/* FIXME check if this mds is the master of specified id */
static int
is_master(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
          unsigned int id, int type)
{
        return qctxt->lqc_handler ? 1 : 0;
}

static int
schedule_dqacq(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
               struct qunit_data *qdata, int opc, int wait,
               struct obd_trans_info *oti);

static inline void qdata_to_oqaq(struct qunit_data *qdata,
                                 struct quota_adjust_qunit *oqaq)
{
        LASSERT(qdata);
        LASSERT(oqaq);

        oqaq->qaq_flags = qdata->qd_flags;
        oqaq->qaq_id    = qdata->qd_id;
        if (QDATA_IS_ADJBLK(qdata))
                oqaq->qaq_bunit_sz = qdata->qd_qunit;
        if (QDATA_IS_ADJINO(qdata))
                oqaq->qaq_iunit_sz = qdata->qd_qunit;
}

static int
dqacq_completion(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                 struct qunit_data *qdata, int rc, int opc)
{
        struct lustre_qunit *qunit = NULL;
        struct super_block *sb = qctxt->lqc_sb;
        int err = 0;
        struct quota_adjust_qunit *oqaq = NULL;
        int rc1 = 0;
        ENTRY;

        LASSERT(qdata);
        QDATA_DEBUG(qdata, "obd(%s): complete %s quota req\n",
                    obd->obd_name, (opc == QUOTA_DQACQ) ? "acq" : "rel");

        /* do it only when a releasing quota req more than 5MB b=18491 */
        if (opc == QUOTA_DQREL && qdata->qd_count >= 5242880)
                OBD_FAIL_TIMEOUT(OBD_FAIL_QUOTA_DELAY_REL, 5);

        /* update local operational quota file */
        if (rc == 0) {
                __u64 count = QUSG(qdata->qd_count, QDATA_IS_BLK(qdata));
                struct obd_quotactl *qctl;
                __u64 *hardlimit;

                OBD_ALLOC_PTR(qctl);
                if (qctl == NULL)
                        GOTO(out, err = -ENOMEM);

                /* acq/rel qunit for specified uid/gid is serialized,
                 * so there is no race between get fs quota limit and
                 * set fs quota limit */
                qctl->qc_cmd = Q_GETQUOTA;
                qctl->qc_id = qdata->qd_id;
                qctl->qc_type = QDATA_IS_GRP(qdata);
                err = fsfilt_quotactl(obd, sb, qctl);
                if (err) {
                        CERROR("error get quota fs limit! (rc:%d)\n", err);
                        GOTO(out_mem, err);
                }

                if (QDATA_IS_BLK(qdata)) {
                        qctl->qc_dqblk.dqb_valid = QIF_BLIMITS;
                        hardlimit = &qctl->qc_dqblk.dqb_bhardlimit;
                } else {
                        qctl->qc_dqblk.dqb_valid = QIF_ILIMITS;
                        hardlimit = &qctl->qc_dqblk.dqb_ihardlimit;
                }

                CDEBUG(D_QUOTA, "hardlimt: "LPU64"\n", *hardlimit);

                if (*hardlimit == 0)
                        goto out_mem;

                switch (opc) {
                case QUOTA_DQACQ:
                        INC_QLIMIT(*hardlimit, count);
                        break;
                case QUOTA_DQREL:
                        if (count >= *hardlimit)
                                CERROR("release quota error: id(%u) flag(%u) "
                                       "type(%c) isblk(%c) count("LPU64") "
                                       "qd_qunit("LPU64") hardlimit("LPU64") "
                                       "qdata(%p)\n",
                                       qdata->qd_id, qdata->qd_flags,
                                       QDATA_IS_GRP(qdata) ? 'g' : 'u',
                                       QDATA_IS_BLK(qdata) ? 'b': 'i',
                                       qdata->qd_count, qdata->qd_qunit, *hardlimit,
                                       qdata);
                        else
                                *hardlimit -= count;
                        break;
                default:
                        LBUG();
                }

                /* clear quota limit */
                if (count == 0)
                        *hardlimit = 0;

                qctl->qc_cmd = Q_SETQUOTA;
                err = fsfilt_quotactl(obd, sb, qctl);
                if (err)
                        CERROR("error set quota fs limit! (rc:%d)\n", err);

                QDATA_DEBUG(qdata, "%s completion\n",
                            opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
out_mem:
                OBD_FREE_PTR(qctl);
        } else if (rc == -EDQUOT) {
                QDATA_DEBUG(qdata, "acquire qunit got EDQUOT.\n");
        } else if (rc == -EBUSY) {
                QDATA_DEBUG(qdata, "it's is recovering, got EBUSY.\n");
        } else {
                CERROR("acquire qunit got error! (rc:%d)\n", rc);
        }
out:
        /* remove the qunit from hash */
        spin_lock(&qunit_hash_lock);

        qunit = dqacq_in_flight(qctxt, qdata);
        /* this qunit has been removed by qctxt_cleanup() */
        if (!qunit) {
                spin_unlock(&qunit_hash_lock);
                QDATA_DEBUG(qdata, "%s is discarded because qunit isn't found\n",
                            opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
                RETURN(err);
        }

        LASSERT(opc == qunit->lq_opc);
        /* remove this qunit from lq_hash so that new processes cannot be added
         * to qunit->lq_waiters */
        remove_qunit_nolock(qunit);
        spin_unlock(&qunit_hash_lock);

        compute_lqs_after_removing_qunit(qunit);


        if (rc == 0)
                rc = QUOTA_REQ_RETURNED;
        QUNIT_SET_STATE_AND_RC(qunit, QUNIT_FINISHED, rc);
        /* wake up all waiters */
        wake_up(&qunit->lq_waitq);

        /* this is for dqacq_in_flight() */
        qunit_put(qunit);
        /* this is for alloc_qunit() */
        qunit_put(qunit);
        if (rc < 0 && rc != -EDQUOT)
                 RETURN(err);

        /* don't reschedule in such cases:
         *   - acq/rel failure and qunit isn't changed,
         *     but not for quota recovery.
         *   - local dqacq/dqrel.
         *   - local disk io failure.
         */
         OBD_ALLOC_PTR(oqaq);
         if (!oqaq)
                 RETURN(-ENOMEM);
         qdata_to_oqaq(qdata, oqaq);
         /* adjust the qunit size in slaves */
         rc1 = quota_adjust_slave_lqs(oqaq, qctxt);
         OBD_FREE_PTR(oqaq);
         if (rc1 < 0) {
                 CERROR("adjust slave's qunit size failed!(rc:%d)\n", rc1);
                 RETURN(rc1);
         }
         if (err || (rc < 0 && rc != -EBUSY && rc1 == 0) ||
             is_master(obd, qctxt, qdata->qd_id, QDATA_IS_GRP(qdata)))
                RETURN(err);

         if (opc == QUOTA_DQREL && qdata->qd_count >= 5242880)
                 OBD_FAIL_RETURN(OBD_FAIL_QUOTA_DELAY_REL, err);

        /* reschedule another dqacq/dqrel if needed */
        qdata->qd_count = 0;
        qdata->qd_flags &= LQUOTA_QUNIT_FLAGS;
        rc1 = check_cur_qunit(obd, qctxt, qdata);
        if (rc1 > 0) {
                int opc;
                opc = rc1 == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                rc1 = schedule_dqacq(obd, qctxt, qdata, opc, 0, NULL);
                QDATA_DEBUG(qdata, "reschedudle opc(%d) rc(%d)\n", opc, rc1);
        }
        RETURN(err);
}

struct dqacq_async_args {
        struct lustre_quota_ctxt *aa_ctxt;
        struct lustre_qunit *aa_qunit;
};

static int dqacq_interpret(struct ptlrpc_request *req, void *data, int rc)
{
        struct dqacq_async_args *aa = (struct dqacq_async_args *)data;
        struct lustre_quota_ctxt *qctxt = aa->aa_ctxt;
        struct lustre_qunit *qunit = aa->aa_qunit;
        struct obd_device *obd = req->rq_import->imp_obd;
        struct qunit_data *qdata = NULL;
        int rc1 = 0;
        ENTRY;

        LASSERT(req);
        LASSERT(req->rq_import);

        /* there are several forms of qunit(historic causes), so we need to
         * adjust qunit from slaves to the same form here */
        OBD_ALLOC(qdata, sizeof(struct qunit_data));
        if (!qdata)
                RETURN(-ENOMEM);

        /* if a quota req timeouts or is dropped, we should update quota
         * statistics which will be handled in dqacq_completion. And in
         * this situation we should get qdata from request instead of
         * reply */
        rc1 = quota_get_qdata(req, qdata,
                              (rc != 0) ? QUOTA_REQUEST : QUOTA_REPLY,
                              QUOTA_IMPORT);
        if (rc1 < 0) {
                DEBUG_REQ(D_ERROR, req,
                          "error unpacking qunit_data(rc: %d)\n", rc1);
                *qdata = qunit->lq_data;
        }

        QDATA_DEBUG(qdata, "qdata: interpret rc(%d).\n", rc);
        QDATA_DEBUG((&qunit->lq_data), "lq_data: \n");

        if (qdata->qd_id != qunit->lq_data.qd_id ||
            OBD_FAIL_CHECK(OBD_FAIL_QUOTA_RET_QDATA)) {
                CERROR("the returned qd_id isn't expected!"
                       "(qdata: %u, lq_data: %u)\n", qdata->qd_id,
                       qunit->lq_data.qd_id);
                qdata->qd_id = qunit->lq_data.qd_id;
                rc = -EPROTO;
        }
        if (QDATA_IS_GRP(qdata) != QDATA_IS_GRP(&qunit->lq_data)) {
                CERROR("the returned grp/usr isn't expected!"
                       "(qdata: %u, lq_data: %u)\n", qdata->qd_flags,
                       qunit->lq_data.qd_flags);
                if (QDATA_IS_GRP(&qunit->lq_data))
                        QDATA_SET_GRP(qdata);
                else
                        QDATA_CLR_GRP(qdata);
                rc = -EPROTO;
        }
        if (qdata->qd_count > qunit->lq_data.qd_count) {
                CERROR("the returned qd_count isn't expected!"
                       "(qdata: "LPU64", lq_data: "LPU64")\n", qdata->qd_count,
                       qunit->lq_data.qd_count);
                rc = -EPROTO;
        }

        rc = dqacq_completion(obd, qctxt, qdata, rc,
                              lustre_msg_get_opc(req->rq_reqmsg));

        OBD_FREE(qdata, sizeof(struct qunit_data));

        RETURN(rc);
}

/* check if quota master is online */
int check_qm(struct lustre_quota_ctxt *qctxt)
{
        int rc;
        ENTRY;

        spin_lock(&qctxt->lqc_lock);
        /* quit waiting when mds is back or qctxt is cleaned up */
        rc = qctxt->lqc_import || !qctxt->lqc_valid;
        spin_unlock(&qctxt->lqc_lock);

        RETURN(rc);
}

/* wake up all waiting threads when lqc_import is NULL */
void dqacq_interrupt(struct lustre_quota_ctxt *qctxt)
{
        struct lustre_qunit *qunit, *tmp;
        int i;
        ENTRY;

        spin_lock(&qunit_hash_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(qunit, tmp, &qunit_hash[i], lq_hash) {
                        if (qunit->lq_ctxt != qctxt)
                                continue;

                        /* Wake up all waiters. Do not change lq_state.
                         * The waiters will check lq_rc which is kept as 0
                         * if no others change it, then the waiters will return
                         * -EAGAIN to caller who can perform related quota
                         * acq/rel if necessary. */
                        wake_up_all(&qunit->lq_waitq);
                }
        }
        spin_unlock(&qunit_hash_lock);
        EXIT;
}

static int got_qunit(struct lustre_qunit *qunit, int is_master)
{
        struct lustre_quota_ctxt *qctxt = qunit->lq_ctxt;
        int rc = 0;
        ENTRY;

        spin_lock(&qunit->lq_lock);
        switch (qunit->lq_state) {
        case QUNIT_IN_HASH:
        case QUNIT_RM_FROM_HASH:
                break;
        case QUNIT_FINISHED:
                rc = 1;
                break;
        default:
                CERROR("invalid qunit state %d\n", qunit->lq_state);
        }
        spin_unlock(&qunit->lq_lock);

        if (!rc) {
                spin_lock(&qctxt->lqc_lock);
                rc = !qctxt->lqc_valid;
                if (!is_master)
                        rc |= !qctxt->lqc_import;
                spin_unlock(&qctxt->lqc_lock);
        }

        RETURN(rc);
}

static inline void
revoke_lqs_rec(struct lustre_qunit_size *lqs, struct qunit_data *qdata, int opc)
{
        /* revoke lqs_xxx_rec which is computed in check_cur_qunit
         * b=18630 */
        spin_lock(&lqs->lqs_lock);
        quota_compute_lqs(qdata, lqs, 0, (opc == QUOTA_DQACQ) ? 1 : 0);
        spin_unlock(&lqs->lqs_lock);
}

static int
schedule_dqacq(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
               struct qunit_data *qdata, int opc, int wait,
               struct obd_trans_info *oti)
{
        struct lustre_qunit *qunit, *empty;
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_request *req;
        struct dqacq_async_args *aa;
        int size[2] = { sizeof(struct ptlrpc_body), 0 };
        struct obd_import *imp = NULL;
        struct lustre_qunit_size *lqs = NULL;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        int ismaster = is_master(obd, qctxt, qdata->qd_id, QDATA_IS_GRP(qdata));
        int rc = 0;
        ENTRY;

        LASSERT(opc == QUOTA_DQACQ || opc == QUOTA_DQREL);
        do_gettimeofday(&work_start);

        lqs = quota_search_lqs(LQS_KEY(QDATA_IS_GRP(qdata), qdata->qd_id),
                               qctxt, 0);
        if (lqs == NULL || IS_ERR(lqs)) {
                CERROR("Can't find the lustre qunit size!\n");
                RETURN(-EPERM);
        }

        if ((empty = alloc_qunit(qctxt, qdata, opc)) == NULL) {
                revoke_lqs_rec(lqs, qdata, opc);
                /* this is for quota_search_lqs */
                lqs_putref(lqs);
                RETURN(-ENOMEM);
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_QUOTA_DELAY_SD, 5);

        spin_lock(&qunit_hash_lock);
        qunit = dqacq_in_flight(qctxt, qdata);
        if (qunit) {
                spin_unlock(&qunit_hash_lock);
                qunit_put(empty);

                revoke_lqs_rec(lqs, qdata, opc);
                /* this is for quota_search_lqs */
                lqs_putref(lqs);
                goto wait_completion;
        }
        qunit = empty;
        qunit_get(qunit);
        insert_qunit_nolock(qctxt, qunit);
        spin_unlock(&qunit_hash_lock);

        /* From here, the quota request will be sent anyway.
         * When this qdata request returned or is cancelled,
         * lqs_putref will be called at that time */
        lqs_getref(lqs);
        /* this is for quota_search_lqs */
        lqs_putref(lqs);

        QDATA_DEBUG(qdata, "obd(%s): send %s quota req\n",
                    obd->obd_name, (opc == QUOTA_DQACQ) ? "acq" : "rel");
        /* master is going to dqacq/dqrel from itself */
        if (ismaster) {
                int rc2;
                QDATA_DEBUG(qdata, "local %s.\n",
                            opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
                QDATA_SET_CHANGE_QS(qdata);
                rc = qctxt->lqc_handler(obd, qdata, opc);
                rc2 = dqacq_completion(obd, qctxt, qdata, rc, opc);
                /* this is for qunit_get() */
                qunit_put(qunit);

                do_gettimeofday(&work_end);
                timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
                if (opc == QUOTA_DQACQ)
                        lprocfs_counter_add(qctxt->lqc_stats,
                                            wait ? LQUOTA_SYNC_ACQ : LQUOTA_ASYNC_ACQ,
                                            timediff);
                else
                        lprocfs_counter_add(qctxt->lqc_stats,
                                            wait ? LQUOTA_SYNC_REL : LQUOTA_ASYNC_REL,
                                            timediff);
                RETURN(rc ? rc : rc2);
        }

        spin_lock(&qctxt->lqc_lock);
        if (!qctxt->lqc_import) {
                spin_unlock(&qctxt->lqc_lock);
                QDATA_DEBUG(qdata, "lqc_import is invalid.\n");

                spin_lock(&qunit_hash_lock);
                remove_qunit_nolock(qunit);
                spin_unlock(&qunit_hash_lock);

                compute_lqs_after_removing_qunit(qunit);

                QUNIT_SET_STATE_AND_RC(qunit, QUNIT_FINISHED, -EAGAIN);
                wake_up(&qunit->lq_waitq);

                /* this is for qunit_get() */
                qunit_put(qunit);
                /* this for alloc_qunit() */
                qunit_put(qunit);
                spin_lock(&qctxt->lqc_lock);
                if (wait && !qctxt->lqc_import) {
                        spin_unlock(&qctxt->lqc_lock);

                        LASSERT(oti && oti->oti_thread &&
                                oti->oti_thread->t_watchdog);

                        lc_watchdog_disable(oti->oti_thread->t_watchdog);
                        CDEBUG(D_QUOTA, "sleep for quota master\n");
                        l_wait_event(qctxt->lqc_wait_for_qmaster,
                                     check_qm(qctxt), &lwi);
                        CDEBUG(D_QUOTA, "wake up when quota master is back\n");
                        lc_watchdog_touch(oti->oti_thread->t_watchdog,
                                 GET_TIMEOUT(oti->oti_thread->t_svc));
                } else {
                        spin_unlock(&qctxt->lqc_lock);
                }

                RETURN(-EAGAIN);
        }
        imp = class_import_get(qctxt->lqc_import);
        spin_unlock(&qctxt->lqc_lock);

        /* build dqacq/dqrel request */
        LASSERT(imp);
        size[1] = quota_get_qunit_data_size(imp->
                                            imp_connect_data.ocd_connect_flags);

        req = ptlrpc_prep_req(imp, LUSTRE_MDS_VERSION, opc, 2,
                              size, NULL);
        if (!req) {
                dqacq_completion(obd, qctxt, qdata, -ENOMEM, opc);
                class_import_put(imp);
                /* this is for qunit_get() */
                qunit_put(qunit);
                RETURN(-ENOMEM);
        }

        rc = quota_copy_qdata(req, qdata, QUOTA_REQUEST, QUOTA_IMPORT);
        if (rc < 0) {
                CERROR("Can't pack qunit_data(rc: %d)\n", rc);
                dqacq_completion(obd, qctxt, qdata, rc, opc);
                class_import_put(imp);
                /* this is for qunit_get() */
                qunit_put(qunit);
                RETURN(rc);
        }
        ptlrpc_req_set_repsize(req, 2, size);
        req->rq_no_resend = req->rq_no_delay = 1;
        class_import_put(imp);

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_ctxt = qctxt;
        aa->aa_qunit = qunit;

        req->rq_interpret_reply = dqacq_interpret;
        ptlrpcd_add_req(req);

        QDATA_DEBUG(qdata, "%s scheduled.\n",
                    opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
wait_completion:
        if (wait && qunit) {
                struct qunit_data *p = &qunit->lq_data;

                QDATA_DEBUG(p, "qunit(%p) is waiting for dqacq.\n", qunit);
                l_wait_event(qunit->lq_waitq, got_qunit(qunit, ismaster), &lwi);
                /* rc = -EAGAIN, it means the quota master isn't ready yet
                 * rc = QUOTA_REQ_RETURNED, it means a quota req is finished;
                 * rc = -EDQUOT, it means out of quota
                 * rc = -EBUSY, it means recovery is happening
                 * other rc < 0, it means real errors, functions who call
                 * schedule_dqacq should take care of this */
                spin_lock(&qunit->lq_lock);
                rc = qunit->lq_rc;
                spin_unlock(&qunit->lq_lock);
                CDEBUG(D_QUOTA, "qunit(%p) finishes waiting. (rc:%d)\n",
                       qunit, rc);
        }

        qunit_put(qunit);
        do_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        if (opc == QUOTA_DQACQ)
                lprocfs_counter_add(qctxt->lqc_stats,
                                    wait ? LQUOTA_SYNC_ACQ : LQUOTA_ASYNC_ACQ,
                                    timediff);
        else
                lprocfs_counter_add(qctxt->lqc_stats,
                                    wait ? LQUOTA_SYNC_REL : LQUOTA_ASYNC_REL,
                                    timediff);

        RETURN(rc);
}

int
qctxt_adjust_qunit(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                   uid_t uid, gid_t gid, __u32 isblk, int wait,
                   struct obd_trans_info *oti)
{
        int rc = 0, i = USRQUOTA;
        __u32 id[MAXQUOTAS] = { uid, gid };
        struct qunit_data qdata[MAXQUOTAS];
        ENTRY;

        /* XXX In quota_chk_acq_common(), we do something like:
         *
         *     while (quota_check_common() & QUOTA_RET_ACQUOTA) {
         *            rc = qctxt_adjust_qunit();
         *     }
         *
         *     to make sure the slave acquired enough quota from master.
         *
         *     Unfortunately, qctxt_adjust_qunit() checks QB/QI_SET to
         *     decide if do real DQACQ or not, but quota_check_common()
         *     doesn't check QB/QI_SET flags. This inconsistence could
         *     lead into an infinite loop.
         *
         *     We can't fix it by simply adding QB/QI_SET checking in the
         *     quota_check_common(), since we must guarantee that the
         *     paried quota_pending_commit() has same QB/QI_SET, but the
         *     flags can be actually cleared at any time...
         *
         *     A quick non-intrusive solution is to just skip the
         *     QB/QI_SET checking here when the @wait is non-zero.
         *     (If the @wait is non-zero, the caller must have already
         *     checked the QB/QI_SET).
         */
        if (!wait &&
            quota_is_set(obd, uid, gid, isblk ? QB_SET : QI_SET) == 0)
                RETURN(0);

        for (i = 0; i < MAXQUOTAS; i++) {
                qdata[i].qd_id = id[i];
                qdata[i].qd_flags = i;
                if (isblk)
                        QDATA_SET_BLK(&qdata[i]);
                qdata[i].qd_count = 0;

                rc = check_cur_qunit(obd, qctxt, &qdata[i]);
                if (rc > 0) {
                        int opc;
                        /* need acquire or release */
                        opc = rc == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                        rc = schedule_dqacq(obd, qctxt, &qdata[i], opc,
                                            wait,oti);
                        if (rc < 0)
                                RETURN(rc);
                } else if (wait == 1) {
                        /* when wait equates 1, that means mds_quota_acquire
                         * or filter_quota_acquire is calling it. */
                        rc = qctxt_wait_pending_dqacq(qctxt, id[i], i, isblk);
                        if (rc < 0)
                                RETURN(rc);
                }
        }

        RETURN(rc);
}

int
qctxt_wait_pending_dqacq(struct lustre_quota_ctxt *qctxt, unsigned int id,
                         unsigned short type, int isblk)
{
        struct lustre_qunit *qunit = NULL;
        struct qunit_data qdata;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        struct l_wait_info lwi = { 0 };
        int ismaster = is_master(NULL, qctxt, id, type);
        int rc = 0;
        ENTRY;

        do_gettimeofday(&work_start);
        qdata.qd_id = id;
        qdata.qd_flags = type;
        if (isblk)
                QDATA_SET_BLK(&qdata);
        qdata.qd_count = 0;

        spin_lock(&qunit_hash_lock);
        qunit = dqacq_in_flight(qctxt, &qdata);
        spin_unlock(&qunit_hash_lock);

        if (qunit) {
                struct qunit_data *p = &qunit->lq_data;

                QDATA_DEBUG(p, "qunit(%p) is waiting for dqacq.\n", qunit);
                l_wait_event(qunit->lq_waitq, got_qunit(qunit, ismaster), &lwi);
                CDEBUG(D_QUOTA, "qunit(%p) finishes waiting. (rc:%d)\n",
                       qunit, qunit->lq_rc);
                /* keep same as schedule_dqacq() b=17030 */
                spin_lock(&qunit->lq_lock);
                rc = qunit->lq_rc;
                spin_unlock(&qunit->lq_lock);
                /* this is for dqacq_in_flight() */
                qunit_put(qunit);
                do_gettimeofday(&work_end);
                timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
                lprocfs_counter_add(qctxt->lqc_stats,
                                    isblk ? LQUOTA_WAIT_PENDING_BLK_QUOTA :
                                            LQUOTA_WAIT_PENDING_INO_QUOTA,
                                    timediff);
        } else {
                do_gettimeofday(&work_end);
                timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
                lprocfs_counter_add(qctxt->lqc_stats,
                                    isblk ? LQUOTA_NOWAIT_PENDING_BLK_QUOTA :
                                            LQUOTA_NOWAIT_PENDING_INO_QUOTA,
                                    timediff);
        }

        RETURN(rc);
}

int
qctxt_init(struct obd_device *obd, dqacq_handler_t handler)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct super_block *sb = obd->u.obt.obt_sb;
        int rc = 0;
        ENTRY;

        LASSERT(qctxt);

        rc = ptlrpcd_addref();
        if (rc)
                RETURN(rc);

        cfs_waitq_init(&qctxt->lqc_wait_for_qmaster);
        cfs_waitq_init(&qctxt->lqc_lqs_waitq);
        atomic_set(&qctxt->lqc_lqs, 0);
        spin_lock_init(&qctxt->lqc_lock);
        spin_lock(&qctxt->lqc_lock);
        qctxt->lqc_handler = handler;
        qctxt->lqc_sb = sb;
        qctxt->lqc_import = NULL;
        qctxt->lqc_recovery = 0;
        qctxt->lqc_switch_qs = 1; /* Change qunit size in default setting */
        qctxt->lqc_valid = 1;
        qctxt->lqc_cqs_boundary_factor = 4;
        qctxt->lqc_cqs_least_bunit = PTLRPC_MAX_BRW_SIZE;
        qctxt->lqc_cqs_least_iunit = 2;
        qctxt->lqc_cqs_qs_factor = 2;
        qctxt->lqc_flags = 0;
        QUOTA_MASTER_UNREADY(qctxt);
        qctxt->lqc_bunit_sz = default_bunit_sz;
        qctxt->lqc_btune_sz = default_bunit_sz / 100 * default_btune_ratio;
        qctxt->lqc_iunit_sz = default_iunit_sz;
        qctxt->lqc_itune_sz = default_iunit_sz * default_itune_ratio / 100;
        qctxt->lqc_switch_seconds = 300; /* enlarging will wait 5 minutes
                                          * after the last shrinking */
        qctxt->lqc_sync_blk = 0;
        spin_unlock(&qctxt->lqc_lock);

        qctxt->lqc_lqs_hash = lustre_hash_init("LQS_HASH",
                                               hash_lqs_cur_bits,
                                               HASH_LQS_MAX_BITS,
                                               &lqs_hash_ops, LH_REHASH);
        if (!qctxt->lqc_lqs_hash)
                CERROR("%s: initialize hash lqs failed\n", obd->obd_name);

#ifdef LPROCFS
        if (lquota_proc_setup(obd, is_master(obd, qctxt, 0, 0)))
                CERROR("%s: initialize proc failed\n", obd->obd_name);
#endif

        RETURN(rc);
}

static int check_lqs(struct lustre_quota_ctxt *qctxt)
{
        int rc;
        ENTRY;

        rc = !atomic_read(&qctxt->lqc_lqs);

        RETURN(rc);
}


void hash_put_lqs(void *obj, void *data)
{
        lqs_putref((struct lustre_qunit_size *)obj);
}

void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force)
{
        struct lustre_qunit *qunit, *tmp;
        struct list_head tmp_list;
        struct l_wait_info lwi = { 0 };
        int i;
        ENTRY;

        INIT_LIST_HEAD(&tmp_list);

        spin_lock(&qctxt->lqc_lock);
        qctxt->lqc_valid = 0;
        spin_unlock(&qctxt->lqc_lock);

        spin_lock(&qunit_hash_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(qunit, tmp, &qunit_hash[i], lq_hash) {
                        if (qunit->lq_ctxt != qctxt)
                                continue;
                        remove_qunit_nolock(qunit);
                        list_add(&qunit->lq_hash, &tmp_list);
                }
        }
        spin_unlock(&qunit_hash_lock);

        list_for_each_entry_safe(qunit, tmp, &tmp_list, lq_hash) {
                list_del_init(&qunit->lq_hash);
                compute_lqs_after_removing_qunit(qunit);

                /* wake up all waiters */
                QUNIT_SET_STATE_AND_RC(qunit, QUNIT_FINISHED, 0);
                wake_up(&qunit->lq_waitq);
                qunit_put(qunit);
        }

        /* after qctxt_cleanup, qctxt might be freed, then check_qm() is
         * unpredicted. So we must wait until lqc_wait_for_qmaster is empty */
        while (cfs_waitq_active(&qctxt->lqc_wait_for_qmaster)) {
                cfs_waitq_signal(&qctxt->lqc_wait_for_qmaster);
                cfs_schedule_timeout(CFS_TASK_INTERRUPTIBLE,
                                     cfs_time_seconds(1));
        }

        lustre_hash_for_each_safe(qctxt->lqc_lqs_hash, hash_put_lqs, NULL);
        l_wait_event(qctxt->lqc_lqs_waitq, check_lqs(qctxt), &lwi);
        lustre_hash_exit(qctxt->lqc_lqs_hash);

        ptlrpcd_decref();

#ifdef LPROCFS
        if (lquota_proc_cleanup(qctxt))
                CERROR("cleanup proc error!\n");
#endif

        EXIT;
}

struct qslave_recov_thread_data {
        struct obd_device *obd;
        struct lustre_quota_ctxt *qctxt;
        struct completion comp;
};

/* FIXME only recovery block quota by now */
static int qslave_recovery_main(void *arg)
{
        struct qslave_recov_thread_data *data = arg;
        struct obd_device *obd = data->obd;
        struct lustre_quota_ctxt *qctxt = data->qctxt;
        unsigned int type;
        int rc = 0;
        ENTRY;

        cfs_daemonize_ctxt("qslave_recovd");

        complete(&data->comp);

        if (qctxt->lqc_recovery)
                RETURN(0);
        qctxt->lqc_recovery = 1;

        for (type = USRQUOTA; type < MAXQUOTAS; type++) {
                struct qunit_data qdata;
                struct quota_info *dqopt = sb_dqopt(qctxt->lqc_sb);
                struct list_head id_list;
                struct dquot_id *dqid, *tmp;
                int ret;

                LOCK_DQONOFF_MUTEX(dqopt);
                if (!ll_sb_has_quota_active(qctxt->lqc_sb, type)) {
                        UNLOCK_DQONOFF_MUTEX(dqopt);
                        break;
                }

                LASSERT(dqopt->files[type] != NULL);
                INIT_LIST_HEAD(&id_list);
#ifndef KERNEL_SUPPORTS_QUOTA_READ
                rc = fsfilt_qids(obd, dqopt->files[type], NULL, type, &id_list);
#else
                rc = fsfilt_qids(obd, NULL, dqopt->files[type], type, &id_list);
#endif
                UNLOCK_DQONOFF_MUTEX(dqopt);
                if (rc)
                        CERROR("Get ids from quota file failed. (rc:%d)\n", rc);

                list_for_each_entry_safe(dqid, tmp, &id_list, di_link) {
                        list_del_init(&dqid->di_link);
                        /* skip slave recovery on itself */
                        if (is_master(obd, qctxt, dqid->di_id, type))
                                goto free;
                        if (rc && rc != -EBUSY)
                                goto free;

                        qdata.qd_id = dqid->di_id;
                        qdata.qd_flags = type;
                        QDATA_SET_BLK(&qdata);
                        qdata.qd_count = 0;

                        ret = check_cur_qunit(obd, qctxt, &qdata);
                        if (ret > 0) {
                                int opc;
                                opc = ret == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                                rc = schedule_dqacq(obd, qctxt, &qdata, opc,
                                                    0, NULL);
                                if (rc == -EDQUOT)
                                        rc = 0;
                        } else {
                                rc = 0;
                        }

                        if (rc && rc != -EBUSY)
                                CERROR("qslave recovery failed! (id:%d type:%d "
                                       " rc:%d)\n", dqid->di_id, type, rc);
free:
                        OBD_FREE_PTR(dqid);
                }
        }

        qctxt->lqc_recovery = 0;
        RETURN(rc);
}

void
qslave_start_recovery(struct obd_device *obd, struct lustre_quota_ctxt *qctxt)
{
        struct qslave_recov_thread_data data;
        int rc;
        ENTRY;

        if (!ll_sb_any_quota_active(qctxt->lqc_sb))
                goto exit;

        data.obd = obd;
        data.qctxt = qctxt;
        init_completion(&data.comp);

        rc = kernel_thread(qslave_recovery_main, &data, CLONE_VM|CLONE_FILES);
        if (rc < 0) {
                CERROR("Cannot start quota recovery thread: rc %d\n", rc);
                goto exit;
        }
        wait_for_completion(&data.comp);
exit:
        EXIT;
}


/*
 * lqs<->qctxt hash operations
 */

/* string hashing using djb2 hash algorithm */
static unsigned
lqs_hash(lustre_hash_t *lh, void *key, unsigned mask)
{
        unsigned long long id;
        unsigned hash;
        ENTRY;

        LASSERT(key);
        id = *((unsigned long long *)key);
        hash = (LQS_KEY_GRP(id) ? 5381 : 5387) * (unsigned)LQS_KEY_ID(id);

        RETURN(hash & mask);
}

static void *
lqs_key(struct hlist_node *hnode)
{
        struct lustre_qunit_size *lqs;
        ENTRY;

        lqs = hlist_entry(hnode, struct lustre_qunit_size, lqs_hash);
        RETURN(&lqs->lqs_key);
}

static int
lqs_compare(void *key, struct hlist_node *hnode)
{
        struct lustre_qunit_size *q =
            hlist_entry(hnode, struct lustre_qunit_size, lqs_hash);

        RETURN(q->lqs_key == *((unsigned long long *)key));
}

static void *
lqs_get(struct hlist_node *hnode)
{
        struct lustre_qunit_size *q =
            hlist_entry(hnode, struct lustre_qunit_size, lqs_hash);
        ENTRY;

        lqs_getref(q);

        RETURN(q);
}

static void *
lqs_put(struct hlist_node *hnode)
{
        struct lustre_qunit_size *q =
            hlist_entry(hnode, struct lustre_qunit_size, lqs_hash);
        ENTRY;

        lqs_putref(q);

        RETURN(q);
}

static void
lqs_exit(struct hlist_node *hnode)
{
        struct lustre_qunit_size *q;
        ENTRY;

        q = hlist_entry(hnode, struct lustre_qunit_size, lqs_hash);
        /*
         * Nothing should be left. User of lqs put it and
         * lqs also was deleted from table by this time
         * so we should have 0 refs.
         */
        LASSERTF(atomic_read(&q->lqs_refcount) == 0,
                 "Busy lqs %p with %d refs\n", q,
                 atomic_read(&q->lqs_refcount));
        OBD_FREE_PTR(q);
        EXIT;
}

static lustre_hash_ops_t lqs_hash_ops = {
        .lh_hash    = lqs_hash,
        .lh_key     = lqs_key,
        .lh_compare = lqs_compare,
        .lh_get     = lqs_get,
        .lh_put     = lqs_put,
        .lh_exit    = lqs_exit
};
#endif /* HAVE_QUOTA_SUPPORT */
