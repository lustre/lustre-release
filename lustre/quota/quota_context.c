/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/quota/quota_context.c
 *  Lustre Quota Context
 *
 *  Copyright (c) 2001-2005 Cluster File Systems, Inc.
 *   Author: Niu YaWei <niu@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   No redistribution or use is permitted outside of Cluster File Systems, Inc.
 *
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_MDS

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
#include "quota_internal.h"

extern struct lustre_hash_operations lqs_hash_operations;

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
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(1, 7, 0, 0)
        if (imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_QUOTA64 &&
            !OBD_FAIL_CHECK(OBD_FAIL_QUOTA_QD_COUNT_32BIT))
#else
        if (imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_QUOTA64)
#endif
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

        if (!sb_any_quota_enabled(sb))
                RETURN(0);

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

 search_lqs:
        quota_search_lqs(qdata, NULL, qctxt, &lqs);
        if (!lqs) {
                CDEBUG(D_QUOTA, "Can't find the lustre qunit size!\n");
                ret = quota_create_lqs(qdata, NULL, qctxt, &lqs);
                if (ret == -EALREADY) {
                        ret = 0;
                        goto search_lqs;
                }
                if (ret < 0)
                        GOTO (out, ret);
        }
        spin_lock(&lqs->lqs_lock);

        if (QDATA_IS_BLK(qdata)) {
                qunit_sz = lqs->lqs_bunit_sz;
                tune_sz  = lqs->lqs_btune_sz;
                pending_write = lqs->lqs_bwrite_pending * CFS_PAGE_SIZE;
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
        if (limit + record < 0)
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
        }
        CDEBUG(D_QUOTA, "type: %c, limit: "LPU64", usage: "LPU64
               ", pending_write: "LPU64", record: "LPD64
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

        if (!sb_any_quota_enabled(sb))
                RETURN(QUOTA_RET_NOQUOTA);

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

/* caller must hold qunit_hash_lock */
static struct lustre_qunit *dqacq_in_flight(struct lustre_quota_ctxt *qctxt,
                                            struct qunit_data *qdata)
{
        unsigned int hashent = qunit_hashfn(qctxt, qdata);
        struct lustre_qunit *qunit;
        ENTRY;

        LASSERT_SPIN_LOCKED(&qunit_hash_lock);
        qunit = find_qunit(hashent, qctxt, qdata);
        RETURN(qunit);
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

static void
insert_qunit_nolock(struct lustre_quota_ctxt *qctxt, struct lustre_qunit *qunit)
{
        struct list_head *head;

        LASSERT(list_empty(&qunit->lq_hash));
        head = qunit_hash + qunit_hashfn(qctxt, &qunit->lq_data);
        list_add(&qunit->lq_hash, head);
        QUNIT_SET_STATE(qunit, QUNIT_IN_HASH);
}

static void compute_lqs_after_removing_qunit(struct lustre_qunit *qunit)
{
        struct lustre_qunit_size *lqs = NULL;

        quota_search_lqs(&qunit->lq_data, NULL, qunit->lq_ctxt, &lqs);
        if (lqs) {
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
               struct qunit_data *qdata, int opc, int wait);

static int split_before_schedule_dqacq(struct obd_device *obd,
                                       struct lustre_quota_ctxt *qctxt,
                                       struct qunit_data *qdata, int opc, int wait)
{
        int rc = 0;
        unsigned long factor;
        struct qunit_data tmp_qdata;
        ENTRY;

        LASSERT(qdata && qdata->qd_count);
        QDATA_DEBUG(qdata, "%s quota split.\n",
                    QDATA_IS_BLK(qdata) ? "block" : "inode");
        if (QDATA_IS_BLK(qdata))
                factor = MAX_QUOTA_COUNT32 / qctxt->lqc_bunit_sz *
                        qctxt->lqc_bunit_sz;
        else
                factor = MAX_QUOTA_COUNT32 / qctxt->lqc_iunit_sz *
                        qctxt->lqc_iunit_sz;

        if (qctxt->lqc_import && should_translate_quota(qctxt->lqc_import) &&
            qdata->qd_count > factor) {
                tmp_qdata = *qdata;
                tmp_qdata.qd_count = factor;
                qdata->qd_count -= tmp_qdata.qd_count;
                QDATA_DEBUG((&tmp_qdata), "be split.\n");
                rc = schedule_dqacq(obd, qctxt, &tmp_qdata, opc, wait);
        } else{
                QDATA_DEBUG(qdata, "don't be split.\n");
                rc = schedule_dqacq(obd, qctxt, qdata, opc, wait);
        }

        RETURN(rc);
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
                switch (opc) {
                case QUOTA_DQACQ:
                        INC_QLIMIT(*hardlimit, count);
                        break;
                case QUOTA_DQREL:
                        LASSERTF(count < *hardlimit,
                                 "count: "LPU64", hardlimit: "LPU64".\n",
                                 count, *hardlimit);
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

        /* wake up all waiters */
        QUNIT_SET_STATE_AND_RC(qunit, QUNIT_FINISHED, rc);
        wake_up(&qunit->lq_waitq);

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
         if (err || (rc && rc != -EBUSY && rc1 == 0) ||
             is_master(obd, qctxt, qdata->qd_id, QDATA_IS_GRP(qdata)))
                RETURN(err);

        /* reschedule another dqacq/dqrel if needed */
        qdata->qd_count = 0;
        qdata->qd_flags &= LQUOTA_QUNIT_FLAGS;
        rc1 = check_cur_qunit(obd, qctxt, qdata);
        if (rc1 > 0) {
                int opc;
                opc = rc1 == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                rc1 = split_before_schedule_dqacq(obd, qctxt, qdata, opc, 0);
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

        if (rc == -EIO || rc == -EINTR || rc == -ENOTCONN )
                /* if a quota req timeouts or is dropped, we should update quota
                 * statistics which will be handled in dqacq_completion. And in
                 * this situation we should get qdata from request instead of
                 * reply */
                rc1 = quota_get_qdata(req, qdata, QUOTA_REQUEST, QUOTA_IMPORT);
        else
                rc1 = quota_get_qdata(req, qdata, QUOTA_REPLY, QUOTA_IMPORT);
        if (rc1 < 0) {
                DEBUG_REQ(D_ERROR, req, "error unpacking qunit_data\n");
                GOTO(exit, rc = -EPROTO);
        }

        QDATA_DEBUG(qdata, "qdata: interpret rc(%d).\n", rc);
        QDATA_DEBUG((&qunit->lq_data), "lq_data: \n");

        if (qdata->qd_id != qunit->lq_data.qd_id ||
            OBD_FAIL_CHECK_ONCE(OBD_FAIL_QUOTA_RET_QDATA)) {
                CDEBUG(D_ERROR, "the returned qd_id isn't expected!"
                       "(qdata: %u, lq_data: %u)\n", qdata->qd_id,
                       qunit->lq_data.qd_id);
                qdata->qd_id = qunit->lq_data.qd_id;
                rc = -EPROTO;
        }
        if (QDATA_IS_GRP(qdata) != QDATA_IS_GRP(&qunit->lq_data)) {
                CDEBUG(D_ERROR, "the returned grp/usr isn't expected!"
                       "(qdata: %u, lq_data: %u)\n", qdata->qd_flags,
                       qunit->lq_data.qd_flags);
                if (QDATA_IS_GRP(&qunit->lq_data))
                        QDATA_SET_GRP(qdata);
                else
                        QDATA_CLR_GRP(qdata);
                rc = -EPROTO;
        }
        if (qdata->qd_count > qunit->lq_data.qd_count) {
                CDEBUG(D_ERROR, "the returned qd_count isn't expected!"
                       "(qdata: "LPU64", lq_data: "LPU64")\n", qdata->qd_count,
                       qunit->lq_data.qd_count);
                rc = -EPROTO;
        }

        rc = dqacq_completion(obd, qctxt, qdata, rc,
                              lustre_msg_get_opc(req->rq_reqmsg));

exit:
        OBD_FREE(qdata, sizeof(struct qunit_data));

        RETURN(rc);
}

static int got_qunit(struct lustre_qunit *qunit)
{
        int rc;
        ENTRY;

        spin_lock(&qunit->lq_lock);
        switch (qunit->lq_state) {
        case QUNIT_IN_HASH:
        case QUNIT_RM_FROM_HASH:
                rc = 0;
                break;
        case QUNIT_FINISHED:
                rc = 1;
                break;
        default:
                rc = 0;
                CERROR("invalid qunit state %d\n", qunit->lq_state);
        }
        spin_unlock(&qunit->lq_lock);
        RETURN(rc);
}

static int
schedule_dqacq(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
               struct qunit_data *qdata, int opc, int wait)
{
        struct lustre_qunit *qunit, *empty;
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_request *req;
        struct dqacq_async_args *aa;
        int size[2] = { sizeof(struct ptlrpc_body), 0 };
        struct obd_import *imp = NULL;
        unsigned long factor;
        struct lustre_qunit_size *lqs = NULL;
        int rc = 0;
        ENTRY;

        if ((empty = alloc_qunit(qctxt, qdata, opc)) == NULL)
                RETURN(-ENOMEM);

        spin_lock(&qunit_hash_lock);
        qunit = dqacq_in_flight(qctxt, qdata);
        if (qunit) {
                if (wait)
                        qunit_get(qunit);
                spin_unlock(&qunit_hash_lock);
                free_qunit(empty);

                goto wait_completion;
        }
        qunit = empty;
        insert_qunit_nolock(qctxt, qunit);
        spin_unlock(&qunit_hash_lock);

        LASSERT(qunit);

        quota_search_lqs(qdata, NULL, qctxt, &lqs);
        if (lqs) {
                spin_lock(&lqs->lqs_lock);
                quota_compute_lqs(qdata, lqs, 1, (opc == QUOTA_DQACQ) ? 1 : 0);
                /* when this qdata returned from mds, it will call lqs_putref */
                lqs_getref(lqs);
                spin_unlock(&lqs->lqs_lock);
                /* this is for quota_search_lqs */
                lqs_putref(lqs);
        } else {
                CDEBUG(D_ERROR, "Can't find the lustre qunit size!\n");
        }

        QDATA_DEBUG(qdata, "obd(%s): send %s quota req\n",
                    obd->obd_name, (opc == QUOTA_DQACQ) ? "acq" : "rel");
        /* master is going to dqacq/dqrel from itself */
        if (is_master(obd, qctxt, qdata->qd_id, QDATA_IS_GRP(qdata))) {
                int rc2;
                QDATA_DEBUG(qdata, "local %s.\n",
                            opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
                QDATA_SET_CHANGE_QS(qdata);
                rc = qctxt->lqc_handler(obd, qdata, opc);
                rc2 = dqacq_completion(obd, qctxt, qdata, rc, opc);
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

                qunit_put(qunit);
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
                RETURN(-ENOMEM);
        }

        if (QDATA_IS_BLK(qdata))
                factor = MAX_QUOTA_COUNT32 / qctxt->lqc_bunit_sz *
                        qctxt->lqc_bunit_sz;
        else
                factor = MAX_QUOTA_COUNT32 / qctxt->lqc_iunit_sz *
                        qctxt->lqc_iunit_sz;

        LASSERTF(!should_translate_quota(imp) || qdata->qd_count <= factor,
                 "qd_count: "LPU64"; should_translate_quota: %d.\n",
                 qdata->qd_count, should_translate_quota(imp));
        rc = quota_copy_qdata(req, qdata, QUOTA_REQUEST, QUOTA_IMPORT);
        if (rc < 0) {
                CDEBUG(D_ERROR, "Can't pack qunit_data\n");
                RETURN(-EPROTO);
        }
        ptlrpc_req_set_repsize(req, 2, size);
        class_import_put(imp);

        if (wait && qunit) 
                qunit_get(qunit);

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = (struct dqacq_async_args *)&req->rq_async_args;
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
                l_wait_event(qunit->lq_waitq, got_qunit(qunit), &lwi);
                /* rc = -EAGAIN, it means a quota req is finished;
                 * rc = -EDQUOT, it means out of quota
                 * rc = -EBUSY, it means recovery is happening
                 * other rc < 0, it means real errors, functions who call
                 * schedule_dqacq should take care of this */
                spin_lock(&qunit->lq_lock);
                if (qunit->lq_rc == 0)
                        rc = -EAGAIN;
                else
                        rc = qunit->lq_rc;
                spin_unlock(&qunit->lq_lock);
                CDEBUG(D_QUOTA, "qunit(%p) finishes waiting. (rc:%d)\n",
                       qunit, rc);
                qunit_put(qunit);
        }
        RETURN(rc);
}

int
qctxt_adjust_qunit(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                   uid_t uid, gid_t gid, __u32 isblk, int wait)
{
        int ret, rc = 0, i = USRQUOTA;
        __u32 id[MAXQUOTAS] = { uid, gid };
        struct qunit_data qdata[MAXQUOTAS];
        ENTRY;

        CLASSERT(MAXQUOTAS < 4);
        if (!sb_any_quota_enabled(qctxt->lqc_sb))
                RETURN(0);

        for (i = 0; i < MAXQUOTAS; i++) {
                qdata[i].qd_id = id[i];
                qdata[i].qd_flags = i;
                if (isblk)
                        QDATA_SET_BLK(&qdata[i]);
                qdata[i].qd_count = 0;

                ret = check_cur_qunit(obd, qctxt, &qdata[i]);
                if (ret > 0) {
                        int opc;
                        /* need acquire or release */
                        opc = ret == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                        ret = split_before_schedule_dqacq(obd, qctxt, &qdata[i], 
                                                          opc, wait);
                        if (!rc)
                                rc = ret;
                } else if (wait == 1) {
                        /* when wait equates 1, that means mds_quota_acquire
                         * or filter_quota_acquire is calling it. */
                        qctxt_wait_pending_dqacq(qctxt, id[i], i, isblk);
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
        struct l_wait_info lwi = { 0 };
        ENTRY;

        qdata.qd_id = id;
        qdata.qd_flags = type;
        if (isblk)
                QDATA_SET_BLK(&qdata);
        qdata.qd_count = 0;

        spin_lock(&qunit_hash_lock);
        qunit = dqacq_in_flight(qctxt, &qdata);
        if (qunit)
                /* grab reference on this qunit to handle races with
                 * dqacq_completion(). Otherwise, this qunit could be freed just
                 * after we release the qunit_hash_lock */
                qunit_get(qunit);
        spin_unlock(&qunit_hash_lock);

        if (qunit) {
                struct qunit_data *p = &qunit->lq_data;

                QDATA_DEBUG(p, "qunit(%p) is waiting for dqacq.\n", qunit);
                l_wait_event(qunit->lq_waitq, got_qunit(qunit), &lwi);
                CDEBUG(D_QUOTA, "qunit(%p) finishes waiting. (rc:%d)\n",
                       qunit, qunit->lq_rc);
                qunit_put(qunit);
        }
        RETURN(0);
}

int
qctxt_init(struct lustre_quota_ctxt *qctxt, struct super_block *sb,
           dqacq_handler_t handler)
{
        int rc = 0;
        ENTRY;

        LASSERT(qctxt);

        rc = ptlrpcd_addref();
        if (rc)
                RETURN(rc);

        spin_lock_init(&qctxt->lqc_lock);
        spin_lock(&qctxt->lqc_lock);
        qctxt->lqc_handler = handler;
        qctxt->lqc_sb = sb;
        qctxt->lqc_import = NULL;
        qctxt->lqc_recovery = 0;
        qctxt->lqc_switch_qs = 1; /* Change qunit size in default setting */
        qctxt->lqc_cqs_boundary_factor = 4;
        qctxt->lqc_cqs_least_bunit = PTLRPC_MAX_BRW_SIZE;
        qctxt->lqc_cqs_least_iunit = 2;
        qctxt->lqc_cqs_qs_factor = 2;
        qctxt->lqc_atype = 0;
        qctxt->lqc_status= 0;
        qctxt->lqc_bunit_sz = default_bunit_sz;
        qctxt->lqc_btune_sz = default_bunit_sz / 100 * default_btune_ratio;
        qctxt->lqc_iunit_sz = default_iunit_sz;
        qctxt->lqc_itune_sz = default_iunit_sz * default_itune_ratio / 100;
        qctxt->lqc_switch_seconds = 300; /* enlarging will wait 5 minutes
                                          * after the last shrinking */
        rc = lustre_hash_init(&LQC_HASH_BODY(qctxt), "LQS_HASH",128,
                              &lqs_hash_operations);
        if (rc) {
                CDEBUG(D_ERROR, "initialize hash lqs on ost error!\n");
                lustre_hash_exit(&LQC_HASH_BODY(qctxt));
        }
        spin_unlock(&qctxt->lqc_lock);

        RETURN(rc);
}

void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force)
{
        struct lustre_qunit *qunit, *tmp;
        struct list_head tmp_list;
        int i;
        ENTRY;

        INIT_LIST_HEAD(&tmp_list);

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

        lustre_hash_exit(&LQC_HASH_BODY(qctxt));
        ptlrpcd_decref();

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

        ptlrpc_daemonize("qslave_recovd");

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
                if (!sb_has_quota_enabled(qctxt->lqc_sb, type)) {
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
                                rc = split_before_schedule_dqacq(obd, qctxt,
                                                                 &qdata, opc,
                                                                 0);
                                if (rc == -EDQUOT)
                                        rc = 0;
                        } else {
                                rc = 0;
                        }

                        if (rc)
                                CDEBUG(rc == -EBUSY ? D_QUOTA : D_ERROR,
                                       "qslave recovery failed! (id:%d type:%d "
                                       " rc:%d)\n", dqid->di_id, type, rc);
free:
                        kfree(dqid);
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

        if (!sb_any_quota_enabled(qctxt->lqc_sb))
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

