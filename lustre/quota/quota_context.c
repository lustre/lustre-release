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
#include "quota_internal.h"

unsigned long default_bunit_sz = 100 * 1024 * 1024;       /* 100M bytes */
unsigned long default_btune_ratio = 50;                   /* 50 percentage */
unsigned long default_iunit_sz = 5000;       /* 5000 inodes */
unsigned long default_itune_ratio = 50;      /* 50 percentage */

cfs_mem_cache_t *qunit_cachep = NULL;
struct list_head qunit_hash[NR_DQHASH];
spinlock_t qunit_hash_lock = SPIN_LOCK_UNLOCKED;

struct lustre_qunit {
        struct list_head lq_hash;               /* Hash list in memory */
        atomic_t lq_refcnt;                     /* Use count */
        struct lustre_quota_ctxt *lq_ctxt;      /* Quota context this applies to */
        struct qunit_data lq_data;              /* See qunit_data */
        unsigned int lq_opc;                    /* QUOTA_DQACQ, QUOTA_DQREL */
        struct list_head lq_waiters;            /* All write threads waiting for this qunit */
};

int should_translate_quota (struct obd_import *imp)
{
        ENTRY;

        LASSERT(imp);
        if ((imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_QUOTA64) &&
            !OBD_FAIL_CHECK(OBD_FAIL_QUOTA_QD_COUNT_32BIT))
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
                LASSERTF(rc == 0, "couldn't destroy qunit_cache slab\n");
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
                CFS_INIT_LIST_HEAD(qunit_hash + i);
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
        unsigned int type = qdata->qd_flags & QUOTA_IS_GRP;

        unsigned long tmp = ((unsigned long)qctxt >> L1_CACHE_SHIFT) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

/* compute the remaining quota for certain gid or uid b=11693 */
int compute_remquota(struct obd_device *obd,
                     struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata)
{
        struct super_block *sb = qctxt->lqc_sb;
        __u64 usage, limit;
        struct obd_quotactl *qctl;
        int ret = QUOTA_RET_OK;
        __u32 qdata_type = qdata->qd_flags & QUOTA_IS_GRP;
        ENTRY;

        if (!sb_any_quota_enabled(sb))
                RETURN(QUOTA_RET_NOQUOTA);

        /* ignore root user */
        if (qdata->qd_id == 0 && qdata_type == USRQUOTA)
                RETURN(QUOTA_RET_NOLIMIT);

        OBD_ALLOC_PTR(qctl);
        if (qctl == NULL)
                RETURN(-ENOMEM);

        /* get fs quota usage & limit */
        qctl->qc_cmd = Q_GETQUOTA;
        qctl->qc_id = qdata->qd_id;
        qctl->qc_type = qdata_type;
        ret = fsfilt_quotactl(obd, sb, qctl);
        if (ret) {
                if (ret == -ESRCH)      /* no limit */
                        ret = QUOTA_RET_NOLIMIT;
                else
                        CDEBUG(D_QUOTA, "can't get fs quota usage! (rc:%d)",
                               ret);
                GOTO(out, ret);
        }

        usage = qctl->qc_dqblk.dqb_curspace;
        limit = qctl->qc_dqblk.dqb_bhardlimit << QUOTABLOCK_BITS;
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
                    qdata->qd_id == tmp->qd_id && qdata->qd_flags == tmp->qd_flags)
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
        __u64 usage, limit;
        struct obd_quotactl *qctl;
        int ret = 0;
        __u32 qdata_type = qdata->qd_flags & QUOTA_IS_GRP;
        __u32 is_blk = (qdata->qd_flags & QUOTA_IS_BLOCK) >> 1;
        ENTRY;

        if (!sb_any_quota_enabled(sb))
                RETURN(0);

        OBD_ALLOC_PTR(qctl);
        if (qctl == NULL)
                RETURN(-ENOMEM);

        /* get fs quota usage & limit */
        qctl->qc_cmd = Q_GETQUOTA;
        qctl->qc_id = qdata->qd_id;
        qctl->qc_type = qdata_type;
        ret = fsfilt_quotactl(obd, sb, qctl);
        if (ret) {
                if (ret == -ESRCH)      /* no limit */
                        ret = 0;
                else
                        CERROR("can't get fs quota usage! (rc:%d)\n", ret);
                GOTO(out, ret);
        }

        if (is_blk) {
                usage = qctl->qc_dqblk.dqb_curspace;
                limit = qctl->qc_dqblk.dqb_bhardlimit << QUOTABLOCK_BITS;
                qunit_sz = qctxt->lqc_bunit_sz;
                tune_sz = qctxt->lqc_btune_sz;

                LASSERT(!(qunit_sz % QUOTABLOCK_SIZE));
        } else {
                usage = qctl->qc_dqblk.dqb_curinodes;
                limit = qctl->qc_dqblk.dqb_ihardlimit;
                qunit_sz = qctxt->lqc_iunit_sz;
                tune_sz = qctxt->lqc_itune_sz;
        }

        /* ignore the no quota limit case */
        if (!limit)
                GOTO(out, ret = 0);

        /* we don't count the MIN_QLIMIT */
        if ((limit == MIN_QLIMIT && !is_blk) ||
            (toqb(limit) == MIN_QLIMIT && is_blk))
                limit = 0;

        LASSERT(qdata->qd_count == 0);
        if (limit <= usage + tune_sz) {
                while (qdata->qd_count + limit <= usage + tune_sz)
                        qdata->qd_count += qunit_sz;
                ret = 1;
        } else if (limit > usage + qunit_sz + tune_sz) {
                while (limit - qdata->qd_count > usage + qunit_sz + tune_sz)
                        qdata->qd_count += qunit_sz;
                ret = 2;
        }
        LASSERT(ret == 0 || qdata->qd_count);
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

        CFS_INIT_LIST_HEAD(&qunit->lq_hash);
        CFS_INIT_LIST_HEAD(&qunit->lq_waiters);
        atomic_set(&qunit->lq_refcnt, 1);
        qunit->lq_ctxt = qctxt;
        memcpy(&qunit->lq_data, qdata, sizeof(*qdata));
        qunit->lq_opc = opc;

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
}

static void remove_qunit_nolock(struct lustre_qunit *qunit)
{
        LASSERT(!list_empty(&qunit->lq_hash));
        list_del_init(&qunit->lq_hash);
}

struct qunit_waiter {
        struct list_head qw_entry;
        cfs_waitq_t      qw_waitq;
        int qw_rc;
};

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

static int split_before_schedule_dqacq(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                                       struct qunit_data *qdata, int opc, int wait)
{
        int rc = 0;
        unsigned long factor;
        struct qunit_data tmp_qdata;
        ENTRY;

        LASSERT(qdata && qdata->qd_count);
        QDATA_DEBUG(qdata, "%s quota split.\n",
                    (qdata->qd_flags & QUOTA_IS_BLOCK) ? "block" : "inode");
        if (qdata->qd_flags & QUOTA_IS_BLOCK)
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
dqacq_completion(struct obd_device *obd,
                 struct lustre_quota_ctxt *qctxt,
                 struct qunit_data *qdata, int rc, int opc)
{
        struct lustre_qunit *qunit = NULL;
        struct super_block *sb = qctxt->lqc_sb;
        unsigned long qunit_sz;
        struct qunit_waiter *qw, *tmp;
        int err = 0;
        __u32 qdata_type = qdata->qd_flags & QUOTA_IS_GRP;
        __u32 is_blk = (qdata->qd_flags & QUOTA_IS_BLOCK) >> 1;
        __u64 qd_tmp = qdata->qd_count;
        unsigned long div_r;
        ENTRY;

        LASSERT(qdata);
        qunit_sz = is_blk ? qctxt->lqc_bunit_sz : qctxt->lqc_iunit_sz;
        div_r = do_div(qd_tmp, qunit_sz);
        LASSERTF(!div_r, "qunit_sz: %lu, return qunit_sz: "LPU64"\n",
                 qunit_sz, qd_tmp);

        /* update local operational quota file */
        if (rc == 0) {
                __u32 count = QUSG(qdata->qd_count, is_blk);
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
                qctl->qc_type = qdata_type;
                err = fsfilt_quotactl(obd, sb, qctl);
                if (err) {
                        CERROR("error get quota fs limit! (rc:%d)\n", err);
                        GOTO(out_mem, err);
                }

                if (is_blk) {
                        qctl->qc_dqblk.dqb_valid = QIF_BLIMITS;
                        hardlimit = &qctl->qc_dqblk.dqb_bhardlimit;
                } else {
                        qctl->qc_dqblk.dqb_valid = QIF_ILIMITS;
                        hardlimit = &qctl->qc_dqblk.dqb_ihardlimit;
                }

                switch (opc) {
                case QUOTA_DQACQ:
                        CDEBUG(D_QUOTA, "%s(acq):count: %d, hardlimt: "LPU64
                               ",type: %s.\n", obd->obd_name, count, *hardlimit,
                               qdata_type ? "grp": "usr");
                        INC_QLIMIT(*hardlimit, count);
                        break;
                case QUOTA_DQREL:
                        CDEBUG(D_QUOTA, "%s(rel):count: %d, hardlimt: "LPU64
                               ",type: %s.\n", obd->obd_name, count, *hardlimit,
                               qdata_type ? "grp": "usr");
                        LASSERTF(count < *hardlimit,
                                 "count: %d, hardlimit: "LPU64".\n",
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
                RETURN(err);
        }

        LASSERT(opc == qunit->lq_opc);
        remove_qunit_nolock(qunit);

        /* wake up all waiters */
        list_for_each_entry_safe(qw, tmp, &qunit->lq_waiters, qw_entry) {
                list_del_init(&qw->qw_entry);
                qw->qw_rc = rc;
                wake_up(&qw->qw_waitq);
        }

        spin_unlock(&qunit_hash_lock);

        qunit_put(qunit);

        /* don't reschedule in such cases:
         *   - acq/rel failure, but not for quota recovery.
         *   - local dqacq/dqrel.
         *   - local disk io failure.
         */
        if (err || (rc && rc != -EBUSY) ||
            is_master(obd, qctxt, qdata->qd_id, qdata_type))
                RETURN(err);

        /* reschedule another dqacq/dqrel if needed */
        qdata->qd_count = 0;
        rc = check_cur_qunit(obd, qctxt, qdata);
        if (rc > 0) {
                int opc;
                opc = rc == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                rc = split_before_schedule_dqacq(obd, qctxt, qdata, opc, 0);
                QDATA_DEBUG(qdata, "reschedudle opc(%d) rc(%d)\n", opc, rc);
        }
        RETURN(err);
}

struct dqacq_async_args {
        struct lustre_quota_ctxt *aa_ctxt;
        struct lustre_qunit *aa_qunit;
};

static int dqacq_interpret(const struct lu_env *env,
                           struct ptlrpc_request *req, void *data, int rc)
{
        struct dqacq_async_args *aa = (struct dqacq_async_args *)data;
        struct lustre_quota_ctxt *qctxt = aa->aa_ctxt;
        struct lustre_qunit *qunit = aa->aa_qunit;
        struct obd_device *obd = req->rq_import->imp_obd;
        struct qunit_data *qdata = NULL;
        struct qunit_data_old *qdata_old = NULL;
        ENTRY;

        LASSERT(req);
        LASSERT(req->rq_import);

        if ((req->rq_import->imp_connect_data.ocd_connect_flags &
             OBD_CONNECT_QUOTA64) &&
            !OBD_FAIL_CHECK(OBD_FAIL_QUOTA_QD_COUNT_32BIT)) {
                CDEBUG(D_QUOTA, "qd_count is 64bit!\n");

                qdata = req_capsule_server_swab_get(&req->rq_pill,
                                                    &RMF_QUNIT_DATA,
                                          (void*)lustre_swab_qdata);
        } else {
                CDEBUG(D_QUOTA, "qd_count is 32bit!\n");

                qdata = req_capsule_server_swab_get(&req->rq_pill,
                                                    &RMF_QUNIT_DATA,
                                       (void*)lustre_swab_qdata_old);
                qdata = lustre_quota_old_to_new(qdata_old);
        }
        if (qdata == NULL) {
                DEBUG_REQ(D_ERROR, req, "error unpacking qunit_data");
                RETURN(-EPROTO);
        }

        LASSERT(qdata->qd_id == qunit->lq_data.qd_id &&
                (qdata->qd_flags & QUOTA_IS_GRP) ==
                 (qunit->lq_data.qd_flags & QUOTA_IS_GRP) &&
                (qdata->qd_count == qunit->lq_data.qd_count ||
                 qdata->qd_count == 0));

        QDATA_DEBUG(qdata, "%s interpret rc(%d).\n",
                    lustre_msg_get_opc(req->rq_reqmsg) == QUOTA_DQACQ ?
                    "DQACQ" : "DQREL", rc);

        rc = dqacq_completion(obd, qctxt, qdata, rc,
                              lustre_msg_get_opc(req->rq_reqmsg));

        RETURN(rc);
}

static int got_qunit(struct qunit_waiter *waiter)
{
        int rc = 0;
        ENTRY;
        spin_lock(&qunit_hash_lock);
        rc = list_empty(&waiter->qw_entry);
        spin_unlock(&qunit_hash_lock);
        RETURN(rc);
}

static int
schedule_dqacq(struct obd_device *obd,
               struct lustre_quota_ctxt *qctxt,
               struct qunit_data *qdata, int opc, int wait)
{
        struct lustre_qunit *qunit, *empty;
        struct qunit_waiter qw;
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_request *req;
        struct qunit_data *reqdata;
        struct dqacq_async_args *aa;
	unsigned long factor;	
        int rc = 0;
        ENTRY;

        CFS_INIT_LIST_HEAD(&qw.qw_entry);
        init_waitqueue_head(&qw.qw_waitq);
        qw.qw_rc = 0;

        if ((empty = alloc_qunit(qctxt, qdata, opc)) == NULL)
                RETURN(-ENOMEM);

        spin_lock(&qunit_hash_lock);

        qunit = dqacq_in_flight(qctxt, qdata);
        if (qunit) {
                if (wait)
                        list_add_tail(&qw.qw_entry, &qunit->lq_waiters);
                spin_unlock(&qunit_hash_lock);

                free_qunit(empty);
                goto wait_completion;
        }
        qunit = empty;
        insert_qunit_nolock(qctxt, qunit);
        if (wait)
                list_add_tail(&qw.qw_entry, &qunit->lq_waiters);
        spin_unlock(&qunit_hash_lock);

        LASSERT(qunit);

        /* master is going to dqacq/dqrel from itself */
        if (is_master(obd, qctxt, qdata->qd_id, qdata->qd_flags & QUOTA_IS_GRP))
        {
                int rc2;
                QDATA_DEBUG(qdata, "local %s.\n",
                            opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
                rc = qctxt->lqc_handler(obd, qdata, opc);
                rc2 = dqacq_completion(obd, qctxt, qdata, rc, opc);
                RETURN((rc && rc != -EDQUOT) ? rc : rc2);
        }

        /* build dqacq/dqrel request */
        LASSERT(qctxt->lqc_import);

        req = ptlrpc_request_alloc_pack(qctxt->lqc_import, &RQF_MDS_QUOTA_DQACQ,
                                        LUSTRE_MDS_VERSION, opc);
        if (req == NULL) {
                dqacq_completion(obd, qctxt, qdata, -ENOMEM, opc);
                RETURN(-ENOMEM);
        }

	if (qdata->qd_flags & QUOTA_IS_BLOCK)
	        factor = MAX_QUOTA_COUNT32 / qctxt->lqc_bunit_sz *
                         qctxt->lqc_bunit_sz;
        else
                factor = MAX_QUOTA_COUNT32 / qctxt->lqc_iunit_sz *
                         qctxt->lqc_iunit_sz;

        LASSERT(!should_translate_quota(qctxt->lqc_import) ||
                qdata->qd_count <= factor);
        if (should_translate_quota(qctxt->lqc_import))
        {
                struct qunit_data_old *reqdata_old, *tmp;

                reqdata_old = req_capsule_client_get(&req->rq_pill,
                                                     &RMF_QUNIT_DATA);

                tmp = lustre_quota_new_to_old(qdata);
                *reqdata_old = *tmp;
                req_capsule_set_size(&req->rq_pill, &RMF_QUNIT_DATA, RCL_SERVER,
                                     sizeof(*reqdata_old));
                CDEBUG(D_QUOTA, "qd_count is 32bit!\n");
        } else {
                reqdata = req_capsule_client_get(&req->rq_pill,
                                                 &RMF_QUNIT_DATA);

                *reqdata = *qdata;
                req_capsule_set_size(&req->rq_pill, &RMF_QUNIT_DATA, RCL_SERVER,
                                     sizeof(*reqdata));
                CDEBUG(D_QUOTA, "qd_count is 64bit!\n");
        }
        ptlrpc_request_set_replen(req);

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = (struct dqacq_async_args *)&req->rq_async_args;
        aa->aa_ctxt = qctxt;
        aa->aa_qunit = qunit;

        req->rq_interpret_reply = dqacq_interpret;
        ptlrpcd_add_req(req, PSCOPE_OTHER);

        QDATA_DEBUG(qdata, "%s scheduled.\n",
                    opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
wait_completion:
        if (wait && qunit) {
                struct qunit_data *p = &qunit->lq_data;
                QDATA_DEBUG(p, "wait for dqacq.\n");

                l_wait_event(qw.qw_waitq, got_qunit(&qw), &lwi);
                if (qw.qw_rc == 0)
                        rc = -EAGAIN;

                CDEBUG(D_QUOTA, "wait dqacq done. (rc:%d)\n", qw.qw_rc);
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
                qdata[i].qd_flags = 0;
                qdata[i].qd_flags |= i;
                qdata[i].qd_flags |= isblk ? QUOTA_IS_BLOCK : 0;
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
                }
        }

        RETURN(rc);
}

int
qctxt_wait_pending_dqacq(struct lustre_quota_ctxt *qctxt, unsigned int id,
                         unsigned short type, int isblk)
{
        struct lustre_qunit *qunit = NULL;
        struct qunit_waiter qw;
        struct qunit_data qdata;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        CFS_INIT_LIST_HEAD(&qw.qw_entry);
        init_waitqueue_head(&qw.qw_waitq);
        qw.qw_rc = 0;

        qdata.qd_id = id;
        qdata.qd_flags = 0;
        qdata.qd_flags |= type;
        qdata.qd_flags |= isblk ? QUOTA_IS_BLOCK : 0;
        qdata.qd_count = 0;

        spin_lock(&qunit_hash_lock);

        qunit = dqacq_in_flight(qctxt, &qdata);
        if (qunit)
                list_add_tail(&qw.qw_entry, &qunit->lq_waiters);

        spin_unlock(&qunit_hash_lock);

        if (qunit) {
                struct qunit_data *p = &qdata;
                QDATA_DEBUG(p, "wait for dqacq completion.\n");
                l_wait_event(qw.qw_waitq, got_qunit(&qw), &lwi);
                QDATA_DEBUG(p, "wait dqacq done. (rc:%d)\n", qw.qw_rc);
        }
        RETURN(0);
}

int
qctxt_init(struct lustre_quota_ctxt *qctxt, struct super_block *sb,
           dqacq_handler_t handler)
{
        int rc = 0;
        ENTRY;

        rc = ptlrpcd_addref();
        if (rc)
                RETURN(rc);

        qctxt->lqc_handler = handler;
        qctxt->lqc_sb = sb;
        qctxt->lqc_import = NULL;
        qctxt->lqc_recovery = 0;
        qctxt->lqc_atype = 0;
        qctxt->lqc_status= 0;
        qctxt->lqc_bunit_sz = default_bunit_sz;
        qctxt->lqc_btune_sz = default_bunit_sz / 100 * default_btune_ratio;
        qctxt->lqc_iunit_sz = default_iunit_sz;
        qctxt->lqc_itune_sz = default_iunit_sz * default_itune_ratio / 100;

        RETURN(0);
}

void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force)
{
        struct lustre_qunit *qunit, *tmp;
        struct qunit_waiter *qw, *tmp2;
        int i;
        ENTRY;

        spin_lock(&qunit_hash_lock);

        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(qunit, tmp, &qunit_hash[i], lq_hash) {
                        if (qunit->lq_ctxt != qctxt)
                                continue;

                        remove_qunit_nolock(qunit);
                        /* wake up all waiters */
                        list_for_each_entry_safe(qw, tmp2, &qunit->lq_waiters,
                                                 qw_entry) {
                                list_del_init(&qw->qw_entry);
                                qw->qw_rc = 0;
                                wake_up(&qw->qw_waitq);
                        }
                        qunit_put(qunit);
                }
        }

        spin_unlock(&qunit_hash_lock);

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
                CFS_INIT_LIST_HEAD(&id_list);
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
                        qdata.qd_flags = 0;
                        qdata.qd_flags |= type;
                        qdata.qd_flags |= QUOTA_IS_BLOCK;
                        qdata.qd_count = 0;

                        ret = check_cur_qunit(obd, qctxt, &qdata);
                        if (ret > 0) {
                                int opc;
                                opc = ret == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                                rc = split_before_schedule_dqacq(obd, qctxt, &qdata, opc, 0);
                        } else
                                rc = 0;

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
