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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LQUOTA

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/init.h>
# include <linux/fs.h>
# include <linux/jbd.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/smp_lock.h>
#  include <linux/buffer_head.h>
#  include <linux/workqueue.h>
#  include <linux/mount.h>
# else
#  include <linux/locks.h>
# endif
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_mds.h>
#include <lustre_dlm.h>
#include <lustre_cfg.h>
#include <obd_ost.h>
#include <lustre_fsfilt.h>
#include <lustre_quota.h>
#include <lprocfs_status.h>
#include "quota_internal.h"

#ifdef __KERNEL__

#ifdef HAVE_QUOTA_SUPPORT

static cfs_time_t last_print = 0;
static spinlock_t last_print_lock = SPIN_LOCK_UNLOCKED;

static int filter_quota_setup(struct obd_device *obd)
{
        int rc = 0;
        struct obd_device_target *obt = &obd->u.obt;
        ENTRY;

        init_rwsem(&obt->obt_rwsem);
        obt->obt_qfmt = LUSTRE_QUOTA_V2;
        atomic_set(&obt->obt_quotachecking, 1);
        rc = qctxt_init(obd, NULL);
        if (rc)
                CERROR("initialize quota context failed! (rc:%d)\n", rc);

        RETURN(rc);
}

static int filter_quota_cleanup(struct obd_device *obd)
{
        ENTRY;
        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        RETURN(0);
}

static int filter_quota_setinfo(struct obd_device *obd, void *data)
{
        struct obd_export *exp = data;
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct obd_import *imp;
        ENTRY;

        /* setup the quota context import */
        spin_lock(&qctxt->lqc_lock);
        qctxt->lqc_import = exp->exp_imp_reverse;
        spin_unlock(&qctxt->lqc_lock);
        CDEBUG(D_QUOTA, "%s: lqc_import(%p) of obd(%p) is reactivated now, \n",
               obd->obd_name,exp->exp_imp_reverse, obd);

        /* make imp's connect flags equal relative exp's connect flags
         * adding it to avoid the scan export list
         */
        imp = qctxt->lqc_import;
        if (likely(imp))
                imp->imp_connect_data.ocd_connect_flags |=
                        (exp->exp_connect_flags &
                         (OBD_CONNECT_QUOTA64 | OBD_CONNECT_CHANGE_QS));

        cfs_waitq_signal(&qctxt->lqc_wait_for_qmaster);
        /* start quota slave recovery thread. (release high limits) */
        qslave_start_recovery(obd, qctxt);
        RETURN(0);
}

static int filter_quota_clearinfo(struct obd_export *exp, struct obd_device *obd)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        ENTRY;

        /* lquota may be not set up before destroying export, b=14896 */
        if (!obd->obd_set_up)
                RETURN(0);

        /* when exp->exp_imp_reverse is destroyed, the corresponding lqc_import
         * should be invalid b=12374 */
        if (qctxt->lqc_import && qctxt->lqc_import == exp->exp_imp_reverse) {
                spin_lock(&qctxt->lqc_lock);
                qctxt->lqc_import = NULL;
                spin_unlock(&qctxt->lqc_lock);
                CDEBUG(D_QUOTA, "%s: lqc_import of obd(%p) is invalid now.\n",
                       obd->obd_name, obd);
        }
        RETURN(0);
}

static int filter_quota_enforce(struct obd_device *obd, unsigned int ignore)
{
        ENTRY;

        if (!sb_any_quota_enabled(obd->u.obt.obt_sb))
                RETURN(0);

        if (ignore) {
                CDEBUG(D_QUOTA, "blocks will be written with ignoring quota.\n");
                cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
        } else {
                cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
        }

        RETURN(0);
}

static int filter_quota_getflag(struct obd_device *obd, struct obdo *oa)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct lustre_quota_ctxt *qctxt = &obt->obt_qctxt;
        int err, cnt, rc = 0;
        struct obd_quotactl *oqctl;
        ENTRY;

        if (!sb_any_quota_enabled(obt->obt_sb))
                RETURN(0);

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl) {
                CERROR("Not enough memory!");
                RETURN(-ENOMEM);
        }

        /* set over quota flags for a uid/gid */
        oa->o_valid |= OBD_MD_FLUSRQUOTA | OBD_MD_FLGRPQUOTA;
        oa->o_flags &= ~(OBD_FL_NO_USRQUOTA | OBD_FL_NO_GRPQUOTA);

        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct quota_adjust_qunit oqaq_tmp;
                struct lustre_qunit_size *lqs = NULL;

                oqaq_tmp.qaq_flags = cnt;
                oqaq_tmp.qaq_id = (cnt == USRQUOTA) ? oa->o_uid : oa->o_gid;

                quota_search_lqs(NULL, &oqaq_tmp, qctxt, &lqs);
                if (lqs) {
                        spin_lock(&lqs->lqs_lock);
                        if (lqs->lqs_bunit_sz <= qctxt->lqc_sync_blk) {
                                oa->o_flags |= (cnt == USRQUOTA) ?
                                        OBD_FL_NO_USRQUOTA : OBD_FL_NO_GRPQUOTA;
                                spin_unlock(&lqs->lqs_lock);
                                CDEBUG(D_QUOTA, "set sync flag: bunit(%lu), "
                                       "sync_blk(%d)\n", lqs->lqs_bunit_sz,
                                       qctxt->lqc_sync_blk);
                                /* this is for quota_search_lqs */
                                lqs_putref(lqs);
                                continue;
                        }
                        spin_unlock(&lqs->lqs_lock);
                        /* this is for quota_search_lqs */
                        lqs_putref(lqs);
                }

                memset(oqctl, 0, sizeof(*oqctl));

                oqctl->qc_cmd = Q_GETQUOTA;
                oqctl->qc_type = cnt;
                oqctl->qc_id = (cnt == USRQUOTA) ? oa->o_uid : oa->o_gid;
                err = fsfilt_quotactl(obd, obt->obt_sb, oqctl);
                if (err) {
                        if (!rc)
                                rc = err;
                        oa->o_valid &= ~((cnt == USRQUOTA) ? OBD_MD_FLUSRQUOTA :
                                                             OBD_MD_FLGRPQUOTA);
                        continue;
                }

                if (oqctl->qc_dqblk.dqb_bhardlimit &&
                   (toqb(oqctl->qc_dqblk.dqb_curspace) >=
                    oqctl->qc_dqblk.dqb_bhardlimit))
                        oa->o_flags |= (cnt == USRQUOTA) ?
                                OBD_FL_NO_USRQUOTA : OBD_FL_NO_GRPQUOTA;
        }
        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

/**
 * check whether the left quota of certain uid and gid can satisfy a block_write
 * or inode_create rpc. When need to acquire quota, return QUOTA_RET_ACQUOTA
 */
static int quota_check_common(struct obd_device *obd, unsigned int uid,
                              unsigned int gid, int count, int cycle, int isblk)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int i;
        __u32 id[MAXQUOTAS] = { uid, gid };
        struct qunit_data qdata[MAXQUOTAS];
        int rc = 0, rc2[2] = { 0, 0 };
        ENTRY;

        CLASSERT(MAXQUOTAS < 4);
        if (!sb_any_quota_enabled(qctxt->lqc_sb))
                RETURN(rc);

        spin_lock(&qctxt->lqc_lock);
        if (!qctxt->lqc_valid){
                spin_unlock(&qctxt->lqc_lock);
                RETURN(rc);
        }
        spin_unlock(&qctxt->lqc_lock);

        for (i = 0; i < MAXQUOTAS; i++) {
                struct lustre_qunit_size *lqs = NULL;

                qdata[i].qd_id = id[i];
                qdata[i].qd_flags = i;
                if (isblk)
                        QDATA_SET_BLK(&qdata[i]);
                qdata[i].qd_count = 0;

                /* ignore root user */
                if (qdata[i].qd_id == 0 && !QDATA_IS_GRP(&qdata[i]))
                        continue;

                quota_search_lqs(&qdata[i], NULL, qctxt, &lqs);
                if (!lqs)
                        continue;

                rc2[i] = compute_remquota(obd, qctxt, &qdata[i], isblk);
                spin_lock(&lqs->lqs_lock);
                if (!cycle) {
                        rc = QUOTA_RET_INC_PENDING;
                        if (isblk)
                                lqs->lqs_bwrite_pending += count;
                        else
                                lqs->lqs_iwrite_pending += count;
                }
                if (rc2[i] == QUOTA_RET_OK) {
                        if (isblk && qdata[i].qd_count <
                            lqs->lqs_bwrite_pending * CFS_PAGE_SIZE)
                                rc2[i] = QUOTA_RET_ACQUOTA;
                        if (!isblk && qdata[i].qd_count <
                            lqs->lqs_iwrite_pending)
                                rc2[i] = QUOTA_RET_ACQUOTA;
                }
                spin_unlock(&lqs->lqs_lock);
                CDEBUG(D_QUOTA, "count: %d, write pending: %lu, qd_count: "LPU64
                       ".\n", count,
                       isblk ? lqs->lqs_bwrite_pending : lqs->lqs_iwrite_pending,
                       qdata[i].qd_count);

                /* When cycle is zero, lqs_*_pending will be changed. We will
                 * get reference of the lqs here and put reference of lqs in
                 * quota_pending_commit b=14784 */
                if (!cycle)
                        lqs_getref(lqs);

                /* this is for quota_search_lqs */
                lqs_putref(lqs);
        }

        if (rc2[0] == QUOTA_RET_ACQUOTA || rc2[1] == QUOTA_RET_ACQUOTA)
                RETURN(rc | QUOTA_RET_ACQUOTA);
        else
                RETURN(rc);
}

static int quota_chk_acq_common(struct obd_device *obd, unsigned int uid,
                                unsigned int gid, int count, int *pending,
                                quota_acquire acquire,
                                struct obd_trans_info *oti, int isblk)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        struct l_wait_info lwi = { 0 };
        int rc = 0, cycle = 0, count_err = 1;
        ENTRY;

        CDEBUG(D_QUOTA, "check quota for %s\n", obd->obd_name);
        *pending = 0;
        /* Unfortunately, if quota master is too busy to handle the
         * pre-dqacq in time and quota hash on ost is used up, we
         * have to wait for the completion of in flight dqacq/dqrel,
         * in order to get enough quota for write b=12588 */
        do_gettimeofday(&work_start);
        while ((rc = quota_check_common(obd, uid, gid, count, cycle, isblk)) &
               QUOTA_RET_ACQUOTA) {

                spin_lock(&qctxt->lqc_lock);
                if (!qctxt->lqc_import && oti) {
                        spin_unlock(&qctxt->lqc_lock);

                        LASSERT(oti && oti->oti_thread &&
                                oti->oti_thread->t_watchdog);

                        lc_watchdog_disable(oti->oti_thread->t_watchdog);
                        CDEBUG(D_QUOTA, "sleep for quota master\n");
                        l_wait_event(qctxt->lqc_wait_for_qmaster, check_qm(qctxt),
                                     &lwi);
                        CDEBUG(D_QUOTA, "wake up when quota master is back\n");
                        lc_watchdog_touch(oti->oti_thread->t_watchdog);
                } else {
                        spin_unlock(&qctxt->lqc_lock);
                }

                if (rc & QUOTA_RET_INC_PENDING)
                        *pending = 1;

                cycle++;
                if (isblk)
                        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_HOLD_WRITE_RPC, 90);
                /* after acquire(), we should run quota_check_common again
                 * so that we confirm there are enough quota to finish write */
                rc = acquire(obd, uid, gid, oti, isblk);

                /* please reference to dqacq_completion for the below */
                /* a new request is finished, try again */
                if (rc == -EAGAIN) {
                        CDEBUG(D_QUOTA, "finish a quota req, try again\n");
                        continue;
                }

                /* it is out of quota already */
                if (rc == -EDQUOT) {
                        CDEBUG(D_QUOTA, "out of quota,  return -EDQUOT\n");
                        break;
                }

                /* -EBUSY and others, wait a second and try again */
                if (rc < 0) {
                        cfs_waitq_t        waitq;
                        struct l_wait_info lwi;

                        if (oti && oti->oti_thread && oti->oti_thread->t_watchdog)
                                lc_watchdog_touch(oti->oti_thread->t_watchdog);
                        CDEBUG(D_QUOTA, "rc: %d, count_err: %d\n", rc,
                               count_err++);

                        init_waitqueue_head(&waitq);
                        lwi = LWI_TIMEOUT(cfs_time_seconds(min(cycle, 10)), NULL,
                                          NULL);
                        l_wait_event(waitq, 0, &lwi);
                }

                if (rc < 0 || cycle % 10 == 2) {
                        spin_lock(&last_print_lock);
                        if (last_print == 0 ||
                            cfs_time_before((last_print + cfs_time_seconds(30)),
                                            cfs_time_current())) {
                                last_print = cfs_time_current();
                                spin_unlock(&last_print_lock);
                                CWARN("still haven't managed to acquire quota "
                                      "space from the quota master after %d "
                                      "retries (err=%d, rc=%d)\n",
                                      cycle, count_err - 1, rc);
                        } else {
                                spin_unlock(&last_print_lock);
                        }
                }

                CDEBUG(D_QUOTA, "recheck quota with rc: %d, cycle: %d\n", rc,
                       cycle);
        }

        if (!cycle && rc & QUOTA_RET_INC_PENDING)
                *pending = 1;

        do_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        lprocfs_counter_add(qctxt->lqc_stats,
                            isblk ? LQUOTA_WAIT_FOR_CHK_BLK :
                                    LQUOTA_WAIT_FOR_CHK_INO,
                            timediff);

        RETURN(rc);
}

/**
 * when a block_write or inode_create rpc is finished, adjust the record for
 * pending blocks and inodes
 */
static int quota_pending_commit(struct obd_device *obd, unsigned int uid,
                                unsigned int gid, int count, int isblk)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        int i;
        __u32 id[MAXQUOTAS] = { uid, gid };
        struct qunit_data qdata[MAXQUOTAS];
        ENTRY;

        CDEBUG(D_QUOTA, "commit pending quota for  %s\n", obd->obd_name);
        CLASSERT(MAXQUOTAS < 4);
        if (!sb_any_quota_enabled(qctxt->lqc_sb))
                RETURN(0);

        do_gettimeofday(&work_start);
        for (i = 0; i < MAXQUOTAS; i++) {
                struct lustre_qunit_size *lqs = NULL;

                qdata[i].qd_id = id[i];
                qdata[i].qd_flags = i;
                if (isblk)
                        QDATA_SET_BLK(&qdata[i]);
                qdata[i].qd_count = 0;

                if (qdata[i].qd_id == 0 && !QDATA_IS_GRP(&qdata[i]))
                        continue;

                quota_search_lqs(&qdata[i], NULL, qctxt, &lqs);
                if (lqs) {
                        int flag = 0;
                        CDEBUG(D_QUOTA, "pending: %lu, count: %d.\n",
                               isblk ? lqs->lqs_bwrite_pending :
                               lqs->lqs_iwrite_pending, count);
                        spin_lock(&lqs->lqs_lock);
                        if (isblk) {
                                if (lqs->lqs_bwrite_pending >= count) {
                                        lqs->lqs_bwrite_pending -= count;
                                        spin_unlock(&lqs->lqs_lock);
                                        flag = 1;
                                } else {
                                        spin_unlock(&lqs->lqs_lock);
                                        CDEBUG(D_ERROR,
                                               "there are too many blocks!\n");
                                }
                        } else {
                                if (lqs->lqs_iwrite_pending >= count) {
                                        lqs->lqs_iwrite_pending -= count;
                                        spin_unlock(&lqs->lqs_lock);
                                        flag = 1;
                                } else {
                                        spin_unlock(&lqs->lqs_lock);
                                        CDEBUG(D_ERROR,
                                               "there are too many files!\n");
                                }
                        }

                        lqs_putref(lqs);
                        /* When lqs_*_pening is changed back, we'll putref lqs
                         * here b=14784 */
                        if (flag)
                                lqs_putref(lqs);
                }
        }
        do_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        lprocfs_counter_add(qctxt->lqc_stats,
                            isblk ? LQUOTA_WAIT_FOR_COMMIT_BLK :
                                    LQUOTA_WAIT_FOR_COMMIT_INO,
                            timediff);

        RETURN(0);
}

static int mds_quota_init(void)
{
        return lustre_dquot_init();
}

static int mds_quota_exit(void)
{
        lustre_dquot_exit();
        return 0;
}

static int mds_quota_setup(struct obd_device *obd)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct mds_obd *mds = &obd->u.mds;
        int rc;
        ENTRY;

        if (unlikely(mds->mds_quota)) {
                CWARN("try to reinitialize quota context!\n");
                RETURN(0);
        }

        init_rwsem(&obt->obt_rwsem);
        obt->obt_qfmt = LUSTRE_QUOTA_V2;
        mds->mds_quota_info.qi_version = LUSTRE_QUOTA_V2;
        atomic_set(&obt->obt_quotachecking, 1);
        /* initialize quota master and quota context */
        sema_init(&mds->mds_qonoff_sem, 1);
        rc = qctxt_init(obd, dqacq_handler);
        if (rc) {
                CERROR("initialize quota context failed! (rc:%d)\n", rc);
                RETURN(rc);
        }
        mds->mds_quota = 1;
        RETURN(rc);
}

static int mds_quota_cleanup(struct obd_device *obd)
{
        ENTRY;
        if (unlikely(!obd->u.mds.mds_quota))
                RETURN(0);

        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        RETURN(0);
}

static int mds_quota_setinfo(struct obd_device *obd, void *data)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        ENTRY;

        if (unlikely(!obd->u.mds.mds_quota))
                RETURN(0);

        if (data != NULL)
                QUOTA_MASTER_READY(qctxt);
        else
                QUOTA_MASTER_UNREADY(qctxt);
        RETURN(0);
}

static int mds_quota_fs_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_quotactl oqctl;
        ENTRY;

        if (unlikely(!mds->mds_quota))
                RETURN(0);

        mds->mds_quota = 0;
        memset(&oqctl, 0, sizeof(oqctl));
        oqctl.qc_type = UGQUOTA;

        down(&mds->mds_qonoff_sem);
        mds_admin_quota_off(obd, &oqctl);
        up(&mds->mds_qonoff_sem);
        RETURN(0);
}

static int quota_acquire_common(struct obd_device *obd, unsigned int uid,
                                unsigned int gid, struct obd_trans_info *oti,
                                int isblk)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc;
        ENTRY;

        rc = qctxt_adjust_qunit(obd, qctxt, uid, gid, isblk, 1, oti);
        RETURN(rc);
}

#endif /* HAVE_QUOTA_SUPPORT */
#endif /* __KERNEL__ */

struct osc_quota_info {
        struct list_head        oqi_hash;       /* hash list */
        struct client_obd      *oqi_cli;        /* osc obd */
        unsigned int            oqi_id;         /* uid/gid of a file */
        short                   oqi_type;       /* quota type */
};

spinlock_t qinfo_list_lock = SPIN_LOCK_UNLOCKED;

static struct list_head qinfo_hash[NR_DQHASH];
/* SLAB cache for client quota context */
cfs_mem_cache_t *qinfo_cachep = NULL;

static inline int hashfn(struct client_obd *cli, unsigned long id, int type)
                         __attribute__((__const__));

static inline int hashfn(struct client_obd *cli, unsigned long id, int type)
{
        unsigned long tmp = ((unsigned long)cli>>6) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

/* caller must hold qinfo_list_lock */
static inline void insert_qinfo_hash(struct osc_quota_info *oqi)
{
        struct list_head *head = qinfo_hash +
                hashfn(oqi->oqi_cli, oqi->oqi_id, oqi->oqi_type);

        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        list_add(&oqi->oqi_hash, head);
}

/* caller must hold qinfo_list_lock */
static inline void remove_qinfo_hash(struct osc_quota_info *oqi)
{
        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        list_del_init(&oqi->oqi_hash);
}

/* caller must hold qinfo_list_lock */
static inline struct osc_quota_info *find_qinfo(struct client_obd *cli,
                                                unsigned int id, int type)
{
        unsigned int hashent = hashfn(cli, id, type);
        struct osc_quota_info *oqi;
        ENTRY;

        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        list_for_each_entry(oqi, &qinfo_hash[hashent], oqi_hash) {
                if (oqi->oqi_cli == cli &&
                    oqi->oqi_id == id && oqi->oqi_type == type)
                        return oqi;
        }
        RETURN(NULL);
}

static struct osc_quota_info *alloc_qinfo(struct client_obd *cli,
                                          unsigned int id, int type)
{
        struct osc_quota_info *oqi;
        ENTRY;

        OBD_SLAB_ALLOC(oqi, qinfo_cachep, CFS_ALLOC_STD, sizeof(*oqi));
        if(!oqi)
                RETURN(NULL);

        CFS_INIT_LIST_HEAD(&oqi->oqi_hash);
        oqi->oqi_cli = cli;
        oqi->oqi_id = id;
        oqi->oqi_type = type;

        RETURN(oqi);
}

static void free_qinfo(struct osc_quota_info *oqi)
{
        OBD_SLAB_FREE(oqi, qinfo_cachep, sizeof(*oqi));
}

int osc_quota_chkdq(struct client_obd *cli, unsigned int uid, unsigned int gid)
{
        unsigned int id;
        int cnt, rc = QUOTA_OK;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi = NULL;

                id = (cnt == USRQUOTA) ? uid : gid;
                oqi = find_qinfo(cli, id, cnt);
                if (oqi) {
                        rc = NO_QUOTA;
                        break;
                }
        }
        spin_unlock(&qinfo_list_lock);

        RETURN(rc);
}

int osc_quota_setdq(struct client_obd *cli, unsigned int uid, unsigned int gid,
                    obd_flag valid, obd_flag flags)
{
        unsigned int id;
        obd_flag noquota;
        int cnt, rc = 0;
        ENTRY;


        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi, *old;

                if (!(valid & ((cnt == USRQUOTA) ?
                    OBD_MD_FLUSRQUOTA : OBD_MD_FLGRPQUOTA)))
                        continue;

                id = (cnt == USRQUOTA) ? uid : gid;
                noquota = (cnt == USRQUOTA) ?
                    (flags & OBD_FL_NO_USRQUOTA) : (flags & OBD_FL_NO_GRPQUOTA);

                oqi = alloc_qinfo(cli, id, cnt);
                if (oqi) {
                        spin_lock(&qinfo_list_lock);

                        old = find_qinfo(cli, id, cnt);
                        if (old && !noquota)
                                remove_qinfo_hash(old);
                        else if (!old && noquota)
                                insert_qinfo_hash(oqi);

                        spin_unlock(&qinfo_list_lock);

                        if (old || !noquota)
                                free_qinfo(oqi);
                        if (old && !noquota)
                                free_qinfo(old);
                } else {
                        CERROR("not enough mem!\n");
                        rc = -ENOMEM;
                        break;
                }
        }

        RETURN(rc);
}

int osc_quota_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        struct osc_quota_info *oqi, *n;
        int i;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        if (oqi->oqi_cli != cli)
                                continue;
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        spin_unlock(&qinfo_list_lock);

        RETURN(0);
}

int osc_quota_init(void)
{
        int i;
        ENTRY;

        LASSERT(qinfo_cachep == NULL);
        qinfo_cachep = cfs_mem_cache_create("osc_quota_info",
                                            sizeof(struct osc_quota_info),
                                            0, 0);
        if (!qinfo_cachep)
                RETURN(-ENOMEM);

        for (i = 0; i < NR_DQHASH; i++)
                CFS_INIT_LIST_HEAD(qinfo_hash + i);

        RETURN(0);
}

int osc_quota_exit(void)
{
        struct osc_quota_info *oqi, *n;
        int i, rc;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        spin_unlock(&qinfo_list_lock);

        rc = cfs_mem_cache_destroy(qinfo_cachep);
        LASSERTF(rc == 0, "couldn't destory qinfo_cachep slab\n");
        qinfo_cachep = NULL;

        RETURN(0);
}

#ifdef __KERNEL__
#ifdef HAVE_QUOTA_SUPPORT
quota_interface_t mds_quota_interface = {
        .quota_init     = mds_quota_init,
        .quota_exit     = mds_quota_exit,
        .quota_setup    = mds_quota_setup,
        .quota_cleanup  = mds_quota_cleanup,
        .quota_check    = target_quota_check,
        .quota_ctl      = mds_quota_ctl,
        .quota_setinfo  = mds_quota_setinfo,
        .quota_fs_cleanup = mds_quota_fs_cleanup,
        .quota_recovery = mds_quota_recovery,
        .quota_adjust   = mds_quota_adjust,
        .quota_chkquota = quota_chk_acq_common,
        .quota_acquire  = quota_acquire_common,
        .quota_pending_commit = quota_pending_commit,
};

quota_interface_t filter_quota_interface = {
        .quota_setup    = filter_quota_setup,
        .quota_cleanup  = filter_quota_cleanup,
        .quota_check    = target_quota_check,
        .quota_ctl      = filter_quota_ctl,
        .quota_setinfo  = filter_quota_setinfo,
        .quota_clearinfo = filter_quota_clearinfo,
        .quota_enforce  = filter_quota_enforce,
        .quota_getflag  = filter_quota_getflag,
        .quota_acquire  = quota_acquire_common,
        .quota_adjust   = filter_quota_adjust,
        .quota_chkquota = quota_chk_acq_common,
        .quota_adjust_qunit   = filter_quota_adjust_qunit,
        .quota_pending_commit = quota_pending_commit,
};
#endif
#endif /* __KERNEL__ */

quota_interface_t mdc_quota_interface = {
        .quota_ctl      = client_quota_ctl,
        .quota_check    = client_quota_check,
        .quota_poll_check = client_quota_poll_check,
};

quota_interface_t lmv_quota_interface = {
        .quota_ctl      = lmv_quota_ctl,
        .quota_check    = lmv_quota_check,
};

quota_interface_t osc_quota_interface = {
        .quota_ctl      = client_quota_ctl,
        .quota_check    = client_quota_check,
        .quota_poll_check = client_quota_poll_check,
        .quota_init     = osc_quota_init,
        .quota_exit     = osc_quota_exit,
        .quota_chkdq    = osc_quota_chkdq,
        .quota_setdq    = osc_quota_setdq,
        .quota_cleanup  = osc_quota_cleanup,
        .quota_adjust_qunit = client_quota_adjust_qunit,
};

quota_interface_t lov_quota_interface = {
        .quota_ctl      = lov_quota_ctl,
        .quota_check    = lov_quota_check,
        .quota_adjust_qunit = lov_quota_adjust_qunit,
};

#ifdef __KERNEL__

cfs_proc_dir_entry_t *lquota_type_proc_dir = NULL;

static int __init init_lustre_quota(void)
{
#ifdef HAVE_QUOTA_SUPPORT
        int rc = 0;

        lquota_type_proc_dir = lprocfs_register(OBD_LQUOTA_DEVICENAME,
                                                proc_lustre_root,
                                                NULL, NULL);
        if (IS_ERR(lquota_type_proc_dir)) {
                CERROR("LProcFS failed in lquota-init\n");
                rc = PTR_ERR(lquota_type_proc_dir);
                return rc;
        }

        rc = qunit_cache_init();
        if (rc)
                return rc;

        PORTAL_SYMBOL_REGISTER(filter_quota_interface);
        PORTAL_SYMBOL_REGISTER(mds_quota_interface);
#endif
        PORTAL_SYMBOL_REGISTER(mdc_quota_interface);
        PORTAL_SYMBOL_REGISTER(lmv_quota_interface);
        PORTAL_SYMBOL_REGISTER(osc_quota_interface);
        PORTAL_SYMBOL_REGISTER(lov_quota_interface);
        return 0;
}

static void /*__exit*/ exit_lustre_quota(void)
{
        PORTAL_SYMBOL_UNREGISTER(mdc_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(lmv_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(osc_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(lov_quota_interface);
#ifdef HAVE_QUOTA_SUPPORT
        PORTAL_SYMBOL_UNREGISTER(filter_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(mds_quota_interface);

        qunit_cache_cleanup();

        if (lquota_type_proc_dir)
                lprocfs_remove(&lquota_type_proc_dir);
#endif
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Quota");
MODULE_LICENSE("GPL");

cfs_module(lquota, "1.0.0", init_lustre_quota, exit_lustre_quota);

#ifdef HAVE_QUOTA_SUPPORT
EXPORT_SYMBOL(mds_quota_interface);
EXPORT_SYMBOL(filter_quota_interface);
#endif
EXPORT_SYMBOL(mdc_quota_interface);
EXPORT_SYMBOL(lmv_quota_interface);
EXPORT_SYMBOL(osc_quota_interface);
EXPORT_SYMBOL(lov_quota_interface);
#endif /* __KERNEL */
