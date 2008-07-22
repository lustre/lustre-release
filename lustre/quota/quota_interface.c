/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lustre/quota/quota_interface.c
 *
 * Copyright (c) 2001-2005 Cluster File Systems, Inc.
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * No redistribution or use is permitted outside of Cluster File Systems, Inc.
 *
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/init.h>
# include <linux/fs.h>
# include <linux/jbd.h>
# include <linux/ext3_fs.h>
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

/* quota proc file handling functions */
#ifdef LPROCFS

#define USER_QUOTA      1
#define GROUP_QUOTA     2

#define MAX_STYPE_SIZE  5

/* The following information about CURRENT quotas is expected on the output:
 * MDS: u for user quotas (administrative+operational) turned on,
 *      g for group quotas (administrative+operational) turned on,
 *      1 for 32-bit operational quotas and 32-bit administrative quotas,
 *      2 for 32-bit operational quotas and 64-bit administrative quotas,
 *      3 for 64-bit operational quotas and 64-bit administrative quotas
 * OST: u for user quotas (operational) turned on,
 *      g for group quotas (operational) turned on,
 *      1 for 32-bit local operational quotas,
 *      3 for 64-bit local operational quotas,
 * Permanent parameters can be read with lctl (?)
 */
int lprocfs_quota_rd_type(char *page, char **start, off_t off, int count,
                          int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        char stype[MAX_STYPE_SIZE + 1] = "";
        int oq_type, rc, is_mds;
        lustre_quota_version_t aq_version, oq_version;
        struct obd_device_target *obt;

        LASSERT(obd != NULL);

        obt = &obd->u.obt;
        is_mds = !strcmp(obd->obd_type->typ_name, LUSTRE_MDS_NAME);

        /* Collect the needed information */
        oq_type = obd->u.obt.obt_qctxt.lqc_flags;
        oq_version = obt->obt_qfmt;
        if (is_mds) {
                rc = mds_quota_get_version(obd, &aq_version);
                if (rc)
                        return -EPROTO;
                /* Here we can also assert that aq_type == oq_type
                 * except for quota startup/shutdown states     */
        }

        /* Transform the collected data into a user-readable string */
        if (oq_type & LQC_USRQUOTA_FLAG)
                strcat(stype, "u");
        if (oq_type & LQC_GRPQUOTA_FLAG)
                strcat(stype, "g");

        if ((!is_mds || aq_version == LUSTRE_QUOTA_V1) &&
            oq_version == LUSTRE_QUOTA_V1)
                strcat(stype, "1");
#ifdef HAVE_QUOTA64
        else if ((!is_mds || aq_version == LUSTRE_QUOTA_V2) &&
                 oq_version == LUSTRE_QUOTA_V2)
                strcat(stype, "3");
#endif
        else if (is_mds && aq_version == LUSTRE_QUOTA_V2 &&
                 oq_version == LUSTRE_QUOTA_V1)
                strcat(stype, "2");
        else
                return -EPROTO;

        return snprintf(page, count, "%s\n", stype);
}
EXPORT_SYMBOL(lprocfs_quota_rd_type);

static int auto_quota_on(struct obd_device *obd, int type,
                         struct super_block *sb, int is_master)
{
        struct obd_quotactl *oqctl;
        struct lvfs_run_ctxt saved;
        int rc = 0, id;
        struct obd_device_target *obt;
        ENTRY;

        LASSERT(type == USRQUOTA || type == GRPQUOTA || type == UGQUOTA);

        obt = &obd->u.obt;

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl)
                RETURN(-ENOMEM);

        if (!atomic_dec_and_test(&obt->obt_quotachecking)) {
                CDEBUG(D_INFO, "other people are doing quotacheck\n");
                atomic_inc(&obt->obt_quotachecking);
                RETURN(-EBUSY);
        }

        id = UGQUOTA2LQC(type);
        /* quota already turned on */
        if ((obt->obt_qctxt.lqc_flags & id) == id) {
                rc = 0;
                goto out;
        }

        oqctl->qc_type = type;
        oqctl->qc_cmd = Q_QUOTAON;
        oqctl->qc_id = obt->obt_qfmt;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (is_master) {
                struct mds_obd *mds = &obd->u.mds;

                down(&mds->mds_qonoff_sem);
                /* turn on cluster wide quota */
                rc = mds_admin_quota_on(obd, oqctl);
                if (rc)
                        CDEBUG(rc == -ENOENT ? D_QUOTA : D_ERROR,
                               "auto-enable admin quota failed. rc=%d\n", rc);
                up(&mds->mds_qonoff_sem);

        }
        if (!rc) {
                /* turn on local quota */
                rc = fsfilt_quotactl(obd, sb, oqctl);
                if (rc)
                        CDEBUG(rc == -ENOENT ? D_QUOTA : D_ERROR,
                               "auto-enable local quota failed. rc=%d\n", rc);
                else
                        obt->obt_qctxt.lqc_flags |= UGQUOTA2LQC(type);
        }

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

out:
        atomic_inc(&obt->obt_quotachecking);

        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

static int filter_quota_set_version(struct obd_device *obd, 
                                    lustre_quota_version_t version)
{
        struct obd_device_target *obt = &obd->u.obt;

        if (version != LUSTRE_QUOTA_V1) {
#ifdef HAVE_QUOTA64
                if (version != LUSTRE_QUOTA_V2)
#endif
                        return -EINVAL;
        }

        if (!atomic_dec_and_test(&obt->obt_quotachecking)) {
                CDEBUG(D_INFO, "other people are doing quotacheck\n");
                atomic_inc(&obt->obt_quotachecking);
                return -EBUSY;
        }

        if (obt->obt_qctxt.lqc_flags & (LQC_USRQUOTA_FLAG | LQC_GRPQUOTA_FLAG)) {
                atomic_inc(&obt->obt_quotachecking);
                return -EBUSY;
        }

        obt->obt_qfmt = version;

        atomic_inc(&obt->obt_quotachecking);

        return 0;
}

/* The following settings of CURRENT quotas is expected on the input:
 * MDS: u for user quotas (administrative+operational) turned on,
 *      g for group quotas (administrative+operational) turned on,
 *      1 for 32-bit operational quotas and 32-bit administrative quotas,
 *      2 for 32-bit operational quotas and 64-bit administrative quotas,
 *      3 for 64-bit operational quotas and 64-bit administrative quotas
 * OST: u for user quotas (operational) turned on,
 *      g for group quotas (operational) turned on,
 *      1 for 32-bit local operational quotas,
 *      2 for 32-bit local operational quotas,
 *      3 for 64-bit local operational quotas,
 * Permanent parameters can be set with lctl/tunefs
 */
int lprocfs_quota_wr_type(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        struct obd_device_target *obt;
        int type = 0, is_mds, idx;
        unsigned long i;
        char stype[MAX_STYPE_SIZE + 1] = "";
        static const lustre_quota_version_t s2av[3] = {LUSTRE_QUOTA_V1,
                                                       LUSTRE_QUOTA_V2,
                                                       LUSTRE_QUOTA_V2},
                                            s2ov[3] = {LUSTRE_QUOTA_V1,
                                                       LUSTRE_QUOTA_V1,
                                                       LUSTRE_QUOTA_V2};
        LASSERT(obd != NULL);

        obt = &obd->u.obt;

        is_mds = !strcmp(obd->obd_type->typ_name, LUSTRE_MDS_NAME);

        if (count > MAX_STYPE_SIZE)
                return -EINVAL;

        if (copy_from_user(stype, buffer, count))
                return -EFAULT;

        for (i = 0 ; i < count ; i++) {
                int rc;

                switch (stype[i]) {
                case 'u' :
                        type |= USER_QUOTA;
                        break;
                case 'g' :
                        type |= GROUP_QUOTA;
                        break;
                /* quota version specifiers */
                case '1' :
                case '2' :
                case '3' :
                        idx = stype[i] - '1';
#ifndef HAVE_QUOTA64
                        if (s2ov[idx] == LUSTRE_QUOTA_V2)
                                return -EINVAL;
#endif
                        if (is_mds) {
                                rc = mds_quota_set_version(obd, s2av[idx]);
                                if (rc) {
                                        CDEBUG(D_QUOTA, "failed to set admin "
                                               "quota to spec %c! %d\n",
                                               stype[i], rc);
                                        return rc;
                                }
                        }
                        rc = filter_quota_set_version(obd, s2ov[idx]);
                        if (rc) {
                                CDEBUG(D_QUOTA, "failed to set operational quota"
                                       " to spec %c! %d\n", stype[i], rc);
                                return rc;
                        }
                        break;
                default  : /* just skip stray symbols like \n */
                        break;
                }
        }

        if (type != 0)
                auto_quota_on(obd, type - 1, obt->obt_sb, is_mds);

        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_type);

#endif /* LPROCFS */

static int filter_quota_setup(struct obd_device *obd)
{
        int rc = 0;
        struct obd_device_target *obt = &obd->u.obt;
        ENTRY;

#ifdef HAVE_QUOTA64
        obt->obt_qfmt = LUSTRE_QUOTA_V2;
#else
        obt->obt_qfmt = LUSTRE_QUOTA_V1;
#endif
        atomic_set(&obt->obt_quotachecking, 1);
        rc = qctxt_init(&obt->obt_qctxt, obt->obt_sb, NULL);
        if (rc)
                CERROR("initialize quota context failed! (rc:%d)\n", rc);

        RETURN(rc);
}

static int filter_quota_cleanup(struct obd_device *obd)
{
        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        return 0;
}

static int filter_quota_setinfo(struct obd_export *exp, struct obd_device *obd)
{
        struct obd_import *imp;

        /* setup the quota context import */
        spin_lock(&obd->u.obt.obt_qctxt.lqc_lock);
        obd->u.obt.obt_qctxt.lqc_import = exp->exp_imp_reverse;
        spin_unlock(&obd->u.obt.obt_qctxt.lqc_lock);

        /* make imp's connect flags equal relative exp's connect flags
         * adding it to avoid the scan export list
         */
        imp = exp->exp_imp_reverse;
        if (imp)
                imp->imp_connect_data.ocd_connect_flags |=
                        (exp->exp_connect_flags &
                         (OBD_CONNECT_QUOTA64 | OBD_CONNECT_CHANGE_QS));

        /* start quota slave recovery thread. (release high limits) */
        qslave_start_recovery(obd, &obd->u.obt.obt_qctxt);
        return 0;
}

static int filter_quota_clearinfo(struct obd_export *exp, struct obd_device *obd)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;

        /* lquota may be not set up before destroying export, b=14896 */
        if (!obd->obd_set_up)
                return 0;

        /* when exp->exp_imp_reverse is destroyed, the corresponding lqc_import
         * should be invalid b=12374 */
        if (qctxt->lqc_import == exp->exp_imp_reverse) {
                spin_lock(&qctxt->lqc_lock);
                qctxt->lqc_import = NULL;
                spin_unlock(&qctxt->lqc_lock);
        }

        return 0;
}

static int filter_quota_enforce(struct obd_device *obd, unsigned int ignore)
{
        ENTRY;

        if (!sb_any_quota_enabled(obd->u.obt.obt_sb))
                RETURN(0);

        if (ignore)
                cap_raise(current->cap_effective, CAP_SYS_RESOURCE);
        else
                cap_lower(current->cap_effective, CAP_SYS_RESOURCE);

        RETURN(0);
}

static int filter_quota_getflag(struct obd_device *obd, struct obdo *oa)
{
        struct obd_device_target *obt = &obd->u.obt;
        int err, cnt, rc = 0;
        struct obd_quotactl *oqctl;
        ENTRY;

        if (!sb_any_quota_enabled(obt->obt_sb))
                RETURN(0);

        oa->o_flags &= ~(OBD_FL_NO_USRQUOTA | OBD_FL_NO_GRPQUOTA);

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl) {
                CERROR("Not enough memory!");
                RETURN(-ENOMEM);
        }

        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                memset(oqctl, 0, sizeof(*oqctl));

                oqctl->qc_cmd = Q_GETQUOTA;
                oqctl->qc_type = cnt;
                oqctl->qc_id = (cnt == USRQUOTA) ? oa->o_uid : oa->o_gid;
                err = fsfilt_quotactl(obd, obt->obt_sb, oqctl);
                if (err) {
                        if (!rc)
                                rc = err;
                        continue;
                }

                /* set over quota flags for a uid/gid */
                oa->o_valid |= (cnt == USRQUOTA) ?
                               OBD_MD_FLUSRQUOTA : OBD_MD_FLGRPQUOTA;
                if (oqctl->qc_dqblk.dqb_bhardlimit &&
                   (toqb(oqctl->qc_dqblk.dqb_curspace) >=
                    oqctl->qc_dqblk.dqb_bhardlimit))
                        oa->o_flags |= (cnt == USRQUOTA) ?
                                OBD_FL_NO_USRQUOTA : OBD_FL_NO_GRPQUOTA;
        }
        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

static int filter_quota_acquire(struct obd_device *obd, unsigned int uid,
                                unsigned int gid)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc;
        ENTRY;

        rc = qctxt_adjust_qunit(obd, qctxt, uid, gid, LQUOTA_FLAGS_BLK, 1);
        RETURN(rc);
}

/* check whether the left quota of certain uid and gid can satisfy a block_write
 * or inode_create rpc. When need to acquire quota, return QUOTA_RET_ACQUOTA */
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

                CDEBUG(D_QUOTA, "write pending: %lu, qd_count: "LPU64".\n",
                       isblk ? lqs->lqs_bwrite_pending : lqs->lqs_iwrite_pending,
                       qdata[i].qd_count);
                if (rc2[i] == QUOTA_RET_OK) {
                        if (isblk && qdata[i].qd_count <
                            lqs->lqs_bwrite_pending * CFS_PAGE_SIZE)
                                rc2[i] = QUOTA_RET_ACQUOTA;
                        if (!isblk && qdata[i].qd_count <
                            lqs->lqs_iwrite_pending)
                                rc2[i] = QUOTA_RET_ACQUOTA;
                }

                spin_unlock(&lqs->lqs_lock);

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
                                int isblk, quota_acquire acquire)
{
        int rc = 0, cycle = 0, count_err = 0;
        ENTRY;

        /* Unfortunately, if quota master is too busy to handle the
         * pre-dqacq in time and quota hash on ost is used up, we
         * have to wait for the completion of in flight dqacq/dqrel,
         * in order to get enough quota for write b=12588 */
        while ((rc = quota_check_common(obd, uid, gid, count, cycle, isblk)) &
               QUOTA_RET_ACQUOTA) {

                if (rc & QUOTA_RET_INC_PENDING)
                        *pending = 1;

                cycle++;
                if (isblk)
                        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_HOLD_WRITE_RPC, 90);
                /* after acquire(), we should run quota_check_common again
                 * so that we confirm there are enough quota to finish write */
                rc = acquire(obd, uid, gid);

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

                /* -EBUSY and others, try 10 times */
                if (rc < 0 && count_err < 10) {
                        CDEBUG(D_QUOTA, "rc: %d, count_err: %d\n", rc, count_err++);
                        cfs_schedule_timeout(CFS_TASK_INTERRUPTIBLE, HZ);
                        continue;
                }

                if (count_err >= 10 || cycle >= 1000) {
                        CDEBUG(D_ERROR, "we meet 10 errors or run too many"
                               " cycles when acquiring quota, quit checking with"
                               " rc: %d, cycle: %d.\n", rc, cycle);
                        break;
                }

                CDEBUG(D_QUOTA, "recheck quota with rc: %d, cycle: %d\n", rc,
                       cycle);
        }

        if (!cycle && rc & QUOTA_RET_INC_PENDING)
                *pending = 1;

        RETURN(rc);
}


static int filter_quota_check(struct obd_device *obd, unsigned int uid,
                              unsigned int gid, int npage, int *flag,
                              quota_acquire acquire)
{
        return quota_chk_acq_common(obd, uid, gid, npage, flag, LQUOTA_FLAGS_BLK,
                                    acquire);
}

/* when a block_write or inode_create rpc is finished, adjust the record for
 * pending blocks and inodes*/
static int quota_pending_commit(struct obd_device *obd, unsigned int uid,
                                unsigned int gid, int count, int isblk)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int i;
        __u32 id[MAXQUOTAS] = { uid, gid };
        struct qunit_data qdata[MAXQUOTAS];
        ENTRY;

        CLASSERT(MAXQUOTAS < 4);
        if (!sb_any_quota_enabled(qctxt->lqc_sb))
                RETURN(0);

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
                        spin_lock(&lqs->lqs_lock);
                        CDEBUG(D_QUOTA, "pending: %lu, count: %d.\n",
                               isblk ? lqs->lqs_bwrite_pending :
                               lqs->lqs_iwrite_pending, count);

                        if (isblk) {
                                if (lqs->lqs_bwrite_pending >= count) {
                                        lqs->lqs_bwrite_pending -= count;
                                        flag = 1;
                                } else {
                                        CDEBUG(D_ERROR,
                                               "there are too many blocks!\n");
                                }
                        } else {
                                if (lqs->lqs_iwrite_pending >= count) {
                                        lqs->lqs_iwrite_pending -= count;
                                        flag = 1;
                                } else {
                                        CDEBUG(D_ERROR,
                                               "there are too many files!\n");
                                }
                        }

                        spin_unlock(&lqs->lqs_lock);
                        lqs_putref(lqs);
                        /* When lqs_*_pening is changed back, we'll putref lqs
                         * here b=14784 */
                        if (flag)
                                lqs_putref(lqs);
                }
        }

        RETURN(0);
}

static int filter_quota_pending_commit(struct obd_device *obd, unsigned int uid,
                                       unsigned int gid, int npage)
{
        return quota_pending_commit(obd, uid, gid, npage, LQUOTA_FLAGS_BLK);
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

#ifdef HAVE_QUOTA64
        obt->obt_qfmt = LUSTRE_QUOTA_V2;
#else
        obt->obt_qfmt = LUSTRE_QUOTA_V1;
#endif
        mds->mds_quota_info.qi_version = LUSTRE_QUOTA_V2;
        atomic_set(&obt->obt_quotachecking, 1);
        /* initialize quota master and quota context */
        sema_init(&mds->mds_qonoff_sem, 1);
        rc = qctxt_init(&obt->obt_qctxt, obt->obt_sb, dqacq_handler);
        if (rc) {
                CERROR("initialize quota context failed! (rc:%d)\n", rc);
                RETURN(rc);
        }
        RETURN(rc);
}

static int mds_quota_cleanup(struct obd_device *obd)
{
        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        RETURN(0);
}

static int mds_quota_fs_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_quotactl oqctl;
        ENTRY;

        memset(&oqctl, 0, sizeof(oqctl));
        oqctl.qc_type = UGQUOTA;

        down(&mds->mds_qonoff_sem);
        mds_admin_quota_off(obd, &oqctl);
        up(&mds->mds_qonoff_sem);
        RETURN(0);
}

static int mds_quota_check(struct obd_device *obd, unsigned int uid,
                           unsigned int gid, int inodes, int *flag,
                           quota_acquire acquire)
{
        return quota_chk_acq_common(obd, uid, gid, inodes, flag, 0, acquire);
}

static int mds_quota_acquire(struct obd_device *obd, unsigned int uid,
                             unsigned int gid)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc;
        ENTRY;

        rc = qctxt_adjust_qunit(obd, qctxt, uid, gid, 0, 1);
        RETURN(rc);
}

static int mds_quota_pending_commit(struct obd_device *obd, unsigned int uid,
                                    unsigned int gid, int inodes)
{
        return quota_pending_commit(obd, uid, gid, inodes, 0);
}
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

        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        list_for_each_entry(oqi, &qinfo_hash[hashent], oqi_hash) {
                if (oqi->oqi_cli == cli &&
                    oqi->oqi_id == id && oqi->oqi_type == type)
                        return oqi;
        }
        return NULL;
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
quota_interface_t mds_quota_interface = {
        .quota_init     = mds_quota_init,
        .quota_exit     = mds_quota_exit,
        .quota_setup    = mds_quota_setup,
        .quota_cleanup  = mds_quota_cleanup,
        .quota_check    = target_quota_check,
        .quota_ctl      = mds_quota_ctl,
        .quota_fs_cleanup       =mds_quota_fs_cleanup,
        .quota_recovery = mds_quota_recovery,
        .quota_adjust   = mds_quota_adjust,
        .quota_chkquota = mds_quota_check,
        .quota_acquire  = mds_quota_acquire,
        .quota_pending_commit = mds_quota_pending_commit,
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
        .quota_acquire  = filter_quota_acquire,
        .quota_adjust   = filter_quota_adjust,
        .quota_chkquota = filter_quota_check,
        .quota_adjust_qunit   = filter_quota_adjust_qunit,
        .quota_pending_commit = filter_quota_pending_commit,
};
#endif /* __KERNEL__ */

quota_interface_t mdc_quota_interface = {
        .quota_ctl      = client_quota_ctl,
        .quota_check    = client_quota_check,
        .quota_poll_check = client_quota_poll_check,
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
        .quota_check    = lov_quota_check,
        .quota_ctl      = lov_quota_ctl,
        .quota_adjust_qunit = lov_quota_adjust_qunit,
};

#ifdef __KERNEL__
static int __init init_lustre_quota(void)
{
        int rc = qunit_cache_init();
        if (rc)
                return rc;
        PORTAL_SYMBOL_REGISTER(filter_quota_interface);
        PORTAL_SYMBOL_REGISTER(mds_quota_interface);
        PORTAL_SYMBOL_REGISTER(mdc_quota_interface);
        PORTAL_SYMBOL_REGISTER(osc_quota_interface);
        PORTAL_SYMBOL_REGISTER(lov_quota_interface);
        return 0;
}

static void /*__exit*/ exit_lustre_quota(void)
{
        PORTAL_SYMBOL_UNREGISTER(filter_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(mds_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(mdc_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(osc_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(lov_quota_interface);

        qunit_cache_cleanup();
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Quota");
MODULE_LICENSE("GPL");

cfs_module(lquota, "1.0.0", init_lustre_quota, exit_lustre_quota);

EXPORT_SYMBOL(mds_quota_interface);
EXPORT_SYMBOL(filter_quota_interface);
EXPORT_SYMBOL(mdc_quota_interface);
EXPORT_SYMBOL(osc_quota_interface);
EXPORT_SYMBOL(lov_quota_interface);
#endif /* __KERNEL */
