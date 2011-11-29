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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/quota/quota_master.c
 *
 * Lustre Quota Master request handler
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
#include <linux/quota.h>

#include <obd_class.h>
#include <lustre_quota.h>
#include <lustre_fsfilt.h>
#include <lustre_mds.h>

#include "quota_internal.h"

#ifdef HAVE_QUOTA_SUPPORT

/* lock ordering: mds->mds_qonoff_sem > dquot->dq_sem */
static struct list_head lustre_dquot_hash[NR_DQHASH];
static spinlock_t dquot_hash_lock = SPIN_LOCK_UNLOCKED;

cfs_mem_cache_t *lustre_dquot_cachep;

int lustre_dquot_init(void)
{
        int i;
        ENTRY;

        LASSERT(lustre_dquot_cachep == NULL);
        lustre_dquot_cachep = cfs_mem_cache_create("lustre_dquot_cache",
                                                   sizeof(struct lustre_dquot),
                                                   0, 0);
        if (!lustre_dquot_cachep)
                return (-ENOMEM);

        for (i = 0; i < NR_DQHASH; i++) {
                INIT_LIST_HEAD(lustre_dquot_hash + i);
        }
        RETURN(0);
}

void lustre_dquot_exit(void)
{
        int i;
        ENTRY;
        /* FIXME cleanup work ?? */

        for (i = 0; i < NR_DQHASH; i++) {
                LASSERT(list_empty(lustre_dquot_hash + i));
        }
        if (lustre_dquot_cachep) {
                int rc;
                rc = cfs_mem_cache_destroy(lustre_dquot_cachep);
                LASSERTF(rc == 0,"couldn't destroy lustre_dquot_cachep slab\n");
                lustre_dquot_cachep = NULL;
        }
        EXIT;
}

static inline int
dquot_hashfn(struct lustre_quota_info *info, unsigned int id, int type)
             __attribute__((__const__));

static inline int
dquot_hashfn(struct lustre_quota_info *info, unsigned int id, int type)
{
        unsigned long tmp = ((unsigned long)info >> L1_CACHE_SHIFT) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

/* caller must hold dquot_hash_lock */
static struct lustre_dquot *find_dquot(int hashent,
                                       struct lustre_quota_info *lqi, qid_t id,
                                       int type)
{
        struct lustre_dquot *dquot;
        ENTRY;

        LASSERT_SPIN_LOCKED(&dquot_hash_lock);
        list_for_each_entry(dquot, &lustre_dquot_hash[hashent], dq_hash) {
                if (dquot->dq_info == lqi &&
                    dquot->dq_id == id && dquot->dq_type == type)
                        RETURN(dquot);
        }
        RETURN(NULL);
}

static struct lustre_dquot *alloc_dquot(struct lustre_quota_info *lqi,
                                        qid_t id, int type)
{
        struct lustre_dquot *dquot = NULL;
        ENTRY;

        OBD_SLAB_ALLOC(dquot, lustre_dquot_cachep, CFS_ALLOC_IO, sizeof(*dquot));
        if (dquot == NULL)
                RETURN(NULL);

        INIT_LIST_HEAD(&dquot->dq_hash);
        init_mutex_locked(&dquot->dq_sem);
        dquot->dq_refcnt = 1;
        dquot->dq_info = lqi;
        dquot->dq_id = id;
        dquot->dq_type = type;
        dquot->dq_status = DQ_STATUS_AVAIL;

        RETURN(dquot);
}

static void free_dquot(struct lustre_dquot *dquot)
{
        OBD_SLAB_FREE(dquot, lustre_dquot_cachep, sizeof(*dquot));
}

static void insert_dquot_nolock(struct lustre_dquot *dquot)
{
        struct list_head *head = lustre_dquot_hash +
            dquot_hashfn(dquot->dq_info, dquot->dq_id, dquot->dq_type);
        LASSERT(list_empty(&dquot->dq_hash));
        list_add(&dquot->dq_hash, head);
}

static void remove_dquot_nolock(struct lustre_dquot *dquot)
{
        LASSERT(!list_empty(&dquot->dq_hash));
        list_del_init(&dquot->dq_hash);
}

static void lustre_dqput(struct lustre_dquot *dquot)
{
        ENTRY;
        spin_lock(&dquot_hash_lock);
        LASSERT(dquot->dq_refcnt);
        dquot->dq_refcnt--;
        if (!dquot->dq_refcnt) {
                remove_dquot_nolock(dquot);
                free_dquot(dquot);
        }
        spin_unlock(&dquot_hash_lock);
        EXIT;
}

static struct lustre_dquot *lustre_dqget(struct obd_device *obd,
                                         struct lustre_quota_info *lqi,
                                         qid_t id, int type)
{
        unsigned int hashent = dquot_hashfn(lqi, id, type);
        struct lustre_dquot *dquot, *empty;
        ENTRY;

        if ((empty = alloc_dquot(lqi, id, type)) == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        spin_lock(&dquot_hash_lock);
        if ((dquot = find_dquot(hashent, lqi, id, type)) != NULL) {
                dquot->dq_refcnt++;
                spin_unlock(&dquot_hash_lock);
                free_dquot(empty);
        } else {
                int rc;

                dquot = empty;
                insert_dquot_nolock(dquot);
                spin_unlock(&dquot_hash_lock);

                rc = fsfilt_dquot(obd, dquot, QFILE_RD_DQUOT);
                up(&dquot->dq_sem);
                if (rc) {
                        CERROR("can't read dquot from admin quotafile! "
                               "(rc:%d)\n", rc);
                        lustre_dqput(dquot);
                        RETURN(ERR_PTR(rc));
                }

        }

        LASSERT(dquot);
        RETURN(dquot);
}

static void init_oqaq(struct quota_adjust_qunit *oqaq,
                      struct lustre_quota_ctxt *qctxt,
                      qid_t id, int type)
{
        struct lustre_qunit_size *lqs = NULL;

        oqaq->qaq_id = id;
        oqaq->qaq_flags = type;
        lqs = quota_search_lqs(LQS_KEY(type, id), qctxt, 0);
        if (lqs && !IS_ERR(lqs)) {
                spin_lock(&lqs->lqs_lock);
                oqaq->qaq_bunit_sz = lqs->lqs_bunit_sz;
                oqaq->qaq_iunit_sz = lqs->lqs_iunit_sz;
                oqaq->qaq_flags    = lqs->lqs_flags;
                spin_unlock(&lqs->lqs_lock);
                lqs_putref(lqs);
        } else {
                CDEBUG(D_QUOTA, "Can't find the lustre qunit size!\n");
                oqaq->qaq_bunit_sz = qctxt->lqc_bunit_sz;
                oqaq->qaq_iunit_sz = qctxt->lqc_iunit_sz;
        }
}

int dqacq_adjust_qunit_sz(struct obd_device *obd, qid_t id, int type,
                          __u32 is_blk)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_ctxt *qctxt = &mds->mds_obt.obt_qctxt;
        __u32 ost_num = mds->mds_lov_objid_count, mdt_num = 1;
        struct quota_adjust_qunit *oqaq = NULL;
        unsigned int uid = 0, gid = 0;
        struct lustre_quota_info *info = &mds->mds_quota_info;
        struct lustre_dquot *dquot = NULL;
        int adjust_res = 0;
        int rc = 0;
        ENTRY;

        LASSERT(mds);
        dquot = lustre_dqget(obd, info, id, type);
        if (IS_ERR(dquot))
                RETURN(PTR_ERR(dquot));

        OBD_ALLOC_PTR(oqaq);
        if (!oqaq)
                GOTO(out, rc = -ENOMEM);

        down(&dquot->dq_sem);
        init_oqaq(oqaq, qctxt, id, type);

        rc = dquot_create_oqaq(qctxt, dquot, ost_num, mdt_num,
                               is_blk ? LQUOTA_FLAGS_ADJBLK :
                               LQUOTA_FLAGS_ADJINO, oqaq);

        if (rc < 0) {
                CERROR("create oqaq failed! (rc:%d)\n", rc);
                GOTO(out_sem, rc);
        }
        QAQ_DEBUG(oqaq, "show oqaq.\n")

        if (!QAQ_IS_ADJBLK(oqaq) && !QAQ_IS_ADJINO(oqaq))
                GOTO(out_sem, rc);

        /* adjust the mds slave qunit size */
        adjust_res = quota_adjust_slave_lqs(oqaq, qctxt);
        if (adjust_res <= 0) {
                if (adjust_res < 0) {
                        rc = adjust_res;
                        CERROR("adjust mds slave's qunit size failed! "
                               "(rc:%d)\n", rc);
                } else {
                        CDEBUG(D_QUOTA, "qunit doesn't need to be adjusted.\n");
                }
                GOTO(out_sem, rc);
        }

        if (type)
                gid = dquot->dq_id;
        else
                uid = dquot->dq_id;

        up(&dquot->dq_sem);

        rc = qctxt_adjust_qunit(obd, qctxt, uid, gid, is_blk, 0, NULL);
        if (rc == -EDQUOT || rc == -EBUSY) {
                CDEBUG(D_QUOTA, "rc: %d.\n", rc);
                rc = 0;
        }
        if (rc) {
                CERROR("%s: mds fail to adjust file quota! (rc:%d)\n",
                       obd->obd_name, rc);
                GOTO(out, rc);
        }

        /* only when block qunit is reduced, boardcast to osts */
        if ((adjust_res & LQS_BLK_DECREASE) && QAQ_IS_ADJBLK(oqaq))
                rc = obd_quota_adjust_qunit(mds->mds_lov_exp, oqaq, qctxt);

out:
        lustre_dqput(dquot);
        if (oqaq)
                OBD_FREE_PTR(oqaq);

        RETURN(rc);
out_sem:
	up(&dquot->dq_sem);
	goto out;
}

int dqacq_handler(struct obd_device *obd, struct qunit_data *qdata, int opc)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_ctxt *qctxt = &mds->mds_obt.obt_qctxt;
        struct lustre_quota_info *info = &mds->mds_quota_info;
        struct lustre_dquot *dquot = NULL;
        __u64 *usage = NULL;
        __u64 hlimit = 0, slimit = 0;
        time_t *time = NULL;
        unsigned int grace = 0;
        struct lustre_qunit_size *lqs = NULL;
        int rc = 0;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_OBD_DQACQ, -EIO);

        dquot = lustre_dqget(obd, info, qdata->qd_id, QDATA_IS_GRP(qdata));
        if (IS_ERR(dquot))
                RETURN(PTR_ERR(dquot));

        DQUOT_DEBUG(dquot, "get dquot in dqacq_handler\n");
        QINFO_DEBUG(dquot->dq_info, "get dquot in dqadq_handler\n");

        down(&mds->mds_qonoff_sem);
        down(&dquot->dq_sem);

        if (dquot->dq_status & DQ_STATUS_RECOVERY) {
                DQUOT_DEBUG(dquot, "this dquot is under recovering.\n");
                GOTO(out, rc = -EBUSY);
        }

        if (QDATA_IS_BLK(qdata)) {
                grace = info->qi_info[QDATA_IS_GRP(qdata)].dqi_bgrace;
                usage = &dquot->dq_dqb.dqb_curspace;
                hlimit = dquot->dq_dqb.dqb_bhardlimit;
                slimit = dquot->dq_dqb.dqb_bsoftlimit;
                time = &dquot->dq_dqb.dqb_btime;
        } else {
                grace = info->qi_info[QDATA_IS_GRP(qdata)].dqi_igrace;
                usage = (__u64 *) & dquot->dq_dqb.dqb_curinodes;
                hlimit = dquot->dq_dqb.dqb_ihardlimit;
                slimit = dquot->dq_dqb.dqb_isoftlimit;
                time = &dquot->dq_dqb.dqb_itime;
        }

        /* if the quota limit in admin quotafile is zero, we just inform
         * slave to clear quota limit with zero qd_count */
        if (hlimit == 0 && slimit == 0) {
                qdata->qd_count = 0;
                GOTO(out, rc);
        }

        switch (opc) {
        case QUOTA_DQACQ:
                if (hlimit &&
                    QUSG(*usage + qdata->qd_count, QDATA_IS_BLK(qdata)) > hlimit)
                {
                        if (QDATA_IS_CHANGE_QS(qdata) &&
                            QUSG(*usage, QDATA_IS_BLK(qdata)) < hlimit)
                                qdata->qd_count = (hlimit -
                                        QUSG(*usage, QDATA_IS_BLK(qdata)))
                                        * (QDATA_IS_BLK(qdata) ?
                                           QUOTABLOCK_SIZE : 1);
                        else
                                GOTO(out, rc = -EDQUOT);
                }

                if (slimit &&
                    QUSG(*usage + qdata->qd_count, QDATA_IS_BLK(qdata)) > slimit) {
                        if (*time && cfs_time_current_sec() >= *time)
                                GOTO(out, rc = -EDQUOT);
                        else if (!*time)
                                *time = cfs_time_current_sec() + grace;
                }

                *usage += qdata->qd_count;
                break;
        case QUOTA_DQREL:
                /* The usage in administrative file might be incorrect before
                 * recovery done */
                if (*usage < qdata->qd_count)
                        *usage = 0;
                else
                        *usage -= qdata->qd_count;

                /* (usage <= soft limit) but not (usage < soft limit) */
                if (!slimit || QUSG(*usage, QDATA_IS_BLK(qdata)) <= slimit)
                        *time = 0;
                break;
        default:
                LBUG();
        }

        rc = fsfilt_dquot(obd, dquot, QFILE_WR_DQUOT);
        EXIT;
out:
        up(&dquot->dq_sem);
        up(&mds->mds_qonoff_sem);
        lustre_dqput(dquot);
        if (rc != -EDQUOT)
                dqacq_adjust_qunit_sz(obd, qdata->qd_id, QDATA_IS_GRP(qdata),
                                      QDATA_IS_BLK(qdata));

        lqs = quota_search_lqs(LQS_KEY(QDATA_IS_GRP(qdata), qdata->qd_id),
                               qctxt, 0);
        if (lqs == NULL || IS_ERR(lqs)) {
                CDEBUG(D_INFO, "Can't find the lustre qunit size!\n");
                qdata->qd_qunit  = QDATA_IS_BLK(qdata) ? qctxt->lqc_bunit_sz :
                                                         qctxt->lqc_iunit_sz;
        } else {
                spin_lock(&lqs->lqs_lock);
                qdata->qd_qunit  = QDATA_IS_BLK(qdata) ? lqs->lqs_bunit_sz :
                                                         lqs->lqs_iunit_sz;
                spin_unlock(&lqs->lqs_lock);
        }

        if (QDATA_IS_BLK(qdata))
                QDATA_SET_ADJBLK(qdata);
        else
                QDATA_SET_ADJINO(qdata);

        QDATA_DEBUG(qdata, "alloc/release qunit in dqacq_handler\n");
        if (lqs)
                lqs_putref(lqs);

        return rc;
}

int mds_quota_adjust(struct obd_device *obd, unsigned int qcids[],
                     unsigned int qpids[], int rc, int opc)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc2 = 0;
        ENTRY;

        if (rc && rc != -EDQUOT && rc != ENOLCK)
                RETURN(0);

        switch (opc) {
        case FSFILT_OP_RENAME:
                /* acquire/release block quota on owner of original parent */
                rc2 = qctxt_adjust_qunit(obd, qctxt, qpids[2], qpids[3], 1, 0,
                                         NULL);
                /* fall-through */
        case FSFILT_OP_SETATTR:
                /* acquire/release file quota on original owner */
                rc2 |= qctxt_adjust_qunit(obd, qctxt, qpids[0], qpids[1], 0, 0,
                                          NULL);
                /* fall-through */
        case FSFILT_OP_CREATE:
        case FSFILT_OP_UNLINK:
                /* acquire/release file/block quota on owner of child
                 * (or current owner) */
                rc2 |= qctxt_adjust_qunit(obd, qctxt, qcids[0], qcids[1], 0, 0,
                                          NULL);
                rc2 |= qctxt_adjust_qunit(obd, qctxt, qcids[0], qcids[1], 1, 0,
                                          NULL);
                /* acquire/release block quota on owner of parent
                 * (or original owner) */
                rc2 |= qctxt_adjust_qunit(obd, qctxt, qpids[0], qpids[1], 1, 0,
                                          NULL);
                break;
        default:
                LBUG();
                break;
        }

        if (rc2)
                CDEBUG(D_QUOTA,
                       "mds adjust qunit %ssuccessfully! (opc:%d rc:%d)\n",
                       rc2 == QUOTA_REQ_RETURNED ? "" : "un", opc, rc2);
        RETURN(0);
}

int filter_quota_adjust(struct obd_device *obd, unsigned int qcids[],
                        unsigned int qpids[], int rc, int opc)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc2 = 0;
        ENTRY;

        if (rc && rc != -EDQUOT)
                RETURN(0);

        switch (opc) {
        case FSFILT_OP_SETATTR:
                /* acquire/release block quota on original & current owner */
                rc = qctxt_adjust_qunit(obd, qctxt, qcids[0], qcids[1], 1, 0,
                                        NULL);
                rc2 = qctxt_adjust_qunit(obd, qctxt, qpids[0], qpids[1], 1, 0,
                                         NULL);
                break;
        case FSFILT_OP_UNLINK:
                /* release block quota on this owner */
        case FSFILT_OP_CREATE: /* XXX for write operation on obdfilter */
                /* acquire block quota on this owner */
                rc = qctxt_adjust_qunit(obd, qctxt, qcids[0], qcids[1], 1, 0,
                                        NULL);
                break;
        default:
                LBUG();
                break;
        }

        if (rc || rc2) {
                if (!rc)
                        rc = rc2;
                CDEBUG(D_QUOTA,
                       "filter adjust qunit %ssuccessfully! (opc:%d rc%d)\n",
                       rc == QUOTA_REQ_RETURNED ? "" : "un", opc, rc);
        }

        RETURN(0);
}

static const char prefix[] = "OBJECTS/";

int mds_quota_get_version(struct obd_device *obd,
                          lustre_quota_version_t *aver,
                          lustre_quota_version_t *over)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;

        if (!atomic_dec_and_test(&mds->mds_obt.obt_quotachecking)) {
                CDEBUG(D_INFO, "other people are doing quotacheck\n");
                atomic_inc(&mds->mds_obt.obt_quotachecking);
                RETURN(-EBUSY);
        }
        down(&mds->mds_qonoff_sem);

        *aver = qinfo->qi_version;
        *over = mds->mds_obt.obt_qfmt;

        up(&mds->mds_qonoff_sem);
        atomic_inc(&mds->mds_obt.obt_quotachecking);

        return 0;
}

int mds_quota_set_version(struct obd_device *obd,
                          lustre_quota_version_t aver,
                          lustre_quota_version_t over)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        int rc = 0, i;

        LASSERT(aver == LUSTRE_QUOTA_V1 || aver == LUSTRE_QUOTA_V2);
        LASSERT(over == LUSTRE_QUOTA_V1 || over == LUSTRE_QUOTA_V2);

        if (!atomic_dec_and_test(&mds->mds_obt.obt_quotachecking)) {
                CDEBUG(D_INFO, "other people are doing quotacheck\n");
                atomic_inc(&mds->mds_obt.obt_quotachecking);
                RETURN(-EBUSY);
        }

        down(&mds->mds_qonoff_sem);

        /* no need to change version? nothing to do then */
        if (qinfo->qi_version != aver) {
                for (i = 0; i < MAXQUOTAS; i++) {
                        /* quota file has been opened ? */
                        if (qinfo->qi_files[i]) {
                                rc = -EBUSY;
                                goto out;
                        }
                }

                CDEBUG(D_INFO, "changing quota version %d -> %d\n",
                       qinfo->qi_version, aver);
                qinfo->qi_version = aver;
        }

        mds->mds_obt.obt_qfmt = over;

out:
        up(&mds->mds_qonoff_sem);
        atomic_inc(&mds->mds_obt.obt_quotachecking);

        return rc;
}

int mds_quota_invalidate(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        int rc = 0, i;
        char *quotafiles_v1[] = LUSTRE_ADMIN_QUOTAFILES_V1;
        char *quotafiles_v2[] = LUSTRE_ADMIN_QUOTAFILES_V2;
        char name[64];
        struct lvfs_run_ctxt saved;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA &&
            oqctl->qc_type != UGQUOTA)
                return -EINVAL;

        down(&mds->mds_qonoff_sem);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        for (i = 0; i < MAXQUOTAS; i++) {
                struct file *fp;
                char* quotafile = (qinfo->qi_version == LUSTRE_QUOTA_V1)?
                                   quotafiles_v1[i]:quotafiles_v2[i];

                if (!Q_TYPESET(oqctl, i))
                        continue;

                /* quota file has been opened ? */
                if (qinfo->qi_files[i]) {
                        rc = -EBUSY;
                        goto out;
                }

                LASSERT(strlen(quotafile) + sizeof(prefix) <= sizeof(name));
                sprintf(name, "%s%s", prefix, quotafile);

                fp = filp_open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
                if (IS_ERR(fp)) {
                        rc = PTR_ERR(fp);
                        CERROR("%s: error invalidating admin quotafile %s (rc:%d)\n",
                               obd->obd_name, name, rc);
                }
                else
                        filp_close(fp, 0);
        }

out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        up(&mds->mds_qonoff_sem);

        return rc;
}

int mds_quota_finvalidate(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_device_target *obt = &obd->u.obt;
        int rc;
        struct lvfs_run_ctxt saved;
        ENTRY;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA &&
            oqctl->qc_type != UGQUOTA)
                RETURN(-EINVAL);

        if (!atomic_dec_and_test(&obt->obt_quotachecking)) {
                CDEBUG(D_INFO, "other people are doing quotacheck\n");
                GOTO(out, rc = -EBUSY);
        }

        if (obt->obt_qctxt.lqc_flags & UGQUOTA2LQC(oqctl->qc_type))
                GOTO(out, rc = -EBUSY);

        down(&mds->mds_qonoff_sem);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        oqctl->qc_cmd = Q_FINVALIDATE;
        rc = fsfilt_quotactl(obd, obt->obt_sb, oqctl);
        if (!rc)
                rc = obd_quotactl(mds->mds_lov_exp, oqctl);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        up(&mds->mds_qonoff_sem);
        EXIT;
out:
        atomic_inc(&obt->obt_quotachecking);

        return rc;
}

int init_admin_quotafiles(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        char *quotafiles_v1[] = LUSTRE_ADMIN_QUOTAFILES_V1;
        char *quotafiles_v2[] = LUSTRE_ADMIN_QUOTAFILES_V2;
        struct lvfs_run_ctxt saved;
        char name[64];
        int i, rc = 0;
        ENTRY;

        down(&mds->mds_qonoff_sem);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        for (i = 0; i < MAXQUOTAS && !rc; i++) {
                struct file *fp;
                char* quotafile = (qinfo->qi_version == LUSTRE_QUOTA_V1)?
                                        quotafiles_v1[i]:quotafiles_v2[i];

                if (!Q_TYPESET(oqctl, i))
                        continue;

                /* quota file has been opened ? */
                if (qinfo->qi_files[i]) {
                        CWARN("init %s admin quotafile while quota on.\n",
                              i == USRQUOTA ? "user" : "group");
                        continue;
                }

                LASSERT(strlen(quotafile) + sizeof(prefix) <= sizeof(name));
                sprintf(name, "%s%s", prefix, quotafile);

                /* check if quota file exists and is correct */
                fp = filp_open(name, O_RDONLY, 0);
                if (!IS_ERR(fp)) {
                        /* irregular file is not the right place for quota */
                        if (!S_ISREG(fp->f_dentry->d_inode->i_mode)) {
                                CERROR("%s: admin quota file %s is not "
                                       "regular!", obd->obd_name, quotafile);
                                filp_close(fp, 0);
                                rc = -EINVAL;
                                break;
                        }
                        qinfo->qi_files[i] = fp;
                        rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_CHK);
                        qinfo->qi_files[i] = 0;
                        filp_close(fp, 0);
                }
                else
                        rc = PTR_ERR(fp);

                if (!rc)
                        continue;

                /* -EINVAL may be returned by quotainfo for bad quota file */
                if (rc != -ENOENT && rc != -EINVAL) {
                        CERROR("%s: error opening old quota file %s (%d)\n",
                               obd->obd_name, name, rc);
                        break;
                }

                CDEBUG(D_INFO, "%s new quota file %s\n", name,
                       rc == -ENOENT ? "creating" : "overwriting");

                /* create quota file overwriting old if needed */
                fp = filp_open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
                if (IS_ERR(fp)) {
                        rc = PTR_ERR(fp);
                        CERROR("%s: error creating admin quotafile %s (rc:%d)\n",
                               obd->obd_name, name, rc);
                        break;
                }

                qinfo->qi_files[i] = fp;

                switch (qinfo->qi_version) {
                case LUSTRE_QUOTA_V1:
                        rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_INIT_INFO);
                        if (rc)
                                CERROR("%s: error init %s admin quotafile! "
                                       "(rc:%d)\n", obd->obd_name,
                                       i == USRQUOTA ? "user" : "group", rc);
                        break;
                case LUSTRE_QUOTA_V2:
                        rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_CONVERT);
                        if (rc)
                                CERROR("%s: error convert %s admin quotafile! "
                                       "(rc:%d)\n", obd->obd_name,
                                       i == USRQUOTA ? "user" : "group", rc);
                        break;
                default:
                        LBUG();
                }

                filp_close(fp, 0);
                qinfo->qi_files[i] = NULL;
        }

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        up(&mds->mds_qonoff_sem);

        RETURN(rc);
}

static int close_quota_files(struct obd_quotactl *oqctl,
                             struct lustre_quota_info *qinfo)
{
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < MAXQUOTAS; i++) {
                if (!Q_TYPESET(oqctl, i))
                        continue;
                if (qinfo->qi_files[i] == NULL) {
                        rc = -ESRCH;
                        continue;
                }
                filp_close(qinfo->qi_files[i], 0);
                qinfo->qi_files[i] = NULL;
        }
        RETURN(rc);
}

int mds_admin_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        const char *quotafiles_v1[] = LUSTRE_ADMIN_QUOTAFILES_V1;
        const char *quotafiles_v2[] = LUSTRE_ADMIN_QUOTAFILES_V2;
        char name[64];
        int i, rc = 0;
        ENTRY;

        /* open admin quota files and read quotafile info */
        for (i = 0; i < MAXQUOTAS; i++) {
                struct file *fp;
                const char* quotafile = qinfo->qi_version == LUSTRE_QUOTA_V1?
                                        quotafiles_v1[i] : quotafiles_v2[i];

                if (!Q_TYPESET(oqctl, i) || qinfo->qi_files[i] != NULL)
                        continue;

                LASSERT(strlen(quotafile)
                        + sizeof(prefix) <= sizeof(name));
                sprintf(name, "%s%s", prefix, quotafile);

                fp = filp_open(name, O_RDWR, 0);
                /* handle transparent migration to 64 bit quota file */
                if (IS_ERR(fp) && PTR_ERR(fp) == -ENOENT &&
                    qinfo->qi_version == LUSTRE_QUOTA_V2) {
                        CDEBUG(D_INFO, "attempting to convert V1 quota file to"
                                       " V2 format\n");
                        fp = filp_open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
                        if (!IS_ERR(fp)) {
                                qinfo->qi_files[i] = fp;
                                rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_CONVERT);
                                if (rc) {
                                        CERROR("error convert %s admin "
                                               "quotafile! (rc:%d)\n",
                                               i == USRQUOTA ? "user" : "group",
                                               rc);
                                        break;
                                }
                        }
                }

                if (IS_ERR(fp) || !S_ISREG(fp->f_dentry->d_inode->i_mode)) {
                        rc = IS_ERR(fp) ? PTR_ERR(fp) : -EINVAL;
                        CERROR("error open/create %s! (rc:%d)\n", name, rc);
                        break;
                }
                qinfo->qi_files[i] = fp;

                rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_CHK);
                if (rc) {
                        CERROR("invalid quota file %s! (rc:%d)\n", name, rc);
                        break;
                }

                rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_RD_INFO);
                if (rc) {
                        CERROR("error read quotainfo of %s! (rc:%d)\n", name,
                               rc);
                        break;
                }
        }

        if (rc && rc != -EBUSY)
                close_quota_files(oqctl, qinfo);

        RETURN(rc);
}

int mds_admin_quota_off(struct obd_device *obd,
                        struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        int rc;
        ENTRY;

        /* close admin quota files */
        rc = close_quota_files(oqctl, qinfo);
        RETURN(rc);
}

int mds_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        int rc;
        ENTRY;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA &&
            oqctl->qc_type != UGQUOTA)
                RETURN(-EINVAL);

        rc = generic_quota_on(obd, oqctl, 1);

        RETURN(rc);
}

int mds_quota_off(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_device_target *obt = &obd->u.obt;
        struct lvfs_run_ctxt saved;
        int rc, rc2;
        ENTRY;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA &&
            oqctl->qc_type != UGQUOTA)
                RETURN(-EINVAL);

        if (!atomic_dec_and_test(&obt->obt_quotachecking)) {
                CDEBUG(D_INFO, "other people are doing quotacheck\n");
                atomic_inc(&obt->obt_quotachecking);
                RETURN(-EBUSY);
        }

        down(&mds->mds_qonoff_sem);
        /* close admin quota files */
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        mds_admin_quota_off(obd, oqctl);

        rc = obd_quotactl(mds->mds_lov_exp, oqctl);
        rc2 = fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);
        if (!rc2)
                obt->obt_qctxt.lqc_flags &= ~UGQUOTA2LQC(oqctl->qc_type);

        CDEBUG(D_QUOTA, "%s: quotaoff type:flags:rc %u:%lu:%d\n",
               obd->obd_name, oqctl->qc_type, obt->obt_qctxt.lqc_flags, rc);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        up(&mds->mds_qonoff_sem);
        atomic_inc(&obt->obt_quotachecking);

        RETURN(rc ?: rc2);
}

int mds_set_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        struct obd_dqinfo *dqinfo = &oqctl->qc_dqinfo;
        int rc;
        ENTRY;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA)
                RETURN(-EINVAL);

        down(&mds->mds_qonoff_sem);
        if (qinfo->qi_files[oqctl->qc_type] == NULL) {
                rc = -ESRCH;
                goto out;
        }

        qinfo->qi_info[oqctl->qc_type].dqi_bgrace = dqinfo->dqi_bgrace;
        qinfo->qi_info[oqctl->qc_type].dqi_igrace = dqinfo->dqi_igrace;
        qinfo->qi_info[oqctl->qc_type].dqi_flags = dqinfo->dqi_flags;

        rc = fsfilt_quotainfo(obd, qinfo, oqctl->qc_type, QFILE_WR_INFO);

out:
        up(&mds->mds_qonoff_sem);
        RETURN(rc);
}

int mds_get_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        struct obd_dqinfo *dqinfo = &oqctl->qc_dqinfo;
        int rc = 0;
        ENTRY;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA)
                RETURN(-EINVAL);

        down(&mds->mds_qonoff_sem);
        if (qinfo->qi_files[oqctl->qc_type] == NULL) {
                rc = -ESRCH;
                goto out;
        }

        dqinfo->dqi_bgrace = qinfo->qi_info[oqctl->qc_type].dqi_bgrace;
        dqinfo->dqi_igrace = qinfo->qi_info[oqctl->qc_type].dqi_igrace;
        dqinfo->dqi_flags = qinfo->qi_info[oqctl->qc_type].dqi_flags;

out:
        up(&mds->mds_qonoff_sem);
        RETURN(rc);
}

int dquot_create_oqaq(struct lustre_quota_ctxt *qctxt,
                      struct lustre_dquot *dquot, __u32 ost_num, __u32 mdt_num,
                      int type, struct quota_adjust_qunit *oqaq)
{
        __u64 bunit_curr_o, iunit_curr_o;
        unsigned long shrink_qunit_limit = qctxt->lqc_cqs_boundary_factor;
        unsigned long cqs_factor = qctxt->lqc_cqs_qs_factor;
        __u64 blimit = dquot->dq_dqb.dqb_bhardlimit ?
                dquot->dq_dqb.dqb_bhardlimit : dquot->dq_dqb.dqb_bsoftlimit;
        __u64 ilimit = dquot->dq_dqb.dqb_ihardlimit ?
                dquot->dq_dqb.dqb_ihardlimit : dquot->dq_dqb.dqb_isoftlimit;
        int rc = 0;
        ENTRY;

        if (!dquot || !oqaq)
                RETURN(-EINVAL);
        LASSERT_SEM_LOCKED(&dquot->dq_sem);
        LASSERT(oqaq->qaq_iunit_sz);
        LASSERT(oqaq->qaq_bunit_sz);

        /* don't change qunit size */
        if (!qctxt->lqc_switch_qs)
                RETURN(rc);

        bunit_curr_o = oqaq->qaq_bunit_sz;
        iunit_curr_o = oqaq->qaq_iunit_sz;

        if (dquot->dq_type == GRPQUOTA)
                QAQ_SET_GRP(oqaq);

        if ((type & LQUOTA_FLAGS_ADJBLK) && blimit) {
                __u64 b_limitation =
                        oqaq->qaq_bunit_sz * ost_num * shrink_qunit_limit;
                /* enlarge block qunit size */
                while (blimit >
                       QUSG(dquot->dq_dqb.dqb_curspace + 2 * b_limitation, 1)) {
                        oqaq->qaq_bunit_sz =
                                QUSG(oqaq->qaq_bunit_sz * cqs_factor, 1)
                                << QUOTABLOCK_BITS;
                        b_limitation = oqaq->qaq_bunit_sz * ost_num *
                                shrink_qunit_limit;
                }

                if (oqaq->qaq_bunit_sz > qctxt->lqc_bunit_sz)
                        oqaq->qaq_bunit_sz = qctxt->lqc_bunit_sz;

                /* shrink block qunit size */
                while (blimit <
                       QUSG(dquot->dq_dqb.dqb_curspace + b_limitation, 1)) {
                        do_div(oqaq->qaq_bunit_sz , cqs_factor);
                        oqaq->qaq_bunit_sz = QUSG(oqaq->qaq_bunit_sz, 1) <<
                                QUOTABLOCK_BITS;
                        b_limitation = oqaq->qaq_bunit_sz * ost_num *
                                shrink_qunit_limit;
                        if (oqaq->qaq_bunit_sz <  qctxt->lqc_cqs_least_bunit)
                                break;
                }

                if (oqaq->qaq_bunit_sz < qctxt->lqc_cqs_least_bunit)
                        oqaq->qaq_bunit_sz = qctxt->lqc_cqs_least_bunit;

                if (bunit_curr_o != oqaq->qaq_bunit_sz)
                        QAQ_SET_ADJBLK(oqaq);

        }

        if ((type & LQUOTA_FLAGS_ADJINO) && ilimit) {
                __u64 i_limitation =
                        oqaq->qaq_iunit_sz * mdt_num * shrink_qunit_limit;
                /* enlarge file qunit size */
                while (ilimit > dquot->dq_dqb.dqb_curinodes
                       + 2 * i_limitation) {
                        oqaq->qaq_iunit_sz = oqaq->qaq_iunit_sz * cqs_factor;
                        i_limitation = oqaq->qaq_iunit_sz * mdt_num *
                                shrink_qunit_limit;
                }

                if (oqaq->qaq_iunit_sz > qctxt->lqc_iunit_sz)
                        oqaq->qaq_iunit_sz = qctxt->lqc_iunit_sz;

                /* shrink file qunit size */
                while (ilimit < dquot->dq_dqb.dqb_curinodes
                       + i_limitation) {
                        do_div(oqaq->qaq_iunit_sz, cqs_factor);
                        i_limitation = oqaq->qaq_iunit_sz * mdt_num *
                                       shrink_qunit_limit;
                        if (oqaq->qaq_iunit_sz < qctxt->lqc_cqs_least_iunit)
                                break;
                }

                if (oqaq->qaq_iunit_sz < qctxt->lqc_cqs_least_iunit)
                        oqaq->qaq_iunit_sz = qctxt->lqc_cqs_least_iunit;

                if (iunit_curr_o != oqaq->qaq_iunit_sz)
                        QAQ_SET_ADJINO(oqaq);

        }

        QAQ_DEBUG(oqaq, "the oqaq computed\n");

        RETURN(rc);
}

static int mds_init_slave_ilimits(struct obd_device *obd,
                                  struct obd_quotactl *oqctl, int set)
{
        /* XXX: for file limits only adjust local now */
        struct obd_device_target *obt = &obd->u.obt;
        struct lustre_quota_ctxt *qctxt = &obt->obt_qctxt;
        unsigned int uid = 0, gid = 0;
        struct obd_quotactl *ioqc = NULL;
        struct lustre_qunit_size *lqs;
        int flag;
        int rc;
        ENTRY;

        /* if we are going to set zero limit, needn't init slaves */
        if (!oqctl->qc_dqblk.dqb_ihardlimit && !oqctl->qc_dqblk.dqb_isoftlimit &&
            !set)
                RETURN(0);

        OBD_ALLOC_PTR(ioqc);
        if (!ioqc)
                RETURN(-ENOMEM);

        flag = oqctl->qc_dqblk.dqb_ihardlimit ||
               oqctl->qc_dqblk.dqb_isoftlimit || !set;
        ioqc->qc_cmd = flag ? Q_INITQUOTA : Q_SETQUOTA;
        ioqc->qc_id = oqctl->qc_id;
        ioqc->qc_type = oqctl->qc_type;
        ioqc->qc_dqblk.dqb_valid = QIF_ILIMITS;
        ioqc->qc_dqblk.dqb_ihardlimit = flag ? MIN_QLIMIT : 0;

        /* build lqs for mds */
        lqs = quota_search_lqs(LQS_KEY(oqctl->qc_type, oqctl->qc_id),
                               qctxt, flag ? 1 : 0);
        if (lqs && !IS_ERR(lqs)) {
                if (flag)
                        lqs->lqs_flags |= QI_SET;
                else
                        lqs->lqs_flags &= ~QI_SET;
                lqs_putref(lqs);
        } else {
                CERROR("fail to %s lqs for inode(%s id: %u)!\n",
                       flag ? "create" : "search",
                       oqctl->qc_type ? "group" : "user",
                       oqctl->qc_id);
                GOTO(out, rc = PTR_ERR(lqs));
        }

        /* set local limit to MIN_QLIMIT */
        rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, ioqc);
        if (rc)
                GOTO(out, rc);

        /* trigger local qunit pre-acquire */
        if (oqctl->qc_type == USRQUOTA)
                uid = oqctl->qc_id;
        else
                gid = oqctl->qc_id;

        rc = qctxt_adjust_qunit(obd, &obd->u.obt.obt_qctxt, uid, gid, 0, 0,
                                NULL);
        if (rc == -EDQUOT || rc == -EBUSY) {
                CDEBUG(D_QUOTA, "rc: %d.\n", rc);
                rc = 0;
        }
        if (rc) {
                CDEBUG(D_QUOTA,"error mds adjust local file quota! (rc:%d)\n",
                       rc);
                GOTO(out, rc);
        }
        /* FIXME initialize all slaves in CMD */
        EXIT;
out:
        if (ioqc)
                OBD_FREE_PTR(ioqc);
        return rc;
}

static int mds_init_slave_blimits(struct obd_device *obd,
                                  struct obd_quotactl *oqctl, int set)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct lustre_quota_ctxt *qctxt = &obt->obt_qctxt;
        struct mds_obd *mds = &obd->u.mds;
        struct obd_quotactl *ioqc;
        struct lustre_qunit_size *lqs;
        unsigned int uid = 0, gid = 0;
        int rc;
        int flag;
        ENTRY;

        /* if we are going to set zero limit, needn't init slaves */
        if (!oqctl->qc_dqblk.dqb_bhardlimit && !oqctl->qc_dqblk.dqb_bsoftlimit &&
            !set)
                RETURN(0);

        OBD_ALLOC_PTR(ioqc);
        if (!ioqc)
                RETURN(-ENOMEM);

        flag = oqctl->qc_dqblk.dqb_bhardlimit ||
               oqctl->qc_dqblk.dqb_bsoftlimit || !set;
        ioqc->qc_cmd = flag ? Q_INITQUOTA : Q_SETQUOTA;
        ioqc->qc_id = oqctl->qc_id;
        ioqc->qc_type = oqctl->qc_type;
        ioqc->qc_dqblk.dqb_valid = QIF_BLIMITS;
        ioqc->qc_dqblk.dqb_bhardlimit = flag ? MIN_QLIMIT : 0;

        /* build lqs for mds */
        lqs = quota_search_lqs(LQS_KEY(oqctl->qc_type, oqctl->qc_id),
                               qctxt, flag ? 1 : 0);
        if (lqs && !IS_ERR(lqs)) {
                if (flag)
                        lqs->lqs_flags |= QB_SET;
                else
                        lqs->lqs_flags &= ~QB_SET;
                lqs_putref(lqs);
        } else {
                CERROR("fail to %s lqs for block(%s id: %u)!\n",
                       flag ? "create" : "search",
                       oqctl->qc_type ? "group" : "user",
                       oqctl->qc_id);
                GOTO(out, rc = PTR_ERR(lqs));
        }

        rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, ioqc);
        if (rc)
                GOTO(out, rc);

        /* trigger local qunit pre-acquire */
        if (oqctl->qc_type == USRQUOTA)
                uid = oqctl->qc_id;
        else
                gid = oqctl->qc_id;

        /* initialize all slave's limit */
        rc = obd_quotactl(mds->mds_lov_exp, ioqc);

        rc = qctxt_adjust_qunit(obd, &obd->u.obt.obt_qctxt, uid, gid, 1, 0,
                                NULL);
        if (rc == -EDQUOT || rc == -EBUSY) {
                CDEBUG(D_QUOTA, "rc: %d.\n", rc);
                rc = 0;
        }
        if (rc) {
                CERROR("error mds adjust local block quota! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        EXIT;
out:
        OBD_FREE_PTR(ioqc);
        return rc;
}

static void adjust_lqs(struct obd_device *obd, struct quota_adjust_qunit *qaq)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc = 0;

        QAQ_SET_CREATE_LQS(qaq);
        /* adjust local lqs */
        rc = quota_adjust_slave_lqs(qaq, qctxt);
        if (rc < 0)
                CERROR("adjust master's qunit size failed!(rc=%d)\n", rc);

        /* adjust remote lqs */
        if (QAQ_IS_ADJBLK(qaq)) {
                rc = obd_quota_adjust_qunit(obd->u.mds.mds_lov_exp, qaq, qctxt);
                if (rc < 0)
                        CERROR("adjust slaves' qunit size failed!(rc=%d)\n", rc);

        }
}

int mds_set_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_ctxt *qctxt = &mds->mds_obt.obt_qctxt;
        struct obd_device *lov_obd = class_exp2obd(mds->mds_lov_exp);
        struct lov_obd *lov = &lov_obd->u.lov;
        struct quota_adjust_qunit *oqaq = NULL;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        __u64 ihardlimit, isoftlimit, bhardlimit, bsoftlimit;
        time_t btime, itime;
        struct lustre_dquot *dquot;
        struct obd_dqblk *dqblk = &oqctl->qc_dqblk;
        /* orig_set means if quota was set before; now_set means we are
         * setting/cancelling quota */
        int orig_set, now_set;
        int rc, rc2 = 0, flag = 0;
        ENTRY;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA)
                RETURN(-EINVAL);

        OBD_ALLOC_PTR(oqaq);
        if (!oqaq)
                RETURN(-ENOMEM);
        down(&mds->mds_qonoff_sem);
        init_oqaq(oqaq, qctxt, oqctl->qc_id, oqctl->qc_type);

        if (qinfo->qi_files[oqctl->qc_type] == NULL)
                GOTO(out_sem, rc = -ESRCH);

        dquot = lustre_dqget(obd, qinfo, oqctl->qc_id, oqctl->qc_type);
        if (IS_ERR(dquot))
                GOTO(out_sem, rc = PTR_ERR(dquot));
        DQUOT_DEBUG(dquot, "get dquot in mds_set_blk\n");
        QINFO_DEBUG(dquot->dq_info, "get dquot in mds_set_blk\n");

        down(&dquot->dq_sem);

        if (dquot->dq_status) {
                up(&dquot->dq_sem);
                lustre_dqput(dquot);
                GOTO(out_sem, rc = -EBUSY);
        }
        dquot->dq_status |= DQ_STATUS_SET;

        ihardlimit = dquot->dq_dqb.dqb_ihardlimit;
        isoftlimit = dquot->dq_dqb.dqb_isoftlimit;
        bhardlimit = dquot->dq_dqb.dqb_bhardlimit;
        bsoftlimit = dquot->dq_dqb.dqb_bsoftlimit;
        btime = dquot->dq_dqb.dqb_btime;
        itime = dquot->dq_dqb.dqb_itime;

        if (dqblk->dqb_valid & QIF_BTIME)
                dquot->dq_dqb.dqb_btime = dqblk->dqb_btime;
        if (dqblk->dqb_valid & QIF_ITIME)
                dquot->dq_dqb.dqb_itime = dqblk->dqb_itime;

        if (dqblk->dqb_valid & QIF_BLIMITS) {
                dquot->dq_dqb.dqb_bhardlimit = dqblk->dqb_bhardlimit;
                dquot->dq_dqb.dqb_bsoftlimit = dqblk->dqb_bsoftlimit;
                /* clear usage (limit pool) */
                if (!dquot->dq_dqb.dqb_bhardlimit &&
                    !dquot->dq_dqb.dqb_bsoftlimit)
                        dquot->dq_dqb.dqb_curspace = 0;

                /* clear grace time */
                if (!dqblk->dqb_bsoftlimit ||
                    toqb(dquot->dq_dqb.dqb_curspace) <= dqblk->dqb_bsoftlimit)
                        dquot->dq_dqb.dqb_btime = 0;
                /* set grace only if user hasn't provided his own */
                else if (!(dqblk->dqb_valid & QIF_BTIME))
                        dquot->dq_dqb.dqb_btime = cfs_time_current_sec() +
                                qinfo->qi_info[dquot->dq_type].dqi_bgrace;

                flag |= LQUOTA_FLAGS_ADJBLK;
        }

        if (dqblk->dqb_valid & QIF_ILIMITS) {
                dquot->dq_dqb.dqb_ihardlimit = dqblk->dqb_ihardlimit;
                dquot->dq_dqb.dqb_isoftlimit = dqblk->dqb_isoftlimit;
                /* clear usage (limit pool) */
                if (!dquot->dq_dqb.dqb_ihardlimit &&
                    !dquot->dq_dqb.dqb_isoftlimit)
                        dquot->dq_dqb.dqb_curinodes = 0;

                if (!dqblk->dqb_isoftlimit ||
                    dquot->dq_dqb.dqb_curinodes <= dqblk->dqb_isoftlimit)
                        dquot->dq_dqb.dqb_itime = 0;
                else if (!(dqblk->dqb_valid & QIF_ITIME))
                        dquot->dq_dqb.dqb_itime = cfs_time_current_sec() +
                                qinfo->qi_info[dquot->dq_type].dqi_igrace;

                flag |= LQUOTA_FLAGS_ADJINO;
        }
        QAQ_DEBUG(oqaq, "before dquot_create_oqaq\n");
        rc = dquot_create_oqaq(qctxt, dquot, lov->desc.ld_tgt_count, 1,
                               flag, oqaq);
        QAQ_DEBUG(oqaq, "after dquot_create_oqaq\n");
        if (rc < 0)
                CDEBUG(D_QUOTA, "adjust qunit size failed! (rc:%d)\n", rc);


        rc = fsfilt_dquot(obd, dquot, QFILE_WR_DQUOT);

        up(&dquot->dq_sem);

        if (rc) {
                CERROR("set limit failed! (rc:%d)\n", rc);
                goto out;
        }

        up(&mds->mds_qonoff_sem);

        adjust_lqs(obd, oqaq);

        orig_set = ihardlimit || isoftlimit;
        now_set  = dqblk->dqb_ihardlimit || dqblk->dqb_isoftlimit;
        if (dqblk->dqb_valid & QIF_ILIMITS && orig_set != now_set) {
                down(&dquot->dq_sem);
                dquot->dq_dqb.dqb_curinodes = 0;
                up(&dquot->dq_sem);
                rc = mds_init_slave_ilimits(obd, oqctl, orig_set);
                if (rc) {
                        CERROR("init slave ilimits failed! (rc:%d)\n", rc);
                        goto revoke_out;
                }
        }

        orig_set = bhardlimit || bsoftlimit;
        now_set  = dqblk->dqb_bhardlimit || dqblk->dqb_bsoftlimit;
        if (dqblk->dqb_valid & QIF_BLIMITS && orig_set != now_set) {
                down(&dquot->dq_sem);
                dquot->dq_dqb.dqb_curspace = 0;
                up(&dquot->dq_sem);
                rc = mds_init_slave_blimits(obd, oqctl, orig_set);
                if (rc) {
                        CERROR("init slave blimits failed! (rc:%d)\n", rc);
                        goto revoke_out;
                }
        }

revoke_out:
        down(&mds->mds_qonoff_sem);
        down(&dquot->dq_sem);
        if (rc) {
                /* cancel previous setting */
                dquot->dq_dqb.dqb_ihardlimit = ihardlimit;
                dquot->dq_dqb.dqb_isoftlimit = isoftlimit;
                dquot->dq_dqb.dqb_bhardlimit = bhardlimit;
                dquot->dq_dqb.dqb_bsoftlimit = bsoftlimit;
                dquot->dq_dqb.dqb_btime = btime;
                dquot->dq_dqb.dqb_itime = itime;
        }
        rc2 = fsfilt_dquot(obd, dquot, QFILE_WR_DQUOT);
        up(&dquot->dq_sem);

out:
        down(&dquot->dq_sem);
        dquot->dq_status &= ~DQ_STATUS_SET;
        up(&dquot->dq_sem);
        lustre_dqput(dquot);
        EXIT;
out_sem:
        up(&mds->mds_qonoff_sem);

        if (oqaq)
                OBD_FREE_PTR(oqaq);

        return rc ? rc : rc2;
}

static int mds_get_space(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct obd_quotactl *soqc;
        struct lvfs_run_ctxt saved;
        __u64 curspace;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(soqc);
        if (!soqc)
                RETURN(-ENOMEM);

        soqc->qc_cmd = Q_GETOQUOTA;
        soqc->qc_id = oqctl->qc_id;
        soqc->qc_type = oqctl->qc_type;

        rc = obd_quotactl(obd->u.mds.mds_lov_exp, soqc);
        if (rc)
                goto out;

        curspace = soqc->qc_dqblk.dqb_curspace;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        soqc->qc_dqblk.dqb_curspace = 0;
        rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, soqc);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc)
                goto out;

        oqctl->qc_dqblk.dqb_curinodes = soqc->qc_dqblk.dqb_curinodes;
        oqctl->qc_dqblk.dqb_valid |= QIF_INODES;
        oqctl->qc_dqblk.dqb_curspace = curspace + soqc->qc_dqblk.dqb_curspace;
        oqctl->qc_dqblk.dqb_valid |= QIF_USAGE;

out:
        OBD_FREE_PTR(soqc);

        RETURN(rc);
}

int mds_get_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        struct lustre_dquot *dquot;
        struct obd_dqblk *dqblk = &oqctl->qc_dqblk;
        int rc;
        ENTRY;

        if (oqctl->qc_type != USRQUOTA &&
            oqctl->qc_type != GRPQUOTA)
                RETURN(-EINVAL);

        down(&mds->mds_qonoff_sem);
        dqblk->dqb_valid = 0;
        if (qinfo->qi_files[oqctl->qc_type] == NULL)
                GOTO(out, rc = -ESRCH);

        dquot = lustre_dqget(obd, qinfo, oqctl->qc_id, oqctl->qc_type);
        if (IS_ERR(dquot))
                GOTO(out, rc = PTR_ERR(dquot));

        down(&dquot->dq_sem);
        dqblk->dqb_ihardlimit = dquot->dq_dqb.dqb_ihardlimit;
        dqblk->dqb_isoftlimit = dquot->dq_dqb.dqb_isoftlimit;
        dqblk->dqb_bhardlimit = dquot->dq_dqb.dqb_bhardlimit;
        dqblk->dqb_bsoftlimit = dquot->dq_dqb.dqb_bsoftlimit;
        dqblk->dqb_btime = dquot->dq_dqb.dqb_btime;
        dqblk->dqb_itime = dquot->dq_dqb.dqb_itime;
        dqblk->dqb_valid |= QIF_LIMITS | QIF_TIMES;
        /* mds_get_space will hopefully update stats to more accurate values */
        dqblk->dqb_curinodes = dquot->dq_dqb.dqb_curinodes;
        dqblk->dqb_curspace  = dquot->dq_dqb.dqb_curspace;
        up(&dquot->dq_sem);

        lustre_dqput(dquot);
        up(&mds->mds_qonoff_sem);

        /* if mds_get_space fails we still return rc=0, but the unset
         * QIF_INODES and QIF_USAGE will signal that the data are inaccurate */
        mds_get_space(obd, oqctl);

        EXIT;
        return 0;
out:
        up(&mds->mds_qonoff_sem);
        return rc;
}

int mds_get_obd_quota(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct lvfs_run_ctxt saved;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}


/* FIXME we only recovery block limit by now, need recovery inode
 * limits also after CMD involved in */
static int 
dquot_recovery(struct obd_device *obd, unsigned int id, unsigned short type)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo= &obd->u.mds.mds_quota_info;
        struct lustre_dquot *dquot;
        struct obd_quotactl *qctl;
        __u64 total_limits = 0;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(qctl);
        if (qctl == NULL)
                RETURN(-ENOMEM);

        dquot = lustre_dqget(obd, qinfo, id, type);
        if (IS_ERR(dquot)) {
                CERROR("Get dquot failed. (rc:%ld)\n", PTR_ERR(dquot));
                OBD_FREE_PTR(qctl);
                RETURN(PTR_ERR(dquot));
        }

        down(&dquot->dq_sem);

        /* don't recovery the dquot without limits or under setting */
        if (!(dquot->dq_dqb.dqb_bhardlimit || dquot->dq_dqb.dqb_bsoftlimit) ||
            dquot->dq_status)
                GOTO(skip, rc = 0);
        dquot->dq_status |= DQ_STATUS_RECOVERY;

        up(&dquot->dq_sem);

        /* get real bhardlimit from all slaves. */
        qctl->qc_cmd = Q_GETOQUOTA;
        qctl->qc_type = type;
        qctl->qc_id = id;
        qctl->qc_stat = QUOTA_RECOVERING;
        rc = obd_quotactl(obd->u.mds.mds_lov_exp, qctl);
        if (rc)
                GOTO(out, rc);
        total_limits = qctl->qc_dqblk.dqb_bhardlimit;

        /* get real bhardlimit from master */
        rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, qctl);
        if (rc)
                GOTO(out, rc);
        total_limits += qctl->qc_dqblk.dqb_bhardlimit;

        /* amend the usage of the administrative quotafile */
        down(&mds->mds_qonoff_sem);
        down(&dquot->dq_sem);

        dquot->dq_dqb.dqb_curspace = total_limits << QUOTABLOCK_BITS;

        rc = fsfilt_dquot(obd, dquot, QFILE_WR_DQUOT);
        if (rc)
                CERROR("write dquot failed! (rc:%d)\n", rc);

        up(&dquot->dq_sem);
        up(&mds->mds_qonoff_sem);
        EXIT;
out:
        down(&dquot->dq_sem);
        dquot->dq_status &= ~DQ_STATUS_RECOVERY;
skip:
        up(&dquot->dq_sem);

        lustre_dqput(dquot);
        OBD_FREE_PTR(qctl);
        return rc;
}

struct qmaster_recov_thread_data {
        struct obd_device *obd;
        struct completion comp;
};

static int qmaster_recovery_main(void *arg)
{
        struct qmaster_recov_thread_data *data = arg;
        struct obd_device *obd = data->obd;
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        int rc = 0;
        unsigned short type;
        ENTRY;

        cfs_daemonize_ctxt("qmaster_recovd");

        class_incref(obd);
        complete(&data->comp);

        for (type = USRQUOTA; type < MAXQUOTAS; type++) {
                struct list_head id_list;
                struct dquot_id *dqid, *tmp;

                down(&mds->mds_qonoff_sem);
                if (qinfo->qi_files[type] == NULL) {
                        up(&mds->mds_qonoff_sem);
                        continue;
                }
                INIT_LIST_HEAD(&id_list);
                rc = fsfilt_qids(obd, qinfo->qi_files[type], NULL, type,
                                 &id_list);
                up(&mds->mds_qonoff_sem);

                if (rc)
                        CERROR("error get ids from admin quotafile.(%d)\n", rc);

                list_for_each_entry_safe(dqid, tmp, &id_list, di_link) {
                        list_del_init(&dqid->di_link);
                        if (rc)
                                goto free;

                        rc = dquot_recovery(obd, dqid->di_id, type);
                        if (rc)
                                CERROR("%s: qmaster recovery failed for %sid %d"
                                       " rc:%d)\n", obd->obd_name,
                                       type ? "g" : "u", dqid->di_id, rc);
free:
                        OBD_FREE_PTR(dqid);
                }
        }
        class_decref(obd);
        RETURN(rc);
}

int mds_quota_recovery(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct qmaster_recov_thread_data data;
        int rc = 0;
        ENTRY;

        mutex_down(&obd->obd_dev_sem);
        if (mds->mds_lov_desc.ld_active_tgt_count != mds->mds_lov_objid_count) {
                CWARN("Only %u/%u OSTs are active, abort quota recovery\n",
                      mds->mds_lov_desc.ld_active_tgt_count,
                      mds->mds_lov_objid_count);
                mutex_up(&obd->obd_dev_sem);
                RETURN(rc);
        }
        mutex_up(&obd->obd_dev_sem);

        data.obd = obd;
        init_completion(&data.comp);

        rc = kernel_thread(qmaster_recovery_main, &data, CLONE_VM|CLONE_FILES);
        if (rc < 0)
                CERROR("%s: cannot start quota recovery thread: rc %d\n",
                       obd->obd_name, rc);

        wait_for_completion(&data.comp);
        RETURN(rc);
}

#endif /* HAVE_QUOTA_SUPPORT */
