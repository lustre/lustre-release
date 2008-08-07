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
#define DEBUG_SUBSYSTEM S_MDS

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/init.h>
# include <linux/fs.h>
# include <linux/jbd.h>
# include <linux/ext3_fs.h>
# include <linux/quota.h>
# include <linux/smp_lock.h>
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
# include <linux/mount.h>
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
#include "quota_internal.h"

#ifdef __KERNEL__
int mds_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct obd_device *obd = exp->exp_obd;
        int rc = 0;
        ENTRY;

        switch (oqctl->qc_cmd) {
        case Q_QUOTAON:
                rc = mds_quota_on(obd, oqctl);
                break;
        case Q_QUOTAOFF:
                mds_quota_off(obd, oqctl);
                break;
        case Q_SETINFO:
                rc = mds_set_dqinfo(obd, oqctl);
                break;
        case Q_GETINFO:
                rc = mds_get_dqinfo(obd, oqctl);
                break;
        case Q_SETQUOTA:
                rc = mds_set_dqblk(obd, oqctl);
                break;
        case Q_GETQUOTA:
                rc = mds_get_dqblk(obd, oqctl);
                break;
        case Q_GETOINFO:
        case Q_GETOQUOTA:
                rc = mds_get_obd_quota(obd, oqctl);
                break;
        default:
                CERROR("%s: unsupported mds_quotactl command: %d\n",
                       obd->obd_name, oqctl->qc_cmd);
                RETURN(-EFAULT);
        }

        if (rc)
                CDEBUG(D_INFO, "mds_quotactl admin quota command %d, id %u, "
                               "type %d, failed: rc = %d\n",
                       oqctl->qc_cmd, oqctl->qc_id, oqctl->qc_type, rc);

        RETURN(rc);
}

int filter_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_device_target *obt = &obd->u.obt;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        switch (oqctl->qc_cmd) {
        case Q_QUOTAON:
        case Q_QUOTAOFF:
                if (!atomic_dec_and_test(&obt->obt_quotachecking)) {
                        CDEBUG(D_INFO, "other people are doing quotacheck\n");
                        atomic_inc(&obt->obt_quotachecking);
                        rc = -EBUSY;
                        break;
                }
        case Q_GETOINFO:
        case Q_GETOQUOTA:
        case Q_GETQUOTA:
                /* In recovery scenario, this pending dqacq/dqrel might have
                 * been processed by master successfully before it's dquot
                 * on master enter recovery mode. We must wait for this 
                 * dqacq/dqrel done then return the correct limits to master */
                if (oqctl->qc_stat == QUOTA_RECOVERING)
                        qctxt_wait_pending_dqacq(&obd->u.obt.obt_qctxt,
                                                 oqctl->qc_id, oqctl->qc_type, 
                                                 1);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                if (oqctl->qc_cmd == Q_QUOTAON || oqctl->qc_cmd == Q_QUOTAOFF) {
                        if (!rc)
                                obt->obt_qctxt.lqc_status = 
                                        (oqctl->qc_cmd == Q_QUOTAON) ? 1 : 0;
                        atomic_inc(&obt->obt_quotachecking);
                }
                break;
        case Q_SETQUOTA:
                qctxt_wait_pending_dqacq(&obd->u.obt.obt_qctxt, 
                                         oqctl->qc_id, oqctl->qc_type, 1);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);

                if (!rc) {
                        oqctl->qc_cmd = Q_SYNC;
                        fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);
                        oqctl->qc_cmd = Q_SETQUOTA;
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                break;
        case Q_INITQUOTA:
                {
                unsigned int uid = 0, gid = 0;

                /* Initialize quota limit to MIN_QLIMIT */
                LASSERT(oqctl->qc_dqblk.dqb_valid == QIF_BLIMITS);
                LASSERT(oqctl->qc_dqblk.dqb_bsoftlimit == 0);

                /* There might be a pending dqacq/dqrel (which is going to
                 * clear stale limits on slave). we should wait for it's 
                 * completion then initialize limits */
                qctxt_wait_pending_dqacq(&obd->u.obt.obt_qctxt, 
                                         oqctl->qc_id, oqctl->qc_type, 1);

                if (!oqctl->qc_dqblk.dqb_bhardlimit)
                        goto adjust;
                
                LASSERT(oqctl->qc_dqblk.dqb_bhardlimit == MIN_QLIMIT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);

                /* Update on-disk quota, in case of lose the changed limits
                 * (MIN_QLIMIT) on crash, which cannot be recovered.*/
                if (!rc) {
                        oqctl->qc_cmd = Q_SYNC;
                        fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);
                        oqctl->qc_cmd = Q_INITQUOTA;
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                if (rc)
                        RETURN(rc);
adjust:
                /* Trigger qunit pre-acquire */
                if (oqctl->qc_type == USRQUOTA)
                        uid = oqctl->qc_id;
                else
                        gid = oqctl->qc_id;

                rc = qctxt_adjust_qunit(obd, &obd->u.obt.obt_qctxt, 
                                        uid, gid, 1, 0);
                break;
                }
        default:
                CERROR("%s: unsupported filter_quotactl command: %d\n",
                       obd->obd_name, oqctl->qc_cmd);
                RETURN(-EFAULT);
        }

        RETURN(rc);
}
#endif /* __KERNEL__ */

int client_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct ptlrpc_request *req;
        struct obd_quotactl   *oqc;
        int                    ver, opc, rc;
        ENTRY;

        if (!strcmp(exp->exp_obd->obd_type->typ_name, LUSTRE_MDC_NAME)) {
                ver = LUSTRE_MDS_VERSION,
                opc = MDS_QUOTACTL;
        } else if (!strcmp(exp->exp_obd->obd_type->typ_name, LUSTRE_OSC_NAME)) {
                ver = LUSTRE_OST_VERSION,
                opc = OST_QUOTACTL;
        } else {
                RETURN(-EINVAL);
        }

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
                                        &RQF_MDS_QUOTACTL, ver, opc);
        if (req == NULL)
                RETURN(-ENOMEM);

        oqc = req_capsule_client_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
        *oqc = *oqctl;

        ptlrpc_request_set_replen(req);

        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                oqc = req_capsule_server_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
                if (oqc == NULL)
                        GOTO(out, rc = -EPROTO);

                *oqctl = *oqc;
        }
out:
        ptlrpc_req_finished(req);
        RETURN (rc);
}

int lov_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        __u64 curspace = 0;
        __u32 bhardlimit = 0;
        int i, rc = 0;
        ENTRY;

        if (oqctl->qc_cmd != Q_QUOTAON && oqctl->qc_cmd != Q_QUOTAOFF &&
            oqctl->qc_cmd != Q_GETOQUOTA && oqctl->qc_cmd != Q_INITQUOTA &&
            oqctl->qc_cmd != Q_SETQUOTA) {
                CERROR("bad quota opc %x for lov obd", oqctl->qc_cmd);
                RETURN(-EFAULT);
        }

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int err;

                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_active) {
                        if (oqctl->qc_cmd == Q_GETOQUOTA) {
                                CERROR("ost %d is inactive\n", i);
                                rc = -EIO;
                                break;
                        } else {
                                CDEBUG(D_HA, "ost %d is inactive\n", i);
                                continue;
                        }
                }

                err = obd_quotactl(lov->lov_tgts[i]->ltd_exp, oqctl);
                if (err) {
                        if (lov->lov_tgts[i]->ltd_active && !rc)
                                rc = err;
                        continue;
                }

                if (oqctl->qc_cmd == Q_GETOQUOTA) {
                        curspace += oqctl->qc_dqblk.dqb_curspace;
                        bhardlimit += oqctl->qc_dqblk.dqb_bhardlimit;
                }
        }

        if (oqctl->qc_cmd == Q_GETOQUOTA) {
                oqctl->qc_dqblk.dqb_curspace = curspace;
                oqctl->qc_dqblk.dqb_bhardlimit = bhardlimit;
        }
        RETURN(rc);
}
