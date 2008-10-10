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

#ifndef __QUOTA_INTERNAL_H
#define __QUOTA_INTERNAL_H

#include <lustre_quota.h>

/* QUSG covnert bytes to blocks when counting block quota */
#define QUSG(count, isblk)      (isblk ? toqb(count) : count)

/* This flag is set in qc_stat to distinguish if the current getquota 
 * operation is for quota recovery */
#define QUOTA_RECOVERING    0x01

#ifdef __KERNEL__

#define DQUOT_DEBUG(dquot, fmt, arg...)                                       \
        CDEBUG(D_QUOTA, "refcnt(%u) id(%u) type(%u) off(%llu) flags(%lu) "    \
               "bhardlimit(%u) curspace("LPX64") ihardlimit(%u) "             \
               "curinodes(%u): " fmt, dquot->dq_refcnt,                       \
               dquot->dq_id, dquot->dq_type, dquot->dq_off,  dquot->dq_flags, \
               dquot->dq_dqb.dqb_bhardlimit, dquot->dq_dqb.dqb_curspace,      \
               dquot->dq_dqb.dqb_ihardlimit, dquot->dq_dqb.dqb_curinodes,     \
               ## arg);                                                       \

#define QINFO_DEBUG(qinfo, fmt, arg...)                                       \
        CDEBUG(D_QUOTA, "files (%p/%p) flags(%lu/%lu) blocks(%u/%u) "         \
               "free_blk(/%u/%u) free_entry(%u/%u): " fmt,                    \
               qinfo->qi_files[0], qinfo->qi_files[1],                        \
               qinfo->qi_info[0].dqi_flags, qinfo->qi_info[1].dqi_flags,      \
               qinfo->qi_info[0].dqi_blocks, qinfo->qi_info[1].dqi_blocks,    \
               qinfo->qi_info[0].dqi_free_blk, qinfo->qi_info[1].dqi_free_blk,\
               qinfo->qi_info[0].dqi_free_entry,                              \
               qinfo->qi_info[1].dqi_free_entry, ## arg);

#define QDATA_DEBUG(qd, fmt, arg...)                                          \
        CDEBUG(D_QUOTA, "id(%u) type(%lu) count("LPU64") isblk(%lu):"         \
               fmt, qd->qd_id, qd->qd_flags & QUOTA_IS_GRP, qd->qd_count,     \
               (qd->qd_flags & QUOTA_IS_BLOCK) >> 1,       \
               ## arg);


/* quota_context.c */
void qunit_cache_cleanup(void);
int qunit_cache_init(void);
int qctxt_adjust_qunit(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                       uid_t uid, gid_t gid, __u32 isblk, int wait);
int qctxt_wait_pending_dqacq(struct lustre_quota_ctxt *qctxt, unsigned int id,
                             unsigned short type, int isblk);
int qctxt_init(struct lustre_quota_ctxt *qctxt, struct super_block *sb,
               dqacq_handler_t handler);
void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force);
void qslave_start_recovery(struct obd_device *obd, 
                           struct lustre_quota_ctxt *qctxt);
int compute_remquota(struct obd_device *obd,
                     struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata);
/* quota_master.c */
int lustre_dquot_init(void);
void lustre_dquot_exit(void);
int dqacq_handler(struct obd_device *obd, struct qunit_data *qdata, int opc);
int mds_quota_adjust(struct obd_device *obd, unsigned int qcids[],
                     unsigned int qpids[], int rc, int opc);
int filter_quota_adjust(struct obd_device *obd, unsigned int qcids[],
                        unsigned int qpids[], int rc, int opc);
int init_admin_quotafiles(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_admin_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_off(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_set_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_get_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_set_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_get_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_recovery(struct obd_device *obd);
int mds_get_obd_quota(struct obd_device *obd, struct obd_quotactl *oqctl);
#endif

/* quota_ctl.c */
int mds_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl);
int filter_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl);
int client_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl);
int lov_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl);

/* quota_chk.c */
int target_quota_check(struct obd_export *exp, struct obd_quotactl *oqctl);
int client_quota_check(struct obd_export *exp, struct obd_quotactl *oqctl);
int lov_quota_check(struct obd_export *exp, struct obd_quotactl *oqctl);
int client_quota_poll_check(struct obd_export *exp, struct if_quotacheck *qchk);

#endif
