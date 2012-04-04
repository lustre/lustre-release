/*
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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
#define OBD_LQUOTA_DEVICENAME  "lquota"

#ifdef __KERNEL__

#define DQUOT_DEBUG(dquot, fmt, arg...)                                       \
        CDEBUG(D_QUOTA, "refcnt(%u) id(%u) type(%u) off(%llu) flags(%lu) "    \
               "bhardlimit("LPU64") curspace("LPU64") ihardlimit("LPU64") "   \
               "curinodes("LPU64"): " fmt, cfs_atomic_read(&dquot->dq_refcnt),\
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
        CDEBUG(D_QUOTA, "id(%u) flag(%u) type(%c) isblk(%c) count("LPU64") "  \
               "qd_qunit("LPU64"): " fmt, qd->qd_id, qd->qd_flags,            \
               QDATA_IS_GRP(qd) ? 'g' : 'u', QDATA_IS_BLK(qd) ? 'b': 'i',     \
               qd->qd_count,                                                  \
               (QDATA_IS_ADJBLK(qd) | QDATA_IS_ADJINO(qd)) ? qd->qd_qunit : 0,\
               ## arg);

#define QAQ_DEBUG(qaq, fmt, arg...)                                           \
        CDEBUG(D_QUOTA, "id(%u) flag(%u) type(%c) bunit("LPU64") "            \
               "iunit("LPU64"): " fmt, qaq->qaq_id, qaq->qaq_flags,           \
               QAQ_IS_GRP(qaq) ? 'g': 'u', qaq->qaq_bunit_sz,                 \
               qaq->qaq_iunit_sz, ## arg);

#define LQS_DEBUG(lqs, fmt, arg...)                                           \
        CDEBUG(D_QUOTA, "lqs(%p) id(%u) flag(%lu) type(%c) bunit(%lu) "       \
               "btune(%lu) iunit(%lu) itune(%lu) lqs_bwrite_pending(%lu) "    \
               "lqs_iwrite_pending(%lu) ino_rec(%lld) blk_rec(%lld) "         \
               "refcount(%d): "                                               \
               fmt, lqs, lqs->lqs_id, lqs->lqs_flags,                         \
               LQS_IS_GRP(lqs) ? 'g' : 'u',                                   \
               lqs->lqs_bunit_sz, lqs->lqs_btune_sz, lqs->lqs_iunit_sz,       \
               lqs->lqs_itune_sz, lqs->lqs_bwrite_pending,                    \
               lqs->lqs_iwrite_pending, lqs->lqs_ino_rec,                     \
               lqs->lqs_blk_rec, cfs_atomic_read(&lqs->lqs_refcount), ## arg);


/* quota_context.c */
void qunit_cache_cleanup(void);
int qunit_cache_init(void);
int qctxt_adjust_qunit(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                       const unsigned int id[], __u32 isblk, int wait,
                       struct obd_trans_info *oti);
int qctxt_wait_pending_dqacq(struct lustre_quota_ctxt *qctxt, unsigned int id,
                             unsigned short type, int isblk);
int qctxt_init(struct obd_device *obd, dqacq_handler_t handler);
void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force);
void qslave_start_recovery(struct obd_device *obd,
                           struct lustre_quota_ctxt *qctxt);
int compute_remquota(struct obd_device *obd,
                     struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata,
                     int isblk);
int check_qm(struct lustre_quota_ctxt *qctxt);
void dqacq_interrupt(struct lustre_quota_ctxt *qctxt);
int quota_is_on(struct lustre_quota_ctxt *qctxt, struct obd_quotactl *oqctl);
int quota_is_off(struct lustre_quota_ctxt *qctxt, struct obd_quotactl *oqctl);
void* quota_barrier(struct lustre_quota_ctxt *qctxt,
                    struct obd_quotactl *oqctl, int isblk);
void quota_unbarrier(void *handle);
/* quota_master.c */
int lustre_dquot_init(void);
void lustre_dquot_exit(void);
int dqacq_handler(struct obd_device *obd, struct qunit_data *qdata, int opc);
int mds_quota_adjust(struct obd_device *obd, const unsigned int qcids[],
                     const unsigned int qpids[], int rc, int opc);
int filter_quota_adjust(struct obd_device *obd, const unsigned int qcids[],
                        const unsigned int qpids[], int rc, int opc);
int init_admin_quotafiles(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_get_version(struct obd_device *obd, lustre_quota_version_t *ver);
int mds_quota_invalidate(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_finvalidate(struct obd_device *obd, struct obd_quotactl *oqctl);

int mds_admin_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_off(struct obd_device *obd, struct obd_quotactl *oqctl);
int do_mds_quota_off(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_admin_quota_off(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_set_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_get_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_set_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_get_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl);
int mds_quota_recovery(struct obd_device *obd);
int mds_get_obd_quota(struct obd_device *obd, struct obd_quotactl *oqctl);
int dquot_create_oqaq(struct lustre_quota_ctxt *qctxt, struct lustre_dquot
                      *dquot, __u32 ost_num, __u32 mdt_num, int type,
                      struct quota_adjust_qunit *oqaq);
int generic_quota_on(struct obd_device *, struct obd_quotactl *, int);
#endif

/* quota_ctl.c */
int mds_quota_ctl(struct obd_device *obd, struct obd_export *exp,
                  struct obd_quotactl *oqctl);
int filter_quota_ctl(struct obd_device *unused, struct obd_export *exp,
                     struct obd_quotactl *oqctl);

/* quota_chk.c */
int target_quota_check(struct obd_device *obd, struct obd_export *exp,
                       struct obd_quotactl *oqctl);

int quota_adjust_slave_lqs(struct quota_adjust_qunit *oqaq, struct
                          lustre_quota_ctxt *qctxt);
#ifdef __KERNEL__
int quota_is_set(struct obd_device *obd, const unsigned int id[], int flag);
struct lustre_qunit_size *quota_search_lqs(unsigned long long lqs_key,
                                           struct lustre_quota_ctxt *qctxt,
                                           int create);
void quota_compute_lqs(struct qunit_data *qdata, struct lustre_qunit_size *lqs,
                       int is_chk, int is_acq);


extern int quote_get_qdata(struct ptlrpc_request *req, struct qunit_data *qdata,
                           int is_req, int is_exp);
extern int quote_copy_qdata(struct ptlrpc_request *req, struct qunit_data *qdata,
                            int is_req, int is_exp);
int filter_quota_adjust_qunit(struct obd_export *exp,
                              struct quota_adjust_qunit *oqaq,
                              struct lustre_quota_ctxt *qctxt,
                              struct ptlrpc_request_set *rqset);
int lquota_proc_setup(struct obd_device *obd, int is_master);
int lquota_proc_cleanup(struct lustre_quota_ctxt *qctxt);
void build_lqs(struct obd_device *obd);

extern cfs_proc_dir_entry_t *lquota_type_proc_dir;
#endif

#define LQS_BLK_DECREASE 1
#define LQS_BLK_INCREASE 2
#define LQS_INO_DECREASE 4
#define LQS_INO_INCREASE 8

/* the return status of quota operation */
#define QUOTA_REQ_RETURNED 1

#endif
