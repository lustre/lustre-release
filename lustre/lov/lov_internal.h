/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef LOV_INTERNAL_H
#define LOV_INTERNAL_H

#include <linux/lustre_user.h>

#define LAP_MAGIC 8200

struct lov_async_page {
        int                             lap_magic;
        int                             lap_stripe;
        obd_off                         lap_sub_offset;
        void                            *lap_sub_cookie;
        struct obd_async_page_ops       *lap_caller_ops;
        struct obd_async_page_ops       *lap_caller_data;
        obd_id                          lap_loi_id;
};

/* lov_obd.c */
int lov_get_stripecnt(struct lov_obd *lov, int stripe_count);
int lov_alloc_memmd(struct lov_stripe_md **lsmp, int stripe_count, int pattern);
void lov_free_memmd(struct lov_stripe_md **lsmp);

/* lov_log.c */
int lov_llog_init(struct obd_device *obd, struct obd_device *tgt,
                  int count, struct llog_logid *logid);
int lov_llog_finish(struct obd_device *obd, int count);

/* lov_pack.c */
int lov_packmd(struct obd_export *exp, struct lov_mds_md **lmm,
               struct lov_stripe_md *lsm);
int lov_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm, int lmm_bytes);
int lov_setstripe(struct obd_export *exp,
                  struct lov_stripe_md **lsmp, struct lov_user_md *lump);
int lov_setea(struct obd_export *exp, struct lov_stripe_md **lsmp, 
              struct lov_user_md *lump);
int lov_getstripe(struct obd_export *exp,
                  struct lov_stripe_md *lsm, struct lov_user_md *lump);

/* lproc_lov.c */
extern struct file_operations lov_proc_target_fops;

#endif
