/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

/* lov_obd.c */
int lov_get_stripecnt(struct lov_obd *lov, int stripe_count);
int lov_alloc_memmd(struct lov_stripe_md **lsmp, int stripe_count);
void lov_free_memmd(struct lov_stripe_md **lsmp);

/* lov_log.c */
int lov_llog_setup(struct obd_device *obd, struct obd_device *disk_obd,
                   int index, int count ,struct llog_logid *logids);
int lov_llog_cleanup(struct obd_device *obd);
int lov_llog_origin_add(struct obd_export *exp,
                        int index,
                        struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                        struct llog_cookie *logcookies, int numcookies);
int lov_llog_repl_cancel(struct obd_device *obd, struct lov_stripe_md *lsm,
                         int count, struct llog_cookie *cookies, int flags);


#if 0
int lov_get_catalogs(struct lov_obd *lov, struct llog_handle *cathandle);
int lov_log_add(struct obd_export *exp,
                struct llog_handle *cathandle,
                struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                struct llog_cookie *logcookies, int numcookies);
#endif

/* lov_pack.c */
int lov_packmd(struct obd_export *exp, struct lov_mds_md **lmm,
               struct lov_stripe_md *lsm);
int lov_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsm,
                 struct lov_mds_md *lmm, int lmmsize);
int lov_setstripe(struct obd_export *exp,
                  struct lov_stripe_md **lsmp, struct lov_mds_md *lump);
int lov_getstripe(struct obd_export *exp,
                  struct lov_stripe_md *lsm, struct lov_mds_md *lump);

/* lproc_lov.c */
extern struct file_operations lov_proc_target_fops;
