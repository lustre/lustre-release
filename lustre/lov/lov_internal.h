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

/* lov_pack.c */
int lov_packmd(struct lustre_handle *conn, struct lov_mds_md **lmm,
               struct lov_stripe_md *lsm);
int lov_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsm,
                 struct lov_mds_md *lmm, int lmmsize);
int lov_setstripe(struct lustre_handle *conn,
                  struct lov_stripe_md **lsmp, struct lov_mds_md *lmmu);
int lov_getstripe(struct lustre_handle *conn,
                  struct lov_stripe_md *lsm, struct lov_mds_md *lmmu);

/* lproc_lov.c */
extern struct file_operations lov_proc_target_fops;
