/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef CMOBD_INTERNAL_H
#define CMOBD_INTERNAL_H

/* cmobd_reint.c */
int cmobd_reintegrate(struct obd_device *);
int cmobd_dummy_lsm(struct lov_stripe_md **, int, struct obdo*, __u32);
void cmobd_free_lsm(struct lov_stripe_md **);

/* cmobd_write.c */
int cmobd_replay_write(struct obd_device *, struct obdo*, struct ldlm_extent *);
int cmobd_init_write_srv(struct obd_device *);
void cmobd_cleanup_write_srv(struct obd_device *);

int cmobd_reint_mds(struct obd_device*, void *record);
int cmobd_reint_setattr(struct obd_device *obd, void *rec);
int cmobd_reint_create(struct obd_device *obd, void *rec);
int cmobd_reint_write(struct obd_device *obd, void *rec);

#endif /* CMOBD_INTERNAL_H */
