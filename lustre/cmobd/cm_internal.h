/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef CM_INTERNAL_H
#define CM_INTERNAL_H

int cmobd_reintegrate(struct obd_device *);
int cmobd_dummy_lsm(struct lov_stripe_md **, int, struct obdo*, __u32);
void cmobd_free_lsm(struct lov_stripe_md **);

int cmobd_replay_write(struct obd_device *, struct obdo *, 
                       struct ldlm_extent *);

int cmobd_init_write_srv(struct obd_device *);
void cmobd_cleanup_write_srv(struct obd_device *);

int cmobd_reint_mds(struct obd_device*obd, void *record, int opcode);
int cmobd_reint_oss(struct obd_device *obd, void *record, int opcode);

/* methods for updating/reading master lustre_id from local MDS inode EA.*/
int mds_update_mid(struct obd_device *obd, struct lustre_id *id,
                   void *data, int data_len);

int mds_read_mid(struct obd_device *obd, struct lustre_id *id,
                 void *data, int data_len);

#endif /* CM_INTERNAL_H */
