/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003, 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
