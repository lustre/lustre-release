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

#ifndef _MDS_INTERNAL_H
#define _MDS_INTERNAL_H

#include <lustre_disk.h>
#include <lustre_mds.h>

int mds_cleanup_pending(struct obd_device *obd);


/* mds/mds_log.c */
int mds_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                  struct obd_device *tgt, int count,
                  struct llog_catid *logid, struct obd_uuid *uuid);
int mds_llog_finish(struct obd_device *obd, int count);

/* mds/mds_lov.c */
int mds_lov_connect(struct obd_device *obd, char * lov_name);
int mds_lov_disconnect(struct obd_device *obd);

int mds_lov_clear_orphans(struct mds_obd *mds, struct obd_uuid *ost_uuid);
void mds_lov_update_objids(struct obd_device *obd, struct lov_mds_md *lmm);
int mds_lov_set_nextid(struct obd_device *obd);

int mds_lov_start_synchronize(struct obd_device *obd,
                              struct obd_device *watched,
                              void *data, int nonblock);
int mds_post_mds_lovconf(struct obd_device *obd);
int mds_notify(struct obd_device *obd, struct obd_device *watched,
               enum obd_notify_event ev, void *data);
int mds_convert_lov_ea(struct obd_device *obd, struct inode *inode,
                       struct lov_mds_md *lmm, int lmm_size,
                       __u64 connect_flags);
int mds_init_lov_desc(struct obd_device *obd, struct obd_export *osc_exp);

int mds_obd_create(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md **ea, struct obd_trans_info *oti);
int mds_obd_destroy(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *ea, struct obd_trans_info *oti,
                    struct obd_export *md_exp);

/* mds/handler.c */
extern struct lvfs_callback_ops mds_lvfs_ops;
/* quota stuff */
extern quota_interface_t *mds_quota_interface_ref;

/* mds/lproc_mds.c */
enum {
        LPROC_MDS_OPEN = 0,
        LPROC_MDS_CLOSE,
        LPROC_MDS_MKNOD,
        LPROC_MDS_LINK,
        LPROC_MDS_UNLINK,
        LPROC_MDS_MKDIR,
        LPROC_MDS_RMDIR,
        LPROC_MDS_RENAME,
        LPROC_MDS_GETXATTR,
        LPROC_MDS_SETXATTR,
        LPROC_MDS_LAST,
};
void mds_counter_incr(struct obd_export *exp, int opcode);
void mds_stats_counter_init(struct lprocfs_stats *stats);
void lprocfs_mds_init_vars(struct lprocfs_static_vars *lvars);
void lprocfs_mdt_init_vars(struct lprocfs_static_vars *lvars);
#endif /* _MDS_INTERNAL_H */
