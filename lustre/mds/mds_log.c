/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/mds_log.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <portals/list.h>
#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_commit_confd.h>

#include "mds_internal.h"

int mds_llog_setup(struct obd_device *obd, struct obd_device *disk_obd,
                   int index, int count, struct llog_logid *logid)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd->u.mds.mds_osc_obd, llog_setup, 0);
        rc = OBP(obd->u.mds.mds_osc_obd, llog_setup)(obd->u.mds.mds_osc_obd,
                                                     disk_obd, index, count,
                                                     logid);
        RETURN(rc);
}

int mds_llog_cleanup(struct obd_device *obd)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd->u.mds.mds_osc_obd, llog_cleanup, 0);
        rc = OBP(obd->u.mds.mds_osc_obd, llog_cleanup)(obd->u.mds.mds_osc_obd);
        RETURN(rc);
}

int mds_llog_origin_add(struct obd_export *exp, int index,
                        struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                        struct llog_cookie *logcookies, int numcookies)
{
        int rc;
        struct obd_export *lov_exp = exp->exp_obd->u.mds.mds_osc_exp;
        ENTRY;

        EXP_CHECK_OP(lov_exp, llog_origin_add);

        rc = OBP(lov_exp->exp_obd, llog_origin_add)(lov_exp, index, rec, lsm,
                                                    logcookies, numcookies);
        RETURN(rc);
}

int mds_llog_repl_cancel(struct obd_device *obd, struct lov_stripe_md *lsm,
                          int count, struct llog_cookie *cookies, int flags)
{
        int rc;
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        ENTRY;

        OBD_CHECK_OP(obd, llog_repl_cancel, -EOPNOTSUPP);

        rc = OBP(lov_obd, llog_repl_cancel)(lov_obd, lsm, count, cookies,
                                            flags);
        RETURN(rc);
}

int mds_log_op_unlink(struct obd_device *obd, struct inode *inode,
                      struct lustre_msg *repmsg, int offset)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_stripe_md *lsm = NULL;
        struct llog_unlink_rec *lur;
        int rc;
        ENTRY;

        if (IS_ERR(mds->mds_osc_obd))
                RETURN(PTR_ERR(mds->mds_osc_obd));

        rc = obd_unpackmd(mds->mds_osc_exp, &lsm,
                          lustre_msg_buf(repmsg, offset, 0),
                          repmsg->buflens[offset]);
        if (rc < 0)
                RETURN(rc);

        OBD_ALLOC(lur, sizeof(*lur));
        if (!lur)
                RETURN(-ENOMEM);
        lur->lur_hdr.lrh_len = lur->lur_tail.lrt_len = sizeof(*lur);
        lur->lur_hdr.lrh_type = MDS_UNLINK_REC;
        lur->lur_oid = inode->i_ino;
        lur->lur_ogen = inode->i_generation;

#ifdef ENABLE_ORPHANS
        rc = obd_llog_origin_add(mds->mds_osc_exp, 0, &lur->lur_hdr,
                                 lsm, lustre_msg_buf(repmsg, offset + 1, 0),
                                 repmsg->buflens[offset + 1] /
                                 sizeof(struct llog_cookie));
#endif

        obd_free_memmd(mds->mds_osc_exp, &lsm);
        OBD_FREE(lur, sizeof(*lur));

        RETURN(rc);
}
