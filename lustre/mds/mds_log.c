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

#if 0
static int mds_logop_cleanup(struct llog_obd_ctxt *ctxt)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        struct llog_obd_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = lov_obd->obd_llog_ctxt[ctxt->loc_idx];
        rc = llog_cleanup(lctxt);
        RETURN(rc);
}
#endif

static int mds_llog_origin_add(struct llog_obd_ctxt *ctxt,
                        struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                        struct llog_cookie *logcookies, int numcookies)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        struct llog_obd_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = lov_obd->obd_llog_ctxt[ctxt->loc_idx];
        rc = llog_add(lctxt, rec, lsm, logcookies, numcookies);
        RETURN(rc);
}

static int mds_llog_repl_cancel(struct llog_obd_ctxt *ctxt, struct lov_stripe_md *lsm,
                          int count, struct llog_cookie *cookies, int flags)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        struct llog_obd_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = lov_obd->obd_llog_ctxt[ctxt->loc_idx];
        rc = llog_cancel(lctxt, lsm, count, cookies,flags);
        RETURN(rc);
}

int mds_log_op_unlink(struct obd_device *obd, struct inode *inode,
                      struct lustre_msg *repmsg, int offset)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_stripe_md *lsm = NULL;
        struct llog_unlink_rec *lur;
#ifdef ENABLE_ORPHANS
        struct llog_obd_ctxt *ctxt;
#endif
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
        ctxt = obd->obd_llog_ctxt[LLOG_UNLINK_ORIG_CTXT];
        rc = llog_add(ctxt, &lur->lur_hdr,
                                 lsm, lustre_msg_buf(repmsg, offset + 1, 0),
                                 repmsg->buflens[offset + 1] /
                                 sizeof(struct llog_cookie));
#endif

        obd_free_memmd(mds->mds_osc_exp, &lsm);
        OBD_FREE(lur, sizeof(*lur));

        RETURN(rc);
}

static struct llog_operations mds_unlink_orig_logops = {
        //lop_cleanup:    mds_logop_cleanup,
        lop_add:        mds_llog_origin_add,
};

static struct llog_operations mds_size_repl_logops = {
        //lop_cleanup:    mds_logop_cleanup,
        lop_cancel:     mds_llog_repl_cancel
};

int mds_llog_init(struct obd_device *obd, struct obd_device *tgt,
                  int count, struct llog_logid *logid)
{
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        int rc;
        ENTRY;
        
        rc = llog_setup(obd, LLOG_UNLINK_ORIG_CTXT, tgt, 0, NULL, &mds_unlink_orig_logops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, LLOG_SIZE_REPL_CTXT, tgt, 0, NULL, &mds_size_repl_logops);
        if (rc)
                RETURN(rc);

        rc = obd_llog_init(lov_obd, tgt, count, logid);        
        if (rc) 
                CERROR("error lov_llog_init\n"); 

        RETURN(rc);
}

int mds_llog_finish(struct obd_device *obd, int count)
{
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        int rc;
        ENTRY;
        
        rc = llog_cleanup(obd->obd_llog_ctxt[LLOG_UNLINK_ORIG_CTXT]);
        if (rc)
                RETURN(rc);

        rc = llog_cleanup(obd->obd_llog_ctxt[LLOG_SIZE_REPL_CTXT]);
        if (rc)
                RETURN(rc);

        rc = obd_llog_finish(lov_obd, count);        
        if (rc) 
                CERROR("error lov_llog_finish\n"); 

        RETURN(rc);
}
