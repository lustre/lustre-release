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


struct llog_handle *mds_get_catalog(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mds_server_data *msd = mds->mds_server_data;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle = NULL;
        struct llog_logid logid;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        if (msd->msd_catalog_oid) {
                logid.lgl_oid = le64_to_cpu(msd->msd_catalog_oid);
                logid.lgl_ogen = le32_to_cpu(msd->msd_catalog_ogen);
                rc = llog_create(obd, &cathandle, &logid, NULL);
                if (rc) {
                        CERROR("error opening catalog "LPX64":%x: rc %d\n",
                               logid.lgl_oid, logid.lgl_ogen,
                               (int)PTR_ERR(cathandle));
                        msd->msd_catalog_oid = 0;
                        msd->msd_catalog_ogen = 0;
                }
        }

        if (!msd->msd_catalog_oid) {
                rc = llog_create(obd, &cathandle, NULL, NULL);
                if (rc) {
                        CERROR("error creating new catalog: rc %d\n", rc);
                        cathandle = ERR_PTR(rc);
                        GOTO(out, cathandle);
                }
                logid = cathandle->lgh_id;
                msd->msd_catalog_oid = cpu_to_le64(logid.lgl_oid);
                msd->msd_catalog_ogen = cpu_to_le32(logid.lgl_ogen);
                rc = mds_update_server_data(obd, 0);
                if (rc) {
                        CERROR("error writing new catalog to disk: rc %d\n",rc);
                        GOTO(out_handle, rc);
                }
        }

        //rc = llog_init_handle(cathandle, LLOG_F_IS_CAT, &obd->u.filter.fo_mdc_uuid);
        rc = llog_init_handle(cathandle, LLOG_F_IS_CAT, &obd->obd_uuid);
        if (rc)
                GOTO(out_handle, rc);
out:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        RETURN(cathandle);

out_handle:
        llog_close(cathandle);
        cathandle = ERR_PTR(rc);
        goto out;
}


int mds_log_op_unlink(struct obd_device *obd, 
                      struct inode *inode, struct lustre_msg *repmsg,
                      int offset)
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
#if 0
        rc = obd_log_add(mds->mds_osc_exp, mds->mds_catalog, &lur->lur_hdr,
                         lsm, lustre_msg_buf(repmsg, offset + 1, 0),
                         repmsg->buflens[offset+1]/sizeof(struct llog_cookie),
                         NULL);
#endif
        rc = lov_log_add(mds->mds_osc_exp, mds->mds_catalog, &lur->lur_hdr,
                         lsm, lustre_msg_buf(repmsg, offset + 1, 0),
                         repmsg->buflens[offset+1]/sizeof(struct llog_cookie));
#endif

        obd_free_memmd(mds->mds_osc_exp, &lsm);
        OBD_FREE(lur, sizeof(*lur));

        RETURN(rc);
}
