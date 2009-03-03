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
 *
 * lustre/ofd/ofd_llog.c
 *
 * Author: Alex Tomas <alex@clusterfs.com>
 */


#define DEBUG_SUBSYSTEM S_FILTER

#include <lustre_log.h>
#if 0
#include <lustre_commit_confd.h>
#endif
#include "ofd_internal.h"

#define OBD_LLOG_GROUP  0

static struct llog_operations filter_mds_ost_repl_logops /* initialized below*/;
#if 0
static struct llog_operations filter_size_orig_logops = {
        lop_setup: llog_obd_origin_setup,
        lop_cleanup: llog_obd_origin_cleanup,
        lop_add: llog_obd_origin_add
};
#endif

int filter_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                     struct obd_device *tgt, int count,
                     struct llog_catid *catid, struct obd_uuid *uuid)
{
        struct filter_device *ofd = filter_dev(obd->obd_lu_dev);
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        if (olg == &obd->obd_olg) {
                LASSERT(ofd->ofd_lcm == NULL);
                ofd->ofd_lcm = llog_recov_thread_init(obd->obd_name);
                if (!ofd->ofd_lcm)
                        RETURN(-ENOMEM);

                filter_mds_ost_repl_logops = llog_client_ops;
                filter_mds_ost_repl_logops.lop_cancel = llog_obd_repl_cancel;
                filter_mds_ost_repl_logops.lop_connect = llog_obd_repl_connect;
                filter_mds_ost_repl_logops.lop_sync = llog_obd_repl_sync;
        } else {
                LASSERT(ofd->ofd_lcm != NULL);
        }
        rc = llog_setup(obd, olg, LLOG_MDS_OST_REPL_CTXT, tgt, 0, NULL,
                        &filter_mds_ost_repl_logops);
        if (rc)
                GOTO(cleanup, rc);

        /* FIXME - assign unlink_cb for filter's recovery */
        LASSERT(olg);
        ctxt = llog_group_get_ctxt(olg, LLOG_MDS_OST_REPL_CTXT);

        LASSERT(ctxt != NULL);
        ctxt->llog_proc_cb = filter_recov_log_mds_ost_cb;
        ctxt->loc_lcm = ofd->ofd_lcm;
        llog_ctxt_put(ctxt);

cleanup:
        if (rc) {
                llog_recov_thread_fini(ofd->ofd_lcm, 1);
                ofd->ofd_lcm = NULL;
        }
        RETURN(rc);
}

static int filter_group_llog_finish(struct obd_llog_group *olg)
{
        struct llog_ctxt *ctxt;
        int rc = 0, rc2 = 0;
        ENTRY;

        ctxt = llog_group_get_ctxt(olg, LLOG_MDS_OST_REPL_CTXT);
        if (ctxt)
                rc = llog_cleanup(ctxt);

#if 0
        ctxt = llog_group_get_ctxt(olg, LLOG_SIZE_ORIG_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);
        if (!rc)
                rc = rc2;
#endif

        RETURN(rc);
}

int filter_llog_finish(struct obd_device *obd, int count)
{
        struct filter_device *ofd = filter_dev(obd->obd_lu_dev);
        int rc;
        ENTRY;

        if (ofd->ofd_lcm) {
                llog_recov_thread_fini(ofd->ofd_lcm, obd->obd_force);
                ofd->ofd_lcm = NULL;
        }
        /* finish obd llog group */
        rc = filter_group_llog_finish(&obd->obd_olg);

        RETURN(rc);
}


struct obd_llog_group *filter_find_olg(struct obd_device *obd, int group)
{
        struct filter_device *ofd = filter_dev(obd->obd_lu_dev);
        struct obd_llog_group *olg, *nolg;
        int rc;

        if (group == OBD_LLOG_GROUP)
                RETURN(&obd->obd_olg);

        spin_lock(&ofd->ofd_llog_list_lock);
        list_for_each_entry(olg, &ofd->ofd_llog_list, olg_list) {
                if (olg->olg_group == group) {
                        spin_unlock(&ofd->ofd_llog_list_lock);
                        RETURN(olg);
                }
        }
        spin_unlock(&ofd->ofd_llog_list_lock);

        OBD_ALLOC_PTR(olg);
        if (olg == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        llog_group_init(olg, group);
        spin_lock(&ofd->ofd_llog_list_lock);
        list_for_each_entry(nolg, &ofd->ofd_llog_list, olg_list) {
                if (nolg->olg_group == group) {
                        spin_unlock(&ofd->ofd_llog_list_lock);
                        OBD_FREE_PTR(olg);
                        RETURN(nolg);
                }
        }
        list_add(&olg->olg_list, &ofd->ofd_llog_list);
        spin_unlock(&ofd->ofd_llog_list_lock);

        rc = llog_cat_initialize(obd, olg, 1, NULL);
        if (rc) {
                spin_lock(&ofd->ofd_llog_list_lock);
                list_del(&olg->olg_list);
                spin_unlock(&ofd->ofd_llog_list_lock);
                OBD_FREE_PTR(olg);
                RETURN(ERR_PTR(rc));
        }
        CDEBUG(D_OTHER, "%s: new llog group %u (0x%p)\n",
               obd->obd_name, group, olg);

        RETURN(olg);
}

/* Callback for processing the setattr log record received from MDS by
 * llog_client_api. */
static int filter_recov_log_setattr_cb(struct llog_ctxt *ctxt,
                                       struct llog_rec_hdr *rec,
                                       struct llog_cookie *cookie)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_export *exp = obd->obd_self_export;
        struct llog_setattr_rec *lsr;
        struct obd_info oinfo = { { { 0 } } };
        obd_id oid;
        int rc = 0;
        ENTRY;

        lsr = (struct llog_setattr_rec *)rec;
        OBDO_ALLOC(oinfo.oi_oa);
        if (oinfo.oi_oa == NULL)
                RETURN(-ENOMEM);

        oinfo.oi_oa->o_valid |= (OBD_MD_FLID | OBD_MD_FLUID | OBD_MD_FLGID |
                                 OBD_MD_FLCOOKIE);
        oinfo.oi_oa->o_id = lsr->lsr_oid;
        oinfo.oi_oa->o_gr = lsr->lsr_ogen;
        oinfo.oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        oinfo.oi_oa->o_uid = lsr->lsr_uid;
        oinfo.oi_oa->o_gid = lsr->lsr_gid;
        oinfo.oi_oa->o_lcookie = *cookie;
        oid = oinfo.oi_oa->o_id;

        rc = filter_setattr(exp, &oinfo, NULL);
        OBDO_FREE(oinfo.oi_oa);

        if (rc == -ENOENT) {
                CDEBUG(D_HA, "object already removed, send cookie\n");
                llog_cancel(ctxt, NULL, 1, cookie, 0);
                 GOTO(exit, rc = 0);
        }

        if (rc == 0)
                CDEBUG(D_HA, "object: "LPU64" in record is chown/chgrp\n", oid);

exit:
        RETURN(rc);
}

/* Callback for processing the unlink log record received from MDS by 
 * llog_client_api. */
int filter_recov_log_unlink_cb(struct llog_ctxt *ctxt,
                                      struct llog_rec_hdr *rec,
                                      struct llog_cookie *cookie)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_export *exp = obd->obd_self_export;
        struct llog_unlink_rec *lur;
        struct obdo *oa;
        obd_id oid;
        int rc = 0;
        ENTRY;

        lur = (struct llog_unlink_rec *)rec;
        OBDO_ALLOC(oa);
        if (oa == NULL)
                RETURN(-ENOMEM);
        oa->o_valid |= OBD_MD_FLCOOKIE;
        oa->o_id = lur->lur_oid;
        oa->o_gr = lur->lur_ogen;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        oa->o_lcookie = *cookie;
        oid = oa->o_id;

        rc = filter_destroy(exp, oa, NULL, NULL, NULL, NULL);
        OBDO_FREE(oa);
        if (rc == -ENOENT) {
                CDEBUG(D_HA, "object already removed, send cookie\n");
                llog_cancel(ctxt, NULL, 1, cookie, 0);
                GOTO(exit, rc = 0);
        }

        if (rc == 0)
                CDEBUG(D_HA, "object: "LPU64" in record is destroyed\n", oid);

exit:
        RETURN(rc);
}

int filter_recov_log_mds_ost_cb(struct llog_handle *llh,
                               struct llog_rec_hdr *rec, void *data)
{
        struct llog_ctxt *ctxt = llh->lgh_ctxt;
        struct llog_cookie cookie;
        int rc = 0;
        ENTRY;

        if (ctxt->loc_obd->obd_stopping)
                RETURN(LLOG_PROC_BREAK);

        if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_LLOG_RECOVERY_TIMEOUT, 30);
        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
        cookie.lgc_index = rec->lrh_index;

        switch (rec->lrh_type) {
        case MDS_UNLINK_REC:
                rc = filter_recov_log_unlink_cb(ctxt, rec, &cookie);
                break;
        case MDS_SETATTR_REC:
                rc = filter_recov_log_setattr_cb(ctxt, rec, &cookie);
                break;
        case LLOG_GEN_REC: {
                struct llog_gen_rec *lgr = (struct llog_gen_rec *)rec;
                if (llog_gen_lt(lgr->lgr_gen, ctxt->loc_gen))
                        rc = 0;
                else
                        rc = LLOG_PROC_BREAK;
                CDEBUG(D_HA, "fetch generation log, send cookie\n");
                llog_cancel(ctxt, NULL, 1, &cookie, 0);
                RETURN(rc);
                }
                break;
        default:
                CERROR("log record type %08x unknown\n", rec->lrh_type);
                RETURN(-EINVAL);
                break;
        }

        RETURN(rc);
}

static struct obd_llog_group *
filter_find_olg_internal(struct filter_obd *filter, int group)
{
        struct obd_llog_group *olg;

        LASSERT_SPIN_LOCKED(&filter->fo_llog_list_lock);
        list_for_each_entry(olg, &filter->fo_llog_list, olg_list) {
                if (olg->olg_group == group)
                        RETURN(olg);
        }
        RETURN(NULL);
}


/**
 * Find the llog_group of the filter according to the group. If it can not
 * find, create the llog_group, which only happens when mds is being synced
 * with OST.
 */
struct obd_llog_group *filter_find_create_olg(struct obd_device *obd, int group)
{
        struct obd_llog_group *olg = NULL;
        struct filter_obd *filter;
        int rc;

        filter = &obd->u.filter;

        if (group == FILTER_GROUP_LLOG)
                RETURN(&obd->obd_olg);

        spin_lock(&filter->fo_llog_list_lock);
        olg = filter_find_olg_internal(filter, group);
        if (olg) {
                if (olg->olg_initializing) {
                        GOTO(out_unlock, olg = ERR_PTR(-EBUSY));
                } else {
                        GOTO(out_unlock, olg);
                }
        }
        OBD_ALLOC_PTR(olg);
        if (olg == NULL)
               GOTO(out_unlock, olg = ERR_PTR(-ENOMEM));

        llog_group_init(olg, group);
        list_add(&olg->olg_list, &filter->fo_llog_list);
        olg->olg_initializing = 1;
        spin_unlock(&filter->fo_llog_list_lock);

        rc = llog_cat_initialize(obd, olg, 1, NULL);
        if (rc) {
               spin_lock(&filter->fo_llog_list_lock);
               list_del(&olg->olg_list);
               spin_unlock(&filter->fo_llog_list_lock);
               OBD_FREE_PTR(olg);
               GOTO(out, olg = ERR_PTR(-ENOMEM));
        }
        spin_lock(&filter->fo_llog_list_lock);
        olg->olg_initializing = 0;
        spin_unlock(&filter->fo_llog_list_lock);
        CDEBUG(D_OTHER, "%s: new llog group %u (0x%p)\n",
              obd->obd_name, group, olg);
out:
        RETURN(olg);

out_unlock:
        spin_unlock(&filter->fo_llog_list_lock);
        GOTO(out, olg);
}

