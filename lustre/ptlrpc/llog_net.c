/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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
 *
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#ifdef __KERNEL__
#include <linux/fs.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <portals/list.h>
#include <linux/lvfs.h>

#ifdef __KERNEL__

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int llog_net_create(struct obd_device *obd, struct llog_handle **res,
                            struct llog_logid *logid, char *name)
{
        struct llog_handle *handle;
        ENTRY;

        handle = llog_alloc_handle();
        if (handle == NULL)
                RETURN(-ENOMEM);
        *res = handle;

        if (!logid) {
                CERROR("llog_net_create: must pass logid\n");
                llog_free_handle(handle);
                RETURN(-EINVAL);
        }

        handle->lgh_file = NULL;
        handle->lgh_obd = obd;
        handle->lgh_id.lgl_ogr = 1;
        handle->lgh_id.lgl_oid =
                handle->lgh_file->f_dentry->d_inode->i_ino;
        handle->lgh_id.lgl_ogen =
                handle->lgh_file->f_dentry->d_inode->i_generation;

        RETURN(0);
}

#ifdef ENABLE_ORPHANS
int llog_origin_handle_cancel(struct obd_device *obd, 
                              struct ptlrpc_request *req)
{
        struct llog_cookie *logcookies;
        int num_cookies, rc = 0;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle;
        int i;
        ENTRY;

        LASSERT(obd->obd_llog_ctxt);

        logcookies = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*logcookies));
        num_cookies = req->rq_reqmsg->buflens[0]/sizeof(*logcookies);
        if (logcookies == NULL || num_cookies == 0) {
                DEBUG_REQ(D_HA, req, "no cookies sent");
                RETURN(-EFAULT);
        }
#if 0
        /* workaround until we don't need to send replies */
        rc = lustre_pack_reply(req, 0, NULL, NULL);
        req->rq_repmsg->status = rc;
        if (rc)
                RETURN(rc);
        /* end workaround */
#endif
        i = logcookies->lgc_subsys;
        if (i < 0 || i > LLOG_OBD_MAX_HANDLES) {
                LBUG();
                RETURN(-EINVAL);
        }
        cathandle = obd->obd_llog_ctxt->loc_handles[i];
        LASSERT(cathandle);

        push_ctxt(&saved, &obd->obd_ctxt, NULL); 
        rc = llog_cat_cancel_records(cathandle, num_cookies, logcookies);
        if (rc)
                CERROR("cancel %d llog-records failed: %d\n", num_cookies, rc);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        //req->rq_repmsg->status = rc;
        RETURN(rc);
}
EXPORT_SYMBOL(llog_origin_handle_cancel);
#endif

int llog_receptor_accept(struct obd_device *obd, struct obd_import *imp)
{
        ENTRY;
        LASSERT(obd->obd_llog_ctxt);
        obd->obd_llog_ctxt->loc_imp = imp;
        RETURN(0);
}
EXPORT_SYMBOL(llog_receptor_accept);

int llog_initiator_connect(struct obd_device *obd)
{
        ENTRY;
        LASSERT(obd->obd_llog_ctxt);
        obd->obd_llog_ctxt->loc_imp = obd->u.cli.cl_import;
        RETURN(0);
}
EXPORT_SYMBOL(llog_initiator_connect);

struct llog_operations llog_net_ops = {
        //lop_next_block:  llog_lvfs_next_block,
        //lop_read_header: llog_lvfs_read_header,
        lop_create:      llog_net_create,
};

EXPORT_SYMBOL(llog_lvfs_ops);

#else /* !__KERNEL__ */
int llog_initiator_connect(struct obd_device *obd)
{
        return 0;
}
#endif
