/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _MGS_INTERNAL_H
#define _MGS_INTERNAL_H

#include <linux/lustre_mgs.h>

#define MGS_SERVICE_WATCHDOG_TIMEOUT (obd_timeout * 1000)

extern struct lvfs_callback_ops mgs_lvfs_ops;

static inline struct mgs_obd *mgs_req2mgs(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mgs;
}

extern int mgmt_handle_first_connect(struct ptlrpc_request *req);
extern int mgmt_handle_mds_add(struct ptlrpc_request *req);
extern int mgmt_handle_ost_add(struct ptlrpc_request *req);
extern int mgmt_handle_ost_del(struct ptlrpc_request *req);
#endif
