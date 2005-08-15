/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _MGS_INTERNAL_H
#define _MGS_INTERNAL_H

#define MGS_SERVICE_WATCHDOG_TIMEOUT (obd_timeout * 1000)

static inline struct mgs_obd *mgs_req2mgs(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mgs;
}

struct mgs_open_llogs {
        struct list_head    mol_list;
        struct dentry       *mol_dentry;
        __u64               mod_id;
};

extern struct lvfs_callback_ops mgs_lvfs_ops;

#endif /* _MGS_INTERNAL_H */
