/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef OST_INTERNAL_H
#define OST_INTERNAL_H

#ifdef LPROCFS
extern void ost_print_req(void *seq_file, struct ptlrpc_request *req);
#else
# define ost_print_req NULL
#endif

#ifdef HAVE_QUOTA_SUPPORT
/* Quota stuff */
int ost_quotacheck(struct ptlrpc_request *req);
int ost_quotactl(struct ptlrpc_request *req);
#else
static inline int ost_quotacheck(struct ptlrpc_request *req)
{
        req->rq_status = -ENOTSUPP;
        return -ENOTSUPP;
}
static inline int ost_quotactl(struct ptlrpc_request *req)
{
        req->rq_status = -ENOTSUPP;
        return -ENOTSUPP;
}
#endif

#endif /* OST_INTERNAL_H */
