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

/*
 * tunables for per-thread page pool (bug 5137)
 */
enum {
        /*
         * pool size in pages
         */
        OST_THREAD_POOL_SIZE = PTLRPC_MAX_BRW_PAGES,
        /*
         * GFP mask used to allocate pages for pool
         */
        OST_THREAD_POOL_GFP  = GFP_HIGHUSER
};

struct page;
struct niobuf_local;
struct niobuf_remote;
struct ptlrpc_request;

/*
 * struct ost_thread_local_cache is allocated and initialized for each OST
 * thread by ost_thread_init().
 */
struct ost_thread_local_cache {
        /*
         * pool of pages and nio buffers used by write-path
         */
        struct page          *page  [OST_THREAD_POOL_SIZE];
        struct niobuf_local   local [OST_THREAD_POOL_SIZE];
        struct niobuf_remote  remote[OST_THREAD_POOL_SIZE];
};

struct ost_thread_local_cache *ost_tls(struct ptlrpc_request *r);

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
