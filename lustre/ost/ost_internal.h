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

#define OSS_SERVICE_WATCHDOG_FACTOR 2000

/*
 * tunables for per-thread page pool (bug 5137)
 */
#define OST_THREAD_POOL_SIZE PTLRPC_MAX_BRW_PAGES  /* pool size in pages */
#define OST_THREAD_POOL_GFP  CFS_ALLOC_HIGHUSER    /* GFP mask for pool pages */

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

#define OSS_DEF_CREATE_THREADS  2UL
#define OSS_MAX_CREATE_THREADS 16UL

/* Quota stuff */
extern quota_interface_t *quota_interface;

#endif /* OST_INTERNAL_H */
