/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
 */

#ifndef _LUSTRE_NET_H
#define _LUSTRE_NET_H

#ifdef __KERNEL__
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/tqueue.h>
#else
#include <linux/workqueue.h>
#endif
#endif

#include <linux/kp30.h>
// #include <linux/obd.h>
#include <portals/p30.h>
#include <portals/lib-types.h>                  /* FIXME (for PTL_MD_MAX_IOV) */
#include <linux/lustre_idl.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_import.h>
#include <linux/lprocfs_status.h>

/* Size over which to OBD_VMALLOC() rather than OBD_ALLOC() service request
 * buffers */
#define SVC_BUF_VMALLOC_THRESHOLD (2*PAGE_SIZE)

/* The following constants determine how much memory is devoted to
 * buffering in the lustre services.
 *
 * ?_NEVENTS            # event queue entries
 *
 * ?_NBUFS              # request buffers
 * ?_BUFSIZE            # bytes in a single request buffer
 * total memory = ?_NBUFS * ?_BUFSIZE
 *
 * ?_MAXREQSIZE         # maximum request service will receive
 * messages larger than ?_MAXREQSIZE are dropped.
 * request buffers are auto-unlinked when less than ?_MAXREQSIZE
 * is left in them.
 */

#define LDLM_NUM_THREADS        min(smp_num_cpus * smp_num_cpus * 8, 64)
#define LDLM_NBUF_MAX   256UL
#define LDLM_BUFSIZE    (8 * 1024)
#define LDLM_MAXREQSIZE (5 * 1024)
#define LDLM_MAXMEM      (num_physpages*(PAGE_SIZE/1024))
#define LDLM_NBUFS       min(LDLM_MAXMEM/LDLM_BUFSIZE, LDLM_NBUF_MAX)

#define MDT_MAX_THREADS 32UL
#define MDT_NUM_THREADS max(min_t(unsigned long, num_physpages / 8192, \
                                  MDT_MAX_THREADS), 2UL)
#define MDS_NBUF_MAX    512UL
#define MDS_BUFSIZE     (8 * 1024)
/* Assume file name length = FNAME_MAX = 256 (true for extN).
 *        path name length = PATH_MAX = 4096
 *        LOV MD size max  = EA_MAX = 4000
 * symlink:  FNAME_MAX + PATH_MAX  <- largest
 * link:     FNAME_MAX + PATH_MAX  (mds_rec_link < mds_rec_create)
 * rename:   FNAME_MAX + FNAME_MAX
 * open:     FNAME_MAX + EA_MAX
 *
 * MDS_MAXREQSIZE ~= 4736 bytes =
 * lustre_msg + ldlm_request + mds_body + mds_rec_create + FNAME_MAX + PATH_MAX
 *
 * Realistic size is about 512 bytes (20 character name + 128 char symlink),
 * except in the open case where there are a large number of OSTs in a LOV.
 */
#define MDS_MAXREQSIZE  (5 * 1024)
#define MDS_MAXMEM      (num_physpages*(PAGE_SIZE/128))
#define MDS_NBUFS       min(MDS_MAXMEM/MDS_BUFSIZE, MDS_NBUF_MAX)

#define OST_MAX_THREADS 36UL
#define OST_NUM_THREADS max(min_t(unsigned long, num_physpages / 8192, \
                                  OST_MAX_THREADS), 2UL)
#define OST_NBUF_MAX    5000UL
#define OST_BUFSIZE     (8 * 1024)
/* OST_MAXREQSIZE ~= 1640 bytes =
 * lustre_msg + obdo + 16 * obd_ioobj + 64 * niobuf_remote
 *
 * - single object with 16 pages is 512 bytes
 * - OST_MAXREQSIZE must be at least 1 page of cookies plus some spillover
 */
#define OST_MAXREQSIZE  (5 * 1024)
#define OST_MAXMEM      (num_physpages*(PAGE_SIZE/128))
#define OST_NBUFS       min(OST_MAXMEM/OST_BUFSIZE, OST_NBUF_MAX)

#define PTLBD_NUM_THREADS        4
#define PTLBD_NBUFS      20
#define PTLBD_BUFSIZE    (32 * 1024)
#define PTLBD_MAXREQSIZE 1024

struct ptlrpc_peer {
        ptl_nid_t         peer_nid;
        struct ptlrpc_ni *peer_ni;
};

struct ptlrpc_connection {
        struct list_head        c_link;
        struct ptlrpc_peer      c_peer;
        struct obd_uuid         c_remote_uuid;
        atomic_t                c_refcount;
};

struct ptlrpc_client {
        __u32                     cli_request_portal;
        __u32                     cli_reply_portal;
        char                     *cli_name;
};

/* state flags of requests */
/* XXX only ones left are those used by the bulk descs as well! */
#define PTL_RPC_FL_INTR      (1 << 0)  /* reply wait was interrupted by user */
#define PTL_RPC_FL_TIMEOUT   (1 << 7)  /* request timed out waiting for reply */

#define REQ_MAX_ACK_LOCKS 8

#define SWAB_PARANOIA 1
#if SWAB_PARANOIA
/* unpacking: assert idx not unpacked already */
#define LASSERT_REQSWAB(rq, idx)                                \
do {                                                            \
        LASSERT ((idx) < sizeof ((rq)->rq_req_swab_mask) * 8);  \
        LASSERT (((rq)->rq_req_swab_mask & (1 << (idx))) == 0); \
        (rq)->rq_req_swab_mask |= (1 << (idx));                 \
} while (0)

#define LASSERT_REPSWAB(rq, idx)                                \
do {                                                            \
        LASSERT ((idx) < sizeof ((rq)->rq_rep_swab_mask) * 8);  \
        LASSERT (((rq)->rq_rep_swab_mask & (1 << (idx))) == 0); \
        (rq)->rq_rep_swab_mask |= (1 << (idx));                 \
} while (0)

/* just looking: assert idx already unpacked */
#define LASSERT_REQSWABBED(rq, idx)                     \
LASSERT ((idx) < sizeof ((rq)->rq_req_swab_mask) * 8 && \
         ((rq)->rq_req_swab_mask & (1 << (idx))) != 0)

#define LASSERT_REPSWABBED(rq, idx)                     \
LASSERT ((idx) < sizeof ((rq)->rq_rep_swab_mask) * 8 && \
         ((rq)->rq_rep_swab_mask & (1 << (idx))) != 0)
#else
#define LASSERT_REQSWAB(rq, idx)
#define LASSERT_REPSWAB(rq, idx)
#define LASSERT_REQSWABBED(rq, idx)
#define LASSERT_REPSWABBED(rq, idx)
#endif

union ptlrpc_async_args {
        /* Scratchpad for passing args to completion interpreter. Users
         * cast to the struct of their choosing, and LASSERT that this is
         * big enough.  For _tons_ of context, OBD_ALLOC a struct and store
         * a pointer to it here.  The pointer_arg ensures this struct is at
         * least big enough for that. */
        void      *pointer_arg[9];
        __u64      space[4];
};

struct ptlrpc_request_set;
typedef int (*set_interpreter_func)(struct ptlrpc_request_set *, void *, int);

struct ptlrpc_request_set {
        int               set_remaining; /* # uncompleted requests */
        wait_queue_head_t set_waitq;
        wait_queue_head_t *set_wakeup_ptr;
        struct list_head  set_requests;
        set_interpreter_func    set_interpret; /* completion callback */
        union ptlrpc_async_args set_args; /* completion context */
        /* locked so that any old caller can communicate requests to
         * the set holder who can then fold them into the lock-free set */
        spinlock_t        set_new_req_lock;
        struct list_head  set_new_requests;
};

struct ptlrpc_bulk_desc;

/*
 * ptlrpc callback & work item stuff
 */
struct ptlrpc_cb_id {
        void   (*cbid_fn)(ptl_event_t *ev);     /* specific callback fn */
        void    *cbid_arg;                      /* additional arg */
};

#define RS_MAX_LOCKS 4
#define RS_DEBUG     1

struct ptlrpc_reply_state {
        struct ptlrpc_cb_id   rs_cb_id;
        struct list_head      rs_list;
        struct list_head      rs_exp_list;
        struct list_head      rs_obd_list;
#if RS_DEBUG
        struct list_head      rs_debug_list;
#endif
        /* updates to following flag serialised by srv_request_lock */
        unsigned int          rs_difficult:1;   /* ACK/commit stuff */
        unsigned int          rs_scheduled:1;   /* being handled? */
        unsigned int          rs_scheduled_ever:1; /* any schedule attempts? */
        unsigned int          rs_handled:1;     /* been handled yet? */
        unsigned int          rs_on_net:1;      /* reply_out_callback pending? */

        int                   rs_size;
        __u64                 rs_transno;
        __u64                 rs_xid;
        struct obd_export    *rs_export;
        struct ptlrpc_srv_ni *rs_srv_ni;
        ptl_handle_md_t       rs_md_h;

        /* locks awaiting client reply ACK */
        int                   rs_nlocks;
        struct lustre_handle  rs_locks[RS_MAX_LOCKS];
        ldlm_mode_t           rs_modes[RS_MAX_LOCKS];
        /* last member: variable sized reply message */
        struct lustre_msg     rs_msg;
};

struct ptlrpc_request {
        int rq_type; /* one of PTL_RPC_MSG_* */
        struct list_head rq_list;
        int rq_status;
        spinlock_t rq_lock;
        /* client-side flags */
        unsigned int rq_intr:1, rq_replied:1, rq_err:1,
            rq_timedout:1, rq_resend:1, rq_restart:1, rq_replay:1,
            rq_no_resend:1, rq_waiting:1, rq_receiving_reply:1;
        int rq_phase;
        /* client-side refcount for SENT race */
        atomic_t rq_refcount;

        int rq_request_portal; /* XXX FIXME bug 249 */
        int rq_reply_portal; /* XXX FIXME bug 249 */

        /* client-side # reply bytes actually received  */
        int rq_nob_received;

        int rq_reqlen;
        struct lustre_msg *rq_reqmsg;

        int rq_timeout;
        int rq_replen;
        struct lustre_msg *rq_repmsg;
        __u64 rq_transno;
        __u64 rq_xid;
        struct list_head rq_replay_list;

#if SWAB_PARANOIA
        __u32 rq_req_swab_mask;
        __u32 rq_rep_swab_mask;
#endif

        int rq_import_generation;
        enum lustre_imp_state rq_send_state;

        /* client+server request */
        ptl_handle_md_t      rq_req_md_h;
        struct ptlrpc_cb_id  rq_req_cbid;

        /* server-side... */
        struct timeval                     rq_arrival_time; /* request arrival time */
        struct ptlrpc_reply_state         *rq_reply_state; /* separated reply state */
        struct ptlrpc_request_buffer_desc *rq_rqbd; /* incoming request buffer */
        
        /* client-only incoming reply */
        ptl_handle_md_t      rq_reply_md_h;
        wait_queue_head_t    rq_reply_waitq;
        struct ptlrpc_cb_id  rq_reply_cbid;
        
        struct ptlrpc_peer rq_peer; /* XXX see service.c can this be factored away? */
        struct obd_export *rq_export;
        struct obd_import *rq_import;
        
        void (*rq_replay_cb)(struct ptlrpc_request *);
        void (*rq_commit_cb)(struct ptlrpc_request *);
        void  *rq_cb_data;

        struct ptlrpc_bulk_desc *rq_bulk;       /* client side bulk */
        time_t rq_sent;                         /* when the request was sent */

        /* Multi-rpc bits */
        struct list_head rq_set_chain;
        struct ptlrpc_request_set *rq_set;
        void *rq_interpret_reply;               /* Async completion handler */
        union ptlrpc_async_args rq_async_args;  /* Async completion context */
};


#define RQ_PHASE_NEW           0xebc0de00
#define RQ_PHASE_RPC           0xebc0de01
#define RQ_PHASE_BULK          0xebc0de02
#define RQ_PHASE_INTERPRET     0xebc0de03
#define RQ_PHASE_COMPLETE      0xebc0de04

/* Spare the preprocessor, spoil the bugs. */
#define FLAG(field, str) (field ? str : "")

#define PTLRPC_REQUEST_COMPLETE(req) ((req)->rq_phase > RQ_PHASE_RPC)

#define DEBUG_REQ_FLAGS(req)                                                    \
        ((req->rq_phase == RQ_PHASE_NEW) ? "New" :                              \
         (req->rq_phase == RQ_PHASE_RPC) ? "Rpc" :                              \
         (req->rq_phase == RQ_PHASE_INTERPRET) ? "Interpret" :                  \
         (req->rq_phase == RQ_PHASE_COMPLETE) ? "Complete" : "?phase?"),        \
        FLAG(req->rq_intr, "I"), FLAG(req->rq_replied, "R"),                    \
        FLAG(req->rq_err, "E"),                                                 \
        FLAG(req->rq_timedout, "X") /* eXpired */, FLAG(req->rq_resend, "S"),   \
        FLAG(req->rq_restart, "T"), FLAG(req->rq_replay, "P"),                  \
        FLAG(req->rq_no_resend, "N"),                                           \
        FLAG(req->rq_waiting, "W")

#define REQ_FLAGS_FMT "%s:%s%s%s%s%s%s%s%s%s"

#define DEBUG_REQ(level, req, fmt, args...)                                    \
do {                                                                           \
CDEBUG(level, "@@@ " fmt                                                       \
       " req@%p x"LPD64"/t"LPD64" o%d->%s@%s:%d lens %d/%d ref %d fl "         \
       REQ_FLAGS_FMT"/%x/%x rc %d/%d\n" , ## args, req, req->rq_xid,           \
       req->rq_transno,                                                        \
       req->rq_reqmsg ? req->rq_reqmsg->opc : -1,                              \
       req->rq_import ? (char *)req->rq_import->imp_target_uuid.uuid : "<?>",  \
       req->rq_import ?                                                        \
          (char *)req->rq_import->imp_connection->c_remote_uuid.uuid : "<?>",  \
       (req->rq_import && req->rq_import->imp_client) ?                        \
           req->rq_import->imp_client->cli_request_portal : -1,                \
       req->rq_reqlen, req->rq_replen,                                         \
       atomic_read(&req->rq_refcount),                                         \
       DEBUG_REQ_FLAGS(req),                                                   \
       req->rq_reqmsg ? req->rq_reqmsg->flags : 0,                             \
       req->rq_repmsg ? req->rq_repmsg->flags : 0,                             \
       req->rq_status, req->rq_repmsg ? req->rq_repmsg->status : 0);           \
} while (0)

struct ptlrpc_bulk_page {
        struct list_head bp_link;
        int bp_buflen;
        int bp_pageoffset;                      /* offset within a page */
        struct page *bp_page;
};

#define BULK_GET_SOURCE   0
#define BULK_PUT_SINK     1
#define BULK_GET_SINK     2
#define BULK_PUT_SOURCE   3

struct ptlrpc_bulk_desc {
        unsigned int bd_success:1;              /* completed successfully */
        unsigned int bd_network_rw:1;           /* accessible to the network */
        unsigned int bd_type:2;                 /* {put,get}{source,sink} */
        unsigned int bd_registered:1;           /* client side */
        spinlock_t   bd_lock;                   /* serialise with callback */
        int bd_import_generation;
        struct obd_export *bd_export;
        struct obd_import *bd_import;
        __u32 bd_portal;
        struct ptlrpc_request *bd_req;          /* associated request */
        wait_queue_head_t      bd_waitq;        /* server side only WQ */
        int                    bd_page_count;   /* # pages (== entries in bd_iov) */
        int                    bd_max_pages;    /* allocated size of bd_iov */
        int                    bd_nob;          /* # bytes covered */
        int                    bd_nob_transferred; /* # bytes GOT/PUT */

        __u64                  bd_last_xid;

        struct ptlrpc_cb_id    bd_cbid;         /* network callback info */
        ptl_handle_md_t        bd_md_h;         /* associated MD */
        
#ifdef __KERNEL__
        ptl_kiov_t bd_iov[PTL_MD_MAX_IOV];
#else
        struct iovec bd_iov[PTL_MD_MAX_IOV];
#endif
};

struct ptlrpc_thread {
        struct list_head t_link;

        __u32 t_flags;
        wait_queue_head_t t_ctl_waitq;
};

struct ptlrpc_request_buffer_desc {
        struct list_head       rqbd_list;
        struct ptlrpc_srv_ni  *rqbd_srv_ni;
        ptl_handle_md_t        rqbd_md_h;
        int                    rqbd_refcount;
        int                    rqbd_eventcount;
        char                  *rqbd_buffer;
        struct ptlrpc_cb_id    rqbd_cbid;
        struct ptlrpc_request  rqbd_req;
};

/* event queues are per-ni, because one day we may get a hardware
 * supported NAL that delivers events asynchonously wrt kernel portals
 * into the eq.
 */
struct ptlrpc_ni { /* Generic interface state */
        char                   *pni_name;
        int                     pni_number;
        ptl_handle_ni_t         pni_ni_h;
        ptl_handle_eq_t         pni_eq_h;
};

struct ptlrpc_srv_ni {
        /* Interface-specific service state */
        struct ptlrpc_service  *sni_service;    /* owning service */
        struct ptlrpc_ni       *sni_ni;         /* network interface */
        struct list_head        sni_rqbds;      /* all the request buffers */
        struct list_head        sni_active_replies; /* all the active replies */
        int                     sni_nrqbd_receiving; /* # posted request buffers */
};

typedef int (*svc_handler_t)(struct ptlrpc_request *req);

struct ptlrpc_service {
        struct list_head srv_list;              /* chain thru all services */
        int              srv_max_req_size;      /* biggest request to receive */
        int              srv_buf_size;          /* size of individual buffers */
        int              srv_nbufs;             /* total # req buffer descs allocated */
        int              srv_nthreads;          /* # running threads */
        int              srv_n_difficult_replies; /* # 'difficult' replies */
        int              srv_n_active_reqs;     /* # reqs being served */
        
        __u32 srv_req_portal;
        __u32 srv_rep_portal;

        int               srv_n_queued_reqs;    /* # reqs waiting to be served */
        struct list_head  srv_request_queue;    /* reqs waiting for service */

        atomic_t          srv_outstanding_replies;
        struct list_head  srv_reply_queue;      /* replies waiting for service */

        wait_queue_head_t srv_waitq; /* all threads sleep on this */

        struct list_head   srv_threads;
        struct obd_device *srv_obddev;
        svc_handler_t      srv_handler;
        
        char *srv_name;  /* only statically allocated strings here; we don't clean them */

        spinlock_t               srv_lock;

        struct proc_dir_entry   *srv_procroot;
        struct lprocfs_stats    *srv_stats;
        
        struct ptlrpc_srv_ni srv_interfaces[0];
};

/* ptlrpc/events.c */
extern struct ptlrpc_ni ptlrpc_interfaces[];
extern int              ptlrpc_ninterfaces;
extern int ptlrpc_uuid_to_peer(struct obd_uuid *uuid, struct ptlrpc_peer *peer);
extern void request_out_callback (ptl_event_t *ev);
extern void reply_in_callback(ptl_event_t *ev);
extern void client_bulk_callback (ptl_event_t *ev);
extern void request_in_callback(ptl_event_t *ev);
extern void reply_out_callback(ptl_event_t *ev);
extern void server_bulk_callback (ptl_event_t *ev);

/* ptlrpc/connection.c */
void ptlrpc_dump_connections(void);
void ptlrpc_readdress_connection(struct ptlrpc_connection *, struct obd_uuid *);
struct ptlrpc_connection *ptlrpc_get_connection(struct ptlrpc_peer *peer,
                                                struct obd_uuid *uuid);
int ptlrpc_put_connection(struct ptlrpc_connection *c);
struct ptlrpc_connection *ptlrpc_connection_addref(struct ptlrpc_connection *);
void ptlrpc_init_connection(void);
void ptlrpc_cleanup_connection(void);

/* ptlrpc/niobuf.c */
int ptlrpc_start_bulk_transfer(struct ptlrpc_bulk_desc *desc);
void ptlrpc_abort_bulk(struct ptlrpc_bulk_desc *desc);
int ptlrpc_register_bulk(struct ptlrpc_request *req);
void ptlrpc_unregister_bulk (struct ptlrpc_request *req);

static inline int ptlrpc_bulk_active (struct ptlrpc_bulk_desc *desc) 
{
        unsigned long flags;
        int           rc;

        spin_lock_irqsave (&desc->bd_lock, flags);
        rc = desc->bd_network_rw;
        spin_unlock_irqrestore (&desc->bd_lock, flags);
        return (rc);
}

int ptlrpc_send_reply(struct ptlrpc_request *req, int);
int ptlrpc_reply(struct ptlrpc_request *req);
int ptlrpc_error(struct ptlrpc_request *req);
void ptlrpc_resend_req(struct ptlrpc_request *request);
int ptl_send_rpc(struct ptlrpc_request *request);
void ptlrpc_register_rqbd (struct ptlrpc_request_buffer_desc *rqbd);

/* ptlrpc/client.c */
void ptlrpc_init_client(int req_portal, int rep_portal, char *name,
                        struct ptlrpc_client *);
void ptlrpc_cleanup_client(struct obd_import *imp);
struct ptlrpc_connection *ptlrpc_uuid_to_connection(struct obd_uuid *uuid);

static inline int
ptlrpc_client_receiving_reply (struct ptlrpc_request *req)
{
        unsigned long flags;
        int           rc;
        
        spin_lock_irqsave(&req->rq_lock, flags);
        rc = req->rq_receiving_reply;
        spin_unlock_irqrestore(&req->rq_lock, flags);
        return (rc);
}

static inline int
ptlrpc_client_replied (struct ptlrpc_request *req)
{
        unsigned long flags;
        int           rc;
        
        spin_lock_irqsave(&req->rq_lock, flags);
        rc = req->rq_replied;
        spin_unlock_irqrestore(&req->rq_lock, flags);
        return (rc);
}

static inline void
ptlrpc_wake_client_req (struct ptlrpc_request *req)
{
        if (req->rq_set == NULL)
                wake_up(&req->rq_reply_waitq);
        else
                wake_up(&req->rq_set->set_waitq);
}

int ptlrpc_queue_wait(struct ptlrpc_request *req);
int ptlrpc_replay_req(struct ptlrpc_request *req);
void ptlrpc_unregister_reply(struct ptlrpc_request *req);
void ptlrpc_restart_req(struct ptlrpc_request *req);
void ptlrpc_abort_inflight(struct obd_import *imp);

struct ptlrpc_request_set *ptlrpc_prep_set(void);
int ptlrpc_set_next_timeout(struct ptlrpc_request_set *);
int ptlrpc_check_set(struct ptlrpc_request_set *set);
int ptlrpc_set_wait(struct ptlrpc_request_set *);
int ptlrpc_expired_set(void *data);
void ptlrpc_interrupted_set(void *data);
void ptlrpc_mark_interrupted(struct ptlrpc_request *req);
void ptlrpc_set_destroy(struct ptlrpc_request_set *);
void ptlrpc_set_add_req(struct ptlrpc_request_set *, struct ptlrpc_request *);
void ptlrpc_set_add_new_req(struct ptlrpc_request_set *,
                            struct ptlrpc_request *);

struct ptlrpc_request *ptlrpc_prep_req(struct obd_import *imp, int opcode,
                                       int count, int *lengths, char **bufs);
void ptlrpc_free_req(struct ptlrpc_request *request);
void ptlrpc_req_finished(struct ptlrpc_request *request);
void ptlrpc_req_finished_with_imp_lock(struct ptlrpc_request *request);
struct ptlrpc_request *ptlrpc_request_addref(struct ptlrpc_request *req);
struct ptlrpc_bulk_desc *ptlrpc_prep_bulk_imp (struct ptlrpc_request *req,
                                               int npages, int type, int portal);
struct ptlrpc_bulk_desc *ptlrpc_prep_bulk_exp(struct ptlrpc_request *req,
                                              int npages, int type, int portal);
void ptlrpc_free_bulk(struct ptlrpc_bulk_desc *bulk);
void ptlrpc_prep_bulk_page(struct ptlrpc_bulk_desc *desc,
                           struct page *page, int pageoffset, int len);
void ptlrpc_retain_replayable_request(struct ptlrpc_request *req,
                                      struct obd_import *imp);
__u64 ptlrpc_next_xid(void);

/* ptlrpc/service.c */
void ptlrpc_save_lock (struct ptlrpc_request *req, 
                       struct lustre_handle *lock, int mode);
void ptlrpc_commit_replies (struct obd_device *obd);
void ptlrpc_schedule_difficult_reply (struct ptlrpc_reply_state *rs);
struct ptlrpc_service *ptlrpc_init_svc(int nbufs, int bufsize, int max_req_size,
                                       int req_portal, int rep_portal, 
                                       svc_handler_t, char *name,
                                       struct proc_dir_entry *proc_entry);
void ptlrpc_stop_all_threads(struct ptlrpc_service *svc);
int ptlrpc_start_n_threads(struct obd_device *dev, struct ptlrpc_service *svc,
                           int cnt, char *base_name);
int ptlrpc_start_thread(struct obd_device *dev, struct ptlrpc_service *svc,
                        char *name);
int ptlrpc_unregister_service(struct ptlrpc_service *service);
int liblustre_check_services (void *arg);

struct ptlrpc_svc_data {
        char *name;
        struct ptlrpc_service *svc;
        struct ptlrpc_thread *thread;
        struct obd_device *dev;
};

/* ptlrpc/import.c */
int ptlrpc_connect_import(struct obd_import *imp, char * new_uuid);
int ptlrpc_init_import(struct obd_import *imp);
int ptlrpc_disconnect_import(struct obd_import *imp);
int ptlrpc_import_recovery_state_machine(struct obd_import *imp);

/* ptlrpc/pack_generic.c */
int lustre_msg_swabbed(struct lustre_msg *msg);
int lustre_pack_request(struct ptlrpc_request *, int count, int *lens,
                        char **bufs);
int lustre_pack_reply(struct ptlrpc_request *, int count, int *lens,
                      char **bufs);
void lustre_free_reply_state(struct ptlrpc_reply_state *rs);
int lustre_msg_size(int count, int *lengths);
int lustre_unpack_msg(struct lustre_msg *m, int len);
void *lustre_msg_buf(struct lustre_msg *m, int n, int minlen);
char *lustre_msg_string (struct lustre_msg *m, int n, int max_len);
void *lustre_swab_buf(struct lustre_msg *, int n, int minlen, void *swabber);
void *lustre_swab_reqbuf (struct ptlrpc_request *req, int n, int minlen,
                          void *swabber);
void *lustre_swab_repbuf (struct ptlrpc_request *req, int n, int minlen,
                          void *swabber);

/* ldlm/ldlm_lib.c */
int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf);
int client_obd_cleanup(struct obd_device * obddev, int flags);
int client_connect_import(struct lustre_handle *conn, struct obd_device *obd,
                          struct obd_uuid *cluuid);
int client_disconnect_export(struct obd_export *exp, int failover);

/* ptlrpc/pinger.c */
int ptlrpc_pinger_add_import(struct obd_import *imp);
int ptlrpc_pinger_del_import(struct obd_import *imp);

/* ptlrpc/ptlrpcd.c */
void ptlrpcd_wake(void);
void ptlrpcd_add_req(struct ptlrpc_request *req);
int ptlrpcd_addref(void);
void ptlrpcd_decref(void);

/* ptlrpc/lproc_ptlrpc.c */
#ifdef __KERNEL__
void ptlrpc_lprocfs_register_obd(struct obd_device *obddev);
void ptlrpc_lprocfs_unregister_obd(struct obd_device *obddev);
#else
#define ptlrpc_lprocfs_register_obd(param...) do{}while(0)
#define ptlrpc_lprocfs_unregister_obd(param...) do{}while(0)
#endif

/* ptlrpc/llog_server.c */
int llog_origin_handle_create(struct ptlrpc_request *req);
int llog_origin_handle_next_block(struct ptlrpc_request *req);
int llog_origin_handle_read_header(struct ptlrpc_request *req);
int llog_origin_handle_close(struct ptlrpc_request *req);
int llog_origin_handle_cancel(struct ptlrpc_request *req);
int llog_catinfo(struct ptlrpc_request *req);

/* ptlrpc/llog_client.c */
extern struct llog_operations llog_client_ops;

#endif
