/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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

#include <linux/tqueue.h>
#include <linux/kp30.h>
// #include <linux/obd.h>
#include <portals/p30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_import.h>

/* The following constants determine how much memory is devoted to
 * buffering in the lustre services.
 *
 * ?_NEVENTS            # event queue entries
 *
 * ?_NBUFS		# request buffers
 * ?_BUFSIZE		# bytes in a single request buffer
 * total memory = ?_NBUFS * ?_BUFSIZE
 *
 * ?_MAXREQSIZE         # maximum request service will receive
 * larger messages will get dropped.
 * request buffers are auto-unlinked when less than ?_MAXREQSIZE
 * is left in them.
 */

#define LDLM_NEVENTS	1024
#define LDLM_NBUFS	10
#define LDLM_BUFSIZE	(64 * 1024)
#define LDLM_MAXREQSIZE	1024

#define MDS_NEVENTS	1024
#define MDS_NBUFS	10
#define MDS_BUFSIZE	(64 * 1024)
#define MDS_MAXREQSIZE	1024

#define OST_NEVENTS	min(num_physpages / 16, 32768UL)
#define OST_NBUFS	min(OST_NEVENTS / 128, 256UL)
#define OST_BUFSIZE	((OST_NEVENTS > 4096UL ? 128 : 64) * 1024)
#define OST_MAXREQSIZE	(8 * 1024)

#define CONN_INVALID 1

struct ptlrpc_connection {
        struct list_head        c_link;
        struct lustre_peer      c_peer;
        __u8                    c_local_uuid[37];  /* XXX do we need this? */
        __u8                    c_remote_uuid[37];

        int                     c_level;
        __u32                   c_generation;  /* changes upon new connection */
        __u32                   c_epoch;       /* changes when peer changes */
        __u32                   c_bootcount;   /* peer's boot count */

        spinlock_t              c_lock;        /* also protects req->rq_list */
        __u32                   c_xid_in;
        __u32                   c_xid_out;

        atomic_t                c_refcount;
        __u64                   c_token;
        __u64                   c_remote_conn;
        __u64                   c_remote_token;

        __u64                   c_last_xid;    /* protected by c_lock */
        __u64                   c_last_committed;/* protected by c_lock */
        struct list_head        c_delayed_head;/* delayed until post-recovery */
        struct list_head        c_sending_head;/* protected by c_lock */
        struct list_head        c_dying_head;  /* protected by c_lock */
        struct recovd_data      c_recovd_data;

        struct list_head        c_imports;
        struct list_head        c_exports;
        struct list_head        c_sb_chain;
        __u32                   c_flags; /* can we indicate INVALID elsewhere? */
};

struct ptlrpc_client {
        __u32                     cli_request_portal;
        __u32                     cli_reply_portal;

        __u32                     cli_target_devno;

        void                     *cli_data;
        // struct semaphore          cli_rpc_sem; /* limits outstanding requests */

        char                     *cli_name;
};

/* state flags of requests */
#define PTL_RPC_FL_INTR      (1 << 0)
#define PTL_RPC_FL_REPLIED   (1 << 1)  /* reply was received */
#define PTL_RPC_FL_SENT      (1 << 2)
#define PTL_BULK_FL_SENT     (1 << 3)
#define PTL_BULK_FL_RCVD     (1 << 4)
#define PTL_RPC_FL_ERR       (1 << 5)
#define PTL_RPC_FL_TIMEOUT   (1 << 6)
#define PTL_RPC_FL_RESEND    (1 << 7)
#define PTL_RPC_FL_RECOVERY  (1 << 8)  /* retransmission for recovery */
#define PTL_RPC_FL_FINISHED  (1 << 9)
#define PTL_RPC_FL_RETAIN    (1 << 10) /* retain for replay after reply */
#define PTL_RPC_FL_REPLAY    (1 << 11) /* replay upon recovery */
#define PTL_RPC_FL_ALLOCREP  (1 << 12) /* reply buffer allocated */

struct ptlrpc_request { 
        int rq_type; /* one of PTL_RPC_MSG_* */
        struct list_head rq_list;
        struct obd_device *rq_obd;
        int rq_status;
        int rq_flags; 
        atomic_t rq_refcount;

        int rq_reqlen;
        struct lustre_msg *rq_reqmsg;

        int rq_replen;
        struct lustre_msg *rq_repmsg;
        __u64 rq_transno;
        __u64 rq_xid;

        int rq_level;
        time_t rq_timeout;
        //        void * rq_reply_handle;
        wait_queue_head_t rq_wait_for_rep;

        /* incoming reply */
        ptl_md_t rq_reply_md;
        ptl_handle_md_t rq_reply_md_h; /* we can lose this: set, never read */
        ptl_handle_me_t rq_reply_me_h;

        /* outgoing req/rep */
        ptl_md_t rq_req_md;

        struct lustre_peer rq_peer; /* XXX see service.c can this be factored away? */
        struct obd_export *rq_export;
        struct ptlrpc_connection *rq_connection;
        struct obd_import *rq_import;
        struct ptlrpc_service *rq_svc;

        void (*rq_replay_cb)(struct ptlrpc_request *, void *);
        void *rq_replay_cb_data;
};

struct ptlrpc_bulk_page {
        struct ptlrpc_bulk_desc *bp_desc;
        struct list_head bp_link;
        void *bp_buf;
        int bp_buflen;
        struct page *bp_page;
        __u32 bp_xid;
        __u32 bp_flags;
        struct dentry *bp_dentry;
        int (*bp_cb)(struct ptlrpc_bulk_page *);
};


struct ptlrpc_bulk_desc {
        int bd_flags;
        struct ptlrpc_connection *bd_connection;
        struct ptlrpc_client *bd_client;
        __u32 bd_portal;
        struct lustre_handle bd_conn;
        void (*bd_cb)(struct ptlrpc_bulk_desc *, void *);
        void *bd_cb_data;

        wait_queue_head_t bd_waitq;
        struct list_head bd_page_list;
        __u32 bd_page_count;
        atomic_t bd_refcount;
        void *bd_desc_private;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        struct work_struct bd_queue;
#else
        struct tq_struct bd_queue;
#endif

        ptl_md_t bd_md;
        ptl_handle_md_t bd_md_h;
        ptl_handle_me_t bd_me_h;

        atomic_t	bd_source_callback_count;

        struct iovec bd_iov[16];    /* self-sized pre-allocated iov */
};

struct ptlrpc_thread {
        struct list_head t_link;

        __u32 t_flags; 
        wait_queue_head_t t_ctl_waitq;
};

struct ptlrpc_request_buffer_desc {
        struct list_head       rqbd_list;
        struct ptlrpc_service *rqbd_service;
        ptl_handle_me_t        rqbd_me_h;
        atomic_t               rqbd_refcount;
        char                  *rqbd_buffer;
};

struct ptlrpc_service {
        time_t srv_time;
        time_t srv_timeout;

        /* incoming request buffers */
        /* FIXME: perhaps a list of EQs, if multiple NIs are used? */

        __u32            srv_max_req_size;      /* biggest request to receive */
        __u32            srv_buf_size;          /* # bytes in a request buffer */
        struct list_head srv_rqbds;             /* all the request buffer descriptors */
        __u32            srv_nrqbds;            /* # request buffers */
        atomic_t         srv_nrqbds_receiving;  /* # request buffers posted for input */

        __u32 srv_req_portal;
        __u32 srv_rep_portal;

        __u32 srv_xid;

        /* event queue */
        ptl_handle_eq_t srv_eq_h;

        struct lustre_peer srv_self;

        wait_queue_head_t srv_waitq; /* all threads sleep on this */

        spinlock_t srv_lock;
        struct list_head srv_threads;
        int (*srv_handler)(struct ptlrpc_request *req);
        char *srv_name;  /* only statically allocated strings here; we don't clean them */
};

static inline void ptlrpc_hdl2req(struct ptlrpc_request *req, struct lustre_handle *h)
{
        req->rq_reqmsg->addr = h->addr;
        req->rq_reqmsg->cookie = h->cookie;
}

typedef void (*bulk_callback_t)(struct ptlrpc_bulk_desc *, void *);

typedef int (*svc_handler_t)(struct ptlrpc_request *req);

/* rpc/connection.c */
void ptlrpc_readdress_connection(struct ptlrpc_connection *conn, obd_uuid_t uuid);
struct ptlrpc_connection *ptlrpc_get_connection(struct lustre_peer *peer,
                                                obd_uuid_t uuid);
int ptlrpc_put_connection(struct ptlrpc_connection *c);
struct ptlrpc_connection *ptlrpc_connection_addref(struct ptlrpc_connection *);
void ptlrpc_init_connection(void);
void ptlrpc_cleanup_connection(void);

/* rpc/niobuf.c */
int ptlrpc_check_bulk_sent(struct ptlrpc_bulk_desc *bulk);
int ptlrpc_check_bulk_received(struct ptlrpc_bulk_desc *bulk);
int ptlrpc_send_bulk(struct ptlrpc_bulk_desc *);
int ptlrpc_register_bulk(struct ptlrpc_bulk_desc *);
int ptlrpc_abort_bulk(struct ptlrpc_bulk_desc *bulk);
int ptlrpc_reply(struct ptlrpc_service *svc, struct ptlrpc_request *req);
int ptlrpc_error(struct ptlrpc_service *svc, struct ptlrpc_request *req);
void ptlrpc_resend_req(struct ptlrpc_request *request);
int ptl_send_rpc(struct ptlrpc_request *request);
void ptlrpc_link_svc_me(struct ptlrpc_request_buffer_desc *rqbd);

/* rpc/client.c */
void ptlrpc_init_client(int req_portal, int rep_portal, char *name,
                        struct ptlrpc_client *);
void ptlrpc_cleanup_client(struct obd_import *imp);
__u8 *ptlrpc_req_to_uuid(struct ptlrpc_request *req);
struct ptlrpc_connection *ptlrpc_uuid_to_connection(obd_uuid_t uuid);

int ptlrpc_queue_wait(struct ptlrpc_request *req);
void ptlrpc_continue_req(struct ptlrpc_request *req);
int ptlrpc_replay_req(struct ptlrpc_request *req);
void ptlrpc_restart_req(struct ptlrpc_request *req);

struct ptlrpc_request *ptlrpc_prep_req(struct obd_import *imp, int opcode,
                                       int count, int *lengths, char **bufs);
void ptlrpc_free_req(struct ptlrpc_request *request);
void ptlrpc_req_finished(struct ptlrpc_request *request);
struct ptlrpc_bulk_desc *ptlrpc_prep_bulk(struct ptlrpc_connection *);
void ptlrpc_free_bulk(struct ptlrpc_bulk_desc *bulk);
struct ptlrpc_bulk_page *ptlrpc_prep_bulk_page(struct ptlrpc_bulk_desc *desc);
void ptlrpc_free_bulk_page(struct ptlrpc_bulk_page *page);
int ptlrpc_check_status(struct ptlrpc_request *req, int err);

/* rpc/service.c */
struct ptlrpc_service *
ptlrpc_init_svc(__u32 nevents, __u32 nbufs, __u32 bufsize, __u32 max_req_size, 
                int req_portal, int rep_portal,
                obd_uuid_t uuid, svc_handler_t, char *name);
void ptlrpc_stop_all_threads(struct ptlrpc_service *svc);
int ptlrpc_start_thread(struct obd_device *dev, struct ptlrpc_service *svc,
                        char *name);
int ptlrpc_unregister_service(struct ptlrpc_service *service);

struct ptlrpc_svc_data { 
        char *name;
        struct ptlrpc_service *svc; 
        struct ptlrpc_thread *thread;
        struct obd_device *dev;
}; 

/* rpc/pack_generic.c */
int lustre_pack_msg(int count, int *lens, char **bufs, int *len,
                    struct lustre_msg **msg);
int lustre_msg_size(int count, int *lengths);
int lustre_unpack_msg(struct lustre_msg *m, int len);
void *lustre_msg_buf(struct lustre_msg *m, int n);

static inline void ptlrpc_bulk_decref(struct ptlrpc_bulk_desc *desc)
{
        if (atomic_dec_and_test(&desc->bd_refcount)) {
                CDEBUG(D_PAGE, "Released last ref on %p, freeing\n", desc);
                ptlrpc_free_bulk(desc);
        } else {
                CDEBUG(D_PAGE, "%p -> %d\n", desc,
                       atomic_read(&desc->bd_refcount));
        }
}

static inline void ptlrpc_bulk_addref(struct ptlrpc_bulk_desc *desc)
{
        atomic_inc(&desc->bd_refcount);
        CDEBUG(D_PAGE, "Set refcount of %p to %d\n", desc,
               atomic_read(&desc->bd_refcount));
}

#endif
