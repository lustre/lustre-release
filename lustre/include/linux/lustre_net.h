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
#include <linux/obd.h>
#include <portals/p30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_ha.h>

/* default rpc ring length */
#define RPC_RING_LENGTH    10

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

        struct list_head        c_clients; /* XXXshaver will be c_imports */
        struct list_head        c_exports;

        /* should this be in recovd_data? */
        struct recovd_obd      *c_recovd;
};

struct ptlrpc_client {
        struct obd_device        *cli_obd;
        __u32                     cli_request_portal;
        __u32                     cli_reply_portal;

        __u32                     cli_target_devno;

        struct ptlrpc_connection *cli_connection;

        void                     *cli_data;
        struct semaphore          cli_rpc_sem; /* limits outstanding requests */

        struct list_head          cli_client_chain;
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
        int rq_type; /* one of PTL_RPC_REQUEST, PTL_RPC_REPLY, PTL_RPC_BULK */
        struct list_head rq_list;
        struct list_head rq_multi;
        struct obd_device *rq_obd;
        int rq_status;
        int rq_flags; 
        __u32 rq_connid;
        atomic_t rq_refcount;

        int rq_reqlen;
        struct lustre_msg *rq_reqmsg;

        int rq_replen;
        struct lustre_msg *rq_repmsg;
        __u64 rq_transno;
        __u64 rq_xid;

        char *rq_bulkbuf;
        int rq_bulklen;

        int rq_level;
        time_t rq_time;
        time_t rq_timeout;
        //        void * rq_reply_handle;
        wait_queue_head_t rq_wait_for_rep;

        /* incoming reply */
        ptl_md_t rq_reply_md;
        ptl_handle_md_t rq_reply_md_h;
        ptl_handle_me_t rq_reply_me_h;

        /* outgoing req/rep */
        ptl_md_t rq_req_md;
        ptl_handle_md_t rq_req_md_h;

        struct lustre_peer rq_peer; /* XXX see service.c can this be factored away? */
        struct obd_export *rq_export;
        struct ptlrpc_connection *rq_connection;
        struct ptlrpc_client *rq_client;
        struct ptlrpc_service *rq_svc;
};

struct ptlrpc_bulk_page {
        struct ptlrpc_bulk_desc *b_desc;
        struct list_head b_link;
        char *b_buf;
        int b_buflen;
        struct page *b_page;
        __u32 b_xid;
        __u32 b_flags;
        struct dentry *b_dentry;
        int (*b_cb)(struct ptlrpc_bulk_page *);
};

struct ptlrpc_bulk_desc {
        int b_flags;
        struct ptlrpc_connection *b_connection;
        struct ptlrpc_client *b_client;
        __u32 b_portal;
        struct lustre_handle b_conn;
        void (*b_cb)(struct ptlrpc_bulk_desc *, void *);
        void *b_cb_data;

        wait_queue_head_t b_waitq;
        struct list_head b_page_list;
        __u32 b_page_count;
        atomic_t b_refcount;
        void *b_desc_private;
        struct tq_struct b_queue;

        ptl_md_t b_md;
        ptl_handle_md_t b_md_h;
        ptl_handle_me_t b_me_h;

        struct iovec b_iov[16];    /* self-sized pre-allocated iov */
};

struct ptlrpc_thread {
        struct list_head t_link;

        __u32 t_flags; 
        wait_queue_head_t t_ctl_waitq;
};

struct ptlrpc_service {
        time_t srv_time;
        time_t srv_timeout;

        /* incoming request buffers */
        /* FIXME: perhaps a list of EQs, if multiple NIs are used? */
        char *srv_buf[RPC_RING_LENGTH];
        __u32 srv_ref_count[RPC_RING_LENGTH];
        ptl_handle_me_t srv_me_h[RPC_RING_LENGTH];
        __u32 srv_buf_size;
        __u32 srv_ring_length;
        __u32 srv_req_portal;
        __u32 srv_rep_portal;

        __u32 srv_xid;

        /* event queue */
        ptl_handle_eq_t srv_eq_h;

        struct lustre_peer srv_self;

        wait_queue_head_t srv_waitq; /* all threads sleep on this */

        spinlock_t srv_lock;
        struct list_head srv_reqs;
        struct list_head srv_threads;
        int (*srv_handler)(struct ptlrpc_request *req);
        char *srv_name;  /* only statically allocated strings here; we don't clean them */
};

static inline void ptlrpc_hdl2req(struct ptlrpc_request *req, struct lustre_handle *h)
{
        req->rq_reqmsg->addr = h->addr;
        req->rq_reqmsg->cookie = h->cookie;
}
struct ptlrpc_request *ptlrpc_prep_req2(struct lustre_handle *conn, 
                                        int opcode, int count, int *lengths,
                                        char **bufs);

typedef void (*bulk_callback_t)(struct ptlrpc_bulk_desc *, void *);

typedef int (*svc_handler_t)(struct ptlrpc_request *req);

/* rpc/connection.c */
void ptlrpc_readdress_connection(struct ptlrpc_connection *conn, char *uuid);
struct ptlrpc_connection *ptlrpc_get_connection(struct lustre_peer *peer);
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
void ptlrpc_link_svc_me(struct ptlrpc_service *service, int i);

/* rpc/client.c */
void ptlrpc_init_client(int req_portal, int rep_portal, struct ptlrpc_client *,
                        struct ptlrpc_connection *);
void ptlrpc_cleanup_client(struct ptlrpc_client *cli);
__u8 *ptlrpc_req_to_uuid(struct ptlrpc_request *req);
struct ptlrpc_connection *ptlrpc_uuid_to_connection(char *uuid);

int ptlrpc_queue_wait(struct ptlrpc_request *req);
void ptlrpc_continue_req(struct ptlrpc_request *req);
int ptlrpc_replay_req(struct ptlrpc_request *req);
void ptlrpc_restart_req(struct ptlrpc_request *req);

struct ptlrpc_request *ptlrpc_prep_req(struct ptlrpc_client *cl, int opcode,
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
ptlrpc_init_svc(__u32 bufsize, int req_portal, int rep_portal, char *uuid,
                svc_handler_t, char *name);
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
        if (atomic_dec_and_test(&desc->b_refcount)) {
                CDEBUG(D_PAGE, "Released last ref on %p, freeing\n", desc);
                ptlrpc_free_bulk(desc);
        } else {
                CDEBUG(D_PAGE, "%p -> %d\n", desc,
                       atomic_read(&desc->b_refcount));
        }
}

static inline void ptlrpc_bulk_addref(struct ptlrpc_bulk_desc *desc)
{
        atomic_inc(&desc->b_refcount);
        CDEBUG(D_PAGE, "Set refcount of %p to %d\n", desc,
               atomic_read(&desc->b_refcount));
}

#endif
