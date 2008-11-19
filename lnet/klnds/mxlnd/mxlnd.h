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
 *
 * Copyright (C) 2006 Myricom, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/mxlnd/mxlnd.h
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Scott Atchley <atchley at myri.com>
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>       /* module */
#include <linux/kernel.h>       /* module */
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/uio.h>
#include <linux/fs.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/init.h>         /* module */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>
#include <linux/random.h>
#include <linux/utsname.h>

#include <net/sock.h>
#include <linux/in.h>

#include <linux/netdevice.h>    /* these are needed for ARP */
#include <linux/if_arp.h>
#include <net/arp.h>
#include <linux/inetdevice.h>

#define DEBUG_SUBSYSTEM S_LND

#include "libcfs/kp30.h"
#include "lnet/lnet.h"
#include "lnet/lib-lnet.h"

#define MX_KERNEL 1
#include "mx_extensions.h"
#include "myriexpress.h"

#if LNET_MAX_IOV > MX_MAX_SEGMENTS
    #error LNET_MAX_IOV is greater then MX_MAX_SEGMENTS
#endif

/* Using MX's 64 match bits
 * We are using the match bits to specify message type and the cookie.  The
 * highest four bits (60-63) are reserved for message type. Below we specify
 * the types. MXLND_MASK_ICON_REQ and MXLND_MASK_ICON_ACK are used for
 * mx_iconnect().  We reserve the remaining combinations for future use.  The
 * next 8 bits (52-59) are reserved for returning a status code for failed
 * GET_DATA (payload) messages. The last 52 bits are used for cookies. That
 * should allow unique cookies for 4 KB messages at 10 Gbps line rate without
 * rollover for about 8 years. That should be enough. */

/* constants */
#define MXLND_MASK_ICON_REQ (0xBLL << 60) /* it is a mx_iconnect() completion */
#define MXLND_MASK_CONN_REQ (0xCLL << 60) /* CONN_REQ msg */
#define MXLND_MASK_ICON_ACK (0x9LL << 60) /* it is a mx_iconnect() completion */
#define MXLND_MASK_CONN_ACK (0xALL << 60) /* CONN_ACK msg*/
#define MXLND_MASK_EAGER    (0xELL << 60) /* EAGER msg */
#define MXLND_MASK_NOOP     (0x1LL << 60) /* NOOP msg */
#define MXLND_MASK_PUT_REQ  (0x2LL << 60) /* PUT_REQ msg */
#define MXLND_MASK_PUT_ACK  (0x3LL << 60) /* PUT_ACK msg */
#define MXLND_MASK_PUT_DATA (0x4LL << 60) /* PUT_DATA msg */
#define MXLND_MASK_GET_REQ  (0x5LL << 60) /* GET_REQ msg */
#define MXLND_MASK_GET_DATA (0x6LL << 60) /* GET_DATA msg */
//#define MXLND_MASK_NAK      (0x7LL << 60) /* NAK msg */

#define MXLND_MAX_COOKIE    ((1LL << 52) - 1)         /* when to roll-over the cookie value */
#define MXLND_NCOMPLETIONS  (MXLND_N_SCHED + 2)   /* max threads for completion array */

/* defaults for configurable parameters */
#define MXLND_N_SCHED           1               /* # schedulers (mx_wait_any() threads) */
#define MXLND_MX_BOARD          0               /* Use the first MX NIC if more than 1 avail */
#define MXLND_MX_EP_ID          3               /* MX endpoint ID */
#define MXLND_COMM_TIMEOUT      (20 * HZ)       /* timeout for send/recv (jiffies) */
#define MXLND_WAIT_TIMEOUT      HZ              /* timeout for wait (jiffies) */
#define MXLND_POLLING           1000            /* poll iterations before blocking */
#define MXLND_MAX_PEERS         1024            /* number of nodes talking to me */
#define MXLND_EAGER_NUM         MXLND_MAX_PEERS /* number of pre-posted receives */
#define MXLND_EAGER_SIZE        PAGE_SIZE       /* pre-posted eager message size */
#define MXLND_MSG_QUEUE_DEPTH   8               /* msg queue depth */
#define MXLND_CREDIT_HIGHWATER  (MXLND_MSG_QUEUE_DEPTH - 2)
                                                /* when to send a noop to return credits */
#define MXLND_NTX               256             /* # of kmx_tx - total sends in flight 
                                                   1/2 are reserved for connect messages */

#define MXLND_HASH_BITS         6               /* the number of bits to hash over */
#define MXLND_HASH_SIZE         (1<<MXLND_HASH_BITS)
                                                /* number of peer lists for lookup.
                                                   we hash over the last N bits of
                                                   the IP address converted to an int. */
#define MXLND_HASH_MASK         (MXLND_HASH_SIZE - 1)
                                                /* ensure we use only the last N bits */

/* debugging features */
#define MXLND_CKSUM             0               /* checksum kmx_msg_t */
#define MXLND_DEBUG             0               /* turn on printk()s */

extern inline void mxlnd_noop(char *s, ...);
#if MXLND_DEBUG
        #define MXLND_PRINT printk
#else
        #define MXLND_PRINT mxlnd_noop
#endif

/* provide wrappers around LIBCFS_ALLOC/FREE to keep MXLND specific
 * memory usage stats that include pages */

#define MXLND_ALLOC(x, size) \
        do { \
                spin_lock(&kmxlnd_data.kmx_global_lock); \
                kmxlnd_data.kmx_mem_used += size; \
                spin_unlock(&kmxlnd_data.kmx_global_lock); \
                LIBCFS_ALLOC(x, size); \
                if (x == NULL) { \
                        spin_lock(&kmxlnd_data.kmx_global_lock); \
                        kmxlnd_data.kmx_mem_used -= size; \
                        spin_unlock(&kmxlnd_data.kmx_global_lock); \
                } \
        } while (0)

#define MXLND_FREE(x, size) \
        do { \
                spin_lock(&kmxlnd_data.kmx_global_lock); \
                kmxlnd_data.kmx_mem_used -= size; \
                spin_unlock(&kmxlnd_data.kmx_global_lock); \
                LIBCFS_FREE(x, size); \
        } while (0)


typedef struct kmx_tunables {
        int     *kmx_n_waitd;           /* # completion threads */
        int     *kmx_max_peers;         /* max # of potential peers */
        int     *kmx_cksum;             /* checksum small msgs? */
        int     *kmx_ntx;               /* total # of tx (1/2 for LNET 1/2 for CONN_REQ */
        int     *kmx_credits;           /* concurrent sends to 1 peer */
        int     *kmx_board;             /* MX board (NIC) number */
        int     *kmx_ep_id;             /* MX endpoint number */
        int     *kmx_polling;           /* if 0, block. if > 0, poll this many
                                           iterations before blocking */
        char    **kmx_hosts;            /* Location of hosts file, if used */
} kmx_tunables_t;

/* structure to hold IP-to-hostname resolution data */
struct kmx_host {
        struct kmx_peer    *mxh_peer;           /* pointer to matching peer */
        u32                 mxh_addr;           /* IP address as int */
        char               *mxh_hostname;       /* peer's hostname */
        u32                 mxh_board;          /* peer's board rank */
        u32                 mxh_ep_id;          /* peer's MX endpoint ID */
        struct list_head    mxh_list;           /* position on kmx_hosts */
        spinlock_t          mxh_lock;           /* lock */
};

/* global interface state */
typedef struct kmx_data
{
        int                 kmx_init;           /* initialization state */
        int                 kmx_shutdown;       /* shutting down? */
        atomic_t            kmx_nthreads;       /* number of threads */
        struct completion  *kmx_completions;    /* array of completion structs */
        lnet_ni_t          *kmx_ni;             /* the LND instance */
        u64                 kmx_incarnation;    /* my incarnation value - unused */
        long                kmx_mem_used;       /* memory used */
        struct kmx_host    *kmx_localhost;      /* pointer to my kmx_host info */
        mx_endpoint_t       kmx_endpt;          /* the MX endpoint */

        spinlock_t          kmx_global_lock;    /* global lock */

        struct list_head    kmx_conn_req;       /* list of connection requests */
        spinlock_t          kmx_conn_lock;      /* connection list lock */
        struct semaphore    kmx_conn_sem;       /* semaphore for connection request list */

        struct list_head    kmx_hosts;          /* host lookup info */
        spinlock_t          kmx_hosts_lock;     /* hosts list lock */

        struct list_head    kmx_peers[MXLND_HASH_SIZE];
                                                /* list of all known peers */
        rwlock_t            kmx_peers_lock;     /* peer list rw lock */
        atomic_t            kmx_npeers;         /* number of peers */

        struct list_head    kmx_txs;            /* all tx descriptors */
        struct list_head    kmx_tx_idle;        /* list of idle tx */
        spinlock_t          kmx_tx_idle_lock;   /* lock for idle tx list */
        s32                 kmx_tx_used;        /* txs in use */
        u64                 kmx_tx_next_cookie; /* unique id for tx */
        struct list_head    kmx_tx_queue;       /* generic send queue */
        spinlock_t          kmx_tx_queue_lock;  /* lock for generic sends */
        struct semaphore    kmx_tx_queue_sem;   /* semaphore for tx queue */

        struct list_head    kmx_rxs;            /* all rx descriptors */
        spinlock_t          kmx_rxs_lock;       /* lock for rxs list */
        struct list_head    kmx_rx_idle;        /* list of idle tx */
        spinlock_t          kmx_rx_idle_lock;   /* lock for idle rx list */
} kmx_data_t;

#define MXLND_INIT_NOTHING      0       /* in the beginning, there was nothing... */
#define MXLND_INIT_DATA         1       /* main data structures created */
#define MXLND_INIT_TXS          2       /* tx descriptors created */
#define MXLND_INIT_RXS          3       /* initial rx descriptors created */
#define MXLND_INIT_MX           4       /* initiate MX library, open endpoint, get NIC id */
#define MXLND_INIT_THREADS      5       /* waitd, timeoutd, tx_queued threads */
#define MXLND_INIT_ALL          6       /* startup completed */

#include "mxlnd_wire.h"

enum kmx_req_type {
        MXLND_REQ_TX    = 0,
        MXLND_REQ_RX    = 1,
};

/* The life cycle of a request */
enum kmx_req_state {
        MXLND_CTX_INIT       = 0,               /* just created */
        MXLND_CTX_IDLE       = 1,               /* available for use */
        MXLND_CTX_PREP       = 2,               /* getting ready for send/recv */
        MXLND_CTX_PENDING    = 3,               /* mx_isend() or mx_irecv() called */
        MXLND_CTX_COMPLETED  = 4,               /* cleaning up after completion or timeout */
        MXLND_CTX_CANCELED   = 5,               /* timed out but still in ctx list */
};

/* Context Structure - generic tx/rx descriptor
 * It represents the context (or state) of each send or receive request.
 * In other LNDs, they have separate TX and RX descriptors and this replaces both.
 *
 * We will keep the these on the global kmx_rxs and kmx_txs lists for cleanup
 * during shutdown(). We will move them between the rx/tx idle lists and the
 * pending list which is monitored by mxlnd_timeoutd().
 */
struct kmx_ctx {
        enum kmx_req_type   mxc_type;           /* TX or RX */
        u64                 mxc_incarnation;    /* store the peer's incarnation here
                                                   to verify before changing flow
                                                   control credits after completion */
        unsigned long       mxc_deadline;       /* request time out in absolute jiffies */
        enum kmx_req_state  mxc_state;          /* what is the state of the request? */
        struct list_head    mxc_global_list;    /* place on kmx_rxs or kmx_txs */
        struct list_head    mxc_list;           /* place on rx/tx idle list, tx q, peer tx */
        struct list_head    mxc_rx_list;        /* place on mxp_rx_posted list */
        spinlock_t          mxc_lock;           /* lock */

        lnet_nid_t          mxc_nid;            /* dst's NID if peer is not known */
        struct kmx_peer    *mxc_peer;           /* owning peer */
        struct kmx_conn    *mxc_conn;           /* owning conn */
        struct kmx_msg     *mxc_msg;            /* msg hdr mapped to mxc_page */
        struct page        *mxc_page;           /* buffer for eager msgs */
        lnet_msg_t         *mxc_lntmsg[2];      /* lnet msgs to finalize */

        u8                  mxc_msg_type;       /* what type of message is this? */
        u64                 mxc_cookie;         /* completion cookie */
        u64                 mxc_match;          /* MX match info */
        mx_ksegment_t       mxc_seg;            /* local MX ksegment for non-DATA */
        mx_ksegment_t      *mxc_seg_list;       /* MX ksegment array for DATA */
        int                 mxc_nseg;           /* number of segments */
        unsigned long       mxc_pin_type;       /* MX_PIN_KERNEL or MX_PIN_PHYSICAL */
        u32                 mxc_nob;            /* number of bytes sent/received */
        mx_request_t        mxc_mxreq;          /* MX request */
        mx_status_t         mxc_status;         /* MX status */
        s64                 mxc_get;            /* # of times returned from idle list */
        s64                 mxc_put;            /* # of times returned from idle list */
};

#define MXLND_CONN_DISCONNECT  -2       /* conn is being destroyed - do not add txs */
#define MXLND_CONN_FAIL        -1       /* connect failed (bad handshake, unavail, etc.) */
#define MXLND_CONN_INIT         0       /* in the beginning, there was nothing... */
#define MXLND_CONN_REQ          1       /* a connection request message is needed */
#define MXLND_CONN_ACK          2       /* a connection ack is needed */
#define MXLND_CONN_WAIT         3       /* waiting for req or ack to complete */
#define MXLND_CONN_READY        4       /* ready to send */

/* connection state - queues for queued and pending msgs */
struct kmx_conn
{
        u64                 mxk_incarnation;    /* connections's incarnation value */
        atomic_t            mxk_refcount;       /* reference counting */

        struct kmx_peer    *mxk_peer;           /* owning peer */
        mx_endpoint_addr_t  mxk_epa;            /* peer's endpoint address */

        struct list_head    mxk_list;           /* for placing on mxp_conns */
        spinlock_t          mxk_lock;           /* lock */
        unsigned long       mxk_timeout;        /* expiration of oldest pending tx/rx */
        unsigned long       mxk_last_tx;        /* when last tx completed with success */
        unsigned long       mxk_last_rx;        /* when last rx completed */

        int                 mxk_credits;        /* # of my credits for sending to peer */
        int                 mxk_outstanding;    /* # of credits to return */

        int                 mxk_status;         /* can we send messages? MXLND_CONN_* */
        struct list_head    mxk_tx_credit_queue;   /* send queue for peer */
        struct list_head    mxk_tx_free_queue;  /* send queue for peer */
        int                 mxk_ntx_msgs;       /* # of msgs on tx queues */
        int                 mxk_ntx_data ;      /* # of DATA on tx queues */
        int                 mxk_ntx_posted;     /* # of tx msgs in flight */
        int                 mxk_data_posted;    /* # of tx data payloads in flight */

        struct list_head    mxk_pending;        /* in flight rxs and txs */
};

/* peer state */
struct kmx_peer
{
        lnet_nid_t          mxp_nid;            /* peer's LNET NID */
        u64                 mxp_incarnation;    /* peer's incarnation value */
        atomic_t            mxp_refcount;       /* reference counts */

        struct kmx_host    *mxp_host;           /* peer lookup info */
        u64                 mxp_nic_id;         /* remote's MX nic_id for mx_connect() */

        struct list_head    mxp_peers;          /* for placing on kmx_peers */
        spinlock_t          mxp_lock;           /* lock */

        struct list_head    mxp_conns;          /* list of connections */
        struct kmx_conn    *mxp_conn;           /* current connection */

        unsigned long       mxp_reconnect_time;  /* when to retry connect */
        int                 mxp_incompatible;   /* incorrect conn_req values */
};

extern kmx_data_t       kmxlnd_data;
extern kmx_tunables_t   kmxlnd_tunables;

/* required for the LNET API */
int  mxlnd_startup(lnet_ni_t *ni);
void mxlnd_shutdown(lnet_ni_t *ni);
int  mxlnd_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int  mxlnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int  mxlnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, int delayed,
                unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov, 
                unsigned int offset, unsigned int mlen, unsigned int rlen);

/* in mxlnd.c */
extern void mxlnd_thread_stop(long id);
extern int  mxlnd_ctx_alloc(struct kmx_ctx **ctxp, enum kmx_req_type type);
extern void mxlnd_ctx_free(struct kmx_ctx *ctx);
extern void mxlnd_ctx_init(struct kmx_ctx *ctx);
extern lnet_nid_t mxlnd_nic_id2nid(lnet_ni_t *ni, u64 nic_id);
extern u64 mxlnd_nid2nic_id(lnet_nid_t nid);

/* in mxlnd_cb.c */
void mxlnd_eager_recv(void *context, uint64_t match_value, uint32_t length);
extern mx_unexp_handler_action_t mxlnd_unexpected_recv(void *context,
                mx_endpoint_addr_t source, uint64_t match_value, uint32_t length, 
                void *data_if_available);
extern void mxlnd_peer_free(struct kmx_peer *peer);
extern void mxlnd_conn_free(struct kmx_conn *conn);
extern void mxlnd_sleep(unsigned long timeout);
extern int  mxlnd_tx_queued(void *arg);
extern void mxlnd_handle_rx_completion(struct kmx_ctx *rx);
extern int  mxlnd_check_sends(struct kmx_peer *peer);
extern int  mxlnd_tx_peer_queued(void *arg);
extern int  mxlnd_request_waitd(void *arg);
extern int  mxlnd_unex_recvd(void *arg);
extern int  mxlnd_timeoutd(void *arg);
extern int  mxlnd_connd(void *arg);

#define mxlnd_peer_addref(peer)                                 \
do {                                                            \
        LASSERT(peer != NULL);                                  \
        LASSERT(atomic_read(&(peer)->mxp_refcount) > 0);        \
        atomic_inc(&(peer)->mxp_refcount);                      \
} while (0)


#define mxlnd_peer_decref(peer)                                 \
do {                                                            \
        LASSERT(atomic_read(&(peer)->mxp_refcount) > 0);        \
        if (atomic_dec_and_test(&(peer)->mxp_refcount))         \
                mxlnd_peer_free(peer);                          \
} while (0)

#define mxlnd_conn_addref(conn)                                 \
do {                                                            \
        LASSERT(conn != NULL);                                  \
        LASSERT(atomic_read(&(conn)->mxk_refcount) > 0);        \
        atomic_inc(&(conn)->mxk_refcount);                      \
} while (0)


#define mxlnd_conn_decref(conn)                                 \
do {                                                            \
        LASSERT(atomic_read(&(conn)->mxk_refcount) > 0);        \
        if (atomic_dec_and_test(&(conn)->mxk_refcount))         \
                mxlnd_conn_free(conn);                          \
} while (0)
