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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/openiblnd/openiblnd.h
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/uio.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>

#include <net/sock.h>
#include <linux/in.h>

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>

#include <ts_ib_core.h>
#include <ts_ib_cm.h>
#include <ts_ib_sa_client.h>

#ifndef USING_TSAPI

/* OpenIB Gen1 */
typedef struct ib_qp       ib_qp_t;
typedef struct ib_mr       ib_mr_t;
typedef struct ib_fmr      ib_fmr_t;
typedef struct ib_pd       ib_pd_t;
typedef struct ib_cq       ib_cq_t;
typedef struct ib_fmr_pool ib_fmr_pool_t;

#else

/* Cisco (topspin) */
typedef void                 ib_qp_t;
typedef void                 ib_mr_t;
typedef void                 ib_fmr_t;
typedef void                 ib_pd_t;
typedef void                 ib_cq_t;
typedef void                 ib_fmr_pool_t;

#define IB_ACCESS_LOCAL_WRITE              TS_IB_ACCESS_LOCAL_WRITE
#define IB_WQ_SIGNAL_SELECTABLE            TS_IB_ACCESS_LOCAL_WRITE
#define IB_TRANSPORT_RC                    TS_IB_TRANSPORT_RC
#define IB_QP_STATE_INIT                   TS_IB_QP_STATE_INIT
#define IB_QP_ATTRIBUTE_STATE              TS_IB_QP_ATTRIBUTE_STATE
#define IB_QP_ATTRIBUTE_PORT               TS_IB_QP_ATTRIBUTE_PORT
#define IB_QP_ATTRIBUTE_PKEY_INDEX         TS_IB_QP_ATTRIBUTE_PKEY_INDEX
#define IB_QP_ATTRIBUTE_RDMA_ATOMIC_ENABLE TS_IB_QP_ATTRIBUTE_RDMA_ATOMIC_ENABLE
#define IB_ACCESS_LOCAL_WRITE              TS_IB_ACCESS_LOCAL_WRITE
#define IB_ACCESS_REMOTE_WRITE             TS_IB_ACCESS_REMOTE_WRITE
#define IB_ACCESS_REMOTE_READ              TS_IB_ACCESS_REMOTE_READ
#define IB_CQ_CALLBACK_INTERRU             TS_IB_CQ_CALLBACK_INTERRUPTPT
#define IB_CQ_PROVIDER_REARM               TS_IB_CQ_PROVIDER_REARM
#define IB_CQ_CALLBACK_INTERRUPT           TS_IB_CQ_CALLBACK_INTERRUPT
#define IB_COMPLETION_STATUS_SUCCESS       TS_IB_COMPLETION_STATUS_SUCCESS
#define IB_OP_SEND                         TS_IB_OP_SEND
#define IB_OP_RDMA_WRITE                   TS_IB_OP_RDMA_WRITE
#define IB_OP_RDMA_READ                    TS_IB_OP_RDMA_READ

#endif

#ifdef CONFIG_SMP
# define IBNAL_N_SCHED      num_online_cpus()   /* # schedulers */
#else
# define IBNAL_N_SCHED      1                   /* # schedulers */
#endif

#define IBNAL_FMR                    1
//#define IBNAL_CALLBACK_CTXT  IB_CQ_CALLBACK_PROCESS
#define IBNAL_CALLBACK_CTXT  IB_CQ_CALLBACK_INTERRUPT


/* tunables fixed at compile time */
#define IBNAL_PEER_HASH_SIZE         101        /* # peer lists */
#define IBNAL_RESCHED                100        /* # scheduler loops before reschedule */
#define IBNAL_MSG_QUEUE_SIZE         8          /* # messages/RDMAs in-flight */
#define IBNAL_CREDIT_HIGHWATER       6          /* when to eagerly return credits */
#define IBNAL_MSG_SIZE              (4<<10)     /* max size of queued messages (inc hdr) */
#define IBNAL_RDMA_BASE              0x0eeb0000

/* QP tunables */
#define IBNAL_RETRY                  7          /* # times to retry */
#define IBNAL_RNR_RETRY              7          /*  */
#define IBNAL_CM_RETRY               7          /* # times to retry connection */
#define IBNAL_FLOW_CONTROL           1
#define IBNAL_RESPONDER_RESOURCES    8

/************************/
/* derived constants... */

/* TX messages (shared by all connections) */
#define IBNAL_TX_MSGS()       (*kibnal_tunables.kib_ntx)
#define IBNAL_TX_MSG_BYTES()  (IBNAL_TX_MSGS() * IBNAL_MSG_SIZE)
#define IBNAL_TX_MSG_PAGES()  ((IBNAL_TX_MSG_BYTES() + PAGE_SIZE - 1)/PAGE_SIZE)

/* RX messages (per connection) */
#define IBNAL_RX_MSGS         (IBNAL_MSG_QUEUE_SIZE * 2)
#define IBNAL_RX_MSG_BYTES    (IBNAL_RX_MSGS * IBNAL_MSG_SIZE)
#define IBNAL_RX_MSG_PAGES    ((IBNAL_RX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)

/* we may have up to 2 completions per transmit +
   1 completion per receive, per connection */
#define IBNAL_CQ_ENTRIES()  ((2*IBNAL_TX_MSGS()) +                                      \
                             (IBNAL_RX_MSGS * *kibnal_tunables.kib_concurrent_peers))

typedef struct
{
        char    **kib_ipif_basename;            /* IPoIB interface base name */
        int      *kib_n_connd;                  /* # connection daemons */
        int      *kib_min_reconnect_interval;   /* min connect retry seconds... */
        int      *kib_max_reconnect_interval;   /* max connect retry seconds */
        int      *kib_concurrent_peers;         /* max # peers */
        int      *kib_cksum;                    /* checksum kib_msg_t? */
        int      *kib_timeout;                  /* comms timeout (seconds) */
        int      *kib_keepalive;                /* keepalive (seconds) */
        int      *kib_ntx;                      /* # tx descs */
        int      *kib_credits;                  /* # concurrent sends */
        int      *kib_peercredits;              /* # concurrent sends to 1 peer */

        cfs_sysctl_table_header_t *kib_sysctl;  /* sysctl interface */
} kib_tunables_t;

typedef struct
{
        int               ibp_npages;           /* # pages */
        int               ibp_mapped;           /* mapped? */
        __u64             ibp_vaddr;            /* mapped region vaddr */
        __u32             ibp_lkey;             /* mapped region lkey */
        __u32             ibp_rkey;             /* mapped region rkey */
        ib_mr_t          *ibp_handle;           /* mapped region handle */
        struct page      *ibp_pages[0];
} kib_pages_t;

typedef struct
{
        int               kib_init;             /* initialisation state */
        __u64             kib_incarnation;      /* which one am I */
        int               kib_shutdown;         /* shut down? */
        atomic_t          kib_nthreads;         /* # live threads */
        lnet_ni_t        *kib_ni;               /* _the_ openib interface */

        __u64             kib_svc_id;           /* service number I listen on */
        tTS_IB_GID        kib_svc_gid;          /* device/port GID */
        __u16             kib_svc_pkey;         /* device/port pkey */
        
        void             *kib_listen_handle;    /* IB listen handle */
        
        rwlock_t          kib_global_lock;      /* stabilize peer/conn ops */

        struct list_head *kib_peers;            /* hash table of all my known peers */
        int               kib_peer_hash_size;   /* size of kib_peers */
        int               kib_nonewpeers;       /* prevent new peers? */
        atomic_t          kib_npeers;           /* # peers extant */
        atomic_t          kib_nconns;           /* # connections extant */

        struct list_head  kib_reaper_conns;     /* connections to reap */
        wait_queue_head_t kib_reaper_waitq;     /* reaper sleeps here */
        unsigned long     kib_reaper_waketime;  /* when reaper will wake */
        spinlock_t        kib_reaper_lock;      /* serialise */

        struct list_head  kib_connd_peers;      /* peers waiting for a connection */
        struct list_head  kib_connd_acceptq;    /* accepted sockets to handle */
        wait_queue_head_t kib_connd_waitq;      /* connection daemons sleep here */
        int               kib_connd_connecting; /* # connds connecting */
        spinlock_t        kib_connd_lock;       /* serialise */

        wait_queue_head_t kib_sched_waitq;      /* schedulers sleep here */
        struct list_head  kib_sched_txq;        /* tx requiring attention */
        struct list_head  kib_sched_rxq;        /* rx requiring attention */
        spinlock_t        kib_sched_lock;       /* serialise */

        struct kib_tx    *kib_tx_descs;         /* all the tx descriptors */
        kib_pages_t      *kib_tx_pages;         /* premapped tx msg pages */

        struct list_head  kib_idle_txs;         /* idle tx descriptors */
        __u64             kib_next_tx_cookie;   /* RDMA completion cookie */
        spinlock_t        kib_tx_lock;          /* serialise */

        int               kib_hca_idx;          /* my HCA number */
        struct ib_device *kib_device;           /* "the" device */
        struct ib_device_properties kib_device_props; /* its properties */
        int               kib_port;             /* port on the device */
        struct ib_port_properties kib_port_props; /* its properties */
        ib_pd_t          *kib_pd;               /* protection domain */
#if IBNAL_FMR
        ib_fmr_pool_t    *kib_fmr_pool;         /* fast memory region pool */
#endif
        ib_cq_t          *kib_cq;               /* completion queue */

} kib_data_t;

#define IBNAL_INIT_NOTHING         0
#define IBNAL_INIT_DATA            1
#define IBNAL_INIT_LIB             2
#define IBNAL_INIT_PD              3
#define IBNAL_INIT_FMR             4
#define IBNAL_INIT_TXD             5
#define IBNAL_INIT_CQ              6
#define IBNAL_INIT_ALL             7

typedef struct kib_acceptsock                   /* accepted socket queued for connd */
{
        struct list_head     ibas_list;         /* queue for attention */
        struct socket       *ibas_sock;         /* the accepted socket */
} kib_acceptsock_t;

/************************************************************************
 * IB Wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 * They may be sent via TCP/IP (service ID,GID,PKEY query/response),
 * as private data in the connection request/response, or "normally".
 */

typedef struct kib_svcrsp                       /* service response */
{
        __u64             ibsr_svc_id;          /* service's id */
        __u8              ibsr_svc_gid[16];     /* service's gid */
        __u16             ibsr_svc_pkey;        /* service's pkey */
} WIRE_ATTR kib_svcrsp_t;

typedef struct kib_connparams
{
        __u32             ibcp_queue_depth;
} WIRE_ATTR kib_connparams_t;

typedef struct
{
        union {
                ib_mr_t         *mr;
                ib_fmr_t        *fmr;
        }                 md_handle;
        __u32             md_lkey;
        __u32             md_rkey;
        __u64             md_addr;
} kib_md_t;

typedef struct
{
        __u32             rd_key;               /* remote key */
        __u32             rd_nob;               /* # of bytes */
        __u64             rd_addr;              /* remote io vaddr */
} WIRE_ATTR kib_rdma_desc_t;

typedef struct
{
        lnet_hdr_t        ibim_hdr;             /* portals header */
        char              ibim_payload[0];      /* piggy-backed payload */
} WIRE_ATTR kib_immediate_msg_t;

typedef struct
{
        lnet_hdr_t        ibrm_hdr;             /* portals header */
        __u64             ibrm_cookie;          /* opaque completion cookie */
        kib_rdma_desc_t   ibrm_desc;            /* where to suck/blow */
} WIRE_ATTR kib_rdma_msg_t;

typedef struct
{
        __u64             ibcm_cookie;          /* opaque completion cookie */
        __u32             ibcm_status;          /* completion status */
} WIRE_ATTR kib_completion_msg_t;

typedef struct
{
        /* First 2 fields fixed FOR ALL TIME */
        __u32             ibm_magic;            /* I'm an openibnal message */
        __u16             ibm_version;          /* this is my version number */

        __u8              ibm_type;             /* msg type */
        __u8              ibm_credits;          /* returned credits */
        __u32             ibm_nob;              /* # bytes in whole message */
        __u32             ibm_cksum;            /* checksum (0 == no checksum) */
        __u64             ibm_srcnid;           /* sender's NID */
        __u64             ibm_srcstamp;         /* sender's incarnation */
        __u64             ibm_dstnid;           /* destination's NID */
        __u64             ibm_dststamp;         /* destination's incarnation */
        union {
                kib_svcrsp_t          svcrsp;
                kib_connparams_t      connparams;
                kib_immediate_msg_t   immediate;
                kib_rdma_msg_t        rdma;
                kib_completion_msg_t  completion;
        } WIRE_ATTR       ibm_u;
} WIRE_ATTR kib_msg_t;

#define IBNAL_MSG_MAGIC LNET_PROTO_OPENIB_MAGIC /* unique magic */
#define IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD 2   /* previous protocol version */
#define IBNAL_MSG_VERSION              3        /* current protocol version */

#define IBNAL_MSG_SVCQRY            0xb0        /* service query */
#define IBNAL_MSG_SVCRSP            0xb1        /* service response */
#define IBNAL_MSG_CONNREQ           0xc0        /* connection request */
#define IBNAL_MSG_CONNACK           0xc1        /* connection acknowledge */
#define IBNAL_MSG_NOOP              0xd0        /* nothing (just credits) */
#define IBNAL_MSG_IMMEDIATE         0xd1        /* portals hdr + payload */
#define IBNAL_MSG_PUT_RDMA          0xd2        /* portals PUT hdr + source rdma desc */
#define IBNAL_MSG_PUT_DONE          0xd3        /* signal PUT rdma completion */
#define IBNAL_MSG_GET_RDMA          0xd4        /* portals GET hdr + sink rdma desc */
#define IBNAL_MSG_GET_DONE          0xd5        /* signal GET rdma completion */

/***********************************************************************/

typedef struct kib_rx                           /* receive message */
{
        struct list_head          rx_list;      /* queue for attention */
        struct kib_conn          *rx_conn;      /* owning conn */
        int                       rx_nob;       /* # bytes received (-1 while posted) */
        __u64                     rx_vaddr;     /* pre-mapped buffer (hca vaddr) */
        kib_msg_t                *rx_msg;       /* pre-mapped buffer (host vaddr) */
        struct ib_receive_param   rx_sp;        /* receive work item */
        struct ib_gather_scatter  rx_gl;        /* and it's memory */
} kib_rx_t;

typedef struct kib_tx                           /* transmit message */
{
        struct list_head          tx_list;      /* queue on idle_txs ibc_tx_queue etc. */
        struct kib_conn          *tx_conn;      /* owning conn */
        int                       tx_mapped;    /* mapped for RDMA? */
        int                       tx_sending;   /* # tx callbacks outstanding */
        int                       tx_status;    /* completion status */
        unsigned long             tx_deadline;  /* completion deadline */
        int                       tx_passive_rdma; /* peer sucks/blows */
        int                       tx_passive_rdma_wait; /* waiting for peer to complete */
        __u64                     tx_passive_rdma_cookie; /* completion cookie */
        lnet_msg_t               *tx_lntmsg[2]; /* ptl msgs to finalize on completion */
        kib_md_t                  tx_md;        /* RDMA mapping (active/passive) */
        __u64                     tx_vaddr;     /* pre-mapped buffer (hca vaddr) */
        kib_msg_t                *tx_msg;       /* pre-mapped buffer (host vaddr) */
        int                       tx_nsp;       /* # send work items */
        struct ib_send_param      tx_sp[2];     /* send work items... */
        struct ib_gather_scatter  tx_gl[2];     /* ...and their memory */
} kib_tx_t;

#define KIB_TX_UNMAPPED       0
#define KIB_TX_MAPPED         1
#define KIB_TX_MAPPED_FMR     2

typedef struct kib_connreq
{
        /* active connection-in-progress state */
        struct kib_conn           *cr_conn;
        kib_msg_t                  cr_msg;
        __u64                      cr_tid;
        tTS_IB_GID                 cr_gid;
        kib_svcrsp_t               cr_svcrsp;
        struct ib_path_record      cr_path;
        struct ib_cm_active_param  cr_connparam;
} kib_connreq_t;

typedef struct kib_conn
{
        struct kib_peer    *ibc_peer;           /* owning peer */
        struct list_head    ibc_list;           /* stash on peer's conn list */
        __u64               ibc_incarnation;    /* which instance of the peer */
        int                 ibc_version;        /* peer protocol version */
        atomic_t            ibc_refcount;       /* # users */
        int                 ibc_state;          /* what's happening */
        int                 ibc_nsends_posted;  /* # uncompleted sends */
        int                 ibc_credits;        /* # credits I have */
        int                 ibc_outstanding_credits; /* # credits to return */
        int                 ibc_reserved_credits; /* # credits for ACK/DONE msgs */
        unsigned long       ibc_last_send;      /* time of last send */
        struct list_head    ibc_tx_queue_nocred; /* sends that don't need a credit */
        struct list_head    ibc_tx_queue_rsrvd; /* sends that need a reserved cred */
        struct list_head    ibc_tx_queue;       /* send queue */
        struct list_head    ibc_active_txs;     /* active tx awaiting completion */
        spinlock_t          ibc_lock;           /* serialise */
        kib_rx_t           *ibc_rxs;            /* the rx descs */
        kib_pages_t        *ibc_rx_pages;       /* premapped rx msg pages */
        ib_qp_t            *ibc_qp;             /* queue pair */
        __u32               ibc_qpn;            /* queue pair number */
        tTS_IB_CM_COMM_ID   ibc_comm_id;        /* connection ID? */
        kib_connreq_t      *ibc_connreq;        /* connection request state */
} kib_conn_t;

#define IBNAL_CONN_INIT_NOTHING      0          /* initial state */
#define IBNAL_CONN_INIT_QP           1          /* ibc_qp set up */
#define IBNAL_CONN_CONNECTING        2          /* started to connect */
#define IBNAL_CONN_ESTABLISHED       3          /* connection established */
#define IBNAL_CONN_DEATHROW          4          /* waiting to be closed */
#define IBNAL_CONN_ZOMBIE            5          /* waiting to be freed */

typedef struct kib_peer
{
        struct list_head    ibp_list;           /* stash on global peer list */
        struct list_head    ibp_connd_list;     /* schedule on kib_connd_peers */
        lnet_nid_t          ibp_nid;            /* who's on the other end(s) */
        __u32               ibp_ip;             /* IP to query for peer conn params */
        int                 ibp_port;           /* port to qery for peer conn params */
        __u64               ibp_incarnation;    /* peer's incarnation */
        atomic_t            ibp_refcount;       /* # users */
        int                 ibp_persistence;    /* "known" peer refs */
        struct list_head    ibp_conns;          /* all active connections */
        struct list_head    ibp_tx_queue;       /* msgs waiting for a conn */
        int                 ibp_connecting;     /* current active connection attempts */
        int                 ibp_accepting;      /* current passive connection attempts */
        unsigned long       ibp_reconnect_time; /* when reconnect may be attempted */
        unsigned long       ibp_reconnect_interval; /* exponential backoff */
        int                 ibp_error;          /* errno on closing this peer */
        cfs_time_t          ibp_last_alive;     /* when (in jiffies) I was last alive */
} kib_peer_t;

extern kib_data_t      kibnal_data;
extern kib_tunables_t  kibnal_tunables;

/******************************************************************************/

/* these are purposely avoiding using local vars so they don't increase
 * stack consumption. */

#define kibnal_conn_addref(conn)                                \
do {                                                            \
        CDEBUG(D_NET, "conn[%p] (%d)++\n",                      \
               (conn), atomic_read(&(conn)->ibc_refcount));     \
        LASSERT(atomic_read(&(conn)->ibc_refcount) > 0);        \
        atomic_inc(&(conn)->ibc_refcount);                      \
} while (0)

#define kibnal_conn_decref(conn)                                              \
do {                                                                          \
        unsigned long   flags;                                                \
                                                                              \
        CDEBUG(D_NET, "conn[%p] (%d)--\n",                                    \
               (conn), atomic_read(&(conn)->ibc_refcount));                   \
        LASSERT(atomic_read(&(conn)->ibc_refcount) > 0);                      \
        if (atomic_dec_and_test(&(conn)->ibc_refcount)) {                     \
                spin_lock_irqsave(&kibnal_data.kib_reaper_lock, flags);       \
                list_add_tail(&(conn)->ibc_list,                              \
                              &kibnal_data.kib_reaper_conns);                 \
                wake_up(&kibnal_data.kib_reaper_waitq);                       \
                spin_unlock_irqrestore(&kibnal_data.kib_reaper_lock, flags);  \
        }                                                                     \
} while (0)

#define kibnal_peer_addref(peer)                                \
do {                                                            \
        CDEBUG(D_NET, "peer[%p] -> %s (%d)++\n",                \
               (peer), libcfs_nid2str((peer)->ibp_nid),         \
               atomic_read (&(peer)->ibp_refcount));            \
        LASSERT(atomic_read(&(peer)->ibp_refcount) > 0);        \
        atomic_inc(&(peer)->ibp_refcount);                      \
} while (0)

#define kibnal_peer_decref(peer)                                \
do {                                                            \
        CDEBUG(D_NET, "peer[%p] -> %s (%d)--\n",                \
               (peer), libcfs_nid2str((peer)->ibp_nid),         \
               atomic_read (&(peer)->ibp_refcount));            \
        LASSERT(atomic_read(&(peer)->ibp_refcount) > 0);        \
        if (atomic_dec_and_test(&(peer)->ibp_refcount))         \
                kibnal_destroy_peer(peer);                      \
} while (0)

/******************************************************************************/

static inline struct list_head *
kibnal_nid2peerlist (lnet_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) % kibnal_data.kib_peer_hash_size;

        return (&kibnal_data.kib_peers [hash]);
}

static inline int
kibnal_peer_active(kib_peer_t *peer)
{
        /* Am I in the peer hash table? */
        return (!list_empty(&peer->ibp_list));
}

static inline void
kibnal_queue_tx_locked (kib_tx_t *tx, kib_conn_t *conn)
{
        struct list_head      *q;

        LASSERT (tx->tx_nsp > 0);               /* work items set up */
        LASSERT (tx->tx_conn == NULL);          /* only set here */

        kibnal_conn_addref(conn);
        tx->tx_conn = conn;
        tx->tx_deadline = jiffies + *kibnal_tunables.kib_timeout * HZ;

        if (conn->ibc_version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD) {
                /* All messages have simple credit control */
                q = &conn->ibc_tx_queue;
        } else {
                LASSERT (conn->ibc_version == IBNAL_MSG_VERSION);
                
                switch (tx->tx_msg->ibm_type) {
                case IBNAL_MSG_PUT_RDMA:
                case IBNAL_MSG_GET_RDMA:
                        /* RDMA request: reserve a buffer for the RDMA reply
                         * before sending */
                        q = &conn->ibc_tx_queue_rsrvd;
                        break;

                case IBNAL_MSG_PUT_DONE:
                case IBNAL_MSG_GET_DONE:
                        /* RDMA completion: no credits; peer has reserved a
                         * reply buffer */
                        q = &conn->ibc_tx_queue_nocred;
                        break;
                
                case IBNAL_MSG_NOOP:
                case IBNAL_MSG_IMMEDIATE:
                        /* Otherwise: consume a credit before sending */
                        q = &conn->ibc_tx_queue;
                        break;
                
                default:
                        LBUG();
                        q = NULL;
                }
        }

        list_add_tail(&tx->tx_list, q);
}

static inline int
kibnal_send_keepalive(kib_conn_t *conn) 
{
        return (*kibnal_tunables.kib_keepalive > 0) &&
                time_after(jiffies, conn->ibc_last_send +
                           *kibnal_tunables.kib_keepalive*HZ);
}

/* CAVEAT EMPTOR:
 * We rely on tx/rx descriptor alignment to allow us to use the lowest bit
 * of the work request id as a flag to determine if the completion is for a
 * transmit or a receive.  It seems that that the CQ entry's 'op' field
 * isn't always set correctly on completions that occur after QP teardown. */

static inline __u64
kibnal_ptr2wreqid (void *ptr, int isrx)
{
        unsigned long lptr = (unsigned long)ptr;

        LASSERT ((lptr & 1) == 0);
        return (__u64)(lptr | (isrx ? 1 : 0));
}

static inline void *
kibnal_wreqid2ptr (__u64 wreqid)
{
        return (void *)(((unsigned long)wreqid) & ~1UL);
}

static inline int
kibnal_wreqid_is_rx (__u64 wreqid)
{
        return (wreqid & 1) != 0;
}

#if (IB_NTXRXPARAMS == 3)
static inline int
kibnal_ib_send(ib_qp_t *qp, struct ib_send_param *p)
{
        return ib_send(qp, p, 1);
}

static inline int
kibnal_ib_receive(ib_qp_t *qp, struct ib_receive_param *p)
{
        return ib_receive(qp, p, 1);
}
#elif (IB_NTXRXPARAMS == 4)
static inline int
kibnal_ib_send(ib_qp_t *qp, struct ib_send_param *p)
{
        return ib_send(qp, p, 1, NULL);
}

static inline int
kibnal_ib_receive(ib_qp_t *qp, struct ib_receive_param *p)
{
        return ib_receive(qp, p, 1, NULL);
}
#else
 #error "IB_NTXRXPARAMS not set correctly"
#endif

int kibnal_startup (lnet_ni_t *ni);
void kibnal_shutdown (lnet_ni_t *ni);
int kibnal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int kibnal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int kibnal_eager_recv (lnet_ni_t *ni, void *private, 
                       lnet_msg_t *lntmsg, void **new_private);
int kibnal_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, 
                int delayed, unsigned int niov, 
                struct iovec *iov, lnet_kiov_t *kiov,
                unsigned int offset, unsigned int mlen, unsigned int rlen);
int kibnal_accept(lnet_ni_t *ni, struct socket *sock);

extern void kibnal_init_msg(kib_msg_t *msg, int type, int body_nob);
extern void kibnal_pack_msg(kib_msg_t *msg, int version, int credits, 
                            lnet_nid_t dstnid, __u64 dststamp);
extern int kibnal_unpack_msg(kib_msg_t *msg, int expected_version, int nob);
extern void kibnal_handle_svcqry (struct socket *sock);
extern int kibnal_make_svcqry (kib_conn_t *conn);
extern void kibnal_free_acceptsock (kib_acceptsock_t *as);
extern int kibnal_create_peer (kib_peer_t **peerp, lnet_nid_t nid);
extern void kibnal_destroy_peer (kib_peer_t *peer);
extern int kibnal_add_persistent_peer(lnet_nid_t nid, __u32 ip, int port);
extern int kibnal_del_peer (lnet_nid_t nid);
extern kib_peer_t *kibnal_find_peer_locked (lnet_nid_t nid);
extern void kibnal_unlink_peer_locked (kib_peer_t *peer);
extern void kibnal_peer_alive(kib_peer_t *peer);
extern int  kibnal_close_stale_conns_locked (kib_peer_t *peer,
                                              __u64 incarnation);
extern kib_conn_t *kibnal_create_conn (void);
extern void kibnal_destroy_conn (kib_conn_t *conn);
extern int kibnal_alloc_pages (kib_pages_t **pp, int npages, int access);
extern void kibnal_free_pages (kib_pages_t *p);

extern void kibnal_check_sends (kib_conn_t *conn);

extern tTS_IB_CM_CALLBACK_RETURN
kibnal_bad_conn_callback (tTS_IB_CM_EVENT event, tTS_IB_CM_COMM_ID cid,
                          void *param, void *arg);
extern tTS_IB_CM_CALLBACK_RETURN
kibnal_conn_callback (tTS_IB_CM_EVENT event, tTS_IB_CM_COMM_ID cid,
                       void *param, void *arg);
extern tTS_IB_CM_CALLBACK_RETURN
kibnal_passive_conn_callback (tTS_IB_CM_EVENT event, tTS_IB_CM_COMM_ID cid,
                               void *param, void *arg);

extern void kibnal_close_conn_locked (kib_conn_t *conn, int error);
extern void kibnal_destroy_conn (kib_conn_t *conn);
extern int  kibnal_thread_start (int (*fn)(void *arg), void *arg);
extern int  kibnal_scheduler(void *arg);
extern int  kibnal_connd (void *arg);
extern int  kibnal_reaper (void *arg);
extern void kibnal_callback (ib_cq_t *cq, struct ib_cq_entry *e, void *arg);
extern void kibnal_txlist_done (struct list_head *txlist, int status);
extern void kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob);
extern int  kibnal_close_conn (kib_conn_t *conn, int why);
extern void kibnal_start_active_rdma (int type, int status,
                                      kib_rx_t *rx, lnet_msg_t *lntmsg,
                                      unsigned int niov,
                                      struct iovec *iov, lnet_kiov_t *kiov,
                                      int offset, int nob);

extern int  kibnal_tunables_init(void);
extern void kibnal_tunables_fini(void);
