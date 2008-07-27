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
 * lnet/klnds/iiblnd/iiblnd.h
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

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>

#include <linux/iba/ibt.h>

#define GCC_VERSION (__GNUC__ * 10000 \
                + __GNUC_MINOR__ * 100 \
                + __GNUC_PATCHLEVEL__)

/* Test for GCC > 3.2.2 */
#if GCC_VERSION <= 30202
/* GCC 3.2.2, and presumably several versions before it, will
 * miscompile this driver. See
 * http://gcc.gnu.org/bugzilla/show_bug.cgi?id=9853. */
#error Invalid GCC version. Must use GCC >= 3.2.3
#endif

#ifdef CONFIG_SMP
# define IBNAL_N_SCHED      num_online_cpus()   /* # schedulers */
#else
# define IBNAL_N_SCHED      1                   /* # schedulers */
#endif

#define IBNAL_USE_FMR                0          /* map on demand v. use whole mem mapping */
#define KIBLND_DETAILED_DEBUG        0

/* tunables fixed at compile time */
#define IBNAL_PEER_HASH_SIZE         101        /* # peer lists */
#define IBNAL_RESCHED                100        /* # scheduler loops before reschedule */
#define IBNAL_MSG_QUEUE_SIZE         8          /* # messages/RDMAs in-flight */
#define IBNAL_CREDIT_HIGHWATER       7          /* when to eagerly return credits */
#define IBNAL_MSG_SIZE              (4<<10)     /* max size of queued messages (inc hdr) */
#define IBNAL_RDMA_BASE              0x0eeb0000
#define IBNAL_STARTING_PSN           1

/* QP tunables */
/* 7 indicates infinite retry attempts, Infinicon recommended 5 */
#define IBNAL_RETRY                  5          /* # times to retry */
#define IBNAL_RNR_RETRY              5          /*  */
#define IBNAL_CM_RETRY               5          /* # times to retry connection */
#define IBNAL_FLOW_CONTROL           1
#define IBNAL_ACK_TIMEOUT            20         /* supposedly 4 secs */
#define IBNAL_EE_FLOW                1
#define IBNAL_LOCAL_SUB              1
#define IBNAL_FAILOVER_ACCEPTED      0

/************************/
/* derived constants... */

/* TX messages (shared by all connections) */
#define IBNAL_TX_MSGS()       (*kibnal_tunables.kib_ntx)
#define IBNAL_TX_MSG_BYTES()  (IBNAL_TX_MSGS() * IBNAL_MSG_SIZE)
#define IBNAL_TX_MSG_PAGES()  ((IBNAL_TX_MSG_BYTES() + PAGE_SIZE - 1)/PAGE_SIZE)

#if IBNAL_USE_FMR
# define IBNAL_MAX_RDMA_FRAGS 1
# define IBNAL_CONCURRENT_SENDS IBNAL_RX_MSGS
#else
# define IBNAL_MAX_RDMA_FRAGS LNET_MAX_IOV
# define IBNAL_CONCURRENT_SENDS IBNAL_MSG_QUEUE_SIZE
#endif

/* RX messages (per connection) */
#define IBNAL_RX_MSGS         (IBNAL_MSG_QUEUE_SIZE * 2)
#define IBNAL_RX_MSG_BYTES    (IBNAL_RX_MSGS * IBNAL_MSG_SIZE)
#define IBNAL_RX_MSG_PAGES    ((IBNAL_RX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)

#define IBNAL_CQ_ENTRIES()  (IBNAL_TX_MSGS() * (1 + IBNAL_MAX_RDMA_FRAGS) +             \
                             (IBNAL_RX_MSGS * *kibnal_tunables.kib_concurrent_peers))

typedef struct
{
        char            **kib_hca_basename;     /* HCA base name */
        char            **kib_ipif_basename;    /* IPoIB interface base name */
        char            **kib_service_name;     /* global service name */
        unsigned int     *kib_service_number;   /* global service number */
        int              *kib_min_reconnect_interval; /* min connect retry seconds... */
        int              *kib_max_reconnect_interval; /* max connect retry seconds */
        int              *kib_concurrent_peers; /* max # peers */
        int              *kib_cksum;            /* checksum kib_msg_t? */
        int              *kib_timeout;          /* comms timeout (seconds) */
        int              *kib_keepalive;        /* keepalive timeout (seconds) */
        int              *kib_ntx;              /* # tx descs */
        int              *kib_credits;          /* # concurrent sends */
        int              *kib_peercredits;      /* # concurrent sends to 1 peer */
        int              *kib_sd_retries;       /* # concurrent sends to 1 peer */
        int              *kib_concurrent_sends; /* send work queue sizing */
#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
        cfs_sysctl_table_header_t *kib_sysctl;  /* sysctl interface */
#endif
} kib_tunables_t;

/* NB The Infinicon stack has specific typedefs for some things
 * (e.g. IB_{L,R}_KEY), that just map back to __u32 etc */
typedef struct
{
        int               ibp_npages;           /* # pages */
        struct page      *ibp_pages[0];
} kib_pages_t;

typedef struct
{
        IB_HANDLE         md_handle;
        __u32             md_lkey;
        __u32             md_rkey;
        __u64             md_addr;
} kib_md_t;

typedef struct
{
        int               kib_init;             /* initialisation state */
        __u64             kib_incarnation;      /* which one am I */
        int               kib_shutdown;         /* shut down? */
        atomic_t          kib_nthreads;         /* # live threads */
        lnet_ni_t        *kib_ni;               /* _the_ iib instance */

        __u64             kib_port_guid;        /* my GUID (lo 64 of GID)*/
        __u16             kib_port_pkey;        /* my pkey, whatever that is */
        struct semaphore  kib_listener_signal;  /* signal completion */
        IB_HANDLE         kib_listener_cep;     /* connection end point */

        rwlock_t          kib_global_lock;      /* stabilize peer/conn ops */
        int               kib_ready;            /* CQ callback fired */
        int               kib_checking_cq;      /* a scheduler is checking the CQ */

        struct list_head *kib_peers;            /* hash table of all my known peers */
        int               kib_peer_hash_size;   /* size of kib_peers */
        atomic_t          kib_npeers;           /* # peers extant */
        atomic_t          kib_nconns;           /* # connections extant */

        struct list_head  kib_connd_zombies;    /* connections to free */
        struct list_head  kib_connd_conns;      /* connections to progress */
        struct list_head  kib_connd_peers;      /* peers waiting for a connection */
        wait_queue_head_t kib_connd_waitq;      /* connection daemon sleep here */
        spinlock_t        kib_connd_lock;       /* serialise */

        wait_queue_head_t kib_sched_waitq;      /* schedulers sleep here */
        spinlock_t        kib_sched_lock;       /* serialise */

        struct kib_tx    *kib_tx_descs;         /* all the tx descriptors */
        kib_pages_t      *kib_tx_pages;         /* premapped tx msg pages */

        struct list_head  kib_idle_txs;         /* idle tx descriptors */
        __u64             kib_next_tx_cookie;   /* RDMA completion cookie */
        spinlock_t        kib_tx_lock;          /* serialise */

        IB_HANDLE         kib_hca;              /* The HCA */
        int               kib_port;             /* port on the device */
        IB_HANDLE         kib_pd;               /* protection domain */
        IB_HANDLE         kib_sd;               /* SD handle */
        IB_HANDLE         kib_cq;               /* completion queue */
        kib_md_t          kib_whole_mem;        /* whole-mem registration */

        int               kib_hca_idx;          /* my HCA number */
        uint64            kib_hca_guids[8];     /* all the HCA guids */
        IB_CA_ATTRIBUTES  kib_hca_attrs;        /* where to get HCA attrs */

        COMMAND_CONTROL_PARAMETERS kib_sdretry; /* control SD query retries */
} kib_data_t;

#define IBNAL_INIT_NOTHING         0
#define IBNAL_INIT_DATA            1
#define IBNAL_INIT_LIB             2
#define IBNAL_INIT_HCA             3
#define IBNAL_INIT_PORTATTRS       4
#define IBNAL_INIT_SD              5
#define IBNAL_INIT_PD              6
#define IBNAL_INIT_MD              7
#define IBNAL_INIT_TXD             8
#define IBNAL_INIT_CQ              9
#define IBNAL_INIT_ALL             10

/************************************************************************
 * Wire message structs.
 * These are sent in sender's byte order (i.e. receiver flips).
 * CAVEAT EMPTOR: other structs communicated between nodes (e.g. MAD
 * private data and SM service info), is LE on the wire.
 */

typedef struct kib_connparams
{
        __u32             ibcp_queue_depth;
        __u32             ibcp_max_msg_size;
        __u32             ibcp_max_frags;
} WIRE_ATTR kib_connparams_t;

typedef struct
{
        lnet_hdr_t        ibim_hdr;             /* portals header */
        char              ibim_payload[0];      /* piggy-backed payload */
} WIRE_ATTR kib_immediate_msg_t;

#if IBNAL_USE_FMR
typedef struct
{
	__u64             rd_addr;             	/* IO VMA address */
	__u32             rd_nob;              	/* # of bytes */
	__u32             rd_key;		/* remote key */
} WIRE_ATTR kib_rdma_desc_t;
#else
typedef struct
{
        __u32             rf_nob;               /* # of bytes */
        __u64             rf_addr;              /* remote io vaddr */
} WIRE_ATTR kib_rdma_frag_t;

typedef struct
{
        __u32             rd_key;               /* local/remote key */
        __u32             rd_nfrag;             /* # fragments */
        kib_rdma_frag_t   rd_frags[0];          /* buffer frags */
} WIRE_ATTR kib_rdma_desc_t;
#endif

typedef struct
{
        lnet_hdr_t        ibprm_hdr;            /* LNET header */
        __u64             ibprm_cookie;         /* opaque completion cookie */
} WIRE_ATTR kib_putreq_msg_t;

typedef struct
{
        __u64             ibpam_src_cookie;     /* reflected completion cookie */
        __u64             ibpam_dst_cookie;     /* opaque completion cookie */
        kib_rdma_desc_t   ibpam_rd;             /* sender's sink buffer */
} WIRE_ATTR kib_putack_msg_t;

typedef struct
{
        lnet_hdr_t        ibgm_hdr;             /* LNET header */
        __u64             ibgm_cookie;          /* opaque completion cookie */
        kib_rdma_desc_t   ibgm_rd;              /* sender's sink buffer */
} WIRE_ATTR kib_get_msg_t;

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
        __u64             ibm_seq;              /* sequence number */

        union {
                kib_connparams_t      connparams;
                kib_immediate_msg_t   immediate;
                kib_putreq_msg_t      putreq;
                kib_putack_msg_t      putack;
                kib_get_msg_t         get;
                kib_completion_msg_t  completion;
        } WIRE_ATTR ibm_u;
} WIRE_ATTR kib_msg_t;

#define IBNAL_MSG_MAGIC LNET_PROTO_IIB_MAGIC    /* unique magic */
#define IBNAL_MSG_VERSION              2        /* current protocol version */
#define IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD 1   /* previous version */

#define IBNAL_MSG_CONNREQ           0xc0        /* connection request */
#define IBNAL_MSG_CONNACK           0xc1        /* connection acknowledge */
#define IBNAL_MSG_NOOP              0xd0        /* nothing (just credits) */
#define IBNAL_MSG_IMMEDIATE         0xd1        /* immediate */
#define IBNAL_MSG_PUT_REQ           0xd2        /* putreq (src->sink) */
#define IBNAL_MSG_PUT_NAK           0xd3        /* completion (sink->src) */
#define IBNAL_MSG_PUT_ACK           0xd4        /* putack (sink->src) */
#define IBNAL_MSG_PUT_DONE          0xd5        /* completion (src->sink) */
#define IBNAL_MSG_GET_REQ           0xd6        /* getreq (sink->src) */
#define IBNAL_MSG_GET_DONE          0xd7        /* completion (src->sink: all OK) */

/* connection rejection reasons */
#define IBNAL_REJECT_CONN_RACE       0          /* You lost connection race */
#define IBNAL_REJECT_NO_RESOURCES    1          /* Out of memory/conns etc */
#define IBNAL_REJECT_FATAL           2          /* Anything else */

/***********************************************************************/

typedef struct kib_rx                           /* receive message */
{
        struct list_head          rx_list;      /* queue for attention */
        struct kib_conn          *rx_conn;      /* owning conn */
        int                       rx_nob;       /* # bytes received (-1 while posted) */
        __u64                     rx_hca_msg;   /* pre-mapped buffer (hca vaddr) */
        kib_msg_t                *rx_msg;       /* pre-mapped buffer (host vaddr) */
        IB_WORK_REQ2              rx_wrq;
        IB_LOCAL_DATASEGMENT      rx_gl;        /* and its memory */
} kib_rx_t;

typedef struct kib_tx                           /* transmit message */
{
        struct list_head          tx_list;      /* queue on idle_txs ibc_tx_queue etc. */
        struct kib_conn          *tx_conn;      /* owning conn */
        int                       tx_mapped;    /* mapped for RDMA? */
        int                       tx_sending;   /* # tx callbacks outstanding */
        int                       tx_queued;    /* queued for sending */
        int                       tx_waiting;   /* waiting for peer */
        int                       tx_status;    /* completion status */
        unsigned long             tx_deadline;  /* completion deadline */
        __u64                     tx_cookie;    /* completion cookie */
        lnet_msg_t               *tx_lntmsg[2]; /* lnet msgs to finalize on completion */
        kib_msg_t                *tx_msg;       /* pre-mapped buffer (host vaddr) */
        __u64                     tx_hca_msg;   /* pre-mapped buffer (HCA vaddr) */
        int                       tx_nwrq;      /* # send work items */
#if IBNAL_USE_FMR
        IB_WORK_REQ2              tx_wrq[2];    /* send work items... */
        IB_LOCAL_DATASEGMENT      tx_gl[2];     /* ...and their memory */
        kib_rdma_desc_t           tx_rd[1];     /* rdma descriptor */
        kib_md_t                  tx_md;        /* mapping */
        __u64                    *tx_pages;     /* page phys addrs */
#else
        IB_WORK_REQ2             *tx_wrq;       /* send work items... */
        IB_LOCAL_DATASEGMENT     *tx_gl;        /* ...and their memory */
        kib_rdma_desc_t          *tx_rd;        /* rdma descriptor (src buffers) */
#endif
} kib_tx_t;

typedef struct
{
        /* scratchpad during connection establishment */
        IB_QP_ATTRIBUTES_QUERY cv_qpattrs;
        QUERY                  cv_query;
        IB_SERVICE_RECORD      cv_svcrec;
        IB_PATH_RECORD         cv_path;
        CM_CONN_INFO           cv_cmci;
} kib_connvars_t;

typedef struct kib_conn
{
        struct kib_peer    *ibc_peer;           /* owning peer */
        struct list_head    ibc_list;           /* stash on peer's conn list */
        __u64               ibc_incarnation;    /* which instance of the peer */
        __u64               ibc_txseq;          /* tx sequence number */
        __u64               ibc_rxseq;          /* rx sequence number */
        __u32               ibc_version;        /* peer protocol version */
        atomic_t            ibc_refcount;       /* # users */
        int                 ibc_state;          /* what's happening */
        int                 ibc_nsends_posted;  /* # uncompleted sends */
        int                 ibc_credits;        /* # credits I have */
        int                 ibc_outstanding_credits; /* # credits to return */
        int                 ibc_reserved_credits; /* # credits for ACK/DONE msgs */
        unsigned long       ibc_last_send;      /* time of last send */
        struct list_head    ibc_early_rxs;      /* rxs completed before ESTABLISHED */
        struct list_head    ibc_tx_queue_nocred; /* sends that don't need a cred */
        struct list_head    ibc_tx_queue_rsrvd; /* sends that need a reserved cred */
        struct list_head    ibc_tx_queue;       /* send queue */
        struct list_head    ibc_active_txs;     /* active tx awaiting completion */
        spinlock_t          ibc_lock;           /* serialise */
        kib_rx_t           *ibc_rxs;            /* the rx descs */
        kib_pages_t        *ibc_rx_pages;       /* premapped rx msg pages */
        IB_HANDLE           ibc_qp;             /* queue pair */
        IB_HANDLE           ibc_cep;            /* CM endpoint */
        kib_connvars_t     *ibc_cvars;          /* connection scratchpad */
} kib_conn_t;

#define IBNAL_CONN_INIT_NOTHING      0          /* initial state */
#define IBNAL_CONN_INIT_QP           1          /* ibc_qp set up */
#define IBNAL_CONN_CONNECTING        2          /* started to connect */
#define IBNAL_CONN_ESTABLISHED       3          /* connection established */
#define IBNAL_CONN_DISCONNECTING     4          /* to send disconnect req */
#define IBNAL_CONN_DISCONNECTED      5          /* no more QP or CM traffic */

/* types of connection */
#define IBNAL_CONN_ACTIVE            0          /* active connect */
#define IBNAL_CONN_PASSIVE           1          /* passive connect */
#define IBNAL_CONN_WAITING           2          /* waiting for connect */

typedef struct kib_peer
{
        struct list_head    ibp_list;           /* stash on global peer list */
        struct list_head    ibp_connd_list;     /* schedule on kib_connd_peers */
        lnet_nid_t          ibp_nid;            /* who's on the other end(s) */
        atomic_t            ibp_refcount;       /* # users */
        int                 ibp_persistence;    /* "known" peer refs */
        int                 ibp_version;        /* protocol version */
        struct list_head    ibp_conns;          /* all active connections */
        struct list_head    ibp_tx_queue;       /* msgs waiting for a conn */
        int                 ibp_connecting;     /* active connects in progress */
        int                 ibp_accepting;      /* passive connects in progress */
        int                 ibp_passivewait;    /* waiting for peer to connect */
        unsigned long       ibp_passivewait_deadline; /* when passive wait must complete */
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
                spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);        \
                list_add_tail(&(conn)->ibc_list,                              \
                              &kibnal_data.kib_connd_zombies);                \
                wake_up(&kibnal_data.kib_connd_waitq);                        \
                spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);   \
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

static inline int
kibnal_peer_connecting(kib_peer_t *peer)
{
        /* Am I expecting a connection to materialise? */
        return (peer->ibp_connecting != 0 ||
                peer->ibp_accepting != 0 ||
                peer->ibp_passivewait);
}

static inline void
kibnal_queue_tx_locked (kib_tx_t *tx, kib_conn_t *conn)
{
        struct list_head  *q;
        
        LASSERT (tx->tx_nwrq > 0);              /* work items set up */
        LASSERT (!tx->tx_queued);               /* not queued for sending already */

        tx->tx_queued = 1;
        tx->tx_deadline = jiffies + (*kibnal_tunables.kib_timeout * HZ);

        if (tx->tx_conn == NULL) {
                kibnal_conn_addref(conn);
                tx->tx_conn = conn;
                LASSERT (tx->tx_msg->ibm_type != IBNAL_MSG_PUT_DONE);
        } else {
                LASSERT (tx->tx_conn == conn);
                LASSERT (tx->tx_msg->ibm_type == IBNAL_MSG_PUT_DONE);
        }

        if (conn->ibc_version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD) {
                /* All messages have simple credit control */
                q = &conn->ibc_tx_queue;
        } else {
                LASSERT (conn->ibc_version == IBNAL_MSG_VERSION);
                
                switch (tx->tx_msg->ibm_type) {
                case IBNAL_MSG_PUT_REQ:
                case IBNAL_MSG_GET_REQ:
                        /* RDMA request: reserve a buffer for the RDMA reply
                         * before sending */
                        q = &conn->ibc_tx_queue_rsrvd;
                        break;

                case IBNAL_MSG_PUT_NAK:
                case IBNAL_MSG_PUT_ACK:
                case IBNAL_MSG_PUT_DONE:
                case IBNAL_MSG_GET_DONE:
                        /* RDMA reply/completion: no credits; peer has reserved
                         * a reply buffer */
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

#define KIBNAL_SERVICE_KEY_MASK  (IB_SERVICE_RECORD_COMP_SERVICENAME |          \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_1 |       \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_2 |       \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_3 |       \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_4 |       \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_5 |       \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_6 |       \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_7 |       \
                                  IB_SERVICE_RECORD_COMP_SERVICEDATA8_8)

static inline __u64*
kibnal_service_nid_field(IB_SERVICE_RECORD *srv)
{
        /* must be consistent with KIBNAL_SERVICE_KEY_MASK */
        return (__u64 *)srv->ServiceData8;
}

static inline void
kibnal_set_service_keys(IB_SERVICE_RECORD *srv, lnet_nid_t nid)
{
        char *svc_name = *kibnal_tunables.kib_service_name;

        LASSERT (strlen(svc_name) < sizeof(srv->ServiceName));
        memset (srv->ServiceName, 0, sizeof(srv->ServiceName));
        strcpy (srv->ServiceName, svc_name);

        *kibnal_service_nid_field(srv) = cpu_to_le64(nid);
}

/* CAVEAT EMPTOR: We rely on tx/rx descriptor alignment to allow us to use the
 * lowest 2 bits of the work request id to stash the work item type (the op
 * field is not valid when the wc completes in error). */

#define IBNAL_WID_TX    0
#define IBNAL_WID_RX    1
#define IBNAL_WID_RDMA  2
#define IBNAL_WID_MASK  3UL

static inline __u64
kibnal_ptr2wreqid (void *ptr, int type)
{
        unsigned long lptr = (unsigned long)ptr;

        LASSERT ((lptr & IBNAL_WID_MASK) == 0);
        LASSERT ((type & ~IBNAL_WID_MASK) == 0);
        return (__u64)(lptr | type);
}

static inline void *
kibnal_wreqid2ptr (__u64 wreqid)
{
        return (void *)(((unsigned long)wreqid) & ~IBNAL_WID_MASK);
}

static inline int
kibnal_wreqid2type (__u64 wreqid)
{
        return (wreqid & IBNAL_WID_MASK);
}

static inline void
kibnal_set_conn_state (kib_conn_t *conn, int state)
{
        CDEBUG(D_NET,"%p state %d\n", conn, state);
        conn->ibc_state = state;
        mb();
}

#if IBNAL_USE_FMR

static inline int
kibnal_rd_size (kib_rdma_desc_t *rd) 
{
        return rd->rd_nob;
}

#else
static inline int
kibnal_rd_size (kib_rdma_desc_t *rd)
{
        int   i;
        int   size;
        
        for (i = size = 0; i < rd->rd_nfrag; i++)
                size += rd->rd_frags[i].rf_nob;
        
        return size;
}
#endif

int  kibnal_startup (lnet_ni_t *ni);
void kibnal_shutdown (lnet_ni_t *ni);
int  kibnal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int  kibnal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int  kibnal_eager_recv (lnet_ni_t *ni, void *private, 
                        lnet_msg_t *lntmsg, void **new_private);
int  kibnal_recv (lnet_ni_t *ni, void *private, lnet_msg_t *msg,
                  int delayed, unsigned int niov,
                  struct iovec *iov, lnet_kiov_t *kiov,
                  unsigned int offset, unsigned int mlen, unsigned int rlen);
void kibnal_init_msg(kib_msg_t *msg, int type, int body_nob);
void kibnal_pack_msg(kib_msg_t *msg, __u32 version, int credits, 
                     lnet_nid_t dstnid, __u64 dststamp, __u64 seq);
void kibnal_pack_connmsg(kib_msg_t *msg, __u32 version, int nob, int type,
                         lnet_nid_t dstnid, __u64 dststamp);
int  kibnal_unpack_msg(kib_msg_t *msg, __u32 expected_version, int nob);
IB_HANDLE kibnal_create_cep(lnet_nid_t nid);
int  kibnal_create_peer (kib_peer_t **peerp, lnet_nid_t nid);
void kibnal_destroy_peer (kib_peer_t *peer);
kib_peer_t *kibnal_find_peer_locked (lnet_nid_t nid);
int  kibnal_del_peer (lnet_nid_t nid);
void kibnal_peer_alive (kib_peer_t *peer);
void kibnal_unlink_peer_locked (kib_peer_t *peer);
int  kibnal_add_persistent_peer (lnet_nid_t nid);
int  kibnal_close_stale_conns_locked (kib_peer_t *peer,
                                      __u64 incarnation);
int  kibnal_conn_rts(kib_conn_t *conn,
                     __u32 qpn, __u8 resp_res, __u8 init_depth, __u32 psn);
kib_conn_t *kibnal_create_conn (lnet_nid_t nid, int proto_version);
void kibnal_destroy_conn (kib_conn_t *conn);
void kibnal_listen_callback(IB_HANDLE cep, CM_CONN_INFO *info, void *arg);
int  kibnal_alloc_pages (kib_pages_t **pp, int npages);
void kibnal_free_pages (kib_pages_t *p);
void kibnal_queue_tx (kib_tx_t *tx, kib_conn_t *conn);
void kibnal_txlist_done (struct list_head *txlist, int status);
int  kibnal_post_receives (kib_conn_t *conn);
int  kibnal_init_rdma (kib_tx_t *tx, int type, int nob,
                       kib_rdma_desc_t *dstrd, __u64 dstcookie);
void kibnal_check_sends (kib_conn_t *conn);
void kibnal_close_conn_locked (kib_conn_t *conn, int error);
int  kibnal_thread_start (int (*fn)(void *arg), void *arg);
int  kibnal_scheduler(void *arg);
int  kibnal_connd (void *arg);
void kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob);
void kibnal_close_conn (kib_conn_t *conn, int why);
void kibnal_start_active_rdma (int type, int status,
                               kib_rx_t *rx, lnet_msg_t *lntmsg,
                               unsigned int niov,
                               struct iovec *iov, lnet_kiov_t *kiov,
                               unsigned int offset, unsigned int nob);
void kibnal_hca_async_callback (void *hca_arg, IB_EVENT_RECORD *ev);
void kibnal_hca_callback (void *hca_arg, void *cq_arg);
int  kibnal_tunables_init (void);
void kibnal_tunables_fini (void);
