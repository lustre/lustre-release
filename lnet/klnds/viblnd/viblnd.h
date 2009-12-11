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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/viblnd/viblnd.h
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Frank Zago <fzago@systemfabricworks.com>
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
#include <linux/random.h>

#include <net/sock.h>
#include <linux/in.h>

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/kp30.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>
#include <lnet/lnet-sysctl.h>

/* CPU_{L,B}E #defines needed by Voltaire headers */
#include <asm/byteorder.h>
#ifdef __BIG_ENDIAN__
#define CPU_BE 1
#define CPU_LE 0
#endif
#ifdef __LITTLE_ENDIAN__
#define CPU_BE 0
#define CPU_LE 1
#endif

#include <vverbs.h>
#include <ib-cm.h>
#include <ibat.h>

/* GCC 3.2.2, miscompiles this driver.  
 * See http://gcc.gnu.org/bugzilla/show_bug.cgi?id=9853. */
#define GCC_VERSION ((__GNUC__*100 + __GNUC_MINOR__)*100 + __GNUC_PATCHLEVEL__)
#if (GCC_VERSION >= 30000) && (GCC_VERSION < 30203)
# error Invalid GCC version. Must use GCC < 3.0.0 || GCC >= 3.2.3
#endif

#ifdef CONFIG_SMP
# define IBNAL_N_SCHED      num_online_cpus()   /* # schedulers */
#else
# define IBNAL_N_SCHED      1                   /* # schedulers */
#endif

#define IBNAL_USE_FMR  1

/* tunables fixed at compile time */
#define IBNAL_PEER_HASH_SIZE         101        /* # peer lists */
#define IBNAL_RESCHED                100        /* # scheduler loops before reschedule */
#define IBNAL_MSG_QUEUE_SIZE         8          /* # messages/RDMAs in-flight */
#define IBNAL_CREDIT_HIGHWATER       7          /* when eagerly to return credits */
#define IBNAL_MSG_SIZE              (4<<10)     /* max size of queued messages (inc hdr) */

/* constants derived from sdp-connection.c */
#define IBNAL_QKEY               0
#define IBNAL_PKEY               0xffff
#define IBNAL_PKEY_IDX           0
#define IBNAL_SGID_IDX           0
#define IBNAL_SERVICE_LEVEL      0
#define IBNAL_STATIC_RATE        0
#define IBNAL_EE_FLOW_CNT        1
#define IBNAL_LOCAL_SUB          1
#define IBNAL_TRAFFIC_CLASS      0
#define IBNAL_SOURCE_PATH_BIT    0
#define IBNAL_OUS_DST_RD         1
#define IBNAL_IB_MTU             vv_mtu_1024

/* constants derived from sdp-hca-params.h */
#define PATH_RATE_2_5GB           2
#define MLX_IPD_1x                1
#define MLX_IPD_4x                0
#define IBNAL_R_2_STATIC_RATE(r)  ((r) == PATH_RATE_2_5GB ? MLX_IPD_1x : MLX_IPD_4x)

/* other low-level IB constants */
#define IBNAL_PKT_LIFETIME        5
#define IBNAL_ARB_INITIATOR_DEPTH 0
#define IBNAL_ARB_RESP_RES        0
#define IBNAL_FAILOVER_ACCEPTED   0

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
#define IBNAL_RX_MSGS         (IBNAL_MSG_QUEUE_SIZE*2)
#define IBNAL_RX_MSG_BYTES    (IBNAL_RX_MSGS * IBNAL_MSG_SIZE)
#define IBNAL_RX_MSG_PAGES    ((IBNAL_RX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)

#define IBNAL_CQ_ENTRIES()    (IBNAL_TX_MSGS() * (1 + IBNAL_MAX_RDMA_FRAGS) +           \
                               IBNAL_RX_MSGS * *kibnal_tunables.kib_concurrent_peers)

typedef struct
{
        unsigned int     *kib_service_number;   /* IB service number */
        int              *kib_min_reconnect_interval; /* first failed connection retry... */
        int              *kib_max_reconnect_interval; /* ...exponentially increasing to this */
        int              *kib_concurrent_peers; /* max # nodes all talking to me */
        int              *kib_cksum;            /* checksum kib_msg_t? */
        int              *kib_timeout;          /* comms timeout (seconds) */
        int              *kib_ntx;              /* # tx descs */
        int              *kib_credits;          /* # concurrent sends */
        int              *kib_peercredits;      /* # concurrent sends to 1 peer */
        int              *kib_arp_retries;      /* # times to retry ARP */
        char            **kib_hca_basename;     /* HCA base name */
        char            **kib_ipif_basename;    /* IPoIB interface base name */
        int              *kib_local_ack_timeout; /* IB RC QP ack timeout... */
        int              *kib_retry_cnt;        /* ...and retry */
        int              *kib_rnr_cnt;          /* RNR retries... */
        int              *kib_rnr_nak_timer;    /* ...and interval */
        int              *kib_keepalive;        /* keepalive interval */
        int              *kib_concurrent_sends; /* send work queue sizing */
#if IBNAL_USE_FMR
        int              *kib_fmr_remaps;       /* # FMR maps before unmap required */
#endif
#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
        cfs_sysctl_table_header_t *kib_sysctl;  /* sysctl interface */
#endif
} kib_tunables_t;

typedef struct
{
        int               ibp_npages;           /* # pages */
        struct page      *ibp_pages[0];
} kib_pages_t;

#if IBNAL_USE_FMR
typedef struct
{
        vv_fmr_h_t        md_fmrhandle;         /* FMR handle */
        int               md_fmrcount;          /* # mappings left */
        int               md_active;            /* mapping in use? */
        __u32             md_lkey;              /* local key */
        __u32             md_rkey;              /* remote key */
        __u64             md_addr;              /* IO VM address */
} kib_md_t;
#endif

typedef struct
{
        int               kib_init;             /* initialisation state */
        __u64             kib_incarnation;      /* which one am I */
        int               kib_shutdown;         /* shut down? */
        atomic_t          kib_nthreads;         /* # live threads */
        lnet_ni_t        *kib_ni;               /* _the_ nal instance */

        vv_gid_t          kib_port_gid;         /* device/port GID */
        vv_p_key_t        kib_port_pkey;        /* device/port pkey */
        
        cm_cep_handle_t   kib_listen_handle;    /* IB listen handle */

        rwlock_t          kib_global_lock;      /* stabilize peer/conn ops */
        int               kib_ready;            /* CQ callback fired */
        int               kib_checking_cq;      /* a scheduler is checking the CQ */
        
        struct list_head *kib_peers;            /* hash table of all my known peers */
        int               kib_peer_hash_size;   /* size of kib_peers */
        atomic_t          kib_npeers;           /* # peers extant */
        atomic_t          kib_nconns;           /* # connections extant */

        void             *kib_connd;            /* the connd task (serialisation assertions) */
        struct list_head  kib_connd_peers;      /* peers wanting to get connected */
        struct list_head  kib_connd_pcreqs;     /* passive connection requests */
        struct list_head  kib_connd_conns;      /* connections to setup/teardown */
        struct list_head  kib_connd_zombies;    /* connections with zero refcount */
        wait_queue_head_t kib_connd_waitq;      /* connection daemon sleeps here */
        spinlock_t        kib_connd_lock;       /* serialise */

        wait_queue_head_t kib_sched_waitq;      /* schedulers sleep here */
        spinlock_t        kib_sched_lock;       /* serialise */

        struct kib_tx    *kib_tx_descs;         /* all the tx descriptors */
        kib_pages_t      *kib_tx_pages;         /* premapped tx msg pages */

        struct list_head  kib_idle_txs;         /* idle tx descriptors */
        __u64             kib_next_tx_cookie;   /* RDMA completion cookie */
        spinlock_t        kib_tx_lock;          /* serialise */

        vv_hca_h_t        kib_hca;              /* The HCA */
        vv_hca_attrib_t   kib_hca_attrs;        /* its properties */
        int               kib_port;             /* port on the device */
        vv_port_attrib_t  kib_port_attr;        /* its properties */

        vv_pd_h_t         kib_pd;               /* protection domain */
        vv_cq_h_t         kib_cq;               /* completion queue */

} kib_data_t;

#define IBNAL_INIT_NOTHING         0
#define IBNAL_INIT_DATA            1
#define IBNAL_INIT_LIB             2
#define IBNAL_INIT_HCA             3
#define IBNAL_INIT_ASYNC           4
#define IBNAL_INIT_PD              5
#define IBNAL_INIT_TXD             6
#define IBNAL_INIT_CQ              7
#define IBNAL_INIT_ALL             8

#include "viblnd_wire.h"

/***********************************************************************/

typedef struct kib_rx                           /* receive message */
{
        struct list_head          rx_list;      /* queue for attention */
        struct kib_conn          *rx_conn;      /* owning conn */
        int                       rx_nob;       /* # bytes received (-1 while posted) */
        vv_l_key_t                rx_lkey;      /* local key */
        kib_msg_t                *rx_msg;       /* pre-mapped buffer (host vaddr) */
        vv_wr_t                   rx_wrq;       /* receive work item */
        vv_scatgat_t              rx_gl;        /* and its memory */
} kib_rx_t;

typedef struct kib_tx                           /* transmit message */
{
        struct list_head          tx_list;      /* queue on idle_txs ibc_tx_queue etc. */
        struct kib_conn          *tx_conn;      /* owning conn */
        int                       tx_sending;   /* # tx callbacks outstanding */
        int                       tx_queued;    /* queued for sending */
        int                       tx_waiting;   /* waiting for peer */
        int                       tx_status;    /* completion status */
        unsigned long             tx_deadline;  /* completion deadline */
        __u64                     tx_cookie;    /* completion cookie */
        lnet_msg_t               *tx_lntmsg[2]; /* lnet msgs to finalize on completion */
        vv_l_key_t                tx_lkey;      /* local key for message buffer */
        kib_msg_t                *tx_msg;       /* message buffer (host vaddr) */
        int                       tx_nwrq;      /* # send work items */
#if IBNAL_USE_FMR
        vv_wr_t                   tx_wrq[2];    /* send work items... */
        vv_scatgat_t              tx_gl[2];     /* ...and their memory */
        kib_rdma_desc_t           tx_rd[1];     /* rdma descriptor */
        kib_md_t                  tx_md;        /* FMR mapping descriptor */
        __u64                    *tx_pages;     /* page phys addrs */
#else
        vv_wr_t                  *tx_wrq;       /* send work items... */
        vv_scatgat_t             *tx_gl;        /* ...and their memory */
        kib_rdma_desc_t          *tx_rd;        /* rdma descriptor (src buffers) */
#endif
} kib_tx_t;

/* Passive connection request (listener callback) queued for handling by connd */
typedef struct kib_pcreq
{
        struct list_head  pcr_list;             /* queue for handling by connd */
        cm_cep_handle_t   pcr_cep;              /* listening handle */
        cm_request_data_t pcr_cmreq;            /* request data */
} kib_pcreq_t;

typedef struct kib_connvars
{
        /* connection-in-progress variables */
        __u32               cv_port;
        __u32               cv_pkey_index;
        __u32               cv_rnr_count;
        __u32               cv_sgid_index;
        __u32               cv_remote_qpn;
        __u32               cv_local_qpn;
        __u32               cv_rxpsn;
        __u32               cv_txpsn;
        ib_path_record_v2_t cv_path;
        ibat_arp_data_t     cv_arp;
        ibat_stat_t         cv_arprc;
        cm_conn_data_t      cv_conndata;
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
        int                 ibc_disconnect;     /* some disconnect callback fired */
        int                 ibc_comms_error;    /* set on comms error */
        unsigned long       ibc_last_send;      /* time of last send */
        struct list_head    ibc_early_rxs;      /* rxs completed before ESTABLISHED */
        struct list_head    ibc_tx_queue_nocred; /* sends that don't need a cred */
        struct list_head    ibc_tx_queue_rsrvd; /* sends that need a reserved cred */
        struct list_head    ibc_tx_queue;       /* send queue */
        struct list_head    ibc_active_txs;     /* active tx awaiting completion */
        spinlock_t          ibc_lock;           /* serialise */
        kib_rx_t           *ibc_rxs;            /* the rx descs */
        kib_pages_t        *ibc_rx_pages;       /* premapped rx msg pages */
        vv_qp_h_t           ibc_qp;             /* queue pair */
        cm_cep_handle_t     ibc_cep;            /* connection endpoint */
        kib_connvars_t     *ibc_connvars;       /* in-progress connection state */
} kib_conn_t;

#define IBNAL_CONN_INIT_NOTHING       0         /* incomplete init */
#define IBNAL_CONN_INIT_QP            1         /* QP allocated */
#define IBNAL_CONN_INIT               2         /* completed init */
#define IBNAL_CONN_ACTIVE_ARP         3         /* active arping */
#define IBNAL_CONN_ACTIVE_CONNECT     4         /* active sending req */
#define IBNAL_CONN_ACTIVE_CHECK_REPLY 5         /* active checking reply */
#define IBNAL_CONN_ACTIVE_RTU         6         /* active sending rtu */
#define IBNAL_CONN_PASSIVE_WAIT       7         /* passive waiting for rtu */
#define IBNAL_CONN_ESTABLISHED        8         /* connection established */
#define IBNAL_CONN_DISCONNECT1        9         /* disconnect phase 1 */
#define IBNAL_CONN_DISCONNECT2        10        /* disconnect phase 2 */
#define IBNAL_CONN_DISCONNECTED       11        /* disconnect complete */

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
        int                 ibp_arp_count;      /* # arp attempts */
        unsigned long       ibp_reconnect_time; /* when reconnect may be attempted */
        unsigned long       ibp_reconnect_interval; /* exponential backoff */
        int                 ibp_error;          /* errno on closing this peer */
        cfs_time_t          ibp_last_alive;     /* when (in jiffies) I was last alive */
} kib_peer_t;


extern kib_data_t      kibnal_data;
extern kib_tunables_t  kibnal_tunables;

int kibnal_startup (lnet_ni_t *ni);
void kibnal_shutdown (lnet_ni_t *ni);
int kibnal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int kibnal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
extern int kibnal_eager_recv (lnet_ni_t *ni, void *private,
                              lnet_msg_t *lntmsg, void **new_private);
int kibnal_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, 
                int delayed, unsigned int niov, 
                struct iovec *iov, lnet_kiov_t *kiov,
                unsigned int offset, unsigned int mlen, unsigned int rlen);
extern void kibnal_init_msg(kib_msg_t *msg, int type, int body_nob);
extern void kibnal_pack_msg(kib_msg_t *msg, __u32 version, int credits,
                            lnet_nid_t dstnid, __u64 dststamp, __u64 seq);
extern int  kibnal_unpack_msg(kib_msg_t *msg, __u32 expected_version, int nob);
extern int  kibnal_create_peer(kib_peer_t **peerp, lnet_nid_t nid);
extern void kibnal_destroy_peer(kib_peer_t *peer);
extern int  kibnal_add_persistent_peer (lnet_nid_t nid, __u32 ip);
extern int  kibnal_del_peer(lnet_nid_t nid);
extern kib_peer_t *kibnal_find_peer_locked(lnet_nid_t nid);
extern void kibnal_unlink_peer_locked(kib_peer_t *peer);
extern void kibnal_peer_alive(kib_peer_t *peer);
extern int  kibnal_close_stale_conns_locked(kib_peer_t *peer,
                                            __u64 incarnation);
extern kib_conn_t *kibnal_create_conn(cm_cep_handle_t cep);
extern void kibnal_listen_callback(cm_cep_handle_t cep, cm_conn_data_t *info, void *arg);

extern int  kibnal_alloc_pages(kib_pages_t **pp, int npages, int access);
extern void kibnal_free_pages(kib_pages_t *p);

extern void kibnal_check_sends(kib_conn_t *conn);
extern void kibnal_close_conn_locked(kib_conn_t *conn, int error);
extern void kibnal_destroy_conn(kib_conn_t *conn);
extern int  kibnal_thread_start(int (*fn)(void *arg), void *arg);
extern int  kibnal_scheduler(void *arg);
extern int  kibnal_connd(void *arg);
extern void kibnal_init_tx_msg(kib_tx_t *tx, int type, int body_nob);
extern void kibnal_close_conn(kib_conn_t *conn, int why);
extern int  kibnal_set_qp_state(kib_conn_t *conn, vv_qp_state_t new_state);
extern void kibnal_async_callback(vv_event_record_t ev);
extern void kibnal_cq_callback(unsigned long context);
extern void kibnal_passive_connreq(kib_pcreq_t *pcr, int reject);
extern void kibnal_txlist_done (struct list_head *txlist, int status);
extern void kibnal_queue_tx(kib_tx_t *tx, kib_conn_t *conn);
extern int  kibnal_init_rdma(kib_tx_t *tx, int type, int nob,
                             kib_rdma_desc_t *dstrd, __u64 dstcookie);
extern int  kibnal_tunables_init(void);
extern void kibnal_tunables_fini(void);

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

static inline struct list_head *
kibnal_nid2peerlist (lnet_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) % kibnal_data.kib_peer_hash_size;

        return (&kibnal_data.kib_peers [hash]);
}

static inline int
kibnal_peer_active (kib_peer_t *peer)
{
        /* Am I in the peer hash table? */
        return (!list_empty(&peer->ibp_list));
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

#ifndef IBNAL_VOIDSTAR_SGADDR
# define IBNAL_VOIDSTAR_SGADDR 0
#endif

#if IBNAL_VOIDSTAR_SGADDR
# if defined(CONFIG_HIGHMEM)
#  if defined(CONFIG_X86) && defined(CONFIG_HIGHMEM4G)
   /* truncation to void* doesn't matter if 0 <= physmem < 4G
    * so allow x86 with 32 bit phys addrs */
#  elif defined(CONFIG_IA64)
   /* OK anyway on 64-bit arch */
#  else
#   error "Can't support HIGHMEM when vv_scatgat_t::v_address is void *"
#  endif
# endif
# define KIBNAL_ADDR2SG(a)       ((void *)((unsigned long)(a)))
# define KIBNAL_SG2ADDR(a)       ((__u64)((unsigned long)(a)))
static inline __u64 kibnal_addr2net (__u64 addr)
{
        void        *netaddr;
        vv_return_t  vvrc = vv_va2advertise_addr(kibnal_data.kib_hca, 
                                                 KIBNAL_ADDR2SG(addr),
                                                 &netaddr);
        LASSERT (vvrc == vv_return_ok);
        return KIBNAL_SG2ADDR(netaddr);
}
#else
# define KIBNAL_ADDR2SG(a)       a
# define KIBNAL_SG2ADDR(a)       a
static inline __u64 kibnal_addr2net (__u64 addr)
{
        __u64        netaddr;
        vv_return_t  vvrc = vv_va2advertise_addr(kibnal_data.kib_hca, 
                                                 addr,
                                                 &netaddr);
        LASSERT (vvrc == vv_return_ok);
        return netaddr;
}
#endif

/* CAVEAT EMPTOR: We rely on tx/rx descriptor alignment to allow us to use the
 * lowest 2 bits of the work request id to stash the work item type (the op
 * field is not valid when the wc completes in error). */

#define IBNAL_WID_TX    0
#define IBNAL_WID_RX    1
#define IBNAL_WID_RDMA  2
#define IBNAL_WID_MASK  3UL

static inline vv_wr_id_t
kibnal_ptr2wreqid (void *ptr, int type)
{
        unsigned long lptr = (unsigned long)ptr;

        LASSERT ((lptr & IBNAL_WID_MASK) == 0);
        LASSERT ((type & ~IBNAL_WID_MASK) == 0);
        return (vv_wr_id_t)(lptr | type);
}

static inline void *
kibnal_wreqid2ptr (vv_wr_id_t wreqid)
{
        return (void *)(((unsigned long)wreqid) & ~IBNAL_WID_MASK);
}

static inline int
kibnal_wreqid2type (vv_wr_id_t wreqid)
{
        return (wreqid & IBNAL_WID_MASK);
}

static inline void
kibnal_set_conn_state (kib_conn_t *conn, int state)
{
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
static inline __u64
kibnal_rf_addr (kib_rdma_frag_t *rf)
{
        return  (((__u64)rf->rf_addr_hi)<<32) | ((__u64)rf->rf_addr_lo);
}

static inline void
kibnal_rf_set (kib_rdma_frag_t *rf, __u64 addr, int nob)
{
        rf->rf_addr_lo = addr & 0xffffffff;
        rf->rf_addr_hi = (addr >> 32) & 0xffffffff;
        rf->rf_nob = nob;
}

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
