/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *   Author: Frank Zago <fzago@systemfabricworks.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <linux/config.h>
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

#define DEBUG_SUBSYSTEM S_IBNAL

#define IBNAL_CHECK_ADVERT

#include <libcfs/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>
#include <portals/nal.h>

#include <vverbs.h>
#include <sa-mads.h>
#include <ib-cm.h>
#include <gsi.h>

#if 0
#undef CDEBUG
#define CDEBUG(mask, format, a...) printk(KERN_INFO "%s:%d - " format, __func__, __LINE__,##a)
#endif

#ifdef __CHECKER__
#undef CDEBUG
#undef CERROR
#define CDEBUG(a...)
#define CERROR(a...)
#endif

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

#define IBNAL_SERVICE_NAME   "vibnal"
#define IBNAL_SERVICE_NUMBER 0x11b9a2 /* TODO */

#if CONFIG_SMP
# define IBNAL_N_SCHED      num_online_cpus()   /* # schedulers */
#else
# define IBNAL_N_SCHED      1                   /* # schedulers */
#endif

#define IBNAL_MIN_RECONNECT_INTERVAL HZ         /* first failed connection retry... */
#define IBNAL_MAX_RECONNECT_INTERVAL (60*HZ)    /* ...exponentially increasing to this */

#define IBNAL_MSG_SIZE       (4<<10)            /* max size of queued messages (inc hdr) */

#define IBNAL_MSG_QUEUE_SIZE   8                /* # messages/RDMAs in-flight */
#define IBNAL_CREDIT_HIGHWATER 7                /* when to eagerly return credits */

/* 7 indicates infinite retry attempts, Infinicon recommended 5 */
#define IBNAL_RETRY            5                /* # times to retry */
#define IBNAL_RNR_RETRY        5                /*  */
#define IBNAL_CM_RETRY         5                /* # times to retry connection */

#define IBNAL_FLOW_CONTROL     1
#define IBNAL_ACK_TIMEOUT       20              /* supposedly 4 secs */

#define IBNAL_NTX             64                /* # tx descs */
/* this had to be dropped down so that we only register < 255 pages per
 * region.  this will change if we register all memory. */
#define IBNAL_NTX_NBLK        128               /* # reserved tx descs */

#define IBNAL_PEER_HASH_SIZE  101               /* # peer lists */

#define IBNAL_RESCHED         100               /* # scheduler loops before reschedule */

#define IBNAL_CONCURRENT_PEERS 1000             /* # nodes all talking at once to me */

/* default vals for runtime tunables */
#define IBNAL_IO_TIMEOUT      50                /* default comms timeout (seconds) */

/************************/
/* derived constants... */

/* TX messages (shared by all connections) */
#define IBNAL_TX_MSGS       (IBNAL_NTX + IBNAL_NTX_NBLK)
#define IBNAL_TX_MSG_BYTES  (IBNAL_TX_MSGS * IBNAL_MSG_SIZE)
#define IBNAL_TX_MSG_PAGES  ((IBNAL_TX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)

#define IBNAL_TX_MAX_SG (PTL_MD_MAX_IOV + 1)

/* RX messages (per connection) */
#define IBNAL_RX_MSGS       IBNAL_MSG_QUEUE_SIZE
#define IBNAL_RX_MSG_BYTES  (IBNAL_RX_MSGS * IBNAL_MSG_SIZE)
#define IBNAL_RX_MSG_PAGES  ((IBNAL_RX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)


/* we may have up to 2 completions per transmit +
   1 completion per receive, per connection */
#define IBNAL_CQ_ENTRIES  ((2*IBNAL_TX_MSGS) +                          \
                           (IBNAL_RX_MSGS * IBNAL_CONCURRENT_PEERS))

#define IBNAL_RDMA_BASE  0x0eeb0000
#define IBNAL_FMR        0
#define IBNAL_WHOLE_MEM  1
#define IBNAL_CKSUM      0

/* Starting sequence number. */
#define IBNAL_STARTING_PSN 0x465A

/* Timeout for SA requests, in seconds */
#define GSI_TIMEOUT 5
#define GSI_RETRY 10

typedef struct
{
        int               kib_io_timeout;       /* comms timeout (seconds) */
        struct ctl_table_header *kib_sysctl;    /* sysctl interface */
} kib_tunables_t;

/* some of these have specific types in the stack that just map back
 * to the uFOO types, like IB_{L,R}_KEY. */
typedef struct
{
        int               ibp_npages;           /* # pages */
        int               ibp_mapped;           /* mapped? */
        __u64             ibp_vaddr;            /* mapped region vaddr */
        __u32             ibp_lkey;             /* mapped region lkey */
        __u32             ibp_rkey;             /* mapped region rkey */
        vv_mem_reg_h_t    ibp_handle;           /* mapped region handle */
        struct page      *ibp_pages[0];
} kib_pages_t;

typedef struct
{
        vv_mem_reg_h_t    md_handle;
        __u32             md_lkey;
        __u32             md_rkey;
        __u64             md_addr;
} kib_md_t __attribute__((packed));

typedef struct
{
        /* initialisation state. These values are sorted by their initialization order. */
        enum {
                IBNAL_INIT_NOTHING,
                IBNAL_INIT_DATA,
                IBNAL_INIT_LIB,
                IBNAL_INIT_HCA,
                IBNAL_INIT_ASYNC,
                IBNAL_INIT_PORT,
                IBNAL_INIT_GSI_POOL,
                IBNAL_INIT_GSI,
                IBNAL_INIT_PD,
#if IBNAL_FMR
                IBNAL_INIT_FMR,
#endif
                IBNAL_INIT_TXD,
                IBNAL_INIT_CQ,
                IBNAL_INIT_ALL,
        } kib_init;

        __u64             kib_incarnation;      /* which one am I */
        int               kib_shutdown;         /* shut down? */
        atomic_t          kib_nthreads;         /* # live threads */

        __u64             kib_service_id;       /* service number I listen on */
        vv_gid_t          kib_port_gid;         /* port GID in HOST ORDER! */
        vv_p_key_t        kib_port_pkey;        /* my pkey */
        ptl_nid_t         kib_nid;              /* my NID */
        struct semaphore  kib_nid_mutex;        /* serialise NID ops */
        cm_cep_handle_t   kib_cep;              /* connection end point */

        rwlock_t          kib_global_lock;      /* stabilize peer/conn ops */

        struct list_head *kib_peers;            /* hash table of all my known peers */
        int               kib_peer_hash_size;   /* size of kib_peers */
        atomic_t          kib_npeers;           /* # peers extant */
        atomic_t          kib_nconns;           /* # connections extant */

        struct list_head  kib_connd_conns;      /* connections to progress */
        struct list_head  kib_connd_peers;      /* peers waiting for a connection */
        wait_queue_head_t kib_connd_waitq;      /* connection daemons sleep here */
        unsigned long     kib_connd_waketime;   /* when connd will wake */
        spinlock_t        kib_connd_lock;       /* serialise */

        wait_queue_head_t kib_sched_waitq;      /* schedulers sleep here */
        struct list_head  kib_sched_txq;        /* tx requiring attention */
        struct list_head  kib_sched_rxq;        /* rx requiring attention */
        spinlock_t        kib_sched_lock;       /* serialise */

        struct kib_tx    *kib_tx_descs;         /* all the tx descriptors */
        kib_pages_t      *kib_tx_pages;         /* premapped tx msg pages */

        struct list_head  kib_idle_txs;         /* idle tx descriptors */
        struct list_head  kib_idle_nblk_txs;    /* idle reserved tx descriptors */
        wait_queue_head_t kib_idle_tx_waitq;    /* block here for tx descriptor */
        __u64             kib_next_tx_cookie;   /* RDMA completion cookie */
        spinlock_t        kib_tx_lock;          /* serialise */

        vv_hca_h_t        kib_hca;              /* The HCA */
        vv_hca_attrib_t   kib_hca_attrs;      /* HCA attributes */

        int               kib_port;             /* port on the device */
        vv_port_attrib_t  kib_port_attr;      /* port attributes */

        vv_pd_h_t         kib_pd;               /* protection domain */
        vv_cq_h_t         kib_cq;               /* completion queue */

        void             *kib_listen_handle;    /* where I listen for connections */

        /* These fields are left untouched, so they can be shared. */
        union {
                cm_drequest_data_t dreq_data;
                cm_dreply_data_t   drep_data;
        } cm_data;

        /* Send and receive MADs (service records, path records) */
        gsi_class_handle_t      gsi_handle;
        gsi_dtgrm_pool_handle_t gsi_pool_handle;
        struct semaphore gsi_mutex; /* protect GSI list - TODO:spinlock instead? */
        struct list_head gsi_pending; /* pending GSI datagrams */

} kib_data_t;

/************************************************************************
 * Wire message structs.
 * These are sent in sender's byte order (i.e. receiver flips).
 * CAVEAT EMPTOR: other structs communicated between nodes (e.g. MAD
 * private data and SM service info), is LE on the wire.
 */

/* also kib_md_t above */

typedef struct
{
        __u32                 rd_nob;           /* # of bytes */
        __u64                 rd_addr;          /* remote io vaddr */
} kib_rdma_desc_t __attribute__((packed));

typedef struct
{
        ptl_hdr_t         ibim_hdr;             /* portals header */
        char              ibim_payload[0];      /* piggy-backed payload */
} kib_immediate_msg_t __attribute__((packed));

/* these arrays serve two purposes during rdma.  they are built on the passive
 * side and sent to the active side as remote arguments.  On the active side
 * the descs are used as a data structure on the way to local gather items.
 * the different roles result in split local/remote meaning of desc->rd_key */
typedef struct
{
        ptl_hdr_t         ibrm_hdr;             /* portals header */
        __u64             ibrm_cookie;          /* opaque completion cookie */
        __u32             ibrm_num_descs;       /* how many descs */
        __u32             rd_key;               /* remote key */
        kib_rdma_desc_t   ibrm_desc[0];         /* where to suck/blow */
} kib_rdma_msg_t __attribute__((packed));

#define kib_rdma_msg_len(num_descs) \
        offsetof(kib_msg_t, ibm_u.rdma.ibrm_desc[num_descs])

typedef struct
{
        __u64             ibcm_cookie;          /* opaque completion cookie */
        __u32             ibcm_status;          /* completion status */
} kib_completion_msg_t __attribute__((packed));

typedef struct
{
        __u32              ibm_magic;           /* I'm an openibnal message */
        __u16              ibm_version;         /* this is my version number */
        __u8               ibm_type;            /* msg type */
        __u8               ibm_credits;         /* returned credits */
#if IBNAL_CKSUM
        __u32              ibm_nob;
        __u32              ibm_cksum;
#endif
        union {
                kib_immediate_msg_t   immediate;
                kib_rdma_msg_t        rdma;
                kib_completion_msg_t  completion;
        } ibm_u __attribute__((packed));
} kib_msg_t __attribute__((packed));

#define IBNAL_MSG_MAGIC       0x0be91b91        /* unique magic */
#define IBNAL_MSG_VERSION              1        /* current protocol version */

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
        int                       rx_rdma;      /* RDMA completion posted? */
        int                       rx_posted;    /* posted? */
        kib_msg_t                *rx_msg;     /* pre-mapped buffer */
        vv_l_key_t                l_key;
        vv_wr_t                   rx_wrq;
        vv_scatgat_t              rx_gl;        /* and its memory */
} kib_rx_t;

typedef struct kib_tx                           /* transmit message */
{
        struct list_head          tx_list;      /* queue on idle_txs ibc_tx_queue etc. */
        int                       tx_isnblk;    /* I'm reserved for non-blocking sends */
        struct kib_conn          *tx_conn;      /* owning conn */
        int                       tx_mapped;    /* mapped for RDMA? */
        int                       tx_sending;   /* # tx callbacks outstanding */
        int                       tx_status;    /* completion status */
        unsigned long             tx_deadline;  /* completion deadline */
        int                       tx_passive_rdma; /* peer sucks/blows */
        int                       tx_passive_rdma_wait; /* waiting for peer to complete */
        __u64                     tx_passive_rdma_cookie; /* completion cookie */
        lib_msg_t                *tx_libmsg[2]; /* lib msgs to finalize on completion */
        kib_md_t                  tx_md;        /* RDMA mapping (active/passive) */
        kib_msg_t                *tx_msg;       /* pre-mapped buffer */
        vv_l_key_t                l_key;
        vv_r_key_t                r_key;
        int                       tx_nsp;       /* # send work items */
        vv_wr_t                  tx_wrq[IBNAL_TX_MAX_SG];    /* send work items... */
        vv_scatgat_t              tx_gl[IBNAL_TX_MAX_SG];     /* ...and their memory */
} kib_tx_t;

#define KIB_TX_UNMAPPED       0
#define KIB_TX_MAPPED         1
#define KIB_TX_MAPPED_FMR     2

typedef struct kib_wire_connreq
{
        __u32        wcr_magic;                 /* I'm an openibnal connreq */
        __u16        wcr_version;               /* this is my version number */
        __u16        wcr_queue_depth;           /* this is my receive queue size */
        __u64        wcr_nid;                   /* peer's NID */
        __u64        wcr_incarnation;           /* peer's incarnation */
} kib_wire_connreq_t;

typedef struct kib_gid
{
        __u64   hi, lo;
} kib_gid_t;

typedef struct kib_connreq
{
        /* connection-in-progress */
        struct kib_conn                    *cr_conn;
        kib_wire_connreq_t                  cr_wcr;
        __u64                               cr_tid;
        //ib_service_record_v2_t              cr_service;
        kib_gid_t                           cr_gid;
        ib_path_record_v2_t                 cr_path;

        union {
                cm_request_data_t                   cr_cm_req;
                cm_rtu_data_t                       cr_cm_rtu;
        } ;

} kib_connreq_t;

typedef struct kib_conn
{
        struct kib_peer    *ibc_peer;           /* owning peer */
        struct list_head    ibc_list;           /* stash on peer's conn list */
        __u64               ibc_incarnation;    /* which instance of the peer */
        atomic_t            ibc_refcount;       /* # users */
        int                 ibc_state;          /* what's happening */
        atomic_t            ibc_nob;            /* # bytes buffered */
        int                 ibc_nsends_posted;  /* # uncompleted sends */
        int                 ibc_credits;        /* # credits I have */
        int                 ibc_outstanding_credits; /* # credits to return */
        int                 ibc_rcvd_disconnect;/* received discon request */
        int                 ibc_sent_disconnect;/* sent discon request */
        struct list_head    ibc_tx_queue;       /* send queue */
        struct list_head    ibc_active_txs;     /* active tx awaiting completion */
        spinlock_t          ibc_lock;           /* serialise */
        kib_rx_t           *ibc_rxs;            /* the rx descs */
        kib_pages_t        *ibc_rx_pages;       /* premapped rx msg pages */
        vv_qp_h_t           ibc_qp;             /* queue pair */
        cm_cep_handle_t     ibc_cep;            /* connection ID? */
        vv_qp_attr_t        ibc_qp_attrs;    /* QP attrs */
        kib_connreq_t      *ibc_connreq;        /* connection request state */
} kib_conn_t;

#define IBNAL_CONN_INIT_NOTHING      0          /* initial state */
#define IBNAL_CONN_INIT_QP           1          /* ibc_qp set up */
#define IBNAL_CONN_CONNECTING        2          /* started to connect */
#define IBNAL_CONN_ESTABLISHED       3          /* connection established */
#define IBNAL_CONN_SEND_DREQ         4          /* to send disconnect req */
#define IBNAL_CONN_DREQ              5          /* sent disconnect req */
#define IBNAL_CONN_DREP              6          /* sent disconnect rep */
#define IBNAL_CONN_DISCONNECTED      7          /* no more QP or CM traffic */

#define KIB_ASSERT_CONN_STATE(conn, state) do {                         \
        LASSERTF((conn)->ibc_state == state, "%d\n", conn->ibc_state);  \
} while (0)

#define KIB_ASSERT_CONN_STATE_RANGE(conn, low, high) do {               \
        LASSERTF(low <= high, "%d %d\n", low, high);                    \
        LASSERTF((conn)->ibc_state >= low && (conn)->ibc_state <= high, \
                 "%d\n", conn->ibc_state);                              \
} while (0)

typedef struct kib_peer
{
        struct list_head    ibp_list;           /* stash on global peer list */
        struct list_head    ibp_connd_list;     /* schedule on kib_connd_peers */
        ptl_nid_t           ibp_nid;            /* who's on the other end(s) */
        atomic_t            ibp_refcount;       /* # users */
        int                 ibp_persistence;    /* "known" peer refs */
        struct list_head    ibp_conns;          /* all active connections */
        struct list_head    ibp_tx_queue;       /* msgs waiting for a conn */
        int                 ibp_connecting;     /* connecting+accepting */
        unsigned long       ibp_reconnect_time; /* when reconnect may be attempted */
        unsigned long       ibp_reconnect_interval; /* exponential backoff */
} kib_peer_t;

struct sa_request;
typedef void (*sa_request_cb_t)(struct sa_request *request);

struct sa_request {
        /* Link all the pending GSI datagrams together. */
        struct list_head list;

        int retry;              /* number of retries left (after a timeout only) */
        int status;             /* status of the request */
        gsi_dtgrm_t *dtgrm_req; /* request */
        gsi_dtgrm_t *dtgrm_resp; /* response */
        sa_mad_v2_t *mad;       /* points inside the datagram */

        void *context;

        struct timer_list timer;

        /* When the requests is completed, we either call the callback
         * or post a completion. They are mutually exclusive. */
        struct completion signal;
        sa_request_cb_t callback;
};

/* The CM callback are called on the interrupt level. However we
 * cannot do everything we want on that level, so we let keventd run
 * the callback. */
struct cm_off_level {
        struct tq_struct tq;

        cm_cep_handle_t cep;
        cm_conn_data_t *info;
        kib_conn_t *conn;
};

extern lib_nal_t       kibnal_lib;
extern kib_data_t      kibnal_data;
extern kib_tunables_t  kibnal_tunables;

static inline int wrq_signals_completion(vv_wr_t *wrq)
{
        return wrq->completion_notification != 0;
}

/******************************************************************************/

/* these are purposely avoiding using local vars so they don't increase
 * stack consumption. */

#define kib_peer_addref(peer) do {                                      \
        LASSERTF(atomic_read(&peer->ibp_refcount) > 0, "%d\n",          \
                 atomic_read(&peer->ibp_refcount));                     \
        CDEBUG(D_NET, "++peer[%p] -> "LPX64" (%d)\n",                   \
               peer, peer->ibp_nid, atomic_read (&peer->ibp_refcount)); \
        atomic_inc(&peer->ibp_refcount);                                \
} while (0)

#define kib_peer_decref(peer) do {                                      \
        LASSERTF(atomic_read(&peer->ibp_refcount) > 0, "%d\n",          \
                 atomic_read(&peer->ibp_refcount));                     \
        CDEBUG(D_NET, "--peer[%p] -> "LPX64" (%d)\n",                   \
               peer, peer->ibp_nid, atomic_read (&peer->ibp_refcount)); \
        if (atomic_dec_and_test (&peer->ibp_refcount)) {                \
                CDEBUG (D_NET, "destroying peer "LPX64" %p\n",          \
                        peer->ibp_nid, peer);                           \
                kibnal_destroy_peer (peer);                             \
        }                                                               \
} while (0)

/******************************************************************************/

static inline struct list_head *
kibnal_nid2peerlist (ptl_nid_t nid)
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
        /* CAVEAT EMPTOR: tx takes caller's ref on conn */

        LASSERT (tx->tx_nsp > 0);               /* work items set up */
        LASSERT (tx->tx_conn == NULL);          /* only set here */

        tx->tx_conn = conn;
        tx->tx_deadline = jiffies + kibnal_tunables.kib_io_timeout * HZ;
        list_add_tail(&tx->tx_list, &conn->ibc_tx_queue);
}

static inline __u64*
kibnal_service_nid_field(ib_service_record_v2_t *sr)
{
        /* The service key mask must have byte 0 to 7 set. */
        return (__u64 *)sr->service_data8;
}

static inline void
kibnal_set_service_keys(ib_service_record_v2_t *sr, ptl_nid_t nid)
{
        LASSERT (strlen(IBNAL_SERVICE_NAME) < sizeof(sr->service_name));

        strcpy (sr->service_name, IBNAL_SERVICE_NAME);

        *kibnal_service_nid_field(sr) = cpu_to_le64(nid);
}

#if CONFIG_X86
/* TODO: use vv_va2adverize instead */
static inline __u64
kibnal_page2phys (struct page *p)
{
        __u64 page_number = p - mem_map;

        return (page_number << PAGE_SHIFT);
}
#else
# error "no page->phys"
#endif

/* CAVEAT EMPTOR: We rely on tx/rx descriptor alignment to allow us to
 * use the lowest bit of the work request id as a flag to determine if
 * the completion is for a transmit or a receive (the op field is not
 * valid when the wc completes in error). */

static inline vv_wr_id_t
kibnal_ptr2wreqid (void *ptr, int isrx)
{
        unsigned long lptr = (unsigned long)ptr;

        LASSERT ((lptr & 1) == 0);
        return (vv_wr_id_t)(lptr | (isrx ? 1 : 0));
}

static inline void *
kibnal_wreqid2ptr (vv_wr_id_t wreqid)
{
        return (void *)(((unsigned long)wreqid) & ~1UL);
}

static inline int
kibnal_wreqid_is_rx (vv_wr_id_t wreqid)
{
        return (wreqid & 1) != 0;
}

static inline int
kibnal_whole_mem(void)
{
#if IBNAL_WHOLE_MEM
        return true;
#else
        return false;
#endif
}

/* Voltaire stores GIDs in host order. */
static inline void gid_swap(vv_gid_t *gid)
{
        u_int64_t s;

        s = gid->scope.g.subnet;
        gid->scope.g.subnet = cpu_to_be64(gid->scope.g.eui64);
        gid->scope.g.eui64 = cpu_to_be64(s);
}

#if 0
static void dump_qp(kib_conn_t *conn)
{
        vv_qp_attr_t *qp_attrs;
        void *qp_context;
        vv_return_t retval;

        CERROR("QP dumping %p\n", conn);

        retval = vv_qp_query(kibnal_data.kib_hca, conn->ibc_qp, &qp_context, &conn->ibc_qp_attrs);
        if (retval) {
                CERROR ("Couldn't query qp attributes: %d\n", retval);
                return;
        }

        qp_attrs = &conn->ibc_qp_attrs;

        CERROR("QP %x dump\n", qp_attrs->query.qp_num);
        CERROR("  vv_qp_attr_mask = %llx\n", qp_attrs->query.vv_qp_attr_mask);
        CERROR("  qp_state = %d\n", qp_attrs->query.qp_state);
        CERROR("  cq_send_h = %p\n", qp_attrs->query.cq_send_h);
        CERROR("  cq_receive_h = %p \n", qp_attrs->query.cq_receive_h);
        CERROR("  send_max_outstand_wr = %d\n", qp_attrs->query.send_max_outstand_wr);
        CERROR("  receive_max_outstand_wr = %d\n", qp_attrs->query.receive_max_outstand_wr);
        CERROR("  max_scatgat_per_send_wr = %d\n", qp_attrs->query.max_scatgat_per_send_wr);
        CERROR("  max_scatgat_per_receive_wr = %d\n", qp_attrs->query.max_scatgat_per_receive_wr);
        CERROR("  send_psn = %x\n", qp_attrs->query.send_psn);
        CERROR("  receve_psn = %x\n", qp_attrs->query.receve_psn);
        CERROR("  access_control = %x\n", qp_attrs->query.access_control);
        CERROR("  phy_port_num = %d\n", qp_attrs->query.phy_port_num);
        CERROR("  primary_p_key_indx = %x\n", qp_attrs->query.primary_p_key_indx);
        CERROR("  q_key = %x\n", qp_attrs->query.q_key);
        CERROR("  destanation_qp = %x\n", qp_attrs->query.destanation_qp);
        CERROR("  rdma_r_atom_outstand_num = %d\n", qp_attrs->query.rdma_r_atom_outstand_num);
        CERROR("  responder_rdma_r_atom_num = %d\n", qp_attrs->query.responder_rdma_r_atom_num);
        CERROR("  min_rnr_nak_timer = %d\n", qp_attrs->query.min_rnr_nak_timer);
        CERROR("  pd_h = %lx\n", qp_attrs->query.pd_h);
        CERROR("  recv_solicited_events = %d\n", qp_attrs->query.recv_solicited_events);
        CERROR("  send_signaled_comp = %d\n", qp_attrs->query.send_signaled_comp);
        CERROR("  flow_control = %d\n", qp_attrs->query.flow_control);
}
#else
#define dump_qp(a)
#endif

#if 0
static void dump_wqe(vv_wr_t *wr)
{
        CERROR("Dumping send WR %p\n", wr);

        CERROR("  wr_id = %llx\n", wr->wr_id);
        CERROR("  completion_notification = %d\n", wr->completion_notification);
        CERROR("  scatgat_list = %p\n", wr->scatgat_list);
        CERROR("  num_of_data_segments = %d\n", wr->num_of_data_segments);

        if (wr->scatgat_list && wr->num_of_data_segments) {
                CERROR("    scatgat_list[0].v_address = %p\n", wr->scatgat_list[0].v_address);
                CERROR("    scatgat_list[0].length = %d\n", wr->scatgat_list[0].length);
                CERROR("    scatgat_list[0].l_key = %x\n", wr->scatgat_list[0].l_key);
        }

        CERROR("  wr_type = %d\n", wr->wr_type);

        switch(wr->wr_type) {
        case vv_wr_send:
                CERROR("  send\n");

                CERROR("  fance_indicator = %d\n", wr->type.send.send_qp_type.rc_type.fance_indicator);
                break;

        case vv_wr_receive:
                break;

        case vv_wr_rdma_write:
        case vv_wr_rdma_read:
                CERROR("  rdma\n");
                CERROR("  fance_indicator = %d\n", wr->type.send.send_qp_type.rc_type.fance_indicator);
                CERROR("  r_addr = %llx\n", wr->type.send.send_qp_type.rc_type.r_addr);
                CERROR("  r_r_key = %x\n", wr->type.send.send_qp_type.rc_type.r_r_key);
                break;

        default:
                break;
        }
}

#else
#define dump_wqe(a)
#endif

#if 0
static void dump_wc(vv_wc_t *wc)
{
        CERROR("Dumping WC\n");

        CERROR("  wr_id = %llx\n", wc->wr_id);
        CERROR("  operation_type = %d\n", wc->operation_type);
        CERROR("  num_bytes_transfered = %lld\n", wc->num_bytes_transfered);
        CERROR("  completion_status = %d\n", wc->completion_status);
}
#else
#define dump_wc(a)
#endif

#if 0
static void hexdump(char *string, void *ptr, int len)
{
        unsigned char *c = ptr;
        int i;

        if (len < 0 || len > 2048)  {
                printk("XXX what the hell? %d\n",len);
                return;
        }

        printk("%d bytes of '%s' from 0x%p\n", len, string, ptr);

        for (i = 0; i < len;) {
                printk("%02x",*(c++));
                i++;
                if (!(i & 15)) {
                        printk("\n");
                } else if (!(i&1)) {
                        printk(" ");
                }
        }

        if(len & 15) {
                printk("\n");
        }
}
#else
#define hexdump(a,b,c)
#endif

/*--------------------------------------------------------------------------*/


extern kib_peer_t *kibnal_create_peer (ptl_nid_t nid);
extern void kibnal_destroy_peer (kib_peer_t *peer);
extern int kibnal_del_peer (ptl_nid_t nid, int single_share);
extern kib_peer_t *kibnal_find_peer_locked (ptl_nid_t nid);
extern void kibnal_unlink_peer_locked (kib_peer_t *peer);
extern int  kibnal_close_stale_conns_locked (kib_peer_t *peer,
                                              __u64 incarnation);
extern kib_conn_t *kibnal_create_conn (void);
extern void kibnal_put_conn (kib_conn_t *conn);
extern void kibnal_destroy_conn (kib_conn_t *conn);
extern void kibnal_listen_callback(cm_cep_handle_t cep, cm_conn_data_t *info, void *arg);

extern int kibnal_alloc_pages (kib_pages_t **pp, int npages, int access);
extern void kibnal_free_pages (kib_pages_t *p);

extern void kibnal_check_sends (kib_conn_t *conn);
extern void kibnal_close_conn_locked (kib_conn_t *conn, int error);
extern void kibnal_destroy_conn (kib_conn_t *conn);
extern int  kibnal_thread_start (int (*fn)(void *arg), void *arg);
extern int  kibnal_scheduler(void *arg);
extern int  kibnal_connd (void *arg);
extern void kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob);
extern void kibnal_close_conn (kib_conn_t *conn, int why);
extern void kibnal_start_active_rdma (int type, int status,
                                      kib_rx_t *rx, lib_msg_t *libmsg,
                                      unsigned int niov,
                                      struct iovec *iov, ptl_kiov_t *kiov,
                                      size_t offset, size_t nob);

void kibnal_ca_async_callback(vv_event_record_t ev);
void kibnal_ca_callback (unsigned long context);
extern void vibnal_mad_received_cb(gsi_class_handle_t handle, void *context, gsi_dtgrm_t * dtgrm);
extern void vibnal_mad_sent_cb(gsi_class_handle_t handle, void *context, gsi_dtgrm_t * dtgrm);
extern int kibnal_advertize_op(ptl_nid_t nid, int op, sa_request_cb_t callback, void *context);
extern int vibnal_start_sa_request(struct sa_request *request);
extern struct sa_request *alloc_sa_request(void);
extern void free_sa_request(struct sa_request *request);
extern int kibnal_pathrecord_op(struct sa_request *request, vv_gid_t dgid, sa_request_cb_t callback, void *context);
