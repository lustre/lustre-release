/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
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

#define DEBUG_SUBSYSTEM S_NAL

#include <libcfs/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>
#include <portals/nal.h>

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

#define IBNAL_SERVICE_NAME   "iibnal"
#define IBNAL_SERVICE_NUMBER 0x11b9a1

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
//#define IBNAL_CALLBACK_CTXT  IB_CQ_CALLBACK_PROCESS
#define IBNAL_CALLBACK_CTXT  IB_CQ_CALLBACK_INTERRUPT

/* XXX I have no idea. */
#define IBNAL_STARTING_PSN 1

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
        IB_HANDLE         ibp_handle;           /* mapped region handle */
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

        __u64             kib_service_id;       /* service number I listen on */
        __u64             kib_port_guid;        /* my GUID (lo 64 of GID)*/
        __u16             kib_port_pkey;        /* my pkey, whatever that is */
        ptl_nid_t         kib_nid;              /* my NID */
        struct semaphore  kib_nid_mutex;        /* serialise NID ops */
        struct semaphore  kib_nid_signal;       /* signal completion */
        IB_HANDLE         kib_cep;              /* connection end point */

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

        IB_HANDLE         kib_hca;              /* The HCA */
        int               kib_port;             /* port on the device */
        IB_HANDLE         kib_pd;               /* protection domain */
        IB_HANDLE         kib_sd;               /* SD handle */
        IB_HANDLE         kib_cq;               /* completion queue */
        kib_md_t          kib_md;               /* full-mem registration */

        void             *kib_listen_handle;    /* where I listen for connections */

        IBT_INTERFACE_UNION kib_interfaces;     /* The Infinicon IBT interface */

        uint64              kib_hca_guids[8];   /* all the HCA guids */
        IB_CA_ATTRIBUTES    kib_hca_attrs;      /* where to get HCA attrs */
        FABRIC_OPERATION_DATA kib_fabopdata;    /* (un)advertise service record */
} kib_data_t;

#define IBNAL_INIT_NOTHING         0
#define IBNAL_INIT_DATA            1
#define IBNAL_INIT_LIB             2
#define IBNAL_INIT_HCA             3
#define IBNAL_INIT_PORTATTRS       4
#define IBNAL_INIT_PORT            5
#define IBNAL_INIT_SD              6
#define IBNAL_INIT_PD              7
#define IBNAL_INIT_FMR             8
#define IBNAL_INIT_MR              9
#define IBNAL_INIT_TXD             10
#define IBNAL_INIT_CQ              11
#define IBNAL_INIT_ALL             12

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
} WIRE_ATTR kib_rdma_desc_t;

typedef struct
{
        ptl_hdr_t         ibim_hdr;             /* portals header */
        char              ibim_payload[0];      /* piggy-backed payload */
} WIRE_ATTR kib_immediate_msg_t;

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
} WIRE_ATTR kib_rdma_msg_t;

#define kib_rdma_msg_len(num_descs) \
        offsetof(kib_msg_t, ibm_u.rdma.ibrm_desc[num_descs])

typedef struct
{
        __u64             ibcm_cookie;          /* opaque completion cookie */
        __u32             ibcm_status;          /* completion status */
} WIRE_ATTR kib_completion_msg_t;

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
        } WIRE_ATTR ibm_u;
} WIRE_ATTR kib_msg_t;

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
        __u64                     rx_vaddr;     /* pre-mapped buffer (hca vaddr) */
        kib_msg_t                *rx_msg;       /* pre-mapped buffer (host vaddr) */
        IB_WORK_REQ               rx_wrq;
        IB_LOCAL_DATASEGMENT      rx_gl;        /* and its memory */
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
        __u64                     tx_vaddr;     /* pre-mapped buffer (hca vaddr) */
        kib_msg_t                *tx_msg;       /* pre-mapped buffer (host vaddr) */
        int                       tx_nsp;       /* # send work items */
        IB_WORK_REQ               tx_wrq[IBNAL_TX_MAX_SG];    /* send work items... */
        IB_LOCAL_DATASEGMENT      tx_gl[IBNAL_TX_MAX_SG];     /* ...and their memory */
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
        IB_SERVICE_RECORD                   cr_service;
        kib_gid_t                           cr_gid;
        IB_PATH_RECORD                      cr_path;
        CM_REQUEST_INFO                     cr_cmreq;
        CM_CONN_INFO                        cr_discarded;
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
        IB_HANDLE           ibc_qp;             /* queue pair */
        IB_HANDLE           ibc_cep;            /* connection ID? */
        IB_QP_ATTRIBUTES_QUERY ibc_qp_attrs;    /* QP attrs */
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


extern lib_nal_t       kibnal_lib;
extern kib_data_t      kibnal_data;
extern kib_tunables_t  kibnal_tunables;

/******************************************************************************/
/* Infinicon IBT interface wrappers */
#define IIBT_IF (kibnal_data.kib_interfaces.ver2)

static inline FSTATUS
iibt_get_hca_guids(uint32 *hca_count, EUI64 *hca_guid_list)
{
        return IIBT_IF.GetCaGuids(hca_count, hca_guid_list);
}

static inline FSTATUS
iibt_open_hca(EUI64                    hca_guid,
             IB_COMPLETION_CALLBACK   completion_callback,
             IB_ASYNC_EVENT_CALLBACK  async_event_callback,
             void                    *arg,
             IB_HANDLE               *handle)
{
        return IIBT_IF.Vpi.OpenCA(hca_guid, completion_callback,
                                  async_event_callback, arg, handle);
}

static inline FSTATUS
iibt_query_hca(IB_HANDLE hca_handle, IB_CA_ATTRIBUTES *attrs, void **argp)
{
        return IIBT_IF.Vpi.QueryCA(hca_handle, attrs, argp);
}

static inline FSTATUS
iibt_close_hca(IB_HANDLE hca_handle)
{
        return IIBT_IF.Vpi.CloseCA(hca_handle);
}

static inline FSTATUS
iibt_pd_allocate(IB_HANDLE hca_handle, __u32 max_avs, IB_HANDLE *pd_handle)
{
        return IIBT_IF.Vpi.AllocatePD(hca_handle, max_avs, pd_handle);
}

static inline FSTATUS
iibt_pd_free(IB_HANDLE pd_handle)
{
        return IIBT_IF.Vpi.FreePD(pd_handle);
}

static inline FSTATUS
iibt_register_physical_memory(IB_HANDLE hca_handle,
                              IB_VIRT_ADDR requested_io_va,
                              void *phys_buffers, uint64 nphys_buffers,
                              uint32 io_va_offset, IB_HANDLE pd_handle,
                              IB_ACCESS_CONTROL access,
                              IB_HANDLE *mem_handle,
                              IB_VIRT_ADDR *actual_io_va,
                              IB_L_KEY *lkey, IB_R_KEY *rkey)
{
        return IIBT_IF.Vpi.RegisterPhysMemRegion(hca_handle, requested_io_va,
                                                 phys_buffers, nphys_buffers,
                                                 io_va_offset, pd_handle,
                                                 access,
                                                 mem_handle, actual_io_va,
                                                 lkey, rkey);
}

static inline FSTATUS
iibt_register_contig_physical_memory(IB_HANDLE hca_handle,
                                     IB_VIRT_ADDR requested_io_va,
                                     IB_MR_PHYS_BUFFER *phys_buffers,
                                     uint64 nphys_buffers,
                                     uint32 io_va_offset, IB_HANDLE pd_handle,
                                     IB_ACCESS_CONTROL access,
                                     IB_HANDLE *mem_handle,
                                     IB_VIRT_ADDR *actual_io_va,
                                     IB_L_KEY *lkey, IB_R_KEY *rkey)
{
        return IIBT_IF.Vpi.RegisterContigPhysMemRegion(hca_handle,
                                                       requested_io_va,
                                                       phys_buffers,
                                                       nphys_buffers,
                                                       io_va_offset, pd_handle,
                                                       access,
                                                       mem_handle, actual_io_va,
                                                       lkey, rkey);
}

static inline FSTATUS
iibt_register_memory(IB_HANDLE hca_handle,
                     void *virt_addr, unsigned int length,
                     IB_HANDLE pd_handle,
                     IB_ACCESS_CONTROL access,
                     IB_HANDLE *mem_handle,
                     IB_L_KEY *lkey, IB_R_KEY *rkey)
{
        return IIBT_IF.Vpi.RegisterMemRegion(hca_handle,
                                             virt_addr, length,
                                             pd_handle,
                                             access,
                                             mem_handle,
                                             lkey, rkey);
}

static inline FSTATUS
iibt_deregister_memory(IB_HANDLE mem_handle)
{
        return IIBT_IF.Vpi.DeregisterMemRegion(mem_handle);
}

static inline FSTATUS
iibt_cq_create(IB_HANDLE hca_handle, uint32 requested_size,
              void *arg, IB_HANDLE *cq_handle, uint32 *actual_size)
{
        return IIBT_IF.Vpi.CreateCQ(hca_handle, requested_size,
                                   arg, cq_handle, actual_size);
}

static inline FSTATUS
iibt_cq_poll(IB_HANDLE cq_handle, IB_WORK_COMPLETION *wc)
{
        return IIBT_IF.Vpi.PollCQ(cq_handle, wc);
}

static inline FSTATUS
iibt_cq_rearm(IB_HANDLE cq_handle, IB_CQ_EVENT_SELECT select)
{
        return IIBT_IF.Vpi.RearmCQ(cq_handle, select);
}

static inline FSTATUS
iibt_cq_destroy(IB_HANDLE cq_handle)
{
        return IIBT_IF.Vpi.DestroyCQ(cq_handle);
}

static inline FSTATUS
iibt_qp_create(IB_HANDLE hca_handle, IB_QP_ATTRIBUTES_CREATE *create_attr,
              void *arg, IB_HANDLE *cq_handle,
              IB_QP_ATTRIBUTES_QUERY *query_attr)
{
        return IIBT_IF.Vpi.CreateQP(hca_handle, create_attr, arg, cq_handle,
                                    query_attr);
}

static inline FSTATUS
iibt_qp_query(IB_HANDLE qp_handle, IB_QP_ATTRIBUTES_QUERY *query_attr,
              void **arg_ptr)
{
        return IIBT_IF.Vpi.QueryQP(qp_handle, query_attr, arg_ptr);
}

static inline FSTATUS
iibt_qp_modify(IB_HANDLE qp_handle, IB_QP_ATTRIBUTES_MODIFY *modify_attr,
               IB_QP_ATTRIBUTES_QUERY *query_attr)
{
        return IIBT_IF.Vpi.ModifyQP(qp_handle, modify_attr, query_attr);
}

static inline FSTATUS
iibt_qp_destroy(IB_HANDLE qp_handle)
{
        return IIBT_IF.Vpi.DestroyQP(qp_handle);
}

static inline FSTATUS
iibt_postrecv(IB_HANDLE qp_handle, IB_WORK_REQ *work_req)
{
        return IIBT_IF.Vpi.PostRecv(qp_handle, work_req);
}

static inline FSTATUS
iibt_postsend(IB_HANDLE qp_handle, IB_WORK_REQ *work_req)
{
        return IIBT_IF.Vpi.PostSend(qp_handle, work_req);
}

static inline FSTATUS
iibt_sd_register(IB_HANDLE *sd_handle, CLIENT_CONTROL_PARAMETERS *p)
{
        return IIBT_IF.Sdi.Register(sd_handle, p);
}

static inline FSTATUS
iibt_sd_deregister(IB_HANDLE sd_handle)
{
        return IIBT_IF.Sdi.Deregister(sd_handle);
}

static inline FSTATUS
iibt_sd_port_fabric_operation(IB_HANDLE sd_handle, EUI64 port_guid,
                              FABRIC_OPERATION_DATA *fod,
                              PFABRIC_OPERATION_CALLBACK callback,
                              COMMAND_CONTROL_PARAMETERS *p, void *arg)
{
        return IIBT_IF.Sdi.PortFabricOperation(sd_handle, port_guid,
                                               fod, callback, p, arg);
}

static inline FSTATUS
iibt_sd_query_port_fabric_information(IB_HANDLE sd_handle, EUI64 port_guid,
                                      QUERY *qry,
                                      PQUERY_CALLBACK callback,
                                      COMMAND_CONTROL_PARAMETERS *p, void *arg)
{
        return IIBT_IF.Sdi.QueryPortFabricInformation(sd_handle, port_guid,
                                                      qry, callback, p, arg);
}

static inline IB_HANDLE
iibt_cm_create_cep(CM_CEP_TYPE type)
{
        return IIBT_IF.Cmi.CmCreateCEP(type);
}

static inline FSTATUS
iibt_cm_modify_cep(IB_HANDLE cep, uint32 attr, char* value, uint32 len,
                   uint32 offset)
{
        return IIBT_IF.Cmi.CmModifyCEP(cep, attr, value, len, offset);
}

static inline FSTATUS
iibt_cm_destroy_cep(IB_HANDLE cep_handle)
{
        return IIBT_IF.Cmi.CmDestroyCEP(cep_handle);
}

static inline FSTATUS
iibt_cm_listen(IB_HANDLE cep, CM_LISTEN_INFO *info,
               PFN_CM_CALLBACK callback, void *arg)
{
        return IIBT_IF.Cmi.CmListen(cep, info, callback, arg);
}

static inline FSTATUS
iibt_cm_cancel(IB_HANDLE cep)
{
        return IIBT_IF.Cmi.CmCancel(cep);
}

static inline FSTATUS
iibt_cm_accept(IB_HANDLE cep,
               CM_CONN_INFO *send_info, CM_CONN_INFO *recv_info,
               PFN_CM_CALLBACK callback, void *arg,
               IB_HANDLE *new_cep)
{
        return IIBT_IF.Cmi.CmAccept(cep,
                                    send_info, recv_info,
                                    callback, arg, new_cep);
}

static inline FSTATUS
iibt_cm_reject(IB_HANDLE cep, CM_REJECT_INFO *rej)
{
        return IIBT_IF.Cmi.CmReject(cep, rej);
}

static inline FSTATUS
iibt_cm_disconnect(IB_HANDLE cep, CM_DREQUEST_INFO *req,
                   CM_DREPLY_INFO *reply)
{
        return IIBT_IF.Cmi.CmDisconnect(cep, req, reply);
}

static inline FSTATUS
iibt_cm_connect (IB_HANDLE cep, CM_REQUEST_INFO *req,
                 PFN_CM_CALLBACK callback, void *arg)
{
        return IIBT_IF.Cmi.CmConnect (cep, req, callback, arg);
}

static inline int wrq_signals_completion(IB_WORK_REQ *wrq)
{
        return wrq->Req.SendRC.Options.s.SignaledCompletion == 1;
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
kibnal_set_service_keys(IB_SERVICE_RECORD *srv, ptl_nid_t nid)
{
        LASSERT (strlen(IBNAL_SERVICE_NAME) < sizeof(srv->ServiceName));
        memset (srv->ServiceName, 0, sizeof(srv->ServiceName));
        strcpy (srv->ServiceName, IBNAL_SERVICE_NAME);

        *kibnal_service_nid_field(srv) = cpu_to_le64(nid);
}

#if 0
static inline void
kibnal_show_rdma_attr (kib_conn_t *conn)
{
        struct ib_qp_attribute qp_attr;
        int                    rc;

        memset (&qp_attr, 0, sizeof(qp_attr));
        rc = ib_qp_query(conn->ibc_qp, &qp_attr);
        if (rc != 0) {
                CERROR ("Can't get qp attrs: %d\n", rc);
                return;
        }

        CWARN ("RDMA CAPABILITY: write %s read %s\n",
               (qp_attr.valid_fields & TS_IB_QP_ATTRIBUTE_RDMA_ATOMIC_ENABLE) ?
               (qp_attr.enable_rdma_write ? "enabled" : "disabled") : "invalid",
               (qp_attr.valid_fields & TS_IB_QP_ATTRIBUTE_RDMA_ATOMIC_ENABLE) ?
               (qp_attr.enable_rdma_read ? "enabled" : "disabled") : "invalid");
}
#endif

#if CONFIG_X86
static inline __u64
kibnal_page2phys (struct page *p)
{
        __u64 page_number = p - mem_map;

        return (page_number << PAGE_SHIFT);
}
#else
# error "no page->phys"
#endif

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

static inline int
kibnal_whole_mem(void)
{
        return kibnal_data.kib_md.md_handle != NULL;
}

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
void kibnal_listen_callback(IB_HANDLE cep, CM_CONN_INFO *info, void *arg);

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

void kibnal_ca_async_callback (void *ca_arg, IB_EVENT_RECORD *ev);
void kibnal_ca_callback (void *ca_arg, void *cq_arg);
