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

#define DEBUG_SUBSYSTEM S_OPENIBNAL

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>
#include <portals/nal.h>

#include <ts_ib_core.h>
#include <ts_ib_cm.h>
#include <ts_ib_sa_client.h>

#define OPENIBNAL_SERVICE_NAME   "openibnal"

#if CONFIG_SMP
# define OPENIBNAL_N_SCHED      num_online_cpus() /* # schedulers */
#else
# define OPENIBNAL_N_SCHED      1                 /* # schedulers */
#endif

#define OPENIBNAL_MIN_RECONNECT_INTERVAL HZ       /* first failed connection retry... */
#define OPENIBNAL_MAX_RECONNECT_INTERVAL (60*HZ)  /* ...exponentially increasing to this */

#define OPENIBNAL_MSG_SIZE       (4<<10)          /* max size of queued messages (inc hdr) */

#define OPENIBNAL_MSG_QUEUE_SIZE   8              /* # messages in-flight */
#define OPENIBNAL_CREDIT_HIGHWATER 6              /* when to eagerly return credits */
#define OPENIBNAL_RETRY            7              /* # times to retry */
#define OPENIBNAL_RNR_RETRY        7              /*  */
#define OPENIBNAL_CM_RETRY         7              /* # times to retry connection */
#define OPENIBNAL_FLOW_CONTROL     1
#define OPENIBNAL_RESPONDER_RESOURCES 8

#define OPENIBNAL_NTX             64              /* # tx descs */
#define OPENIBNAL_NTX_NBLK        256             /* # reserved tx descs */

#define OPENIBNAL_PEER_HASH_SIZE  101             /* # peer lists */

#define OPENIBNAL_RESCHED         100             /* # scheduler loops before reschedule */

#define OPENIBNAL_CONCURRENT_PEERS 1000           /* # nodes all talking at once to me */

/* default vals for runtime tunables */
#define OPENIBNAL_IO_TIMEOUT      50              /* default comms timeout (seconds) */

/************************/
/* derived constants... */

/* TX messages (shared by all connections) */
#define OPENIBNAL_TX_MSGS       (OPENIBNAL_NTX + OPENIBNAL_NTX_NBLK)
#define OPENIBNAL_TX_MSG_BYTES  (OPENIBNAL_TX_MSGS * OPENIBNAL_MSG_SIZE)
#define OPENIBNAL_TX_MSG_PAGES  ((OPENIBNAL_TX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)

/* we may have up to 2 completions per transmit */
#define OPENIBNAL_TX_CQ_ENTRIES  (2*OPENIBNAL_TX_MSGS)

/* RX messages (per connection) */
#define OPENIBNAL_RX_MSGS       OPENIBNAL_MSG_QUEUE_SIZE
#define OPENIBNAL_RX_MSG_BYTES  (OPENIBNAL_RX_MSGS * OPENIBNAL_MSG_SIZE)
#define OPENIBNAL_RX_MSG_PAGES  ((OPENIBNAL_RX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)

/* 1 completion per receive, per connection */
#define OPENIBNAL_RX_CQ_ENTRIES (OPENIBNAL_RX_MSGS * OPENIBNAL_CONCURRENT_PEERS)

#define OPENIBNAL_RDMA_BASE  0x0eeb0000
#define OPENIBNAL_FMR        1
#define OPENIBNAL_CKSUM      0
//#define OPENIBNAL_CALLBACK_CTXT  IB_CQ_CALLBACK_PROCESS
#define OPENIBNAL_CALLBACK_CTXT  IB_CQ_CALLBACK_INTERRUPT

typedef struct 
{
        int               koib_io_timeout;      /* comms timeout (seconds) */
        struct ctl_table_header *koib_sysctl;   /* sysctl interface */
} koib_tunables_t;

typedef struct
{
        int               oibp_npages;          /* # pages */
        int               oibp_mapped;          /* mapped? */
        __u64             oibp_vaddr;           /* mapped region vaddr */
        __u32             oibp_lkey;            /* mapped region lkey */
        __u32             oibp_rkey;            /* mapped region rkey */
        struct ib_mr     *oibp_handle;          /* mapped region handle */
        struct page      *oibp_pages[0];
} koib_pages_t;
        
typedef struct 
{
        int               koib_init;            /* initialisation state */
        __u64             koib_incarnation;     /* which one am I */
        int               koib_shutdown;        /* shut down? */
        atomic_t          koib_nthreads;        /* # live threads */

        __u64             koib_cm_service_id;   /* service number I listen on */
        ptl_nid_t         koib_nid;             /* my NID */
        struct semaphore  koib_nid_mutex;       /* serialise NID ops */
        struct semaphore  koib_nid_signal;      /* signal completion */

        rwlock_t          koib_global_lock;     /* stabilize peer/conn ops */

        struct list_head *koib_peers;           /* hash table of all my known peers */
        int               koib_peer_hash_size;  /* size of koib_peers */
        atomic_t          koib_npeers;          /* # peers extant */
        atomic_t          koib_nconns;          /* # connections extant */

        struct list_head  koib_connd_conns;     /* connections to progress */
        struct list_head  koib_connd_peers;     /* peers waiting for a connection */
        wait_queue_head_t koib_connd_waitq;     /* connection daemons sleep here */
        unsigned long     koib_connd_waketime;  /* when connd will wake */
        spinlock_t        koib_connd_lock;      /* serialise */

        wait_queue_head_t koib_sched_waitq;     /* schedulers sleep here */
        struct list_head  koib_sched_txq;       /* tx requiring attention */
        struct list_head  koib_sched_rxq;       /* rx requiring attention */
        spinlock_t        koib_sched_lock;      /* serialise */
        
        struct koib_tx   *koib_tx_descs;        /* all the tx descriptors */
        koib_pages_t     *koib_tx_pages;        /* premapped tx msg pages */

        struct list_head  koib_idle_txs;        /* idle tx descriptors */
        struct list_head  koib_idle_nblk_txs;   /* idle reserved tx descriptors */
        wait_queue_head_t koib_idle_tx_waitq;   /* block here for tx descriptor */
        __u64             koib_next_tx_cookie;  /* RDMA completion cookie */
        spinlock_t        koib_tx_lock;         /* serialise */
        
        struct ib_device *koib_device;          /* "the" device */
        struct ib_device_properties koib_device_props; /* its properties */
        int               koib_port;            /* port on the device */
        struct ib_port_properties koib_port_props; /* its properties */
        struct ib_pd     *koib_pd;              /* protection domain */
#if OPENIBNAL_FMR
        struct ib_fmr_pool *koib_fmr_pool;      /* fast memory region pool */
#endif
        struct ib_cq     *koib_rx_cq;           /* receive completion queue */
        struct ib_cq     *koib_tx_cq;           /* transmit completion queue */
        void             *koib_listen_handle;   /* where I listen for connections */
        struct ib_common_attrib_service koib_service; /* SM service */
        
} koib_data_t;

#define OPENIBNAL_INIT_NOTHING         0
#define OPENIBNAL_INIT_DATA            1
#define OPENIBNAL_INIT_LIB             2
#define OPENIBNAL_INIT_PD              3
#define OPENIBNAL_INIT_FMR             4
#define OPENIBNAL_INIT_TXD             5
#define OPENIBNAL_INIT_RX_CQ           6
#define OPENIBNAL_INIT_TX_CQ           7
#define OPENIBNAL_INIT_ALL             8

/************************************************************************
 * Wire message structs.
 * These are sent in sender's byte order (i.e. receiver flips).
 * CAVEAT EMPTOR: other structs communicated between nodes (e.g. MAD
 * private data and SM service info), is LE on the wire.
 */

typedef struct
{
        union {
                struct ib_mr    *mr;
                struct ib_fmr   *fmr;
        }                 md_handle;
        __u32             md_lkey;
        __u32             md_rkey;
        __u64             md_addr;
} koib_md_t;

typedef struct
{
        __u32                 rd_key;           /* remote key */
        __u32                 rd_nob;           /* # of bytes */
        __u64                 rd_addr;          /* remote io vaddr */
} koib_rdma_desc_t;


typedef struct
{
        ptl_hdr_t         oibim_hdr;            /* portals header */
        char              oibim_payload[0];     /* piggy-backed payload */
} koib_immediate_msg_t;

typedef struct
{
        ptl_hdr_t         oibrm_hdr;            /* portals header */
        __u64             oibrm_cookie;         /* opaque completion cookie */
        koib_rdma_desc_t  oibrm_desc;           /* where to suck/blow */
} koib_rdma_msg_t;

typedef struct
{
        __u64             oibcm_cookie;         /* opaque completion cookie */
        __u32             oibcm_status;         /* completion status */
} koib_completion_msg_t;

typedef struct
{
        __u32              oibm_magic;          /* I'm an openibnal message */
        __u16              oibm_version;        /* this is my version number */
        __u8               oibm_type;           /* msg type */
        __u8               oibm_credits;        /* returned credits */
#if OPENIBNAL_CKSUM
        __u32              oibm_nob;
        __u32              oibm_cksum;
#endif
        union {
                koib_immediate_msg_t   immediate;
                koib_rdma_msg_t        rdma;
                koib_completion_msg_t  completion;
        }                    oibm_u;
} koib_msg_t;

#define OPENIBNAL_MSG_MAGIC       0x0be91b91    /* unique magic */
#define OPENIBNAL_MSG_VERSION              1    /* current protocol version */

#define OPENIBNAL_MSG_NOOP              0xd0    /* nothing (just credits) */
#define OPENIBNAL_MSG_IMMEDIATE         0xd1    /* portals hdr + payload */
#define OPENIBNAL_MSG_PUT_RDMA          0xd2    /* portals PUT hdr + source rdma desc */
#define OPENIBNAL_MSG_PUT_DONE          0xd3    /* signal PUT rdma completion */
#define OPENIBNAL_MSG_GET_RDMA          0xd4    /* portals GET hdr + sink rdma desc */
#define OPENIBNAL_MSG_GET_DONE          0xd5    /* signal GET rdma completion */

/***********************************************************************/

typedef struct koib_rx                          /* receive message */
{
        struct list_head          rx_list;      /* queue for attention */
        struct koib_conn         *rx_conn;      /* owning conn */
        int                       rx_rdma;      /* RDMA completion posted? */
        int                       rx_posted;    /* posted? */
        __u64                     rx_vaddr;     /* pre-mapped buffer (hca vaddr) */
        koib_msg_t               *rx_msg;       /* pre-mapped buffer (host vaddr) */
        struct ib_receive_param   rx_sp;        /* receive work item */
        struct ib_gather_scatter  rx_gl;        /* and it's memory */
} koib_rx_t;

typedef struct koib_tx                          /* transmit message */
{
        struct list_head          tx_list;      /* queue on idle_txs ibc_tx_queue etc. */
        int                       tx_isnblk;    /* I'm reserved for non-blocking sends */
        struct koib_conn         *tx_conn;      /* owning conn */
        int                       tx_mapped;    /* mapped for RDMA? */
        int                       tx_sending;   /* # tx callbacks outstanding */
        int                       tx_status;    /* completion status */
        int                       tx_passive_rdma; /* waiting for peer to RDMA? */
        int                       tx_passive_rdma_wait; /* on ibc_rdma_queue */
        unsigned long             tx_passive_rdma_deadline; /* completion deadline */
        __u64                     tx_passive_rdma_cookie; /* completion cookie */
        lib_msg_t                *tx_libmsg[2]; /* lib msgs to finalize on completion */
        koib_md_t                 tx_md;        /* RDMA mapping (active/passive) */
        __u64                     tx_vaddr;     /* pre-mapped buffer (hca vaddr) */
        koib_msg_t               *tx_msg;       /* pre-mapped buffer (host vaddr) */
        int                       tx_nsp;       /* # send work items */
        struct ib_send_param      tx_sp[2];     /* send work items... */
        struct ib_gather_scatter  tx_gl[2];     /* ...and their memory */
} koib_tx_t;

#define KOIB_TX_UNMAPPED       0
#define KOIB_TX_MAPPED         1
#define KOIB_TX_MAPPED_FMR     2

typedef struct koib_wire_connreq
{
        __u32        wcr_magic;                 /* I'm an openibnal connreq */
        __u16        wcr_version;               /* this is my version number */
        __u16        wcr_queue_depth;           /* this is my receive queue size */
        __u64        wcr_nid;                   /* peer's NID */
        __u64        wcr_incarnation;           /* peer's incarnation */
} koib_wire_connreq_t;

typedef struct koib_connreq
{
        /* connection-in-progress */
        struct koib_conn                   *cr_conn;
        koib_wire_connreq_t                 cr_wcr;
        __u64                               cr_tid;
        struct ib_common_attrib_service     cr_service;
        tTS_IB_GID                          cr_gid;
        struct ib_path_record               cr_path;
        struct ib_cm_active_param           cr_connparam;
} koib_connreq_t;

typedef struct koib_conn
{ 
        struct koib_peer   *ibc_peer;           /* owning peer */
        struct list_head    ibc_list;           /* stash on peer's conn list */
        __u64               ibc_incarnation;    /* which instance of the peer */
        atomic_t            ibc_refcount;       /* # users */
        int                 ibc_state;          /* what's happening */
        atomic_t            ibc_nob;            /* # bytes buffered */
        int                 ibc_nsends_posted;  /* # uncompleted sends */
        int                 ibc_credits;        /* # credits I have */
        int                 ibc_outstanding_credits; /* # credits to return */
        struct list_head    ibc_tx_queue;       /* send queue */
        struct list_head    ibc_rdma_queue;     /* tx awaiting RDMA completion */
        spinlock_t          ibc_lock;           /* serialise */
        koib_rx_t          *ibc_rxs;            /* the rx descs */
        koib_pages_t       *ibc_rx_pages;       /* premapped rx msg pages */
        struct ib_qp       *ibc_qp;             /* queue pair */
        __u32               ibc_qpn;            /* queue pair number */
        tTS_IB_CM_COMM_ID   ibc_comm_id;        /* connection ID? */
        koib_connreq_t     *ibc_connreq;        /* connection request state */
} koib_conn_t;

#define OPENIBNAL_CONN_INIT_NOTHING      0      /* initial state */
#define OPENIBNAL_CONN_INIT_QP           1      /* ibc_qp set up */
#define OPENIBNAL_CONN_CONNECTING        2      /* started to connect */
#define OPENIBNAL_CONN_ESTABLISHED       3      /* connection established */
#define OPENIBNAL_CONN_DEATHROW          4      /* waiting to be closed */
#define OPENIBNAL_CONN_ZOMBIE            5      /* waiting to be freed */

typedef struct koib_peer
{
        struct list_head    ibp_list;           /* stash on global peer list */
        struct list_head    ibp_connd_list;     /* schedule on koib_connd_peers */
        ptl_nid_t           ibp_nid;            /* who's on the other end(s) */
        atomic_t            ibp_refcount;       /* # users */
        int                 ibp_persistence;    /* "known" peer refs */
        struct list_head    ibp_conns;          /* all active connections */
        struct list_head    ibp_tx_queue;       /* msgs waiting for a conn */
        int                 ibp_connecting;     /* connecting+accepting */
        unsigned long       ibp_reconnect_time; /* when reconnect may be attempted */
        unsigned long       ibp_reconnect_interval; /* exponential backoff */
} koib_peer_t;


extern lib_nal_t        koibnal_lib;
extern koib_data_t      koibnal_data;
extern koib_tunables_t  koibnal_tunables;

static inline struct list_head *
koibnal_nid2peerlist (ptl_nid_t nid) 
{
        unsigned int hash = ((unsigned int)nid) % koibnal_data.koib_peer_hash_size;
        
        return (&koibnal_data.koib_peers [hash]);
}

static inline int
koibnal_peer_active(koib_peer_t *peer)
{
        /* Am I in the peer hash table? */
        return (!list_empty(&peer->ibp_list));
}

static inline void
koibnal_queue_tx_locked (koib_tx_t *tx, koib_conn_t *conn)
{
        /* CAVEAT EMPTOR: tx takes caller's ref on conn */

        LASSERT (tx->tx_nsp > 0);               /* work items set up */
        LASSERT (tx->tx_conn == NULL);          /* only set here */

        tx->tx_conn = conn;
        list_add_tail(&tx->tx_list, &conn->ibc_tx_queue);
}

#define KOIBNAL_SERVICE_KEY_MASK  (IB_SA_SERVICE_COMP_MASK_NAME |       \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_1 |    \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_2 |    \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_3 |    \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_4 |    \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_5 |    \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_6 |    \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_7 |    \
                                   IB_SA_SERVICE_COMP_MASK_DATA8_8)

static inline __u64*
koibnal_service_nid_field(struct ib_common_attrib_service *srv)
{
        /* must be consistent with KOIBNAL_SERVICE_KEY_MASK */
        return (__u64 *)srv->service_data8;
}


static inline void
koibnal_set_service_keys(struct ib_common_attrib_service *srv, ptl_nid_t nid)
{
        LASSERT (strlen (OPENIBNAL_SERVICE_NAME) < sizeof(srv->service_name));
        memset (srv->service_name, 0, sizeof(srv->service_name));
        strcpy (srv->service_name, OPENIBNAL_SERVICE_NAME);

        *koibnal_service_nid_field(srv) = cpu_to_le64(nid);
}

#if 0
static inline void
koibnal_show_rdma_attr (koib_conn_t *conn)
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
koibnal_page2phys (struct page *p)
{
        __u64 page_number = p - mem_map;
        
        return (page_number << PAGE_SHIFT);
}
#else
# error "no page->phys"
#endif

extern koib_peer_t *koibnal_create_peer (ptl_nid_t nid);
extern void koibnal_put_peer (koib_peer_t *peer);
extern int koibnal_del_matching_peers (ptl_nid_t nid, int persistent_only, 
                                       int all_refs, int del_conns);
extern koib_peer_t *koibnal_find_peer_locked (ptl_nid_t nid);
extern void koibnal_unlink_peer_locked (koib_peer_t *peer);
extern int  koibnal_close_stale_conns_locked (koib_peer_t *peer, 
                                              __u64 incarnation);
extern koib_conn_t *koibnal_create_conn (void);
extern void koibnal_put_conn (koib_conn_t *conn);
extern void koibnal_destroy_conn (koib_conn_t *conn);
extern int koibnal_alloc_pages (koib_pages_t **pp, int npages, int access);
extern void koibnal_free_pages (koib_pages_t *p);

extern void koibnal_check_sends (koib_conn_t *conn);

extern tTS_IB_CM_CALLBACK_RETURN
koibnal_conn_callback (tTS_IB_CM_EVENT event, tTS_IB_CM_COMM_ID cid,
                       void *param, void *arg);
extern tTS_IB_CM_CALLBACK_RETURN 
koibnal_passive_conn_callback (tTS_IB_CM_EVENT event, tTS_IB_CM_COMM_ID cid,
                               void *param, void *arg);

extern void koibnal_close_conn_locked (koib_conn_t *conn, int error);
extern void koibnal_destroy_conn (koib_conn_t *conn);
extern int  koibnal_thread_start (int (*fn)(void *arg), void *arg);
extern int  koibnal_scheduler(void *arg);
extern int  koibnal_connd (void *arg);
extern void koibnal_rx_callback (struct ib_cq *cq, struct ib_cq_entry *e, void *arg);
extern void koibnal_tx_callback (struct ib_cq *cq, struct ib_cq_entry *e, void *arg);
extern void koibnal_init_tx_msg (koib_tx_t *tx, int type, int body_nob);
extern int  koibnal_close_conn (koib_conn_t *conn, int why);
extern void koibnal_start_active_rdma (int type, int status, 
                                       koib_rx_t *rx, lib_msg_t *libmsg, 
                                       unsigned int niov, 
                                       struct iovec *iov, ptl_kiov_t *kiov,
                                       size_t offset, size_t nob);




