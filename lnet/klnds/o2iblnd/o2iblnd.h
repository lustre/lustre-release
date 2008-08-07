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
 * lnet/klnds/o2iblnd/o2iblnd.h
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
#include <linux/random.h>
#include <linux/pci.h>

#include <net/sock.h>
#include <linux/in.h>

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/kp30.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>

#if !HAVE_GFP_T
typedef int gfp_t;
#endif

#include <rdma/rdma_cm.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_fmr_pool.h>

/* tunables fixed at compile time */
#ifdef CONFIG_SMP
# define IBLND_N_SCHED      num_online_cpus()   /* # schedulers */
#else
# define IBLND_N_SCHED      1                   /* # schedulers */
#endif

#define IBLND_PEER_HASH_SIZE         101        /* # peer lists */
#define IBLND_RESCHED                100        /* # scheduler loops before reschedule */
#define IBLND_MSG_QUEUE_SIZE         8          /* # messages/RDMAs in-flight */
#define IBLND_CREDIT_HIGHWATER       7          /* when eagerly to return credits */
#define IBLND_MSG_SIZE              (4<<10)     /* max size of queued messages (inc hdr) */

#define IBLND_MAP_ON_DEMAND  0
#if IBLND_MAP_ON_DEMAND
# define IBLND_MAX_RDMA_FRAGS        1
#else
# define IBLND_MAX_RDMA_FRAGS        LNET_MAX_IOV
#endif

/************************/
/* derived constants... */

/* TX messages (shared by all connections) */
#define IBLND_TX_MSGS()       (*kiblnd_tunables.kib_ntx)
#define IBLND_TX_MSG_BYTES()  (IBLND_TX_MSGS() * IBLND_MSG_SIZE)
#define IBLND_TX_MSG_PAGES()  ((IBLND_TX_MSG_BYTES() + PAGE_SIZE - 1)/PAGE_SIZE)

/* RX messages (per connection) */
#define IBLND_RX_MSGS         (IBLND_MSG_QUEUE_SIZE * 2)
#define IBLND_RX_MSG_BYTES    (IBLND_RX_MSGS * IBLND_MSG_SIZE)
#define IBLND_RX_MSG_PAGES    ((IBLND_RX_MSG_BYTES + PAGE_SIZE - 1)/PAGE_SIZE)

/* WRs and CQEs (per connection) */
#define IBLND_RECV_WRS        IBLND_RX_MSGS
#define IBLND_SEND_WRS        ((*kiblnd_tunables.kib_concurrent_sends) * \
                               (1 + IBLND_MAX_RDMA_FRAGS))
#define IBLND_CQ_ENTRIES()    (IBLND_RECV_WRS + IBLND_SEND_WRS)

typedef struct
{
        unsigned int     *kib_service;          /* IB service number */
        int              *kib_min_reconnect_interval; /* first failed connection retry... */
        int              *kib_max_reconnect_interval; /* ...exponentially increasing to this */
        int              *kib_cksum;            /* checksum kib_msg_t? */
        int              *kib_timeout;          /* comms timeout (seconds) */
        int              *kib_keepalive;        /* keepalive timeout (seconds) */
        int              *kib_ntx;              /* # tx descs */
        int              *kib_credits;          /* # concurrent sends */
        int              *kib_peercredits;      /* # concurrent sends to 1 peer */
        char            **kib_default_ipif;     /* default IPoIB interface */
        int              *kib_retry_count;
        int              *kib_rnr_retry_count;
        int              *kib_concurrent_sends; /* send work queue sizing */
        int		 *kib_ib_mtu;		/* IB MTU */
#if IBLND_MAP_ON_DEMAND
        int              *kib_fmr_pool_size;    /* # FMRs in pool */
        int              *kib_fmr_flush_trigger; /* When to trigger FMR flush */
        int              *kib_fmr_cache;        /* enable FMR pool cache? */
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

typedef struct 
{
        struct list_head     ibd_list;          /* chain on kib_devs */
        __u32                ibd_ifip;          /* IPoIB interface IP */
        char                 ibd_ifname[32];    /* IPoIB interface name */
        int                  ibd_nnets;         /* # nets extant */

        struct rdma_cm_id   *ibd_cmid;          /* IB listener (bound to 1 device) */
        struct ib_pd        *ibd_pd;            /* PD for the device */
        struct ib_mr        *ibd_mr;            /* MR for non RDMA I/O */
} kib_dev_t;

typedef struct
{
        __u64                ibn_incarnation;   /* my epoch */
        int                  ibn_init;          /* initialisation state */
        int                  ibn_shutdown;      /* shutting down? */

        atomic_t             ibn_npeers;        /* # peers extant */
        atomic_t             ibn_nconns;        /* # connections extant */

        struct kib_tx       *ibn_tx_descs;      /* all the tx descriptors */
        kib_pages_t         *ibn_tx_pages;      /* premapped tx msg pages */
        struct list_head     ibn_idle_txs;      /* idle tx descriptors */
        spinlock_t           ibn_tx_lock;       /* serialise */

#if IBLND_MAP_ON_DEMAND
        struct ib_fmr_pool  *ibn_fmrpool;       /* FMR pool for RDMA I/O */
#endif

        kib_dev_t           *ibn_dev;           /* underlying IB device */
} kib_net_t;

typedef struct
{
        int                  kib_init;          /* initialisation state */
        int                  kib_shutdown;      /* shut down? */
        struct list_head     kib_devs;          /* IB devices extant */
        atomic_t             kib_nthreads;      /* # live threads */
        rwlock_t             kib_global_lock;   /* stabilize net/dev/peer/conn ops */

        struct list_head    *kib_peers;         /* hash table of all my known peers */
        int                  kib_peer_hash_size; /* size of kib_peers */

        void                *kib_connd;         /* the connd task (serialisation assertions) */
        struct list_head     kib_connd_conns;   /* connections to setup/teardown */
        struct list_head     kib_connd_zombies; /* connections with zero refcount */
        wait_queue_head_t    kib_connd_waitq;   /* connection daemon sleeps here */
        spinlock_t           kib_connd_lock;    /* serialise */

        wait_queue_head_t    kib_sched_waitq;   /* schedulers sleep here */
        struct list_head     kib_sched_conns;   /* conns to check for rx completions */
        spinlock_t           kib_sched_lock;    /* serialise */

        __u64                kib_next_tx_cookie; /* RDMA completion cookie */
        struct ib_qp_attr    kib_error_qpa;      /* QP->ERROR */
} kib_data_t;

#define IBLND_INIT_NOTHING         0
#define IBLND_INIT_DATA            1
#define IBLND_INIT_ALL             2

/************************************************************************
 * IB Wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 */

typedef struct kib_connparams
{
        __u16             ibcp_queue_depth;
        __u16             ibcp_max_frags;
        __u32             ibcp_max_msg_size;
} WIRE_ATTR kib_connparams_t;

typedef struct
{
        lnet_hdr_t        ibim_hdr;             /* portals header */
        char              ibim_payload[0];      /* piggy-backed payload */
} WIRE_ATTR kib_immediate_msg_t;

#if IBLND_MAP_ON_DEMAND
typedef struct
{
	__u64             rd_addr;             	/* IO VMA address */
	__u32             rd_nob;              	/* # of bytes */
	__u32             rd_key;		/* remote key */
} WIRE_ATTR kib_rdma_desc_t;
#else
typedef struct
{
        __u32             rf_nob;               /* # bytes this frag */
        __u64             rf_addr;              /* CAVEAT EMPTOR: misaligned!! */
} WIRE_ATTR kib_rdma_frag_t;

typedef struct
{
        __u32             rd_key;               /* local/remote key */
        __u32             rd_nfrags;            /* # fragments */
        kib_rdma_frag_t   rd_frags[0];          /* buffer frags */
} WIRE_ATTR kib_rdma_desc_t;
#endif
        
typedef struct
{
        lnet_hdr_t        ibprm_hdr;            /* portals header */
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
        lnet_hdr_t        ibgm_hdr;             /* portals header */
        __u64             ibgm_cookie;          /* opaque completion cookie */
        kib_rdma_desc_t   ibgm_rd;              /* rdma descriptor */
} WIRE_ATTR kib_get_msg_t;

typedef struct
{
        __u64             ibcm_cookie;          /* opaque completion cookie */
        __s32             ibcm_status;          /* < 0 failure: >= 0 length */
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
                kib_connparams_t      connparams;
                kib_immediate_msg_t   immediate;
                kib_putreq_msg_t      putreq;
                kib_putack_msg_t      putack;
                kib_get_msg_t         get;
                kib_completion_msg_t  completion;
        } WIRE_ATTR ibm_u;
} WIRE_ATTR kib_msg_t;

#define IBLND_MSG_MAGIC LNET_PROTO_IB_MAGIC	/* unique magic */

#define IBLND_MSG_VERSION           0x11

#define IBLND_MSG_CONNREQ           0xc0        /* connection request */
#define IBLND_MSG_CONNACK           0xc1        /* connection acknowledge */
#define IBLND_MSG_NOOP              0xd0        /* nothing (just credits) */
#define IBLND_MSG_IMMEDIATE         0xd1        /* immediate */
#define IBLND_MSG_PUT_REQ           0xd2        /* putreq (src->sink) */
#define IBLND_MSG_PUT_NAK           0xd3        /* completion (sink->src) */
#define IBLND_MSG_PUT_ACK           0xd4        /* putack (sink->src) */
#define IBLND_MSG_PUT_DONE          0xd5        /* completion (src->sink) */
#define IBLND_MSG_GET_REQ           0xd6        /* getreq (sink->src) */
#define IBLND_MSG_GET_DONE          0xd7        /* completion (src->sink: all OK) */

typedef struct {
        __u32            ibr_magic;             /* sender's magic */
        __u16            ibr_version;           /* sender's version */
        __u8             ibr_why;               /* reject reason */
} WIRE_ATTR kib_rej_t;


/* connection rejection reasons */
#define IBLND_REJECT_CONN_RACE       1          /* You lost connection race */
#define IBLND_REJECT_NO_RESOURCES    2          /* Out of memory/conns etc */
#define IBLND_REJECT_FATAL           3          /* Anything else */

/***********************************************************************/

typedef struct kib_rx                           /* receive message */
{
        struct list_head          rx_list;      /* queue for attention */
        struct kib_conn          *rx_conn;      /* owning conn */
        int                       rx_nob;       /* # bytes received (-1 while posted) */
        enum ib_wc_status         rx_status;    /* completion status */
        kib_msg_t                *rx_msg;       /* message buffer (host vaddr) */
        __u64                     rx_msgaddr;   /* message buffer (I/O addr) */
        DECLARE_PCI_UNMAP_ADDR   (rx_msgunmap); /* for dma_unmap_single() */
        struct ib_recv_wr         rx_wrq;       /* receive work item... */
        struct ib_sge             rx_sge;       /* ...and its memory */
} kib_rx_t;

#define IBLND_POSTRX_DONT_POST    0             /* don't post */
#define IBLND_POSTRX_NO_CREDIT    1             /* post: no credits */
#define IBLND_POSTRX_PEER_CREDIT  2             /* post: give peer back 1 credit */
#define IBLND_POSTRX_RSRVD_CREDIT 3             /* post: give myself back 1 reserved credit */

typedef struct kib_tx                           /* transmit message */
{
        struct list_head          tx_list;      /* queue on idle_txs ibc_tx_queue etc. */
        struct kib_conn          *tx_conn;      /* owning conn */
        int                       tx_sending;   /* # tx callbacks outstanding */
        int                       tx_queued;    /* queued for sending */
        int                       tx_waiting;   /* waiting for peer */
        int                       tx_status;    /* LNET completion status */
        unsigned long             tx_deadline;  /* completion deadline */
        __u64                     tx_cookie;    /* completion cookie */
        lnet_msg_t               *tx_lntmsg[2]; /* lnet msgs to finalize on completion */
        kib_msg_t                *tx_msg;       /* message buffer (host vaddr) */
        __u64                     tx_msgaddr;   /* message buffer (I/O addr) */
        DECLARE_PCI_UNMAP_ADDR   (tx_msgunmap); /* for dma_unmap_single() */
        int                       tx_nwrq;      /* # send work items */
#if IBLND_MAP_ON_DEMAND
        struct ib_send_wr         tx_wrq[2];    /* send work items... */
        struct ib_sge             tx_sge[2];    /* ...and their memory */
        kib_rdma_desc_t           tx_rd[1];     /* rdma descriptor */
        __u64                    *tx_pages;     /* rdma phys page addrs */
        struct ib_pool_fmr       *tx_fmr;       /* rdma mapping (mapped if != NULL) */
#else
        struct ib_send_wr        *tx_wrq;       /* send work items... */
        struct ib_sge            *tx_sge;       /* ...and their memory */
        kib_rdma_desc_t          *tx_rd;        /* rdma descriptor */
        int                       tx_nfrags;    /* # entries in... */
        struct scatterlist       *tx_frags;     /* dma_map_sg descriptor */
        int                       tx_dmadir;    /* dma direction */
#endif        
} kib_tx_t;

typedef struct kib_connvars
{
        /* connection-in-progress variables */
        kib_msg_t                 cv_msg;
} kib_connvars_t;

typedef struct kib_conn
{
        struct kib_peer    *ibc_peer;           /* owning peer */
        struct list_head    ibc_list;           /* stash on peer's conn list */
        struct list_head    ibc_sched_list;     /* schedule for attention */
        __u64               ibc_incarnation;    /* which instance of the peer */
        atomic_t            ibc_refcount;       /* # users */
        int                 ibc_state;          /* what's happening */
        int                 ibc_nsends_posted;  /* # uncompleted sends */
        int                 ibc_credits;        /* # credits I have */
        int                 ibc_outstanding_credits; /* # credits to return */
        int                 ibc_reserved_credits;/* # ACK/DONE msg credits */
        int                 ibc_comms_error;    /* set on comms error */
        int                 ibc_nrx:8;          /* receive buffers owned */
        int                 ibc_scheduled:1;    /* scheduled for attention */
        int                 ibc_ready:1;        /* CQ callback fired */
        unsigned long       ibc_last_send;      /* time of last send */
        struct list_head    ibc_early_rxs;      /* rxs completed before ESTABLISHED */
        struct list_head    ibc_tx_noops;       /* IBLND_MSG_NOOPs */
        struct list_head    ibc_tx_queue;       /* sends that need a credit */
        struct list_head    ibc_tx_queue_nocred;/* sends that don't need a credit */
        struct list_head    ibc_tx_queue_rsrvd; /* sends that need to reserve an ACK/DONE msg */
        struct list_head    ibc_active_txs;     /* active tx awaiting completion */
        spinlock_t          ibc_lock;           /* serialise */
        kib_rx_t           *ibc_rxs;            /* the rx descs */
        kib_pages_t        *ibc_rx_pages;       /* premapped rx msg pages */

        struct rdma_cm_id  *ibc_cmid;           /* CM id */
        struct ib_cq       *ibc_cq;             /* completion queue */

        kib_connvars_t     *ibc_connvars;       /* in-progress connection state */
} kib_conn_t;

#define IBLND_CONN_INIT               0         /* being intialised */
#define IBLND_CONN_ACTIVE_CONNECT     1         /* active sending req */
#define IBLND_CONN_PASSIVE_WAIT       2         /* passive waiting for rtu */
#define IBLND_CONN_ESTABLISHED        3         /* connection established */
#define IBLND_CONN_CLOSING            4         /* being closed */
#define IBLND_CONN_DISCONNECTED       5         /* disconnected */

typedef struct kib_peer
{
        struct list_head    ibp_list;           /* stash on global peer list */
        lnet_nid_t          ibp_nid;            /* who's on the other end(s) */
        lnet_ni_t          *ibp_ni;             /* LNet interface */
        atomic_t            ibp_refcount;       /* # users */
        struct list_head    ibp_conns;          /* all active connections */
        struct list_head    ibp_tx_queue;       /* msgs waiting for a conn */
        int                 ibp_connecting;     /* current active connection attempts */
        int                 ibp_accepting;      /* current passive connection attempts */
        int                 ibp_error;          /* errno on closing this peer */
        cfs_time_t          ibp_last_alive;     /* when (in jiffies) I was last alive */
} kib_peer_t;


extern kib_data_t      kiblnd_data;
extern kib_tunables_t  kiblnd_tunables;

#define kiblnd_conn_addref(conn)                                \
do {                                                            \
        CDEBUG(D_NET, "conn[%p] (%d)++\n",                      \
               (conn), atomic_read(&(conn)->ibc_refcount));     \
        LASSERT(atomic_read(&(conn)->ibc_refcount) > 0);        \
        atomic_inc(&(conn)->ibc_refcount);                      \
} while (0)

#define kiblnd_conn_decref(conn)                                              \
do {                                                                          \
        unsigned long   flags;                                                \
                                                                              \
        CDEBUG(D_NET, "conn[%p] (%d)--\n",                                    \
               (conn), atomic_read(&(conn)->ibc_refcount));                   \
        LASSERT(atomic_read(&(conn)->ibc_refcount) > 0);                      \
        if (atomic_dec_and_test(&(conn)->ibc_refcount)) {                     \
                spin_lock_irqsave(&kiblnd_data.kib_connd_lock, flags);        \
                list_add_tail(&(conn)->ibc_list,                              \
                              &kiblnd_data.kib_connd_zombies);                \
                wake_up(&kiblnd_data.kib_connd_waitq);                        \
                spin_unlock_irqrestore(&kiblnd_data.kib_connd_lock, flags);   \
        }                                                                     \
} while (0)

#define kiblnd_peer_addref(peer)                                \
do {                                                            \
        CDEBUG(D_NET, "peer[%p] -> %s (%d)++\n",                \
               (peer), libcfs_nid2str((peer)->ibp_nid),         \
               atomic_read (&(peer)->ibp_refcount));            \
        LASSERT(atomic_read(&(peer)->ibp_refcount) > 0);        \
        atomic_inc(&(peer)->ibp_refcount);                      \
} while (0)

#define kiblnd_peer_decref(peer)                                \
do {                                                            \
        CDEBUG(D_NET, "peer[%p] -> %s (%d)--\n",                \
               (peer), libcfs_nid2str((peer)->ibp_nid),         \
               atomic_read (&(peer)->ibp_refcount));            \
        LASSERT(atomic_read(&(peer)->ibp_refcount) > 0);        \
        if (atomic_dec_and_test(&(peer)->ibp_refcount))         \
                kiblnd_destroy_peer(peer);                      \
} while (0)

static inline struct list_head *
kiblnd_nid2peerlist (lnet_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) % kiblnd_data.kib_peer_hash_size;

        return (&kiblnd_data.kib_peers [hash]);
}

static inline int
kiblnd_peer_active (kib_peer_t *peer)
{
        /* Am I in the peer hash table? */
        return (!list_empty(&peer->ibp_list));
}

static inline kib_conn_t *
kiblnd_get_conn_locked (kib_peer_t *peer)
{
        LASSERT (!list_empty(&peer->ibp_conns));

        /* just return the first connection */
        return list_entry(peer->ibp_conns.next, kib_conn_t, ibc_list);
}

static inline int
kiblnd_send_keepalive(kib_conn_t *conn)
{
        return (*kiblnd_tunables.kib_keepalive > 0) &&
                time_after(jiffies, conn->ibc_last_send +
                           *kiblnd_tunables.kib_keepalive*HZ);
}

static inline int
kiblnd_send_noop(kib_conn_t *conn)
{
        LASSERT (conn->ibc_state >= IBLND_CONN_ESTABLISHED);

        if (conn->ibc_outstanding_credits < IBLND_CREDIT_HIGHWATER &&
            !kiblnd_send_keepalive(conn))
                return 0; /* No need to send NOOP */

        if (!list_empty(&conn->ibc_tx_noops) ||       /* NOOP already queued */
            !list_empty(&conn->ibc_tx_queue_nocred) || /* can be piggybacked */
            conn->ibc_credits == 0)                    /* no credit */
                return 0;

        if (conn->ibc_credits == 1 &&      /* last credit reserved for */
            conn->ibc_outstanding_credits == 0) /* giving back credits */
                return 0;

        /* No tx to piggyback NOOP onto or no credit to send a tx */
        return (list_empty(&conn->ibc_tx_queue) || conn->ibc_credits == 1);
}

static inline void
kiblnd_abort_receives(kib_conn_t *conn)
{
        ib_modify_qp(conn->ibc_cmid->qp,
                     &kiblnd_data.kib_error_qpa, IB_QP_STATE);
}

/* CAVEAT EMPTOR: We rely on descriptor alignment to allow us to use the
 * lowest bits of the work request id to stash the work item type. */

#define IBLND_WID_TX    0
#define IBLND_WID_RDMA  1
#define IBLND_WID_RX    2
#define IBLND_WID_MASK  3UL

static inline __u64
kiblnd_ptr2wreqid (void *ptr, int type)
{
        unsigned long lptr = (unsigned long)ptr;

        LASSERT ((lptr & IBLND_WID_MASK) == 0);
        LASSERT ((type & ~IBLND_WID_MASK) == 0);
        return (__u64)(lptr | type);
}

static inline void *
kiblnd_wreqid2ptr (__u64 wreqid)
{
        return (void *)(((unsigned long)wreqid) & ~IBLND_WID_MASK);
}

static inline int
kiblnd_wreqid2type (__u64 wreqid)
{
        return (wreqid & IBLND_WID_MASK);
}

static inline void
kiblnd_set_conn_state (kib_conn_t *conn, int state)
{
        conn->ibc_state = state;
        mb();
}

#if IBLND_MAP_ON_DEMAND
static inline int
kiblnd_rd_size (kib_rdma_desc_t *rd)
{
        return rd->rd_nob;
}
#else
static inline int
kiblnd_rd_size (kib_rdma_desc_t *rd)
{
        int   i;
        int   size;
        
        for (i = size = 0; i < rd->rd_nfrags; i++)
                size += rd->rd_frags[i].rf_nob;
        
        return size;
}
#endif

#if (IBLND_OFED_VERSION == 1020) || (IBLND_OFED_VERSION == 1025)

static inline __u64 kiblnd_dma_map_single(struct ib_device *dev,
                                          void *msg, size_t size,
                                          enum dma_data_direction direction)
{
        return ib_dma_map_single(dev, msg, size, direction);
}

static inline void kiblnd_dma_unmap_single(struct ib_device *dev,
                                           __u64 addr, size_t size,
                                          enum dma_data_direction direction)
{
        ib_dma_unmap_single(dev, addr, size, direction);
}

#define KIBLND_UNMAP_ADDR_SET(p, m, a)  do {} while (0)
#define KIBLND_UNMAP_ADDR(p, m, a)      (a)

static inline int kiblnd_dma_map_sg(struct ib_device *dev,
                                    struct scatterlist *sg, int nents,
                                    enum dma_data_direction direction)
{
        return ib_dma_map_sg(dev, sg, nents, direction);
}

static inline void kiblnd_dma_unmap_sg(struct ib_device *dev,
                                       struct scatterlist *sg, int nents,
                                       enum dma_data_direction direction)
{
        ib_dma_unmap_sg(dev, sg, nents, direction);
}

static inline __u64 kiblnd_sg_dma_address(struct ib_device *dev,
                                          struct scatterlist *sg)
{
        return ib_sg_dma_address(dev, sg);
}

static inline unsigned int kiblnd_sg_dma_len(struct ib_device *dev,
                                             struct scatterlist *sg)
{
        return ib_sg_dma_len(dev, sg);
}

/* XXX We use KIBLND_CONN_PARAM(e) as writable buffer, it's not strictly
 * right because OFED1.2 defines it as const, to use it we have to add
 * (void *) cast to overcome "const" */

#define KIBLND_CONN_PARAM(e)            ((e)->param.conn.private_data)
#define KIBLND_CONN_PARAM_LEN(e)        ((e)->param.conn.private_data_len)

#elif (IBLND_OFED_VERSION == 1010)

static inline dma_addr_t kiblnd_dma_map_single(struct ib_device *dev,
                                               void *msg, size_t size,
                                               enum dma_data_direction direction)
{
        return dma_map_single(dev->dma_device, msg, size, direction);
}

static inline void kiblnd_dma_unmap_single(struct ib_device *dev,
                                           dma_addr_t addr, size_t size,
                                           enum dma_data_direction direction)
{
        dma_unmap_single(dev->dma_device, addr, size, direction);
}

#define KIBLND_UNMAP_ADDR_SET(p, m, a)  pci_unmap_addr_set(p, m, a)
#define KIBLND_UNMAP_ADDR(p, m, a)      pci_unmap_addr(p, m)

static inline int kiblnd_dma_map_sg(struct ib_device *dev,
                                    struct scatterlist *sg, int nents,
                                    enum dma_data_direction direction)
{
        return dma_map_sg(dev->dma_device, sg, nents, direction);
}

static inline void kiblnd_dma_unmap_sg(struct ib_device *dev,
                                       struct scatterlist *sg, int nents,
                                       enum dma_data_direction direction)
{
        return dma_unmap_sg(dev->dma_device, sg, nents, direction);
}


static inline dma_addr_t kiblnd_sg_dma_address(struct ib_device *dev,
                                               struct scatterlist *sg)
{
        return sg_dma_address(sg);
}


static inline unsigned int kiblnd_sg_dma_len(struct ib_device *dev,
                                             struct scatterlist *sg)
{
        return sg_dma_len(sg);
}

#define KIBLND_CONN_PARAM(e)            ((e)->private_data)
#define KIBLND_CONN_PARAM_LEN(e)        ((e)->private_data_len)

#endif

int  kiblnd_startup (lnet_ni_t *ni);
void kiblnd_shutdown (lnet_ni_t *ni);
int  kiblnd_ctl (lnet_ni_t *ni, unsigned int cmd, void *arg);

int  kiblnd_tunables_init(void);
void kiblnd_tunables_fini(void);

int  kiblnd_connd (void *arg);
int  kiblnd_scheduler(void *arg);
int  kiblnd_thread_start (int (*fn)(void *arg), void *arg);

int  kiblnd_alloc_pages (kib_pages_t **pp, int npages);
void kiblnd_free_pages (kib_pages_t *p);

int  kiblnd_cm_callback(struct rdma_cm_id *cmid,
                        struct rdma_cm_event *event);

int  kiblnd_create_peer (lnet_ni_t *ni, kib_peer_t **peerp, lnet_nid_t nid);
void kiblnd_destroy_peer (kib_peer_t *peer);
void kiblnd_destroy_dev (kib_dev_t *dev);
void kiblnd_unlink_peer_locked (kib_peer_t *peer);
void kiblnd_peer_alive (kib_peer_t *peer);
kib_peer_t *kiblnd_find_peer_locked (lnet_nid_t nid);
void kiblnd_peer_connect_failed (kib_peer_t *peer, int active, int error);
int  kiblnd_close_stale_conns_locked (kib_peer_t *peer, __u64 incarnation);

void kiblnd_connreq_done(kib_conn_t *conn, int status);
kib_conn_t *kiblnd_create_conn (kib_peer_t *peer, struct rdma_cm_id *cmid,
                                int state);
void kiblnd_destroy_conn (kib_conn_t *conn);
void kiblnd_close_conn (kib_conn_t *conn, int error);
void kiblnd_close_conn_locked (kib_conn_t *conn, int error);

int  kiblnd_init_rdma (lnet_ni_t *ni, kib_tx_t *tx, int type,
                       int nob, kib_rdma_desc_t *dstrd, __u64 dstcookie);

void kiblnd_queue_tx_locked (kib_tx_t *tx, kib_conn_t *conn);
void kiblnd_queue_tx (kib_tx_t *tx, kib_conn_t *conn);
void kiblnd_init_tx_msg (lnet_ni_t *ni, kib_tx_t *tx, int type, int body_nob);
void kiblnd_txlist_done (lnet_ni_t *ni, struct list_head *txlist, int status);
void kiblnd_check_sends (kib_conn_t *conn);

void kiblnd_qp_event(struct ib_event *event, void *arg);
void kiblnd_cq_event(struct ib_event *event, void *arg);
void kiblnd_cq_completion(struct ib_cq *cq, void *arg);

void kiblnd_init_msg (kib_msg_t *msg, int type, int body_nob);
void kiblnd_pack_msg (lnet_ni_t *ni, kib_msg_t *msg,
                      int credits, lnet_nid_t dstnid, __u64 dststamp);
int  kiblnd_unpack_msg(kib_msg_t *msg, int nob);
int  kiblnd_post_rx (kib_rx_t *rx, int credit);

int  kiblnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int  kiblnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, int delayed,
                 unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
                 unsigned int offset, unsigned int mlen, unsigned int rlen);
