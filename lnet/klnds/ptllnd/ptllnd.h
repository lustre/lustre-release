/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
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
#include <linux/random.h>

#include <net/sock.h>
#include <linux/in.h>


#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/kp30.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>
#include <portals/p30.h>
#include <lnet/ptllnd.h>        /* Depends on portals/p30.h */

/*
 * Define this to enable console debug logging
 * and simulation
 */
//#define PJK_DEBUGGING

#if CONFIG_SMP
# define PTLLND_N_SCHED         num_online_cpus()   /* # schedulers */
#else
# define PTLLND_N_SCHED         1                   /* # schedulers */
#endif



/* defaults for modparams/tunables */
#define PTLLND_NTX              256        /* # tx descs */
#define PTLLND_NRX              (64 * num_online_cpus()) /* # rx desc */
#define PTLLND_CONCURRENT_PEERS 1152       /* # nodes all talking at once to me */
#define PTLLND_CKSUM            0          /* checksum kptl_msg_t? 0 = Diabled */
#define PTLLND_TIMEOUT          50         /* default comms timeout (seconds) */
#define PTLLND_RXB_NPAGES       1          /* Number of pages for a single RX Buffer */
#define PTLLND_RXB_SPARES       8          /* Number of spare buffers (account inuse) */
#define PTLLND_CREDITS          128        /* concurrent sends */
#define PTLLND_PEER_HASH_SIZE   101        /* # of buckets in peer hash table */

/* tunables fixed at compile time */
#define PTLLND_CREDIT_HIGHWATER ((*kptllnd_tunables.kptl_peercredits)-1)  /* when to eagerly return credits */

typedef struct
{
        int             *kptl_ntx;              /* # tx descs */
        int             *kptl_concurrent_peers; /* max # nodes all talking to me */
        int             *kptl_cksum;            /* checksum kptl_msg_t? */
        int             *kptl_timeout;          /* comms timeout (seconds) */
        int             *kptl_portal;           /* portal number */
        int             *kptl_pid;              /* portals PID (self + kernel peers) */
        int             *kptl_rxb_npages;       /* number of pages for rx buffer */
        int             *kptl_rxb_nspare;       /* number of spare rx buffers */
        int             *kptl_credits;          /* number of credits */
        int             *kptl_peercredits;      /* number of credits */
        int             *kptl_max_msg_size;     /* max immd message size*/
        int             *kptl_peer_hash_table_size; /* # slots in peer hash table */

#ifdef PJK_DEBUGGING
        int             *kptl_simulation_bitmap;/* simulation bitmap */
#endif

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
        struct ctl_table_header *kptl_sysctl;    /* sysctl interface */
#endif
} kptl_tunables_t;

#include "lnet/ptllnd_wire.h"

/***********************************************************************/

typedef struct kptl_data kptl_data_t;
typedef struct kptl_rx_buffer kptl_rx_buffer_t;
typedef struct kptl_peer kptl_peer_t;

typedef struct {
        char      eva_type;
} kptl_eventarg_t;

#define PTLLND_EVENTARG_TYPE_MSG    0x1
#define PTLLND_EVENTARG_TYPE_RDMA   0x2
#define PTLLND_EVENTARG_TYPE_BUF    0x3

typedef struct kptl_rx                          /* receive message */
{
        struct list_head        rx_list;        /* queue for attention */
        kptl_rx_buffer_t       *rx_rxb;         /* the rx buffer pointer */
        kptl_msg_t             *rx_msg;         /* received message */
        int                     rx_nob;         /* received message size */
        ptl_process_id_t        rx_initiator;   /* sender's address */
#if CRAY_XT3
        ptl_uid_t               rx_uid;         /* sender's uid */
#endif
        kptl_peer_t            *rx_peer;        /* pointer to peer */
        char                    rx_space[0];    /* copy of incoming request */
} kptl_rx_t;

typedef struct kptl_rx_buffer_pool
{
        spinlock_t              rxbp_lock;
        struct list_head        rxbp_list;      /* all allocated buffers */
        int                     rxbp_count;     /* # allocated buffers */
        int                     rxbp_reserved;  /* # requests to buffer */
        int                     rxbp_shutdown;  /* shutdown flag */
} kptl_rx_buffer_pool_t;

struct kptl_rx_buffer
{
        kptl_rx_buffer_pool_t  *rxb_pool;
        struct list_head        rxb_list;       /* for the rxb_pool list */
        struct list_head        rxb_repost_list;/* for the kptl_sched_rxbq list */
        int                     rxb_posted:1;   /* on the net */
        int                     rxb_idle:1;     /* all done */
        kptl_eventarg_t         rxb_eventarg;   /* event->md.user_ptr */
        int                     rxb_refcount;   /* reference count */
        ptl_handle_md_t         rxb_mdh;        /* the portals memory descriptor (MD) handle */
        char                   *rxb_buffer;     /* the buffer */

};

enum kptl_tx_type
{
        TX_TYPE_RESERVED                = 0,
        TX_TYPE_SMALL_MESSAGE           = 1,
        TX_TYPE_PUT_REQUEST             = 2,
        TX_TYPE_GET_REQUEST             = 3,
        TX_TYPE_PUT_RESPONSE            = 4,
        TX_TYPE_GET_RESPONSE            = 5,
};

typedef union {
#ifdef _USING_LUSTRE_PORTALS_
        struct iovec iov[PTL_MD_MAX_IOV];
        lnet_kiov_t kiov[PTL_MD_MAX_IOV];
#else
        ptl_md_iovec_t iov[PTL_MD_MAX_IOV];
#endif
} kptl_fragvec_t;

typedef struct kptl_tx                           /* transmit message */
{
        struct list_head        tx_list;      /* queue on idle_txs etc */
        atomic_t                tx_refcount;  /* reference count*/
        enum kptl_tx_type       tx_type;      /* small msg/{put,get}{req,resp} */
        int                     tx_active:1;  /* queued on the peer */
        int                     tx_idle:1;    /* on the free list */
        kptl_eventarg_t         tx_msg_eventarg; /* event->md.user_ptr */
        kptl_eventarg_t         tx_rdma_eventarg; /* event->md.user_ptr */
        int                     tx_status;    /* the status of this tx descriptor */
        ptl_handle_md_t         tx_rdma_mdh;  /* RDMA buffer */
        ptl_handle_md_t         tx_msg_mdh;   /* the portals MD handle for the initial message */
        lnet_msg_t             *tx_lnet_msg;  /* LNET message to finalize */
        lnet_msg_t             *tx_lnet_replymsg; /* LNET reply message to finalize */
        kptl_msg_t             *tx_msg;       /* the message data */
        kptl_peer_t            *tx_peer;      /* the peer this is waiting on */
        unsigned long           tx_deadline;  /* deadline */
        ptl_md_t                tx_rdma_md;   /* rdma buffer */
        kptl_fragvec_t         *tx_rdma_frags; /* buffer fragments */
} kptl_tx_t;

enum kptllnd_peer_state
{
        PEER_STATE_UNINITIALIZED        = 0,
        PEER_STATE_ALLOCATED            = 1,
        PEER_STATE_WAITING_HELLO        = 2,
        PEER_STATE_ACTIVE               = 3,
        PEER_STATE_CLOSING              = 4,
        PEER_STATE_ZOMBIE               = 5,
};

struct kptl_peer
{
        struct list_head        peer_list;
        atomic_t                peer_refcount;          /* The current refrences */
        enum kptllnd_peer_state peer_state;
        spinlock_t              peer_lock;              /* serialize */
        struct list_head        peer_sendq;             /* txs waiting for mh handles */
        struct list_head        peer_activeq;           /* txs awaiting completion */
        lnet_nid_t              peer_nid;               /* Peer's LNET NID */
        ptl_process_id_t        peer_ptlid;             /* Peer's portals id */
        __u64                   peer_incarnation;       /* peer's incarnation */
        __u64                   peer_tx_seqnum;         /* next seq# to send with*/
        int                     peer_credits;           /* number of send credits */
        int                     peer_outstanding_credits;/* number of peer credits */
        __u64                   peer_next_matchbits;    /* Next value to use for tx desc matchbits */
        __u64                   peer_last_matchbits_seen; /* last matchbits seen*/
};

struct kptl_data
{
        int                     kptl_init;             /* initialisation state */
        volatile int            kptl_shutdown;         /* shut down? */
        atomic_t                kptl_nthreads;         /* # live threads */
        lnet_ni_t              *kptl_ni;               /* _the_ LND instance */
        ptl_handle_ni_t         kptl_nih;              /* network inteface handle */
        ptl_process_id_t        kptl_portals_id;       /* Portals ID of interface */
        __u64                   kptl_incarnation;      /* which one am I */
        ptl_handle_eq_t         kptl_eqh;              /* Event Queue (EQ) */

        spinlock_t              kptl_sched_lock;       /* serialise the next 3 members*/
        wait_queue_head_t       kptl_sched_waitq;      /* schedulers sleep here */
        struct list_head        kptl_sched_txq;        /* tx requiring attention */
        struct list_head        kptl_sched_rxq;        /* rx requiring attention */
        struct list_head        kptl_sched_rxbq;       /* rxb requiring reposting */

        wait_queue_head_t       kptl_watchdog_waitq;   /* watchdog sleeps here */

        kptl_rx_buffer_pool_t   kptl_rx_buffer_pool;   /* rx buffer pool */
        cfs_mem_cache_t*        kptl_rx_cache;         /* rx descripter cache */

        struct kptl_tx         *kptl_tx_descs;         /* the tx descriptors array */
        spinlock_t              kptl_tx_lock;          /* serialise idle tx list*/
        struct list_head        kptl_idle_txs;         /* idle tx descriptors */

        rwlock_t                kptl_peer_rw_lock;     /* lock for peer table */
        struct list_head       *kptl_peers;            /* hash table of all my known peers */
        struct list_head        kptl_closing_peers;    /* peers being closed */
        int                     kptl_peer_hash_size;   /* size of kptl_peers */
        int                     kptl_npeers;           /* # peers extant */
};

enum 
{
        PTLLND_INIT_NOTHING = 0,
        PTLLND_INIT_DATA,
        PTLLND_INIT_TXD,
        PTLLND_INIT_RXD,
        PTLLND_INIT_ALL,
};

extern kptl_tunables_t  kptllnd_tunables;
extern kptl_data_t      kptllnd_data;

static inline lnet_nid_t 
kptllnd_ptl2lnetnid(ptl_nid_t portals_nid)
{
#ifdef _USING_LUSTRE_PORTALS_
        return LNET_MKNID(LNET_NIDNET(kptllnd_data.kptl_ni->ni_nid), 
                          LNET_NIDADDR(portals_nid));
#else
	return LNET_MKNID(LNET_NIDNET(kptllnd_data.kptl_ni->ni_nid), 
                          portals_nid);
#endif
}

static inline ptl_nid_t kptllnd_lnet2ptlnid(lnet_nid_t lnet_nid)
{
#ifdef _USING_LUSTRE_PORTALS_
        return LNET_MKNID(LNET_NIDNET(kptllnd_data.kptl_portals_id.nid), 
                          LNET_NIDADDR(lnet_nid));
#else
	return LNET_NIDADDR(lnet_nid);
#endif
}

int  kptllnd_startup(lnet_ni_t *ni);
void kptllnd_shutdown(lnet_ni_t *ni);
int  kptllnd_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int  kptllnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int  kptllnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
                  int delayed, unsigned int niov, 
                  struct iovec *iov, lnet_kiov_t *kiov,
                  unsigned int offset, unsigned int mlen, unsigned int rlen);
int  kptllnd_eager_recv(struct lnet_ni *ni, void *private, 
                        lnet_msg_t *msg, void **new_privatep);
void kptllnd_eq_callback(ptl_event_t *evp);
int  kptllnd_scheduler(void *arg);
int  kptllnd_watchdog(void *arg);
int  kptllnd_thread_start(int (*fn)(void *arg), void *arg);
int  kptllnd_tunables_init(void);
void kptllnd_tunables_fini(void);

const char *kptllnd_evtype2str(int evtype);
const char *kptllnd_msgtype2str(int msgtype);

static inline void *
kptllnd_eventarg2obj (kptl_eventarg_t *eva)
{
        switch (eva->eva_type) {
        default:
                LBUG();
        case PTLLND_EVENTARG_TYPE_BUF:
                return list_entry(eva, kptl_rx_buffer_t, rxb_eventarg);
        case PTLLND_EVENTARG_TYPE_RDMA:
                return list_entry(eva, kptl_tx_t, tx_rdma_eventarg);
        case PTLLND_EVENTARG_TYPE_MSG:
                return list_entry(eva, kptl_tx_t, tx_msg_eventarg);
        }
}

/*
 * RX BUFFER SUPPORT FUNCTIONS
 */
void kptllnd_rx_buffer_pool_init(kptl_rx_buffer_pool_t *rxbp);
void kptllnd_rx_buffer_pool_fini(kptl_rx_buffer_pool_t *rxbp);
int  kptllnd_rx_buffer_pool_reserve(kptl_rx_buffer_pool_t *rxbp, int count);
void kptllnd_rx_buffer_pool_unreserve(kptl_rx_buffer_pool_t *rxbp, int count);
void kptllnd_rx_buffer_callback(ptl_event_t *ev);
void kptllnd_rx_buffer_post(kptl_rx_buffer_t *rxb);

static inline int
kptllnd_rx_buffer_size(void)
{
        return PAGE_SIZE * (*kptllnd_tunables.kptl_rxb_npages);
}

static inline void
kptllnd_rx_buffer_addref(kptl_rx_buffer_t *rxb)
{
        unsigned long flags;
        
        spin_lock_irqsave(&rxb->rxb_pool->rxbp_lock, flags);
        rxb->rxb_refcount++;
        spin_unlock_irqrestore(&rxb->rxb_pool->rxbp_lock, flags);
}

static inline void
kptllnd_rx_buffer_decref_locked(kptl_rx_buffer_t *rxb)
{
        if (--(rxb->rxb_refcount) == 0) {
                list_add_tail(&rxb->rxb_repost_list, 
                              &kptllnd_data.kptl_sched_rxbq);
                wake_up(&kptllnd_data.kptl_sched_waitq);
        }
}

static inline void
kptllnd_rx_buffer_decref(kptl_rx_buffer_t *rxb)
{
        unsigned long flags;
        
        spin_lock_irqsave(&rxb->rxb_pool->rxbp_lock, flags);
        kptllnd_rx_buffer_decref_locked(rxb);
        spin_unlock_irqrestore(&rxb->rxb_pool->rxbp_lock, flags);
}

/*
 * RX SUPPORT FUNCTIONS
 */
void kptllnd_rx_done(kptl_rx_t *rx);
void kptllnd_rx_parse(kptl_rx_t *rx);

/*
 * PEER SUPPORT FUNCTIONS
 */
void kptllnd_peer_destroy(kptl_peer_t *peer);
int  kptllnd_peer_del(lnet_nid_t nid);
void kptllnd_peer_close(kptl_peer_t *peer);
void kptllnd_handle_closing_peers(void);
int  kptllnd_peer_connect(kptl_tx_t *tx, lnet_nid_t nid);
void kptllnd_peer_check_sends(kptl_peer_t *peer);
void kptllnd_peer_check_bucket(int idx);
void kptllnd_tx_launch(kptl_tx_t *tx, lnet_process_id_t target);
kptl_peer_t *kptllnd_peer_handle_hello(ptl_process_id_t initiator,
                                       kptl_msg_t *msg);
kptl_peer_t *kptllnd_ptlnid2peer_locked(ptl_nid_t nid);

static inline void
kptllnd_peer_addref (kptl_peer_t *peer)
{
        atomic_inc(&peer->peer_refcount);
}

static inline void
kptllnd_peer_decref (kptl_peer_t *peer)
{
        if (atomic_dec_and_test(&peer->peer_refcount))
                kptllnd_peer_destroy(peer);
}

static inline void
kptllnd_set_tx_peer(kptl_tx_t *tx, kptl_peer_t *peer) 
{
        LASSERT (tx->tx_peer == NULL);
        
        kptllnd_peer_addref(peer);
        tx->tx_peer = peer;
}

static inline struct list_head *
kptllnd_ptlnid2peerlist(ptl_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) %
                            kptllnd_data.kptl_peer_hash_size;

        return &kptllnd_data.kptl_peers[hash];
}

static inline kptl_peer_t *
kptllnd_nid2peer_locked(lnet_nid_t nid)
{
        return kptllnd_ptlnid2peer_locked(kptllnd_lnet2ptlnid(nid));
}

static inline kptl_peer_t *
kptllnd_ptlnid2peer(ptl_nid_t nid)
{
        kptl_peer_t   *peer;
        unsigned long  flags;

        read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        peer = kptllnd_ptlnid2peer_locked(nid);
        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        return peer;
}

static inline kptl_peer_t *
kptllnd_nid2peer(lnet_nid_t nid)
{
        return kptllnd_ptlnid2peer(kptllnd_lnet2ptlnid(nid));
}

/*
 * TX SUPPORT FUNCTIONS
 */
int  kptllnd_setup_tx_descs(void);
void kptllnd_cleanup_tx_descs(void);
void kptllnd_tx_fini(kptl_tx_t *tx);
kptl_tx_t *kptllnd_get_idle_tx(enum kptl_tx_type purpose);
void kptllnd_tx_callback(ptl_event_t *ev);

static inline void
kptllnd_tx_addref(kptl_tx_t *tx)
{
        atomic_inc(&tx->tx_refcount);
}

static inline void 
kptllnd_tx_decref(kptl_tx_t *tx)
{
        LASSERT (!in_interrupt());        /* Thread context only */

        if (atomic_dec_and_test(&tx->tx_refcount))
                kptllnd_tx_fini(tx);
}

/*
 * MESSAGE SUPPORT FUNCTIONS
 */
void kptllnd_init_msg(kptl_msg_t *msg, int type, int body_nob);
void kptllnd_msg_pack(kptl_msg_t *msgp, int credits, lnet_nid_t dstnid,
                      __u64 dststamp, __u64 seq);
int  kptllnd_msg_unpack(kptl_msg_t *msg, int nob);

/*
 * MISC SUPPORT FUNCTIONS
 */
void kptllnd_init_rdma_md(kptl_tx_t *tx, unsigned int niov,
                          struct iovec *iov, lnet_kiov_t *kiov,
                          unsigned int offset, unsigned int nob);

#ifdef PJK_DEBUGGING
#define SIMULATION_FAIL_TX_PUT_ALLOC   0       /* 0x00000001 */
#define SIMULATION_FAIL_TX_GET_ALLOC   1       /* 0x00000002 */
#define SIMULATION_FAIL_TX             2       /* 0x00000004 */
#define SIMULATION_FAIL_RX_ALLOC       3       /* 0x00000008 */

#define IS_SIMULATION_ENABLED(x) \
        (((*kptllnd_tunables.kptl_simulation_bitmap) & 1<< SIMULATION_##x) != 0)
#else
#define IS_SIMULATION_ENABLED(x)       0
#endif

