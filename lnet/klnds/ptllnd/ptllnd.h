/*
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/ptllnd/ptllnd.h
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/uio.h>

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

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>
#include <lnet/lnet-sysctl.h>
#include <portals/p30.h>
#include <lnet/ptllnd.h>        /* Depends on portals/p30.h */

/*
 * Define this to enable console debug logging
 * and simulation
 */
//#define PJK_DEBUGGING

#ifdef CONFIG_SMP
# define PTLLND_N_SCHED         cfs_num_online_cpus()   /* # schedulers */
#else
# define PTLLND_N_SCHED         1                   /* # schedulers */
#endif

#define PTLLND_CREDIT_HIGHWATER ((*kptllnd_tunables.kptl_peertxcredits)-1)
  /* when eagerly to return credits */

typedef struct
{
        int             *kptl_ntx;              /* # tx descs to pre-allocate */
        int             *kptl_max_nodes;        /* max # nodes all talking to me */
        int             *kptl_max_procs_per_node; /* max # processes per node */
        int             *kptl_checksum;         /* checksum kptl_msg_t? */
        int             *kptl_timeout;          /* comms timeout (seconds) */
        int             *kptl_portal;           /* portal number */
        int             *kptl_pid;              /* portals PID (self + kernel peers) */
        int             *kptl_rxb_npages;       /* number of pages for rx buffer */
        int             *kptl_rxb_nspare;       /* number of spare rx buffers */
        int             *kptl_credits;          /* number of credits */
        int             *kptl_peertxcredits;    /* number of peer tx credits */
        int             *kptl_peerrtrcredits;   /* number of peer router credits */
        int             *kptl_max_msg_size;     /* max immd message size*/
        int             *kptl_peer_hash_table_size; /* # slots in peer hash table */
        int             *kptl_reschedule_loops; /* scheduler yield loops */
        int             *kptl_ack_puts;         /* make portals ack PUTs */
#ifdef PJK_DEBUGGING
        int             *kptl_simulation_bitmap;/* simulation bitmap */
#endif

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
        cfs_sysctl_table_header_t *kptl_sysctl; /* sysctl interface */
#endif
} kptl_tunables_t;

#include "lnet/ptllnd_wire.h"

/***********************************************************************/

typedef struct kptl_data kptl_data_t;
typedef struct kptl_net kptl_net_t;
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
        cfs_list_t              rx_list;        /* queue for attention */
        kptl_rx_buffer_t       *rx_rxb;         /* the rx buffer pointer */
        kptl_msg_t             *rx_msg;         /* received message */
        int                     rx_nob;         /* received message size */
        unsigned long           rx_treceived;   /* time received */
        ptl_process_id_t        rx_initiator;   /* sender's address */
        kptl_peer_t            *rx_peer;        /* pointer to peer */
        char                    rx_space[0];    /* copy of incoming request */
} kptl_rx_t;

#define PTLLND_POSTRX_DONT_POST    0            /* don't post */
#define PTLLND_POSTRX_NO_CREDIT    1            /* post: no credits */
#define PTLLND_POSTRX_PEER_CREDIT  2            /* post: give peer back 1 credit */

typedef struct kptl_rx_buffer_pool
{
        cfs_spinlock_t          rxbp_lock;
        cfs_list_t              rxbp_list;      /* all allocated buffers */
        int                     rxbp_count;     /* # allocated buffers */
        int                     rxbp_reserved;  /* # requests to buffer */
        int                     rxbp_shutdown;  /* shutdown flag */
} kptl_rx_buffer_pool_t;

struct kptl_rx_buffer
{
        kptl_rx_buffer_pool_t *rxb_pool;
        cfs_list_t             rxb_list;       /* for the rxb_pool list */
        cfs_list_t             rxb_repost_list;/* for the kptl_sched_rxbq list */
        int                    rxb_posted:1;   /* on the net */
        int                    rxb_idle:1;     /* all done */
        kptl_eventarg_t        rxb_eventarg;   /* event->md.user_ptr */
        int                    rxb_refcount;   /* reference count */
        ptl_handle_md_t        rxb_mdh;        /* the portals memory descriptor (MD) handle */
        char                  *rxb_buffer;     /* the buffer */

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
        cfs_list_t              tx_list;      /* queue on idle_txs etc */
        cfs_atomic_t            tx_refcount;  /* reference count*/
        enum kptl_tx_type       tx_type;      /* small msg/{put,get}{req,resp} */
        int                     tx_active:1;  /* queued on the peer */
        int                     tx_idle:1;    /* on the free list */
        int                     tx_acked:1;   /* portals ACK wanted (for debug only) */
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
        unsigned long           tx_tposted;   /* time posted */
        ptl_md_t                tx_rdma_md;   /* rdma descriptor */
        kptl_fragvec_t         *tx_frags;     /* buffer fragments */
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
        cfs_list_t              peer_list;
        cfs_atomic_t            peer_refcount;          /* The current references */
        enum kptllnd_peer_state peer_state;
        cfs_spinlock_t          peer_lock;              /* serialize */
        cfs_list_t              peer_noops;             /* PTLLND_MSG_TYPE_NOOP txs */
        cfs_list_t              peer_sendq;             /* txs waiting for mh handles */
        cfs_list_t              peer_activeq;           /* txs awaiting completion */
        lnet_process_id_t       peer_id;                /* Peer's LNET id */
        ptl_process_id_t        peer_ptlid;             /* Peer's portals id */
        __u64                   peer_incarnation;       /* peer's incarnation */
        __u64                   peer_myincarnation;     /* my incarnation at HELLO */
        int                     peer_sent_hello;        /* have I sent HELLO? */
        int                     peer_credits;           /* number of send credits */
        int                     peer_outstanding_credits;/* number of peer credits to return */
        int                     peer_sent_credits;      /* #msg buffers posted for peer */
        int                     peer_max_msg_size;      /* peer's rx buffer size */
        int                     peer_error;             /* errno on closing this peer */
        int                     peer_retry_noop;        /* need to retry returning credits */
        int                     peer_check_stamp;       /* watchdog check stamp */
        cfs_time_t              peer_last_alive;        /* when (in jiffies) I was last alive */
        __u64                   peer_next_matchbits;    /* Next value to register RDMA from peer */
        __u64                   peer_last_matchbits_seen; /* last matchbits used to RDMA to peer */
};

struct kptl_data
{
        int                     kptl_init;             /* initialisation state */
        volatile int            kptl_shutdown;         /* shut down? */
        cfs_atomic_t            kptl_nthreads;         /* # live threads */
        ptl_handle_ni_t         kptl_nih;              /* network inteface handle */
        ptl_process_id_t        kptl_portals_id;       /* Portals ID of interface */
        __u64                   kptl_incarnation;      /* which one am I */
        ptl_handle_eq_t         kptl_eqh;              /* Event Queue (EQ) */

        cfs_rwlock_t            kptl_net_rw_lock;      /* serialise... */
        cfs_list_t              kptl_nets;             /* kptl_net instances */

        cfs_spinlock_t          kptl_sched_lock;       /* serialise... */
        cfs_waitq_t             kptl_sched_waitq;      /* schedulers sleep here */
        cfs_list_t              kptl_sched_txq;        /* tx requiring attention */
        cfs_list_t              kptl_sched_rxq;        /* rx requiring attention */
        cfs_list_t              kptl_sched_rxbq;       /* rxb requiring reposting */

        cfs_waitq_t             kptl_watchdog_waitq;   /* watchdog sleeps here */

        kptl_rx_buffer_pool_t   kptl_rx_buffer_pool;   /* rx buffer pool */
        cfs_mem_cache_t*        kptl_rx_cache;         /* rx descripter cache */

        cfs_atomic_t            kptl_ntx;              /* # tx descs allocated */
        cfs_spinlock_t          kptl_tx_lock;          /* serialise idle tx list*/
        cfs_list_t              kptl_idle_txs;         /* idle tx descriptors */

        cfs_rwlock_t            kptl_peer_rw_lock;     /* lock for peer table */
        cfs_list_t             *kptl_peers;            /* hash table of all my known peers */
        cfs_list_t              kptl_closing_peers;    /* peers being closed */
        cfs_list_t              kptl_zombie_peers;     /* peers waiting for refs to drain */
        int                     kptl_peer_hash_size;   /* size of kptl_peers */
        int                     kptl_npeers;           /* # peers extant */
        int                     kptl_n_active_peers;   /* # active peers */
        int                     kptl_expected_peers;   /* # peers I can buffer HELLOs from */

        kptl_msg_t             *kptl_nak_msg;          /* common NAK message */
        cfs_spinlock_t          kptl_ptlid2str_lock;   /* serialise str ops */
};

struct kptl_net
{
        cfs_list_t        net_list;      /* chain on kptl_data:: kptl_nets */
        lnet_ni_t        *net_ni;
        cfs_atomic_t      net_refcount;  /* # current references */
        int               net_shutdown;  /* lnd_shutdown called */
};

enum 
{
        PTLLND_INIT_NOTHING = 0,
        PTLLND_INIT_DATA,
        PTLLND_INIT_ALL,
};

extern kptl_tunables_t  kptllnd_tunables;
extern kptl_data_t      kptllnd_data;

static inline lnet_nid_t 
kptllnd_ptl2lnetnid(lnet_nid_t ni_nid, ptl_nid_t ptl_nid)
{
#ifdef _USING_LUSTRE_PORTALS_
        return LNET_MKNID(LNET_NIDNET(ni_nid), LNET_NIDADDR(ptl_nid));
#else
        return LNET_MKNID(LNET_NIDNET(ni_nid), ptl_nid);
#endif
}

static inline ptl_nid_t 
kptllnd_lnet2ptlnid(lnet_nid_t lnet_nid)
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
void kptllnd_query (struct lnet_ni *ni, lnet_nid_t nid, cfs_time_t *when);
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
const char *kptllnd_errtype2str(int errtype);

static inline void *
kptllnd_eventarg2obj (kptl_eventarg_t *eva)
{
        switch (eva->eva_type) {
        default:
                LBUG();
        case PTLLND_EVENTARG_TYPE_BUF:
                return cfs_list_entry(eva, kptl_rx_buffer_t, rxb_eventarg);
        case PTLLND_EVENTARG_TYPE_RDMA:
                return cfs_list_entry(eva, kptl_tx_t, tx_rdma_eventarg);
        case PTLLND_EVENTARG_TYPE_MSG:
                return cfs_list_entry(eva, kptl_tx_t, tx_msg_eventarg);
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

        cfs_spin_lock_irqsave(&rxb->rxb_pool->rxbp_lock, flags);
        rxb->rxb_refcount++;
        cfs_spin_unlock_irqrestore(&rxb->rxb_pool->rxbp_lock, flags);
}

static inline void
kptllnd_rx_buffer_decref_locked(kptl_rx_buffer_t *rxb)
{
        if (--(rxb->rxb_refcount) == 0) {
                cfs_spin_lock(&kptllnd_data.kptl_sched_lock);

                cfs_list_add_tail(&rxb->rxb_repost_list,
                                  &kptllnd_data.kptl_sched_rxbq);
                cfs_waitq_signal(&kptllnd_data.kptl_sched_waitq);

                cfs_spin_unlock(&kptllnd_data.kptl_sched_lock);
        }
}

static inline void
kptllnd_rx_buffer_decref(kptl_rx_buffer_t *rxb)
{
        unsigned long flags;
        int           count;

        cfs_spin_lock_irqsave(&rxb->rxb_pool->rxbp_lock, flags);
        count = --(rxb->rxb_refcount);
        cfs_spin_unlock_irqrestore(&rxb->rxb_pool->rxbp_lock, flags);

        if (count == 0)
                kptllnd_rx_buffer_post(rxb);
}

/*
 * RX SUPPORT FUNCTIONS
 */
void kptllnd_rx_parse(kptl_rx_t *rx);
void kptllnd_rx_done(kptl_rx_t *rx, int post_credit);

/*
 * PEER SUPPORT FUNCTIONS
 */
int kptllnd_get_peer_info(int index,
                          lnet_process_id_t *id, 
                          int *state, int *sent_hello,
                          int *refcount, __u64 *incarnation,
                          __u64 *next_matchbits, __u64 *last_matchbits_seen,
                          int *nsendq, int *nactiveq,
                          int *credits, int *outstanding_credits);
void kptllnd_peer_destroy(kptl_peer_t *peer);
int  kptllnd_peer_del(lnet_process_id_t id);
void kptllnd_peer_close_locked(kptl_peer_t *peer, int why);
void kptllnd_peer_close(kptl_peer_t *peer, int why);
void kptllnd_handle_closing_peers(void);
int  kptllnd_peer_connect(kptl_tx_t *tx, lnet_nid_t nid);
void kptllnd_peer_check_sends(kptl_peer_t *peer);
void kptllnd_peer_check_bucket(int idx, int stamp);
void kptllnd_tx_launch(kptl_peer_t *peer, kptl_tx_t *tx, int nfrag);
int  kptllnd_find_target(kptl_net_t *net, lnet_process_id_t target,
                         kptl_peer_t **peerp);
kptl_peer_t *kptllnd_peer_handle_hello(kptl_net_t *net,
                                       ptl_process_id_t initiator,
                                       kptl_msg_t *msg);
kptl_peer_t *kptllnd_id2peer_locked(lnet_process_id_t id);
void kptllnd_peer_alive(kptl_peer_t *peer);

static inline void
kptllnd_peer_addref (kptl_peer_t *peer)
{
        cfs_atomic_inc(&peer->peer_refcount);
}

static inline void
kptllnd_peer_decref (kptl_peer_t *peer)
{
        if (cfs_atomic_dec_and_test(&peer->peer_refcount))
                kptllnd_peer_destroy(peer);
}

static inline void
kptllnd_net_addref (kptl_net_t *net)
{
        LASSERT (cfs_atomic_read(&net->net_refcount) > 0);
        cfs_atomic_inc(&net->net_refcount);
}

static inline void
kptllnd_net_decref (kptl_net_t *net)
{
        LASSERT (cfs_atomic_read(&net->net_refcount) > 0);
        cfs_atomic_dec(&net->net_refcount);
}

static inline void
kptllnd_set_tx_peer(kptl_tx_t *tx, kptl_peer_t *peer)
{
        LASSERT (tx->tx_peer == NULL);

        kptllnd_peer_addref(peer);
        tx->tx_peer = peer;
}

static inline cfs_list_t *
kptllnd_nid2peerlist(lnet_nid_t nid)
{
        /* Only one copy of peer state for all logical peers, so the net part
         * of NIDs is ignored; e.g. A@ptl0 and A@ptl2 share peer state */
        unsigned int hash = ((unsigned int)LNET_NIDADDR(nid)) %
                            kptllnd_data.kptl_peer_hash_size;

        return &kptllnd_data.kptl_peers[hash];
}

static inline kptl_peer_t *
kptllnd_id2peer(lnet_process_id_t id)
{
        kptl_peer_t   *peer;
        unsigned long  flags;

        cfs_read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        peer = kptllnd_id2peer_locked(id);
        cfs_read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        return peer;
}

static inline int
kptllnd_reserve_buffers(int n)
{
        return kptllnd_rx_buffer_pool_reserve(&kptllnd_data.kptl_rx_buffer_pool,
                                              n);
}

static inline int
kptllnd_peer_reserve_buffers(void)
{
        return kptllnd_reserve_buffers(*kptllnd_tunables.kptl_peertxcredits);
}

static inline void
kptllnd_peer_unreserve_buffers(void)
{
        kptllnd_rx_buffer_pool_unreserve(&kptllnd_data.kptl_rx_buffer_pool,
                                         *kptllnd_tunables.kptl_peertxcredits);
}

/*
 * TX SUPPORT FUNCTIONS
 */
int  kptllnd_setup_tx_descs(void);
void kptllnd_cleanup_tx_descs(void);
void kptllnd_tx_fini(kptl_tx_t *tx);
void kptllnd_cancel_txlist(cfs_list_t *peerq, cfs_list_t *txs);
void kptllnd_restart_txs(kptl_net_t *net, lnet_process_id_t id,
                         cfs_list_t *restarts);
kptl_tx_t *kptllnd_get_idle_tx(enum kptl_tx_type purpose);
void kptllnd_tx_callback(ptl_event_t *ev);
const char *kptllnd_tx_typestr(int type);

static inline void
kptllnd_tx_addref(kptl_tx_t *tx)
{
        cfs_atomic_inc(&tx->tx_refcount);
}

static inline void
kptllnd_tx_decref(kptl_tx_t *tx)
{
        LASSERT (!cfs_in_interrupt());        /* Thread context only */

        if (cfs_atomic_dec_and_test(&tx->tx_refcount))
                kptllnd_tx_fini(tx);
}

/*
 * MESSAGE SUPPORT FUNCTIONS
 */
void kptllnd_init_msg(kptl_msg_t *msg, int type,
                      lnet_process_id_t target, int body_nob);
void kptllnd_msg_pack(kptl_msg_t *msg, kptl_peer_t *peer);
int  kptllnd_msg_unpack(kptl_msg_t *msg, int nob);

/*
 * MISC SUPPORT FUNCTIONS
 */
void kptllnd_init_rdma_md(kptl_tx_t *tx, unsigned int niov,
                          struct iovec *iov, lnet_kiov_t *kiov,
                          unsigned int offset, unsigned int nob);
char *kptllnd_ptlid2str(ptl_process_id_t id);

void kptllnd_init_ptltrace(void);
void kptllnd_dump_ptltrace(void);

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
