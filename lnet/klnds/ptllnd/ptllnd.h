/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
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
#include <linux/random.h>

#include <net/sock.h>
#include <linux/in.h>


#define DEBUG_SUBSYSTEM S_NAL

#include <libcfs/kp30.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>
#include <portals/p30.h>

/*
 * The PTLLND was designed to support Portals with
 * Lustre and non-lustre UNLINK semantics.
 * However for now the two targets are Cray Portals
 * on the XT3 and Lustre Portals (for testing) both
 * have Lustre UNLINK semantics, so this is defined
 * by default.
 */
#define LUSTRE_PORTALS_UNLINK_SEMANTICS


/*
 * Define this to enable console debug logging
 * and simulation
 */
//#define PJK_DEBUGGING

/*
 * This was used for some single node testing
 * which has some hacks to allow packets that come
 * back on the lookback LND to have their address
 * fixed up, so that match MD's properly.  And you
 * can setup a connection with your self and transfer data.
 * WARNING: This was for UNIT testing purposes only.
 */
//#define TESTING_WITH_LOOPBACK

#ifdef _USING_LUSTRE_PORTALS_
#define FMT_NID LPX64
#else /* _USING_CRAY_PORTALS_ */
#define FMT_NID "%x"
#define ptl_err_t ptl_ni_fail_t
#define PtlHandleIsEqual(a,b) (a == b)
#endif

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
#define PTLLND_CREDITS          128        /* concurrent sends */
#define PTLLND_PEER_HASH_SIZE   101        /* # of buckets in peer hash table */

/* tunables fixed at compile time */
#define PTLLND_CREDIT_HIGHWATER (*kptllnd_tunables.kptl_peercredits-1)  /* when to eagerly return credits */
#define PTLLND_TIMEOUT_SEC      3          /* How often we check a subset of the peer hash table for timeout*/

typedef struct
{
        int             *kptl_ntx;              /* # tx descs */
        int             *kptl_concurrent_peers; /* max # nodes all talking to me */
        int             *kptl_cksum;            /* checksum kptl_msg_t? */
        int             *kptl_timeout;          /* comms timeout (seconds) */
        int             *kptl_portal;           /* portal number */
        int             *kptl_rxb_npages;       /* number of pages for rx buffer */
        int             *kptl_credits;          /* number of credits */
        int             *kptl_peercredits;      /* number of credits */
        int             *kptl_max_immd_size;    /* max immd message size*/
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

#define POSTED_OBJECT_TYPE_RESERVED     0
#define POSTED_OBJECT_TYPE_TX           1
#define POSTED_OBJECT_TYPE_RXB          2

typedef struct
{
        __u32 pof_type : 2;
}kptl_posted_object_flags_t;

typedef struct kptl_posted_object
{
        kptl_data_t                    *po_kptllnd_data; /* LND Instance Data */
        kptl_posted_object_flags_t      po_flags;        /* flags and state   */
} kptl_posted_object_t;

typedef struct kptl_rx                          /* receive message */
{
        struct list_head        rx_list;        /* queue for attention */
        atomic_t                rx_refcount;
        kptl_rx_buffer_t       *rx_rxb;         /* the rx buffer pointer */
        kptl_msg_t             *rx_msg;
        int                     rx_nob;         /* the number of bytes rcvd */
        ptl_process_id_t        rx_initiator;   /* who send the packet */
        kptl_peer_t            *rx_peer;        /* pointer to peer */
        size_t                  rx_payload[0];  /* payload QQQ*/
} kptl_rx_t;

typedef struct kptl_rx_buffer_pool
{
        spinlock_t              rxbp_lock;
        struct list_head        rxbp_list;
        int                     rxbp_count;     /* the number of elements in the list   */
        int                     rxbp_reserved;  /* the number currently reserved        */
        int                     rxbp_shutdown;  /* the shutdown flag for the pool       */
        int                     rxbp_posted;    /* the number of elements posted        */
}kptl_rx_buffer_pool_t;

typedef enum
{
        RXB_STATE_UNINITIALIZED  = 0,
        RXB_STATE_IDLE           = 1,
        RXB_STATE_POSTED         = 2,
}kptl_rxb_state_t;

struct kptl_rx_buffer
{
        /* NB - becuase this buffer is assigned to a MD's usr_ptr
         * It MUST have kptl_posted_object_t as the first member
         * so that the real type of the element can be determined
         */
        kptl_posted_object_t    rxb_po;
        kptl_rx_buffer_pool_t  *rxb_pool;
        struct list_head        rxb_list;       /* for the rxb_pool list */
        struct list_head        rxb_repost_list;/* for the kptl_sched_rxbq list*/
        kptl_rxb_state_t        rxb_state;      /* the state of this rx buffer*/
        atomic_t                rxb_refcount;   /* outstanding rx */
        ptl_handle_md_t         rxb_mdh;        /* the portals memory descriptor (MD) handle */
        void                   *rxb_buffer;     /* the buffer */

};

typedef enum
{
        TX_STATE_UNINITIALIZED          = 0,
        TX_STATE_ON_IDLE_QUEUE          = 1,
        TX_STATE_ALLOCATED              = 2,
        TX_STATE_WAITING_CREDITS        = 3,
        TX_STATE_WAITING_RESPONSE       = 4
}kptl_tx_state_t;

typedef enum
{
        TX_TYPE_RESERVED                = 0,
        TX_TYPE_SMALL_MESSAGE           = 1,
        TX_TYPE_LARGE_PUT               = 2,
        TX_TYPE_LARGE_GET               = 3,
        TX_TYPE_LARGE_PUT_RESPONSE      = 4,
        TX_TYPE_LARGE_GET_RESPONSE      = 5,
}kptl_tx_type_t;

typedef struct kptl_tx                           /* transmit message */
{
        /* NB - becuase this buffer is assigned to a MD's usr_ptr
         * It MUST have kptl_posted_object_t as the first member
         * so that the real type of the element can be determined
         */
        kptl_posted_object_t    tx_po;
        struct list_head        tx_list;      /* queue on idle_txs ibc_tx_queue etc. */
        struct list_head        tx_schedlist; /* queue on idle_txs ibc_tx_queue etc. */
        atomic_t                tx_refcount;  /* Posted Buffer refrences count*/
        kptl_tx_state_t         tx_state;     /* the state of this tx descriptor */
        int                     tx_seen_send_end; /* if we've seen a SEND_END event */
        int                     tx_seen_reply_end; /* if we've seen a REPLY_END event */
        kptl_tx_type_t          tx_type;      /* type of transfer */
        int                     tx_status;    /* the status of this tx descriptor */
        ptl_handle_md_t         tx_mdh;       /* the portals memory descriptor (MD) handle */
        ptl_handle_md_t         tx_mdh_msg;   /* the portals MD handle for the initial message */
        lnet_msg_t             *tx_ptlmsg;    /* the cookie for finalize */
        lnet_msg_t             *tx_ptlmsg_reply; /* the cookie for the reply message */
        kptl_msg_t             *tx_msg;       /* the message data */
        kptl_peer_t            *tx_peer;      /* the peer this is waiting on */
        unsigned long           tx_deadline;  /* deadline */
        kptl_rx_t              *tx_associated_rx; /* Associated RX for Bulk RDMA */

        unsigned int            tx_payload_niov;
        struct iovec           *tx_payload_iov;
        lnet_kiov_t            *tx_payload_kiov;
        unsigned int            tx_payload_offset;
        int                     tx_payload_nob;

} kptl_tx_t;


typedef enum
{
        PEER_STATE_UNINITIALIZED        = 0,
        PEER_STATE_WAITING_HELLO        = 1,
        PEER_STATE_ACTIVE               = 2,
        PEER_STATE_CANCELED             = 3,
}kptllnd_peer_state_t;

struct kptl_peer
{
        struct list_head        peer_list;
        atomic_t                peer_refcount;          /* The current refrences */
        kptllnd_peer_state_t    peer_state;
        kptl_data_t            *peer_kptllnd_data;      /* LND Instance Data */
        spinlock_t              peer_lock;              /* serialize */
        struct list_head        peer_pending_txs;       /* queue of pending txs */
        struct list_head        peer_active_txs;        /* queue of activce txs */
        int                     peer_active_txs_change_counter;/* updated when peer_active_txs changes*/
        lnet_nid_t              peer_nid;               /* who's on the other end(s) */
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

        kptl_rx_buffer_pool_t   kptl_rx_buffer_pool;   /* rx buffer pool */
        cfs_mem_cache_t*        kptl_rx_cache;         /* rx descripter cache */

        struct kptl_tx         *kptl_tx_descs;         /* the tx descriptors array */
        spinlock_t              kptl_tx_lock;          /* serialise the next 4 members*/
        struct list_head        kptl_idle_txs;         /* idle tx descriptors */

        rwlock_t                kptl_peer_rw_lock;     /* lock for peer table */
        struct list_head       *kptl_peers;            /* hash table of all my known peers */
        struct list_head        kptl_canceled_peers;   /* peers in the canceld state */
        int                     kptl_canceled_peers_counter; /* updated when canceled_peers is modified*/
        int                     kptl_peer_hash_size;   /* size of kptl_peers */
        atomic_t                kptl_npeers;           /* # peers extant */

};

typedef struct kptl_stats
{
        int                     kps_incoming_checksums_calculated;
        int                     kps_incoming_checksums_invalid;
        int                     kps_cleaning_caneled_peers;     /* MP Safe*/
        int                     kps_checking_buckets;
        int                     kps_too_many_peers;             /* MP Safe*/
        int                     kps_peers_created;              /* MP Safe*/
        int                     kps_no_credits;
        int                     kps_saving_last_credit;
        int                     kps_rx_allocated;
        int                     kps_rx_released;
        int                     kps_rx_allocation_failed;
        int                     kps_tx_allocated;
        int                     kps_tx_released;               /* MP Safe*/
        int                     kpt_tx_allocation_failed;
        int                     kps_recv_delayed;
        int                     kps_send_routing;
        int                     kps_send_target_is_router;
        int                     kpt_send_put;
        int                     kps_send_get;
        int                     kps_send_immd;
        int                     kps_send_reply;
        int                     kpt_send_reply_routed;
}kptl_stats_t;

/*
 * Note: Stats update are not atomic (for performance reasons)
 * and therefore not MP safe.  They are more an indiciation of
 * things that are going on, as opposed to a actual count.
 *
 * (e.g. if kps_checking_buckets wasn't incrementing at some
 *  number per second, that would be an indication that the
 *  scheduler thread is stuck or stopped)
 *
 * However where possible the update of the stats are placed inside
 * a spinlock to make them consistent, these are marked MP Safe above.
 *
 */
#define STAT_UPDATE(n) do{ ++kptllnd_stats.n; }while(0)


enum
{
    PTLLND_INIT_NOTHING     = 0,
    PTLLND_INIT_DATA        = 1,
    PTLLND_INIT_TXD         = 2,
    PTLLND_INIT_RXD         = 3,
    PTLLND_INIT_ALL         = 4,
};


extern kptl_tunables_t  kptllnd_tunables;
extern kptl_stats_t     kptllnd_stats;

int kptllnd_startup (
        lnet_ni_t *ni);

void kptllnd_shutdown (
        lnet_ni_t *ni);

int kptllnd_ctl(
        lnet_ni_t *ni,
        unsigned int cmd,
        void *arg);

int kptllnd_send (
        lnet_ni_t *ni,
        void *private,
        lnet_msg_t *lntmsg);

int kptllnd_recv (
        lnet_ni_t *ni,
        void *private,
        lnet_msg_t *lntmsg,
        int delayed,
        unsigned int niov,
        struct iovec *iov,
        lnet_kiov_t *kiov,
        unsigned int offset,
        unsigned int mlen,
        unsigned int rlen);

void kptllnd_eq_callback(
        ptl_event_t *evp);

int  kptllnd_scheduler(
        void *arg);

int  kptllnd_thread_start(
        int (*fn)(void *arg),
        int id,
        kptl_data_t *kptllnd_data);

int  kptllnd_tunables_init(void);
void kptllnd_tunables_fini(void);
void kptllnd_proc_init(void);
void kptllnd_proc_fini(void);

const char *get_ev_type_string(
        int evtype);

const char *get_msg_type_string(
        int type);

kptl_stats_t* kpttllnd_get_stats(void);

void
kptllnd_posted_object_setup(
        kptl_posted_object_t* posted_obj,
        kptl_data_t *kptllnd_data,
        int type);

/*
 * RX BUFFER SUPPORT FUNCTIONS
 */

void
kptllnd_rx_buffer_pool_init(
        kptl_rx_buffer_pool_t *rxbp);

void
kptllnd_rx_buffer_pool_fini(
        kptl_rx_buffer_pool_t *rxbp);

int
kptllnd_rx_buffer_pool_reserve(
        kptl_rx_buffer_pool_t *rxbp,
        kptl_data_t *kptllnd_data,
        int count);

void
kptllnd_rx_buffer_pool_unreserve(
        kptl_rx_buffer_pool_t *rxbp,
        int count);

void
kptllnd_rx_buffer_callback(
        ptl_event_t *ev);

void
kptllnd_rx_buffer_scheduled_post(
        kptl_rx_buffer_t *rxb);

void
kptllnd_rx_buffer_post_handle_error(
        kptl_rx_buffer_t *rxb);

void
kptllnd_rx_buffer_decref(
        kptl_rx_buffer_t *rxb,
        const char *owner);

/*
 * RX SUPPORT FUNCTIONS
 */
void
kptllnd_rx_scheduler_handler(
        kptl_rx_t *rx);

void
kptllnd_rx_addref(
        kptl_rx_t *rx,
        const char *owner);

void
kptllnd_rx_decref(
        kptl_rx_t *rx,
        const char *owner,
        kptl_data_t *kptllnd_data);

/*
 * PEER SUPPORT FUNCTIONS
 */
void
kptllnd_peer_decref (
        kptl_peer_t *peer,
        const char *owner);
void
kptllnd_peer_addref (
        kptl_peer_t *peer,
        const char *owner);

int
kptllnd_peer_del (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid);

void
kptllnd_peer_cancel(
        kptl_peer_t *peer);

void
kptllnd_peer_queue_bulk_rdma_tx_locked(
        kptl_peer_t *peer,
        kptl_tx_t *tx);

void
kptllnd_peer_dequeue_tx(
        kptl_peer_t *peer,
        kptl_tx_t *tx);
void
kptllnd_peer_dequeue_tx_locked(
        kptl_peer_t *peer,
        kptl_tx_t *tx);

int
kptllnd_peer_connect (
        kptl_tx_t *tx,
        lnet_nid_t nid );

void
kptllnd_peer_check_sends (
        kptl_peer_t *peer );
void
kptllnd_peer_check_bucket (
        int idx,
        kptl_data_t *kptllnd_data);

void
kptllnd_tx_launch (
        kptl_tx_t *tx,
        lnet_nid_t target_nid,
        lnet_msg_t *ptlmsg );

kptl_peer_t *
kptllnd_peer_find (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid);

kptl_peer_t *
kptllnd_peer_handle_hello (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid,
        kptl_msg_t *msg);

static inline struct list_head *
kptllnd_nid2peerlist (kptl_data_t *kptllnd_data,lnet_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) % kptllnd_data->kptl_peer_hash_size;

        return (&kptllnd_data->kptl_peers [hash]);
}

/*
 * TX SUPPORT FUNCTIONS
 */
int
kptllnd_setup_tx_descs (
        kptl_data_t *kptllnd_data);

void
kptllnd_cleanup_tx_descs(
        kptl_data_t *kptllnd_data);

void
kptllnd_tx_addref(
        kptl_tx_t *tx);
void
kptllnd_tx_decref(
        kptl_tx_t *tx);
void
kptllnd_tx_scheduled_decref(
        kptl_tx_t *tx);
void
kptllnd_tx_done (
        kptl_tx_t *tx);
kptl_tx_t *
kptllnd_get_idle_tx(
        kptl_data_t *kptllnd_data,
        kptl_tx_type_t purpose);

void
kptllnd_tx_callback(
        ptl_event_t *ev);

/*
 * MESSAGE SUPPORT FUNCTIONS
 */
void
kptllnd_init_msg(
        kptl_msg_t *msg,
        int type,
        int body_nob);

void
kptllnd_msg_pack(
        kptl_msg_t *msgp,
        int credits,
        lnet_nid_t dstnid,
        __u64 dststamp,
        __u64 seq,
        kptl_data_t *kptllnd_data);

int
kptllnd_msg_unpack(
        kptl_msg_t *msg,
        int nob,
        kptl_data_t *kptllnd_data);

/*
 * MISC SUPPORT FUNCTIONS
 */


typedef union {
        struct iovec iov[PTL_MD_MAX_IOV];
#ifdef _USING_LUSTRE_PORTALS_
        ptl_kiov_t kiov[PTL_MD_MAX_IOV];
#endif
}tempiov_t;


void
kptllnd_setup_md(
        kptl_data_t     *kptllnd_data,
        ptl_md_t        *md,
        unsigned int     op,
        kptl_tx_t       *tx,
        unsigned int     payload_niov,
        struct iovec    *payload_iov,
        lnet_kiov_t     *payload_kiov,
        unsigned int     payload_offset,
        int              payload_nob,
        tempiov_t       *tempiov);

int kptllnd_process_scheduled_tx(kptl_data_t *kptllnd_data);
int kptllnd_process_scheduled_rx(kptl_data_t *kptllnd_data);
int kptllnd_process_scheduled_rxb(kptl_data_t *kptllnd_data);

static inline lnet_nid_t ptl2lnetnid(kptl_data_t *kptllnd_data,ptl_nid_t portals_nid)
{
#ifdef _USING_LUSTRE_PORTALS_
        return PTL_MKNID(PTL_NIDNET(kptllnd_data->kptl_ni->ni_nid),   PTL_NIDADDR(portals_nid) );
#else /* _USING_CRAY_PORTALS_ */
	return PTL_MKNID(PTL_NIDNET(kptllnd_data->kptl_ni->ni_nid), portals_nid);
#endif
}

static inline ptl_nid_t lnet2ptlnid(kptl_data_t *kptllnd_data,lnet_nid_t lnet_nid)
{
#ifdef _USING_LUSTRE_PORTALS_
        return PTL_MKNID(PTL_NIDNET(kptllnd_data->kptl_portals_id.nid), PTL_NIDADDR(lnet_nid) );
#else /* _USING_CRAY_PORTALS_ */
	return PTL_NIDADDR(lnet_nid);
#endif
}

#ifdef PJK_DEBUGGING

#define PJK_UT_MSG_ALWAYS(fmt, a...)                    \
do{                                                     \
        printk("<1>ptllnd:%-30s:%u:",__FUNCTION__,cfs_curproc_pid());       \
        printk(fmt,## a);                               \
        CDEBUG(D_TRACE,fmt,## a);                       \
}while(0)

#define PJK_UT_MSG_SIMULATION(fmt, a...)        PJK_UT_MSG_ALWAYS(fmt, ## a )


#if 1
#define PJK_UT_MSG_DATA(fmt, a...)              PJK_UT_MSG_ALWAYS(fmt, ## a )
#else
#define PJK_UT_MSG_DATA(fmt, a...)              do{}while(0)
#endif

#if 1
#define PJK_UT_MSG(fmt, a...)                   PJK_UT_MSG_ALWAYS(fmt, ## a )
#else
#define PJK_UT_MSG(fmt, a...)                   do{}while(0)
#endif


#define SIMULATION_FAIL_BLOCKING_TX_PUT_ALLOC   0       /* 0x00000001 */
#define SIMULATION_FAIL_BLOCKING_TX_GET_ALLOC   1       /* 0x00000002 */
#define SIMULATION_FAIL_BLOCKING_TX             2       /* 0x00000004 */
#define SIMULATION_FAIL_BLOCKING_RX_ALLOC       3       /* 0x00000008 */

#define IS_SIMULATION_ENABLED(x) \
        (((*kptllnd_tunables.kptl_simulation_bitmap) & 1<< SIMULATION_##x) != 0)


#else


#define PJK_UT_MSG_ALWAYS(fmt, a...)            do{}while(0)
#define PJK_UT_MSG_SIMULATION(fmt, a...)        do{}while(0)
#define PJK_UT_MSG_DATA(fmt, a...)              do{}while(0)
#define PJK_UT_MSG(fmt, a...)                   do{}while(0)

#define IS_SIMULATION_ENABLED(x)                0

#endif

