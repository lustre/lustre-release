/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: Eric Barton <eeb@bartonsoftware.com>
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


#define DEBUG_SUBSYSTEM S_LND

#include <lnet/lib-lnet.h>
#include <lnet/ptllnd_wire.h>

#include <portals/p30.h>
#include <lnet/ptllnd.h>           /* Depends on portals/p30.h */

#define PTLLND_DEBUG_TIMING 0

#define PTLLND_MSGS_PER_BUFFER     64
#define PTLLND_MSGS_SPARE          256
#define PTLLND_PEER_HASH_SIZE      101
#define PTLLND_EQ_SIZE             1024
#if PTLLND_DEBUG_TIMING
# define PTLLND_TX_HISTORY         1024
#else
# define PTLLND_TX_HISTORY         0
#endif
#define PTLLND_WARN_LONG_WAIT      5 /* seconds */
#define PTLLND_ABORT_ON_NAK        1 /* abort app on protocol version mismatch */

#define PTLLND_MD_OPTIONS        (PTL_MD_LUSTRE_COMPLETION_SEMANTICS |\
                                  PTL_MD_EVENT_START_DISABLE)
typedef struct
{
        int                        plni_portal;
        ptl_pid_t                  plni_ptllnd_pid; /* Portals PID of peers I may connect to */
        int                        plni_peer_credits;
        int                        plni_max_msg_size;
        int                        plni_buffer_size;
        int                        plni_msgs_spare;
        int                        plni_peer_hash_size;
        int                        plni_eq_size;
        int                        plni_checksum;
        int                        plni_max_tx_history;
        int                        plni_abort_on_nak;

        __u64                      plni_stamp;
        struct list_head           plni_active_txs;
        struct list_head           plni_zombie_txs;
        int                        plni_ntxs;
        int                        plni_nrxs;

        ptl_handle_ni_t            plni_nih;
        ptl_handle_eq_t            plni_eqh;
        ptl_process_id_t           plni_portals_id;   /* Portals ID of interface */

        struct list_head          *plni_peer_hash;
        int                        plni_npeers;

        struct list_head           plni_tx_history;
        int                        plni_ntx_history;

        struct list_head           plni_buffers;
        int                        plni_nbuffers;
        int                        plni_nposted_buffers;
} ptllnd_ni_t;

#define PTLLND_CREDIT_HIGHWATER(plni) ((plni)->plni_peer_credits - 1)

typedef struct
{
        struct list_head           plp_list;
        lnet_ni_t                 *plp_ni;
        lnet_process_id_t          plp_id;
        ptl_process_id_t           plp_ptlid;
        int                        plp_credits;
        int                        plp_max_credits;
        int                        plp_outstanding_credits;
        int                        plp_max_msg_size;
        int                        plp_refcount;
        int                        plp_recvd_hello:1;
        int                        plp_closing:1;
        __u64                      plp_match;
        __u64                      plp_stamp;
        struct list_head           plp_txq;
        struct list_head           plp_activeq;
} ptllnd_peer_t;

typedef struct
{
        struct list_head           plb_list;
        lnet_ni_t                 *plb_ni;
        int                        plb_posted;
        ptl_handle_md_t            plb_md;
        char                      *plb_buffer;
} ptllnd_buffer_t;

typedef struct
{
        ptllnd_peer_t             *rx_peer;
        kptl_msg_t                *rx_msg;
        int                        rx_nob;
} ptllnd_rx_t;

typedef struct
{
        struct list_head           tx_list;
        int                        tx_type;
        int                        tx_status;
        ptllnd_peer_t             *tx_peer;
        lnet_msg_t                *tx_lnetmsg;
        lnet_msg_t                *tx_lnetreplymsg;
        unsigned int               tx_niov;
        ptl_md_iovec_t            *tx_iov;
        ptl_handle_md_t            tx_bulkmdh;
        ptl_handle_md_t            tx_reqmdh;
#if PTLLND_DEBUG_TIMING
        struct timeval             tx_bulk_posted;
        struct timeval             tx_bulk_done;
        struct timeval             tx_req_posted;
        struct timeval             tx_req_done;
#endif
        int                        tx_completing; /* someone already completing */
        int                        tx_msgsize;  /* # bytes in tx_msg */
        kptl_msg_t                 tx_msg;      /* message to send */
} ptllnd_tx_t;

#define PTLLND_RDMA_WRITE           0x100       /* pseudo message type */
#define PTLLND_RDMA_READ            0x101       /* (no msg actually sent) */

/* Hack to extract object type from event's user_ptr relies on (and checks)
 * that structs are somewhat aligned. */
#define PTLLND_EVENTARG_TYPE_TX     0x1
#define PTLLND_EVENTARG_TYPE_BUF    0x2
#define PTLLND_EVENTARG_TYPE_MASK   0x3

static inline void *
ptllnd_obj2eventarg (void *obj, int type)
{
        unsigned long ptr = (unsigned long)obj;

        LASSERT ((ptr & PTLLND_EVENTARG_TYPE_MASK) == 0);
        LASSERT ((type & ~PTLLND_EVENTARG_TYPE_MASK) == 0);

        return (void *)(ptr | type);
}

static inline int
ptllnd_eventarg2type (void *arg)
{
        unsigned long ptr = (unsigned long)arg;

        return (ptr & PTLLND_EVENTARG_TYPE_MASK);
}

static inline void *
ptllnd_eventarg2obj (void *arg)
{
        unsigned long ptr = (unsigned long)arg;

        return (void *)(ptr & ~PTLLND_EVENTARG_TYPE_MASK);
}

#if PTLLND_DEBUG_TIMING
# define PTLLND_DBGT_INIT(tv)  memset(&(tv), 0, sizeof(tv))
# define PTLLND_DBGT_STAMP(tv) gettimeofday(&(tv), NULL)
# define DBGT_FMT              "%ld.%06ld"
# define DBGT_ARGS(tv)         , (long)((tv).tv_sec), (long)((tv).tv_usec)
#else
# define PTLLND_DBGT_INIT(tv)
# define PTLLND_DBGT_STAMP(tv)
# define DBGT_FMT              "-"
# define DBGT_ARGS(tv)
#endif

void ptllnd_cull_tx_history(ptllnd_ni_t *plni);
int ptllnd_startup(lnet_ni_t *ni);
void ptllnd_shutdown(lnet_ni_t *ni);
int ptllnd_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int ptllnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *msg);
int ptllnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg,
                int delayed, unsigned int niov,
                struct iovec *iov, lnet_kiov_t *kiov,
                unsigned int offset, unsigned int mlen, unsigned int rlen);
int ptllnd_eager_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg,
                      void **new_privatep);

ptllnd_tx_t *ptllnd_new_tx(ptllnd_peer_t *peer, int type, int payload_nob);
void ptllnd_notify(lnet_ni_t *ni, lnet_nid_t nid, int alive);
void ptllnd_wait(lnet_ni_t *ni, int milliseconds);
void ptllnd_check_sends(ptllnd_peer_t *peer);
void ptllnd_debug_peer(lnet_ni_t *ni, lnet_process_id_t id);
void ptllnd_destroy_peer(ptllnd_peer_t *peer);
void ptllnd_close_peer(ptllnd_peer_t *peer, int error);
int ptllnd_post_buffer(ptllnd_buffer_t *buf);
int ptllnd_grow_buffers (lnet_ni_t *ni);
const char *ptllnd_evtype2str(int type);
const char *ptllnd_msgtype2str(int type);
char *ptllnd_ptlid2str(ptl_process_id_t id);

static inline void
ptllnd_peer_addref (ptllnd_peer_t *peer)
{
        LASSERT (peer->plp_refcount > 0);
        peer->plp_refcount++;
}

static inline void
ptllnd_peer_decref (ptllnd_peer_t *peer)
{
        LASSERT (peer->plp_refcount > 0);
        peer->plp_refcount--;
        if (peer->plp_refcount == 0)
                ptllnd_destroy_peer(peer);
}

static inline void
ptllnd_post_tx(ptllnd_tx_t *tx)
{
        ptllnd_peer_t *peer = tx->tx_peer;
        LASSERT(tx->tx_peer != NULL);
        list_add_tail(&tx->tx_list, &peer->plp_txq);
        ptllnd_check_sends(peer);
}

static inline lnet_nid_t
ptllnd_ptl2lnetnid(lnet_ni_t *ni, ptl_nid_t portals_nid)
{
	return LNET_MKNID(LNET_NIDNET(ni->ni_nid), portals_nid);
}

static inline ptl_nid_t
ptllnd_lnet2ptlnid(lnet_nid_t lnet_nid)
{
	return LNET_NIDADDR(lnet_nid);
}

/*
 * A note about lprintf():
 *  Normally printf() is redirected to stdout of the console
 *  from which yod launched the catamount application.  However
 *  there is a lot of initilziation code that runs before this
 *  redirection is hooked up, and printf() seems to go to the bit bucket
 *
 *  To get any kind of debug output and init time lprintf() can
 *  be used to output to the console from which bookqk was used to
 *  boot the catamount node.  This works for debugging some simple
 *  cases.
 */


