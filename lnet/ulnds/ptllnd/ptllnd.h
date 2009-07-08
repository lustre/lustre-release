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
 * lnet/ulnds/ptllnd/ptllnd.h
 *
 * Author: Eric Barton <eeb@bartonsoftware.com>
 */


#define DEBUG_SUBSYSTEM S_LND

#include <lnet/lib-lnet.h>
#include <lnet/ptllnd_wire.h>

#include <portals/p30.h>
#include <lnet/ptllnd.h>           /* Depends on portals/p30.h */
#include <stdarg.h>

/* Hack to record history 
 * This should really be done by CDEBUG(D_NETTRACE...  */

typedef struct {
        struct list_head          he_list;
        struct timeval            he_time;
        const char               *he_fn;
        const char               *he_file;
        int                       he_seq;
        int                       he_line;
        char                      he_msg[80];
} ptllnd_he_t;

void ptllnd_dump_history();
void ptllnd_history(const char *fn, const char *file, const int line,
                    const char *fmt, ...);
#define PTLLND_HISTORY(fmt, a...) \
        ptllnd_history(__FUNCTION__, __FILE__, __LINE__, fmt, ## a)

        
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
        int                        plni_abort_on_protocol_mismatch;
        int                        plni_abort_on_nak;
        int                        plni_dump_on_nak;
        int                        plni_debug;
        int                        plni_long_wait;
        int                        plni_watchdog_interval;
        int                        plni_timeout;

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

        int                        plni_watchdog_nextt;
        int                        plni_watchdog_peeridx;

        struct list_head           plni_tx_history;
        int                        plni_ntx_history;

        struct list_head           plni_buffers;
        int                        plni_nbuffers;
        int                        plni_nposted_buffers;
        int                        plni_nmsgs;
} ptllnd_ni_t;

#define PTLLND_CREDIT_HIGHWATER(plni) ((plni)->plni_peer_credits - 1)

typedef struct
{
        struct list_head           plp_list;
        lnet_ni_t                 *plp_ni;
        lnet_process_id_t          plp_id;
        ptl_process_id_t           plp_ptlid;
        int                        plp_credits; /* # msg buffers reserved for me at peer */

        /* credits for msg buffers I've posted for this peer...
         * outstanding - free buffers I've still to inform my peer about
         * sent        - free buffers I've told my peer about
         * lazy        - additional buffers (over and above plni_peer_credits)
         *               posted to prevent peer blocking on sending a non-RDMA
         *               messages to me when LNET isn't eagerly responsive to
         *               the network (i.e. liblustre doesn't have control). 
         * extra_lazy  - lazy credits not required any more. */
        int                        plp_outstanding_credits;
        int                        plp_sent_credits;
        int                        plp_lazy_credits;
        int                        plp_extra_lazy_credits;

        int                        plp_max_msg_size;
        int                        plp_refcount;
        int                        plp_sent_hello:1;
        int                        plp_recvd_hello:1;
        int                        plp_closing:1;
        __u64                      plp_match;
        __u64                      plp_stamp;
        struct list_head           plp_txq;
        struct list_head           plp_noopq;
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
        struct timeval             tx_bulk_posted;
        struct timeval             tx_bulk_done;
        struct timeval             tx_req_posted;
        struct timeval             tx_req_done;
        int                        tx_completing; /* someone already completing */
        int                        tx_msgsize;  /* # bytes in tx_msg */
        time_t                     tx_deadline; /* time to complete by */
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

int ptllnd_parse_int_tunable(int *value, char *name, int dflt);
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
int  ptllnd_setasync(lnet_ni_t *ni, lnet_process_id_t id, int n);
void ptllnd_wait(lnet_ni_t *ni, int milliseconds);
void ptllnd_check_sends(ptllnd_peer_t *peer);
void ptllnd_debug_peer(lnet_ni_t *ni, lnet_process_id_t id);
void ptllnd_destroy_peer(ptllnd_peer_t *peer);
void ptllnd_close_peer(ptllnd_peer_t *peer, int error);
int ptllnd_post_buffer(ptllnd_buffer_t *buf);
int ptllnd_size_buffers (lnet_ni_t *ni, int delta);
const char *ptllnd_evtype2str(int type);
const char *ptllnd_msgtype2str(int type);
const char *ptllnd_errtype2str(int type);
char *ptllnd_ptlid2str(ptl_process_id_t id);
void ptllnd_dump_debug(lnet_ni_t *ni, lnet_process_id_t id);


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
