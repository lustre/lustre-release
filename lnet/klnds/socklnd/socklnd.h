/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define DEBUG_PORTAL_ALLOC
#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/uio.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <asm/uaccess.h>
#include <asm/segment.h>

#define DEBUG_SUBSYSTEM S_SOCKNAL

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>

#define SOCKNAL_N_SCHED num_online_cpus()       /* # socknal schedulers */

#if PTL_LARGE_MTU
# define SOCKNAL_MAX_FWD_PAYLOAD (256<<10)      /* biggest payload I can forward */
#else
# define SOCKNAL_MAX_FWD_PAYLOAD (64<<10)       /* biggest payload I can forward */
#endif

#define SOCKNAL_NLTXS           128             /* # normal transmit messages */
#define SOCKNAL_NNBLK_LTXS	128             /* # transmit messages reserved if can't block */

#define SOCKNAL_SMALL_FWD_NMSGS	128             /* # small messages I can be forwarding at any time */
#define SOCKNAL_LARGE_FWD_NMSGS 64              /* # large messages I can be forwarding at any time */

#define SOCKNAL_SMALL_FWD_PAGES	1               /* # pages in a small message fwd buffer */

#define SOCKNAL_LARGE_FWD_PAGES (PAGE_ALIGN (sizeof (ptl_hdr_t) + SOCKNAL_MAX_FWD_PAYLOAD) >> PAGE_SHIFT)
						/* # pages in a large message fwd buffer */

#define SOCKNAL_RESCHED         100             /* # scheduler loops before reschedule */

#define SOCKNAL_TX_LOW_WATER(sk) (((sk)->sndbuf*8)/10)

typedef struct                                  /* pool of forwarding buffers */
{
        spinlock_t        fmp_lock;             /* serialise */
        struct list_head  fmp_idle_fmbs;        /* buffers waiting for a connection */
        struct list_head  fmp_blocked_conns;    /* connections waiting for a buffer */
} ksock_fmb_pool_t;


typedef struct                                  /* per scheduler state */
{
        spinlock_t        kss_lock;             /* serialise */
        struct list_head  kss_rx_conns;         /* conn waiting to be read */
        struct list_head  kss_tx_conns;         /* conn waiting to be written */
#if SOCKNAL_ZC
        struct list_head  kss_zctxdone_list;    /* completed ZC transmits */
#endif
        wait_queue_head_t kss_waitq;            /* where scheduler sleeps */
        int               kss_nconns;           /* # connections assigned to this scheduler */
} ksock_sched_t;

typedef struct {
        int               ksnd_init;            /* initialisation state */
        
        struct list_head  ksnd_socklist;        /* all my connections */
        rwlock_t          ksnd_socklist_lock;   /* stabilise add/find/remove */

        ptl_nid_t         ksnd_mynid;
        nal_cb_t         *ksnd_nal_cb;
        spinlock_t        ksnd_nal_cb_lock;     /* lib cli/sti lock */

        atomic_t          ksnd_nthreads;        /* # live threads */
        int               ksnd_shuttingdown;    /* tell threads to exit */
        ksock_sched_t    *ksnd_schedulers;      /* scheduler state */
        
        kpr_router_t      ksnd_router;          /* THE router */

        void             *ksnd_fmbs;            /* all the pre-allocated FMBs */
        ksock_fmb_pool_t  ksnd_small_fmp;       /* small message forwarding buffers */
        ksock_fmb_pool_t  ksnd_large_fmp;       /* large message forwarding buffers */

        void             *ksnd_ltxs;            /* all the pre-allocated LTXs */
        spinlock_t        ksnd_idle_ltx_lock;   /* serialise ltx alloc/free */
        struct list_head  ksnd_idle_ltx_list;   /* where to get an idle LTX */
        struct list_head  ksnd_idle_nblk_ltx_list; /* where to get an idle LTX if you can't block */
        wait_queue_head_t ksnd_idle_ltx_waitq;  /* where to block for an idle LTX */

        struct list_head  ksnd_reaper_list;     /* conn waiting to be reaped */
        wait_queue_head_t ksnd_reaper_waitq;    /* reaper sleeps here */
        spinlock_t        ksnd_reaper_lock;     /* serialise */
        unsigned char     ksnd_irq_info[NR_IRQS]; /* irq->scheduler lookup */
} ksock_nal_data_t;

#define SOCKNAL_INIT_NOTHING    0
#define SOCKNAL_INIT_DATA       1
#define SOCKNAL_INIT_PTL        2
#define SOCKNAL_INIT_ALL        3

#define SOCKNAL_IRQ_BOUND       0x80            /* flag we _did_ bind already */
#define SOCKNAL_IRQ_SCHED_MASK	0x7f            /* we assume < 127 CPUs */
#define SOCKNAL_IRQ_UNASSIGNED  0xff            /* flag unassigned */

/* A packet just assembled for transmission is represented by 1 or more
 * struct iovec fragments and 0 or more ptl_kiov_t fragments.  Forwarded
 * messages, or messages from an MD with PTL_MD_KIOV _not_ set have 0
 * ptl_kiov_t fragments.  Messages from an MD with PTL_MD_KIOV set, have 1
 * struct iovec fragment (the header) and up to PTL_MD_MAX_IOV ptl_kiov_t
 * fragments.
 *
 * On the receive side, initially 1 struct iovec fragment is posted for
 * receive (the header).  Once the header has been received, if the message
 * requires forwarding or will be received into mapped memory, up to
 * PTL_MD_MAX_IOV struct iovec fragments describe the target memory.
 * Otherwise up to PTL_MD_MAX_IOV ptl_kiov_t fragments are used.
 */

typedef struct                                  /* transmit packet */
{
        struct list_head        tx_list;        /* queue on conn for transmission etc */
        char                    tx_isfwd;       /* forwarding / sourced here */
        int                     tx_nob;         /* # packet bytes */
        int                     tx_niov;        /* # packet iovec frags */
        struct iovec           *tx_iov;         /* packet iovec frags */
        int                     tx_nkiov;       /* # packet page frags */
        ptl_kiov_t             *tx_kiov;        /* packet page frags */
#if SOCKNAL_ZC        
        ksock_sched_t          *tx_sched;       /* who to wake on callback */
        zccd_t                  tx_zccd;        /* zero copy callback descriptor */
#endif
} ksock_tx_t;

#define KSOCK_ZCCD_2_TX(ptr)	list_entry (ptr, ksock_tx_t, tx_zccd)
/* network zero copy callback descriptor embedded in ksock_tx_t */

/* space for the tx frag descriptors: hdr is always 1 iovec
 * and payload is PTL_MD_MAX of either type. */
typedef struct
{
        struct iovec            hdr;
        union {
                struct iovec    iov[PTL_MD_MAX_IOV];
                ptl_kiov_t      kiov[PTL_MD_MAX_IOV];
        }                       payload;
} ksock_txiovspace_t;

typedef struct                                  /* locally transmitted packet */
{
        ksock_tx_t              ltx_tx;         /* send info */
        struct list_head       *ltx_idle;       /* where to put when idle */
        void                   *ltx_private;    /* lib_finalize() callback arg */
        void                   *ltx_cookie;     /* lib_finalize() callback arg */
        ksock_txiovspace_t      ltx_iov_space;  /* where to stash frag descriptors */
        ptl_hdr_t               ltx_hdr;        /* buffer for packet header */
} ksock_ltx_t;

#define KSOCK_TX_2_KPR_FWD_DESC(ptr)    list_entry ((kprfd_scratch_t *)ptr, kpr_fwd_desc_t, kprfd_scratch)
/* forwarded packets (router->socknal) embedded in kpr_fwd_desc_t::kprfd_scratch */

#define KSOCK_TX_2_KSOCK_LTX(ptr)       list_entry (ptr, ksock_ltx_t, ltx_tx)
/* local packets (lib->socknal) embedded in ksock_ltx_t::ltx_tx */

/* NB list_entry() is used here as convenient macro for calculating a
 * pointer to a struct from the address of a member.
 */

typedef struct                                  /* Kernel portals Socket Forwarding message buffer */
{                                               /* (socknal->router) */
        struct list_head        fmb_list;       /* queue idle */
        kpr_fwd_desc_t          fmb_fwd;        /* router's descriptor */
        int                     fmb_npages;     /* # pages allocated */
        ksock_fmb_pool_t       *fmb_pool;       /* owning pool */
        struct page            *fmb_pages[SOCKNAL_LARGE_FWD_PAGES];
        struct iovec            fmb_iov[SOCKNAL_LARGE_FWD_PAGES];
} ksock_fmb_t;

/* space for the rx frag descriptors; we either read a single contiguous
 * header, or PTL_MD_MAX_IOV frags of payload of either type. */
typedef union {
        struct iovec    iov[PTL_MD_MAX_IOV];
        ptl_kiov_t      kiov[PTL_MD_MAX_IOV];
} ksock_rxiovspace_t;

#define SOCKNAL_RX_HEADER       1               /* reading header */
#define SOCKNAL_RX_BODY         2               /* reading body (to deliver here) */
#define SOCKNAL_RX_BODY_FWD     3               /* reading body (to forward) */
#define SOCKNAL_RX_SLOP         4               /* skipping body */
#define SOCKNAL_RX_GET_FMB      5               /* scheduled for forwarding */
#define SOCKNAL_RX_FMB_SLEEP    6               /* blocked waiting for a fwd desc */

typedef struct 
{ 
        struct list_head    ksnc_list;          /* stash on global socket list */
        struct file        *ksnc_file;          /* socket filp */
        struct socket      *ksnc_sock;          /* actual socket */
        void               *ksnc_saved_data_ready; /* socket's original data_ready() callback */
        void               *ksnc_saved_write_space; /* socket's original write_space() callback */
        ptl_nid_t           ksnc_peernid;       /* who's on the other end */
        atomic_t            ksnc_refcount;      /* # users */
        ksock_sched_t	   *ksnc_scheduler;     /* who schedules this connection */
        
        /* READER */
        struct list_head    ksnc_rx_list;       /* where I enq waiting input or a forwarding descriptor */
        unsigned long       ksnc_rx_ready;      /* data ready to read */
        int                 ksnc_rx_scheduled;  /* being progressed */
        int                 ksnc_rx_state;      /* what is being read */
        int                 ksnc_rx_nob_left;   /* # bytes to next hdr/body  */
        int                 ksnc_rx_nob_wanted; /* bytes actually wanted */
        int                 ksnc_rx_niov;       /* # iovec frags */
        struct iovec       *ksnc_rx_iov;        /* the iovec frags */
        int                 ksnc_rx_nkiov;      /* # page frags */
        ptl_kiov_t         *ksnc_rx_kiov;       /* the page frags */
        ksock_rxiovspace_t  ksnc_rx_iov_space;  /* space for frag descriptors */
        void               *ksnc_cookie;        /* rx lib_finalize passthru arg */
        ptl_hdr_t           ksnc_hdr;           /* where I read headers into */

        /* WRITER */
        struct list_head    ksnc_tx_list;       /* where I enq waiting for output space */
        struct list_head    ksnc_tx_queue;      /* packets waiting to be sent */
        unsigned long       ksnc_tx_ready;      /* write space */
        int                 ksnc_tx_scheduled;  /* being progressed */

} ksock_conn_t;

extern int ksocknal_add_sock (ptl_nid_t nid, int fd, int client);
extern int ksocknal_close_sock(ptl_nid_t nid);
extern int ksocknal_set_mynid(ptl_nid_t nid);
extern int ksocknal_push_sock(ptl_nid_t nid);
extern ksock_conn_t *ksocknal_get_conn (ptl_nid_t nid);
extern void _ksocknal_put_conn (ksock_conn_t *conn);
extern void ksocknal_close_conn (ksock_conn_t *conn);

static inline void
ksocknal_put_conn (ksock_conn_t *conn)
{
        CDEBUG (D_OTHER, "putting conn[%p] -> "LPX64" (%d)\n", 
                conn, conn->ksnc_peernid, atomic_read (&conn->ksnc_refcount));
        
        if (atomic_dec_and_test (&conn->ksnc_refcount))
                _ksocknal_put_conn (conn);
}

extern int ksocknal_thread_start (int (*fn)(void *arg), void *arg);
extern int ksocknal_new_packet (ksock_conn_t *conn, int skip);
extern void ksocknal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd);
extern int ksocknal_scheduler (void *arg);
extern int ksocknal_reaper (void *arg);
extern void ksocknal_data_ready(struct sock *sk, int n);
extern void ksocknal_write_space(struct sock *sk);


extern nal_cb_t         ksocknal_lib;
extern ksock_nal_data_t ksocknal_data;
