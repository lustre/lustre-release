/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *   Author: Kedar Sovani <kedar@calsoftinc.com>
 *   Author: Amey Inamdar <amey@calsoftinc.com>
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
#include <net/tcp.h>
#include <linux/uio.h>
#include <linux/sched.h> 

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <asm/segment.h>

#define DEBUG_SUBSYSTEM S_SOCKNAL

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>

#define SOCKNAL_MAX_FWD_PAYLOAD (64<<10)        /* biggest payload I can forward */

#define SOCKNAL_NLTXS           128             /* # normal transmit messages */
#define SOCKNAL_NNBLK_LTXS	128             /* # transmit messages reserved if can't block */

#define SOCKNAL_SMALL_FWD_NMSGS	128             /* # small messages I can be forwarding at any time */
#define SOCKNAL_LARGE_FWD_NMSGS 32              /* # large messages I can be forwarding at any time */

#define SOCKNAL_SMALL_FWD_PAGES	1               /* # pages in a small message fwd buffer */

#define SOCKNAL_LARGE_FWD_PAGES (PAGE_ALIGN (sizeof (ptl_hdr_t) + SOCKNAL_MAX_FWD_PAYLOAD) >> PAGE_SHIFT)
						/* # pages in a large message fwd buffer */

#define SOCKNAL_RESCHED         100             /* # scheduler loops before reschedule */

#define SOCKNAL_TX_LOW_WATER(sk) (((sk)->sndbuf*8)/10)

#define TOENAL_N_SCHED 1

typedef struct                                  /* pool of forwarding buffers */
{
        struct list_head  fmp_idle_fmbs;        /* buffers waiting for a connection */
        struct list_head  fmp_blocked_conns;    /* connections waiting for a buffer */
} ksock_fmb_pool_t;

typedef struct {
        int               ksnd_init;            /* initialisation state */
        
        struct list_head  ksnd_socklist;        /* all my connections */
        rwlock_t          ksnd_socklist_lock;   /* stabilise add/find/remove */


        ptl_nid_t         ksnd_mynid;
        nal_cb_t         *ksnd_nal_cb;
        spinlock_t        ksnd_nal_cb_lock;     /* lib cli/sti lock */

        atomic_t          ksnd_nthreads;        /* # live threads */
        int               ksnd_shuttingdown;    /* tell threads to exit */
        
        kpr_router_t      ksnd_router;          /* THE router */

        spinlock_t        ksnd_sched_lock;      /* serialise packet scheduling */
        wait_queue_head_t ksnd_sched_waitq;     /* where scheduler(s) wait */

        struct list_head  ksnd_rx_conns;        /* conn waiting to be read */
        struct list_head  ksnd_tx_conns;        /* conn waiting to be written */
        
        void             *ksnd_fmbs;            /* all the pre-allocated FMBs */
        ksock_fmb_pool_t  ksnd_small_fmp;       /* small message forwarding buffers */
        ksock_fmb_pool_t  ksnd_large_fmp;       /* large message forwarding buffers */

        void             *ksnd_ltxs;            /* all the pre-allocated LTXs */
        struct list_head  ksnd_idle_ltx_list;   /* where to get an idle LTX */
        struct list_head  ksnd_idle_nblk_ltx_list; /* where to get an idle LTX if you can't block */
        wait_queue_head_t ksnd_idle_ltx_waitq;  /* where to block for an idle LTX */

        struct list_head  ksnd_reaper_list;     /* conn waiting to be reaped */
        wait_queue_head_t ksnd_reaper_waitq;    /* reaper sleeps here */
        spinlock_t        ksnd_reaper_lock;     /* serialise */
        
        struct task_struct *ksnd_pollthread_tsk;/* task_struct for the poll thread */
        poll_table          ksnd_pwait;         /* poll wait table for the socket */
        int                 ksnd_slistchange;   /* informs the pollthread that
                                                 * the socklist has changed */  
} ksock_nal_data_t;

#define SOCKNAL_INIT_NOTHING    0
#define SOCKNAL_INIT_DATA       1
#define SOCKNAL_INIT_PTL        2
#define SOCKNAL_INIT_ALL        3

typedef struct                                  /* transmit packet */
{
        struct list_head        tx_list;       /* queue on conn for transmission etc */
        char                    tx_isfwd;      /* forwarding / sourced here */
        int                     tx_nob;        /* # packet bytes */
        int                     tx_niov;       /* # packet frags */
        struct iovec           *tx_iov;        /* packet frags */
} ksock_tx_t;

typedef struct                                  /* locally transmitted packet */
{
        ksock_tx_t              ltx_tx;         /* send info */
        struct list_head       *ltx_idle;       /* where to put when idle */
        void                   *ltx_private;    /* lib_finalize() callback arg */
        void                   *ltx_cookie;     /* lib_finalize() callback arg */
        struct iovec            ltx_iov[1 + PTL_MD_MAX_IOV]; /* msg frags */
        ptl_hdr_t               ltx_hdr;        /* buffer for packet header */
} ksock_ltx_t;

#define KSOCK_TX_2_KPR_FWD_DESC(ptr)    list_entry (ptr, kpr_fwd_desc_t, kprfd_scratch)
/* forwarded packets (router->socknal) embedded in kpr_fwd_desc_t::kprfd_scratch */

#define KSOCK_TX_2_KSOCK_LTX(ptr)       list_entry (ptr, ksock_ltx_t, ltx_tx)
/* local packets (lib->socknal) embedded in ksock_ltx_t::ltx_tx */

/* NB list_entry() is used here as convenient macro for calculating a
 * pointer to a struct from the addres of a member.
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
        struct socket      *ksnc_sock;          /* socket */
        ptl_nid_t           ksnc_peernid;       /* who's on the other end */
        atomic_t            ksnc_refcount;      /* # users */
        
        /* READER */
        struct list_head    ksnc_rx_list;       /* where I enq waiting input or a forwarding descriptor */
        unsigned long       ksnc_rx_ready;      /* data ready to read */
        int                 ksnc_rx_scheduled;  /* being progressed */
        int                 ksnc_rx_state;      /* what is being read */
        int                 ksnc_rx_nob_left;   /* # bytes to next hdr/body  */
        int                 ksnc_rx_nob_wanted; /* bytes actually wanted */
        int                 ksnc_rx_niov;       /* # frags */
        struct iovec        ksnc_rx_iov[1 + PTL_MD_MAX_IOV]; /* the frags */

        void               *ksnc_cookie;        /* rx lib_finalize passthru arg */
        ptl_hdr_t           ksnc_hdr;           /* where I read headers into */

        /* WRITER */
        struct list_head    ksnc_tx_list;       /* where I enq waiting for output space */
        struct list_head    ksnc_tx_queue;      /* packets waiting to be sent */
        unsigned long       ksnc_tx_ready;      /* write space */
        int                 ksnc_tx_scheduled;  /* being progressed */
        
} ksock_conn_t;

extern int ktoenal_add_sock (ptl_nid_t nid, int fd);
extern int ktoenal_close_sock(ptl_nid_t nid);
extern int ktoenal_set_mynid(ptl_nid_t nid);
extern int ktoenal_push_sock(ptl_nid_t nid);
extern ksock_conn_t *ktoenal_get_conn (ptl_nid_t nid);
extern void _ktoenal_put_conn (ksock_conn_t *conn);
extern void ktoenal_close_conn (ksock_conn_t *conn);

static inline void
ktoenal_put_conn (ksock_conn_t *conn)
{
        CDEBUG (D_OTHER, "putting conn[%p] -> "LPX64" (%d)\n", 
                conn, conn->ksnc_peernid, atomic_read (&conn->ksnc_refcount));
        
        if (atomic_dec_and_test (&conn->ksnc_refcount))
                _ktoenal_put_conn (conn);
}

extern int ktoenal_thread_start (int (*fn)(void *arg), void *arg);
extern int ktoenal_new_packet (ksock_conn_t *conn, int skip);
extern void ktoenal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd);
extern int ktoenal_scheduler (void *arg);
extern int ktoenal_reaper (void *arg);
extern int ktoenal_pollthread (void *arg);
extern void ktoenal_data_ready(ksock_conn_t *conn);
extern void ktoenal_write_space(ksock_conn_t *conn);


extern nal_cb_t         ktoenal_lib;
extern ksock_nal_data_t ktoenal_data;
