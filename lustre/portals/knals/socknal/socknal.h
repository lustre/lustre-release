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
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/uio.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <asm/div64.h>

#define DEBUG_SUBSYSTEM S_SOCKNAL

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>
#include <portals/socknal.h>

#if CONFIG_SMP
# define SOCKNAL_N_SCHED       num_online_cpus() /* # socknal schedulers */
#else
# define SOCKNAL_N_SCHED        1               /* # socknal schedulers */
#endif
#define SOCKNAL_N_AUTOCONNECTD  4               /* # socknal autoconnect daemons */

#define SOCKNAL_MIN_RECONNECT_INTERVAL	HZ      /* first failed connection retry... */
#define SOCKNAL_MAX_RECONNECT_INTERVAL	(60*HZ) /* ...exponentially increasing to this */

/* default vals for runtime tunables */
#define SOCKNAL_IO_TIMEOUT       50             /* default comms timeout (seconds) */
#define SOCKNAL_EAGER_ACK        0              /* default eager ack (boolean) */
#define SOCKNAL_TYPED_CONNS      1              /* unidirectional large, bidirectional small? */
#define SOCKNAL_ZC_MIN_FRAG     (2<<10)         /* default smallest zerocopy fragment */
#define SOCKNAL_MIN_BULK        (1<<10)         /* smallest "large" message */
#define SOCKNAL_USE_KEEPALIVES   0              /* use tcp/ip keepalive? */

#define SOCKNAL_PEER_HASH_SIZE   101            /* # peer lists */

#define SOCKNAL_SMALL_FWD_NMSGS	128             /* # small messages I can be forwarding at any time */
#define SOCKNAL_LARGE_FWD_NMSGS 64              /* # large messages I can be forwarding at any time */

#define SOCKNAL_SMALL_FWD_PAGES	1               /* # pages in a small message fwd buffer */

#define SOCKNAL_LARGE_FWD_PAGES (PAGE_ALIGN (sizeof (ptl_hdr_t) + PTL_MTU) >> PAGE_SHIFT)
						/* # pages in a large message fwd buffer */

#define SOCKNAL_RESCHED         100             /* # scheduler loops before reschedule */
#define SOCKNAL_ENOMEM_RETRY    1               /* jiffies between retries */

#define SOCKNAL_TX_LOW_WATER(sk) (((sk)->sk_sndbuf*8)/10)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,72))
# define sk_data_ready	data_ready
# define sk_write_space write_space
# define sk_user_data   user_data
# define sk_prot        prot
# define sk_sndbuf      sndbuf
# define sk_socket      socket
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
# define sk_wmem_queued wmem_queued
#endif

typedef struct                                  /* pool of forwarding buffers */
{
        spinlock_t        fmp_lock;             /* serialise */
        struct list_head  fmp_idle_fmbs;        /* free buffers */
        struct list_head  fmp_blocked_conns;    /* connections waiting for a buffer */
        int               fmp_nactive_fmbs;     /* # buffers in use */
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
        int               ksni_valid:1;         /* been set yet? */
        int               ksni_bound:1;         /* bound to a cpu yet? */
        int               ksni_sched:6;         /* which scheduler (assumes < 64) */
} ksock_irqinfo_t;

typedef struct {
        int               ksnd_init;            /* initialisation state */
        int               ksnd_io_timeout;      /* "stuck" socket timeout (seconds) */
        int               ksnd_eager_ack;       /* make TCP ack eagerly? */
        int               ksnd_typed_conns;     /* drive sockets by type? */
        int               ksnd_min_bulk;        /* smallest "large" message */
#if SOCKNAL_ZC
        unsigned int      ksnd_zc_min_frag;     /* minimum zero copy frag size */
#endif
        struct ctl_table_header *ksnd_sysctl;   /* sysctl interface */
        __u64             ksnd_incarnation;     /* my epoch */
        
        rwlock_t          ksnd_global_lock;     /* stabilize peer/conn ops */
        struct list_head *ksnd_peers;           /* hash table of all my known peers */
        int               ksnd_peer_hash_size;  /* size of ksnd_peers */

        nal_cb_t         *ksnd_nal_cb;
        spinlock_t        ksnd_nal_cb_lock;     /* lib cli/sti lock */

        atomic_t          ksnd_nthreads;        /* # live threads */
        int               ksnd_shuttingdown;    /* tell threads to exit */
        ksock_sched_t    *ksnd_schedulers;      /* scheduler state */

        atomic_t          ksnd_npeers;          /* total # peers extant */
        atomic_t          ksnd_nclosing_conns;  /* # closed conns extant */

        kpr_router_t      ksnd_router;          /* THE router */

        ksock_fmb_pool_t  ksnd_small_fmp;       /* small message forwarding buffers */
        ksock_fmb_pool_t  ksnd_large_fmp;       /* large message forwarding buffers */

        atomic_t          ksnd_nactive_ltxs;    /* #active ltxs */

        struct list_head  ksnd_deathrow_conns;  /* conns to be closed */
        struct list_head  ksnd_zombie_conns;    /* conns to be freed */
        struct list_head  ksnd_enomem_conns;    /* conns to be retried */
        wait_queue_head_t ksnd_reaper_waitq;    /* reaper sleeps here */
        unsigned long     ksnd_reaper_waketime; /* when reaper will wake */
        spinlock_t        ksnd_reaper_lock;     /* serialise */

        int               ksnd_enomem_tx;       /* test ENOMEM sender */
        int               ksnd_stall_tx;        /* test sluggish sender */
        int               ksnd_stall_rx;        /* test sluggish receiver */

        struct list_head  ksnd_autoconnectd_routes; /* routes waiting to be connected */
        wait_queue_head_t ksnd_autoconnectd_waitq; /* autoconnectds sleep here */
        spinlock_t        ksnd_autoconnectd_lock; /* serialise */

        ksock_irqinfo_t   ksnd_irqinfo[NR_IRQS];/* irq->scheduler lookup */
} ksock_nal_data_t;

#define SOCKNAL_INIT_NOTHING    0
#define SOCKNAL_INIT_DATA       1
#define SOCKNAL_INIT_PTL        2
#define SOCKNAL_INIT_ALL        3

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

struct ksock_conn;                              /* forward ref */
struct ksock_peer;                              /* forward ref */
struct ksock_route;                             /* forward ref */

typedef struct                                  /* transmit packet */
{
        struct list_head        tx_list;        /* queue on conn for transmission etc */
        char                    tx_isfwd;       /* forwarding / sourced here */
        int                     tx_nob;         /* # packet bytes */
        int                     tx_resid;       /* residual bytes */
        int                     tx_niov;        /* # packet iovec frags */
        struct iovec           *tx_iov;         /* packet iovec frags */
        int                     tx_nkiov;       /* # packet page frags */
        ptl_kiov_t             *tx_kiov;        /* packet page frags */
        struct ksock_conn      *tx_conn;        /* owning conn */
        ptl_hdr_t              *tx_hdr;         /* packet header (for debug only) */
#if SOCKNAL_ZC        
        zccd_t                  tx_zccd;        /* zero copy callback descriptor */
#endif
} ksock_tx_t;

#define KSOCK_ZCCD_2_TX(ptr)	list_entry (ptr, ksock_tx_t, tx_zccd)
/* network zero copy callback descriptor embedded in ksock_tx_t */

typedef struct                                  /* locally transmitted packet */
{
        ksock_tx_t              ltx_tx;         /* send info */
        void                   *ltx_private;    /* lib_finalize() callback arg */
        void                   *ltx_cookie;     /* lib_finalize() callback arg */
        ptl_hdr_t               ltx_hdr;        /* buffer for packet header */
        int                     ltx_desc_size;  /* bytes allocated for this desc */
        struct iovec            ltx_iov[1];     /* iov for hdr + payload */
        ptl_kiov_t              ltx_kiov[0];    /* kiov for payload */
} ksock_ltx_t;

#define KSOCK_TX_2_KPR_FWD_DESC(ptr)    list_entry ((kprfd_scratch_t *)ptr, kpr_fwd_desc_t, kprfd_scratch)
/* forwarded packets (router->socknal) embedded in kpr_fwd_desc_t::kprfd_scratch */

#define KSOCK_TX_2_KSOCK_LTX(ptr)       list_entry (ptr, ksock_ltx_t, ltx_tx)
/* local packets (lib->socknal) embedded in ksock_ltx_t::ltx_tx */

/* NB list_entry() is used here as convenient macro for calculating a
 * pointer to a struct from the address of a member. */

typedef struct                                  /* Kernel portals Socket Forwarding message buffer */
{                                               /* (socknal->router) */
        struct list_head        fmb_list;       /* queue idle */
        kpr_fwd_desc_t          fmb_fwd;        /* router's descriptor */
        int                     fmb_npages;     /* # pages allocated */
        ksock_fmb_pool_t       *fmb_pool;       /* owning pool */
        struct ksock_peer      *fmb_peer;       /* peer received from */
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

typedef struct ksock_conn
{ 
        struct ksock_peer  *ksnc_peer;          /* owning peer */
        struct ksock_route *ksnc_route;         /* owning route */
        struct list_head    ksnc_list;          /* stash on peer's conn list */
        struct socket      *ksnc_sock;          /* actual socket */
        void               *ksnc_saved_data_ready; /* socket's original data_ready() callback */
        void               *ksnc_saved_write_space; /* socket's original write_space() callback */
        atomic_t            ksnc_refcount;      /* # users */
        ksock_sched_t	   *ksnc_scheduler;     /* who schedules this connection */
        __u32               ksnc_ipaddr;        /* peer's IP */
        int                 ksnc_port;          /* peer's port */
        int                 ksnc_closing;       /* being shut down */
        int                 ksnc_type;          /* type of connection */
        __u64               ksnc_incarnation;   /* peer's incarnation */
        
        /* reader */
        struct list_head    ksnc_rx_list;       /* where I enq waiting input or a forwarding descriptor */
        unsigned long       ksnc_rx_deadline;   /* when (in jiffies) receive times out */
        int                 ksnc_rx_started;    /* started receiving a message */
        int                 ksnc_rx_ready;      /* data ready to read */
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
        unsigned long       ksnc_tx_deadline;   /* when (in jiffies) tx times out */
        atomic_t            ksnc_tx_nob;        /* # bytes queued */
        int                 ksnc_tx_ready;      /* write space */
        int                 ksnc_tx_scheduled;  /* being progressed */
} ksock_conn_t;

#define KSNR_TYPED_ROUTES   ((1 << SOCKNAL_CONN_CONTROL) |      \
                             (1 << SOCKNAL_CONN_BULK_IN) |      \
                             (1 << SOCKNAL_CONN_BULK_OUT))

typedef struct ksock_route
{
        struct list_head    ksnr_list;          /* chain on peer route list */
        struct list_head    ksnr_connect_list;  /* chain on autoconnect list */
        struct ksock_peer  *ksnr_peer;          /* owning peer */
        atomic_t            ksnr_refcount;      /* # users */
        int                 ksnr_sharecount;    /* lconf usage counter */
        unsigned long       ksnr_timeout;       /* when (in jiffies) reconnection can happen next */
        unsigned int        ksnr_retry_interval; /* how long between retries */
        __u32               ksnr_ipaddr;        /* an IP address for this peer */
        int                 ksnr_port;          /* port to connect to */
        int                 ksnr_buffer_size;   /* size of socket buffers */
        unsigned int        ksnr_irq_affinity:1; /* set affinity? */
        unsigned int        ksnr_nonagel:1;     /* disable nagle? */
        unsigned int        ksnr_eager:1;       /* connect eagery? */
        unsigned int        ksnr_connecting:4;  /* autoconnects in progress by type */
        unsigned int        ksnr_connected:4;   /* connections established by type */
        unsigned int        ksnr_deleted:1;     /* been removed from peer? */
        int                 ksnr_conn_count;    /* # conns established by this route */
} ksock_route_t;

typedef struct ksock_peer
{
        struct list_head    ksnp_list;          /* stash on global peer list */
        ptl_nid_t           ksnp_nid;           /* who's on the other end(s) */
        atomic_t            ksnp_refcount;      /* # users */
        int                 ksnp_closing;       /* being closed */
        int                 ksnp_error;         /* errno on closing last conn */
        struct list_head    ksnp_conns;         /* all active connections */
        struct list_head    ksnp_routes;        /* routes */
        struct list_head    ksnp_tx_queue;      /* waiting packets */
        unsigned long       ksnp_last_alive;    /* when (in jiffies) I was last alive */
} ksock_peer_t;


extern nal_cb_t         ksocknal_lib;
extern ksock_nal_data_t ksocknal_data;

static inline struct list_head *
ksocknal_nid2peerlist (ptl_nid_t nid) 
{
        unsigned int hash = ((unsigned int)nid) % ksocknal_data.ksnd_peer_hash_size;
        
        return (&ksocknal_data.ksnd_peers [hash]);
}

static inline int
ksocknal_getconnsock (ksock_conn_t *conn) 
{
        int   rc = -ESHUTDOWN;
        
        read_lock (&ksocknal_data.ksnd_global_lock);
        if (!conn->ksnc_closing) {
                rc = 0;
                get_file (conn->ksnc_sock->file);
        }
        read_unlock (&ksocknal_data.ksnd_global_lock);

        return (rc);
}

static inline void
ksocknal_putconnsock (ksock_conn_t *conn)
{
        fput (conn->ksnc_sock->file);
}

extern void ksocknal_put_route (ksock_route_t *route);
extern void ksocknal_put_peer (ksock_peer_t *peer);
extern ksock_peer_t *ksocknal_find_peer_locked (ptl_nid_t nid);
extern ksock_peer_t *ksocknal_get_peer (ptl_nid_t nid);
extern int ksocknal_del_route (ptl_nid_t nid, __u32 ipaddr,
                               int single, int keep_conn);
extern int ksocknal_create_conn (ksock_route_t *route,
                                 struct socket *sock, int bind_irq, int type);
extern void ksocknal_close_conn_locked (ksock_conn_t *conn, int why);
extern void ksocknal_terminate_conn (ksock_conn_t *conn);
extern void ksocknal_destroy_conn (ksock_conn_t *conn);
extern void ksocknal_put_conn (ksock_conn_t *conn);
extern int ksocknal_close_stale_conns_locked (ksock_peer_t *peer, __u64 incarnation);
extern int ksocknal_close_conn_and_siblings (ksock_conn_t *conn, int why);
extern int ksocknal_close_matching_conns (ptl_nid_t nid, __u32 ipaddr);

extern void ksocknal_queue_tx_locked (ksock_tx_t *tx, ksock_conn_t *conn);
extern void ksocknal_tx_done (ksock_tx_t *tx, int asynch);
extern void ksocknal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd);
extern void ksocknal_fmb_callback (void *arg, int error);
extern void ksocknal_notify (void *arg, ptl_nid_t gw_nid, int alive);
extern int ksocknal_thread_start (int (*fn)(void *arg), void *arg);
extern int ksocknal_new_packet (ksock_conn_t *conn, int skip);
extern int ksocknal_scheduler (void *arg);
extern void ksocknal_data_ready(struct sock *sk, int n);
extern void ksocknal_write_space(struct sock *sk);
extern int ksocknal_autoconnectd (void *arg);
extern int ksocknal_reaper (void *arg);
extern int ksocknal_setup_sock (struct socket *sock);
extern int ksocknal_hello (struct socket *sock, 
                           ptl_nid_t *nid, int *type, __u64 *incarnation);
