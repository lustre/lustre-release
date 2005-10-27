/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   This file is part of Lustre, http://www.lustre.org
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

#define DEBUG_SUBSYSTEM S_LND

#if defined(__linux__)
#include "socklnd_lib-linux.h"
#elif defined(__APPLE__)
#include "socklnd_lib-darwin.h"
#else
#error Unsupported Operating System
#endif

#include <libcfs/kp30.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>
#include <lnet/socklnd.h>

/* default vals for tunables/modparams */
#define SOCKNAL_TIMEOUT          50             /* default comms timeout (seconds) */
#define SOCKNAL_NCONND           4              /* # socknal connection daemons */
#define SOCKNAL_MIN_RECONNECTMS  1000           /* first connection retry after (mS)... */
#define SOCKNAL_MAX_RECONNECTMS  60000          /* ...exponentially increasing to this */
#define SOCKNAL_EAGER_ACK        SOCKNAL_ARCH_EAGER_ACK  /* default eager ack (boolean) */
#define SOCKNAL_TYPED_CONNS      1              /* unidirectional large, bidirectional small? */
#define SOCKNAL_ZC_MIN_FRAG     (2<<10)         /* default smallest zerocopy fragment */
#define SOCKNAL_MIN_BULK        (1<<10)         /* smallest "large" message */
#define SOCKNAL_BUFFER_SIZE     (8<<20)         /* default socket buffer size */
#define SOCKNAL_NAGLE            0              /* enable/disable NAGLE? */
#define SOCKNAL_IRQ_AFFINITY     1              /* enable/disable IRQ affinity? */
#define SOCKNAL_KEEPALIVE_IDLE   30             /* # seconds idle before 1st probe */
#define SOCKNAL_KEEPALIVE_COUNT  10             /* # unanswered probes to determine peer death */
#define SOCKNAL_KEEPALIVE_INTVL  2              /* seconds between probes */
#define SOCKNAL_CREDITS          256            /* # concurrent sends */
#define SOCKNAL_PEERCREDITS      8              /* # concurrent sends to 1 peer */

#define SOCKNAL_PEER_HASH_SIZE   101            /* # peer lists */

#define SOCKNAL_SMALL_FWD_NMSGS	128             /* # small messages I can be forwarding at any time */
#define SOCKNAL_LARGE_FWD_NMSGS 64              /* # large messages I can be forwarding at any time */

#define SOCKNAL_RESCHED         100             /* # scheduler loops before reschedule */
#define SOCKNAL_ENOMEM_RETRY    CFS_MIN_DELAY   /* jiffies between retries */

#define SOCKNAL_ROUND_ROBIN     0               /* round robin / load balance */

#define SOCKNAL_SINGLE_FRAG_TX      0           /* disable multi-fragment sends */
#define SOCKNAL_SINGLE_FRAG_RX      0           /* disable multi-fragment receives */

/* risk kmap deadlock on multi-frag I/O (backs off to single-frag if disabled).
 * no risk if we're not running on a CONFIG_HIGHMEM platform. */
#ifdef CONFIG_HIGHMEM
# define SOCKNAL_RISK_KMAP_DEADLOCK  0
#else
# define SOCKNAL_RISK_KMAP_DEADLOCK  1
#endif

/* minimum socket buffer required for connection handshake */
#define SOCKNAL_MIN_BUFFER   (2*(sizeof(lnet_hdr_t) +                   \
                                 LNET_MAX_INTERFACES * sizeof(__u32)))

typedef struct                                  /* per scheduler state */
{
        spinlock_t        kss_lock;             /* serialise */
        struct list_head  kss_rx_conns;         /* conn waiting to be read */
        struct list_head  kss_tx_conns;         /* conn waiting to be written */
#if SOCKNAL_ZC
        struct list_head  kss_zctxdone_list;    /* completed ZC transmits */
#endif
        cfs_waitq_t       kss_waitq;            /* where scheduler sleeps */
        int               kss_nconns;           /* # connections assigned to this scheduler */
} ksock_sched_t;

typedef struct
{
        int               ksni_valid:1;         /* been set yet? */
        int               ksni_bound:1;         /* bound to a cpu yet? */
        int               ksni_sched:6;         /* which scheduler (assumes < 64) */
} ksock_irqinfo_t;

typedef struct                                  /* in-use interface */
{
        __u32             ksni_ipaddr;          /* interface's IP address */
        __u32             ksni_netmask;         /* interface's network mask */
        int               ksni_nroutes;         /* # routes using (active) */
        int               ksni_npeers;          /* # peers using (passive) */
        char              ksni_name[16];        /* interface name */
} ksock_interface_t;

typedef struct
{
        int              *ksnd_timeout;         /* "stuck" socket timeout (seconds) */
        int              *ksnd_nconnds;         /* # connection daemons */
        int              *ksnd_min_reconnectms; /* first connection retry after (ms)... */
        int              *ksnd_max_reconnectms; /* ...exponentially increasing to this */
        int              *ksnd_eager_ack;       /* make TCP ack eagerly? */
        int              *ksnd_typed_conns;     /* drive sockets by type? */
        int              *ksnd_min_bulk;        /* smallest "large" message */
        int              *ksnd_buffer_size;     /* socket buffer size */
        int              *ksnd_nagle;           /* enable NAGLE? */
        int              *ksnd_keepalive_idle;  /* # idle secs before 1st probe */
        int              *ksnd_keepalive_count; /* # probes */
        int              *ksnd_keepalive_intvl; /* time between probes */
        int              *ksnd_credits;         /* # concurrent sends */
        int              *ksnd_peercredits;     /* # concurrent sends to 1 peer */
#if SOCKNAL_ZC
        unsigned int     *ksnd_zc_min_frag;     /* minimum zero copy frag size */
#endif
#if CPU_AFFINITY
        int              *ksnd_irq_affinity;    /* enable IRQ affinity? */
#endif
#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
        cfs_sysctl_table_header_t *ksnd_sysctl;   /* sysctl interface */
#endif
} ksock_tunables_t;

typedef struct
{
        __u64             ksnn_incarnation;     /* my epoch */
        spinlock_t        ksnn_lock;            /* serialise */
        int               ksnn_npeers;          /* # peers */
        int               ksnn_shutdown;        /* shutting down? */
        int               ksnn_ninterfaces;     /* IP interfaces */
        ksock_interface_t ksnn_interfaces[LNET_MAX_INTERFACES];
} ksock_net_t;

typedef struct
{
        int               ksnd_init;            /* initialisation state */
        int               ksnd_nnets;           /* # networks set up */

        rwlock_t          ksnd_global_lock;     /* stabilize peer/conn ops */
        struct list_head *ksnd_peers;           /* hash table of all my known peers */
        int               ksnd_peer_hash_size;  /* size of ksnd_peers */

        int               ksnd_nthreads;        /* # live threads */
        int               ksnd_shuttingdown;    /* tell threads to exit */
        int               ksnd_nschedulers;     /* # schedulers */
        ksock_sched_t    *ksnd_schedulers;      /* their state */

        atomic_t          ksnd_nactive_txs;     /* #active txs */

        struct list_head  ksnd_deathrow_conns;  /* conns to close: reaper_lock*/
        struct list_head  ksnd_zombie_conns;    /* conns to free: reaper_lock */
        struct list_head  ksnd_enomem_conns;    /* conns to retry: reaper_lock*/
        cfs_waitq_t       ksnd_reaper_waitq;    /* reaper sleeps here */
        cfs_time_t        ksnd_reaper_waketime; /* when reaper will wake */
        spinlock_t        ksnd_reaper_lock;     /* serialise */

        int               ksnd_enomem_tx;       /* test ENOMEM sender */
        int               ksnd_stall_tx;        /* test sluggish sender */
        int               ksnd_stall_rx;        /* test sluggish receiver */

        struct list_head  ksnd_connd_connreqs;  /* incoming connection requests */
        struct list_head  ksnd_connd_routes;    /* routes waiting to be connected */
        cfs_waitq_t       ksnd_connd_waitq;     /* connds sleep here */
        spinlock_t        ksnd_connd_lock;      /* serialise */

        ksock_irqinfo_t   ksnd_irqinfo[NR_IRQS];/* irq->scheduler lookup */

} ksock_nal_data_t;

#define SOCKNAL_INIT_NOTHING    0
#define SOCKNAL_INIT_DATA       1
#define SOCKNAL_INIT_ALL        2

/* A packet just assembled for transmission is represented by 1 or more
 * struct iovec fragments (the first frag contains the portals header),
 * followed by 0 or more lnet_kiov_t fragments.
 *
 * On the receive side, initially 1 struct iovec fragment is posted for
 * receive (the header).  Once the header has been received, the payload is
 * received into either struct iovec or lnet_kiov_t fragments, depending on
 * what the header matched or whether the message needs forwarding. */

struct ksock_conn;                              /* forward ref */
struct ksock_peer;                              /* forward ref */
struct ksock_route;                             /* forward ref */

typedef struct                                  /* transmit packet */
{
        struct list_head        tx_list;        /* queue on conn for transmission etc */
        int                     tx_nob;         /* # packet bytes */
        int                     tx_resid;       /* residual bytes */
        int                     tx_niov;        /* # packet iovec frags */
        struct iovec           *tx_iov;         /* packet iovec frags */
        int                     tx_nkiov;       /* # packet page frags */
        lnet_kiov_t            *tx_kiov;        /* packet page frags */
        struct ksock_conn      *tx_conn;        /* owning conn */
        lnet_msg_t             *tx_lnetmsg;     /* lnet message for lnet_finalize() */
#if SOCKNAL_ZC        
        zccd_t                  tx_zccd;        /* zero copy callback descriptor */
#endif
        int                     tx_desc_size;   /* size of this descriptor */
        union {
                struct {
                        struct iovec iov;       /* virt hdr */
                        lnet_kiov_t  kiov[0];   /* paged payload */
                }                  paged;
                struct {
                        struct iovec iov[1];    /* virt hdr + payload */
                }                  virt;
        }                       tx_frags;
} ksock_tx_t;

#define KSOCK_ZCCD_2_TX(ptr)	list_entry (ptr, ksock_tx_t, tx_zccd)
/* network zero copy callback descriptor embedded in ksock_tx_t */

/* space for the rx frag descriptors; we either read a single contiguous
 * header, or up to LNET_MAX_IOV frags of payload of either type. */
typedef union {
        struct iovec     iov[LNET_MAX_IOV];
        lnet_kiov_t      kiov[LNET_MAX_IOV];
} ksock_rxiovspace_t;

#define SOCKNAL_RX_HEADER       1               /* reading header */
#define SOCKNAL_RX_PARSE        2               /* Calling lnet_parse() */
#define SOCKNAL_RX_PARSE_WAIT   3               /* waiting to be told to read the body */
#define SOCKNAL_RX_BODY         4               /* reading body (to deliver here) */
#define SOCKNAL_RX_SLOP         5               /* skipping body */

typedef struct ksock_conn
{ 
        struct ksock_peer  *ksnc_peer;          /* owning peer */
        struct ksock_route *ksnc_route;         /* owning route */
        struct list_head    ksnc_list;          /* stash on peer's conn list */
        struct socket      *ksnc_sock;          /* actual socket */
        void               *ksnc_saved_data_ready; /* socket's original data_ready() callback */
        void               *ksnc_saved_write_space; /* socket's original write_space() callback */
        atomic_t            ksnc_conn_refcount; /* conn refcount */
        atomic_t            ksnc_sock_refcount; /* sock refcount */
        ksock_sched_t	   *ksnc_scheduler;     /* who schedules this connection */
        __u32               ksnc_myipaddr;      /* my IP */
        __u32               ksnc_ipaddr;        /* peer's IP */
        int                 ksnc_port;          /* peer's port */
        int                 ksnc_closing;       /* being shut down */
        int                 ksnc_type;          /* type of connection */
        __u64               ksnc_incarnation;   /* peer's incarnation */
        
        /* reader */
        struct list_head    ksnc_rx_list;       /* where I enq waiting input or a forwarding descriptor */
        cfs_time_t          ksnc_rx_deadline;   /* when (in jiffies) receive times out */
        int                 ksnc_rx_started;    /* started receiving a message */
        int                 ksnc_rx_ready;      /* data ready to read */
        int                 ksnc_rx_scheduled;  /* being progressed */
        int                 ksnc_rx_state;      /* what is being read */
        int                 ksnc_rx_nob_left;   /* # bytes to next hdr/body  */
        int                 ksnc_rx_nob_wanted; /* bytes actually wanted */
        int                 ksnc_rx_niov;       /* # iovec frags */
        struct iovec       *ksnc_rx_iov;        /* the iovec frags */
        int                 ksnc_rx_nkiov;      /* # page frags */
        lnet_kiov_t        *ksnc_rx_kiov;       /* the page frags */
        ksock_rxiovspace_t  ksnc_rx_iov_space;  /* space for frag descriptors */
        void               *ksnc_cookie;        /* rx lnet_finalize passthru arg */
        lnet_hdr_t           ksnc_hdr;           /* where I read headers into */

        /* WRITER */
        struct list_head    ksnc_tx_list;       /* where I enq waiting for output space */
        struct list_head    ksnc_tx_queue;      /* packets waiting to be sent */
        cfs_time_t          ksnc_tx_deadline;   /* when (in jiffies) tx times out */
        int                 ksnc_tx_bufnob;     /* send buffer marker */
        atomic_t            ksnc_tx_nob;        /* # bytes queued */
        int                 ksnc_tx_ready;      /* write space */
        int                 ksnc_tx_scheduled;  /* being progressed */

#if !SOCKNAL_SINGLE_FRAG_RX
        struct iovec        ksnc_rx_scratch_iov[LNET_MAX_IOV];
#endif
#if !SOCKNAL_SINGLE_FRAG_TX
        struct iovec        ksnc_tx_scratch_iov[LNET_MAX_IOV];
#endif
} ksock_conn_t;

#define KSNR_TYPED_ROUTES   ((1 << SOCKLND_CONN_CONTROL) |      \
                             (1 << SOCKLND_CONN_BULK_IN) |      \
                             (1 << SOCKLND_CONN_BULK_OUT))

typedef struct ksock_route
{
        struct list_head    ksnr_list;          /* chain on peer route list */
        struct list_head    ksnr_connd_list;    /* chain on ksnr_connd_routes */
        struct ksock_peer  *ksnr_peer;          /* owning peer */
        atomic_t            ksnr_refcount;      /* # users */
        cfs_time_t          ksnr_timeout;       /* when (in jiffies) reconnection can happen next */
        cfs_duration_t      ksnr_retry_interval; /* how long between retries */
        __u32               ksnr_myipaddr;      /* my IP */
        __u32               ksnr_ipaddr;        /* IP address to connect to */
        int                 ksnr_port;          /* port to connect to */
        unsigned int        ksnr_connecting:4;  /* autoconnect in progress by type */
        unsigned int        ksnr_connected:4;   /* connections established by type */
        unsigned int        ksnr_deleted:1;     /* been removed from peer? */
        unsigned int        ksnr_share_count;   /* created explicitly? */
        int                 ksnr_conn_count;    /* # conns established by this route */
} ksock_route_t;

typedef struct ksock_peer
{
        struct list_head    ksnp_list;          /* stash on global peer list */
        lnet_process_id_t   ksnp_id;            /* who's on the other end(s) */
        atomic_t            ksnp_refcount;      /* # users */
        int                 ksnp_sharecount;    /* lconf usage counter */
        int                 ksnp_closing;       /* being closed */
        int                 ksnp_accepting;     /* # passive connections pending */
        int                 ksnp_error;         /* errno on closing last conn */
        struct list_head    ksnp_conns;         /* all active connections */
        struct list_head    ksnp_routes;        /* routes */
        struct list_head    ksnp_tx_queue;      /* waiting packets */
        cfs_time_t          ksnp_last_alive;    /* when (in jiffies) I was last alive */
        lnet_ni_t          *ksnp_ni;            /* which network */
        int                 ksnp_n_passive_ips; /* # of... */
        __u32               ksnp_passive_ips[LNET_MAX_INTERFACES]; /* preferred local interfaces */
} ksock_peer_t;

typedef struct ksock_connreq
{
        struct list_head    ksncr_list;         /* stash on ksnd_connd_connreqs */
        lnet_ni_t           *ksncr_ni;           /* chosen NI */
        struct socket      *ksncr_sock;         /* accepted socket */
} ksock_connreq_t;

extern ksock_nal_data_t ksocknal_data;
extern ksock_tunables_t ksocknal_tunables;

static inline struct list_head *
ksocknal_nid2peerlist (lnet_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) % ksocknal_data.ksnd_peer_hash_size;

        return (&ksocknal_data.ksnd_peers [hash]);
}

static inline void
ksocknal_conn_addref (ksock_conn_t *conn)
{
        LASSERT (atomic_read(&conn->ksnc_conn_refcount) > 0);
        atomic_inc(&conn->ksnc_conn_refcount);
}

extern void ksocknal_queue_zombie_conn (ksock_conn_t *conn);

static inline void
ksocknal_conn_decref (ksock_conn_t *conn)
{
        LASSERT (atomic_read(&conn->ksnc_conn_refcount) > 0);
        if (atomic_dec_and_test(&conn->ksnc_conn_refcount))
                ksocknal_queue_zombie_conn(conn);
}

static inline int
ksocknal_connsock_addref (ksock_conn_t *conn)
{
        int   rc = -ESHUTDOWN;

        read_lock (&ksocknal_data.ksnd_global_lock);
        if (!conn->ksnc_closing) {
                LASSERT (atomic_read(&conn->ksnc_sock_refcount) > 0);
                atomic_inc(&conn->ksnc_sock_refcount);
                rc = 0;
        }
        read_unlock (&ksocknal_data.ksnd_global_lock);

        return (rc);
}

static inline void
ksocknal_connsock_decref (ksock_conn_t *conn)
{
        LASSERT (atomic_read(&conn->ksnc_sock_refcount) > 0);
        if (atomic_dec_and_test(&conn->ksnc_sock_refcount)) {
                LASSERT (conn->ksnc_closing);
                libcfs_sock_release(conn->ksnc_sock);
                conn->ksnc_sock = NULL;
        }
}

static inline void
ksocknal_route_addref (ksock_route_t *route)
{
        LASSERT (atomic_read(&route->ksnr_refcount) > 0);
        atomic_inc(&route->ksnr_refcount);
}

extern void ksocknal_destroy_route (ksock_route_t *route);

static inline void
ksocknal_route_decref (ksock_route_t *route)
{
        LASSERT (atomic_read (&route->ksnr_refcount) > 0);
        if (atomic_dec_and_test(&route->ksnr_refcount))
                ksocknal_destroy_route (route);
}

static inline void
ksocknal_peer_addref (ksock_peer_t *peer)
{
        LASSERT (atomic_read (&peer->ksnp_refcount) > 0);
        atomic_inc(&peer->ksnp_refcount);
}

extern void ksocknal_destroy_peer (ksock_peer_t *peer);

static inline void
ksocknal_peer_decref (ksock_peer_t *peer)
{
        LASSERT (atomic_read (&peer->ksnp_refcount) > 0);
        if (atomic_dec_and_test(&peer->ksnp_refcount))
                ksocknal_destroy_peer (peer);
}

int ksocknal_startup (lnet_ni_t *ni);
void ksocknal_shutdown (lnet_ni_t *ni);
int ksocknal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int ksocknal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int ksocknal_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, 
                  int delayed, unsigned int niov, 
                  struct iovec *iov, lnet_kiov_t *kiov,
                  unsigned int offset, unsigned int mlen, unsigned int rlen);
int ksocknal_accept(lnet_ni_t *ni, struct socket *sock);

extern int ksocknal_add_peer(lnet_ni_t *ni, lnet_process_id_t id, __u32 ip, int port);
extern ksock_peer_t *ksocknal_find_peer_locked (lnet_ni_t *ni, lnet_process_id_t id);
extern ksock_peer_t *ksocknal_find_peer (lnet_ni_t *ni, lnet_process_id_t id);
extern void ksocknal_peer_failed (ksock_peer_t *peer);
extern int ksocknal_create_conn (lnet_ni_t *ni, ksock_route_t *route,
                                 struct socket *sock, int type);
extern void ksocknal_close_conn_locked (ksock_conn_t *conn, int why);
extern void ksocknal_terminate_conn (ksock_conn_t *conn);
extern void ksocknal_destroy_conn (ksock_conn_t *conn);
extern int ksocknal_close_stale_conns_locked (ksock_peer_t *peer, __u64 incarnation);
extern int ksocknal_close_conn_and_siblings (ksock_conn_t *conn, int why);
extern int ksocknal_close_matching_conns (lnet_process_id_t id, __u32 ipaddr);

extern void ksocknal_queue_tx_locked (ksock_tx_t *tx, ksock_conn_t *conn);
extern void ksocknal_tx_done (lnet_ni_t *ni, ksock_tx_t *tx, int asynch);
extern void ksocknal_txlist_done (lnet_ni_t *ni, struct list_head *txlist);
extern void ksocknal_notify (lnet_ni_t *ni, lnet_nid_t gw_nid, int alive);
extern int ksocknal_thread_start (int (*fn)(void *arg), void *arg);
extern void ksocknal_thread_fini (void);
extern ksock_route_t *ksocknal_find_connecting_route_locked (ksock_peer_t *peer);
extern int ksocknal_new_packet (ksock_conn_t *conn, int skip);
extern int ksocknal_scheduler (void *arg);
extern int ksocknal_connd (void *arg);
extern int ksocknal_reaper (void *arg);
extern int ksocknal_send_hello (lnet_ni_t *ni, ksock_conn_t *conn,
                                lnet_nid_t peer_nid, 
                                __u32 *ipaddrs, int nipaddrs);
extern int ksocknal_recv_hello (lnet_ni_t *ni, ksock_conn_t *conn, 
                                lnet_process_id_t *id, 
                                __u64 *incarnation, __u32 *ipaddrs);

extern void ksocknal_lib_save_callback(struct socket *sock, ksock_conn_t *conn);
extern void ksocknal_lib_set_callback(struct socket *sock,  ksock_conn_t *conn);
extern void ksocknal_lib_act_callback(struct socket *sock, ksock_conn_t *conn);
extern void ksocknal_lib_reset_callback(struct socket *sock, ksock_conn_t *conn);
extern void ksocknal_lib_push_conn (ksock_conn_t *conn);
extern void ksocknal_lib_bind_irq (unsigned int irq);
extern int ksocknal_lib_get_conn_addrs (ksock_conn_t *conn);
extern unsigned int ksocknal_lib_sock_irq (struct socket *sock);
extern int ksocknal_lib_setup_sock (struct socket *so);
extern int ksocknal_lib_send_iov (ksock_conn_t *conn, ksock_tx_t *tx);
extern int ksocknal_lib_send_kiov (ksock_conn_t *conn, ksock_tx_t *tx);
extern void ksocknal_lib_eager_ack (ksock_conn_t *conn);
extern int ksocknal_lib_recv_iov (ksock_conn_t *conn);
extern int ksocknal_lib_recv_kiov (ksock_conn_t *conn);
extern int ksocknal_lib_get_conn_tunables (ksock_conn_t *conn, int *txmem, 
                                           int *rxmem, int *nagle);

extern int ksocknal_lib_tunables_init(void);
extern void ksocknal_lib_tunables_fini(void);
