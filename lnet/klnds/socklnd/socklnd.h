/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
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

#ifndef _SOCKLND_SOCKLND_H_
#define _SOCKLND_SOCKLND_H_

#define DEBUG_PORTAL_ALLOC
#define DEBUG_SUBSYSTEM S_LND

#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/if.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/refcount.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/uio.h>
#include <linux/unistd.h>
#include <linux/hashtable.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <lnet/lib-lnet.h>
#include <lnet/socklnd.h>

#include <libcfs/linux/linux-net.h>

#ifndef NETIF_F_CSUM_MASK
# define NETIF_F_CSUM_MASK NETIF_F_ALL_CSUM
#endif

/* assume one thread for each connection type */
#define SOCKNAL_NSCHEDS		3
#define SOCKNAL_NSCHEDS_HIGH	(SOCKNAL_NSCHEDS << 1)

#define SOCKNAL_PEER_HASH_BITS	7	/* log2 of # peer_ni lists */
#define SOCKNAL_INSANITY_RECONN	5000	/* connd is trying on reconn infinitely */
#define SOCKNAL_ENOMEM_RETRY	1	/* seconds between retries */

#define SOCKNAL_SINGLE_FRAG_TX      0	/* disable multi-fragment sends */
#define SOCKNAL_SINGLE_FRAG_RX      0	/* disable multi-fragment receives */

#define SOCKNAL_VERSION_DEBUG       0	/* enable protocol version debugging */

/* risk kmap deadlock on multi-frag I/O (backs off to single-frag if disabled).
 * no risk if we're not running on a CONFIG_HIGHMEM platform. */
#ifdef CONFIG_HIGHMEM
# define SOCKNAL_RISK_KMAP_DEADLOCK  0
#else
# define SOCKNAL_RISK_KMAP_DEADLOCK  1
#endif

/* per scheduler state */
struct ksock_sched {
	/* serialise */
	spinlock_t kss_lock;
	/* conn waiting to be written */
	struct list_head kss_rx_conns;
	struct list_head kss_tx_conns;
	/* zombie noop tx list */
	struct list_head kss_zombie_noop_txs;
	/* where scheduler sleeps */
	wait_queue_head_t kss_waitq;
	/* # connections assigned to this scheduler */
	int kss_nconns;
	/* max allowed threads */
	int kss_nthreads_max;
	/* number of threads */
	int kss_nthreads;
	/* CPT id */
	int kss_cpt;
};

#define KSOCK_CPT_SHIFT			16
#define KSOCK_THREAD_ID(cpt, sid)	(((cpt) << KSOCK_CPT_SHIFT) | (sid))
#define KSOCK_THREAD_CPT(id)		((id) >> KSOCK_CPT_SHIFT)
#define KSOCK_THREAD_SID(id)		((id) & ((1UL << KSOCK_CPT_SHIFT) - 1))

struct ksock_interface {			/* in-use interface */
	int		ksni_index;		/* Linux interface index */
	struct sockaddr_storage ksni_addr;	/* interface's address */
	__u32		ksni_netmask;		/* interface's network mask */
	int		ksni_nroutes;		/* # routes using (active) */
	int		ksni_npeers;		/* # peers using (passive) */
	char		ksni_name[IFNAMSIZ];	/* interface name */
};

struct ksock_tunables {
	/* "stuck" socket timeout (seconds) */
	int              *ksnd_timeout;
	/* # scheduler threads in each pool while starting */
	int		 *ksnd_nscheds;
        int              *ksnd_nconnds;         /* # connection daemons */
        int              *ksnd_nconnds_max;     /* max # connection daemons */
        int              *ksnd_min_reconnectms; /* first connection retry after (ms)... */
        int              *ksnd_max_reconnectms; /* ...exponentially increasing to this */
        int              *ksnd_eager_ack;       /* make TCP ack eagerly? */
        int              *ksnd_typed_conns;     /* drive sockets by type? */
        int              *ksnd_min_bulk;        /* smallest "large" message */
        int              *ksnd_tx_buffer_size;  /* socket tx buffer size */
        int              *ksnd_rx_buffer_size;  /* socket rx buffer size */
        int              *ksnd_nagle;           /* enable NAGLE? */
        int              *ksnd_round_robin;     /* round robin for multiple interfaces */
        int              *ksnd_keepalive;       /* # secs for sending keepalive NOOP */
        int              *ksnd_keepalive_idle;  /* # idle secs before 1st probe */
        int              *ksnd_keepalive_count; /* # probes */
        int              *ksnd_keepalive_intvl; /* time between probes */
        int              *ksnd_credits;         /* # concurrent sends */
        int              *ksnd_peertxcredits;   /* # concurrent sends to 1 peer_ni */
        int              *ksnd_peerrtrcredits;  /* # per-peer_ni router buffer credits */
        int              *ksnd_peertimeout;     /* seconds to consider peer_ni dead */
        int              *ksnd_enable_csum;     /* enable check sum */
        int              *ksnd_inject_csum_error; /* set non-zero to inject checksum error */
        int              *ksnd_nonblk_zcack;    /* always send zc-ack on non-blocking connection */
        unsigned int     *ksnd_zc_min_payload;  /* minimum zero copy payload size */
        int              *ksnd_zc_recv;         /* enable ZC receive (for Chelsio TOE) */
        int              *ksnd_zc_recv_min_nfrags; /* minimum # of fragments to enable ZC receive */
        int              *ksnd_irq_affinity;    /* enable IRQ affinity? */
#ifdef SOCKNAL_BACKOFF
        int              *ksnd_backoff_init;    /* initial TCP backoff */
        int              *ksnd_backoff_max;     /* maximum TCP backoff */
#endif
#if SOCKNAL_VERSION_DEBUG
        int              *ksnd_protocol;        /* protocol version */
#endif
	int              *ksnd_conns_per_peer;  /* for typed mode, yields:
						 * 1 + 2*conns_per_peer total
						 * for untyped:
						 * conns_per_peer total
						 */
};

struct ksock_net {
	__u64		  ksnn_incarnation;	/* my epoch */
	struct list_head  ksnn_list;		/* chain on global list */
	atomic_t	  ksnn_npeers;		/* # peers */
	struct ksock_interface ksnn_interface;  /* IP interface */
};
/* When the ksock_net is shut down, this (negative) bias is added to
 * ksnn_npeers, which prevents new peers from being added.
 */
#define SOCKNAL_SHUTDOWN_BIAS  (INT_MIN+1)

/** connd timeout */
#define SOCKNAL_CONND_TIMEOUT  120
/** reserved thread for accepting & creating new connd */
#define SOCKNAL_CONND_RESV     1

struct ksock_nal_data {
	int			ksnd_init;	/* initialisation state */
	int			ksnd_nnets;	/* # networks set up */
	struct list_head	ksnd_nets;	/* list of nets */
	/* stabilize peer_ni/conn ops */
	rwlock_t		ksnd_global_lock;
	/* hash table of all my known peers */
	DECLARE_HASHTABLE(ksnd_peers, SOCKNAL_PEER_HASH_BITS);

	atomic_t		ksnd_nthreads;	/* # live threads */
	int			ksnd_shuttingdown; /* tell threads to exit */
	/* schedulers information */
	struct ksock_sched	**ksnd_schedulers;

	atomic_t      ksnd_nactive_txs;    /* #active txs */

	/* conns to close: reaper_lock*/
	struct list_head	ksnd_deathrow_conns;
	/* conns to free: reaper_lock */
	struct list_head	ksnd_zombie_conns;
	/* conns to retry: reaper_lock*/
	struct list_head	ksnd_enomem_conns;
	/* reaper sleeps here */
	wait_queue_head_t       ksnd_reaper_waitq;
	/* when reaper will wake */
	time64_t		ksnd_reaper_waketime;
	/* serialise */
	spinlock_t	  ksnd_reaper_lock;

	int               ksnd_enomem_tx;      /* test ENOMEM sender */
	int               ksnd_stall_tx;       /* test sluggish sender */
	int               ksnd_stall_rx;       /* test sluggish receiver */

	/* incoming connection requests */
	struct list_head	ksnd_connd_connreqs;
	/* routes waiting to be connected */
	struct list_head	ksnd_connd_routes;
	/* connds sleep here */
	wait_queue_head_t	ksnd_connd_waitq;
	/* # connds connecting */
	int			ksnd_connd_connecting;
	/** time stamp of the last failed connecting attempt */
	time64_t		ksnd_connd_failed_stamp;
	/** # starting connd */
	unsigned		ksnd_connd_starting;
	/** time stamp of the last starting connd */
	time64_t		ksnd_connd_starting_stamp;
	/** # running connd */
	unsigned		ksnd_connd_running;
	/* serialise */
	spinlock_t		ksnd_connd_lock;

	/* list head for freed noop tx */
	struct list_head	ksnd_idle_noop_txs;
	/* serialise, g_lock unsafe */
	spinlock_t		ksnd_tx_lock;
};

#define SOCKNAL_INIT_NOTHING    0
#define SOCKNAL_INIT_DATA       1
#define SOCKNAL_INIT_ALL        2

/* A packet just assembled for transmission is represented by 1
 * struct iovec fragment - the portals header -  followed by 0
 * or more struct bio_vec fragments.
 *
 * On the receive side, initially 1 struct kvec fragment is posted for
 * receive (the header).  Once the header has been received, the payload is
 * received into struct bio_vec fragments.
 */
struct ksock_conn;				/* forward ref */
struct ksock_conn_cb;				/* forward ref */
struct ksock_proto;				/* forward ref */

struct ksock_tx {			/* transmit packet */
	struct list_head tx_list;	/* queue on conn for transmission etc */
	struct list_head tx_zc_list;	/* queue on peer_ni for ZC request */
	refcount_t	tx_refcount;	/* tx reference count */
	int		tx_nob;		/* # packet bytes */
	int		tx_resid;	/* residual bytes */
	int		tx_niov;	/* # packet kvec frags */
	int		tx_nkiov;	/* # packet page frags */
	unsigned short	tx_zc_aborted;	/* aborted ZC request */
	unsigned short	tx_zc_capable:1; /* payload is large enough for ZC */
	unsigned short	tx_zc_checked:1; /* Have I checked if I should ZC? */
	unsigned short	tx_nonblk:1;	/* it's a non-blocking ACK */
	struct bio_vec *tx_kiov;	/* packet page frags */
	struct ksock_conn *tx_conn;	/* owning conn */
	struct lnet_msg	*tx_lnetmsg;	/* lnet message for lnet_finalize() */
	time64_t	tx_deadline;	/* when (in secs) tx times out */
	struct ksock_msg tx_msg;	/* socklnd message buffer */
	int		tx_desc_size;	/* size of this descriptor */
	enum lnet_msg_hstatus tx_hstatus; /* health status of tx */
	struct kvec	tx_hdr;		/* virt hdr */
	struct bio_vec	tx_payload[0];	/* paged payload */
};

#define KSOCK_NOOP_TX_SIZE  ((int)offsetof(struct ksock_tx, tx_payload[0]))

/* space for the rx frag descriptors; we either read a single contiguous
 * header, or up to LNET_MAX_IOV frags of payload of either type. */
union ksock_rxiovspace {
	struct kvec	iov[LNET_MAX_IOV];
	struct bio_vec	kiov[LNET_MAX_IOV];
};

#define SOCKNAL_RX_KSM_HEADER   1               /* reading ksock message header */
#define SOCKNAL_RX_LNET_HEADER  2               /* reading lnet message header */
#define SOCKNAL_RX_PARSE        3               /* Calling lnet_parse() */
#define SOCKNAL_RX_PARSE_WAIT   4               /* waiting to be told to read the body */
#define SOCKNAL_RX_LNET_PAYLOAD 5               /* reading lnet payload (to deliver here) */
#define SOCKNAL_RX_SLOP         6               /* skipping body */

struct ksock_conn {
	struct ksock_peer_ni	*ksnc_peer;		/* owning peer_ni */
	struct ksock_conn_cb	*ksnc_conn_cb;		/* owning conn control block */
	struct list_head	ksnc_list;		/* on peer_ni's conn list */
	struct socket		*ksnc_sock;		/* actual socket */
	void			*ksnc_saved_data_ready; /* socket's original
							 * data_ready() cb */
	void			*ksnc_saved_write_space; /* socket's original
							  * write_space() cb */
	refcount_t		ksnc_conn_refcount;	/* conn refcount */
	refcount_t		ksnc_sock_refcount;	/* sock refcount */
	struct ksock_sched	*ksnc_scheduler;	/* who schedules this
							 * connection */
	struct sockaddr_storage ksnc_myaddr;		/* my address */
	struct sockaddr_storage ksnc_peeraddr;		/*  peer_ni's address */
	signed int		ksnc_type:3;		/* type of connection,
							 * should be signed
							 * value */
	unsigned int		ksnc_closing:1;		/* being shut down */
	unsigned int		ksnc_flip:1;		/* flip or not, only for V2.x */
	unsigned int		ksnc_zc_capable:1;	/* enable to ZC */
	const struct ksock_proto *ksnc_proto; /* protocol for the connection */

	/* READER */

	/* where I enq waiting input or a forwarding descriptor */
	struct list_head   ksnc_rx_list;
	time64_t		ksnc_rx_deadline; /* when (in seconds) receive times out */
        __u8                  ksnc_rx_started;  /* started receiving a message */
        __u8                  ksnc_rx_ready;    /* data ready to read */
        __u8                  ksnc_rx_scheduled;/* being progressed */
        __u8                  ksnc_rx_state;    /* what is being read */
        int                   ksnc_rx_nob_left; /* # bytes to next hdr/body */
        int                   ksnc_rx_nob_wanted; /* bytes actually wanted */
	int                   ksnc_rx_niov;     /* # kvec frags */
	struct kvec          *ksnc_rx_iov;      /* the kvec frags */
	int                   ksnc_rx_nkiov;    /* # page frags */
	struct bio_vec       *ksnc_rx_kiov;     /* the page frags */
	union ksock_rxiovspace	ksnc_rx_iov_space;/* space for frag descriptors */
	__u32                 ksnc_rx_csum;     /* partial checksum for incoming
						 * data */
	struct lnet_msg      *ksnc_lnet_msg;    /* rx lnet_finalize arg*/
	struct ksock_msg	ksnc_msg;	/* incoming message buffer:
						 * V2.x message takes the
						 * whole struct
						 * V1.x message is a bare
						 * struct lnet_hdr, it's stored
						 * in ksnc_msg.ksm_u.lnetmsg
						 */
	/* -- WRITER -- */
	/* where I enq waiting for output space */
	struct list_head	ksnc_tx_list;
	/* packets waiting to be sent */
	struct list_head	ksnc_tx_queue;
	/* next TX that can carry a LNet message or ZC-ACK */
	struct ksock_tx		*ksnc_tx_carrier;
	/* when (in seconds) tx times out */
	time64_t		ksnc_tx_deadline;
	/* send buffer marker */
	int			ksnc_tx_bufnob;
	/* # bytes queued */
	atomic_t		ksnc_tx_nob;
	/* write space */
	int			ksnc_tx_ready;
	/* being progressed */
	int			ksnc_tx_scheduled;
	/* time stamp of the last posted TX */
	time64_t		ksnc_tx_last_post;
};

#define SOCKNAL_CONN_COUNT_MAX_BITS	8	/* max conn count bits */

struct ksock_conn_cb {
	struct list_head	ksnr_connd_list;/* chain on ksnr_connd_routes */
	struct ksock_peer_ni   *ksnr_peer;	/* owning peer_ni */
	refcount_t		ksnr_refcount;	/* # users */
	time64_t		ksnr_timeout;	/* when (in secs) reconnection
						 * can happen next
						 */
	time64_t		ksnr_retry_interval;/* secs between retries */
	int			ksnr_myiface;	/* interface index */
	struct sockaddr_storage	ksnr_addr;	/* IP address to connect to */
	unsigned int		ksnr_scheduled:1;/* scheduled for attention */
	unsigned int		ksnr_connecting:1;/* connection in progress */
	unsigned int		ksnr_connected:4;/* connections by type */
	unsigned int		ksnr_deleted:1;	/* been removed from peer_ni? */
	unsigned int		ksnr_ctrl_conn_count:1; /* # conns by type */
	unsigned int		ksnr_blki_conn_count:8;
	unsigned int		ksnr_blko_conn_count:8;
	int			ksnr_conn_count;/* total # conns for this cb */

};

#define SOCKNAL_KEEPALIVE_PING          1       /* cookie for keepalive ping */

struct ksock_peer_ni {
	struct hlist_node	ksnp_list;	/* stash on global peer_ni list */
	time64_t		ksnp_last_alive;/* when (in seconds) I was last alive */
	struct lnet_process_id	ksnp_id;	/* who's on the other end(s) */
	refcount_t		ksnp_refcount;	/* # users */
	int			ksnp_closing;	/* being closed */
	int			ksnp_accepting;	/* # passive connections pending */
	int			ksnp_error;	/* errno on closing last conn */
	__u64			ksnp_zc_next_cookie;/* ZC completion cookie */
	__u64			ksnp_incarnation;   /* latest known peer_ni incarnation */
	const struct ksock_proto *ksnp_proto;	/* latest known protocol */
	struct list_head	ksnp_conns;	/* all active connections */
	struct ksock_conn_cb	*ksnp_conn_cb;	/* conn control block */
	struct list_head	ksnp_tx_queue;	/* waiting packets */
	spinlock_t		ksnp_lock;	/* serialize, g_lock unsafe */
	/* zero copy requests wait for ACK  */
	struct list_head	ksnp_zc_req_list;
	time64_t		ksnp_send_keepalive; /* time to send keepalive */
	struct lnet_ni		*ksnp_ni;	/* which network */
	int			ksnp_n_passive_ips; /* # of... */
	__u32			ksnp_passive_ips[LNET_INTERFACES_NUM]; /* preferred local interfaces */
};

struct ksock_connreq {
	/* stash on ksnd_connd_connreqs */
	struct list_head	ksncr_list;
	/* chosen NI */
	struct lnet_ni		*ksncr_ni;
	/* accepted socket */
	struct socket		*ksncr_sock;
};

extern struct ksock_nal_data ksocknal_data;
extern struct ksock_tunables ksocknal_tunables;

#define SOCKNAL_MATCH_NO        0        /* TX can't match type of connection */
#define SOCKNAL_MATCH_YES       1        /* TX matches type of connection */
#define SOCKNAL_MATCH_MAY       2        /* TX can be sent on the connection, but not preferred */

struct ksock_proto {
        int           pro_version;                                              /* version number of protocol */
	int         (*pro_send_hello)(struct ksock_conn *, struct ksock_hello_msg *);     /* handshake function */
	int         (*pro_recv_hello)(struct ksock_conn *, struct ksock_hello_msg *, int);/* handshake function */
	void        (*pro_pack)(struct ksock_tx *);                                  /* message pack */
	void        (*pro_unpack)(struct ksock_msg *);				/* message unpack */
	struct ksock_tx *(*pro_queue_tx_msg)(struct ksock_conn *, struct ksock_tx *);          /* queue tx on the connection */
	int         (*pro_queue_tx_zcack)(struct ksock_conn *, struct ksock_tx *, __u64); /* queue ZC ack on the connection */
	int         (*pro_handle_zcreq)(struct ksock_conn *, __u64, int);            /* handle ZC request */
	int         (*pro_handle_zcack)(struct ksock_conn *, __u64, __u64);          /* handle ZC ACK */
	int         (*pro_match_tx)(struct ksock_conn *, struct ksock_tx *, int);         /* msg type matches the connection type:
                                                                                 * return value:
                                                                                 *   return MATCH_NO  : no
                                                                                 *   return MATCH_YES : matching type
                                                                                 *   return MATCH_MAY : can be backup */
};

extern const struct ksock_proto ksocknal_protocol_v1x;
extern const struct ksock_proto ksocknal_protocol_v2x;
extern const struct ksock_proto ksocknal_protocol_v3x;

#define KSOCK_PROTO_V1_MAJOR    LNET_PROTO_TCP_VERSION_MAJOR
#define KSOCK_PROTO_V1_MINOR    LNET_PROTO_TCP_VERSION_MINOR
#define KSOCK_PROTO_V1          KSOCK_PROTO_V1_MAJOR

#ifndef CPU_MASK_NONE
#define CPU_MASK_NONE   0UL
#endif

static inline __u32 ksocknal_csum(__u32 crc, unsigned char const *p, size_t len)
{
#if 1
	return crc32_le(crc, p, len);
#else
	while (len-- > 0)
		crc = ((crc + 0x100) & ~0xff) | ((crc + *p++) & 0xff) ;

	return crc;
#endif
}

static inline int
ksocknal_conn_cb_mask(void)
{
	if (!*ksocknal_tunables.ksnd_typed_conns)
		return BIT(SOCKLND_CONN_ANY);

	return (BIT(SOCKLND_CONN_CONTROL) |
		BIT(SOCKLND_CONN_BULK_IN) |
		BIT(SOCKLND_CONN_BULK_OUT));
}

static inline void
ksocknal_conn_addref(struct ksock_conn *conn)
{
	refcount_inc(&conn->ksnc_conn_refcount);
}

extern void ksocknal_queue_zombie_conn(struct ksock_conn *conn);
extern void ksocknal_finalize_zcreq(struct ksock_conn *conn);

static inline void
ksocknal_conn_decref(struct ksock_conn *conn)
{
	if (refcount_dec_and_test(&conn->ksnc_conn_refcount))
		ksocknal_queue_zombie_conn(conn);
}

static inline int
ksocknal_connsock_addref(struct ksock_conn *conn)
{
	int rc = -ESHUTDOWN;

	read_lock(&ksocknal_data.ksnd_global_lock);
	if (!conn->ksnc_closing) {
		refcount_inc(&conn->ksnc_sock_refcount);
		rc = 0;
	}
	read_unlock(&ksocknal_data.ksnd_global_lock);

	return (rc);
}

static inline void
ksocknal_connsock_decref(struct ksock_conn *conn)
{
	if (refcount_dec_and_test(&conn->ksnc_sock_refcount)) {
		LASSERT (conn->ksnc_closing);
		sock_release(conn->ksnc_sock);
		conn->ksnc_sock = NULL;
		ksocknal_finalize_zcreq(conn);
	}
}

static inline void
ksocknal_tx_addref(struct ksock_tx *tx)
{
	refcount_inc(&tx->tx_refcount);
}

extern void ksocknal_tx_prep(struct ksock_conn *, struct ksock_tx *tx);
extern void ksocknal_tx_done(struct lnet_ni *ni, struct ksock_tx *tx, int error);

static inline void
ksocknal_tx_decref(struct ksock_tx *tx)
{
	if (refcount_dec_and_test(&tx->tx_refcount))
		ksocknal_tx_done(NULL, tx, 0);
}

static inline void
ksocknal_conn_cb_addref(struct ksock_conn_cb  *conn_cb)
{
	refcount_inc(&conn_cb->ksnr_refcount);
}

extern void ksocknal_destroy_conn_cb(struct ksock_conn_cb *conn_cb);

static inline void
ksocknal_conn_cb_decref(struct ksock_conn_cb *conn_cb)
{
	if (refcount_dec_and_test(&conn_cb->ksnr_refcount))
		ksocknal_destroy_conn_cb(conn_cb);
}

static inline void
ksocknal_peer_addref(struct ksock_peer_ni *peer_ni)
{
	refcount_inc(&peer_ni->ksnp_refcount);
}

extern void ksocknal_destroy_peer(struct ksock_peer_ni *peer_ni);

static inline void
ksocknal_peer_decref(struct ksock_peer_ni *peer_ni)
{
	if (refcount_dec_and_test(&peer_ni->ksnp_refcount))
		ksocknal_destroy_peer(peer_ni);
}

static inline int ksocknal_timeout(void)
{
	return *ksocknal_tunables.ksnd_timeout ?: lnet_get_lnd_timeout();
}

static inline int ksocknal_conns_per_peer(void)
{
	return *ksocknal_tunables.ksnd_conns_per_peer ?: 1;
}

int ksocknal_startup(struct lnet_ni *ni);
void ksocknal_shutdown(struct lnet_ni *ni);
int ksocknal_ctl(struct lnet_ni *ni, unsigned int cmd, void *arg);
int ksocknal_send(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg);
int ksocknal_recv(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg,
		  int delayed, unsigned int niov,
		  struct bio_vec *kiov,
                  unsigned int offset, unsigned int mlen, unsigned int rlen);
int ksocknal_accept(struct lnet_ni *ni, struct socket *sock);

int ksocknal_add_peer(struct lnet_ni *ni, struct lnet_process_id id,
		      struct sockaddr *addr);
struct ksock_peer_ni *ksocknal_find_peer_locked(struct lnet_ni *ni,
					   struct lnet_process_id id);
struct ksock_peer_ni *ksocknal_find_peer(struct lnet_ni *ni,
				    struct lnet_process_id id);
extern void ksocknal_peer_failed(struct ksock_peer_ni *peer_ni);
extern int ksocknal_create_conn(struct lnet_ni *ni,
				struct ksock_conn_cb *conn_cb,
				struct socket *sock, int type);
extern void ksocknal_close_conn_locked(struct ksock_conn *conn, int why);
extern void ksocknal_terminate_conn(struct ksock_conn *conn);
extern void ksocknal_destroy_conn(struct ksock_conn *conn);
extern int  ksocknal_close_peer_conns_locked(struct ksock_peer_ni *peer_ni,
					     struct sockaddr *peer, int why);
extern int ksocknal_close_conn_and_siblings(struct ksock_conn *conn, int why);
int ksocknal_close_matching_conns(struct lnet_process_id id, __u32 ipaddr);
extern struct ksock_conn *ksocknal_find_conn_locked(struct ksock_peer_ni *peer_ni,
						    struct ksock_tx *tx, int nonblk);

extern int  ksocknal_launch_packet(struct lnet_ni *ni, struct ksock_tx *tx,
				   struct lnet_process_id id);
extern struct ksock_tx *ksocknal_alloc_tx(int type, int size);
extern void ksocknal_free_tx(struct ksock_tx *tx);
extern struct ksock_tx *ksocknal_alloc_tx_noop(__u64 cookie, int nonblk);
extern void ksocknal_next_tx_carrier(struct ksock_conn *conn);
extern void ksocknal_queue_tx_locked(struct ksock_tx *tx, struct ksock_conn *conn);
extern void ksocknal_txlist_done(struct lnet_ni *ni, struct list_head *txlist,
				 int error);
extern int ksocknal_thread_start(int (*fn)(void *arg), void *arg, char *name);
extern void ksocknal_thread_fini(void);
extern void ksocknal_launch_all_connections_locked(struct ksock_peer_ni *peer_ni);
extern struct ksock_conn_cb *ksocknal_find_connectable_conn_cb_locked(struct ksock_peer_ni *peer_ni);
extern struct ksock_conn_cb *ksocknal_find_connecting_conn_cb_locked(struct ksock_peer_ni *peer_ni);
extern int ksocknal_new_packet(struct ksock_conn *conn, int skip);
extern int ksocknal_scheduler(void *arg);
extern int ksocknal_connd(void *arg);
extern int ksocknal_reaper(void *arg);
int ksocknal_send_hello(struct lnet_ni *ni, struct ksock_conn *conn,
			lnet_nid_t peer_nid, struct ksock_hello_msg *hello);
int ksocknal_recv_hello(struct lnet_ni *ni, struct ksock_conn *conn,
			struct ksock_hello_msg *hello,
			struct lnet_process_id *id,
			__u64 *incarnation);
extern void ksocknal_read_callback(struct ksock_conn *conn);
extern void ksocknal_write_callback(struct ksock_conn *conn);

extern int ksocknal_lib_zc_capable(struct ksock_conn *conn);
extern void ksocknal_lib_save_callback(struct socket *sock, struct ksock_conn *conn);
extern void ksocknal_lib_set_callback(struct socket *sock,  struct ksock_conn *conn);
extern void ksocknal_lib_reset_callback(struct socket *sock,
					struct ksock_conn *conn);
extern void ksocknal_lib_push_conn(struct ksock_conn *conn);
extern int ksocknal_lib_get_conn_addrs(struct ksock_conn *conn);
extern int ksocknal_lib_setup_sock(struct socket *so);
extern int ksocknal_lib_send_hdr(struct ksock_conn *conn, struct ksock_tx *tx,
				 struct kvec *scratch_iov);
extern int ksocknal_lib_send_kiov(struct ksock_conn *conn, struct ksock_tx *tx,
				  struct kvec *scratch_iov);
extern void ksocknal_lib_eager_ack(struct ksock_conn *conn);
extern int ksocknal_lib_recv_iov(struct ksock_conn *conn,
				 struct kvec *scratchiov);
extern int ksocknal_lib_recv_kiov(struct ksock_conn *conn, struct page **pages,
		       struct kvec *scratchiov);
extern int ksocknal_lib_get_conn_tunables(struct ksock_conn *conn, int *txmem,
					  int *rxmem, int *nagle);

extern int ksocknal_tunables_init(void);

extern void ksocknal_lib_csum_tx(struct ksock_tx *tx);

extern int ksocknal_lib_memory_pressure(struct ksock_conn *conn);

#endif /* _SOCKLND_SOCKLND_H_ */
