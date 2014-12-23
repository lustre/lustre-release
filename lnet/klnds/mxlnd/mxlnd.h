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
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 *
 * Copyright (C) 2006 Myricom, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/mxlnd/mxlnd.h
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Scott Atchley <atchley at myri.com>
 */

#include <linux/module.h>       /* module */
#include <linux/kernel.h>       /* module */
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/uio.h>
#include <linux/fs.h>

#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/init.h>         /* module */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>
#include <linux/random.h>
#include <linux/utsname.h>
#include <linux/jiffies.h>      /* msecs_to_jiffies */
#include <asm/semaphore.h>

#include <net/sock.h>
#include <linux/in.h>

#include <asm/byteorder.h>      /* __LITTLE_ENDIAN */
#include <net/arp.h>            /* arp table */
#include <linux/netdevice.h>    /* get_device_by_name */
#include <linux/inetdevice.h>   /* neigh_lookup, etc. */
#include <linux/net.h>          /* sock_create_kern, kernel_connect, sock_release */

#define DEBUG_SUBSYSTEM S_LND

#include "libcfs/libcfs.h"
#include "lnet/lnet.h"
#include "lnet/lib-lnet.h"

#define MX_KERNEL 1
#include "mx_extensions.h"
#include "myriexpress.h"

#if LNET_MAX_IOV > MX_MAX_SEGMENTS
    #error LNET_MAX_IOV is greater then MX_MAX_SEGMENTS
#endif

#define MXLND_MSG_MAGIC         0x4d583130              /* unique magic 'MX10' */
#define MXLND_MSG_VERSION       0x03

/* Using MX's 64 match bits
 * We are using the match bits to specify message type and the cookie.  The
 * highest four bits (60-63) are reserved for message type. Below we specify
 * the types. We reserve the remaining combinations for future use.  The next 8
 * bits (52-59) are reserved for returning a status code for failed GET_DATA
 * (payload) messages. The last 52 bits are used for cookies. That should allow
 * unique cookies for 4 KB messages at 10 Gbps line rate without rollover for
 * about 8 years. That should be enough. */

#define MXLND_MSG_OFFSET        60      /* msg type offset */
#define MXLND_MSG_BITS          (64 - MXLND_MSG_OFFSET)
#define MXLND_MSG_MASK          (((1ULL<<MXLND_MSG_BITS) - 1) << MXLND_MSG_OFFSET)
#define MXLND_MSG_TYPE(x)       (((x) & MXLND_MSG_MASK) >> MXLND_MSG_OFFSET)

#define MXLND_ERROR_OFFSET      52      /* error value offset */
#define MXLND_ERROR_BITS        (MXLND_MSG_OFFSET - MXLND_ERROR_OFFSET)
#define MXLND_ERROR_MASK        (((1ULL<<MXLND_ERROR_BITS) - 1) << MXLND_ERROR_OFFSET)
#define MXLND_ERROR_VAL(x)      (((x) & MXLND_ERROR_MASK) >> MXLND_ERROR_OFFSET)

/* message types */
#define MXLND_MSG_ICON_REQ      0xb     /* mx_iconnect() before CONN_REQ */
#define MXLND_MSG_CONN_REQ      0xc     /* connection request */
#define MXLND_MSG_ICON_ACK      0x9     /* mx_iconnect() before CONN_ACK */
#define MXLND_MSG_CONN_ACK      0xa     /* connection request response */
#define MXLND_MSG_BYE           0xd     /* disconnect msg */
#define MXLND_MSG_EAGER         0xe     /* eager message */
#define MXLND_MSG_NOOP          0x1     /* no msg, return credits */
#define MXLND_MSG_PUT_REQ       0x2     /* put request src->sink */
#define MXLND_MSG_PUT_ACK       0x3     /* put ack     src<-sink */
#define MXLND_MSG_PUT_DATA      0x4     /* put payload src->sink */
#define MXLND_MSG_GET_REQ       0x5     /* get request sink->src */
#define MXLND_MSG_GET_DATA      0x6     /* get payload sink<-src */

/* when to roll-over the cookie value */
#define MXLND_MAX_COOKIE        ((1ULL << MXLND_ERROR_OFFSET) - 1)

/* defaults for configurable parameters */
#define MXLND_N_SCHED           1               /* # schedulers (mx_wait_any() threads) */
#define MXLND_NDAEMONS          3               /* connd, timeoutd, tx_queued */
#define MXLND_MX_BOARD          0               /* Use the first MX NIC if more than 1 avail */
#define MXLND_MX_EP_ID          0               /* MX endpoint ID */
/* timeout for send/recv (jiffies) */
#define MXLND_COMM_TIMEOUT	msecs_to_jiffies(20 * MSEC_PER_SEC)
/* timeout for wait (jiffies) */
#define MXLND_WAIT_TIMEOUT	msecs_to_jiffies(MSEC_PER_SEC)
/* timeout for connections (jiffies) */
#define MXLND_CONNECT_TIMEOUT	msecs_to_jiffies(5 * MSEC_PER_SEC)
#define MXLND_POLLING           1000            /* poll iterations before blocking */
#define MXLND_LOOKUP_COUNT      5               /* how many times to try to resolve MAC */
#define MXLND_MAX_PEERS         1024            /* number of nodes talking to me */

#define MXLND_MSG_SIZE          (4<<10)         /* pre-posted eager message size */
#define MXLND_MSG_QUEUE_DEPTH   8               /* default msg queue depth */
#define MXLND_NTX               256             /* default # of tx msg descriptors */

#define MXLND_HASH_BITS         6               /* the number of bits to hash over */
#define MXLND_HASH_SIZE         (1<<MXLND_HASH_BITS)
                                                /* number of peer lists for lookup.
                                                   we hash over the last N bits of
                                                   the IP address converted to an int. */
#define MXLND_HASH_MASK         (MXLND_HASH_SIZE - 1)
                                                /* ensure we use only the last N bits */

/* derived constants... */
/* TX messages (shared by all connections) */
#define MXLND_TX_MSGS()       (*kmxlnd_tunables.kmx_ntx)
#define MXLND_TX_MSG_BYTES()  (MXLND_TX_MSGS() * MXLND_MSG_SIZE)
#define MXLND_TX_MSG_PAGES()  ((MXLND_TX_MSG_BYTES() + PAGE_SIZE - 1)/PAGE_SIZE)

/* RX messages (per connection) */
#define MXLND_RX_MSGS()       (*kmxlnd_tunables.kmx_peercredits)
#define MXLND_RX_MSG_BYTES()  (MXLND_RX_MSGS() * MXLND_MSG_SIZE)
#define MXLND_RX_MSG_PAGES()  ((MXLND_RX_MSG_BYTES() + PAGE_SIZE - 1)/PAGE_SIZE)
#define MXLND_CREDIT_HIGHWATER() (*kmxlnd_tunables.kmx_peercredits - 2)
                                                /* when to send a noop to return credits */

/* debugging features */
#define MXLND_CKSUM             0       /* checksum kmx_msg_t */
#define MXLND_DEBUG             0       /* additional CDEBUG messages */

/* provide wrappers around LIBCFS_ALLOC/FREE to keep MXLND specific
 * memory usage stats that include pages */

#define MXLND_ALLOC(x, size)					\
	do {							\
		spin_lock(&kmxlnd_data.kmx_mem_lock);		\
		kmxlnd_data.kmx_mem_used += size;		\
		spin_unlock(&kmxlnd_data.kmx_mem_lock);		\
		LIBCFS_ALLOC(x, size);				\
		if (unlikely(x == NULL)) {			\
			spin_lock(&kmxlnd_data.kmx_mem_lock);	\
			kmxlnd_data.kmx_mem_used -= size;	\
			spin_unlock(&kmxlnd_data.kmx_mem_lock);	\
		}						\
	} while (0)

#define MXLND_FREE(x, size)					\
	do {							\
		spin_lock(&kmxlnd_data.kmx_mem_lock);		\
		kmxlnd_data.kmx_mem_used -= size;		\
		spin_unlock(&kmxlnd_data.kmx_mem_lock);		\
		LIBCFS_FREE(x, size);				\
	} while (0)


typedef struct kmx_tunables
{
        int     *kmx_n_waitd;           /* # completion threads */
        int     *kmx_max_peers;         /* max # of potential peers */
        int     *kmx_cksum;             /* checksum small msgs? */
        int     *kmx_ntx;               /* total # of tx */
        int     *kmx_credits;           /* concurrent sends to all peers */
        int     *kmx_peercredits;       /* concurrent sends to 1 peer */
        int     *kmx_board;             /* MX board (NIC) number */
        int     *kmx_ep_id;             /* MX endpoint number */
        char    **kmx_default_ipif;     /* IPoMX interface name */
        int     *kmx_polling;           /* if 0, block. if > 0, poll this many
                                           iterations before blocking */
} kmx_tunables_t;

typedef struct
{
        int               mxg_npages;   /* # pages */
        struct page      *mxg_pages[0];
} kmx_pages_t;

/* global interface state */
typedef struct kmx_data
{
	int                 kmx_init;           /* initialization state */
	atomic_t            kmx_shutdown;       /* shutting down? */
	atomic_t            kmx_nthreads;       /* number of threads */
	struct completion   *kmx_completions;   /* array of completion struct */
	lnet_ni_t	    *kmx_ni;		/* the LND instance */
	u64		    kmx_incarnation;	/* my incarnation value */
	long		    kmx_mem_used;	/* memory used */
	mx_endpoint_t	    kmx_endpt;		/* the MX endpoint */
	mx_endpoint_addr_t  kmx_epa;		/* the MX endpoint address */

	rwlock_t	    kmx_global_lock;	/* global lock */
	spinlock_t	    kmx_mem_lock;	/* memory accounting lock */

	cfs_list_t	    kmx_conn_reqs;	/* list of connection reqs */
	spinlock_t	    kmx_conn_lock;	/* connection list lock */
	struct semaphore    kmx_conn_sem;	/* connection request list */
	cfs_list_t          kmx_conn_zombies;   /* list of zombie connections */
	cfs_list_t          kmx_orphan_msgs;    /* list of txs to cancel */

						/* list of all known peers */
	cfs_list_t          kmx_peers[MXLND_HASH_SIZE];
	atomic_t            kmx_npeers;         /* number of peers */

	kmx_pages_t        *kmx_tx_pages;       /* tx msg pages */

	struct kmx_ctx     *kmx_txs;            /* all tx descriptors */
	cfs_list_t          kmx_tx_idle;        /* list of idle tx */
	spinlock_t	    kmx_tx_idle_lock;	/* lock for idle tx list */
	s32		    kmx_tx_used;	/* txs in use */
	u64		    kmx_tx_next_cookie;	/* unique id for tx */
	cfs_list_t	    kmx_tx_queue;	/* generic send queue */
	spinlock_t	    kmx_tx_queue_lock;	/* lock for generic sends */
	struct semaphore    kmx_tx_queue_sem;	/* semaphore for tx queue */
} kmx_data_t;

#define MXLND_INIT_NOTHING      0       /* in the beginning, there was nothing... */
#define MXLND_INIT_DATA         1       /* main data structures created */
#define MXLND_INIT_TXS          2       /* tx descriptors created */
#define MXLND_INIT_MX           3       /* initiate MX library, open endpoint, get NIC id */
#define MXLND_INIT_THREADS      4       /* waitd, timeoutd, tx_queued threads */
#define MXLND_INIT_ALL          5       /* startup completed */

/************************************************************************
 * MXLND Wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 */

typedef struct kmx_connreq_msg
{
        u32             mxcrm_queue_depth;              /* per peer max messages in flight */
        u32             mxcrm_eager_size;               /* size of preposted eager messages */
} WIRE_ATTR kmx_connreq_msg_t;

typedef struct kmx_eager_msg
{
        lnet_hdr_t      mxem_hdr;                       /* lnet header */
        char            mxem_payload[0];                /* piggy-backed payload */
} WIRE_ATTR kmx_eager_msg_t;

typedef struct kmx_putreq_msg
{
        lnet_hdr_t      mxprm_hdr;                      /* lnet header */
        u64             mxprm_cookie;                   /* opaque completion cookie */
} WIRE_ATTR kmx_putreq_msg_t;

typedef struct kmx_putack_msg
{
        u64             mxpam_src_cookie;               /* reflected completion cookie */
        u64             mxpam_dst_cookie;               /* opaque completion cookie */
} WIRE_ATTR kmx_putack_msg_t;

typedef struct kmx_getreq_msg
{
        lnet_hdr_t      mxgrm_hdr;                      /* lnet header */
        u64             mxgrm_cookie;                   /* opaque completion cookie */
} WIRE_ATTR kmx_getreq_msg_t;

typedef struct kmx_msg
{
        /* First two fields fixed for all time */
        u32             mxm_magic;                      /* MXLND message */
        u16             mxm_version;                    /* version number */

        u8              mxm_type;                       /* message type */
        u8              mxm_credits;                    /* returned credits */
        u32             mxm_nob;                        /* # of bytes in whole message */
        u32             mxm_cksum;                      /* checksum (0 == no checksum) */
        u64             mxm_srcnid;                     /* sender's NID */
        u64             mxm_srcstamp;                   /* sender's incarnation */
        u64             mxm_dstnid;                     /* destination's NID */
        u64             mxm_dststamp;                   /* destination's incarnation */

        union {
                kmx_connreq_msg_t       conn_req;
                kmx_eager_msg_t         eager;
                kmx_putreq_msg_t        put_req;
                kmx_putack_msg_t        put_ack;
                kmx_getreq_msg_t        get_req;
        } WIRE_ATTR mxm_u;
} WIRE_ATTR kmx_msg_t;

/***********************************************************************/

enum kmx_req_type {
        MXLND_REQ_TX    = 0,
        MXLND_REQ_RX    = 1,
};

/* The life cycle of a request */
enum kmx_req_state {
        MXLND_CTX_INIT       = 0,               /* just created */
        MXLND_CTX_IDLE       = 1,               /* available for use */
        MXLND_CTX_PREP       = 2,               /* getting ready for send/recv */
        MXLND_CTX_PENDING    = 3,               /* mx_isend() or mx_irecv() called */
        MXLND_CTX_COMPLETED  = 4,               /* cleaning up after completion or timeout */
        MXLND_CTX_CANCELED   = 5,               /* timed out but still in ctx list */
};

/* Context Structure - generic tx/rx descriptor
 * It represents the context (or state) of each send or receive request.
 * In other LNDs, they have separate TX and RX descriptors and this replaces both.
 *
 * The txs live on the global kmx_txs array for cleanup. The rxs are managed
 * per struct kmx_conn. We will move them between the rx/tx idle lists and the
 * pending list which is monitored by mxlnd_timeoutd().
 */
typedef struct kmx_ctx
{
        enum kmx_req_type   mxc_type;           /* TX or RX */
        u64                 mxc_incarnation;    /* store the peer's incarnation here
                                                   to verify before changing flow
                                                   control credits after completion */
        unsigned long       mxc_deadline;       /* request time out in absolute jiffies */
        enum kmx_req_state  mxc_state;          /* what is the state of the request? */
        cfs_list_t          mxc_list;           /* place on rx/tx idle list, tx q, peer tx */
        cfs_list_t          mxc_rx_list;        /* place on mxp_rx_posted list */

        lnet_nid_t          mxc_nid;            /* dst's NID if peer is not known */
        struct kmx_peer    *mxc_peer;           /* owning peer */
        struct kmx_conn    *mxc_conn;           /* owning conn */
        kmx_msg_t          *mxc_msg;            /* msg hdr mapped to mxc_page */
        lnet_msg_t         *mxc_lntmsg[2];      /* lnet msgs to finalize */

        u8                  mxc_msg_type;       /* what type of message is this? */
        u64                 mxc_cookie;         /* completion cookie */
        u64                 mxc_match;          /* MX match info */
        mx_ksegment_t       mxc_seg;            /* local MX ksegment for non-DATA */
        mx_ksegment_t      *mxc_seg_list;       /* MX ksegment array for DATA */
        int                 mxc_nseg;           /* number of segments */
        unsigned long       mxc_pin_type;       /* MX_PIN_PHYSICAL [| MX_PIN_FULLPAGES] */
        u32                 mxc_nob;            /* number of bytes sent/received */
        mx_request_t        mxc_mxreq;          /* MX request */
        mx_status_t         mxc_status;         /* MX status */
        u32                 mxc_errno;          /* errno for LNET */
        u64                 mxc_get;            /* # of times returned from idle list */
        u64                 mxc_put;            /* # of times returned from idle list */
} kmx_ctx_t;

#define MXLND_CONN_DISCONNECT  -2       /* conn is being destroyed - do not add txs */
#define MXLND_CONN_FAIL        -1       /* connect failed (bad handshake, unavail, etc.) */
#define MXLND_CONN_INIT         0       /* in the beginning, there was nothing... */
#define MXLND_CONN_REQ          1       /* a connection request message is needed */
#define MXLND_CONN_ACK          2       /* a connection ack is needed */
#define MXLND_CONN_WAIT         3       /* waiting for req or ack to complete */
#define MXLND_CONN_READY        4       /* ready to send */

/* store all data from an unexpected CONN_[REQ|ACK] receive */
typedef struct kmx_connparams
{
        cfs_list_t              mxr_list;       /* list to hang on kmx_conn_reqs */
        void                   *mxr_context;    /* context - unused - will hold net */
        mx_endpoint_addr_t      mxr_epa;        /* the peer's epa */
        u64                     mxr_match;      /* the CONN_REQ's match bits */
        u32                     mxr_nob;        /* length of CONN_REQ message */
        struct kmx_peer        *mxr_peer;       /* peer if known */
        struct kmx_conn        *mxr_conn;       /* conn if known */
        kmx_msg_t               mxr_msg;        /* the msg header & connreq_msg_t */
} kmx_connparams_t;

/* connection state - queues for queued and pending msgs */
typedef struct kmx_conn
{
        struct kmx_peer    *mxk_peer;           /* owning peer */
        cfs_list_t          mxk_list;           /* for placing on mxp_conns */
        cfs_list_t          mxk_zombie;         /* for placing on zombies list */
        u64                 mxk_incarnation;    /* connections's incarnation value */
        u32                 mxk_sid;            /* peer's MX session id */
	atomic_t        mxk_refcount;       /* reference counting */
        int                 mxk_status;         /* can we send messages? MXLND_CONN_* */

        mx_endpoint_addr_t  mxk_epa;            /* peer's endpoint address */

	spinlock_t	    mxk_lock;		/* lock */
        unsigned long       mxk_timeout;        /* expiration of oldest pending tx/rx */
        unsigned long       mxk_last_tx;        /* when last tx completed with success */
        unsigned long       mxk_last_rx;        /* when last rx completed */

        kmx_pages_t        *mxk_rx_pages;       /* rx msg pages */
        kmx_ctx_t          *mxk_rxs;            /* the rx descriptors */
        cfs_list_t          mxk_rx_idle;        /* list of idle rx */

        int                 mxk_credits;        /* # of my credits for sending to peer */
        int                 mxk_outstanding;    /* # of credits to return */

        cfs_list_t          mxk_tx_credit_queue; /* send queue for peer */
        cfs_list_t          mxk_tx_free_queue;  /* send queue for peer */
        int                 mxk_ntx_msgs;       /* # of msgs on tx queues */
        int                 mxk_ntx_data ;      /* # of DATA on tx queues */
        int                 mxk_ntx_posted;     /* # of tx msgs in flight */
        int                 mxk_data_posted;    /* # of tx data payloads in flight */

        cfs_list_t          mxk_pending;        /* in flight rxs and txs */
} kmx_conn_t;

/* peer state */
typedef struct kmx_peer
{
        cfs_list_t          mxp_list;           /* for placing on kmx_peers */
        lnet_nid_t          mxp_nid;            /* peer's LNET NID */
        lnet_ni_t          *mxp_ni;             /* LNET interface */
	atomic_t        mxp_refcount;       /* reference counts */

        cfs_list_t          mxp_conns;          /* list of connections */
        kmx_conn_t         *mxp_conn;           /* current connection */
        cfs_list_t          mxp_tx_queue;       /* msgs waiting for a conn */

        u32                 mxp_board;          /* peer's board rank */
        u32                 mxp_ep_id;          /* peer's MX endpoint ID */
        u64                 mxp_nic_id;         /* remote's MX nic_id for mx_connect() */

        unsigned long       mxp_reconnect_time; /* when to retry connect */
        int                 mxp_incompatible;   /* incorrect conn_req values */
} kmx_peer_t;

extern kmx_data_t       kmxlnd_data;
extern kmx_tunables_t   kmxlnd_tunables;

/* required for the LNET API */
int  mxlnd_startup(lnet_ni_t *ni);
void mxlnd_shutdown(lnet_ni_t *ni);
int  mxlnd_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int  mxlnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int  mxlnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, int delayed,
                unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
                unsigned int offset, unsigned int mlen, unsigned int rlen);

/* in mxlnd.c */
extern void mxlnd_thread_stop(long id);
extern void mxlnd_ctx_init(kmx_ctx_t *ctx);
extern int  mxlnd_peer_alloc(kmx_peer_t **peerp, lnet_nid_t nid,
                u32 board, u32 ep_id, u64 nic_id);
extern int mxlnd_alloc_pages(kmx_pages_t **pp, int npages);
extern void mxlnd_free_pages(kmx_pages_t *p);

/* in mxlnd_cb.c */
void mxlnd_eager_recv(void *context, uint64_t match_value, uint32_t length);
extern mx_unexp_handler_action_t mxlnd_unexpected_recv(void *context,
                mx_endpoint_addr_t source, uint64_t match_value, uint32_t length,
                void *data_if_available);
extern void mxlnd_peer_free(kmx_peer_t *peer);
extern void mxlnd_conn_free_locked(kmx_conn_t *conn);
extern void mxlnd_conn_disconnect(kmx_conn_t *conn, int mx_dis, int send_bye);
extern int mxlnd_close_matching_conns(lnet_nid_t nid);
extern void mxlnd_sleep(unsigned long timeout);
extern int  mxlnd_tx_queued(void *arg);
extern void mxlnd_handle_rx_completion(kmx_ctx_t *rx);
extern int  mxlnd_check_sends(kmx_peer_t *peer);
extern int  mxlnd_tx_peer_queued(void *arg);
extern int  mxlnd_request_waitd(void *arg);
extern int  mxlnd_unex_recvd(void *arg);
extern int  mxlnd_timeoutd(void *arg);
extern int mxlnd_free_conn_zombies(void);
extern int  mxlnd_connd(void *arg);
extern int mxlnd_del_peer(lnet_nid_t nid);


/**
 * mxlnd_nid_to_hash - hash the nid
 * @nid - LNET ID
 *
 * Takes the u64 nid and XORs the lowest N bits by the next lowest N bits.
 */
static inline int
mxlnd_nid_to_hash(lnet_nid_t nid)
{
        return (nid & MXLND_HASH_MASK) ^
               ((nid & (MXLND_HASH_MASK << MXLND_HASH_BITS)) >> MXLND_HASH_BITS);
}


#define mxlnd_peer_addref(peer)                                 \
do {                                                            \
	LASSERT(peer != NULL);                                  \
	LASSERT(atomic_read(&(peer)->mxp_refcount) > 0);    	\
	atomic_inc(&(peer)->mxp_refcount);                  	\
} while (0)


#define mxlnd_peer_decref(peer)                                 \
do {                                                            \
	LASSERT(atomic_read(&(peer)->mxp_refcount) > 0);    	\
	if (atomic_dec_and_test(&(peer)->mxp_refcount))     	\
		mxlnd_peer_free(peer);                          \
} while (0)

#define mxlnd_conn_addref(conn)                                 \
do {                                                            \
	LASSERT(conn != NULL);                                  \
	LASSERT(atomic_read(&(conn)->mxk_refcount) > 0);    	\
	atomic_inc(&(conn)->mxk_refcount);                  	\
} while (0)


#define mxlnd_conn_decref(conn)						\
do {									\
	LASSERT(conn != NULL);						\
	LASSERT(atomic_read(&(conn)->mxk_refcount) > 0);		\
	if (atomic_dec_and_test(&(conn)->mxk_refcount)) {		\
		spin_lock(&kmxlnd_data.kmx_conn_lock);			\
		LASSERT((conn)->mxk_status == MXLND_CONN_DISCONNECT);	\
		CDEBUG(D_NET, "adding conn %p to zombies\n", (conn));	\
		cfs_list_add_tail(&(conn)->mxk_zombie,			\
				 &kmxlnd_data.kmx_conn_zombies);	\
		spin_unlock(&kmxlnd_data.kmx_conn_lock);		\
		up(&kmxlnd_data.kmx_conn_sem);				\
	}								\
} while (0)

#define mxlnd_valid_msg_type(type)                              \
do {                                                            \
        LASSERT((type) == MXLND_MSG_EAGER    ||                 \
                (type) == MXLND_MSG_ICON_REQ ||                 \
                (type) == MXLND_MSG_CONN_REQ ||                 \
                (type) == MXLND_MSG_ICON_ACK ||                 \
                (type) == MXLND_MSG_CONN_ACK ||                 \
                (type) == MXLND_MSG_BYE      ||                 \
                (type) == MXLND_MSG_NOOP     ||                 \
                (type) == MXLND_MSG_PUT_REQ  ||                 \
                (type) == MXLND_MSG_PUT_ACK  ||                 \
                (type) == MXLND_MSG_PUT_DATA ||                 \
                (type) == MXLND_MSG_GET_REQ  ||                 \
                (type) == MXLND_MSG_GET_DATA);                  \
} while (0)
