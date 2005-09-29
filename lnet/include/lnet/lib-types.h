/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * p30/lib-types.h
 *
 * Types used by the library side routines that do not need to be
 * exposed to the user application
 */

#ifndef __LNET_LIB_TYPES_H__
#define __LNET_LIB_TYPES_H__

#if defined(__linux__)
#include <lnet/linux/lib-types.h>
#elif defined(__APPLE__)
#include <lnet/darwin/lib-types.h>
#else
#error Unsupported Operating System
#endif

#include <libcfs/libcfs.h>
#include <libcfs/list.h>
#include <lnet/types.h>

#define WIRE_ATTR	__attribute__((packed))

/* The wire handle's interface cookie only matches one network interface in
 * one epoch (i.e. new cookie when the interface restarts or the node
 * reboots).  The object cookie only matches one object on that interface
 * during that object's lifetime (i.e. no cookie re-use). */
typedef struct {
        __u64 wh_interface_cookie;
        __u64 wh_object_cookie;
} WIRE_ATTR lnet_handle_wire_t;

/* byte-flip insensitive! */
#define LNET_WIRE_HANDLE_NONE \
((const lnet_handle_wire_t) {.wh_interface_cookie = -1, .wh_object_cookie = -1})

typedef enum {
        LNET_MSG_ACK = 0,
        LNET_MSG_PUT,
        LNET_MSG_GET,
        LNET_MSG_REPLY,
        LNET_MSG_HELLO,
} lnet_msg_type_t;

/* The variant fields of the portals message header are aligned on an 8
 * byte boundary in the message header.  Note that all types used in these
 * wire structs MUST be fixed size and the smaller types are placed at the
 * end. */
typedef struct lnet_ack {
        lnet_handle_wire_t  dst_wmd;
        __u64               match_bits;
        __u32               mlength;
} WIRE_ATTR lnet_ack_t;

typedef struct lnet_put {
        lnet_handle_wire_t  ack_wmd;
        __u64               match_bits;
        __u64               hdr_data;
        __u32               ptl_index;
        __u32               offset;
} WIRE_ATTR lnet_put_t;

typedef struct lnet_get {
        lnet_handle_wire_t  return_wmd;
        __u64               match_bits;
        __u32               ptl_index;
        __u32               src_offset;
        __u32               sink_length;
} WIRE_ATTR lnet_get_t;

typedef struct lnet_reply {
        lnet_handle_wire_t  dst_wmd;
} WIRE_ATTR lnet_reply_t;

typedef struct lnet_hello {
        __u64              incarnation;
        __u32              type;
} WIRE_ATTR lnet_hello_t;

typedef struct {
        lnet_nid_t          dest_nid;
        lnet_nid_t          src_nid;
        lnet_pid_t          dest_pid;
        lnet_pid_t          src_pid;
        __u32               type;               /* lnet_msg_type_t */
        __u32               payload_length;     /* payload data to follow */
        /*<------__u64 aligned------->*/
        union {
                lnet_ack_t   ack;
                lnet_put_t   put;
                lnet_get_t   get;
                lnet_reply_t reply;
                lnet_hello_t hello;
        } msg;
} WIRE_ATTR lnet_hdr_t;

/* A HELLO message contains a magic number and protocol version
 * code in the header's dest_nid, the peer's NID in the src_nid, and
 * LNET_MSG_HELLO in the type field.  All other common fields are zero
 * (including payload_size; i.e. no payload).  
 * This is for use by byte-stream LNDs (e.g. TCP/IP) to check the peer is
 * running the same protocol and to find out its NID. These LNDs should
 * exchange HELLO messages when a connection is first established.  Individual
 * LNDs can put whatever else they fancy in lnet_hdr_t::msg.
 */
typedef struct {
        __u32	magic;                          /* LNET_PROTO_TCP_MAGIC */
        __u16   version_major;                  /* increment on incompatible change */
        __u16   version_minor;                  /* increment on compatible change */
} WIRE_ATTR lnet_magicversion_t;

/* PROTO MAGIC for LNDs that once used their own private acceptor */
#define LNET_PROTO_OPENIB_MAGIC             0x0be91b91
#define LNET_PROTO_RA_MAGIC                 0x0be91b92
#define LNET_PROTO_TCP_MAGIC                0xeebc0ded

#define LNET_PROTO_TCP_VERSION_MAJOR        1
#define LNET_PROTO_TCP_VERSION_MINOR        0

/* Acceptor connection request */
typedef struct {
        __u32       acr_magic;                  /* PTL_ACCEPTOR_PROTO_MAGIC */
        __u32       acr_version;                /* protocol version */
        __u64       acr_nid;                    /* target NID */
} WIRE_ATTR lnet_acceptor_connreq_t;

#define LNET_PROTO_ACCEPTOR_MAGIC         0xacce7100
#define LNET_PROTO_ACCEPTOR_VERSION       1

/* forward refs */
struct lnet_libmd;

typedef struct lnet_msg {
        struct list_head    msg_activelist;
        struct list_head    msg_list;           /* Q for credits */

        lnet_process_id_t   msg_target;
        __u32               msg_type;

        int                 msg_target_is_router:1; /* sending to a router */
        int                 msg_routing:1;      /* being forwarded */
        int                 msg_ack:1;          /* ack on finalize (PUT) */
        int                 msg_sending:1;      /* outgoing message */
        int                 msg_receiving:1;    /* being received */
        int                 msg_recvaftersend:1; /* lnd_recv() outstanding */
        int                 msg_delayed:1;      /* had to Q for buffer or tx credit */
        int                 msg_txcredit:1;     /* taken an NI send credit */
        int                 msg_peertxcredit:1; /* taken a peer send credit */
        int                 msg_rtrcredit:1;    /* taken a globel router credit */
        int                 msg_peerrtrcredit:1; /* taken a peer router credit */
        int                 msg_onactivelist:1; /* on the activelist */

        struct lnet_peer   *msg_txpeer;         /* peer I'm sending to */
        struct lnet_peer   *msg_rxpeer;         /* peer I received from (routed only) */

        void               *msg_private;
        struct lnet_libmd  *msg_md;

        unsigned int        msg_len;
        unsigned int        msg_offset;
        unsigned int        msg_niov;
        struct iovec       *msg_iov;
        lnet_kiov_t        *msg_kiov;

        lnet_event_t        msg_ev;
        lnet_hdr_t          msg_hdr;
} lnet_msg_t;


typedef struct lnet_libhandle {
        struct list_head  lh_hash_chain;
        __u64             lh_cookie;
} lnet_libhandle_t;

#define lh_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

typedef struct lnet_eq {
        struct list_head  eq_list;
        lnet_libhandle_t  eq_lh;
        lnet_seq_t        eq_enq_seq;
        lnet_seq_t        eq_deq_seq;
        unsigned int      eq_size;
        lnet_event_t     *eq_events;
        int               eq_refcount;
        lnet_eq_handler_t eq_callback;
} lnet_eq_t;

typedef struct lnet_me {
        struct list_head   me_list;
        lnet_libhandle_t   me_lh;
        lnet_process_id_t  me_match_id;
        __u64              me_match_bits;
        __u64              me_ignore_bits;
        lnet_unlink_t      me_unlink;
        struct lnet_libmd *me_md;
} lnet_me_t;

typedef struct lnet_libmd {
        struct list_head  md_list;
        lnet_libhandle_t  md_lh;
        lnet_me_t        *md_me;
        char             *md_start;
        unsigned int      md_offset;
        unsigned int      md_length;
        unsigned int      md_max_size;
        int               md_threshold;
        int               md_pending;
        unsigned int      md_options;
        unsigned int      md_flags;
        void             *md_user_ptr;
        lnet_eq_t        *md_eq;
        void             *md_addrkey;
        unsigned int      md_niov;                /* # frags */
        union {
                struct iovec  iov[LNET_MAX_IOV];
                lnet_kiov_t   kiov[LNET_MAX_IOV];
        } md_iov;
} lnet_libmd_t;

#define LNET_MD_FLAG_ZOMBIE           (1 << 0)
#define LNET_MD_FLAG_AUTO_UNLINK      (1 << 1)

#ifdef LNET_USE_LIB_FREELIST
typedef struct
{
        void	          *fl_objs;             /* single contiguous array of objects */
        int                fl_nobjs;            /* the number of them */
        int                fl_objsize;          /* the size (including overhead) of each of them */
        struct list_head   fl_list;             /* where they are enqueued */
} lnet_freelist_t;

typedef struct
{
        struct list_head   fo_list;             /* enqueue on fl_list */
        void              *fo_contents;         /* aligned contents */
} lnet_freeobj_t;
#endif

typedef struct {
        /* info about peers we are trying to fail */
        struct list_head   tp_list;             /* ln_test_peers */
        lnet_nid_t         tp_nid;              /* matching nid */
        unsigned int       tp_threshold;        /* # failures to simulate */
} lnet_test_peer_t;

#define LNET_COOKIE_TYPE_MD    1
#define LNET_COOKIE_TYPE_ME    2
#define LNET_COOKIE_TYPE_EQ    3
#define LNET_COOKIE_TYPES      4
/* LNET_COOKIE_TYPES must be a power of 2, so the cookie type can be
 * extracted by masking with (LNET_COOKIE_TYPES - 1) */

struct lnet_ni;                                  /* forward ref */

typedef struct lnet_lnd
{
        /* fields managed by portals */
        struct list_head  lnd_list;             /* stash in the LND table */
        int               lnd_refcount;         /* # active instances */

        /* fields initialised by the LND */
        unsigned int      lnd_type;
        
        int  (*lnd_startup) (struct lnet_ni *ni);
        void (*lnd_shutdown) (struct lnet_ni *ni);
        int  (*lnd_ctl)(struct lnet_ni *ni, unsigned int cmd, void *arg);

        /* In data movement APIs below, payload buffers are described as a set
         * of 'niov' fragments which are...
         * EITHER 
         *    in virtual memory (struct iovec *iov != NULL)
         * OR
         *    in pages (kernel only: plt_kiov_t *kiov != NULL).
         * The LND may NOT overwrite these fragment descriptors.
         * An 'offset' and may specify a byte offset within the set of
         * fragments to start from 
         */

        /* Start sending a preformatted message.  'private' is NULL for PUT and
	 * GET messages; otherwise this is a response to an incoming message
	 * and 'private' is the 'private' passed to lnet_parse().  Return
	 * non-zero for immediate failure, otherwise complete later with
	 * lnet_finalize() */
	int (*lnd_send)(struct lnet_ni *ni, void *private, lnet_msg_t *msg);

        /* Start receiving 'mlen' bytes of payload data, skipping the following
         * 'rlen' - 'mlen' bytes. 'private' is the 'private' passed to
         * lnet_parse().  Return non-zero for immedaite failure, otherwise
         * complete later with lnet_finalize().  This also gives back a receive
         * credit if the LND does flow control. */
	int (*lnd_recv)(struct lnet_ni *ni, void *private, lnet_msg_t *msg,
                        int delayed, unsigned int niov, 
                        struct iovec *iov, lnet_kiov_t *kiov,
                        unsigned int offset, unsigned int mlen, unsigned int rlen);

        /* lnet_parse() has had to delay processing of this message
         * (e.g. waiting for a forwarding buffer or send credits).  Give the
         * LND a chance to free urgently needed resources.  If called, return 0
         * for success and do NOT give back a receive credit; that has to wait
         * until lnd_recv() gets called.  On failure return < 0 and
         * release resources; lnd_recv() will not be called. */
	int (*lnd_eager_recv)(struct lnet_ni *ni, void *private, lnet_msg_t *msg,
                              void **new_privatep);

        /* notification of peer health */
        void (*lnd_notify)(struct lnet_ni *ni, lnet_nid_t peer, int alive);

#ifdef __KERNEL__
        /* accept a new connection */
        int (*lnd_accept)(struct lnet_ni *ni, struct socket *sock);
#else
        /* wait for something to happen */
        void (*lnd_wait)(struct lnet_ni *ni, int milliseconds);
#endif
} lnd_t;

#define LNET_MAX_INTERFACES   16

typedef struct lnet_ni {
        struct list_head  ni_list;              /* chain on ln_nis */
        struct list_head  ni_txq;               /* messages waiting for tx credits */
        int               ni_maxtxcredits;      /* # tx credits  */
        int               ni_txcredits;         /* # tx credits free */
        int               ni_mintxcredits;      /* lowest it's been */
        int               ni_peertxcredits;     /* # per-peer send credits */
        lnet_nid_t        ni_nid;               /* interface's NID */
        void             *ni_data;              /* instance-specific data */
        lnd_t            *ni_lnd;               /* procedural interface */
        int               ni_refcount;          /* reference count */
        char             *ni_interfaces[LNET_MAX_INTERFACES]; /* equivalent interfaces to use */
} lnet_ni_t;

typedef struct lnet_peer {
        struct list_head  lp_hashlist;          /* chain on peer hash */
        struct list_head  lp_txq;               /* messages blocking for tx credits */
        struct list_head  lp_rtrq;              /* messages blocking for router credits */
        int               lp_txcredits;         /* # tx credits available */
        int               lp_mintxcredits;      /* low water mark */
        int               lp_rtrcredits;        /* # router credits */
        int               lp_minrtrcredits;     /* low water mark */
        int               lp_alive;             /* enabled? */
        long              lp_txqnob;            /* bytes queued for sending */
        time_t            lp_timestamp;         /* time of last aliveness news */
        lnet_ni_t        *lp_ni;                /* interface peer is on */
        lnet_nid_t        lp_nid;               /* peer's NID */
        int               lp_refcount;          /* # refs */
} lnet_peer_t;

typedef struct {
	struct list_head  lr_list;              /* chain on net */
        lnet_peer_t      *lr_gateway;           /* router node */
} lnet_route_t;

typedef struct {
        struct list_head        lrn_list;       /* chain on ln_remote_nets */
        struct list_head        lrn_routes;     /* routes to me */
        __u32                   lrn_net;        /* my net number */
        unsigned int            lrn_hops;       /* how far I am */
} lnet_remotenet_t;

typedef struct {
        struct list_head  rbp_bufs;             /* my free buffer pool */
        struct list_head  rbp_msgs;             /* messages blocking for a buffer */
        int               rbp_npages;           /* # pages in each buffer */
        int               rbp_nbuffers;         /* # buffers */
        int               rbp_credits;          /* # free buffers / blocked messages */
        int               rbp_mincredits;       /* low water mark */
} lnet_rtrbufpool_t;

typedef struct {
        struct list_head   rb_list;             /* chain on rbp_bufs */
        lnet_rtrbufpool_t *rb_pool;             /* owning pool */
        lnet_kiov_t        rb_kiov[0];          /* the buffer space */
} lnet_rtrbuf_t;

typedef struct {
        __u32        msgs_alloc;
        __u32        msgs_max;
        __u32        errors;
        __u32        send_count;
        __u32        recv_count;
        __u32        route_count;
        __u32        drop_count;
        __u64        send_length;
        __u64        recv_length;
        __u64        route_length;
        __u64        drop_length;
} lnet_counters_t;

#define LNET_PEER_HASHSIZE   503                /* prime! */

#define LNET_NRBPOOLS         3                 /* # different router buffer pools */

typedef struct
{
        /* Stuff initialised at LNetInit() */
        int                ln_init;             /* LNetInit() called? */
        int                ln_refcount;         /* LNetNIInit/LNetNIFini counter */
        int                ln_niinit_self;      /* Have I called LNetNIInit myself? */

        int                ln_ptlcompat;        /* do I support talking to portals? */
        
        struct list_head   ln_lnds;             /* registered LNDs */

#ifdef __KERNEL__
        spinlock_t         ln_lock;
        cfs_waitq_t        ln_waitq;
        struct semaphore   ln_api_mutex;
        struct semaphore   ln_lnd_mutex;
#else
# if LNET_SINGLE_THREADED
        int                ln_lock;
        int                ln_api_mutex;
        int                ln_lnd_mutex;
# else
        pthread_cond_t     ln_cond;
        pthread_mutex_t    ln_lock;
        pthread_mutex_t    ln_api_mutex;
        pthread_mutex_t    ln_lnd_mutex;
# endif
#endif

        /* Stuff initialised at LNetNIInit() */

        int                ln_shutdown;         /* shutdown in progress */
        int                ln_nportals;         /* # portals */
        struct list_head  *ln_portals;          /* the vector of portals */

        lnet_pid_t         ln_pid;              /* requested pid */

        struct list_head   ln_nis;              /* LND instances */
        lnet_ni_t         *ln_loni;             /* the loopback NI */
        lnet_ni_t         *ln_eqwaitni;         /* NI to wait for events in */
        struct list_head   ln_zombie_nis;       /* dying LND instances */
        int                ln_nzombie_nis;      /* # of NIs to wait for */

        struct list_head   ln_remote_nets;      /* remote networks with routes to them */
        __u64              ln_remote_nets_version; /* validity stamp */

        struct list_head  *ln_peer_hash;        /* NID->peer hash */
        int                ln_npeers;           /* # peers extant */
        int                ln_peertable_version; /* /proc validity stamp */
        
        int                ln_routing;          /* am I a router? */
        lnet_rtrbufpool_t  ln_rtrpools[LNET_NRBPOOLS]; /* router buffer pools */
        
        int                ln_lh_hash_size;     /* size of lib handle hash table */
        struct list_head  *ln_lh_hash_table;    /* all extant lib handles, this interface */
        __u64              ln_next_object_cookie; /* cookie generator */
        __u64              ln_interface_cookie; /* uniquely identifies this ni in this epoch */

        char              *ln_network_tokens;   /* space for network names */
        int                ln_network_tokens_nob;
        
        struct list_head   ln_test_peers;       /* failure simulation */
        
#ifdef LNET_USE_LIB_FREELIST
        lnet_freelist_t    ln_free_mes;
        lnet_freelist_t    ln_free_msgs;
        lnet_freelist_t    ln_free_mds;
        lnet_freelist_t    ln_free_eqs;
#endif
        struct list_head   ln_active_msgs;
        struct list_head   ln_active_mds;
        struct list_head   ln_active_eqs;

        lnet_counters_t    ln_counters;
} lnet_t;

#endif
