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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/include/lnet/lib-types.h
 *
 * Types used by the library side routines that do not need to be
 * exposed to the user application
 */

#ifndef __LNET_LIB_TYPES_H__
#define __LNET_LIB_TYPES_H__

#ifndef __KERNEL__
# error This include is only for kernel use.
#endif

#include <linux/kthread.h>
#include <linux/uio.h>
#include <linux/types.h>

#include <lnet/lnetctl.h>

/* Max payload size */
#ifndef CONFIG_LNET_MAX_PAYLOAD
# error "CONFIG_LNET_MAX_PAYLOAD must be defined in config.h"
#endif

#define LNET_MAX_PAYLOAD       CONFIG_LNET_MAX_PAYLOAD
#if (LNET_MAX_PAYLOAD < LNET_MTU)
# error "LNET_MAX_PAYLOAD too small - error in configure --with-max-payload-mb"
#elif (LNET_MAX_PAYLOAD > (PAGE_SIZE * LNET_MAX_IOV))
# error "LNET_MAX_PAYLOAD too large - error in configure --with-max-payload-mb"
#endif

/* forward refs */
struct lnet_libmd;

typedef struct lnet_msg {
	struct list_head	msg_activelist;
	struct list_head	msg_list;	/* Q for credits/MD */

	struct lnet_process_id	msg_target;
	/* Primary NID of the source. */
	lnet_nid_t		msg_initiator;
	/* where is it from, it's only for building event */
	lnet_nid_t		msg_from;
	__u32			msg_type;

	/* committed for sending */
	unsigned int		msg_tx_committed:1;
	/* CPT # this message committed for sending */
	unsigned int		msg_tx_cpt:15;
	/* committed for receiving */
	unsigned int		msg_rx_committed:1;
	/* CPT # this message committed for receiving */
	unsigned int		msg_rx_cpt:15;
	/* queued for tx credit */
	unsigned int		msg_tx_delayed:1;
	/* queued for RX buffer */
	unsigned int		msg_rx_delayed:1;
	/* ready for pending on RX delay list */
	unsigned int		msg_rx_ready_delay:1;

	unsigned int          msg_vmflush:1;      /* VM trying to free memory */
	unsigned int          msg_target_is_router:1; /* sending to a router */
	unsigned int          msg_routing:1;      /* being forwarded */
	unsigned int          msg_ack:1;          /* ack on finalize (PUT) */
	unsigned int          msg_sending:1;      /* outgoing message */
	unsigned int          msg_receiving:1;    /* being received */
	unsigned int          msg_txcredit:1;     /* taken an NI send credit */
	unsigned int          msg_peertxcredit:1; /* taken a peer send credit */
	unsigned int          msg_rtrcredit:1;    /* taken a globel router credit */
	unsigned int          msg_peerrtrcredit:1; /* taken a peer router credit */
	unsigned int          msg_onactivelist:1; /* on the activelist */
	unsigned int	      msg_rdma_get:1;

	struct lnet_peer_ni  *msg_txpeer;         /* peer I'm sending to */
	struct lnet_peer_ni  *msg_rxpeer;         /* peer I received from */

	void                 *msg_private;
	struct lnet_libmd    *msg_md;
	/* the NI the message was sent or received over */
	struct lnet_ni       *msg_txni;
	struct lnet_ni       *msg_rxni;

	unsigned int          msg_len;
	unsigned int          msg_wanted;
	unsigned int          msg_offset;
	unsigned int          msg_niov;
	struct kvec	     *msg_iov;
	lnet_kiov_t          *msg_kiov;

	struct lnet_event	msg_ev;
	struct lnet_hdr		msg_hdr;
} lnet_msg_t;

typedef struct lnet_libhandle {
	struct list_head	lh_hash_chain;
	__u64			lh_cookie;
} lnet_libhandle_t;

#define lh_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))

typedef struct lnet_eq {
	struct list_head	eq_list;
	struct lnet_libhandle	eq_lh;
	unsigned long		eq_enq_seq;
	unsigned long		eq_deq_seq;
	unsigned int		eq_size;
	lnet_eq_handler_t	eq_callback;
	struct lnet_event	*eq_events;
	int			**eq_refs;	/* percpt refcount for EQ */
} lnet_eq_t;

typedef struct lnet_me {
	struct list_head	me_list;
	struct lnet_libhandle	me_lh;
	struct lnet_process_id	me_match_id;
	unsigned int		me_portal;
	unsigned int		me_pos;		/* hash offset in mt_hash */
	__u64			me_match_bits;
	__u64			me_ignore_bits;
	enum lnet_unlink	me_unlink;
	struct lnet_libmd      *me_md;
} lnet_me_t;

typedef struct lnet_libmd {
	struct list_head	md_list;
	struct lnet_libhandle	md_lh;
	struct lnet_me	       *md_me;
	char		       *md_start;
	unsigned int		md_offset;
	unsigned int		md_length;
	unsigned int		md_max_size;
	int			md_threshold;
	int			md_refcount;
	unsigned int		md_options;
	unsigned int		md_flags;
	unsigned int		md_niov;	/* # frags at end of struct */
	void		       *md_user_ptr;
	struct lnet_eq	       *md_eq;
	struct lnet_handle_md	md_bulk_handle;
	union {
		struct kvec	iov[LNET_MAX_IOV];
		lnet_kiov_t	kiov[LNET_MAX_IOV];
	} md_iov;
} lnet_libmd_t;

#define LNET_MD_FLAG_ZOMBIE	 (1 << 0)
#define LNET_MD_FLAG_AUTO_UNLINK (1 << 1)
#define LNET_MD_FLAG_ABORTED	 (1 << 2)

typedef struct lnet_test_peer {
	/* info about peers we are trying to fail */
	struct list_head	tp_list;	/* ln_test_peers */
	lnet_nid_t		tp_nid;		/* matching nid */
	unsigned int		tp_threshold;	/* # failures to simulate */
} lnet_test_peer_t;

#define LNET_COOKIE_TYPE_MD    1
#define LNET_COOKIE_TYPE_ME    2
#define LNET_COOKIE_TYPE_EQ    3
#define LNET_COOKIE_TYPE_BITS  2
#define LNET_COOKIE_MASK	((1ULL << LNET_COOKIE_TYPE_BITS) - 1ULL)

struct lnet_ni;					 /* forward ref */
struct socket;

typedef struct lnet_lnd {
	/* fields managed by portals */
	struct list_head	lnd_list;	/* stash in the LND table */
	int			lnd_refcount;	/* # active instances */

	/* fields initialized by the LND */
	__u32			lnd_type;

	int  (*lnd_startup)(struct lnet_ni *ni);
	void (*lnd_shutdown)(struct lnet_ni *ni);
	int  (*lnd_ctl)(struct lnet_ni *ni, unsigned int cmd, void *arg);

	/* In data movement APIs below, payload buffers are described as a set
	 * of 'niov' fragments which are...
	 * EITHER
	 *    in virtual memory (struct kvec *iov != NULL)
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
	int (*lnd_send)(struct lnet_ni *ni, void *private,
			struct lnet_msg *msg);

	/* Start receiving 'mlen' bytes of payload data, skipping the following
	 * 'rlen' - 'mlen' bytes. 'private' is the 'private' passed to
	 * lnet_parse().  Return non-zero for immedaite failure, otherwise
	 * complete later with lnet_finalize().  This also gives back a receive
	 * credit if the LND does flow control. */
	int (*lnd_recv)(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
			int delayed, unsigned int niov,
			struct kvec *iov, lnet_kiov_t *kiov,
			unsigned int offset, unsigned int mlen, unsigned int rlen);

	/* lnet_parse() has had to delay processing of this message
	 * (e.g. waiting for a forwarding buffer or send credits).  Give the
	 * LND a chance to free urgently needed resources.  If called, return 0
	 * for success and do NOT give back a receive credit; that has to wait
	 * until lnd_recv() gets called.  On failure return < 0 and
	 * release resources; lnd_recv() will not be called. */
	int (*lnd_eager_recv)(struct lnet_ni *ni, void *private,
			      struct lnet_msg *msg, void **new_privatep);

	/* notification of peer health */
	void (*lnd_notify)(struct lnet_ni *ni, lnet_nid_t peer, int alive);

	/* query of peer aliveness */
	void (*lnd_query)(struct lnet_ni *ni, lnet_nid_t peer, cfs_time_t *when);

	/* accept a new connection */
	int (*lnd_accept)(struct lnet_ni *ni, struct socket *sock);
} lnd_t;

typedef struct lnet_ni_status {
	lnet_nid_t ns_nid;
	__u32	   ns_status;
	__u32	   ns_unused;
} WIRE_ATTR lnet_ni_status_t;

struct lnet_tx_queue {
	int			tq_credits;	/* # tx credits free */
	int			tq_credits_min;	/* lowest it's been */
	int			tq_credits_max;	/* total # tx credits */
	struct list_head	tq_delayed;	/* delayed TXs */
};

enum lnet_net_state {
	/* set when net block is allocated */
	LNET_NET_STATE_INIT = 0,
	/* set when NIs in net are started successfully */
	LNET_NET_STATE_ACTIVE,
	/* set if all NIs in net are in FAILED state */
	LNET_NET_STATE_INACTIVE,
	/* set when shutting down a NET */
	LNET_NET_STATE_DELETING
};

enum lnet_ni_state {
	/* set when NI block is allocated */
	LNET_NI_STATE_INIT = 0,
	/* set when NI is started successfully */
	LNET_NI_STATE_ACTIVE,
	/* set when LND notifies NI failed */
	LNET_NI_STATE_FAILED,
	/* set when LND notifies NI degraded */
	LNET_NI_STATE_DEGRADED,
	/* set when shuttding down NI */
	LNET_NI_STATE_DELETING
};

struct lnet_element_stats {
	atomic_t	send_count;
	atomic_t	recv_count;
	atomic_t	drop_count;
};

struct lnet_net {
	/* chain on the ln_nets */
	struct list_head	net_list;

	/* net ID, which is composed of
	 * (net_type << 16) | net_num.
	 * net_type can be one of the enumerated types defined in
	 * lnet/include/lnet/nidstr.h */
	__u32			net_id;

	/* priority of the network */
	__u32			net_prio;

	/* total number of CPTs in the array */
	__u32			net_ncpts;

	/* cumulative CPTs of all NIs in this net */
	__u32			*net_cpts;

	/* network tunables */
	struct lnet_ioctl_config_lnd_cmn_tunables net_tunables;

	/*
	 * boolean to indicate that the tunables have been set and
	 * shouldn't be reset
	 */
	bool			net_tunables_set;

	/* procedural interface */
	struct lnet_lnd		*net_lnd;

	/* list of NIs on this net */
	struct list_head	net_ni_list;

	/* list of NIs being added, but not started yet */
	struct list_head	net_ni_added;

	/* dying LND instances */
	struct list_head	net_ni_zombie;

	/* network state */
	enum lnet_net_state	net_state;
};

typedef struct lnet_ni {
	/* chain on the lnet_net structure */
	struct list_head	ni_netlist;

	/* chain on net_ni_cpt */
	struct list_head	ni_cptlist;

	spinlock_t		ni_lock;

	/* number of CPTs */
	int			ni_ncpts;

	/* bond NI on some CPTs */
	__u32			*ni_cpts;

	/* interface's NID */
	lnet_nid_t		ni_nid;

	/* instance-specific data */
	void			*ni_data;

	/* per ni credits */
	atomic_t		ni_tx_credits;

	/* percpt TX queues */
	struct lnet_tx_queue	**ni_tx_queues;

	/* percpt reference count */
	int			**ni_refs;

	/* when I was last alive */
	long			ni_last_alive;

	/* pointer to parent network */
	struct lnet_net		*ni_net;

	/* my health status */
	struct lnet_ni_status	*ni_status;

	/* NI FSM */
	enum lnet_ni_state	ni_state;

	/* per NI LND tunables */
	struct lnet_lnd_tunables ni_lnd_tunables;

	/* lnd tunables set explicitly */
	bool ni_lnd_tunables_set;

	/* NI statistics */
	struct lnet_element_stats ni_stats;

	/* physical device CPT */
	int			ni_dev_cpt;

	/* sequence number used to round robin over nis within a net */
	__u32			ni_seq;

	/*
	 * equivalent interfaces to use
	 * This is an array because socklnd bonding can still be configured
	 */
	char			*ni_interfaces[LNET_NUM_INTERFACES];
	struct net		*ni_net_ns;     /* original net namespace */
} lnet_ni_t;

#define LNET_PROTO_PING_MATCHBITS	0x8000000000000000LL

/* NB: value of these features equal to LNET_PROTO_PING_VERSION_x
 * of old LNet, so there shouldn't be any compatibility issue */
#define LNET_PING_FEAT_INVAL		(0)		/* no feature */
#define LNET_PING_FEAT_BASE		(1 << 0)	/* just a ping */
#define LNET_PING_FEAT_NI_STATUS	(1 << 1)	/* return NI status */
#define LNET_PING_FEAT_RTE_DISABLED	(1 << 2)	/* Routing enabled */

#define LNET_PING_FEAT_MASK		(LNET_PING_FEAT_BASE | \
					 LNET_PING_FEAT_NI_STATUS)

typedef struct lnet_ping_info {
	__u32			pi_magic;
	__u32			pi_features;
	lnet_pid_t		pi_pid;
	__u32			pi_nnis;
	struct lnet_ni_status	pi_ni[0];
} WIRE_ATTR lnet_ping_info_t;

/* router checker data, per router */
#define LNET_MAX_RTR_NIS   16
#define LNET_PINGINFO_SIZE offsetof(struct lnet_ping_info, pi_ni[LNET_MAX_RTR_NIS])
typedef struct lnet_rc_data {
	/* chain on the_lnet.ln_zombie_rcd or ln_deathrow_rcd */
	struct list_head	rcd_list;
	struct lnet_handle_md	rcd_mdh;	/* ping buffer MD */
	struct lnet_peer_ni	*rcd_gateway;	/* reference to gateway */
	struct lnet_ping_info	*rcd_pinginfo;	/* ping buffer */
} lnet_rc_data_t;

struct lnet_peer_ni {
	/* chain on peer_net */
	struct list_head	lpni_on_peer_net_list;
	/* chain on remote peer list */
	struct list_head	lpni_on_remote_peer_ni_list;
	/* chain on peer hash */
	struct list_head	lpni_hashlist;
	/* messages blocking for tx credits */
	struct list_head	lpni_txq;
	/* messages blocking for router credits */
	struct list_head	lpni_rtrq;
	/* chain on router list */
	struct list_head	lpni_rtr_list;
	/* pointer to peer net I'm part of */
	struct lnet_peer_net	*lpni_peer_net;
	/* statistics kept on each peer NI */
	struct lnet_element_stats lpni_stats;
	/* spin lock protecting credits and lpni_txq / lpni_rtrq */
	spinlock_t		lpni_lock;
	/* # tx credits available */
	int			lpni_txcredits;
	/* low water mark */
	int			lpni_mintxcredits;
	/* # router credits */
	int			lpni_rtrcredits;
	/* low water mark */
	int			lpni_minrtrcredits;
	/* bytes queued for sending */
	long			lpni_txqnob;
	/* alive/dead? */
	bool			lpni_alive;
	/* notification outstanding? */
	bool			lpni_notify;
	/* outstanding notification for LND? */
	bool			lpni_notifylnd;
	/* some thread is handling notification */
	bool			lpni_notifying;
	/* SEND event outstanding from ping */
	bool			lpni_ping_notsent;
	/* # times router went dead<->alive. Protected with lpni_lock */
	int			lpni_alive_count;
	/* time of last aliveness news */
	cfs_time_t		lpni_timestamp;
	/* time of last ping attempt */
	cfs_time_t		lpni_ping_timestamp;
	/* != 0 if ping reply expected */
	cfs_time_t		lpni_ping_deadline;
	/* when I was last alive */
	cfs_time_t		lpni_last_alive;
	/* when lpni_ni was queried last time */
	cfs_time_t		lpni_last_query;
	/* network peer is on */
	struct lnet_net		*lpni_net;
	/* peer's NID */
	lnet_nid_t		lpni_nid;
	/* # refs */
	atomic_t		lpni_refcount;
	/* CPT this peer attached on */
	int			lpni_cpt;
	/* # refs from lnet_route_t::lr_gateway */
	int			lpni_rtr_refcount;
	/* sequence number used to round robin over peer nis within a net */
	__u32			lpni_seq;
	/* sequence number used to round robin over gateways */
	__u32			lpni_gw_seq;
	/* health flag */
	bool			lpni_healthy;
	/* returned RC ping features. Protected with lpni_lock */
	unsigned int		lpni_ping_feats;
	/* routes on this peer */
	struct list_head	lpni_routes;
	/* array of preferred local nids */
	lnet_nid_t		*lpni_pref_nids;
	/* number of preferred NIDs in lnpi_pref_nids */
	__u32			lpni_pref_nnids;
	/* router checker state */
	struct lnet_rc_data	*lpni_rcd;
};

struct lnet_peer {
	/* chain on global peer list */
	struct list_head	lp_on_lnet_peer_list;

	/* list of peer nets */
	struct list_head	lp_peer_nets;

	/* primary NID of the peer */
	lnet_nid_t		lp_primary_nid;

	/* peer is Multi-Rail enabled peer */
	bool			lp_multi_rail;
};

struct lnet_peer_net {
	/* chain on peer block */
	struct list_head	lpn_on_peer_list;

	/* list of peer_nis on this network */
	struct list_head	lpn_peer_nis;

	/* pointer to the peer I'm part of */
	struct lnet_peer	*lpn_peer;

	/* Net ID */
	__u32			lpn_net_id;
};

/* peer hash size */
#define LNET_PEER_HASH_BITS	9
#define LNET_PEER_HASH_SIZE	(1 << LNET_PEER_HASH_BITS)

/* peer hash table */
struct lnet_peer_table {
	int			pt_version;	/* /proc validity stamp */
	atomic_t		pt_number;	/* # peers extant */
	struct list_head	*pt_hash;	/* NID->peer hash */
	struct list_head	pt_zombie_list;	/* zombie peers */
	int			pt_zombies;	/* # zombie peers */
	spinlock_t		pt_zombie_lock;	/* protect list and count */
};

/* peer aliveness is enabled only on routers for peers in a network where the
 * struct lnet_ni::ni_peertimeout has been set to a positive value
 */
#define lnet_peer_aliveness_enabled(lp) (the_lnet.ln_routing != 0 && \
					((lp)->lpni_net) && \
					(lp)->lpni_net->net_tunables.lct_peer_timeout > 0)

typedef struct lnet_route {
	struct list_head	lr_list;	/* chain on net */
	struct list_head	lr_gwlist;	/* chain on gateway */
	struct lnet_peer_ni	*lr_gateway;	/* router node */
	__u32			lr_net;		/* remote network number */
	int			lr_seq;		/* sequence for round-robin */
	unsigned int		lr_downis;	/* number of down NIs */
	__u32			lr_hops;	/* how far I am */
	unsigned int		lr_priority;	/* route priority */
} lnet_route_t;

#define LNET_REMOTE_NETS_HASH_DEFAULT	(1U << 7)
#define LNET_REMOTE_NETS_HASH_MAX	(1U << 16)
#define LNET_REMOTE_NETS_HASH_SIZE	(1 << the_lnet.ln_remote_nets_hbits)

typedef struct lnet_remotenet {
	/* chain on ln_remote_nets_hash */
	struct list_head	lrn_list;
	/* routes to me */
	struct list_head	lrn_routes;
	/* my net number */
	__u32			lrn_net;
} lnet_remotenet_t;

/** lnet message has credit and can be submitted to lnd for send/receive */
#define LNET_CREDIT_OK		0
/** lnet message is waiting for credit */
#define LNET_CREDIT_WAIT	1

typedef struct lnet_rtrbufpool {
	/* my free buffer pool */
	struct list_head	rbp_bufs;
	/* messages blocking for a buffer */
	struct list_head	rbp_msgs;
	/* # pages in each buffer */
	int			rbp_npages;
	/* requested number of buffers */
	int			rbp_req_nbuffers;
	/* # buffers actually allocated */
	int			rbp_nbuffers;
	/* # free buffers / blocked messages */
	int			rbp_credits;
	/* low water mark */
	int			rbp_mincredits;
} lnet_rtrbufpool_t;

typedef struct lnet_rtrbuf {
	struct list_head	 rb_list;	/* chain on rbp_bufs */
	struct lnet_rtrbufpool	*rb_pool;	/* owning pool */
	lnet_kiov_t		 rb_kiov[0];	/* the buffer space */
} lnet_rtrbuf_t;

#define LNET_PEER_HASHSIZE   503		/* prime! */

enum lnet_match_flags {
	/* Didn't match anything */
	LNET_MATCHMD_NONE	= (1 << 0),
	/* Matched OK */
	LNET_MATCHMD_OK		= (1 << 1),
	/* Must be discarded */
	LNET_MATCHMD_DROP	= (1 << 2),
	/* match and buffer is exhausted */
	LNET_MATCHMD_EXHAUSTED	= (1 << 3),
	/* match or drop */
	LNET_MATCHMD_FINISH	= (LNET_MATCHMD_OK | LNET_MATCHMD_DROP),
};

/* Options for struct lnet_portal::ptl_options */
#define LNET_PTL_LAZY		    (1 << 0)
#define LNET_PTL_MATCH_UNIQUE	    (1 << 1)	/* unique match, for RDMA */
#define LNET_PTL_MATCH_WILDCARD     (1 << 2)	/* wildcard match, request portal */

/* parameter for matching operations (GET, PUT) */
struct lnet_match_info {
	__u64			mi_mbits;
	struct lnet_process_id	mi_id;
	unsigned int		mi_cpt;
	unsigned int		mi_opc;
	unsigned int		mi_portal;
	unsigned int		mi_rlength;
	unsigned int		mi_roffset;
};

/* ME hash of RDMA portal */
#define LNET_MT_HASH_BITS		8
#define LNET_MT_HASH_SIZE		(1 << LNET_MT_HASH_BITS)
#define LNET_MT_HASH_MASK		(LNET_MT_HASH_SIZE - 1)
/* we allocate (LNET_MT_HASH_SIZE + 1) entries for lnet_match_table::mt_hash,
 * the last entry is reserved for MEs with ignore-bits */
#define LNET_MT_HASH_IGNORE		LNET_MT_HASH_SIZE
/* __u64 has 2^6 bits, so need 2^(LNET_MT_HASH_BITS - LNET_MT_BITS_U64) which
 * is 4 __u64s as bit-map, and add an extra __u64 (only use one bit) for the
 * ME-list with ignore-bits, which is mtable::mt_hash[LNET_MT_HASH_IGNORE] */
#define LNET_MT_BITS_U64		6	/* 2^6 bits */
#define LNET_MT_EXHAUSTED_BITS		(LNET_MT_HASH_BITS - LNET_MT_BITS_U64)
#define LNET_MT_EXHAUSTED_BMAP		((1 << LNET_MT_EXHAUSTED_BITS) + 1)

/* portal match table */
struct lnet_match_table {
	/* reserved for upcoming patches, CPU partition ID */
	unsigned int		mt_cpt;
	unsigned int		mt_portal;	/* portal index */
	/* match table is set as "enabled" if there's non-exhausted MD
	 * attached on mt_mhash, it's only valid for wildcard portal */
	unsigned int		mt_enabled;
	/* bitmap to flag whether MEs on mt_hash are exhausted or not */
	__u64			mt_exhausted[LNET_MT_EXHAUSTED_BMAP];
	struct list_head	*mt_mhash;	/* matching hash */
};

/* these are only useful for wildcard portal */
/* Turn off message rotor for wildcard portals */
#define	LNET_PTL_ROTOR_OFF	0
/* round-robin dispatch all PUT messages for wildcard portals */
#define	LNET_PTL_ROTOR_ON	1
/* round-robin dispatch routed PUT message for wildcard portals */
#define	LNET_PTL_ROTOR_RR_RT	2
/* dispatch routed PUT message by hashing source NID for wildcard portals */
#define	LNET_PTL_ROTOR_HASH_RT	3

typedef struct lnet_portal {
	spinlock_t		ptl_lock;
	unsigned int		ptl_index;	/* portal ID, reserved */
	/* flags on this portal: lazy, unique... */
	unsigned int		ptl_options;
	/* list of messages which are stealing buffer */
	struct list_head	ptl_msg_stealing;
	/* messages blocking for MD */
	struct list_head	ptl_msg_delayed;
	/* Match table for each CPT */
	struct lnet_match_table	**ptl_mtables;
	/* spread rotor of incoming "PUT" */
	unsigned int		ptl_rotor;
	/* # active entries for this portal */
	int			ptl_mt_nmaps;
	/* array of active entries' cpu-partition-id */
	int			ptl_mt_maps[0];
} lnet_portal_t;

#define LNET_LH_HASH_BITS	12
#define LNET_LH_HASH_SIZE	(1ULL << LNET_LH_HASH_BITS)
#define LNET_LH_HASH_MASK	(LNET_LH_HASH_SIZE - 1)

/* resource container (ME, MD, EQ) */
struct lnet_res_container {
	unsigned int		rec_type;	/* container type */
	__u64			rec_lh_cookie;	/* cookie generator */
	struct list_head	rec_active;	/* active resource list */
	struct list_head	*rec_lh_hash;	/* handle hash */
};

/* message container */
struct lnet_msg_container {
	int			msc_init;	/* initialized or not */
	/* max # threads finalizing */
	int			msc_nfinalizers;
	/* msgs waiting to complete finalizing */
	struct list_head	msc_finalizing;
	struct list_head	msc_active;	/* active message list */
	/* threads doing finalization */
	void			**msc_finalizers;
};

/* Router Checker states */
#define LNET_RC_STATE_SHUTDOWN		0	/* not started */
#define LNET_RC_STATE_RUNNING		1	/* started up OK */
#define LNET_RC_STATE_STOPPING		2	/* telling thread to stop */

/* LNet states */
#define LNET_STATE_SHUTDOWN		0	/* not started */
#define LNET_STATE_RUNNING		1	/* started up OK */
#define LNET_STATE_STOPPING		2	/* telling thread to stop */

typedef struct lnet {
	/* CPU partition table of LNet */
	struct cfs_cpt_table		*ln_cpt_table;
	/* number of CPTs in ln_cpt_table */
	unsigned int			ln_cpt_number;
	unsigned int			ln_cpt_bits;

	/* protect LNet resources (ME/MD/EQ) */
	struct cfs_percpt_lock		*ln_res_lock;
	/* # portals */
	int				ln_nportals;
	/* the vector of portals */
	struct lnet_portal		**ln_portals;
	/* percpt ME containers */
	struct lnet_res_container	**ln_me_containers;
	/* percpt MD container */
	struct lnet_res_container	**ln_md_containers;

	/* Event Queue container */
	struct lnet_res_container	ln_eq_container;
	wait_queue_head_t		ln_eq_waitq;
	spinlock_t			ln_eq_wait_lock;

	unsigned int			ln_remote_nets_hbits;

	/* protect NI, peer table, credits, routers, rtrbuf... */
	struct cfs_percpt_lock		*ln_net_lock;
	/* percpt message containers for active/finalizing/freed message */
	struct lnet_msg_container	**ln_msg_containers;
	struct lnet_counters		**ln_counters;
	struct lnet_peer_table		**ln_peer_tables;
	/* list of configured or discovered peers */
	struct list_head		ln_peers;
	/* list of peer nis not on a local network */
	struct list_head		ln_remote_peer_ni_list;
	/* failure simulation */
	struct list_head		ln_test_peers;
	struct list_head		ln_drop_rules;
	struct list_head		ln_delay_rules;
	/* LND instances */
	struct list_head		ln_nets;
	/* the loopback NI */
	struct lnet_ni			*ln_loni;
	/* network zombie list */
	struct list_head		ln_net_zombie;

	/* remote networks with routes to them */
	struct list_head		*ln_remote_nets_hash;
	/* validity stamp */
	__u64				ln_remote_nets_version;
	/* list of all known routers */
	struct list_head		ln_routers;
	/* validity stamp */
	__u64				ln_routers_version;
	/* percpt router buffer pools */
	struct lnet_rtrbufpool		**ln_rtrpools;

	struct lnet_handle_md		ln_ping_target_md;
	struct lnet_handle_eq		ln_ping_target_eq;
	struct lnet_ping_info		*ln_ping_info;

	/* router checker startup/shutdown state */
	int				ln_rc_state;
	/* router checker's event queue */
	struct lnet_handle_eq		ln_rc_eqh;
	/* rcd still pending on net */
	struct list_head		ln_rcd_deathrow;
	/* rcd ready for free */
	struct list_head		ln_rcd_zombie;
	/* serialise startup/shutdown */
	struct semaphore		ln_rc_signal;

	struct mutex			ln_api_mutex;
	struct mutex			ln_lnd_mutex;
	/* Have I called LNetNIInit myself? */
	int				ln_niinit_self;
	/* LNetNIInit/LNetNIFini counter */
	int				ln_refcount;
	/* SHUTDOWN/RUNNING/STOPPING */
	int				ln_state;

	int				ln_routing;	/* am I a router? */
	lnet_pid_t			ln_pid;		/* requested pid */
	/* uniquely identifies this ni in this epoch */
	__u64				ln_interface_cookie;
	/* registered LNDs */
	struct list_head		ln_lnds;

	/* test protocol compatibility flags */
	int				ln_testprotocompat;

	/* 0 - load the NIs from the mod params
	 * 1 - do not load the NIs from the mod params
	 * Reverse logic to ensure that other calls to LNetNIInit
	 * need no change
	 */
	bool				ln_nis_from_mod_params;

	/* waitq for router checker.  As long as there are no routes in
	 * the list, the router checker will sleep on this queue.  when
	 * routes are added the thread will wake up */
	wait_queue_head_t		ln_rc_waitq;
} lnet_t;

#endif
