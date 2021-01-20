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
 * Copyright (c) 2012, 2017, Intel Corporation.
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
#include <linux/semaphore.h>
#include <linux/types.h>

#include <uapi/linux/lnet/lnet-dlc.h>
#include <uapi/linux/lnet/lnetctl.h>

/* Max payload size */
#define LNET_MAX_PAYLOAD	LNET_MTU

/** limit on the number of fragments in discontiguous MDs */
#define LNET_MAX_IOV	256

/*
 * This is the maximum health value.
 * All local and peer NIs created have their health default to this value.
 */
#define LNET_MAX_HEALTH_VALUE 1000

/* forward refs */
struct lnet_libmd;

enum lnet_msg_hstatus {
	LNET_MSG_STATUS_OK = 0,
	LNET_MSG_STATUS_LOCAL_INTERRUPT,
	LNET_MSG_STATUS_LOCAL_DROPPED,
	LNET_MSG_STATUS_LOCAL_ABORTED,
	LNET_MSG_STATUS_LOCAL_NO_ROUTE,
	LNET_MSG_STATUS_LOCAL_ERROR,
	LNET_MSG_STATUS_LOCAL_TIMEOUT,
	LNET_MSG_STATUS_REMOTE_ERROR,
	LNET_MSG_STATUS_REMOTE_DROPPED,
	LNET_MSG_STATUS_REMOTE_TIMEOUT,
	LNET_MSG_STATUS_NETWORK_TIMEOUT,
	LNET_MSG_STATUS_END,
};

struct lnet_rsp_tracker {
	/* chain on the waiting list */
	struct list_head rspt_on_list;
	/* cpt to lock */
	int rspt_cpt;
	/* nid of next hop */
	lnet_nid_t rspt_next_hop_nid;
	/* deadline of the REPLY/ACK */
	ktime_t rspt_deadline;
	/* parent MD */
	struct lnet_handle_md rspt_mdh;
};

struct lnet_msg {
	struct list_head	msg_activelist;
	struct list_head	msg_list;	/* Q for credits/MD */

	struct lnet_process_id	msg_target;
	/* Primary NID of the source. */
	lnet_nid_t		msg_initiator;
	/* where is it from, it's only for building event */
	lnet_nid_t		msg_from;
	__u32			msg_type;

	/*
	 * hold parameters in case message is with held due
	 * to discovery
	 */
	lnet_nid_t		msg_src_nid_param;
	lnet_nid_t		msg_rtr_nid_param;

	/*
	 * Deadline for the message after which it will be finalized if it
	 * has not completed.
	 */
	ktime_t			msg_deadline;

	/* The message health status. */
	enum lnet_msg_hstatus	msg_health_status;
	/* This is a recovery message */
	bool			msg_recovery;
	/* the number of times a transmission has been retried */
	int			msg_retry_count;
	/* flag to indicate that we do not want to resend this message */
	bool			msg_no_resend;

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
};

struct lnet_libhandle {
	struct list_head	lh_hash_chain;
	__u64			lh_cookie;
};

#define lh_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))

struct lnet_eq {
	struct list_head	eq_list;
	struct lnet_libhandle	eq_lh;
	unsigned long		eq_enq_seq;
	unsigned long		eq_deq_seq;
	unsigned int		eq_size;
	lnet_eq_handler_t	eq_callback;
	struct lnet_event	*eq_events;
	int			**eq_refs;	/* percpt refcount for EQ */
};

struct lnet_me {
	struct list_head	me_list;
	struct lnet_libhandle	me_lh;
	struct lnet_process_id	me_match_id;
	unsigned int		me_portal;
	unsigned int		me_pos;		/* hash offset in mt_hash */
	__u64			me_match_bits;
	__u64			me_ignore_bits;
	enum lnet_unlink	me_unlink;
	struct lnet_libmd      *me_md;
};

struct lnet_libmd {
	struct list_head	 md_list;
	struct lnet_libhandle	 md_lh;
	struct lnet_me	        *md_me;
	char		        *md_start;
	unsigned int		 md_offset;
	unsigned int		 md_length;
	unsigned int		 md_max_size;
	int			 md_threshold;
	int			 md_refcount;
	unsigned int		 md_options;
	unsigned int		 md_flags;
	unsigned int		 md_niov;	/* # frags at end of struct */
	void		        *md_user_ptr;
	struct lnet_rsp_tracker *md_rspt_ptr;
	struct lnet_eq	        *md_eq;
	struct lnet_handle_md	 md_bulk_handle;
	union {
		struct kvec	 iov[LNET_MAX_IOV];
		lnet_kiov_t	 kiov[LNET_MAX_IOV];
	} md_iov;
};

#define LNET_MD_FLAG_ZOMBIE	 (1 << 0)
#define LNET_MD_FLAG_AUTO_UNLINK (1 << 1)
#define LNET_MD_FLAG_ABORTED	 (1 << 2)

struct lnet_test_peer {
	/* info about peers we are trying to fail */
	struct list_head	tp_list;	/* ln_test_peers */
	lnet_nid_t		tp_nid;		/* matching nid */
	unsigned int		tp_threshold;	/* # failures to simulate */
};

#define LNET_COOKIE_TYPE_MD    1
#define LNET_COOKIE_TYPE_ME    2
#define LNET_COOKIE_TYPE_EQ    3
#define LNET_COOKIE_TYPE_BITS  2
#define LNET_COOKIE_MASK	((1ULL << LNET_COOKIE_TYPE_BITS) - 1ULL)

struct lnet_ni;					 /* forward ref */
struct socket;

struct lnet_lnd {
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
	void (*lnd_query)(struct lnet_ni *ni, lnet_nid_t peer, time64_t *when);

	/* accept a new connection */
	int (*lnd_accept)(struct lnet_ni *ni, struct socket *sock);
};

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
	/* initial state when NI is created */
	LNET_NI_STATE_INIT = 0,
	/* set when NI is brought up */
	LNET_NI_STATE_ACTIVE,
	/* set when NI is being shutdown */
	LNET_NI_STATE_DELETING,
};

#define LNET_NI_RECOVERY_PENDING	BIT(0)
#define LNET_NI_RECOVERY_FAILED		BIT(1)

enum lnet_stats_type {
	LNET_STATS_TYPE_SEND = 0,
	LNET_STATS_TYPE_RECV,
	LNET_STATS_TYPE_DROP
};

struct lnet_comm_count {
	atomic_t co_get_count;
	atomic_t co_put_count;
	atomic_t co_reply_count;
	atomic_t co_ack_count;
	atomic_t co_hello_count;
};

struct lnet_element_stats {
	struct lnet_comm_count el_send_stats;
	struct lnet_comm_count el_recv_stats;
	struct lnet_comm_count el_drop_stats;
};

struct lnet_health_local_stats {
	atomic_t hlt_local_interrupt;
	atomic_t hlt_local_dropped;
	atomic_t hlt_local_aborted;
	atomic_t hlt_local_no_route;
	atomic_t hlt_local_timeout;
	atomic_t hlt_local_error;
};

struct lnet_health_remote_stats {
	atomic_t hlt_remote_dropped;
	atomic_t hlt_remote_timeout;
	atomic_t hlt_remote_error;
	atomic_t hlt_network_timeout;
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

struct lnet_ni {
	/* chain on the lnet_net structure */
	struct list_head	ni_netlist;

	/* chain on the recovery queue */
	struct list_head	ni_recovery;

	/* MD handle for recovery ping */
	struct lnet_handle_md	ni_ping_mdh;

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
	time64_t		ni_last_alive;

	/* pointer to parent network */
	struct lnet_net		*ni_net;

	/* my health status */
	struct lnet_ni_status	*ni_status;

	/* NI FSM. Protected by lnet_ni_lock() */
	enum lnet_ni_state	ni_state;

	/* Recovery state. Protected by lnet_ni_lock() */
	__u32			ni_recovery_state;

	/* per NI LND tunables */
	struct lnet_lnd_tunables ni_lnd_tunables;

	/* lnd tunables set explicitly */
	bool ni_lnd_tunables_set;

	/* NI statistics */
	struct lnet_element_stats ni_stats;
	struct lnet_health_local_stats ni_hstats;

	/* physical device CPT */
	int			ni_dev_cpt;

	/* sequence number used to round robin over nis within a net */
	__u32			ni_seq;

	/*
	 * health value
	 *	initialized to LNET_MAX_HEALTH_VALUE
	 * Value is decremented every time we fail to send a message over
	 * this NI because of a NI specific failure.
	 * Value is incremented if we successfully send a message.
	 */
	atomic_t		ni_healthv;

	/*
	 * Set to 1 by the LND when it receives an event telling it the device
	 * has gone into a fatal state. Set to 0 when the LND receives an
	 * even telling it the device is back online.
	 */
	atomic_t		ni_fatal_error_on;

	/*
	 * equivalent interfaces to use
	 * This is an array because socklnd bonding can still be configured
	 */
	char			*ni_interfaces[LNET_INTERFACES_NUM];
	struct net		*ni_net_ns;     /* original net namespace */
};

#define LNET_PROTO_PING_MATCHBITS	0x8000000000000000LL

/*
 * Descriptor of a ping info buffer: keep a separate indicator of the
 * size and a reference count. The type is used both as a source and
 * sink of data, so we need to keep some information outside of the
 * area that may be overwritten by network data.
 */
struct lnet_ping_buffer {
	int			pb_nnis;
	atomic_t		pb_refcnt;
	struct lnet_ping_info	pb_info;
};

#define LNET_PING_BUFFER_SIZE(NNIDS) \
	offsetof(struct lnet_ping_buffer, pb_info.pi_ni[NNIDS])
#define LNET_PING_BUFFER_LONI(PBUF)	((PBUF)->pb_info.pi_ni[0].ns_nid)
#define LNET_PING_BUFFER_SEQNO(PBUF)	((PBUF)->pb_info.pi_ni[0].ns_status)

#define LNET_PING_INFO_TO_BUFFER(PINFO)	\
	container_of((PINFO), struct lnet_ping_buffer, pb_info)

/* router checker data, per router */
struct lnet_rc_data {
	/* chain on the_lnet.ln_zombie_rcd or ln_deathrow_rcd */
	struct list_head	rcd_list;
	struct lnet_handle_md	rcd_mdh;	/* ping buffer MD */
	struct lnet_peer_ni	*rcd_gateway;	/* reference to gateway */
	struct lnet_ping_buffer	*rcd_pingbuffer;/* ping buffer */
	int			rcd_nnis;	/* desired size of buffer */
};

struct lnet_peer_ni {
	/* chain on lpn_peer_nis */
	struct list_head	lpni_peer_nis;
	/* chain on remote peer list */
	struct list_head	lpni_on_remote_peer_ni_list;
	/* chain on recovery queue */
	struct list_head	lpni_recovery;
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
	struct lnet_health_remote_stats lpni_hstats;
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
	time64_t		lpni_timestamp;
	/* time of last ping attempt */
	time64_t		lpni_ping_timestamp;
	/* != 0 if ping reply expected */
	time64_t		lpni_ping_deadline;
	/* when I was last alive */
	time64_t		lpni_last_alive;
	/* when lpni_ni was queried last time */
	time64_t		lpni_last_query;
	/* network peer is on */
	struct lnet_net		*lpni_net;
	/* peer's NID */
	lnet_nid_t		lpni_nid;
	/* # refs */
	atomic_t		lpni_refcount;
	/* health value for the peer */
	atomic_t		lpni_healthv;
	/* recovery ping mdh */
	struct lnet_handle_md	lpni_recovery_ping_mdh;
	/* CPT this peer attached on */
	int			lpni_cpt;
	/* state flags -- protected by lpni_lock */
	unsigned		lpni_state;
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
	/* preferred local nids: if only one, use lpni_pref.nid */
	union lpni_pref {
		lnet_nid_t	nid;
		lnet_nid_t	*nids;
	} lpni_pref;
	/* number of preferred NIDs in lnpi_pref_nids */
	__u32			lpni_pref_nnids;
	/* router checker state */
	struct lnet_rc_data	*lpni_rcd;
};

/* Preferred path added due to traffic on non-MR peer_ni */
#define LNET_PEER_NI_NON_MR_PREF	(1 << 0)
/* peer is being recovered. */
#define LNET_PEER_NI_RECOVERY_PENDING	(1 << 1)
/* recovery ping failed */
#define LNET_PEER_NI_RECOVERY_FAILED	(1 << 2)
/* peer is being deleted */
#define LNET_PEER_NI_DELETING		(1 << 3)

struct lnet_peer {
	/* chain on pt_peer_list */
	struct list_head	lp_peer_list;

	/* list of peer nets */
	struct list_head	lp_peer_nets;

	/* list of messages pending discovery*/
	struct list_head	lp_dc_pendq;

	/* primary NID of the peer */
	lnet_nid_t		lp_primary_nid;

	/* source NID to use during discovery */
	lnet_nid_t		lp_disc_src_nid;

	/* CPT of peer_table */
	int			lp_cpt;

	/* number of NIDs on this peer */
	int			lp_nnis;

	/* reference count */
	atomic_t		lp_refcount;

	/* lock protecting peer state flags */
	spinlock_t		lp_lock;

	/* peer state flags */
	unsigned		lp_state;

	/* buffer for data pushed by peer */
	struct lnet_ping_buffer	*lp_data;

	/* MD handle for ping in progress */
	struct lnet_handle_md	lp_ping_mdh;

	/* MD handle for push in progress */
	struct lnet_handle_md	lp_push_mdh;

	/* number of NIDs for sizing push data */
	int			lp_data_nnis;

	/* NI config sequence number of peer */
	__u32			lp_peer_seqno;

	/* Local NI config sequence number acked by peer */
	__u32			lp_node_seqno;

	/* Local NI config sequence number sent to peer */
	__u32			lp_node_seqno_sent;

	/* Ping error encountered during discovery. */
	int			lp_ping_error;

	/* Push error encountered during discovery. */
	int			lp_push_error;

	/* Error encountered during discovery. */
	int			lp_dc_error;

	/* time it was put on the ln_dc_working queue */
	time64_t		lp_last_queued;

	/* link on discovery-related lists */
	struct list_head	lp_dc_list;

	/* tasks waiting on discovery of this peer */
	wait_queue_head_t	lp_dc_waitq;
};

/*
 * The status flags in lp_state. Their semantics have chosen so that
 * lp_state can be zero-initialized.
 *
 * A peer is marked MULTI_RAIL in two cases: it was configured using DLC
 * as multi-rail aware, or the LNET_PING_FEAT_MULTI_RAIL bit was set.
 *
 * A peer is marked NO_DISCOVERY if the LNET_PING_FEAT_DISCOVERY bit was
 * NOT set when the peer was pinged by discovery.
 */
#define LNET_PEER_MULTI_RAIL	(1 << 0)	/* Multi-rail aware */
#define LNET_PEER_NO_DISCOVERY	(1 << 1)	/* Peer disabled discovery */
/*
 * A peer is marked CONFIGURED if it was configured by DLC.
 *
 * In addition, a peer is marked DISCOVERED if it has fully passed
 * through Peer Discovery.
 *
 * When Peer Discovery is disabled, the discovery thread will mark
 * peers REDISCOVER to indicate that they should be re-examined if
 * discovery is (re)enabled on the node.
 *
 * A peer that was created as the result of inbound traffic will not
 * be marked at all.
 */
#define LNET_PEER_CONFIGURED	(1 << 2)	/* Configured via DLC */
#define LNET_PEER_DISCOVERED	(1 << 3)	/* Peer was discovered */
#define LNET_PEER_REDISCOVER	(1 << 4)	/* Discovery was disabled */
/*
 * A peer is marked DISCOVERING when discovery is in progress.
 * The other flags below correspond to stages of discovery.
 */
#define LNET_PEER_DISCOVERING	(1 << 5)	/* Discovering */
#define LNET_PEER_DATA_PRESENT	(1 << 6)	/* Remote peer data present */
#define LNET_PEER_NIDS_UPTODATE	(1 << 7)	/* Remote peer info uptodate */
#define LNET_PEER_PING_SENT	(1 << 8)	/* Waiting for REPLY to Ping */
#define LNET_PEER_PUSH_SENT	(1 << 9)	/* Waiting for ACK of Push */
#define LNET_PEER_PING_FAILED	(1 << 10)	/* Ping send failure */
#define LNET_PEER_PUSH_FAILED	(1 << 11)	/* Push send failure */
/*
 * A ping can be forced as a way to fix up state, or as a manual
 * intervention by an admin.
 * A push can be forced in circumstances that would normally not
 * allow for one to happen.
 */
#define LNET_PEER_FORCE_PING	(1 << 12)	/* Forced Ping */
#define LNET_PEER_FORCE_PUSH	(1 << 13)	/* Forced Push */

struct lnet_peer_net {
	/* chain on lp_peer_nets */
	struct list_head	lpn_peer_nets;

	/* list of peer_nis on this network */
	struct list_head	lpn_peer_nis;

	/* pointer to the peer I'm part of */
	struct lnet_peer	*lpn_peer;

	/* Net ID */
	__u32			lpn_net_id;

	/* reference count */
	atomic_t		lpn_refcount;
};

/* peer hash size */
#define LNET_PEER_HASH_BITS	9
#define LNET_PEER_HASH_SIZE	(1 << LNET_PEER_HASH_BITS)

/*
 * peer hash table - one per CPT
 *
 * protected by lnet_net_lock/EX for update
 *    pt_version
 *    pt_number
 *    pt_hash[...]
 *    pt_peer_list
 *    pt_peers
 * protected by pt_zombie_lock:
 *    pt_zombie_list
 *    pt_zombies
 *
 * pt_zombie lock nests inside lnet_net_lock
 */
struct lnet_peer_table {
	int			pt_version;	/* /proc validity stamp */
	int			pt_number;	/* # peers_ni extant */
	struct list_head	*pt_hash;	/* NID->peer hash */
	struct list_head	pt_peer_list;	/* peers */
	int			pt_peers;	/* # peers */
	struct list_head	pt_zombie_list;	/* zombie peer_ni */
	int			pt_zombies;	/* # zombie peers_ni */
	spinlock_t		pt_zombie_lock;	/* protect list and count */
};

/* peer aliveness is enabled only on routers for peers in a network where the
 * struct lnet_ni::ni_peertimeout has been set to a positive value
 */
#define lnet_peer_aliveness_enabled(lp) (the_lnet.ln_routing != 0 && \
					((lp)->lpni_net) && \
					(lp)->lpni_net->net_tunables.lct_peer_timeout > 0)

struct lnet_route {
	struct list_head	lr_list;	/* chain on net */
	struct list_head	lr_gwlist;	/* chain on gateway */
	struct lnet_peer_ni	*lr_gateway;	/* router node */
	__u32			lr_net;		/* remote network number */
	int			lr_seq;		/* sequence for round-robin */
	unsigned int		lr_downis;	/* number of down NIs */
	__u32			lr_hops;	/* how far I am */
	unsigned int		lr_priority;	/* route priority */
};

#define LNET_REMOTE_NETS_HASH_DEFAULT	(1U << 7)
#define LNET_REMOTE_NETS_HASH_MAX	(1U << 16)
#define LNET_REMOTE_NETS_HASH_SIZE	(1 << the_lnet.ln_remote_nets_hbits)

struct lnet_remotenet {
	/* chain on ln_remote_nets_hash */
	struct list_head	lrn_list;
	/* routes to me */
	struct list_head	lrn_routes;
	/* my net number */
	__u32			lrn_net;
};

/** lnet message has credit and can be submitted to lnd for send/receive */
#define LNET_CREDIT_OK		0
/** lnet message is waiting for credit */
#define LNET_CREDIT_WAIT	1
/** lnet message is waiting for discovery */
#define LNET_DC_WAIT		2

struct lnet_rtrbufpool {
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
};

struct lnet_rtrbuf {
	struct list_head	 rb_list;	/* chain on rbp_bufs */
	struct lnet_rtrbufpool	*rb_pool;	/* owning pool */
	lnet_kiov_t		 rb_kiov[0];	/* the buffer space */
};

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

struct lnet_portal {
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
};

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
	/* msgs waiting to be resent */
	struct list_head	msc_resending;
	struct list_head	msc_active;	/* active message list */
	/* threads doing finalization */
	void			**msc_finalizers;
	/* threads doing resends */
	void			**msc_resenders;
};

/* Peer Discovery states */
#define LNET_DC_STATE_SHUTDOWN		0	/* not started */
#define LNET_DC_STATE_RUNNING		1	/* started up OK */
#define LNET_DC_STATE_STOPPING		2	/* telling thread to stop */

/* Router Checker states */
#define LNET_MT_STATE_SHUTDOWN		0	/* not started */
#define LNET_MT_STATE_RUNNING		1	/* started up OK */
#define LNET_MT_STATE_STOPPING		2	/* telling thread to stop */

/* LNet states */
#define LNET_STATE_SHUTDOWN		0	/* not started */
#define LNET_STATE_RUNNING		1	/* started up OK */
#define LNET_STATE_STOPPING		2	/* telling thread to stop */

struct lnet {
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
	/* resend messages list */
	struct list_head		ln_msg_resend;
	/* spin lock to protect the msg resend list */
	spinlock_t			ln_msg_resend_lock;

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

	/*
	 * Ping target / Push source
	 *
	 * The ping target and push source share a single buffer. The
	 * ln_ping_target is protected against concurrent updates by
	 * ln_api_mutex.
	 */
	struct lnet_handle_md		ln_ping_target_md;
	struct lnet_handle_eq		ln_ping_target_eq;
	struct lnet_ping_buffer		*ln_ping_target;
	atomic_t			ln_ping_target_seqno;

	/*
	 * Push Target
	 *
	 * ln_push_nnis contains the desired size of the push target.
	 * The lnet_net_lock is used to handle update races. The old
	 * buffer may linger a while after it has been unlinked, in
	 * which case the event handler cleans up.
	 */
	struct lnet_handle_eq		ln_push_target_eq;
	struct lnet_handle_md		ln_push_target_md;
	struct lnet_ping_buffer		*ln_push_target;
	int				ln_push_target_nnis;

	/* discovery event queue handle */
	struct lnet_handle_eq		ln_dc_eqh;
	/* discovery requests */
	struct list_head		ln_dc_request;
	/* discovery working list */
	struct list_head		ln_dc_working;
	/* discovery expired list */
	struct list_head		ln_dc_expired;
	/* discovery thread wait queue */
	wait_queue_head_t		ln_dc_waitq;
	/* discovery startup/shutdown state */
	int				ln_dc_state;

	/* monitor thread startup/shutdown state */
	int				ln_mt_state;
	/* router checker's event queue */
	struct lnet_handle_eq		ln_rc_eqh;
	/* rcd still pending on net */
	struct list_head		ln_rcd_deathrow;
	/* rcd ready for free */
	struct list_head		ln_rcd_zombie;
	/* serialise startup/shutdown */
	struct semaphore		ln_mt_signal;

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

	/*
	 * waitq for the monitor thread. The monitor thread takes care of
	 * checking routes, timedout messages and resending messages.
	 */
	wait_queue_head_t		ln_mt_waitq;

	/* per-cpt resend queues */
	struct list_head		**ln_mt_resendqs;
	/* local NIs to recover */
	struct list_head		ln_mt_localNIRecovq;
	/* local NIs to recover */
	struct list_head		ln_mt_peerNIRecovq;
	/*
	 * An array of queues for GET/PUT waiting for REPLY/ACK respectively.
	 * There are CPT number of queues. Since response trackers will be
	 * added on the fast path we can't afford to grab the exclusive
	 * net lock to protect these queues. The CPT will be calculated
	 * based on the mdh cookie.
	 */
	struct list_head		**ln_mt_rstq;
	/*
	 * A response tracker becomes a zombie when the associated MD is queued
	 * for unlink before the response tracker is detached from the MD. An
	 * entry on a zombie list can be freed when either the remaining
	 * operations on the MD complete or when LNet has shut down.
	 */
	struct list_head		**ln_mt_zombie_rstqs;
	/* recovery eq handler */
	struct lnet_handle_eq		ln_mt_eqh;

};

#endif
