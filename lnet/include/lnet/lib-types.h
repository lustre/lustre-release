// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/
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
#include <linux/kref.h>
#include <net/genetlink.h>
#include <lustre_compat/linux/generic-radix-tree.h>

#include <uapi/linux/lnet/lnet-nl.h>
#include <uapi/linux/lnet/lnet-dlc.h>
#include <uapi/linux/lnet/lnetctl.h>
#include <uapi/linux/lnet/nidstr.h>

int libcfs_strid(struct lnet_processid *id, const char *str);

int cfs_match_nid_net(struct lnet_nid *nid, u32 net,
		      struct list_head *net_num_list,
		      struct list_head *addr);

/* Structure to represent \<range_expr\> token of the syntax. */
struct cfs_range_expr {
	/* Link to cfs_expr_list::el_exprs. */
	struct list_head        re_link;
	u32                     re_lo;
	u32                     re_hi;
	u32                     re_stride;
};

struct cfs_expr_list {
	struct list_head        el_link;
	struct list_head        el_exprs;
};

int cfs_expr_list_match(u32 value, struct cfs_expr_list *expr_list);
int cfs_expr_list_values(struct cfs_expr_list *expr_list,
			 int max, u32 **values);
void cfs_expr_list_free(struct cfs_expr_list *expr_list);
int cfs_expr_list_parse(char *str, int len, unsigned int min, unsigned int max,
			struct cfs_expr_list **elpp);
void cfs_expr_list_free_list(struct list_head *list);
#define cfs_expr_list_values_free(values, num)  CFS_FREE_PTR_ARRAY(values, num)

/* Max payload size */
#define LNET_MAX_PAYLOAD	LNET_MTU

/** limit on the number of fragments in discontiguous MDs */
#define LNET_MAX_IOV	256

/*
 * This is the maximum health value.
 * All local and peer NIs created have their health default to this value.
 */
#define LNET_MAX_HEALTH_VALUE 1000
#define LNET_MAX_SELECTION_PRIORITY UINT_MAX

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
	struct lnet_nid rspt_next_hop_nid;
	/* deadline of the REPLY/ACK */
	ktime_t rspt_deadline;
	/* parent MD */
	struct lnet_handle_md rspt_mdh;
};

struct lnet_msg {
	struct list_head	msg_activelist;
	struct list_head	msg_list;	/* Q for credits/MD */

	struct lnet_processid	msg_target;
	/* Primary NID of the source. */
	struct lnet_nid		msg_initiator;
	/* where is it from, it's only for building event */
	struct lnet_nid		msg_from;
	__u32			msg_type;

	/*
	 * hold parameters in case message is with held due
	 * to discovery
	 */
	struct lnet_nid		msg_src_nid_param;
	struct lnet_nid		msg_rtr_nid_param;

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
	struct bio_vec	     *msg_kiov;

	struct lnet_event	msg_ev;
	struct lnet_hdr		msg_hdr;
};

struct lnet_libhandle {
	struct list_head	lh_hash_chain;
	__u64			lh_cookie;
};

#define lh_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))

struct lnet_me {
	struct list_head	me_list;
	int			me_cpt;
	struct lnet_processid	me_match_id;
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
	lnet_handler_t		 md_handler;
	struct lnet_handle_md	 md_bulk_handle;
	struct bio_vec		 md_kiov[LNET_MAX_IOV];
};

#define LNET_MD_FLAG_ZOMBIE	 BIT(0)
#define LNET_MD_FLAG_AUTO_UNLINK BIT(1)
#define LNET_MD_FLAG_ABORTED	 BIT(2)
/* LNET_MD_FLAG_HANDLING is set when a non-unlink event handler
 * is being called for an event relating to the md.
 * It ensures only one such handler runs at a time.
 * The final "unlink" event is only called once the
 * md_refcount has reached zero, and this flag has been cleared,
 * ensuring that it doesn't race with any other event handler
 * call.
 */
#define LNET_MD_FLAG_HANDLING	 BIT(3)
#define LNET_MD_FLAG_GPU	 BIT(5) /**< Special mapping needs */

static inline bool lnet_md_is_gpu(struct lnet_libmd *md)
{
    return (md != NULL) && !!(md->md_flags & LNET_MD_FLAG_GPU);
}

struct lnet_test_peer {
	/* info about peers we are trying to fail */
	struct list_head	tp_list;	/* ln_test_peers */
	struct lnet_nid		tp_nid;		/* matching nid */
	unsigned int		tp_threshold;	/* # failures to simulate */
};

#define LNET_COOKIE_TYPE_MD    1
#define LNET_COOKIE_TYPE_ME    2
#define LNET_COOKIE_TYPE_EQ    3
#define LNET_COOKIE_TYPE_BITS  2
#define LNET_COOKIE_MASK	((1ULL << LNET_COOKIE_TYPE_BITS) - 1ULL)

struct netstrfns {
	u32	nf_type;
	char	*nf_name;
	char	*nf_modname;
	void	(*nf_addr2str)(u32 addr, char *str, size_t size);
	void	(*nf_addr2str_size)(const __be32 *addr, size_t asize,
				    char *str, size_t size);
	int	(*nf_str2addr)(const char *str, int nob, u32 *addr);
	int	(*nf_str2addr_size)(const char *str, int nob,
				    __be32 *addr, size_t *asize);
	int	(*nf_parse_addrlist)(char *str, int len,
				     struct list_head *list);
	int	(*nf_print_addrlist)(char *buffer, int count,
				     struct list_head *list);
	int	(*nf_match_addr)(u32 addr, struct list_head *list);
	int	(*nf_match_netmask)(const __be32 *addr, size_t asize,
				    const __be32 *netmask,
				    const __be32 *netaddr);
	int	(*nf_min_max)(struct list_head *nidlist, u32 *min_nid,
			      u32 *max_nid);
};

struct lnet_ni;					 /* forward ref */
struct socket;

struct lnet_lnd {
	/* fields initialized by the LND */
	__u32			lnd_type;

	int  (*lnd_startup)(struct lnet_ni *ni);
	void (*lnd_shutdown)(struct lnet_ni *ni);
	int  (*lnd_ctl)(struct lnet_ni *ni, unsigned int cmd, void *arg);

	/* In data movement APIs below, payload buffers are described as a set
	 * of 'niov' fragments which are in pages.
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
			struct bio_vec *kiov,
			unsigned int offset, unsigned int mlen, unsigned int rlen);

	/* lnet_parse() has had to delay processing of this message
	 * (e.g. waiting for a forwarding buffer or send credits).  Give the
	 * LND a chance to free urgently needed resources.  If called, return 0
	 * for success and do NOT give back a receive credit; that has to wait
	 * until lnd_recv() gets called.  On failure return < 0 and
	 * release resources; lnd_recv() will not be called. */
	int (*lnd_eager_recv)(struct lnet_ni *ni, void *private,
			      struct lnet_msg *msg, void **new_privatep);

	/* notification of peer down */
	void (*lnd_notify_peer_down)(struct lnet_nid *peer);

	/* accept a new connection */
	int (*lnd_accept)(struct lnet_ni *ni, struct socket *sock);

	/* get dma_dev priority */
	unsigned int (*lnd_get_dev_prio)(struct lnet_ni *ni,
					 unsigned int dev_idx);

	/* Handle LND specific Netlink handling */
	int (*lnd_nl_get)(int cmd, struct sk_buff *msg, int type, void *data);
	int (*lnd_nl_set)(int cmd, struct nlattr *attr, int type, void *data);

	const struct ln_key_list *lnd_keys;

	/* get LND timeout */
	int (*lnd_get_timeout)(void);
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

	/* round robin selection */
	__u32			net_seq;

	/* total number of CPTs in the array */
	__u32			net_ncpts;

	/* cumulative CPTs of all NIs in this net */
	__u32			*net_cpts;

	/* relative net selection priority */
	__u32			net_sel_priority;

	/* network tunables */
	struct lnet_ioctl_config_lnd_cmn_tunables net_tunables;

	/*
	 * boolean to indicate that the tunables have been set and
	 * shouldn't be reset
	 */
	bool			net_tunables_set;

	/* procedural interface */
	const struct lnet_lnd	*net_lnd;

	/* list of NIs on this net */
	struct list_head	net_ni_list;

	/* list of NIs being added, but not started yet */
	struct list_head	net_ni_added;

	/* dying LND instances */
	struct list_head	net_ni_zombie;

	/* when I was last alive */
	time64_t		net_last_alive;

	/* protects access to net_last_alive */
	spinlock_t		net_lock;

	/* list of router nids preferred for this network */
	struct list_head	net_rtr_pref_nids;
};

/* Normally Netlink atttributes are defined in UAPI headers but Lustre is
 * different in that the ABI is in a constant state of change unlike other
 * Netlink interfaces. LNet sends a special header to help user land handle
 * the differences.
 */

/** enum lnet_err_atrrs		      - LNet error netlink properties
 *					For LNet request of multiple items
 *					sometimes those items exist and
 *					others don't. In the case the item
 *					item doesn't exist we return the
 *					error state.
 *
 * @LNET_ERR_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LNET_ERR_ATTR_HDR:			Name of the error header
 *					(NLA_NUL_STRING)
 * @LNET_ERR_ATTR_TYPE:			Which LNet function since error is for
 *					(NLA_STRING)
 * @LNET_ERR_TYPE_ERRNO:		Error code for failure (NLA_S16)
 * @LNET_ERR_DESCR:			Complete error message (NLA_STRING)
 */
enum lnet_err_attrs {
	LNET_ERR_ATTR_UNSPEC = 0,

	LNET_ERR_ATTR_HDR,
	LNET_ERR_ATTR_TYPE,
	LNET_ERR_ATTR_ERRNO,
	LNET_ERR_ATTR_DESCR,
	__LNET_ERR_ATTR_MAX_PLUS_ONE,
};

#define LNET_ERR_ATTR_MAX (__LNET_ERR_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_net_attrs		      - LNet NI netlink properties
 *					attributes that describe LNet 'NI'
 *					These values are used to piece together
 *					messages for sending and receiving.
 *
 * @LNET_NET_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LNET_NET_ATTR_HDR:			grouping for LNet net data (NLA_NUL_STRING)
 * @LNET_NET_ATTR_TYPE:			LNet net this NI belongs to (NLA_STRING)
 * @LNET_NET_ATTR_LOCAL:		Local NI information (NLA_NESTED)
 */
enum lnet_net_attrs {
	LNET_NET_ATTR_UNSPEC = 0,

	LNET_NET_ATTR_HDR,
	LNET_NET_ATTR_TYPE,
	LNET_NET_ATTR_LOCAL,

	__LNET_NET_ATTR_MAX_PLUS_ONE,
};

#define LNET_NET_ATTR_MAX (__LNET_NET_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_net_local_ni_attrs	      - LNet local NI netlink properties
 *						attributes that describe local
 *						NI
 *
 * @LNET_NET_LOCAL_NI_ATTR_UNSPEC:		unspecified attribute to catch
 *						errors
 *
 * @LNET_NET_LOCAL_NI_ATTR_NID:			NID that represents this NI
 *						(NLA_STRING)
 * @LNET_NET_LOCAL_NI_ATTR_STATUS:		State of this NI (NLA_STRING)
 * @LNET_NET_LOCAL_NI_ATTR_INTERFACE:		Defines physical devices. used
 *						to be many devices but no longer
 *						(NLA_NESTED)
 *
 * @LNET_NET_LOCAL_NI_ATTR_STATS:		NI general msg stats (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_UDSP_INFO:		NI UDSP state (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_SEND_STATS:		NI send stats (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_RECV_STATS:		NI received stats (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_DROPPED_STATS:	NI dropped stats (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_HEALTH_STATS:	NI health stats (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_TUNABLES:		NI tunables (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_LND_TUNABLES:	NI LND tunables (NLA_NESTED)
 * @LNET_NET_LOCAL_NI_ATTR_DEV_CPT:		NI CPT interface bound to
 *						(NLA_S32)
 * @LNET_NET_LOCAL_NI_ATTR_CPTS:		CPT core used by this NI
 *						(NLA_STRING)
 */
enum lnet_net_local_ni_attrs {
	LNET_NET_LOCAL_NI_ATTR_UNSPEC = 0,

	LNET_NET_LOCAL_NI_ATTR_NID,
	LNET_NET_LOCAL_NI_ATTR_STATUS,
	LNET_NET_LOCAL_NI_ATTR_INTERFACE,

	LNET_NET_LOCAL_NI_ATTR_STATS,
	LNET_NET_LOCAL_NI_ATTR_UDSP_INFO,
	LNET_NET_LOCAL_NI_ATTR_SEND_STATS,
	LNET_NET_LOCAL_NI_ATTR_RECV_STATS,
	LNET_NET_LOCAL_NI_ATTR_DROPPED_STATS,
	LNET_NET_LOCAL_NI_ATTR_HEALTH_STATS,
	LNET_NET_LOCAL_NI_ATTR_TUNABLES,
	LNET_NET_LOCAL_NI_ATTR_LND_TUNABLES,
	LNET_NET_LOCAL_NI_DEV_CPT,
	LNET_NET_LOCAL_NI_CPTS,

	__LNET_NET_LOCAL_NI_ATTR_MAX_PLUS_ONE,
};

#define LNET_NET_LOCAL_NI_ATTR_MAX (__LNET_NET_LOCAL_NI_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_net_local_ni_intf_attrs - LNet NI device netlink properties
 *					attribute that reports the device
 *					in use
 *
 * @LNET_NET_LOCAL_NI_INTF_ATTR_UNSPEC:	unspecified attribute to catch errors
 *
 * @LNET_NET_LOCAL_NI_INTF_ATTR_TYPE:	Physcial device interface (NLA_STRING)
 */
enum lnet_net_local_ni_intf_attrs {
	LNET_NET_LOCAL_NI_INTF_ATTR_UNSPEC = 0,

	LNET_NET_LOCAL_NI_INTF_ATTR_TYPE,

	__LNET_NET_LOCAL_NI_INTF_ATTR_MAX_PLUS_ONE,
};

#define LNET_NET_LOCAL_NI_INTF_ATTR_MAX (__LNET_NET_LOCAL_NI_INTF_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_net_local_ni_stats_attrs	      - LNet NI netlink properties
 *						attributes that reports the
 *						network traffic stats
 *
 * @LNET_NET_LOCAL_NI_STATS_ATTR_UNSPEC:	unspecified attribute to catch
 *						errors
 *
 * @LNET_NET_LOCAL_NI_STATS_ATTR_SEND_COUNT:	Number of sent messages
 *						(NLA_U32)
 * @LNET_NET_LOCAL_NI_STATS_ATTR_RECV_COUNT:	Number of received messages
 *						(NLA_U32)
 * @LNET_NET_LOCAL_NI_STATS_ATTR_DROP_COUNT:	Number of dropped messages
 *						(NLA_U32)
 */
enum lnet_net_local_ni_stats_attrs {
	LNET_NET_LOCAL_NI_STATS_ATTR_UNSPEC = 0,

	LNET_NET_LOCAL_NI_STATS_ATTR_SEND_COUNT,
	LNET_NET_LOCAL_NI_STATS_ATTR_RECV_COUNT,
	LNET_NET_LOCAL_NI_STATS_ATTR_DROP_COUNT,
	__LNET_NET_LOCAL_NI_STATS_ATTR_MAX_PLUS_ONE,
};

#define LNET_NET_LOCAL_NI_STATS_ATTR_MAX (__LNET_NET_LOCAL_NI_STATS_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_net_local_ni_msg_stats_attrs	      - LNet NI netlink
 *							properties attributes
 *							that reports the message
 *							type traffic stats
 *
 * @LNET_NET_LOCAL_NI_MSG_STATS_ATTR_UNSPEC:		unspecified attribute
 *							to catch errors
 *
 * @LNET_NET_LOCAL_NI_MSG_STATS_ATTR_PUT_COUNT:		Number of PUT messages
 *							(NLA_U32)
 * @LNET_NET_LOCAL_NI_MSG_STATS_ATTR_GET_COUNT:		Number of GET messages
 *							(NLA_U32)
 * @LNET_NET_LOCAL_NI_MSG_STATS_ATTR_REPLY_COUNT:	Number of REPLY messages
 *							(NLA_U32)
 * @LNET_NET_LOCAL_NI_MSG_STATS_ATTR_ACK_COUNT:		Number of ACK messages
 *							(NLA_U32)
 * @LNET_NET_LOCAL_NI_MSG_STATS_ATTR_HELLO_COUNT:	Number of HELLO messages
 *							(NLA_U32)
 */
enum lnet_net_local_ni_msg_stats_attrs {
	LNET_NET_LOCAL_NI_MSG_STATS_ATTR_UNSPEC = 0,

	LNET_NET_LOCAL_NI_MSG_STATS_ATTR_PUT_COUNT,
	LNET_NET_LOCAL_NI_MSG_STATS_ATTR_GET_COUNT,
	LNET_NET_LOCAL_NI_MSG_STATS_ATTR_REPLY_COUNT,
	LNET_NET_LOCAL_NI_MSG_STATS_ATTR_ACK_COUNT,
	LNET_NET_LOCAL_NI_MSG_STATS_ATTR_HELLO_COUNT,
	__LNET_NET_LOCAL_NI_MSG_STATS_ATTR_MAX_PLUS_ONE,
};

#define LNET_NET_LOCAL_NI_MSG_STATS_ATTR_MAX (__LNET_NET_LOCAL_NI_MSG_STATS_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_net_local_ni_health_stats_attrs	      - LNet NI netlink
 *							properties attributes
 *							that reports how
 *							healthly it is.
 *
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_UNSPEC:		unspecified attribute
 *							to catch errors
 *
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_FATAL_ERRORS:	How many fatal errors
 *							(NLA_S32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_LEVEL:		How healthly is NI
 *							(NLA_S32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_INTERRUPTS:	How many interrupts
 *							happened (NLA_U32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_DROPPED:	How much traffic has
 *							been dropped (NLA_U32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ABORTED:	How many aborts
 *							happened (NLA_U32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NO_ROUTE:	How often routing broke
 *							(NLA_U32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_TIMEOUTS:	How often timeouts
 *							occurred (NLA_U32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ERROR:		The number of errors
 *							reported (NLA_U32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_PING_COUNT:	Number of successful
 *							ping (NLA_U32)
 * @LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NEXT_PING:	Number of next pings
 *							(NLA_U64)
 */
enum lnet_net_local_ni_health_stats_attrs {
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_UNSPEC = 0,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_PAD = LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_UNSPEC,

	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_FATAL_ERRORS,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_LEVEL,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_INTERRUPTS,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_DROPPED,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ABORTED,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NO_ROUTE,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_TIMEOUTS,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ERROR,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_PING_COUNT,
	LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NEXT_PING,
	__LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_MAX_PLUS_ONE,
};
#define LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_MAX (__LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_net_local_ni_tunables_attrs	      - LNet NI tunables
 *							netlink properties.
 *							Performance options
 *							for your NI.
 *
 * @LNET_NET_LOCAL_NI_TUNABLES_ATTR_UNSPEC:		unspecified attribute
 *							to catch errors
 *
 * @LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT:	Timeout for LNet peer.
 *							(NLA_S32)
 * @LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS:	Credits for LNet peer.
 *							(NLA_S32)
 * @LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS: Buffer credits for
 *							 LNet peer. (NLA_S32)
 * @LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS:		Credits for LNet peer
 *							TX. (NLA_S32)
 */
enum lnet_net_local_ni_tunables_attr {
	LNET_NET_LOCAL_NI_TUNABLES_ATTR_UNSPEC = 0,

	LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT,
	LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS,
	LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS,
	LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS,
	__LNET_NET_LOCAL_NI_TUNABLES_ATTR_MAX_PLUS_ONE,
};

#define LNET_NET_LOCAL_NI_TUNABLES_ATTR_MAX (__LNET_NET_LOCAL_NI_TUNABLES_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_route_attrs		      - LNet route netlink
 *						attributes that describe
 *						LNet routes
 *
 * @LNET_ROUTE_ATTR_UNSPEC:			unspecified attribute to
 *						catch errors
 *
 * @LNET_ROUTE_ATTR_HDR:			grouping for LNet route data
 *						(NLA_NUL_STRING)
 * @LNET_ROUTE_ATTR_NET:			LNet remote network reached
 *						by the route (NLA_STRING)
 * @LNET_ROUTE_ATTR_GATEWAY:			gateway for the route
 *						(NLA_STRING)
 * @LNET_ROUTE_ATTR_HOP:			route hop count (NLA_S32)
 *
 * @LNET_ROUTE_ATTR_PRIORITY:			rank of this network path
 *						(NLA_U32)
 * @LNET_ROUTE_ATTR_HEALTH_SENSITIVITY:		rate of health value change
 *						for the route (NLA_U32)
 * @LNET_ROUTE_ATTR_STATE:			state of route (NLA_STRING)
 *
 * @LNET_ROUTE_ATTR_TYPE:			Report if we support multi-hop
 *						(NLA_STRING)
 */
enum lnet_route_attrs {
	LNET_ROUTE_ATTR_UNSPEC = 0,

	LNET_ROUTE_ATTR_HDR,
	LNET_ROUTE_ATTR_NET,
	LNET_ROUTE_ATTR_GATEWAY,
	LNET_ROUTE_ATTR_HOP,
	LNET_ROUTE_ATTR_PRIORITY,
	LNET_ROUTE_ATTR_HEALTH_SENSITIVITY,
	LNET_ROUTE_ATTR_STATE,
	LNET_ROUTE_ATTR_TYPE,
	__LNET_ROUTE_ATTR_MAX_PLUS_ONE,
};

#define LNET_ROUTE_ATTR_MAX (__LNET_ROUTE_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_peer_ni_attrs	      - LNet peer NI netlink properties
 *					attributes that describe LNet peer 'NI'.
 *					These values are used to piece together
 *					messages for sending and receiving.
 *
 * @LNET_PEER_NI_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LNET_PEER_NI_ATTR_HDR:		grouping for LNet peer data
 *					(NLA_NUL_STRING)
 * @LNET_PEER_NI_ATTR_PRIMARY_NID:	primary NID of this peer (NLA_STRING)
 * @LNET_PEER_NI_ATTR_MULTIRAIL:	Do we support MultiRail ? (NLA_FLAG)
 * @LNET_PEER_NI_ATTR_STATE:		Bitfields of the peer state (NLA_U32)
 * @LNET_PEER_NI_ATTR_PEER_NI_LIST:	List of remote peers we can reach
 *					(NLA_NESTED)
 */
enum lnet_peer_ni_attrs {
	LNET_PEER_NI_ATTR_UNSPEC = 0,

	LNET_PEER_NI_ATTR_HDR,
	LNET_PEER_NI_ATTR_PRIMARY_NID,
	LNET_PEER_NI_ATTR_MULTIRAIL,
	LNET_PEER_NI_ATTR_STATE,
	LNET_PEER_NI_ATTR_PEER_NI_LIST,
	__LNET_PEER_NI_ATTR_MAX_PLUS_ONE,
};

#define LNET_PEER_NI_ATTR_MAX (__LNET_PEER_NI_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_peer_ni_list_attrs	      - LNet remote peer netlink
 *						properties attributes that
 *						describe remote LNet peer 'NI'.
 *						These values are used to piece
 *						together messages for sending
 *						and receiving.
 *
 * @LNET_PEER_NI_LIST_ATTR_UNSPEC:		unspecified attribute to catch
 *						errors
 *
 * @LNET_PEER_NI_LIST_ATTR_NID:			remote peer's NID (NLA_STRING)
 * @LNET_PEER_NI_LIST_ATTR_UDSP_INFO:		remote peer's UDSP info
 *						(NLA_NESTED)
 * @LNET_PEER_NI_LIST_ATTR_STATE:		state of remote peer
 *						(NLA_STRING)
 *
 * @LNET_PEER_NI_LIST_ATTR_MAX_TX_CREDITS:	Maximum TX credits for remote
 *						peer (NLA_U32)
 * @LNET_PEER_NI_LIST_ATTR_CUR_TX_CREDITS:	Current TX credits for remote
 *						peer (NLA_U32)
 * @LNET_PEER_NI_LIST_ATTR_MIN_TX_CREDITS:	Minimum TX credits for remote
 *						peer (NLA_U32)
 * @LNET_PEER_NI_LIST_ATTR_QUEUE_BUF_COUNT:	Size of TX queue buffer
 *						(NLA_U32)
 * @LNET_PEER_NI_LIST_ATTR_CUR_RTR_CREDITS:	Current router credits for
 *						remote peer (NLA_U32)
 * @LNET_PEER_NI_LIST_ATTR_MIN_RTR_CREDITS:	Minimum router credits for
 *						remote peer (NLA_U32)
 * @LNET_PEER_NI_LIST_ATTR_REFCOUNT:		Remote peer reference count
 *						(NLA_U32)
 * @LNET_PEER_NI_LIST_ATTR_STATS_COUNT:		Remote peer general stats,
 *						reports sent, received, and
 *						dropped packets. (NLA_NESTED)
 *
 * @LNET_PEER_NI_LIST_ATTR_SENT_STATS:		Remote peer sent stats,
 *						reports gets, puts, acks, and
 *						hello packets. (NLA_NESTED)
 * @LNET_PEER_NI_LIST_ATTR_RECV_STATS:		Remote peer received stats,
 *						reports gets, puts, acks, and
 *						hello packets. (NLA_NESTED)
 * @LNET_PEER_NI_LIST_ATTR_DROP_STATS:		Remote peer dropped stats,
 *						reports gets, puts, acks, and
 *						hello packets. (NLA_NESTED)
 * @LNET_PEER_NI_LIST_ATTR_HEALTH_STATS:	Report the stats about the
 *						health of the remote peer.
 *						(NLA_NESTED)
 */
enum lnet_peer_ni_list_attr {
	LNET_PEER_NI_LIST_ATTR_UNSPEC = 0,

	LNET_PEER_NI_LIST_ATTR_NID,
	LNET_PEER_NI_LIST_ATTR_UDSP_INFO,
	LNET_PEER_NI_LIST_ATTR_STATE,

	LNET_PEER_NI_LIST_ATTR_MAX_TX_CREDITS,
	LNET_PEER_NI_LIST_ATTR_CUR_TX_CREDITS,
	LNET_PEER_NI_LIST_ATTR_MIN_TX_CREDITS,
	LNET_PEER_NI_LIST_ATTR_QUEUE_BUF_COUNT,
	LNET_PEER_NI_LIST_ATTR_CUR_RTR_CREDITS,
	LNET_PEER_NI_LIST_ATTR_MIN_RTR_CREDITS,
	LNET_PEER_NI_LIST_ATTR_REFCOUNT,
	LNET_PEER_NI_LIST_ATTR_STATS_COUNT,

	LNET_PEER_NI_LIST_ATTR_SENT_STATS,
	LNET_PEER_NI_LIST_ATTR_RECV_STATS,
	LNET_PEER_NI_LIST_ATTR_DROP_STATS,
	LNET_PEER_NI_LIST_ATTR_HEALTH_STATS,

	__LNET_PEER_NI_LIST_ATTR_MAX_PLUS_ONE,
};

#define LNET_PEER_NI_LIST_ATTR_MAX (__LNET_PEER_NI_LIST_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_peer_ni_list_stats_count		      - LNet remote peer traffic
 *							stats netlink properties
 *							attributes that provide
 *							traffic stats on the
 *							remote LNet peer 'NI'.
 *							These values are used to
 *							piece together messages
 *							for sending and receiving.
 *
 * @LNET_PEER_NI_LIST_STATS_COUNT_ATTR_UNSPEC:		unspecified attribute to
 *							catch errors
 *
 * @LNET_PEER_NI_LIST_STATS_COUNT_ATTR_SEND_COUNT:	Number of sent packets for
 *							remote peer (NLA_U32)
 * @LNET_PEER_NI_LIST_STATS_COUNT_ATTR_RECV_COUNT:	Number of received packets
 *							for remote peer (NLA_U32)
 * @LNET_PEER_NI_LIST_STATS_COUNT_ATTR_DROP_COUNT:	Number of dropped packets
 *							for remote peer (NLA_U32)
 */
enum lnet_peer_ni_list_stats_count {
	LNET_PEER_NI_LIST_STATS_COUNT_ATTR_UNSPEC = 0,

	LNET_PEER_NI_LIST_STATS_COUNT_ATTR_SEND_COUNT,
	LNET_PEER_NI_LIST_STATS_COUNT_ATTR_RECV_COUNT,
	LNET_PEER_NI_LIST_STATS_COUNT_ATTR_DROP_COUNT,
	__LNET_PEER_NI_LIST_STATS_COUNT_ATTR_MAX_PLUS_ONE,
};

#define LNET_PEER_NI_LIST_STATS_COUNT_ATTR_MAX (__LNET_PEER_NI_LIST_STATS_COUNT_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_peer_ni_list_stats	      - LNet remote peer stats netlink
 *						properties attributes that
 *						provide stats on the remote
 *						LNet peer 'NI'. These values are
 *						used to piece together messages
 *						for sending and receiving.
 *
 * @LNET_PEER_NI_LIST_STATS_ATTR_UNSPEC:	unspecified attribute to catch
 *						errors
 *
 * @LNET_PEER_NI_LIST_STATS_ATTR_PUT:		PUT message count for remote
 *						peer (NLA_U32)
 * @LNET_PEER_NI_LIST_STATS_ATTR_GET:		GET message count for remote
 *						peer (NLA_U32)
 * @LNET_PEER_NI_LIST_STATS_ATTR_REPLY:		REPLY message count for remote
 *						peer (NLA_U32)
 * @LNET_PEER_NI_LIST_STATS_ATTR_ACK:		ACK message count for remote
 *						peer (NLA_U32)
 * @LNET_PEER_NI_LIST_STATS_ATTR_HEALTH:	HELLO message count for remote
 *						peer (NLA_U32)
 */
enum lnet_peer_ni_list_stats {
	LNET_PEER_NI_LIST_STATS_ATTR_UNSPEC = 0,

	LNET_PEER_NI_LIST_STATS_ATTR_PUT,
	LNET_PEER_NI_LIST_STATS_ATTR_GET,
	LNET_PEER_NI_LIST_STATS_ATTR_REPLY,
	LNET_PEER_NI_LIST_STATS_ATTR_ACK,
	LNET_PEER_NI_LIST_STATS_ATTR_HELLO,
	__LNET_PEER_NI_LIST_STATS_ATTR_MAX_PLUS_ONE,
};

#define LNET_PEER_NI_LIST_STATS_ATTR_MAX (__LNET_PEER_NI_LIST_STATS_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_peer_ni_list_health_stats		      - LNet remote peer health
 *							stats netlink properties
 *							attributes that provide
 *							stats on the health of a
 *							remote LNet peer 'NI'.
 *							These values are used to
 *							piece together messages
 *							for sending and receiving.
 *
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_UNSPEC:		unspecified attribute to
 *							catch errors
 *
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_VALUE:		Health level of remote
 *							peer (NLA_S32)
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_DROP:		drop message state for
 *							remote peer (NLA_U32)
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_TIMEOUT:	timeout set for remote
 *							peer (NLA_U32)
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_ERROR:		total errors for remote
 *							peer (NLA_U32)
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NETWORK_TIMEOUT: network timeout for
 *							 remote peer (NLA_U32)
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_PING_COUNT:	number of pings for
 *							remote peer (NLA_U32)
 * @LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NEXT_PING:	timestamp for next ping
 *							sent by remote peer
 *							(NLA_S64)
 */
enum lnet_peer_ni_list_health_stats {
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_UNSPEC = 0,
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_PAD = LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_UNSPEC,

	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_VALUE,
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_DROPPED,
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_TIMEOUT,
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_ERROR,
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NETWORK_TIMEOUT,
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_PING_COUNT,
	LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NEXT_PING,

	__LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_MAX_PLUS_ONE,
};

#define LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_MAX (__LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_MAX_PLUS_ONE - 1)

/** LNet netlink ping API */

/** enum lnet_ping_attr				      - LNet ping netlink properties
 *							attributes to describe ping format
 *							These values are used to piece together
 *							messages for sending and receiving.
 *
 * @LNET_PING_ATTR_UNSPEC:				unspecified attribute to catch errors
 *
 * @LNET_PING_ATTR_HDR:					grouping for LNet ping  data (NLA_NUL_STRING)
 * @LNET_PING_ATTR_PRIMARY_NID:				Source NID for ping request (NLA_STRING)
 * @LNET_PING_ATTR_ERRNO:				error code if we fail to ping (NLA_S16)
 * @LNET_PING_ATTR_MULTIRAIL:				Report if MR is supported (NLA_FLAG)
 * @LNET_PING_ATTR_PEER_NI_LIST:			List of peer NI's (NLA_NESTED)
 */
enum lnet_ping_attr {
	LNET_PING_ATTR_UNSPEC = 0,

	LNET_PING_ATTR_HDR,
	LNET_PING_ATTR_PRIMARY_NID,
	LNET_PING_ATTR_ERRNO,
	LNET_PING_ATTR_MULTIRAIL,
	LNET_PING_ATTR_PEER_NI_LIST,
	__LNET_PING_ATTR_MAX_PLUS_ONE,
};

#define LNET_PING_ATTR_MAX (__LNET_PING_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_ping_peer_ni_attr		      - LNet peer ni information reported by
 *							ping command. A list of these are
 *							returned with a ping request.
 *
 * @LNET_PING_PEER_NI_ATTR_UNSPEC:			unspecified attribute to catch errrors
 *
 * @LNET_PING_PEER_NI_ATTR_NID:				NID address of peer NI. (NLA_STRING)
 */
enum lnet_ping_peer_ni_attr {
	LNET_PING_PEER_NI_ATTR_UNSPEC = 0,

	LNET_PING_PEER_NI_ATTR_NID,
	__LNET_PING_PEER_NI_ATTR_MAX_PLUS_ONE,
};

#define LNET_PING_PEER_NI_ATTR_MAX (__LNET_PING_PEER_NI_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_udsp_info_attr			      - LNet UDSP information reported for
 *							some subsystem that tracks it.
 *
 * @LNET_UDSP_INFO_ATTR_UNSPEC:				unspecified attribute to catch errors
 *
 * @LNET_UDSP_INFO_ATTR_NET_PRIORITY,			LNet net priority in selection.
 *							(NLA_S32)
 * @LNET_UDSP_INFO_ATTR_NID_PRIORITY,			NID's priority in selection.
 *							(NLA_S32)
 * @LNET_UDSP_INFO_ATTR_PREF_RTR_NIDS_LIST:		Which gateway's are preferred.
 *							(NLA_NESTED)
 * @LNET_UDSP_INFO_ATTR_PREF_NIDS_LIST:			Which NIDs are preferred.
 *							(NLA_NESTED)
 */
enum lnet_udsp_info_attr {
	LNET_UDSP_INFO_ATTR_UNSPEC = 0,

	LNET_UDSP_INFO_ATTR_NET_PRIORITY,
	LNET_UDSP_INFO_ATTR_NID_PRIORITY,
	LNET_UDSP_INFO_ATTR_PREF_RTR_NIDS_LIST,
	LNET_UDSP_INFO_ATTR_PREF_NIDS_LIST,
	__LNET_UDSP_INFO_ATTR_MAX_PLUS_ONE,
};

#define LNET_UDSP_INFO_ATTR_MAX (__LNET_UDSP_INFO_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_udsp_info_pref_nids_attr		      - LNet UDSP information reported for
 *							some subsystem that tracks it.
 *
 * @LNET_UDSP_INFO_PREF_NIDS_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LNET_UDSP_INFO_PREF_NIDS_ATTR_INDEX,		UDSP prority NIDs label
 *							(NLA_NUL_STRING)
 * @LNET_UDSP_INFO_PREF_NIDS_ATTR_NID,			UDSP prority NID (NLA_STRING)
 */
enum lnet_udsp_info_pref_nids_attr {
	LNET_UDSP_INFO_PREF_NIDS_ATTR_UNSPEC = 0,

	LNET_UDSP_INFO_PREF_NIDS_ATTR_INDEX,
	LNET_UDSP_INFO_PREF_NIDS_ATTR_NID,
	__LNET_UDSP_INFO_PREF_NIDS_ATTR_MAX_PLUS_ONE,
};

#define LNET_UDSP_INFO_PREF_NIDS_ATTR_MAX (__LNET_UDSP_INFO_PREF_NIDS_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_cpt_of_nid_attr			- Attributes to support
 * 						  lnetctl cpt-of-nid command
 *
 * @LNET_CPT_OF_NID_ATTR_UNSPEC			  unspecified attribute to catch
 * 						  errors
 * @LNET_CPT_OF_NID_ATTR_HDR			  Grouping for cpt-of-nid
 * 						  (NLA_NUL_STRING)
 * @LNET_CPT_OF_NID_ATTR_NID			  The NID whose CPT we want to
 * 						  calculate (NLA_STRING)
 * LNET_CPT_OF_NID_ATTR_CPT			  The CPT for the specified NID
 * 						  (NLA_U32)
 */
enum lnet_cpt_of_nid_attr {
	LNET_CPT_OF_NID_ATTR_UNSPEC = 0,

	LNET_CPT_OF_NID_ATTR_HDR,
	LNET_CPT_OF_NID_ATTR_NID,
	LNET_CPT_OF_NID_ATTR_CPT,
	__LNET_CPT_OF_NID_ATTR_MAX_PLUS_ONE,
};

#define LNET_CPT_OF_NID_ATTR_MAX (__LNET_CPT_OF_NID_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_peer_dist_attr		      - Attributes to support
 *						reporting distance for peers
 *
 * @LNET_PEER_DIST_ATTR_UNSPEC			unspecified attribute to catch
 *						errors
 * @LNET_PEER_DIST_ATTR_HDR			Grouping which we just use peer
 *						(NLA_NUL_STRING)
 * @LNET_PEER_DIST_ATTR_NID			The NID we collect data for
 *						(NLA_STRING)
 * @LNET_PEER_DIST_ATTR_DIST			The distance for the specified
 *						NID (NLA_U32)
 * @LNET_PEER_DIST_ATTR_ORDER			The order for the specified NID
 *						(NLA_U32)
 */
enum lnet_peer_dist_attr {
	LNET_PEER_DIST_ATTR_UNSPEC = 0,

	LNET_PEER_DIST_ATTR_HDR,
	LNET_PEER_DIST_ATTR_NID,
	LNET_PEER_DIST_ATTR_DIST,
	LNET_PEER_DIST_ATTR_ORDER,
	__LNET_PEER_DIST_ATTR_MAX_PLUS_ONE,
};

#define LNET_PEER_DIST_ATTR_MAX (__LNET_PEER_DIST_ATTR_MAX_PLUS_ONE - 1)

/** enum lnet_debug_recovery_attr		Attributes to report contents of
 *						the LNet health recovery queues
 *
 * @LNET_DBG_RECOV_ATTR_UNSPEC			Unspecified attribute to catch
 *						errors
 * @LNET_DBG_RECOV_ATTR_HDR			Grouping for NI recovery queue
 *						(NLA_NUL_STRING)
 * @LNET_DBG_RECOV_ATTR_NID			A NID in one of the recovery
 *						queues (NLA_STRING)
 */
enum lnet_debug_recovery_attr {
	LNET_DBG_RECOV_ATTR_UNSPEC = 0,

	LNET_DBG_RECOV_ATTR_HDR,
	LNET_DBG_RECOV_ATTR_NID,
	__LNET_DBG_RECOV_ATTR_MAX_PLUS_ONE,
};

#define LNET_DBG_RECOV_ATTR_MAX (__LNET_DBG_RECOV_ATTR_MAX_PLUS_ONE - 1)


/** enum lnet_fault_rule_attr		Attributes to report LNet fault
 *					injection.
 *
 * @LNET_FAULT_ATTR_UNSPEC		Unspecified attribute to catch errors
 * @LNET_FAULT_ATTR_PAD			Pad attribute for 64b alignment
 *
 * @LNET_FAULT_ATTR_HDR			Grouping for "fault"
 * @LNET_FAULT_ATTR_FA_TYPE		The type of fault injection rule. i.e.
 *					either a "drop" rule or a "delay" rule.
 * @LNET_FAULT_ATTR_FA_SRC		For a description of this field, and
 *					the ones below, refer to
 *					struct lnet_fault_attr
 * @LNET_FAULT_ATTR_FA_DST
 * @LNET_FAULT_ATTR_FA_PTL_MASK
 * @LNET_FAULT_ATTR_FA_MSG_MASK
 * @LNET_FAULT_ATTR_DA_RATE
 * @LNET_FAULT_ATTR_DA_INTERVAL
 * @LNET_FAULT_ATTR_DS_DROPPED
 * @LNET_FAULT_ATTR_LA_RATE
 * @LNET_FAULT_ATTR_LA_INTERVAL
 * @LNET_FAULT_ATTR_LA_LATENCY
 * @LNET_FAULT_ATTR_LS_DELAYED
 * @LNET_FAULT_ATTR_FS_COUNT
 * @LNET_FAULT_ATTR_FS_PUT
 * @LNET_FAULT_ATTR_FS_ACK
 * @LNET_FAULT_ATTR_FS_GET
 * @LNET_FAULT_ATTR_FS_REPLY
 */
enum lnet_fault_rule_attr {
	LNET_FAULT_ATTR_UNSPEC = 0,
	LNET_FAULT_ATTR_PAD = LNET_FAULT_ATTR_UNSPEC,

	LNET_FAULT_ATTR_HDR,
	LNET_FAULT_ATTR_FA_TYPE,
	LNET_FAULT_ATTR_FA_SRC,
	LNET_FAULT_ATTR_FA_DST,
	LNET_FAULT_ATTR_FA_PTL_MASK,
	LNET_FAULT_ATTR_FA_MSG_MASK,
	LNET_FAULT_ATTR_DA_RATE,
	LNET_FAULT_ATTR_DA_INTERVAL,
	LNET_FAULT_ATTR_DS_DROPPED,
	LNET_FAULT_ATTR_LA_RATE,
	LNET_FAULT_ATTR_LA_INTERVAL,
	LNET_FAULT_ATTR_LA_LATENCY,
	LNET_FAULT_ATTR_LS_DELAYED,
	LNET_FAULT_ATTR_FS_COUNT,
	LNET_FAULT_ATTR_FS_PUT,
	LNET_FAULT_ATTR_FS_ACK,
	LNET_FAULT_ATTR_FS_GET,
	LNET_FAULT_ATTR_FS_REPLY,
	__LNET_FAULT_ATTR_MAX_PLUS_ONE,
};

#define LNET_FAULT_ATTR_MAX (__LNET_FAULT_ATTR_MAX_PLUS_ONE - 1)

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
	struct lnet_nid		ni_nid;

	/* instance-specific data */
	void			*ni_data;

	/* per ni credits */
	atomic_t		ni_tx_credits;

	/* percpt TX queues */
	struct lnet_tx_queue	**ni_tx_queues;

	/* percpt reference count */
	int			**ni_refs;

	/* pointer to parent network */
	struct lnet_net		*ni_net;

	/* my health status */
	u32			*ni_status;

	/* NI FSM. Protected by lnet_ni_lock() */
	enum lnet_ni_state	ni_state;

	/* Recovery state. Protected by lnet_ni_lock() */
	__u32			ni_recovery_state;

	/* When to send the next recovery ping */
	time64_t                ni_next_ping;
	/* How many pings sent during current recovery period did not receive
	 * a reply. NB: reset whenever _any_ message arrives on this NI
	 */
	unsigned int		ni_ping_count;

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

	/* the relative selection priority of this NI */
	__u32			ni_sel_priority;

	/*
	 * equivalent interface to use
	 */
	char			*ni_interface;
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
	int			pb_nbytes;	/* sizeof pb_info */
	struct kref		pb_refcnt;
	bool			pb_needs_post;
	struct lnet_ping_info	pb_info;
};

#define LNET_PING_BUFFER_SIZE(bytes) \
	(offsetof(struct lnet_ping_buffer, pb_info) + bytes)
#define LNET_PING_BUFFER_LONI(PBUF)	((PBUF)->pb_info.pi_ni[0].ns_nid)
#define LNET_PING_BUFFER_SEQNO(PBUF)	((PBUF)->pb_info.pi_ni[0].ns_status)

#define LNET_PING_INFO_TO_BUFFER(PINFO)	\
	container_of((PINFO), struct lnet_ping_buffer, pb_info)

static inline int
lnet_ping_sts_size(const struct lnet_nid *nid)
{
	int size;

	/* for deciding the size of the ping buffer */
	if (unlikely(LNET_NID_IS_ANY(nid)))
		return sizeof(struct lnet_ni_large_status);

	if (nid_is_nid4(nid))
		return sizeof(struct lnet_ni_status);

	size = offsetof(struct lnet_ni_large_status, ns_nid) +
	       NID_BYTES(nid);

	return round_up(size, 4);
}

static inline struct lnet_ni_large_status *
lnet_ping_sts_next(const struct lnet_ni_large_status *nis)
{
	return (void *)nis + lnet_ping_sts_size(&nis->ns_nid);
}

static inline bool
lnet_ping_at_least_two_entries(const struct lnet_ping_info *pi)
{
	/* Return true if we have at lease two entries.  There is always a
	 * least one, a 4-byte lo0 interface.
	 */
	struct lnet_ni_large_status *lns;

	if ((pi->pi_features & LNET_PING_FEAT_LARGE_ADDR) == 0)
		return pi->pi_nnis <= 2;
	/* There is at least 1 large-address entry */
	if (pi->pi_nnis != 1)
		return false;
	lns = (void *)&pi->pi_ni[1];
	lns = lnet_ping_sts_next(lns);

	return ((void *)pi + lnet_ping_info_size(pi) <= (void *)lns);
}

struct lnet_nid_list {
	struct list_head nl_list;
	struct lnet_nid nl_nid;
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
	/* pointer to peer net I'm part of */
	struct lnet_peer_net	*lpni_peer_net;
	/* statistics kept on each peer NI */
	struct lnet_element_stats lpni_stats;
	struct lnet_health_remote_stats lpni_hstats;
	/* spin lock protecting credits and lpni_txq */
	spinlock_t		lpni_lock;
	/* # tx credits available */
	int			lpni_txcredits;
	/* low water mark */
	int			lpni_mintxcredits;
	/*
	 * Each peer_ni in a gateway maintains its own credits. This
	 * allows more traffic to gateways that have multiple interfaces.
	 */
	/* # router credits */
	int			lpni_rtrcredits;
	/* low water mark */
	int			lpni_minrtrcredits;
	/* bytes queued for sending */
	long			lpni_txqnob;
	/* network peer is on */
	struct lnet_net		*lpni_net;
	/* peer's NID */
	struct lnet_nid		lpni_nid;
	/* # refs */
	struct kref		lpni_kref;
	/* health value for the peer */
	atomic_t		lpni_healthv;
	/* recovery ping mdh */
	struct lnet_handle_md	lpni_recovery_ping_mdh;
	/* When to send the next recovery ping */
	time64_t		lpni_next_ping;
	/* How many pings sent during current recovery period did not receive
	 * a reply. NB: reset whenever _any_ message arrives from this peer NI
	 */
	unsigned int		lpni_ping_count;
	/* CPT this peer attached on */
	int			lpni_cpt;
	/* state flags -- protected by lpni_lock */
	unsigned		lpni_state;
	/* status of the peer NI as reported by the peer */
	__u32			lpni_ns_status;
	/* sequence number used to round robin over peer nis within a net */
	__u32			lpni_seq;
	/* sequence number used to round robin over gateways */
	__u32			lpni_gw_seq;
	/* returned RC ping features. Protected with lpni_lock */
	unsigned int		lpni_ping_feats;
	/* time last message was received from the peer */
	time64_t		lpni_last_alive;
	/* preferred local nids: if only one, use lpni_pref.nid */
	union lpni_pref {
		struct lnet_nid nid;
		struct list_head nids;
	} lpni_pref;
	/* list of router nids preferred for this peer NI */
	struct list_head	lpni_rtr_pref_nids;
	/* The relative selection priority of this peer NI */
	__u32			lpni_sel_priority;
	/* number of preferred NIDs in lnpi_pref_nids */
	__u32			lpni_pref_nnids;
	/* Whether some thread is processing an lnet_notify() event for this
	 * peer NI
	 */
	bool			lpni_notifying;
	/* Timestamp of the last lnet_notify() event for this peer NI */
	time64_t		lpni_timestamp;
	/* Whether we've received an lnet_notify() event for this peer NI */
	bool			lpni_notified;
};

/* Preferred path added due to traffic on non-MR peer_ni */
#define LNET_PEER_NI_NON_MR_PREF	BIT(0)
/* peer is being recovered. */
#define LNET_PEER_NI_RECOVERY_PENDING	BIT(1)
/* recovery ping failed */
#define LNET_PEER_NI_RECOVERY_FAILED	BIT(2)
/* peer is being deleted */
#define LNET_PEER_NI_DELETING		BIT(3)

struct lnet_peer {
	/* chain on pt_peer_list */
	struct list_head	lp_peer_list;

	/* list of peer nets */
	struct list_head	lp_peer_nets;

	/* list of messages pending discovery*/
	struct list_head	lp_dc_pendq;

	/* chain on router list */
	struct list_head	lp_rtr_list;

	/* primary NID of the peer */
	struct lnet_nid		lp_primary_nid;

	/* source NID to use during discovery */
	struct lnet_nid		lp_disc_src_nid;
	/* destination NID to use during discovery */
	struct lnet_nid		lp_disc_dst_nid;

	/* net to perform discovery on */
	__u32			lp_disc_net_id;

	/* CPT of peer_table */
	int			lp_cpt;

	/* number of NIDs on this peer */
	int			lp_nnis;

	/* # refs from lnet_route::lr_gateway */
	int			lp_rtr_refcount;

	/*
	 * peer specific health sensitivity value to decrement peer nis in
	 * this peer with if set to something other than 0
	 */
	__u32			lp_health_sensitivity;

	/* messages blocking for router credits */
	struct list_head	lp_rtrq;

	/* routes on this peer */
	struct list_head	lp_routes;

	/* reference count */
	atomic_t		lp_refcount;

	/* lock protecting peer state flags and lpni_rtrq */
	spinlock_t		lp_lock;

	/* peer state flags */
	unsigned		lp_state;

	/* buffer for data pushed by peer */
	struct lnet_ping_buffer	*lp_data;

	/* MD handle for ping in progress */
	struct lnet_handle_md	lp_ping_mdh;

	/* MD handle for push in progress */
	struct lnet_handle_md	lp_push_mdh;

	/* number of bytes for sizing pb_info in push data */
	int			lp_data_bytes;

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

	/* cached peer aliveness */
	bool			lp_alive;

	/* sequence number used to round robin traffic to this peer's
	 * nets/NIs
	 */
	__u32                   lp_send_seq;

	/* timestamp of primary nid lock */
	__u64			lp_prim_lock_ts;

	/* merge and assign this NID as primary when discovery completes */
	struct lnet_nid         lp_merge_primary_nid;
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
 *
 * A peer is marked ROUTER if it indicates so in the feature bit.
 */
#define LNET_PEER_MULTI_RAIL		BIT(0)	/* Multi-rail aware */
#define LNET_PEER_NO_DISCOVERY		BIT(1)	/* Peer disabled discovery */
#define LNET_PEER_ROUTER_ENABLED	BIT(2)	/* router feature enabled */

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
#define LNET_PEER_CONFIGURED		BIT(3)	/* Configured via DLC */
#define LNET_PEER_DISCOVERED		BIT(4)	/* Peer was discovered */
#define LNET_PEER_REDISCOVER		BIT(5)	/* Discovery was disabled */
/*
 * A peer is marked DISCOVERING when discovery is in progress.
 * The other flags below correspond to stages of discovery.
 */
#define LNET_PEER_DISCOVERING		BIT(6)	/* Discovering */
#define LNET_PEER_DATA_PRESENT		BIT(7)	/* Remote peer data present */
#define LNET_PEER_NIDS_UPTODATE		BIT(8)	/* Remote peer info uptodate */
#define LNET_PEER_PING_SENT		BIT(9)	/* Waiting for REPLY to Ping */
#define LNET_PEER_PUSH_SENT		BIT(10)	/* Waiting for ACK of Push */
#define LNET_PEER_PING_FAILED		BIT(11)	/* Ping send failure */
#define LNET_PEER_PUSH_FAILED		BIT(12)	/* Push send failure */
/*
 * A ping can be forced as a way to fix up state, or as a manual
 * intervention by an admin.
 * A push can be forced in circumstances that would normally not
 * allow for one to happen.
 */
#define LNET_PEER_FORCE_PING		BIT(13)	/* Forced Ping */
#define LNET_PEER_FORCE_PUSH		BIT(14)	/* Forced Push */

/* force delete even if router */
#define LNET_PEER_RTR_NI_FORCE_DEL	BIT(15)

/* gw undergoing alive discovery */
#define LNET_PEER_RTR_DISCOVERY		BIT(16)
/* gw has undergone discovery (does not indicate success or failure) */
#define LNET_PEER_RTR_DISCOVERED	BIT(17)

/* peer is marked for deletion */
#define LNET_PEER_MARK_DELETION		BIT(18)
/* lnet_peer_del()/lnet_peer_del_locked() has been called on the peer */
#define LNET_PEER_MARK_DELETED		BIT(19)
/* lock primary NID to what's requested by ULP */
#define LNET_PEER_LOCK_PRIMARY		BIT(20)
/* this is for informational purposes only. It is set if a peer gets
 * configured from Lustre with a primary NID which belongs to another peer
 * which is also configured by Lustre as the primary NID.
 */
#define LNET_PEER_BAD_CONFIG		BIT(21)

struct lnet_peer_net {
	/* chain on lp_peer_nets */
	struct list_head	lpn_peer_nets;

	/* list of peer_nis on this network */
	struct list_head	lpn_peer_nis;

	/* pointer to the peer I'm part of */
	struct lnet_peer	*lpn_peer;

	/* Net ID */
	__u32			lpn_net_id;

	/* peer net health */
	int			lpn_healthv;

	/* time of next router ping on this net */
	time64_t		lpn_next_ping;

	/* selection sequence number */
	__u32			lpn_seq;

	/* relative peer net selection priority */
	__u32			lpn_sel_priority;

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
	struct lnet_peer	*lr_gateway;	/* router node */
	struct lnet_nid		lr_nid;		/* NID used to add route */
	__u32			lr_net;		/* remote network number */
	__u32			lr_lnet;	/* local network number */
	int			lr_seq;		/* sequence for round-robin */
	__u32			lr_hops;	/* how far I am */
	unsigned int		lr_priority;	/* route priority */
	atomic_t		lr_alive;	/* cached route aliveness */
	bool			lr_single_hop;  /* this route is single-hop */
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
	struct bio_vec		 rb_kiov[];	/* the buffer space */
};

#define LNET_PEER_HASHSIZE   503		/* prime! */

enum lnet_match_flags {
	/* Didn't match anything */
	LNET_MATCHMD_NONE	= BIT(0),
	/* Matched OK */
	LNET_MATCHMD_OK		= BIT(1),
	/* Must be discarded */
	LNET_MATCHMD_DROP	= BIT(2),
	/* match and buffer is exhausted */
	LNET_MATCHMD_EXHAUSTED	= BIT(3),
	/* match or drop */
	LNET_MATCHMD_FINISH	= (LNET_MATCHMD_OK | LNET_MATCHMD_DROP),
};

/* Options for struct lnet_portal::ptl_options */
#define LNET_PTL_LAZY		BIT(0)
#define LNET_PTL_MATCH_UNIQUE	BIT(1)	/* unique match, for RDMA */
#define LNET_PTL_MATCH_WILDCARD	BIT(2)	/* wildcard match, request portal */

/* parameter for matching operations (GET, PUT) */
struct lnet_match_info {
	__u64			mi_mbits;
	struct lnet_processid	mi_id;
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
	int			ptl_mt_maps[];
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

/* This UDSP structures need to match the user space liblnetconfig structures
 * in order for the marshall and unmarshall functions to be common.
 */

/* Net is described as a
 *  1. net type
 *  2. num range
 */
struct lnet_ud_net_descr {
	__u32 udn_net_type;
	struct list_head udn_net_num_range;
};

/* each NID range is defined as
 *  1. net descriptor
 *  2. address range descriptor
 */
struct lnet_ud_nid_descr {
	struct lnet_ud_net_descr ud_net_id;
	struct list_head ud_addr_range;
	__u32 ud_mem_size;
};

/* a UDSP rule can have up to three user defined NID descriptors
 *	- src: defines the local NID range for the rule
 *	- dst: defines the peer NID range for the rule
 *	- rte: defines the router NID range for the rule
 *
 * An action union defines the action to take when the rule
 * is matched
 */
struct lnet_udsp {
	struct list_head udsp_on_list;
	__u32 udsp_idx;
	struct lnet_ud_nid_descr udsp_src;
	struct lnet_ud_nid_descr udsp_dst;
	struct lnet_ud_nid_descr udsp_rte;
	enum lnet_udsp_action_type udsp_action_type;
	union {
		__u32 udsp_priority;
	} udsp_action;
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

struct nid_update_info {
	GENRADIX(struct lnet_nid) nui_rdx;
	unsigned int		  nui_count;
	__u32			  nui_net;
};

struct nid_update_callback_reg {
	struct list_head nur_list;
	int (*nur_cb)(void *private, struct nid_update_info *nui);
	void *nur_data;
};

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
	/* percpt MD container */
	struct lnet_res_container	**ln_md_containers;

	/* Event Queue container */
	struct lnet_res_container	ln_eq_container;
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
	/* Sequence number used to round robin sends across all nets */
	__u32				ln_net_seq;
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
	lnet_handler_t			ln_ping_target_handler;
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
	lnet_handler_t			ln_push_target_handler;
	struct lnet_handle_md		ln_push_target_md;
	struct lnet_ping_buffer		*ln_push_target;
	/* bytes needed for pb_info to receive push */
	int				ln_push_target_nbytes;

	/* discovery event queue handle */
	lnet_handler_t			ln_dc_handler;
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
	const struct lnet_lnd		*ln_lnds[NUM_LNDS];

	/* test protocol compatibility flags */
	unsigned long			ln_testprotocompat;

	/* 0 - load the NIs from the mod params
	 * 1 - do not load the NIs from the mod params
	 * Reverse logic to ensure that other calls to LNetNIInit
	 * need no change
	 */
	bool				ln_nis_from_mod_params;

	/* Switch to test large NIDs */
	bool				ln_nis_use_large_nids;

	/*
	 * completion for the monitor thread. The monitor thread takes care of
	 * checking routes, timedout messages and resending messages.
	 */
	struct completion		ln_mt_wait_complete;

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
	/* recovery handler */
	lnet_handler_t			ln_mt_handler;

	/*
	 * Completed when the discovery and monitor threads can enter their
	 * work loops
	 */
	struct completion		ln_started;
	/* UDSP list */
	struct list_head		ln_udsp_list;

	struct list_head		ln_nid_update_callbacks;

	/* Number of messages that have exceeded their message deadline */
	atomic_t			ln_late_msg_count;
	/* Total amount of time past their deadline for all late ^ messages */
	atomic64_t			ln_late_msg_nsecs;

	/* for LNDs to signal that ping buffer needs updating */
	atomic_t                        ln_update_ping_buf;

	/* workqueue for serving lnd ping buffer update requests */
	struct workqueue_struct		*ln_pb_update_wq;
	struct work_struct		ln_pb_update_work;

	atomic_t                        ln_pb_update_ready;
};

static const struct nla_policy scalar_attr_policy[LN_SCALAR_MAX + 1] = {
	[LN_SCALAR_ATTR_LIST]		= { .type = NLA_NESTED },
	[LN_SCALAR_ATTR_LIST_SIZE]	= { .type = NLA_U16 },
	[LN_SCALAR_ATTR_INDEX]		= { .type = NLA_U16 },
	[LN_SCALAR_ATTR_NLA_TYPE]	= { .type = NLA_U16 },
	[LN_SCALAR_ATTR_VALUE]		= { .type = NLA_STRING },
	[LN_SCALAR_ATTR_KEY_FORMAT]	= { .type = NLA_U16 },
};

int lnet_genl_send_scalar_list(struct sk_buff *msg, u32 portid, u32 seq,
			       const struct genl_family *family, int flags,
			       u8 cmd, const struct ln_key_list *data[]);

/* Special workaround for pre-4.19 kernels to send error messages
 * from dumpit routines. Newer kernels will send message with
 * NL_SET_ERR_MSG information by default if NETLINK_EXT_ACK is set.
 */
static inline int lnet_nl_send_error(struct sk_buff *msg, int portid, int seq,
				     int error)
{
#ifndef HAVE_NL_DUMP_WITH_EXT_ACK
	struct nlmsghdr *nlh;

	if (!error)
		return 0;

	nlh = nlmsg_put(msg, portid, seq, NLMSG_ERROR, sizeof(error), 0);
	if (!nlh)
		return -ENOMEM;
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	netlink_ack(msg, nlh, error, NULL);
#else
	netlink_ack(msg, nlh, error);
#endif
	return nlmsg_len(nlh);
#else
	return error;
#endif
}

#endif
