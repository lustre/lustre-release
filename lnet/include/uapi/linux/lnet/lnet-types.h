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
 */

#ifndef __UAPI_LNET_TYPES_H__
#define __UAPI_LNET_TYPES_H__

/** \addtogroup lnet
 * @{ */

#include <linux/types.h>
/** \addtogroup lnet_addr
 * @{ */

#define LNET_VERSION		"0.7.0"

/** Portal reserved for LNet's own use.
 * \see lustre/include/lustre/lustre_idl.h for Lustre portal assignments.
 */
#define LNET_RESERVED_PORTAL	  0

/**
 * Address of an end-point in an LNet network.
 *
 * A node can have multiple end-points and hence multiple addresses.
 * An LNet network can be a simple network (e.g. tcp0) or a network of
 * LNet networks connected by LNet routers. Therefore an end-point address
 * has two parts: network ID, and address within a network.
 *
 * \see LNET_NIDNET, LNET_NIDADDR, and LNET_MKNID.
 */
typedef __u64 lnet_nid_t;

/**
 * ID of a process in a node. Shortened as PID to distinguish from
 * lnet_process_id, the global process ID.
 */
typedef __u32 lnet_pid_t;

/** wildcard NID that matches any end-point address */
#define LNET_NID_ANY	  ((lnet_nid_t) -1)
/** wildcard PID that matches any lnet_pid_t */
#define LNET_PID_ANY	  ((lnet_pid_t) -1)

#define LNET_PID_RESERVED 0xf0000000 /* reserved bits in PID */
#define LNET_PID_USERFLAG 0x80000000 /* set in userspace peers */
#define LNET_PID_LUSTRE 12345

/* how an LNET NID encodes net:address */
/** extract the address part of an lnet_nid_t */

static inline __u32 LNET_NIDADDR(lnet_nid_t nid)
{
	return nid & 0xffffffff;
}

static inline __u32 LNET_NIDNET(lnet_nid_t nid)
{
	return (nid >> 32) & 0xffffffff;
}

static inline lnet_nid_t LNET_MKNID(__u32 net, __u32 addr)
{
	return (((__u64)net) << 32) | addr;
}

static inline __u32 LNET_NETNUM(__u32 net)
{
	return net & 0xffff;
}

static inline __u32 LNET_NETTYP(__u32 net)
{
	return (net >> 16) & 0xffff;
}

static inline __u32 LNET_MKNET(__u32 type, __u32 num)
{
	return (type << 16) | num;
}

/** The lolnd NID (i.e. myself) */
#define LNET_NID_LO_0 LNET_MKNID(LNET_MKNET(LOLND, 0), 0)

#define WIRE_ATTR	__attribute__((packed))

/* Packed version of struct lnet_process_id to transfer via network */
struct lnet_process_id_packed {
	lnet_nid_t nid;
	lnet_pid_t pid;	/* node id / process id */
} WIRE_ATTR;

/* The wire handle's interface cookie only matches one network interface in
 * one epoch (i.e. new cookie when the interface restarts or the node
 * reboots).  The object cookie only matches one object on that interface
 * during that object's lifetime (i.e. no cookie re-use). */
struct lnet_handle_wire {
	__u64 wh_interface_cookie;
	__u64 wh_object_cookie;
} WIRE_ATTR;

enum lnet_msg_type {
	LNET_MSG_ACK = 0,
	LNET_MSG_PUT,
	LNET_MSG_GET,
	LNET_MSG_REPLY,
	LNET_MSG_HELLO,
};

/* The variant fields of the portals message header are aligned on an 8
 * byte boundary in the message header.  Note that all types used in these
 * wire structs MUST be fixed size and the smaller types are placed at the
 * end. */
struct lnet_ack {
	struct lnet_handle_wire	dst_wmd;
	__u64			match_bits;
	__u32			mlength;
} WIRE_ATTR;

struct lnet_put {
	struct lnet_handle_wire	ack_wmd;
	__u64			match_bits;
	__u64			hdr_data;
	__u32			ptl_index;
	__u32			offset;
} WIRE_ATTR;

struct lnet_get {
	struct lnet_handle_wire	return_wmd;
	__u64			match_bits;
	__u32			ptl_index;
	__u32			src_offset;
	__u32			sink_length;
} WIRE_ATTR;

struct lnet_reply {
	struct lnet_handle_wire	dst_wmd;
} WIRE_ATTR;

struct lnet_hello {
	__u64			incarnation;
	__u32			type;
} WIRE_ATTR;

struct lnet_hdr {
	lnet_nid_t	dest_nid;
	lnet_nid_t	src_nid;
	lnet_pid_t	dest_pid;
	lnet_pid_t	src_pid;
	__u32		type;		/* enum lnet_msg_type */
	__u32		payload_length;	/* payload data to follow */
	/*<------__u64 aligned------->*/
	union {
		struct lnet_ack		ack;
		struct lnet_put		put;
		struct lnet_get		get;
		struct lnet_reply	reply;
		struct lnet_hello	hello;
	} msg;
} WIRE_ATTR;

/* A HELLO message contains a magic number and protocol version
 * code in the header's dest_nid, the peer's NID in the src_nid, and
 * LNET_MSG_HELLO in the type field.  All other common fields are zero
 * (including payload_size; i.e. no payload).
 * This is for use by byte-stream LNDs (e.g. TCP/IP) to check the peer is
 * running the same protocol and to find out its NID. These LNDs should
 * exchange HELLO messages when a connection is first established.  Individual
 * LNDs can put whatever else they fancy in lnet_hdr::msg.
 */
struct lnet_magicversion {
	__u32	magic;		/* LNET_PROTO_TCP_MAGIC */
	__u16	version_major;	/* increment on incompatible change */
	__u16	version_minor;	/* increment on compatible change */
} WIRE_ATTR;

/* PROTO MAGIC for LNDs */
#define LNET_PROTO_IB_MAGIC		0x0be91b91
#define LNET_PROTO_GNI_MAGIC		0xb00fbabe /* ask Kim */
#define LNET_PROTO_TCP_MAGIC		0xeebc0ded
#define LNET_PROTO_ACCEPTOR_MAGIC	0xacce7100
#define LNET_PROTO_PING_MAGIC		0x70696E67 /* 'ping' */

/* Placeholder for a future "unified" protocol across all LNDs */
/* Current LNDs that receive a request with this magic will respond
 * with a "stub" reply using their current protocol */
#define LNET_PROTO_MAGIC		0x45726963 /* ! */

#define LNET_PROTO_TCP_VERSION_MAJOR	1
#define LNET_PROTO_TCP_VERSION_MINOR	0

/* Acceptor connection request */
struct lnet_acceptor_connreq {
	__u32	acr_magic;	/* PTL_ACCEPTOR_PROTO_MAGIC */
	__u32	acr_version;	/* protocol version */
	__u64	acr_nid;	/* target NID */
} WIRE_ATTR;

#define LNET_PROTO_ACCEPTOR_VERSION	1

struct lnet_counters_common {
	__u32	lcc_msgs_alloc;
	__u32	lcc_msgs_max;
	__u32	lcc_errors;
	__u32	lcc_send_count;
	__u32	lcc_recv_count;
	__u32	lcc_route_count;
	__u32	lcc_drop_count;
	__u64	lcc_send_length;
	__u64	lcc_recv_length;
	__u64	lcc_route_length;
	__u64	lcc_drop_length;
} WIRE_ATTR;

struct lnet_counters_health {
	__u32	lch_rst_alloc;
	__u32	lch_resend_count;
	__u32	lch_response_timeout_count;
	__u32	lch_local_interrupt_count;
	__u32	lch_local_dropped_count;
	__u32	lch_local_aborted_count;
	__u32	lch_local_no_route_count;
	__u32	lch_local_timeout_count;
	__u32	lch_local_error_count;
	__u32	lch_remote_dropped_count;
	__u32	lch_remote_error_count;
	__u32	lch_remote_timeout_count;
	__u32	lch_network_timeout_count;
};

struct lnet_counters {
	struct lnet_counters_common lct_common;
	struct lnet_counters_health lct_health;
};

#define LNET_NI_STATUS_UP	0x15aac0de
#define LNET_NI_STATUS_DOWN	0xdeadface
#define LNET_NI_STATUS_INVALID	0x00000000

struct lnet_ni_status {
	lnet_nid_t ns_nid;
	__u32      ns_status;
	__u32      ns_unused;
} WIRE_ATTR;

/*
 * NB: value of these features equal to LNET_PROTO_PING_VERSION_x
 * of old LNet, so there shouldn't be any compatibility issue
 */
#define LNET_PING_FEAT_INVAL		(0)		/* no feature */
#define LNET_PING_FEAT_BASE		(1 << 0)	/* just a ping */
#define LNET_PING_FEAT_NI_STATUS	(1 << 1)	/* return NI status */
#define LNET_PING_FEAT_RTE_DISABLED	(1 << 2)        /* Routing enabled */
#define LNET_PING_FEAT_MULTI_RAIL	(1 << 3)        /* Multi-Rail aware */
#define LNET_PING_FEAT_DISCOVERY	(1 << 4)	/* Supports Discovery */

/*
 * All ping feature bits fit to hit the wire.
 * In lnet_assert_wire_constants() this is compared against its open-coded
 * value, and in lnet_ping_target_update() it is used to verify that no
 * unknown bits have been set.
 * New feature bits can be added, just be aware that this does change the
 * over-the-wire protocol.
 */
#define LNET_PING_FEAT_BITS		(LNET_PING_FEAT_BASE | \
					 LNET_PING_FEAT_NI_STATUS | \
					 LNET_PING_FEAT_RTE_DISABLED | \
					 LNET_PING_FEAT_MULTI_RAIL | \
					 LNET_PING_FEAT_DISCOVERY)

struct lnet_ping_info {
	__u32			pi_magic;
	__u32			pi_features;
	lnet_pid_t		pi_pid;
	__u32			pi_nnis;
	struct lnet_ni_status	pi_ni[0];
} WIRE_ATTR;

#define LNET_PING_INFO_SIZE(NNIDS) \
	offsetof(struct lnet_ping_info, pi_ni[NNIDS])
#define LNET_PING_INFO_LONI(PINFO)	((PINFO)->pi_ni[0].ns_nid)
#define LNET_PING_INFO_SEQNO(PINFO)	((PINFO)->pi_ni[0].ns_status)

/*
 * This is a hard-coded limit on the number of interfaces supported by
 * the interface bonding implemented by the ksocknal LND. It must be
 * defined here because it is used in LNet data structures that are
 * common to all LNDs.
 */
#define LNET_INTERFACES_NUM	16

/* The minimum number of interfaces per node supported by LNet. */
#define LNET_INTERFACES_MIN	16
/* The default - arbitrary - value of the lnet_max_interfaces tunable. */
#define LNET_INTERFACES_MAX_DEFAULT	200

/**
 * Objects maintained by the LNet are accessed through handles. Handle types
 * have names of the form lnet_handle_xx, where xx is one of the two letter
 * object type codes ('eq' for event queue, 'md' for memory descriptor, and
 * 'me' for match entry). Each type of object is given a unique handle type
 * to enhance type checking.
 */
#define LNET_WIRE_HANDLE_COOKIE_NONE   (-1)

struct lnet_handle_eq {
	__u64	cookie;
};

/**
 * Invalidate eq handle \a h.
 */
static inline void LNetInvalidateEQHandle(struct lnet_handle_eq *h)
{
	h->cookie = LNET_WIRE_HANDLE_COOKIE_NONE;
}

/**
 * Check whether eq handle \a h is invalid.
 *
 * \return 1 if handle is invalid, 0 if valid.
 */
static inline int LNetEQHandleIsInvalid(struct lnet_handle_eq h)
{
	return (LNET_WIRE_HANDLE_COOKIE_NONE == h.cookie);
}

struct lnet_handle_md {
	__u64	cookie;
};

/**
 * Invalidate md handle \a h.
 */
static inline void LNetInvalidateMDHandle(struct lnet_handle_md *h)
{
	h->cookie = LNET_WIRE_HANDLE_COOKIE_NONE;
}

/**
 * Check whether eq handle \a h is invalid.
 *
 * \return 1 if handle is invalid, 0 if valid.
 */
static inline int LNetMDHandleIsInvalid(struct lnet_handle_md h)
{
	return (LNET_WIRE_HANDLE_COOKIE_NONE == h.cookie);
}

struct lnet_handle_me {
	__u64	cookie;
};

/**
 * Global process ID.
 */
struct lnet_process_id {
	/** node id */
	lnet_nid_t nid;
	/** process id */
	lnet_pid_t pid;
};
/** @} lnet_addr */

/** \addtogroup lnet_me
 * @{ */

/**
 * Specifies whether the match entry or memory descriptor should be unlinked
 * automatically (LNET_UNLINK) or not (LNET_RETAIN).
 */
enum lnet_unlink {
	LNET_RETAIN = 0,
	LNET_UNLINK
};

/**
 * Values of the type enum lnet_ins_pos are used to control where a new match
 * entry is inserted. The value LNET_INS_BEFORE is used to insert the new
 * entry before the current entry or before the head of the list. The value
 * LNET_INS_AFTER is used to insert the new entry after the current entry
 * or after the last item in the list.
 */
enum lnet_ins_pos {
	/** insert ME before current position or head of the list */
	LNET_INS_BEFORE,
	/** insert ME after current position or tail of the list */
	LNET_INS_AFTER,
	/** attach ME at tail of local CPU partition ME list */
	LNET_INS_LOCAL
};

/** @} lnet_me */

/** \addtogroup lnet_md
 * @{ */

/**
 * Defines the visible parts of a memory descriptor. Values of this type
 * are used to initialize memory descriptors.
 */
struct lnet_md {
	/**
	 * Specify the memory region associated with the memory descriptor.
	 * If the options field has:
	 * - LNET_MD_KIOV bit set: The start field points to the starting
	 * address of an array of lnet_kiov_t and the length field specifies
	 * the number of entries in the array. The length can't be bigger
	 * than LNET_MAX_IOV. The lnet_kiov_t is used to describe page-based
	 * fragments that are not necessarily mapped in virtal memory.
	 * - LNET_MD_IOVEC bit set: The start field points to the starting
	 * address of an array of struct kvec and the length field specifies
	 * the number of entries in the array. The length can't be bigger
	 * than LNET_MAX_IOV. The struct kvec is used to describe fragments
	 * that have virtual addresses.
	 * - Otherwise: The memory region is contiguous. The start field
	 * specifies the starting address for the memory region and the
	 * length field specifies its length.
	 *
	 * When the memory region is fragmented, all fragments but the first
	 * one must start on page boundary, and all but the last must end on
	 * page boundary.
	 */
	void		*start;
	unsigned int	 length;
	/**
	 * Specifies the maximum number of operations that can be performed
	 * on the memory descriptor. An operation is any action that could
	 * possibly generate an event. In the usual case, the threshold value
	 * is decremented for each operation on the MD. When the threshold
	 * drops to zero, the MD becomes inactive and does not respond to
	 * operations. A threshold value of LNET_MD_THRESH_INF indicates that
	 * there is no bound on the number of operations that may be applied
	 * to a MD.
	 */
	int		 threshold;
	/**
	 * Specifies the largest incoming request that the memory descriptor
	 * should respond to. When the unused portion of a MD (length -
	 * local offset) falls below this value, the MD becomes inactive and
	 * does not respond to further operations. This value is only used
	 * if the LNET_MD_MAX_SIZE option is set.
	 */
	int		 max_size;
	/**
	 * Specifies the behavior of the memory descriptor. A bitwise OR
	 * of the following values can be used:
	 * - LNET_MD_OP_PUT: The LNet PUT operation is allowed on this MD.
	 * - LNET_MD_OP_GET: The LNet GET operation is allowed on this MD.
	 * - LNET_MD_MANAGE_REMOTE: The offset used in accessing the memory
	 *   region is provided by the incoming request. By default, the
	 *   offset is maintained locally. When maintained locally, the
	 *   offset is incremented by the length of the request so that
	 *   the next operation (PUT or GET) will access the next part of
	 *   the memory region. Note that only one offset variable exists
	 *   per memory descriptor. If both PUT and GET operations are
	 *   performed on a memory descriptor, the offset is updated each time.
	 * - LNET_MD_TRUNCATE: The length provided in the incoming request can
	 *   be reduced to match the memory available in the region (determined
	 *   by subtracting the offset from the length of the memory region).
	 *   By default, if the length in the incoming operation is greater
	 *   than the amount of memory available, the operation is rejected.
	 * - LNET_MD_ACK_DISABLE: An acknowledgment should not be sent for
	 *   incoming PUT operations, even if requested. By default,
	 *   acknowledgments are sent for PUT operations that request an
	 *   acknowledgment. Acknowledgments are never sent for GET operations.
	 *   The data sent in the REPLY serves as an implicit acknowledgment.
	 * - LNET_MD_KIOV: The start and length fields specify an array of
	 *   lnet_kiov_t.
	 * - LNET_MD_IOVEC: The start and length fields specify an array of
	 *   struct iovec.
	 * - LNET_MD_MAX_SIZE: The max_size field is valid.
	 * - LNET_MD_BULK_HANDLE: The bulk_handle field is valid.
	 *
	 * Note:
	 * - LNET_MD_KIOV or LNET_MD_IOVEC allows for a scatter/gather
	 *   capability for memory descriptors. They can't be both set.
	 * - When LNET_MD_MAX_SIZE is set, the total length of the memory
	 *   region (i.e. sum of all fragment lengths) must not be less than
	 *   \a max_size.
	 */
	unsigned int	 options;
	/**
	 * A user-specified value that is associated with the memory
	 * descriptor. The value does not need to be a pointer, but must fit
	 * in the space used by a pointer. This value is recorded in events
	 * associated with operations on this MD.
	 */
	void		*user_ptr;
	/**
	 * A handle for the event queue used to log the operations performed on
	 * the memory region. If this argument is a NULL handle (i.e. nullified
	 * by LNetInvalidateHandle()), operations performed on this memory
	 * descriptor are not logged.
	 */
	struct lnet_handle_eq eq_handle;
	/**
	 * The bulk MD handle which was registered to describe the buffers
	 * either to be used to transfer data to the peer or receive data
	 * from the peer. This allows LNet to properly determine the NUMA
	 * node on which the memory was allocated and use that to select the
	 * nearest local network interface. This value is only used
	 * if the LNET_MD_BULK_HANDLE option is set.
	 */
	struct lnet_handle_md bulk_handle;
};

/* Max Transfer Unit (minimum supported everywhere).
 * CAVEAT EMPTOR, with multinet (i.e. routers forwarding between networks)
 * these limits are system wide and not interface-local. */
#define LNET_MTU_BITS	20
#define LNET_MTU	(1 << LNET_MTU_BITS)

/**
 * Options for the MD structure. See struct lnet_md::options.
 */
#define LNET_MD_OP_PUT		     (1 << 0)
/** See struct lnet_md::options. */
#define LNET_MD_OP_GET		     (1 << 1)
/** See struct lnet_md::options. */
#define LNET_MD_MANAGE_REMOTE	     (1 << 2)
/* unused			     (1 << 3) */
/** See struct lnet_md::options. */
#define LNET_MD_TRUNCATE	     (1 << 4)
/** See struct lnet_md::options. */
#define LNET_MD_ACK_DISABLE	     (1 << 5)
/** See struct lnet_md::options. */
#define LNET_MD_IOVEC		     (1 << 6)
/** See struct lnet_md::options. */
#define LNET_MD_MAX_SIZE	     (1 << 7)
/** See struct lnet_md::options. */
#define LNET_MD_KIOV		     (1 << 8)
/** See struct lnet_md::options. */
#define LNET_MD_BULK_HANDLE	     (1 << 9)

/* For compatibility with Cray Portals */
#define LNET_MD_PHYS			     0

/** Infinite threshold on MD operations. See struct lnet_md::threshold */
#define LNET_MD_THRESH_INF	 (-1)

/**
 * A page-based fragment of a MD.
 */
typedef struct {
	/** Pointer to the page where the fragment resides */
	struct page	 *kiov_page;
	/** Length in bytes of the fragment */
	unsigned int	 kiov_len;
	/**
	 * Starting offset of the fragment within the page. Note that the
	 * end of the fragment must not pass the end of the page; i.e.,
	 * kiov_len + kiov_offset <= PAGE_SIZE.
	 */
	unsigned int	 kiov_offset;
} lnet_kiov_t;
/** @} lnet_md */

/** \addtogroup lnet_eq
 * @{ */

/**
 * Six types of events can be logged in an event queue.
 */
enum lnet_event_kind {
	/** An incoming GET operation has completed on the MD. */
	LNET_EVENT_GET		= 1,
	/**
	 * An incoming PUT operation has completed on the MD. The
	 * underlying layers will not alter the memory (on behalf of this
	 * operation) once this event has been logged.
	 */
	LNET_EVENT_PUT,
	/**
	 * A REPLY operation has completed. This event is logged after the
	 * data (if any) from the REPLY has been written into the MD.
	 */
	LNET_EVENT_REPLY,
	/** An acknowledgment has been received. */
	LNET_EVENT_ACK,
	/**
	 * An outgoing send (PUT or GET) operation has completed. This event
	 * is logged after the entire buffer has been sent and it is safe for
	 * the caller to reuse the buffer.
	 *
	 * Note:
	 * - The LNET_EVENT_SEND doesn't guarantee message delivery. It can
	 *   happen even when the message has not yet been put out on wire.
	 * - It's unsafe to assume that in an outgoing GET operation
	 *   the LNET_EVENT_SEND event would happen before the
	 *   LNET_EVENT_REPLY event. The same holds for LNET_EVENT_SEND and
	 *   LNET_EVENT_ACK events in an outgoing PUT operation.
	 */
	LNET_EVENT_SEND,
	/**
	 * A MD has been unlinked. Note that LNetMDUnlink() does not
	 * necessarily trigger an LNET_EVENT_UNLINK event.
	 * \see LNetMDUnlink
	 */
	LNET_EVENT_UNLINK,
};

#define LNET_SEQ_GT(a, b)	(((signed long)((a) - (b))) > 0)

/**
 * Information about an event on a MD.
 */
struct lnet_event {
	/** The identifier (nid, pid) of the target. */
	struct lnet_process_id   target;
	/** The identifier (nid, pid) of the initiator. */
	struct lnet_process_id   initiator;
	/** The source NID on the initiator. */
	struct lnet_process_id   source;
	/**
	 * The NID of the immediate sender. If the request has been forwarded
	 * by routers, this is the NID of the last hop; otherwise it's the
	 * same as the source.
	 */
	lnet_nid_t          sender;
	/** Indicates the type of the event. */
	enum lnet_event_kind	type;
	/** The portal table index specified in the request */
	unsigned int        pt_index;
	/** A copy of the match bits specified in the request. */
	__u64               match_bits;
	/** The length (in bytes) specified in the request. */
	unsigned int        rlength;
	/**
	 * The length (in bytes) of the data that was manipulated by the
	 * operation. For truncated operations, the manipulated length will be
	 * the number of bytes specified by the MD (possibly with an offset,
	 * see struct lnet_md). For all other operations, the manipulated length
	 * will be the length of the requested operation, i.e. rlength.
	 */
	unsigned int        mlength;
	/**
	 * The handle to the MD associated with the event. The handle may be
	 * invalid if the MD has been unlinked.
	 */
	struct lnet_handle_md	md_handle;
	/**
	 * A snapshot of the state of the MD immediately after the event has
	 * been processed. In particular, the threshold field in md will
	 * reflect the value of the threshold after the operation occurred.
	 */
	struct lnet_md           md;
	/**
	 * 64 bits of out-of-band user data. Only valid for LNET_EVENT_PUT.
	 * \see LNetPut
	 */
	__u64               hdr_data;
	/**
	 * The message type, to ensure a handler for LNET_EVENT_SEND can
	 * distinguish between LNET_MSG_GET and LNET_MSG_PUT.
	 */
	__u32               msg_type;
	/**
	 * Indicates the completion status of the operation. It's 0 for
	 * successful operations, otherwise it's an error code.
	 */
	int                 status;
	/**
	 * Indicates whether the MD has been unlinked. Note that:
	 * - An event with unlinked set is the last event on the MD.
	 * - This field is also set for an explicit LNET_EVENT_UNLINK event.
	 * \see LNetMDUnlink
	 */
	int                 unlinked;
	/**
	 * The displacement (in bytes) into the memory region that the
	 * operation used. The offset can be determined by the operation for
	 * a remote managed MD or by the local MD.
	 * \see struct lnet_md::options
	 */
	unsigned int        offset;
	/**
	 * The sequence number for this event. Sequence numbers are unique
	 * to each event.
	 */
	volatile unsigned long sequence;
};

/**
 * Event queue handler function type.
 *
 * The EQ handler runs for each event that is deposited into the EQ. The
 * handler is supplied with a pointer to the event that triggered the
 * handler invocation.
 *
 * The handler must not block, must be reentrant, and must not call any LNet
 * API functions. It should return as quickly as possible.
 */
typedef void (*lnet_eq_handler_t)(struct lnet_event *event);
#define LNET_EQ_HANDLER_NONE NULL
/** @} lnet_eq */

/** \addtogroup lnet_data
 * @{ */

/**
 * Specify whether an acknowledgment should be sent by target when the PUT
 * operation completes (i.e., when the data has been written to a MD of the
 * target process).
 *
 * \see struct lnet_md::options for the discussion on LNET_MD_ACK_DISABLE
 * by which acknowledgments can be disabled for a MD.
 */
enum lnet_ack_req {
	/** Request an acknowledgment */
	LNET_ACK_REQ,
	/** Request that no acknowledgment should be generated. */
	LNET_NOACK_REQ
};
/** @} lnet_data */

/** @} lnet */
#endif
