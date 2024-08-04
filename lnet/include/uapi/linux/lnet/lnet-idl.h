/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __UAPI_LNET_IDL_H__
#define __UAPI_LNET_IDL_H__

#include <linux/types.h>

/************************************************************************
 * Core LNet wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 */

/** Address of an end-point in an LNet network.
 *
 * A node can have multiple end-points and hence multiple addresses.
 * An LNet network can be a simple network (e.g. tcp0) or a network of
 * LNet networks connected by LNet routers. Therefore an end-point address
 * has two parts: network ID, and address within a network.
 * The most-significant-byte in this format is always 0.  A larger value
 * would imply a larger nid with a larger address.
 *
 * \see LNET_NIDNET, LNET_NIDADDR, and LNET_MKNID.
 */
typedef __u64 lnet_nid_t;

/*
 * Address of LNet end-point in extended form
 *
 * To support addresses larger than 32bits we have
 * an extended nid which supports up to 128 bits
 * of address and is extensible.
 * If nid_size is 0, then the nid can be stored in an lnet_nid_t,
 * and the first 8 bytes of the 'struct lnet_nid' are identical to
 * the lnet_nid_t in big-endian format.
 * If nid_type == 0xff, then all other fields should be ignored
 * and this is an ANY wildcard address.  In particular, the nid_size
 * can be 0xff without making the address too big to fit.
 */
struct lnet_nid {
	__u8	nid_size;	/* total bytes - 8 */
	__u8	nid_type;
	__be16	nid_num;
	__be32	nid_addr[4];
} __attribute__((packed));

#define NID_BYTES(nid)		((nid)->nid_size + 8)
#define NID_ADDR_BYTES(nid)	((nid)->nid_size + 4)

/**
 * ID of a process in a node. Shortened as PID to distinguish from
 * lnet_process_id, the global process ID.
 */
typedef __u32 lnet_pid_t;

/* Packed version of struct lnet_process_id to transfer via network */
struct lnet_process_id_packed {
	lnet_nid_t nid;
	lnet_pid_t pid;	/* node id / process id */
} __attribute__((packed));

/* The wire handle's interface cookie only matches one network interface in
 * one epoch (i.e. new cookie when the interface restarts or the node
 * reboots).  The object cookie only matches one object on that interface
 * during that object's lifetime (i.e. no cookie re-use).
 */
struct lnet_handle_wire {
	__u64 wh_interface_cookie;
	__u64 wh_object_cookie;
} __attribute__((packed));

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
 * end.
 */
struct lnet_ack {
	struct lnet_handle_wire	dst_wmd;
	__u64			match_bits;
	__u32			mlength;
} __attribute__((packed));

struct lnet_put {
	struct lnet_handle_wire	ack_wmd;
	__u64			match_bits;
	__u64			hdr_data;
	__u32			ptl_index;
	__u32			offset;
} __attribute__((packed));

struct lnet_get {
	struct lnet_handle_wire	return_wmd;
	__u64			match_bits;
	__u32			ptl_index;
	__u32			src_offset;
	__u32			sink_length;
} __attribute__((packed));

struct lnet_reply {
	struct lnet_handle_wire	dst_wmd;
} __attribute__((packed));

struct lnet_hello {
	__u64			incarnation;
	__u32			type;
} __attribute__((packed));

union lnet_cmd_hdr {
	struct lnet_ack		ack;
	struct lnet_put		put;
	struct lnet_get		get;
	struct lnet_reply	reply;
	struct lnet_hello	hello;
} __attribute__((packed));

/* This is used for message headers that lnet code is manipulating.
 *  All fields before the union are in host-byte-order.
 */
struct lnet_hdr {
	struct lnet_nid		dest_nid;
	struct lnet_nid		src_nid;
	lnet_pid_t		dest_pid;
	lnet_pid_t		src_pid;
	__u32			type;		/* enum lnet_msg_type */
	__u32			payload_length;	/* payload data to follow */
	/*<------__u64 aligned------->*/
	union lnet_cmd_hdr	msg;
} __attribute__((packed));

/* This is used to support conversion between an lnet_hdr and
 * the content of a network message.
 */
struct _lnet_hdr_nid4 {
	lnet_nid_t	dest_nid;
	lnet_nid_t	src_nid;
	lnet_pid_t	dest_pid;
	lnet_pid_t	src_pid;
	__u32		type;		/* enum lnet_msg_type */
	__u32		payload_length;	/* payload data to follow */
	/*<------__u64 aligned------->*/
	union lnet_cmd_hdr msg;
} __attribute__((packed));

/* This is stored in a network message buffer.  Content cannot be accessed
 * without converting to an lnet_hdr.
 */
struct lnet_hdr_nid4 {
	char	_bytes[sizeof(struct _lnet_hdr_nid4)];
} __attribute__((packed));

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
} __attribute__((packed));

/* PROTO MAGIC for LNDs */
#define LNET_PROTO_IB_MAGIC		0x0be91b91
#define LNET_PROTO_GNI_MAGIC		0xb00fbabe /* ask Kim */
#define LNET_PROTO_TCP_MAGIC		0xeebc0ded
#define LNET_PROTO_KFI_MAGIC		0xdeadbeef
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
	__u32	acr_magic;	/* LNET_PROTO_ACCEPTOR_MAGIC */
	__u32	acr_version;	/* protocol version */
	__u64	acr_nid;	/* target NID */
} __attribute__((packed));

#define LNET_PROTO_ACCEPTOR_VERSION	1

struct lnet_acceptor_connreq_v2 {
	__u32			acr_magic;	/* LNET_PROTO_ACCEPTOR_MAGIC */
	__u32			acr_version;	/* protocol version - 2 */
	struct lnet_nid		acr_nid;	/* target NID */
} __attribute__((packed));

/* For use with 16-byte addresses */
#define LNET_PROTO_ACCEPTOR_VERSION_16  2

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
} __attribute__((packed));

#define LNET_NI_STATUS_UP	0x15aac0de
#define LNET_NI_STATUS_DOWN	0xdeadface
#define LNET_NI_STATUS_INVALID	0x00000000

struct lnet_ni_status {
	lnet_nid_t ns_nid;
	__u32      ns_status;
	__u32      ns_msg_size;	/* represents ping buffer size if message
				 * contains large NID addresses.
				 */
} __attribute__((packed));

/* When this appears in lnet_ping_info, it will be large
 * enough to hold whatever nid is present, rounded up
 * to a multiple of 4 bytes.
 * NOTE: all users MUST check ns_nid.nid_size is usable.
 */
struct lnet_ni_large_status {
	__u32		ns_status;
	struct lnet_nid	ns_nid;
} __attribute__((packed));

/* NB: value of these features equal to LNET_PROTO_PING_VERSION_x
 * of old LNet, so there shouldn't be any compatibility issue
 */
#define LNET_PING_FEAT_INVAL		(0)		/* no feature */
#define LNET_PING_FEAT_BASE		(1 << 0)	/* just a ping */
#define LNET_PING_FEAT_NI_STATUS	(1 << 1)	/* return NI status */
#define LNET_PING_FEAT_RTE_DISABLED	(1 << 2)	/* Routing enabled */
#define LNET_PING_FEAT_MULTI_RAIL	(1 << 3)	/* Multi-Rail aware */
#define LNET_PING_FEAT_DISCOVERY	(1 << 4)	/* Supports Discovery */
#define LNET_PING_FEAT_LARGE_ADDR	(1 << 5)	/* Large addr nids present */
#define LNET_PING_FEAT_PRIMARY_LARGE	(1 << 6)	/* Primary is first Large addr */

/*
 * All ping feature bits fit to hit the wire.
 * In lnet_assert_wire_constants() this is compared against its open-coded
 * value, and in lnet_ping_target_update() it is used to verify that no
 * unknown bits have been set.
 * New feature bits can be added, just be aware that this does change the
 * over-the-wire protocol.
 */
#define LNET_PING_FEAT_BITS		(LNET_PING_FEAT_BASE |		\
					 LNET_PING_FEAT_NI_STATUS |	\
					 LNET_PING_FEAT_RTE_DISABLED |	\
					 LNET_PING_FEAT_MULTI_RAIL |	\
					 LNET_PING_FEAT_DISCOVERY |	\
					 LNET_PING_FEAT_LARGE_ADDR |	\
					 LNET_PING_FEAT_PRIMARY_LARGE)

/* NOTE:
 * The first address in pi_ni *must* be the loop-back nid: LNET_NID_LO_0
 * The second address must be the primary nid for the host unless
 * LNET_PING_FEAT_PRIMARY_LARGE is set, then the first large address
 * is the preferred primary.  However nodes that do not recognise that
 * flag will quietly ignore it.
 */
struct lnet_ping_info {
	__u32			pi_magic;
	__u32			pi_features;
	lnet_pid_t		pi_pid;
	__u32			pi_nnis;	/* number of nid4 entries */
	struct lnet_ni_status	pi_ni[];
} __attribute__((packed));

#define LNET_PING_INFO_HDR_SIZE \
	offsetof(struct lnet_ping_info, pi_ni[0])
#define LNET_PING_INFO_MIN_SIZE \
	offsetof(struct lnet_ping_info, pi_ni[LNET_INTERFACES_MIN])
#define LNET_PING_INFO_LONI(PINFO)      ((PINFO)->pi_ni[0].ns_nid)
#define LNET_PING_INFO_SEQNO(PINFO)     ((PINFO)->pi_ni[0].ns_status)
/* If LNET_PING_FEAT_LARGE_ADDR set, pi_nnis is the number of nid4 entries
 * and pi_ni[0].ns_msg_size is the total number of bytes, including header and
 * lnet_ni_large_status entries which follow the lnet_ni_status entries.
 * This must be a multiple of 4.
 */
#define lnet_ping_info_size(pinfo)				\
	(((pinfo)->pi_features & LNET_PING_FEAT_LARGE_ADDR)	\
	? ((pinfo)->pi_ni[0].ns_msg_size & ~3)			\
	: offsetof(struct lnet_ping_info, pi_ni[(pinfo)->pi_nnis]))

#endif
