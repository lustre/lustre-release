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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/include/lnet/socklnd.h
 */
#ifndef __LNET_LNET_SOCKLND_H__
#define __LNET_LNET_SOCKLND_H__

#include <uapi/linux/lnet/lnet-types.h>
#include <uapi/linux/lnet/socklnd.h>

struct ksock_hello_msg {
	__u32			kshm_magic;	/* LNET_PROTO_MAGIC */
	__u32			kshm_version;	/* KSOCK_PROTO_V* */
	struct lnet_nid		kshm_src_nid;	/* sender's nid */
	struct lnet_nid		kshm_dst_nid;	/* destination nid */
	lnet_pid_t		kshm_src_pid;	/* sender's pid */
	lnet_pid_t		kshm_dst_pid;	/* destination pid */
	__u64			kshm_src_incarnation; /* sender's incarnation */
	__u64			kshm_dst_incarnation; /* destination's incarnation */
	__u32			kshm_ctype;	/* SOCKLND_CONN_* */
	__u32			kshm_nips;	/* always sent as zero */
	__u32			kshm_ips[0];	/* deprecated */
} __packed;

struct ksock_hello_msg_nid4 {
	__u32			kshm_magic;	/* LNET_PROTO_MAGIC */
	__u32			kshm_version;	/* KSOCK_PROTO_V* */
	lnet_nid_t		kshm_src_nid;	/* sender's nid */
	lnet_nid_t		kshm_dst_nid;	/* destination nid */
	lnet_pid_t		kshm_src_pid;	/* sender's pid */
	lnet_pid_t		kshm_dst_pid;	/* destination pid */
	__u64			kshm_src_incarnation; /* sender's incarnation */
	__u64			kshm_dst_incarnation; /* destination's incarnation */
	__u32			kshm_ctype;	/* SOCKLND_CONN_* */
	__u32			kshm_nips;	/* sent as zero */
	__u32			kshm_ips[0];	/* deprecated */
} __packed;

struct ksock_msg_hdr {
	__u32			ksh_type;	/* type of socklnd message */
	__u32			ksh_csum;	/* checksum if != 0 */
	__u64			ksh_zc_cookies[2]; /* Zero-Copy request/ACK
						    * cookie
						    */
} __packed;

#define KSOCK_MSG_NOOP		0xc0		/* empty */
#define KSOCK_MSG_LNET		0xc1		/* lnet msg */

struct ksock_msg {
	struct ksock_msg_hdr	ksm_kh;
	union {
		/* case ksm_kh.ksh_type == KSOCK_MSG_NOOP */
		/* - nothing */
		/* case ksm_kh.ksh_type == KSOCK_MSG_LNET */
		struct lnet_hdr_nid4 lnetmsg_nid4;
		/* case ksm_kh.ksh_type == KSOCK_MSG_LNET &&
		 *      kshm_version >= KSOCK_PROTO_V4
		 */
		struct lnet_hdr_nid16 lnetmsg_nid16;
	} __packed ksm_u;
} __packed;
#define ksm_type ksm_kh.ksh_type
#define ksm_csum ksm_kh.ksh_csum
#define ksm_zc_cookies ksm_kh.ksh_zc_cookies

/* We need to know this number to parse hello msg from ksocklnd in
 * other LND (usocklnd, for example) */
#define KSOCK_PROTO_V2		2
#define KSOCK_PROTO_V3		3
#define KSOCK_PROTO_V4		4

#endif
