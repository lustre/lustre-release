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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/klnds/o2iblnd/o2iblnd-idl.h
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */
#ifndef __LNET_O2IBLND_IDL_H__
#define __LNET_O2IBLND_IDL_H__

#include <uapi/linux/lnet/lnet-idl.h>

/************************************************************************
 * IB Wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 */

struct kib_connparams {
	u16			ibcp_queue_depth;
	u16			ibcp_max_frags;
	u32			ibcp_max_msg_size;
} __packed;

struct kib_immediate_msg {
	struct lnet_hdr		ibim_hdr;	/* portals header */
	char			ibim_payload[0];/* piggy-backed payload */
} __packed;

struct kib_rdma_frag {
	u32			rf_nob;		/* # bytes this frag */
	u64			rf_addr;	/* CAVEAT EMPTOR: misaligned!! */
} __packed;

struct kib_rdma_desc {
	u32			rd_key;		/* local/remote key */
	u32			rd_nfrags;	/* # fragments */
	struct kib_rdma_frag	rd_frags[0];	/* buffer frags */
} __packed;

struct kib_putreq_msg {
	struct lnet_hdr		ibprm_hdr;	/* portals header */
	u64			ibprm_cookie;	/* opaque completion cookie */
} __packed;

struct kib_putack_msg {
	u64			ibpam_src_cookie;/* reflected completion cookie */
	u64			ibpam_dst_cookie;/* opaque completion cookie */
	struct kib_rdma_desc	ibpam_rd;	/* sender's sink buffer */
} __packed;

struct kib_get_msg {
	struct lnet_hdr		ibgm_hdr;	/* portals header */
	u64			ibgm_cookie;	/* opaque completion cookie */
	struct kib_rdma_desc	ibgm_rd;	/* rdma descriptor */
} __packed;

struct kib_completion_msg {
	u64			ibcm_cookie;	/* opaque completion cookie */
	s32			ibcm_status;    /* < 0 failure: >= 0 length */
} __packed;

struct kib_msg {
	/* First 2 fields fixed FOR ALL TIME */
	u32			ibm_magic;	/* I'm an ibnal message */
	u16			ibm_version;	/* this is my version number */

	u8			ibm_type;	/* msg type */
	u8			ibm_credits;	/* returned credits */
	u32			ibm_nob;	/* # bytes in whole message */
	u32			ibm_cksum;	/* checksum (0 == no checksum) */
	u64			ibm_srcnid;	/* sender's NID */
	u64			ibm_srcstamp;	/* sender's incarnation */
	u64			ibm_dstnid;	/* destination's NID */
	u64			ibm_dststamp;	/* destination's incarnation */

	union {
		struct kib_connparams		connparams;
		struct kib_immediate_msg	immediate;
		struct kib_putreq_msg		putreq;
		struct kib_putack_msg		putack;
		struct kib_get_msg		get;
		struct kib_completion_msg	completion;
	} __packed ibm_u;
} __packed;

#define IBLND_MSG_MAGIC LNET_PROTO_IB_MAGIC     /* unique magic */

#define IBLND_MSG_VERSION_1	0x11
#define IBLND_MSG_VERSION_2	0x12
#define IBLND_MSG_VERSION	IBLND_MSG_VERSION_2

#define IBLND_MSG_CONNREQ	0xc0	/* connection request */
#define IBLND_MSG_CONNACK	0xc1	/* connection acknowledge */
#define IBLND_MSG_NOOP		0xd0	/* nothing (just credits) */
#define IBLND_MSG_IMMEDIATE	0xd1	/* immediate */
#define IBLND_MSG_PUT_REQ	0xd2	/* putreq (src->sink) */
#define IBLND_MSG_PUT_NAK	0xd3	/* completion (sink->src) */
#define IBLND_MSG_PUT_ACK	0xd4	/* putack (sink->src) */
#define IBLND_MSG_PUT_DONE	0xd5	/* completion (src->sink) */
#define IBLND_MSG_GET_REQ	0xd6	/* getreq (sink->src) */
#define IBLND_MSG_GET_DONE	0xd7	/* completion (src->sink: all OK) */

struct kib_rej {
	u32			ibr_magic;	/* sender's magic */
	u16			ibr_version;	/* sender's version */
	u8			ibr_why;	/* reject reason */
	u8			ibr_padding;	/* padding */
	u64			ibr_incarnation;/* incarnation of peer_ni */
	struct kib_connparams	ibr_cp;		/* connection parameters */
} __packed;

/* connection rejection reasons */
#define IBLND_REJECT_CONN_RACE       1          /* You lost connection race */
#define IBLND_REJECT_NO_RESOURCES    2          /* Out of memory/conns etc */
#define IBLND_REJECT_FATAL           3          /* Anything else */

#define IBLND_REJECT_CONN_UNCOMPAT   4          /* incompatible version peer_ni */
#define IBLND_REJECT_CONN_STALE      5          /* stale peer_ni */

/* peer_ni's rdma frags doesn't match mine */
#define IBLND_REJECT_RDMA_FRAGS      6
/* peer_ni's msg queue size doesn't match mine */
#define IBLND_REJECT_MSG_QUEUE_SIZE  7
#define IBLND_REJECT_INVALID_SRV_ID  8

/***********************************************************************/

#endif /* __LNET_O2IBLND_IDL_H__ */
