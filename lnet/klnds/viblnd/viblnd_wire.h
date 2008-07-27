/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/viblnd/viblnd_wire.h
 *
 * IB Wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 */

typedef struct kib_connparams
{
        __u32             ibcp_queue_depth;
        __u32             ibcp_max_msg_size;
        __u32             ibcp_max_frags;
} WIRE_ATTR kib_connparams_t;

typedef struct
{
        lnet_hdr_t        ibim_hdr;             /* portals header */
        char              ibim_payload[0];      /* piggy-backed payload */
} WIRE_ATTR kib_immediate_msg_t;

#ifndef IBNAL_USE_FMR
# error "IBNAL_USE_FMR must be defined 1 or 0 before including this file"
#endif

#if IBNAL_USE_FMR
typedef struct
{
	__u64             rd_addr;             	/* IO VMA address */
	__u32             rd_nob;              	/* # of bytes */
	__u32             rd_key;		/* remote key */
} WIRE_ATTR kib_rdma_desc_t;
#else
/* YEUCH! the __u64 address is split into 2 __u32 fields to ensure proper
 * packing.  Otherwise we can't fit enough frags into an IBNAL message (<=
 * smallest page size on any arch). */
typedef struct
{
        __u32             rf_nob;               /* # of bytes */
        __u32             rf_addr_lo;           /* lo 4 bytes of vaddr */
        __u32             rf_addr_hi;           /* hi 4 bytes of vaddr */
} WIRE_ATTR kib_rdma_frag_t;

typedef struct
{
        __u32             rd_key;               /* local/remote key */
        __u32             rd_nfrag;             /* # fragments */
        kib_rdma_frag_t   rd_frags[0];          /* buffer frags */
} WIRE_ATTR kib_rdma_desc_t;
#endif

typedef struct
{
        lnet_hdr_t        ibprm_hdr;            /* portals header */
        __u64             ibprm_cookie;         /* opaque completion cookie */
} WIRE_ATTR kib_putreq_msg_t;

typedef struct
{
        __u64             ibpam_src_cookie;     /* reflected completion cookie */
        __u64             ibpam_dst_cookie;     /* opaque completion cookie */
        kib_rdma_desc_t   ibpam_rd;             /* sender's sink buffer */
} WIRE_ATTR kib_putack_msg_t;

typedef struct
{
        lnet_hdr_t        ibgm_hdr;             /* portals header */
        __u64             ibgm_cookie;          /* opaque completion cookie */
        kib_rdma_desc_t   ibgm_rd;              /* rdma descriptor */
} WIRE_ATTR kib_get_msg_t;

typedef struct
{
        __u64             ibcm_cookie;          /* opaque completion cookie */
        __s32             ibcm_status;          /* < 0 failure: >= 0 length */
} WIRE_ATTR kib_completion_msg_t;

typedef struct
{
        /* First 2 fields fixed FOR ALL TIME */
        __u32             ibm_magic;            /* I'm an openibnal message */
        __u16             ibm_version;          /* this is my version number */

        __u8              ibm_type;             /* msg type */
        __u8              ibm_credits;          /* returned credits */
        __u32             ibm_nob;              /* # bytes in whole message */
        __u32             ibm_cksum;            /* checksum (0 == no checksum) */
        __u64             ibm_srcnid;           /* sender's NID */
        __u64             ibm_srcstamp;         /* sender's incarnation */
        __u64             ibm_dstnid;           /* destination's NID */
        __u64             ibm_dststamp;         /* destination's incarnation */
        __u64             ibm_seq;              /* sequence number */

        union {
                kib_connparams_t      connparams;
                kib_immediate_msg_t   immediate;
                kib_putreq_msg_t      putreq;
                kib_putack_msg_t      putack;
                kib_get_msg_t         get;
                kib_completion_msg_t  completion;
        } WIRE_ATTR ibm_u;
} WIRE_ATTR kib_msg_t;

#define IBNAL_MSG_MAGIC LNET_PROTO_VIB_MAGIC	/* unique magic */

#define IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD 0x10 /* previous version */

#define IBNAL_MSG_VERSION           0x11	/* current version */

#define IBNAL_MSG_CONNREQ           0xc0        /* connection request */
#define IBNAL_MSG_CONNACK           0xc1        /* connection acknowledge */
#define IBNAL_MSG_NOOP              0xd0        /* nothing (just credits) */
#define IBNAL_MSG_IMMEDIATE         0xd1        /* immediate */
#define IBNAL_MSG_PUT_REQ           0xd2        /* putreq (src->sink) */
#define IBNAL_MSG_PUT_NAK           0xd3        /* completion (sink->src) */
#define IBNAL_MSG_PUT_ACK           0xd4        /* putack (sink->src) */
#define IBNAL_MSG_PUT_DONE          0xd5        /* completion (src->sink) */
#define IBNAL_MSG_GET_REQ           0xd6        /* getreq (sink->src) */
#define IBNAL_MSG_GET_DONE          0xd7        /* completion (src->sink: all OK) */

/* connection rejection reasons */
#define IBNAL_REJECT_CONN_RACE       0          /* You lost connection race */
#define IBNAL_REJECT_NO_RESOURCES    1          /* Out of memory/conns etc */
#define IBNAL_REJECT_FATAL           2          /* Anything else */
