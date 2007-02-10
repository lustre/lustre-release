/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 * Copyright (C) 2006 Myricom, Inc.
 *   Author: Scott Atchley <atchley at myri.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * MXLND wire format - sent in sender's byte order
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
        u64             mxm_seq;                        /* sequence number */

        union {
                kmx_connreq_msg_t       conn_req;
                kmx_eager_msg_t         eager;
                kmx_putreq_msg_t        put_req;
                kmx_putack_msg_t        put_ack;
                kmx_getreq_msg_t        get_req;
        } WIRE_ATTR mxm_u;
} WIRE_ATTR kmx_msg_t;

#define MXLND_MSG_MAGIC         0x4d583130              /* unique magic 'MX10' */
#define MXLND_MSG_VERSION       0x01

#define MXLND_MSG_CONN_REQ      0xc                     /* connection request */
#define MXLND_MSG_CONN_ACK      0xa                     /* connection request response */
#define MXLND_MSG_EAGER         0xe                     /* eager message */
#define MXLND_MSG_NOOP          0x1                     /* no msg, return credits */
#define MXLND_MSG_PUT_REQ       0x2                     /* put request src->sink */
#define MXLND_MSG_PUT_ACK       0x3                     /* put ack     src<-sink */
#define MXLND_MSG_PUT_DATA      0x4                     /* put payload src->sink */
#define MXLND_MSG_GET_REQ       0x5                     /* get request sink->src */
#define MXLND_MSG_GET_DATA      0x6                     /* get payload sink<-src */
