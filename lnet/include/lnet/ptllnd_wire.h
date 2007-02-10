/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */
 
/************************************************************************
 * Tunable defaults that {u,k}lnds/ptllnd should have in common.
 */

#define PTLLND_PORTAL           9          /* The same portal PTLPRC used when talking to cray portals */
#define PTLLND_PID              9          /* The Portals PID */
#define PTLLND_PEERCREDITS      8          /* concurrent sends to 1 peer */
#define PTLLND_MAX_MSG_SIZE     512        /* Maximum message size */


/************************************************************************
 * Portals LNS Wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 */

#define PTL_RESERVED_MATCHBITS  0x100	/* below this value is reserved
                                         * above is for bulk data transfer */
#define LNET_MSG_MATCHBITS       0      /* the value for the message channel */

typedef struct
{
        lnet_hdr_t        kptlim_hdr;             /* portals header */
        char              kptlim_payload[0];      /* piggy-backed payload */
} WIRE_ATTR kptl_immediate_msg_t;

typedef struct
{
        lnet_hdr_t        kptlrm_hdr;             /* portals header */
        __u64             kptlrm_matchbits;       /* matchbits */
} WIRE_ATTR kptl_rdma_msg_t;

typedef struct
{
        __u64             kptlhm_matchbits;       /* matchbits */
        __u32             kptlhm_max_msg_size;    /* max message size */
} WIRE_ATTR kptl_hello_msg_t;

typedef struct
{
        /* First 2 fields fixed FOR ALL TIME */
        __u32           ptlm_magic;     /* I'm a Portals LND message */
        __u16           ptlm_version;   /* this is my version number */
        __u8            ptlm_type;      /* the message type */
        __u8            ptlm_credits;   /* returned credits */
        __u32           ptlm_nob;       /* # bytes in whole message */
        __u32           ptlm_cksum;     /* checksum (0 == no checksum) */
        __u64           ptlm_srcnid;    /* sender's NID */
        __u64           ptlm_srcstamp;  /* sender's incarnation */
        __u64           ptlm_dstnid;    /* destination's NID */
        __u64           ptlm_dststamp;  /* destination's incarnation */
        __u32           ptlm_srcpid;    /* sender's PID */
        __u32           ptlm_dstpid;    /* destination's PID */

         union {
                kptl_immediate_msg_t    immediate;
                kptl_rdma_msg_t         rdma;
                kptl_hello_msg_t        hello;
        } WIRE_ATTR ptlm_u;

} kptl_msg_t;

#define PTLLND_MSG_MAGIC                LNET_PROTO_PTL_MAGIC
#define PTLLND_MSG_VERSION              0x04

#define PTLLND_RDMA_OK                  0x00
#define PTLLND_RDMA_FAIL                0x01

#define PTLLND_MSG_TYPE_INVALID         0x00
#define PTLLND_MSG_TYPE_PUT             0x01
#define PTLLND_MSG_TYPE_GET             0x02
#define PTLLND_MSG_TYPE_IMMEDIATE       0x03    /* No bulk data xfer*/
#define PTLLND_MSG_TYPE_NOOP            0x04
#define PTLLND_MSG_TYPE_HELLO           0x05
#define PTLLND_MSG_TYPE_NAK             0x06

