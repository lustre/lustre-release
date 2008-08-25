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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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
 * lustre/include/lustre/lustre_idl.h
 *
 * Lustre wire protocol definitions.
 *
 * ALL structs passing over the wire should be declared here.  Structs
 * that are used in interfaces with userspace should go in lustre_user.h.
 *
 * All structs being declared here should be built from simple fixed-size
 * types (__u8, __u16, __u32, __u64) or be built from other types or
 * structs also declared in this file.  Similarly, all flags and magic
 * values in those structs should also be declared here.  This ensures
 * that the Lustre wire protocol is not influenced by external dependencies.
 *
 * The only other acceptable items in this file are VERY SIMPLE accessor
 * functions to avoid callers grubbing inside the structures, and the
 * prototypes of the swabber functions for each struct.  Nothing that
 * depends on external functions or definitions should be in here.
 *
 * Structs must be properly aligned to put 64-bit values on an 8-byte
 * boundary.  Any structs being added here must also be added to
 * utils/wirecheck.c and "make newwiretest" run to regenerate the
 * utils/wiretest.c sources.  This allows us to verify that wire structs
 * have the proper alignment/size on all architectures.
 *
 * DO NOT CHANGE any of the structs, flags, values declared here and used
 * in released Lustre versions.  Some structs may have padding fields that
 * can be used.  Some structs might allow addition at the end (verify this
 * in the code to ensure that new/old clients that see this larger struct
 * do not fail, otherwise you need to implement protocol compatibility).
 *
 * We assume all nodes are either little-endian or big-endian, and we
 * always send messages in the sender's native format.  The receiver
 * detects the message format by checking the 'magic' field of the message.
 *
 * Each wire type has corresponding 'lustre_swab_xxxtypexxx()' routines,
 * implemented either here, inline (trivial implementations) or in
 * ptlrpc/pack_generic.c.  These 'swabbers' convert the type from "other"
 * endian, in-place in the message buffer.
 *
 * A swabber takes a single pointer argument.  The caller must already have
 * verified that the length of the message buffer >= sizeof (type).
 *
 * For variable length types, a second 'lustre_swab_v_xxxtypexxx()' routine
 * may be defined that swabs just the variable part, after the caller has
 * verified that the message buffer is large enough.
 */

#ifndef _LUSTRE_IDL_H_
#define _LUSTRE_IDL_H_

#if defined(__linux__)
#include <linux/lustre_types.h>
#elif defined(__APPLE__)
#include <darwin/lustre_types.h>
#elif defined(__WINNT__)
#include <winnt/lustre_types.h>
#else
#error Unsupported operating system.
#endif

/* Defn's shared with user-space. */
#include <lustre/lustre_user.h>
#include <lustre_ver.h>
#include <lustre/ll_fiemap.h>

#include <libcfs/kp30.h>

/*
 * this file contains all data structures used in Lustre interfaces:
 * - obdo and obd_request records
 * - mds_request records
 * - ldlm data
 * - ioctl's
 */

/*
 *  GENERAL STUFF
 */
/* FOO_REQUEST_PORTAL is for incoming requests on the FOO
 * FOO_REPLY_PORTAL   is for incoming replies on the FOO
 * FOO_BULK_PORTAL    is for incoming bulk on the FOO
 */

#define CONNMGR_REQUEST_PORTAL          1
#define CONNMGR_REPLY_PORTAL            2
//#define OSC_REQUEST_PORTAL            3
#define OSC_REPLY_PORTAL                4
//#define OSC_BULK_PORTAL               5
#define OST_IO_PORTAL                   6
#define OST_CREATE_PORTAL               7
#define OST_BULK_PORTAL                 8
//#define MDC_REQUEST_PORTAL            9
#define MDC_REPLY_PORTAL               10
//#define MDC_BULK_PORTAL              11
#define MDS_REQUEST_PORTAL             12
//#define MDS_REPLY_PORTAL             13
#define MDS_BULK_PORTAL                14
#define LDLM_CB_REQUEST_PORTAL         15
#define LDLM_CB_REPLY_PORTAL           16
#define LDLM_CANCEL_REQUEST_PORTAL     17
#define LDLM_CANCEL_REPLY_PORTAL       18
//#define PTLBD_REQUEST_PORTAL           19
//#define PTLBD_REPLY_PORTAL             20
//#define PTLBD_BULK_PORTAL              21
#define MDS_SETATTR_PORTAL             22
#define MDS_READPAGE_PORTAL            23

#define MGC_REPLY_PORTAL               25
#define MGS_REQUEST_PORTAL             26
#define MGS_REPLY_PORTAL               27
#define OST_REQUEST_PORTAL             28
#define FLD_REQUEST_PORTAL             29
#define SEQ_METADATA_PORTAL            30

#define SVC_KILLED               1
#define SVC_EVENT                2
#define SVC_SIGNAL               4
#define SVC_RUNNING              8
#define SVC_STOPPING            16
#define SVC_STOPPED             32

/* packet types */
#define PTL_RPC_MSG_REQUEST 4711
#define PTL_RPC_MSG_ERR     4712
#define PTL_RPC_MSG_REPLY   4713

/* DON'T use swabbed values of MAGIC as magic! */
#define LUSTRE_MSG_MAGIC_V1 0x0BD00BD0
#define LUSTRE_MSG_MAGIC_V2 0x0BD00BD3

#define LUSTRE_MSG_MAGIC_V1_SWABBED 0xD00BD00B
#define LUSTRE_MSG_MAGIC_V2_SWABBED 0xD30BD00B

#define LUSTRE_MSG_MAGIC LUSTRE_MSG_MAGIC_V2

#define PTLRPC_MSG_VERSION  0x00000003
#define LUSTRE_VERSION_MASK 0xffff0000
#define LUSTRE_OBD_VERSION  0x00010000
#define LUSTRE_MDS_VERSION  0x00020000
#define LUSTRE_OST_VERSION  0x00030000
#define LUSTRE_DLM_VERSION  0x00040000
#define LUSTRE_LOG_VERSION  0x00050000
#define LUSTRE_MGS_VERSION  0x00060000

struct lustre_handle {
        __u64 cookie;
};
#define DEAD_HANDLE_MAGIC 0xdeadbeefcafebabeULL

static inline int lustre_handle_is_used(struct lustre_handle *lh)
{
        return lh->cookie != 0ull;
}

static inline int lustre_handle_equal(struct lustre_handle *lh1,
                                      struct lustre_handle *lh2)
{
        return lh1->cookie == lh2->cookie;
}

static inline void lustre_handle_copy(struct lustre_handle *tgt,
                                      struct lustre_handle *src)
{
        tgt->cookie = src->cookie;
}

/* we depend on this structure to be 8-byte aligned */
/* this type is only endian-adjusted in lustre_unpack_msg() */
struct lustre_msg_v1 {
        struct lustre_handle lm_handle;
        __u32 lm_magic;
        __u32 lm_type;
        __u32 lm_version;
        __u32 lm_opc;
        __u64 lm_last_xid;
        __u64 lm_last_committed;
        __u64 lm_transno;
        __u32 lm_status;
        __u32 lm_flags;
        __u32 lm_conn_cnt;
        __u32 lm_bufcount;
        __u32 lm_buflens[0];
};

/* flags for lm_flags */
#define MSGHDR_AT_SUPPORT               0x1

#define lustre_msg lustre_msg_v2
/* we depend on this structure to be 8-byte aligned */
/* this type is only endian-adjusted in lustre_unpack_msg() */
struct lustre_msg_v2 {
        __u32 lm_bufcount;
        __u32 lm_secflvr;
        __u32 lm_magic;
        __u32 lm_repsize;
        __u32 lm_cksum;
        __u32 lm_flags;
        __u32 lm_padding_2;
        __u32 lm_padding_3;
        __u32 lm_buflens[0];
};

/* without security, ptlrpc_body is put in the first buffer. */
#define PTLRPC_NUM_VERSIONS     4
struct ptlrpc_body {
        struct lustre_handle pb_handle;
        __u32 pb_type;
        __u32 pb_version;
        __u32 pb_opc;
        __u32 pb_status;
        __u64 pb_last_xid;
        __u64 pb_last_seen; /* not used */
        __u64 pb_last_committed;
        __u64 pb_transno;
        __u32 pb_flags;
        __u32 pb_op_flags;
        __u32 pb_conn_cnt;
        __u32 pb_timeout;  /* for req, the deadline, for rep, the service est */
        __u32 pb_service_time; /* for rep, actual service time */
        __u32 pb_limit;
        __u64 pb_slv;
        /* VBR: pre-versions */
        __u64 pb_pre_versions[PTLRPC_NUM_VERSIONS];
        /* padding for future needs */
        __u64 pb_padding[4];
};

extern void lustre_swab_ptlrpc_body(struct ptlrpc_body *pb);

/* message body offset for lustre_msg_v2 */
/* ptlrpc body offset in all request/reply messages */
#define MSG_PTLRPC_BODY_OFF             0

/* normal request/reply message record offset */
#define REQ_REC_OFF                     1
#define REPLY_REC_OFF                   1

/* ldlm request message body offset */
#define DLM_LOCKREQ_OFF                 1 /* lockreq offset */
#define DLM_REQ_REC_OFF                 2 /* normal dlm request record offset */

/* ldlm intent lock message body offset */
#define DLM_INTENT_IT_OFF               2 /* intent lock it offset */
#define DLM_INTENT_REC_OFF              3 /* intent lock record offset */

/* ldlm reply message body offset */
#define DLM_LOCKREPLY_OFF               1 /* lockrep offset */
#define DLM_REPLY_REC_OFF               2 /* reply record offset */

/* only use in req->rq_{req,rep}_swab_mask */
#define MSG_PTLRPC_HEADER_OFF           31

/* Flags that are operation-specific go in the top 16 bits. */
#define MSG_OP_FLAG_MASK   0xffff0000
#define MSG_OP_FLAG_SHIFT  16

/* Flags that apply to all requests are in the bottom 16 bits */
#define MSG_GEN_FLAG_MASK      0x0000ffff
#define MSG_LAST_REPLAY        1
#define MSG_RESENT             2
#define MSG_REPLAY             4
/* #define MSG_AT_SUPPORT         8  avoid until 1.10+ */
#define MSG_DELAY_REPLAY       0x10
#define MSG_VERSION_REPLAY     0x20

/*
 * Flags for all connect opcodes (MDS_CONNECT, OST_CONNECT)
 */

#define MSG_CONNECT_RECOVERING  0x00000001
#define MSG_CONNECT_RECONNECT   0x00000002
#define MSG_CONNECT_REPLAYABLE  0x00000004
//#define MSG_CONNECT_PEER        0x8
#define MSG_CONNECT_LIBCLIENT   0x00000010
#define MSG_CONNECT_INITIAL     0x00000020
#define MSG_CONNECT_ASYNC       0x00000040
#define MSG_CONNECT_NEXT_VER    0x00000080 /* use next version of lustre_msg */
#define MSG_CONNECT_TRANSNO     0x00000100
#define MSG_CONNECT_DELAYED     0x00000200

/* Connect flags */
#define OBD_CONNECT_RDONLY            0x1ULL /*client allowed read-only access*/
#define OBD_CONNECT_INDEX             0x2ULL /*connect to specific LOV idx */
#define OBD_CONNECT_GRANT             0x8ULL /*OSC acquires grant at connect */
#define OBD_CONNECT_SRVLOCK          0x10ULL /*server takes locks for client */
#define OBD_CONNECT_VERSION          0x20ULL /*Lustre versions in ocd */
#define OBD_CONNECT_REQPORTAL        0x40ULL /*Separate non-IO request portal */
#define OBD_CONNECT_ACL              0x80ULL /*access control lists */
#define OBD_CONNECT_XATTR           0x100ULL /*client use extended attributes */
#define OBD_CONNECT_CROW            0x200ULL /*MDS+OST create objects on write*/
#define OBD_CONNECT_TRUNCLOCK       0x400ULL /*locks on server for punch */
#define OBD_CONNECT_TRANSNO         0x800ULL /*replay sends initial transno */
#define OBD_CONNECT_IBITS          0x1000ULL /*support for inodebits locks */
#define OBD_CONNECT_JOIN           0x2000ULL /*files can be concatenated */
#define OBD_CONNECT_ATTRFID        0x4000ULL /*Server supports GetAttr By Fid */
#define OBD_CONNECT_NODEVOH        0x8000ULL /*No open handle on special nodes*/
#define OBD_CONNECT_LCL_CLIENT    0x10000ULL /*local 1.8 client */
#define OBD_CONNECT_RMT_CLIENT    0x20000ULL /*Remote 1.8 client */
#define OBD_CONNECT_BRW_SIZE      0x40000ULL /*Max bytes per rpc */
#define OBD_CONNECT_QUOTA64       0x80000ULL /*64bit qunit_data.qd_count */
#define OBD_CONNECT_MDS_CAPA     0x100000ULL /*MDS capability */
#define OBD_CONNECT_OSS_CAPA     0x200000ULL /*OSS capability */
#define OBD_CONNECT_CANCELSET    0x400000ULL /*Early batched cancels. */
#define OBD_CONNECT_SOM        0x00800000ULL /*Size on MDS */
#define OBD_CONNECT_AT         0x01000000ULL /*client uses adaptive timeouts */
#define OBD_CONNECT_LRU_RESIZE 0x02000000ULL /*Lru resize feature. */
#define OBD_CONNECT_MDS_MDS    0x04000000ULL /*MDS-MDS connection */
#define OBD_CONNECT_REAL       0x08000000ULL /*real connection */
#define OBD_CONNECT_CHANGE_QS  0x10000000ULL /*shrink/enlarge qunit size
                                              *b=10600 */
#define OBD_CONNECT_CKSUM      0x20000000ULL /*support several cksum algos */
#define OBD_CONNECT_FID        0x40000000ULL /* FID is supported */
#define OBD_CONNECT_VBR        0x80000000ULL /* version based recovery */
#define OBD_CONNECT_LOV_V3    0x100000000ULL /* client supports lov v3 ea */
/* also update obd_connect_names[] for lprocfs_rd_connect_flags()
 * and lustre/utils/wirecheck.c */

#ifdef HAVE_LRU_RESIZE_SUPPORT
#define LRU_RESIZE_CONNECT_FLAG OBD_CONNECT_LRU_RESIZE
#else
#define LRU_RESIZE_CONNECT_FLAG 0
#endif

#define MDS_CONNECT_SUPPORTED  (OBD_CONNECT_RDONLY | OBD_CONNECT_VERSION | \
                                OBD_CONNECT_ACL | OBD_CONNECT_XATTR | \
                                OBD_CONNECT_IBITS | OBD_CONNECT_JOIN | \
                                OBD_CONNECT_NODEVOH | OBD_CONNECT_ATTRFID | \
                                OBD_CONNECT_CANCELSET | OBD_CONNECT_AT | \
                                LRU_RESIZE_CONNECT_FLAG | OBD_CONNECT_VBR |\
                                OBD_CONNECT_LOV_V3)
#define OST_CONNECT_SUPPORTED  (OBD_CONNECT_SRVLOCK | OBD_CONNECT_GRANT | \
                                OBD_CONNECT_REQPORTAL | OBD_CONNECT_VERSION | \
                                OBD_CONNECT_TRUNCLOCK | OBD_CONNECT_INDEX | \
                                OBD_CONNECT_BRW_SIZE | OBD_CONNECT_QUOTA64 | \
                                OBD_CONNECT_CANCELSET | OBD_CONNECT_AT | \
                                LRU_RESIZE_CONNECT_FLAG | OBD_CONNECT_CKSUM | \
                                OBD_CONNECT_VBR | OBD_CONNECT_CHANGE_QS)
#define ECHO_CONNECT_SUPPORTED (0)
#define MGS_CONNECT_SUPPORTED  (OBD_CONNECT_VERSION | OBD_CONNECT_AT)

#define OBD_OCD_VERSION(major,minor,patch,fix) (((major)<<24) + ((minor)<<16) +\
                                                ((patch)<<8) + (fix))
#define OBD_OCD_VERSION_MAJOR(version) ((int)((version)>>24)&255)
#define OBD_OCD_VERSION_MINOR(version) ((int)((version)>>16)&255)
#define OBD_OCD_VERSION_PATCH(version) ((int)((version)>>8)&255)
#define OBD_OCD_VERSION_FIX(version)   ((int)(version)&255)

/* This structure is used for both request and reply.
 *
 * If we eventually have separate connect data for different types, which we
 * almost certainly will, then perhaps we stick a union in here. */
struct obd_connect_data {
        __u64 ocd_connect_flags;        /* OBD_CONNECT_* per above */
        __u32 ocd_version;              /* lustre release version number */
        __u32 ocd_grant;                /* initial cache grant amount (bytes) */
        __u32 ocd_index;                /* LOV index to connect to */
        __u32 ocd_brw_size;             /* Maximum BRW size in bytes */
        __u64 ocd_ibits_known;          /* inode bits this client understands */
        __u32 ocd_nllu;                 /* non-local-lustre-user */
        __u32 ocd_nllg;                 /* non-local-lustre-group */
        __u64 ocd_transno;              /* Used in lustre 1.8 */
        __u32 ocd_group;                /* Used in lustre 1.8 */
        __u32 ocd_cksum_types;          /* supported checksum algorithms */
        __u64 padding1;                 /* also fix lustre_swab_connect */
        __u64 padding2;                 /* also fix lustre_swab_connect */
};

extern void lustre_swab_connect(struct obd_connect_data *ocd);

/* b1_6 has smaller body. The defines below is for interoperability */
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2,0,0,0)
#define PTLRPC_INTEROP_1_6      1
#define PTLRPC_BODY_MIN_SIZE    offsetof(struct ptlrpc_body, pb_pre_versions)
#else
#define PTLRPC_BODY_MIN_SIZE    sizeof(struct ptlrpc_body)
#endif

/*
 * Supported checksum algorithms. Up to 32 checksum types are supported.
 * (32-bit mask stored in obd_connect_data::ocd_cksum_types)
 * Please update DECLARE_CKSUM_NAME/OBD_CKSUM_ALL in obd.h when adding a new
 * algorithm and also the OBD_FL_CKSUM* flags.
 */
typedef enum {
        OBD_CKSUM_CRC32 = 0x00000001,
        OBD_CKSUM_ADLER = 0x00000002,
} cksum_type_t;

/*
 *   OST requests: OBDO & OBD request records
 */

/* opcodes */
typedef enum {
        OST_REPLY      =  0,       /* reply ? */
        OST_GETATTR    =  1,
        OST_SETATTR    =  2,
        OST_READ       =  3,
        OST_WRITE      =  4,
        OST_CREATE     =  5,
        OST_DESTROY    =  6,
        OST_GET_INFO   =  7,
        OST_CONNECT    =  8,
        OST_DISCONNECT =  9,
        OST_PUNCH      = 10,
        OST_OPEN       = 11,
        OST_CLOSE      = 12,
        OST_STATFS     = 13,
/*      OST_SAN_READ   = 14,    deprecated */
/*      OST_SAN_WRITE  = 15,    deprecated */
        OST_SYNC       = 16,
        OST_SET_INFO   = 17,
        OST_QUOTACHECK = 18,
        OST_QUOTACTL   = 19,
        OST_QUOTA_ADJUST_QUNIT = 20,
        OST_LAST_OPC
} ost_cmd_t;
#define OST_FIRST_OPC  OST_REPLY

typedef __u64 obd_id;
typedef __u64 obd_gr;
typedef __u64 obd_time;
typedef __u64 obd_size;
typedef __u64 obd_off;
typedef __u64 obd_blocks;
typedef __u64 obd_valid;
typedef __u32 obd_blksize;
typedef __u32 obd_mode;
typedef __u32 obd_uid;
typedef __u32 obd_gid;
typedef __u32 obd_flag;
typedef __u32 obd_count;

#define OBD_FL_INLINEDATA    (0x00000001)
#define OBD_FL_OBDMDEXISTS   (0x00000002)
#define OBD_FL_DELORPHAN     (0x00000004) /* if set in o_flags delete orphans */
#define OBD_FL_NORPC         (0x00000008) /* set in o_flags do in OSC not OST */
#define OBD_FL_IDONLY        (0x00000010) /* set in o_flags only adjust obj id*/
#define OBD_FL_RECREATE_OBJS (0x00000020) /* recreate missing obj */
#define OBD_FL_DEBUG_CHECK   (0x00000040) /* echo client/server debug check */
#define OBD_FL_NO_USRQUOTA   (0x00000100) /* the object's owner is over quota */
#define OBD_FL_NO_GRPQUOTA   (0x00000200) /* the object's group is over quota */
#define OBD_FL_CREATE_CROW   (0x00000400) /* object should be create on write */

/*
 * set this to delegate DLM locking during obd_punch() to the OSTs. Only OSTs
 * that declared OBD_CONNECT_TRUNCLOCK in their connect flags support this
 * functionality.
 */
#define OBD_FL_TRUNCLOCK     (0x00000800)

/*
 * Checksum types
 */
#define OBD_FL_CKSUM_CRC32    (0x00001000)
#define OBD_FL_CKSUM_ADLER    (0x00002000)
#define OBD_FL_CKSUM_ALL      (OBD_FL_CKSUM_CRC32 | OBD_FL_CKSUM_ADLER)

#define LOV_MAGIC_V1      0x0BD10BD0
#define LOV_MAGIC         LOV_MAGIC_V1
#define LOV_MAGIC_JOIN    0x0BD20BD0
#define LOV_MAGIC_V3      0x0BD30BD0

#define LOV_PATTERN_RAID0 0x001   /* stripes are used round-robin */
#define LOV_PATTERN_RAID1 0x002   /* stripes are mirrors of each other */
#define LOV_PATTERN_FIRST 0x100   /* first stripe is not in round-robin */
#define LOV_PATTERN_CMOBD 0x200

#define LOV_OBJECT_GROUP_DEFAULT ~0ULL
#define LOV_OBJECT_GROUP_CLEAR 0ULL

#define MAXPOOLNAME 16
#define POOLNAMEF "%.16s"

#define lov_ost_data lov_ost_data_v1
struct lov_ost_data_v1 {          /* per-stripe data structure (little-endian)*/
        __u64 l_object_id;        /* OST object ID */
        __u64 l_object_gr;        /* OST object group (creating MDS number) */
        __u32 l_ost_gen;          /* generation of this l_ost_idx */
        __u32 l_ost_idx;          /* OST index in LOV (lov_tgt_desc->tgts) */
};

#define lov_mds_md lov_mds_md_v1
struct lov_mds_md_v1 {            /* LOV EA mds/wire data (little-endian) */
        __u32 lmm_magic;          /* magic number = LOV_MAGIC_V1 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u32 lmm_stripe_count;   /* num stripes in use for this object */
        struct lov_ost_data_v1 lmm_objects[0]; /* per-stripe data */
};

struct lov_mds_md_v3 {            /* LOV EA mds/wire data (little-endian) */
        __u32 lmm_magic;          /* magic number = LOV_MAGIC_V3 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u32 lmm_stripe_count;   /* num stripes in use for this object */
        char  lmm_pool_name[MAXPOOLNAME]; /* must be 32bit aligned */
        struct lov_ost_data_v1 lmm_objects[0]; /* per-stripe data */
};


#define OBD_MD_FLID        (0x00000001ULL) /* object ID */
#define OBD_MD_FLATIME     (0x00000002ULL) /* access time */
#define OBD_MD_FLMTIME     (0x00000004ULL) /* data modification time */
#define OBD_MD_FLCTIME     (0x00000008ULL) /* change time */
#define OBD_MD_FLSIZE      (0x00000010ULL) /* size */
#define OBD_MD_FLBLOCKS    (0x00000020ULL) /* allocated blocks count */
#define OBD_MD_FLBLKSZ     (0x00000040ULL) /* block size */
#define OBD_MD_FLMODE      (0x00000080ULL) /* access bits (mode & ~S_IFMT) */
#define OBD_MD_FLTYPE      (0x00000100ULL) /* object type (mode & S_IFMT) */
#define OBD_MD_FLUID       (0x00000200ULL) /* user ID */
#define OBD_MD_FLGID       (0x00000400ULL) /* group ID */
#define OBD_MD_FLFLAGS     (0x00000800ULL) /* flags word */
#define OBD_MD_FLNLINK     (0x00002000ULL) /* link count */
#define OBD_MD_FLGENER     (0x00004000ULL) /* generation number */
/*#define OBD_MD_FLINLINE      (0x00008000ULL) inline data. used until 1.6.5 */
#define OBD_MD_FLRDEV      (0x00010000ULL) /* device number */
#define OBD_MD_FLEASIZE    (0x00020000ULL) /* extended attribute data */
#define OBD_MD_LINKNAME    (0x00040000ULL) /* symbolic link target */
#define OBD_MD_FLHANDLE    (0x00080000ULL) /* file/lock handle */
#define OBD_MD_FLCKSUM     (0x00100000ULL) /* bulk data checksum */
#define OBD_MD_FLQOS       (0x00200000ULL) /* quality of service stats */
#define OBD_MD_FLOSCOPQ    (0x00400000ULL) /* osc opaque data */
#define OBD_MD_FLCOOKIE    (0x00800000ULL) /* log cancellation cookie */
#define OBD_MD_FLGROUP     (0x01000000ULL) /* group */
#define OBD_MD_FLFID       (0x02000000ULL) /* ->ost write inline fid */
#define OBD_MD_FLEPOCH     (0x04000000ULL) /* ->ost write easize is epoch */
#define OBD_MD_FLGRANT     (0x08000000ULL) /* ost preallocation space grant */
#define OBD_MD_FLDIREA     (0x10000000ULL) /* dir's extended attribute data */
#define OBD_MD_FLUSRQUOTA  (0x20000000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLGRPQUOTA  (0x40000000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLMODEASIZE (0x80000000ULL) /* EA size will be changed */

#define OBD_MD_MDS         (0x0000000100000000ULL) /* where an inode lives on */
#define OBD_MD_REINT       (0x0000000200000000ULL) /* reintegrate oa */
#define OBD_MD_MEA         (0x0000000400000000ULL) /* CMD split EA  */

#define OBD_MD_FLXATTR     (0x0000001000000000ULL) /* xattr */
#define OBD_MD_FLXATTRLS   (0x0000002000000000ULL) /* xattr list */
#define OBD_MD_FLXATTRRM   (0x0000004000000000ULL) /* xattr remove */
#define OBD_MD_FLACL       (0x0000008000000000ULL) /* ACL */
#define OBD_MD_FLRMTPERM   (0x0000010000000000ULL) /* remote permission */
#define OBD_MD_FLMDSCAPA   (0x0000020000000000ULL) /* MDS capability */
#define OBD_MD_FLOSSCAPA   (0x0000040000000000ULL) /* OSS capability */
#define OBD_MD_FLCKSPLIT   (0x0000080000000000ULL) /* Check split on server */
#define OBD_MD_FLCROSSREF  (0x0000100000000000ULL) /* Cross-ref case */


#define OBD_MD_FLGETATTR (OBD_MD_FLID    | OBD_MD_FLATIME | OBD_MD_FLMTIME | \
                          OBD_MD_FLCTIME | OBD_MD_FLSIZE  | OBD_MD_FLBLKSZ | \
                          OBD_MD_FLMODE  | OBD_MD_FLTYPE  | OBD_MD_FLUID   | \
                          OBD_MD_FLGID   | OBD_MD_FLFLAGS | OBD_MD_FLNLINK | \
                          OBD_MD_FLGENER | OBD_MD_FLRDEV  | OBD_MD_FLGROUP)


/* don't forget obdo_fid which is way down at the bottom so it can
 * come after the definition of llog_cookie */

struct obd_statfs {
        __u64           os_type;
        __u64           os_blocks;
        __u64           os_bfree;
        __u64           os_bavail;
        __u64           os_files;
        __u64           os_ffree;
        __u8            os_fsid[40];
        __u32           os_bsize;
        __u32           os_namelen;
        __u64           os_maxbytes;
        __u32           os_state;       /* positive error code on server */
        __u32           os_spare1;
        __u32           os_spare2;
        __u32           os_spare3;
        __u32           os_spare4;
        __u32           os_spare5;
        __u32           os_spare6;
        __u32           os_spare7;
        __u32           os_spare8;
        __u32           os_spare9;
};

extern void lustre_swab_obd_statfs (struct obd_statfs *os);
#define OBD_STATFS_NODELAY      0x0001  /* requests should be send without delay
                                         * and resends for avoid deadlocks */

#define OBD_STATFS_FROM_CACHE   0x0002  /* the statfs callback should not update
                                         * obd_osfs_age */

/* ost_body.data values for OST_BRW */

#define OBD_BRW_READ            0x01
#define OBD_BRW_WRITE           0x02
#define OBD_BRW_RWMASK          (OBD_BRW_READ | OBD_BRW_WRITE)
#define OBD_BRW_SYNC            0x08
#define OBD_BRW_CHECK           0x10
#define OBD_BRW_FROM_GRANT      0x20 /* the osc manages this under llite */
#define OBD_BRW_GRANTED         0x40 /* the ost manages this */
#define OBD_BRW_DROP            0x80 /* drop the page after IO */
#define OBD_BRW_NOQUOTA        0x100
#define OBD_BRW_SRVLOCK        0x200 /* Client holds no lock over this page */

#define OBD_OBJECT_EOF 0xffffffffffffffffULL

#define OST_MIN_PRECREATE 32
#define OST_MAX_PRECREATE 20000

struct obd_ioobj {
        obd_id               ioo_id;
        obd_gr               ioo_gr;
        __u32                ioo_type;
        __u32                ioo_bufcnt;
};

extern void lustre_swab_obd_ioobj (struct obd_ioobj *ioo);

/* multiple of 8 bytes => can array */
struct niobuf_remote {
        __u64 offset;
        __u32 len;
        __u32 flags;
};

extern void lustre_swab_niobuf_remote (struct niobuf_remote *nbr);

/* lock value block communicated between the filter and llite */

/* OST_LVB_ERR_INIT is needed because the return code in rc is 
 * negative, i.e. because ((MASK + rc) & MASK) != MASK. */
#define OST_LVB_ERR_INIT 0xffbadbad80000000ULL
#define OST_LVB_ERR_MASK 0xffbadbad00000000ULL
#define OST_LVB_IS_ERR(blocks)                                          \
        ((blocks & OST_LVB_ERR_MASK) == OST_LVB_ERR_MASK)
#define OST_LVB_SET_ERR(blocks, rc)                                     \
        do { blocks = OST_LVB_ERR_INIT + rc; } while (0)
#define OST_LVB_GET_ERR(blocks)    (int)(blocks - OST_LVB_ERR_INIT)

struct ost_lvb {
        __u64 lvb_size;
        __u64 lvb_mtime;
        __u64 lvb_atime;
        __u64 lvb_ctime;
        __u64 lvb_blocks;
};

extern void lustre_swab_ost_lvb(struct ost_lvb *);

/*
 *   MDS REQ RECORDS
 */

/* opcodes */
typedef enum {
        MDS_GETATTR      = 33,
        MDS_GETATTR_NAME = 34,
        MDS_CLOSE        = 35,
        MDS_REINT        = 36,
        MDS_READPAGE     = 37,
        MDS_CONNECT      = 38,
        MDS_DISCONNECT   = 39,
        MDS_GETSTATUS    = 40,
        MDS_STATFS       = 41,
        MDS_PIN          = 42,
        MDS_UNPIN        = 43,
        MDS_SYNC         = 44,
        MDS_DONE_WRITING = 45,
        MDS_SET_INFO     = 46,
        MDS_QUOTACHECK   = 47,
        MDS_QUOTACTL     = 48,
        MDS_GETXATTR     = 49,
        MDS_SETXATTR     = 50,
        MDS_LAST_OPC
} mds_cmd_t;

#define MDS_FIRST_OPC    MDS_GETATTR

/*
 * Do not exceed 63
 */

typedef enum {
        REINT_SETATTR  = 1,
        REINT_CREATE   = 2,
        REINT_LINK     = 3,
        REINT_UNLINK   = 4,
        REINT_RENAME   = 5,
        REINT_OPEN     = 6,
        REINT_SETXATTR = 7,
//      REINT_CLOSE    = 8,
//      REINT_WRITE    = 9,
        REINT_MAX
} mds_reint_t;

/* the disposition of the intent outlines what was executed */
#define DISP_IT_EXECD        0x00000001
#define DISP_LOOKUP_EXECD    0x00000002
#define DISP_LOOKUP_NEG      0x00000004
#define DISP_LOOKUP_POS      0x00000008
#define DISP_OPEN_CREATE     0x00000010
#define DISP_OPEN_OPEN       0x00000020
#define DISP_ENQ_COMPLETE    0x00400000
#define DISP_ENQ_OPEN_REF    0x00800000
#define DISP_ENQ_CREATE_REF  0x01000000
#define DISP_OPEN_LOCK       0x02000000

/* INODE LOCK PARTS */
#define MDS_INODELOCK_LOOKUP 0x000001       /* dentry, mode, owner, group */
#define MDS_INODELOCK_UPDATE 0x000002       /* size, links, timestamps */
#define MDS_INODELOCK_OPEN   0x000004       /* For opened files */

/* Do not forget to increase MDS_INODELOCK_MAXSHIFT when adding new bits */
#define MDS_INODELOCK_MAXSHIFT 2
/* This FULL lock is useful to take on unlink sort of operations */
#define MDS_INODELOCK_FULL ((1<<(MDS_INODELOCK_MAXSHIFT+1))-1)

extern void lustre_swab_ll_fid (struct ll_fid *fid);

struct lu_fid {
        __u64 f_seq;  /* holds fid sequence. Lustre should support 2^64
                       * objects, thus even if one sequence has one object we
                       * reach this value. */
        __u32 f_oid;  /* fid number within its sequence. */
        __u32 f_ver;  /* holds fid version. */
};

#define DFID "[0x%16.16"LPF64"x/0x%8.8x:0x%8.8x]"

#define PFID(fid)     \
        fid_seq(fid), \
        fid_oid(fid), \
        fid_ver(fid)

enum { 
        /** put FID sequence at this offset in ldlm_res_id. */
        LUSTRE_RES_ID_SEQ_OFF = 0,
        /** put FID oid at this offset in ldlm_res_id. */
        LUSTRE_RES_ID_OID_OFF = 1,
        /** put FID version at this offset in ldlm_res_id. */
        LUSTRE_RES_ID_VER_OFF = 2,
        /** put pdo hash at this offset in ldlm_res_id. */
        LUSTRE_RES_ID_HSH_OFF = 3
};

typedef __u64 seqno_t;

struct lu_range {
        __u64 lr_start;
        __u64 lr_end;
};

static inline __u64 range_space(struct lu_range *r)
{
        return r->lr_end - r->lr_start;
}

static inline void range_zero(struct lu_range *r)
{
        r->lr_start = r->lr_end = 0;
}

static inline int range_within(struct lu_range *r,
                               __u64 s)
{
        return s >= r->lr_start && s < r->lr_end;
}

static inline void range_alloc(struct lu_range *r,
                               struct lu_range *s,
                               __u64 w)
{
        r->lr_start = s->lr_start;
        r->lr_end = s->lr_start + w;
        s->lr_start += w;
}
static inline int range_is_sane(struct lu_range *r)
{
        return (r->lr_end >= r->lr_start);
}

static inline int range_is_zero(struct lu_range *r)
{
        return (r->lr_start == 0 && r->lr_end == 0);
}

static inline int range_is_exhausted(struct lu_range *r)
{
        return range_space(r) == 0;
}

#define DRANGE "[%#16.16"LPF64"x-%#16.16"LPF64"x]"

#define PRANGE(range)      \
        (range)->lr_start, \
        (range)->lr_end

enum {
        /*
         * This is how may FIDs may be allocated in one sequence.
         */
        LUSTRE_SEQ_MAX_WIDTH = 0x0000000000004000ULL,
};

enum lu_cli_type {
        LUSTRE_SEQ_METADATA,
        LUSTRE_SEQ_DATA
};

struct lu_client_seq {
        /* Sequence-controller export. */
        struct obd_export      *lcs_exp;
        struct semaphore        lcs_sem;

        /*
         * Range of allowed for allocation sequences. When using lu_client_seq
         * on clients, this contains meta-sequence range. And for servers this
         * contains super-sequence range.
         */
        struct lu_range         lcs_space;

        /* This holds last allocated fid in last obtained seq */
        struct lu_fid           lcs_fid;

        /* LUSTRE_SEQ_METADATA or LUSTRE_SEQ_DATA */
        enum lu_cli_type        lcs_type;
        /*
         * Service uuid, passed from MDT + seq name to form unique seq name to
         * use it with procfs.
         */
        char                    lcs_name[80];

        /*
         * Sequence width, that is how many objects may be allocated in one
         * sequence. Default value for it is LUSTRE_SEQ_MAX_WIDTH.
         */
        __u64                   lcs_width;

};

/*
 * fid constants
 */
enum {
        /* initial fid id value */
        LUSTRE_FID_INIT_OID  = 1UL
};

extern void lustre_swab_lu_fid(struct lu_fid *fid);

/* get object sequence */
static inline __u64 fid_seq(const struct lu_fid *fid)
{
        return fid->f_seq;
}

/* get object id */
static inline __u32 fid_oid(const struct lu_fid *fid)
{
        return fid->f_oid;
}

/* get object version */
static inline __u32 fid_ver(const struct lu_fid *fid)
{
        return fid->f_ver;
}

static inline void fid_init(struct lu_fid *fid)
{
        memset(fid, 0, sizeof(*fid));
}

/* Normal FID sequence starts from this value, i.e. 1<<33 */
#define FID_SEQ_START  0x200000000ULL

/* IDIF sequence starts from this value, i.e. 1<<32 */
#define IDIF_SEQ_START 0x100000000ULL

/**
 * Check if a fid is igif or not.
 * \param fid the fid to be tested.
 * \return true if the fid is a igif; otherwise false. 
 */
static inline int fid_is_igif(const struct lu_fid *fid)
{
        return fid_seq(fid) > 0 && fid_seq(fid) < IDIF_SEQ_START;
}

/**
 * Check if a fid is idif or not.
 * \param fid the fid to be tested.
 * \return true if the fid is a idif; otherwise false. 
 */
static inline int fid_is_idif(const struct lu_fid *fid)
{
        return fid_seq(fid) >= IDIF_SEQ_START  && fid_seq(fid) < FID_SEQ_START;
}

/**
 * Check if a fid is zero.
 * \param fid the fid to be tested.
 * \return true if the fid is zero; otherwise false. 
 */
static inline int fid_is_zero(const struct lu_fid *fid)
{
        return fid_seq(fid) == 0 && fid_oid(fid) == 0;
}

/**
 * Get inode number from a igif.
 * \param fid a igif to get inode number from.
 * \return inode number for the igif.
 */
static inline ino_t lu_igif_ino(const struct lu_fid *fid)
{
        return fid_seq(fid);
}

/**
 * Get inode generation from a igif.
 * \param fid a igif to get inode generation from.
 * \return inode generation for the igif.
 */ 
static inline __u32 lu_igif_gen(const struct lu_fid *fid)
{
        return fid_oid(fid);
}

/**
 * Check if two fids are equal or not.
 * \param f0 the first fid
 * \param f1 the second fid
 * \return true if the two fids are equal; otherwise false. 
 */
static inline int lu_fid_eq(const struct lu_fid *f0,
                            const struct lu_fid *f1)
{
        /* Check that there is no alignment padding. */
        CLASSERT(sizeof *f0 ==
                 sizeof f0->f_seq + sizeof f0->f_oid + sizeof f0->f_ver);
        LASSERTF(fid_is_igif(f0) || fid_ver(f0) == 0, DFID"\n", PFID(f0));
        LASSERTF(fid_is_igif(f1) || fid_ver(f1) == 0, DFID"\n", PFID(f1));
        return memcmp(f0, f1, sizeof *f0) == 0;
}

void fid_cpu_to_le(struct lu_fid *dst, const struct lu_fid *src);
void fid_le_to_cpu(struct lu_fid *dst, const struct lu_fid *src);

struct ldlm_res_id *
fid_build_reg_res_name(const struct lu_fid *f, struct ldlm_res_id *name);
int fid_res_name_eq(const struct lu_fid *f, const struct ldlm_res_id *name);

#define MDS_STATUS_CONN 1
#define MDS_STATUS_LOV 2

struct mds_status_req {
        __u32  flags;
        __u32  repbuf;
};

extern void lustre_swab_mds_status_req (struct mds_status_req *r);

#define MDS_BFLAG_UNCOMMITTED_WRITES   0x1
#define MDS_BFLAG_EXT_FLAGS     0x80000000 /* == EXT3_RESERVED_FL */

/* these should be identical to their EXT3_*_FL counterparts, and are
 * redefined here only to avoid dragging in ext3_fs.h */
#define MDS_SYNC_FL             0x00000008 /* Synchronous updates */
#define MDS_IMMUTABLE_FL        0x00000010 /* Immutable file */
#define MDS_APPEND_FL           0x00000020 /* writes to file may only append */
#define MDS_NOATIME_FL          0x00000080 /* do not update atime */
#define MDS_DIRSYNC_FL          0x00010000 /* dirsync behaviour (dir only) */

#ifdef __KERNEL__
/* If MDS_BFLAG_IOC_FLAGS is set it means we requested EXT3_*_FL inode flags
 * and we need to decode these into local S_* flags in the inode.  Otherwise
 * we pass flags straight through (see bug 9486). */
static inline int ll_ext_to_inode_flags(int flags)
{
        return (flags & MDS_BFLAG_EXT_FLAGS) ?
               (((flags & MDS_SYNC_FL)      ? S_SYNC      : 0) |
                ((flags & MDS_NOATIME_FL)   ? S_NOATIME   : 0) |
                ((flags & MDS_APPEND_FL)    ? S_APPEND    : 0) |
#if defined(S_DIRSYNC)
                ((flags & MDS_DIRSYNC_FL)   ? S_DIRSYNC   : 0) |
#endif
                ((flags & MDS_IMMUTABLE_FL) ? S_IMMUTABLE : 0)) :
               (flags & ~MDS_BFLAG_EXT_FLAGS);
}

/* If keep is set, we do not do anything with iflags, if it is not set, we
 * assume that iflags are inode flags and we need to conver those to
 * EXT3_*_FL flags (see bug 9486 and 12848) */
static inline int ll_inode_to_ext_flags(int iflags, int keep)
{
        return keep ? (iflags & ~MDS_BFLAG_EXT_FLAGS) :
                (((iflags & S_SYNC)     ? MDS_SYNC_FL      : 0) |
                ((iflags & S_NOATIME)   ? MDS_NOATIME_FL   : 0) |
                ((iflags & S_APPEND)    ? MDS_APPEND_FL    : 0) |
#if defined(S_DIRSYNC)
                ((iflags & S_DIRSYNC)   ? MDS_DIRSYNC_FL   : 0) |
#endif
                ((iflags & S_IMMUTABLE) ? MDS_IMMUTABLE_FL : 0));
}
#endif

struct mds_body {
        struct ll_fid  fid1;
        struct ll_fid  fid2;
        struct lustre_handle handle;
        __u64          valid;
        __u64          size;   /* Offset, in the case of MDS_READPAGE */
        __u64          mtime;
        __u64          atime;
        __u64          ctime;
        __u64          blocks; /* XID, in the case of MDS_READPAGE */
        __u64          io_epoch;
        __u64          ino;
        __u32          fsuid;
        __u32          fsgid;
        __u32          capability;
        __u32          mode;
        __u32          uid;
        __u32          gid;
        __u32          flags; /* from vfs for pin/unpin, MDS_BFLAG for close */
        __u32          rdev;
        __u32          nlink; /* #bytes to read in the case of MDS_READPAGE */
        __u32          generation;
        __u32          suppgid;
        __u32          eadatasize;
        __u32          aclsize;
        __u32          max_mdsize;
        __u32          max_cookiesize; /* also fix lustre_swab_mds_body */
        __u32          padding_4; /* also fix lustre_swab_mds_body */
};

extern void lustre_swab_mds_body (struct mds_body *b);

/* struct mdt_body is only used for size checking.
 * mdt_body & mds_body should have the same size.
 */
struct mdt_body {
        struct lu_fid  fid1;
        struct lu_fid  fid2;
        struct lustre_handle handle;
        __u64          valid;
        __u64          size;   /* Offset, in the case of MDS_READPAGE */
        __u64          mtime;
        __u64          atime;
        __u64          ctime;
        __u64          blocks; /* XID, in the case of MDS_READPAGE */
        __u64          ioepoch;
        __u64          ino;    /* for 1.6 compatibility */
        __u32          fsuid;
        __u32          fsgid;
        __u32          capability;
        __u32          mode;
        __u32          uid;
        __u32          gid;
        __u32          flags; /* from vfs for pin/unpin, MDS_BFLAG for close */
        __u32          rdev;
        __u32          nlink; /* #bytes to read in the case of MDS_READPAGE */
        __u32          generation; /* for 1.6 compatibility */
        __u32          suppgid;
        __u32          eadatasize;
        __u32          aclsize;
        __u32          max_mdsize;
        __u32          max_cookiesize;
        __u32          padding_4; /* also fix lustre_swab_mdt_body */
};

#define Q_QUOTACHECK    0x800100
#define Q_INITQUOTA     0x800101        /* init slave limits */
#define Q_GETOINFO      0x800102        /* get obd quota info */
#define Q_GETOQUOTA     0x800103        /* get obd quotas */
#define Q_FINVALIDATE   0x800104        /* invalidate operational quotas */

#define Q_TYPEMATCH(id, type) \
        ((id) == (type) || (id) == UGQUOTA)

#define Q_TYPESET(oqc, type) Q_TYPEMATCH((oqc)->qc_type, type)

#define Q_GETOCMD(oqc) \
        ((oqc)->qc_cmd == Q_GETOINFO || (oqc)->qc_cmd == Q_GETOQUOTA)

struct obd_quotactl {
        __u32                   qc_cmd;
        __u32                   qc_type;
        __u32                   qc_id;
        __u32                   qc_stat;
        struct obd_dqinfo       qc_dqinfo;
        struct obd_dqblk        qc_dqblk;
};

extern void lustre_swab_obd_quotactl(struct obd_quotactl *q);

struct quota_adjust_qunit {
        __u32 qaq_flags;
        __u32 qaq_id;
        __u64 qaq_bunit_sz;
        __u64 qaq_iunit_sz;
        __u64 padding1;
};
extern void lustre_swab_quota_adjust_qunit(struct quota_adjust_qunit *q);

/* flags in qunit_data and quota_adjust_qunit will use macroes below */
#define LQUOTA_FLAGS_GRP       1UL   /* 0 is user, 1 is group */
#define LQUOTA_FLAGS_BLK       2UL   /* 0 is inode, 1 is block */
#define LQUOTA_FLAGS_ADJBLK    4UL   /* adjust the block qunit size */
#define LQUOTA_FLAGS_ADJINO    8UL   /* adjust the inode qunit size */
#define LQUOTA_FLAGS_CHG_QS   16UL   /* indicate whether it has capability of
                                      * OBD_CONNECT_CHANGE_QS */

/* the status of lqs_flags in struct lustre_qunit_size  */
#define LQUOTA_QUNIT_FLAGS (LQUOTA_FLAGS_GRP | LQUOTA_FLAGS_BLK)

#define QAQ_IS_GRP(qaq)    ((qaq)->qaq_flags & LQUOTA_FLAGS_GRP)
#define QAQ_IS_ADJBLK(qaq) ((qaq)->qaq_flags & LQUOTA_FLAGS_ADJBLK)
#define QAQ_IS_ADJINO(qaq) ((qaq)->qaq_flags & LQUOTA_FLAGS_ADJINO)

#define QAQ_SET_GRP(qaq)    ((qaq)->qaq_flags |= LQUOTA_FLAGS_GRP)
#define QAQ_SET_ADJBLK(qaq) ((qaq)->qaq_flags |= LQUOTA_FLAGS_ADJBLK)
#define QAQ_SET_ADJINO(qaq) ((qaq)->qaq_flags |= LQUOTA_FLAGS_ADJINO)

struct mds_rec_setattr {
        __u32           sa_opcode;
        __u32           sa_fsuid;
        __u32           sa_fsgid;
        __u32           sa_cap;
        __u32           sa_suppgid;
        __u32           sa_mode;
        struct ll_fid   sa_fid;
        __u64           sa_valid; /* MDS_ATTR_* attributes */
        __u64           sa_size;
        __u64           sa_mtime;
        __u64           sa_atime;
        __u64           sa_ctime;
        __u32           sa_uid;
        __u32           sa_gid;
        __u32           sa_attr_flags;
        __u32           sa_padding; /* also fix lustre_swab_mds_rec_setattr */
};

/*
 * Attribute flags used in mds_rec_setattr::sa_valid.
 * The kernel's #defines for ATTR_* should not be used over the network
 * since the client and MDS may run different kernels (see bug 13828)
 * Therefore, we should only use MDS_ATTR_* attributes for sa_valid.
 */
#define MDS_ATTR_MODE          0x1ULL /* = 1 */
#define MDS_ATTR_UID           0x2ULL /* = 2 */
#define MDS_ATTR_GID           0x4ULL /* = 4 */
#define MDS_ATTR_SIZE          0x8ULL /* = 8 */
#define MDS_ATTR_ATIME        0x10ULL /* = 16 */
#define MDS_ATTR_MTIME        0x20ULL /* = 32 */
#define MDS_ATTR_CTIME        0x40ULL /* = 64 */
#define MDS_ATTR_ATIME_SET    0x80ULL /* = 128 */
#define MDS_ATTR_MTIME_SET   0x100ULL /* = 256 */
#define MDS_ATTR_FORCE       0x200ULL /* = 512, Not a change, but a change it */
#define MDS_ATTR_ATTR_FLAG   0x400ULL /* = 1024 */
#define MDS_ATTR_KILL_SUID   0x800ULL /* = 2048 */
#define MDS_ATTR_KILL_SGID  0x1000ULL /* = 4096 */
#define MDS_ATTR_CTIME_SET  0x2000ULL /* = 8192 */
#define MDS_ATTR_FROM_OPEN  0x4000ULL /* = 16384, called from open path, ie O_TRUNC */
#define MDS_ATTR_BLOCKS     0x8000ULL /* = 32768 */

extern void lustre_swab_mds_rec_setattr (struct mds_rec_setattr *sa);

#ifndef FMODE_READ
#define FMODE_READ               00000001
#define FMODE_WRITE              00000002
#endif
#define MDS_FMODE_EXEC           00000004
#define MDS_OPEN_CREAT           00000100
#define MDS_OPEN_EXCL            00000200
#define MDS_OPEN_TRUNC           00001000
#define MDS_OPEN_APPEND          00002000
#define MDS_OPEN_SYNC            00010000
#define MDS_OPEN_DIRECTORY       00200000

#define MDS_OPEN_DELAY_CREATE  0100000000 /* delay initial object create */
#define MDS_OPEN_OWNEROVERRIDE 0200000000 /* NFSD rw-reopen ro file for owner */
#define MDS_OPEN_JOIN_FILE     0400000000 /* open for join file*/
#define MDS_OPEN_LOCK         04000000000 /* This open requires open lock */
#define MDS_OPEN_HAS_EA      010000000000 /* specify object create pattern */
#define MDS_OPEN_HAS_OBJS    020000000000 /* Just set the EA the obj exist */

struct mds_rec_create {
        __u32           cr_opcode;
        __u32           cr_fsuid;
        __u32           cr_fsgid;
        __u32           cr_cap;
        __u32           cr_flags; /* for use with open */
        __u32           cr_mode;
        struct ll_fid   cr_fid;
        struct ll_fid   cr_replayfid;
        __u64           cr_time;
        __u64           cr_rdev;
        __u32           cr_suppgid;
        __u32           cr_padding_1; /* also fix lustre_swab_mds_rec_create */
        __u32           cr_padding_2; /* also fix lustre_swab_mds_rec_create */
        __u32           cr_padding_3; /* also fix lustre_swab_mds_rec_create */
        __u32           cr_padding_4; /* also fix lustre_swab_mds_rec_create */
        __u32           cr_padding_5; /* also fix lustre_swab_mds_rec_create */
};

extern void lustre_swab_mds_rec_create (struct mds_rec_create *cr);

struct mdt_rec_create {
        __u32           cr_opcode;
        __u32           cr_fsuid;
        __u32           cr_fsgid;
        __u32           cr_cap;
        __u32           cr_suppgid1;
        __u32           cr_suppgid2;
        struct lu_fid   cr_fid1;
        struct lu_fid   cr_fid2;
        struct lustre_handle cr_old_handle; /* handle in case of open replay */
        __u64           cr_time;
        __u64           cr_rdev;
        __u64           cr_ioepoch;
        __u64           cr_padding_1; /* pad for 64 bits*/
        __u32           cr_mode;
        __u32           cr_bias;
        __u32           cr_flags;     /* for use with open */
        __u32           cr_padding_2; /* pad for 64 bits*/
        __u32           cr_padding_3; /* pad for 64 bits*/
        __u32           cr_padding_4; /* pad for 64 bits*/
};

struct mdt_epoch {
        struct lustre_handle handle;
        __u64  ioepoch;
        __u32  flags;
        __u32  padding;
};

struct mds_rec_join {
        struct ll_fid  jr_fid;
        __u64          jr_headsize;
};

extern void lustre_swab_mds_rec_join (struct mds_rec_join *jr);

struct mdt_rec_join {
        struct lu_fid  jr_fid;
        __u64          jr_headsize;
};


struct mds_rec_link {
        __u32           lk_opcode;
        __u32           lk_fsuid;
        __u32           lk_fsgid;
        __u32           lk_cap;
        __u32           lk_suppgid1;
        __u32           lk_suppgid2;
        struct ll_fid   lk_fid1;
        struct ll_fid   lk_fid2;
        __u64           lk_time;
        __u32           lk_padding_1;  /* also fix lustre_swab_mds_rec_link */
        __u32           lk_padding_2;  /* also fix lustre_swab_mds_rec_link */
        __u32           lk_padding_3;  /* also fix lustre_swab_mds_rec_link */
        __u32           lk_padding_4;  /* also fix lustre_swab_mds_rec_link */
};

extern void lustre_swab_mds_rec_link (struct mds_rec_link *lk);

struct mdt_rec_link {
        __u32           lk_opcode;
        __u32           lk_fsuid;
        __u32           lk_fsgid;
        __u32           lk_cap;
        __u32           lk_suppgid1;
        __u32           lk_suppgid2;
        struct lu_fid   lk_fid1;
        struct lu_fid   lk_fid2;
        __u64           lk_time;
        __u64           lk_padding_1;
        __u64           lk_padding_2;
        __u64           lk_padding_3;
        __u64           lk_padding_4;
        __u32           lk_bias;
        __u32           lk_padding_5;
        __u32           lk_padding_6;
        __u32           lk_padding_7;
        __u32           lk_padding_8;
        __u32           lk_padding_9;
};

struct mds_rec_unlink {
        __u32           ul_opcode;
        __u32           ul_fsuid;
        __u32           ul_fsgid;
        __u32           ul_cap;
        __u32           ul_suppgid;
        __u32           ul_mode;
        struct ll_fid   ul_fid1;
        struct ll_fid   ul_fid2;
        __u64           ul_time;
        __u32           ul_padding_1; /* also fix lustre_swab_mds_rec_unlink */
        __u32           ul_padding_2; /* also fix lustre_swab_mds_rec_unlink */
        __u32           ul_padding_3; /* also fix lustre_swab_mds_rec_unlink */
        __u32           ul_padding_4; /* also fix lustre_swab_mds_rec_unlink */
};

extern void lustre_swab_mds_rec_unlink (struct mds_rec_unlink *ul);

struct mdt_rec_unlink {
        __u32           ul_opcode;
        __u32           ul_fsuid;
        __u32           ul_fsgid;
        __u32           ul_cap;
        __u32           ul_suppgid1;
        __u32           ul_padding2;
        struct lu_fid   ul_fid1;
        struct lu_fid   ul_fid2;
        __u64           ul_time;
        __u64           ul_padding_2;
        __u64           ul_padding_3;
        __u64           ul_padding_4;
        __u64           ul_padding_5;
        __u32           ul_bias;
        __u32           ul_mode;
        __u32           ul_padding_6;
        __u32           ul_padding_7;
        __u32           ul_padding_8;
        __u32           ul_padding_9;
};

struct mds_rec_rename {
        __u32           rn_opcode;
        __u32           rn_fsuid;
        __u32           rn_fsgid;
        __u32           rn_cap;
        __u32           rn_suppgid1;
        __u32           rn_suppgid2;
        struct ll_fid   rn_fid1;
        struct ll_fid   rn_fid2;
        __u64           rn_time;
        __u32           rn_padding_1; /* also fix lustre_swab_mds_rec_rename */
        __u32           rn_padding_2; /* also fix lustre_swab_mds_rec_rename */
        __u32           rn_padding_3; /* also fix lustre_swab_mds_rec_rename */
        __u32           rn_padding_4; /* also fix lustre_swab_mds_rec_rename */
};

extern void lustre_swab_mds_rec_rename (struct mds_rec_rename *rn);

struct mdt_rec_rename {
        __u32           rn_opcode;
        __u32           rn_fsuid;
        __u32           rn_fsgid;
        __u32           rn_cap;
        __u32           rn_suppgid1;
        __u32           rn_suppgid2;
        struct lu_fid   rn_fid1;
        struct lu_fid   rn_fid2;
        __u64           rn_time;
        __u64           rn_padding_1;
        __u64           rn_padding_2;
        __u64           rn_padding_3;
        __u64           rn_padding_4;
        __u32           rn_bias;      /* some operation flags */
        __u32           rn_mode;      /* cross-ref rename has mode */
        __u32           rn_padding_5;
        __u32           rn_padding_6;
        __u32           rn_padding_7;
        __u32           rn_padding_8;
};

struct mdt_rec_setattr {
        __u32           sa_opcode;
        __u32           sa_fsuid;
        __u32           sa_fsgid;
        __u32           sa_cap;
        __u32           sa_suppgid;
        __u32           sa_padding_1;
        struct lu_fid   sa_fid;
        __u64           sa_valid;
        __u32           sa_uid;
        __u32           sa_gid;
        __u64           sa_size;
        __u64           sa_blocks;
        __u64           sa_mtime;
        __u64           sa_atime;
        __u64           sa_ctime;
        __u32           sa_attr_flags;
        __u32           sa_mode;
        __u32           sa_padding_2;
        __u32           sa_padding_3;
        __u32           sa_padding_4;
        __u32           sa_padding_5;
};

struct mdt_rec_setxattr {
        __u32           sx_opcode;
        __u32           sx_fsuid;
        __u32           sx_fsgid;
        __u32           sx_cap;
        __u32           sx_suppgid1;
        __u32           sx_suppgid2;
        struct lu_fid   sx_fid;
        __u64           sx_padding_1; /* These three members are lu_fid size */
        __u32           sx_padding_2;
        __u32           sx_padding_3;
        __u64           sx_valid;
        __u64           sx_padding_4;
        __u64           sx_padding_5;
        __u64           sx_padding_6;
        __u64           sx_padding_7;
        __u32           sx_size;
        __u32           sx_flags;
        __u32           sx_padding_8;
        __u32           sx_padding_9;
        __u32           sx_padding_10;
        __u32           sx_padding_11;
};

/*
 * capa related definitions
 */
#define CAPA_HMAC_MAX_LEN       64
#define CAPA_HMAC_KEY_MAX_LEN   56

/* NB take care when changing the sequence of elements this struct,
 * because the offset info is used in find_capa() */
struct lustre_capa {
        struct lu_fid   lc_fid;     /* fid */
        __u64           lc_opc;     /* operations allowed */
        __u32           lc_uid;     /* uid, it is obsolete, but maybe used in
                                     * future, reserve it for 64-bits aligned.*/
        __u32           lc_flags;   /* HMAC algorithm & flags */
        __u32           lc_keyid;   /* key used for the capability */
        __u32           lc_timeout; /* capa timeout value (sec) */
        __u64           lc_expiry;  /* expiry time (sec) */
        __u8            lc_hmac[CAPA_HMAC_MAX_LEN];   /* HMAC */
} __attribute__((packed));


/*
 *  LOV data structures
 */

#define LOV_MIN_STRIPE_SIZE 65536   /* maximum PAGE_SIZE (ia64), power of 2 */
#define LOV_MAX_STRIPE_COUNT  160   /* until bug 4424 is fixed */
#define LOV_V1_INSANE_STRIPE_COUNT 65532 /* maximum stripe count bz13933 */

#define LOV_MAX_UUID_BUFFER_SIZE  8192
/* The size of the buffer the lov/mdc reserves for the
 * array of UUIDs returned by the MDS.  With the current
 * protocol, this will limit the max number of OSTs per LOV */

#define LOV_DESC_MAGIC 0xB0CCDE5C

/* LOV settings descriptor (should only contain static info) */
struct lov_desc {
        __u32 ld_tgt_count;                /* how many OBD's */
        __u32 ld_active_tgt_count;         /* how many active */
        __u32 ld_default_stripe_count;     /* how many objects are used */
        __u32 ld_pattern;                  /* default PATTERN_RAID0 */
        __u64 ld_default_stripe_size;      /* in bytes */
        __u64 ld_default_stripe_offset;    /* in bytes */
        __u32 ld_padding_0;                /* unused */
        __u32 ld_qos_maxage;               /* in second */
        __u32 ld_padding_1;                /* also fix lustre_swab_lov_desc */
        __u32 ld_padding_2;                /* also fix lustre_swab_lov_desc */
        struct obd_uuid ld_uuid;
};

#define ld_magic ld_active_tgt_count       /* for swabbing from llogs */

extern void lustre_swab_lov_desc (struct lov_desc *ld);

/*
 *   LDLM requests:
 */
/* opcodes -- MUST be distinct from OST/MDS opcodes */
typedef enum {
        LDLM_ENQUEUE     = 101,
        LDLM_CONVERT     = 102,
        LDLM_CANCEL      = 103,
        LDLM_BL_CALLBACK = 104,
        LDLM_CP_CALLBACK = 105,
        LDLM_GL_CALLBACK = 106,
        LDLM_LAST_OPC
} ldlm_cmd_t;
#define LDLM_FIRST_OPC LDLM_ENQUEUE

#define RES_NAME_SIZE 4
struct ldlm_res_id {
        __u64 name[RES_NAME_SIZE];
};

extern void lustre_swab_ldlm_res_id (struct ldlm_res_id *id);

/* lock types */
typedef enum {
        LCK_MINMODE = 0,
        LCK_EX = 1,
        LCK_PW = 2,
        LCK_PR = 4,
        LCK_CW = 8,
        LCK_CR = 16,
        LCK_NL = 32,
        LCK_GROUP = 64,
        LCK_MAXMODE
} ldlm_mode_t;

#define LCK_MODE_NUM    7

typedef enum {
        LDLM_PLAIN     = 10,
        LDLM_EXTENT    = 11,
        LDLM_FLOCK     = 12,
        LDLM_IBITS     = 13,
        LDLM_MAX_TYPE
} ldlm_type_t;

#define LDLM_MIN_TYPE LDLM_PLAIN

struct ldlm_extent {
        __u64 start;
        __u64 end;
        __u64 gid;
};

static inline int ldlm_extent_overlap(struct ldlm_extent *ex1,
                                      struct ldlm_extent *ex2)
{
        return (ex1->start <= ex2->end) && (ex2->start <= ex1->end);
}

struct ldlm_inodebits {
        __u64 bits;
};

struct ldlm_flock {
        __u64 start;
        __u64 end;
        __u64 blocking_export;  /* not actually used over the wire */
        __u32 blocking_pid;     /* not actually used over the wire */
        __u32 pid;
};

/* it's important that the fields of the ldlm_extent structure match
 * the first fields of the ldlm_flock structure because there is only
 * one ldlm_swab routine to process the ldlm_policy_data_t union. if
 * this ever changes we will need to swab the union differently based
 * on the resource type. */

typedef union {
        struct ldlm_extent l_extent;
        struct ldlm_flock  l_flock;
        struct ldlm_inodebits l_inodebits;
} ldlm_policy_data_t;

extern void lustre_swab_ldlm_policy_data (ldlm_policy_data_t *d);

struct ldlm_intent {
        __u64 opc;
};

extern void lustre_swab_ldlm_intent (struct ldlm_intent *i);

struct ldlm_resource_desc {
        ldlm_type_t lr_type;
        __u32 lr_padding;       /* also fix lustre_swab_ldlm_resource_desc */
        struct ldlm_res_id lr_name;
};

extern void lustre_swab_ldlm_resource_desc (struct ldlm_resource_desc *r);

struct ldlm_lock_desc {
        struct ldlm_resource_desc l_resource;
        ldlm_mode_t l_req_mode;
        ldlm_mode_t l_granted_mode;
        ldlm_policy_data_t l_policy_data;
};

extern void lustre_swab_ldlm_lock_desc (struct ldlm_lock_desc *l);

#define LDLM_LOCKREQ_HANDLES 2
#define LDLM_ENQUEUE_CANCEL_OFF 1

struct ldlm_request {
        __u32 lock_flags;
        __u32 lock_count;
        struct ldlm_lock_desc lock_desc;
        struct lustre_handle lock_handle[LDLM_LOCKREQ_HANDLES];
};

/* If LDLM_ENQUEUE, 1 slot is already occupied, 1 is available.
 * Otherwise, 2 are available. */
#define ldlm_request_bufsize(count,type)                                \
({                                                                      \
        int _avail = LDLM_LOCKREQ_HANDLES;                              \
        _avail -= (type == LDLM_ENQUEUE ? LDLM_ENQUEUE_CANCEL_OFF : 0); \
        sizeof(struct ldlm_request) +                                   \
        (count - _avail > 0 ? count - _avail : 0) *                     \
        sizeof(struct lustre_handle);                                   \
})

extern void lustre_swab_ldlm_request (struct ldlm_request *rq);

struct ldlm_reply {
        __u32 lock_flags;
        __u32 lock_padding;     /* also fix lustre_swab_ldlm_reply */
        struct ldlm_lock_desc lock_desc;
        struct lustre_handle lock_handle;
        __u64  lock_policy_res1;
        __u64  lock_policy_res2;
};

extern void lustre_swab_ldlm_reply (struct ldlm_reply *r);


/*
 * Opcodes for mountconf (mgs and mgc)
 */
typedef enum {
        MGS_CONNECT = 250,
        MGS_DISCONNECT,
        MGS_EXCEPTION,         /* node died, etc. */
        MGS_TARGET_REG,        /* whenever target starts up */
        MGS_TARGET_DEL,
        MGS_SET_INFO,
        MGS_LAST_OPC
} mgs_cmd_t;
#define MGS_FIRST_OPC MGS_CONNECT

#define MGS_PARAM_MAXLEN 1024
#define KEY_SET_INFO "set_info"

struct mgs_send_param {
        char             mgs_param[MGS_PARAM_MAXLEN];
};

/* We pass this info to the MGS so it can write config logs */
#define MTI_NAME_MAXLEN 64
#define MTI_PARAM_MAXLEN 4096
#define MTI_NIDS_MAX 32
struct mgs_target_info {
        __u32            mti_lustre_ver;
        __u32            mti_stripe_index;
        __u32            mti_config_ver;
        __u32            mti_flags;
        __u32            mti_nid_count;
        __u32            padding;                    /* 64 bit align */
        char             mti_fsname[MTI_NAME_MAXLEN];
        char             mti_svname[MTI_NAME_MAXLEN];
        char             mti_uuid[sizeof(struct obd_uuid)];
        __u64            mti_nids[MTI_NIDS_MAX];     /* host nids (lnet_nid_t)*/
        char             mti_params[MTI_PARAM_MAXLEN];
};

extern void lustre_swab_mgs_target_info(struct mgs_target_info *oinfo);

/* Config marker flags (in config log) */
#define CM_START       0x01
#define CM_END         0x02
#define CM_SKIP        0x04
#define CM_UPGRADE146  0x08
#define CM_EXCLUDE     0x10
#define CM_START_SKIP (CM_START | CM_SKIP)

struct cfg_marker {
        __u32             cm_step;       /* aka config version */
        __u32             cm_flags;
        __u32             cm_vers;       /* lustre release version number */
        __u32             padding;       /* 64 bit align */
        time_t            cm_createtime; /*when this record was first created */
        time_t            cm_canceltime; /*when this record is no longer valid*/
        char              cm_tgtname[MTI_NAME_MAXLEN];
        char              cm_comment[MTI_NAME_MAXLEN];
};

/*
 * Opcodes for multiple servers.
 */

typedef enum {
        OBD_PING = 400,
        OBD_LOG_CANCEL,
        OBD_QC_CALLBACK,
        OBD_LAST_OPC
} obd_cmd_t;
#define OBD_FIRST_OPC OBD_PING

/* catalog of log objects */

/* Identifier for a single log object */
struct llog_logid {
        __u64                   lgl_oid;
        __u64                   lgl_ogr;
        __u32                   lgl_ogen;
} __attribute__((packed));

/* Records written to the CATALOGS list */
#define CATLIST "CATALOGS"
struct llog_catid {
        struct llog_logid       lci_logid;
        __u32                   lci_padding1;
        __u32                   lci_padding2;
        __u32                   lci_padding3;
} __attribute__((packed));

/*join file lov mds md*/
struct lov_mds_md_join {
        struct lov_mds_md lmmj_md;
        /*join private info*/
        struct llog_logid lmmj_array_id; /*array object id*/
        __u32  lmmj_extent_count;        /*array extent count*/
};

/* Log data record types - there is no specific reason that these need to
 * be related to the RPC opcodes, but no reason not to (may be handy later?)
 */
#define LLOG_OP_MAGIC 0x10600000
#define LLOG_OP_MASK  0xfff00000

typedef enum {
        LLOG_PAD_MAGIC   = LLOG_OP_MAGIC | 0x00000,
        OST_SZ_REC       = LLOG_OP_MAGIC | 0x00f00,
        OST_RAID1_REC    = LLOG_OP_MAGIC | 0x01000,
        MDS_UNLINK_REC   = LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_UNLINK,
        MDS_SETATTR_REC  = LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_SETATTR,
        OBD_CFG_REC      = LLOG_OP_MAGIC | 0x20000,
        PTL_CFG_REC      = LLOG_OP_MAGIC | 0x30000, /* obsolete */
        LLOG_GEN_REC     = LLOG_OP_MAGIC | 0x40000,
        LLOG_JOIN_REC    = LLOG_OP_MAGIC | 0x50000,
        LLOG_HDR_MAGIC   = LLOG_OP_MAGIC | 0x45539,
        LLOG_LOGID_MAGIC = LLOG_OP_MAGIC | 0x4553b,
} llog_op_type;

/*
 * for now, continue to support old pad records which have 0 for their
 * type but still need to be swabbed for their length
 */
#define LLOG_REC_HDR_NEEDS_SWABBING(r)                                  \
        (((r)->lrh_type & __swab32(LLOG_OP_MASK)) ==                    \
         __swab32(LLOG_OP_MAGIC) ||                                     \
         (((r)->lrh_type == 0) && ((r)->lrh_len > LLOG_CHUNK_SIZE)))

/* Log record header - stored in little endian order.
 * Each record must start with this struct, end with a llog_rec_tail,
 * and be a multiple of 256 bits in size.
 */
struct llog_rec_hdr {
        __u32                   lrh_len;
        __u32                   lrh_index;
        __u32                   lrh_type;
        __u32                   padding;
};

struct llog_rec_tail {
        __u32 lrt_len;
        __u32 lrt_index;
};

struct llog_logid_rec {
        struct llog_rec_hdr     lid_hdr;
        struct llog_logid       lid_id;
        __u32                   padding1;
        __u32                   padding2;
        __u32                   padding3;
        __u32                   padding4;
        __u32                   padding5;
        struct llog_rec_tail    lid_tail;
} __attribute__((packed));

/* MDS extent description
 * It is for joined file extent info, each extent info for joined file
 * just like (start, end, lmm).
 */
struct mds_extent_desc {
        __u64                   med_start; /* extent start */
        __u64                   med_len;   /* extent length */
        struct lov_mds_md       med_lmm;   /* extent's lmm  */
};
/*Joined file array extent log record*/
struct llog_array_rec {
        struct llog_rec_hdr     lmr_hdr;
        struct mds_extent_desc  lmr_med;
        struct llog_rec_tail    lmr_tail;
};

struct llog_create_rec {
        struct llog_rec_hdr     lcr_hdr;
        struct ll_fid           lcr_fid;
        obd_id                  lcr_oid;
        obd_count               lcr_ogen;
        __u32                   padding;
        struct llog_rec_tail    lcr_tail;
} __attribute__((packed));

struct llog_orphan_rec {
        struct llog_rec_hdr     lor_hdr;
        obd_id                  lor_oid;
        obd_count               lor_ogen;
        __u32                   padding;
        struct llog_rec_tail    lor_tail;
} __attribute__((packed));

struct llog_unlink_rec {
        struct llog_rec_hdr     lur_hdr;
        obd_id                  lur_oid;
        obd_count               lur_ogen;
        __u32                   padding;
        struct llog_rec_tail    lur_tail;
} __attribute__((packed));

struct llog_setattr_rec {
        struct llog_rec_hdr     lsr_hdr;
        obd_id                  lsr_oid;
        obd_count               lsr_ogen;
        __u32                   lsr_uid;
        __u32                   lsr_gid;
        __u32                   padding;
        struct llog_rec_tail    lsr_tail;
} __attribute__((packed));

struct llog_size_change_rec {
        struct llog_rec_hdr     lsc_hdr;
        struct ll_fid           lsc_fid;
        __u32                   lsc_io_epoch;
        __u32                   padding;
        struct llog_rec_tail    lsc_tail;
} __attribute__((packed));

struct llog_gen {
        __u64 mnt_cnt;
        __u64 conn_cnt;
} __attribute__((packed));

struct llog_gen_rec {
        struct llog_rec_hdr     lgr_hdr;
        struct llog_gen         lgr_gen;
        struct llog_rec_tail    lgr_tail;
};
/* On-disk header structure of each log object, stored in little endian order */
#define LLOG_CHUNK_SIZE         8192
#define LLOG_HEADER_SIZE        (96)
#define LLOG_BITMAP_BYTES       (LLOG_CHUNK_SIZE - LLOG_HEADER_SIZE)

#define LLOG_MIN_REC_SIZE       (24) /* round(llog_rec_hdr + llog_rec_tail) */

/* flags for the logs */
#define LLOG_F_ZAP_WHEN_EMPTY   0x1
#define LLOG_F_IS_CAT           0x2
#define LLOG_F_IS_PLAIN         0x4

struct llog_log_hdr {
        struct llog_rec_hdr     llh_hdr;
        __u64                   llh_timestamp;
        __u32                   llh_count;
        __u32                   llh_bitmap_offset;
        __u32                   llh_size;
        __u32                   llh_flags;
        __u32                   llh_cat_idx;
        /* for a catalog the first plain slot is next to it */
        struct obd_uuid         llh_tgtuuid;
        __u32                   llh_reserved[LLOG_HEADER_SIZE/sizeof(__u32) - 23];
        __u32                   llh_bitmap[LLOG_BITMAP_BYTES/sizeof(__u32)];
        struct llog_rec_tail    llh_tail;
} __attribute__((packed));

#define LLOG_BITMAP_SIZE(llh)  ((llh->llh_hdr.lrh_len -         \
                                 llh->llh_bitmap_offset -       \
                                 sizeof(llh->llh_tail)) * 8)

/* log cookies are used to reference a specific log file and a record therein */
struct llog_cookie {
        struct llog_logid       lgc_lgl;
        __u32                   lgc_subsys;
        __u32                   lgc_index;
        __u32                   lgc_padding;
} __attribute__((packed));

/* llog protocol */
typedef enum {
        LLOG_ORIGIN_HANDLE_CREATE       = 501,
        LLOG_ORIGIN_HANDLE_NEXT_BLOCK   = 502,
        LLOG_ORIGIN_HANDLE_READ_HEADER  = 503,
        LLOG_ORIGIN_HANDLE_WRITE_REC    = 504,
        LLOG_ORIGIN_HANDLE_CLOSE        = 505,
        LLOG_ORIGIN_CONNECT             = 506,
        LLOG_CATINFO                    = 507,  /* for lfs catinfo */
        LLOG_ORIGIN_HANDLE_PREV_BLOCK   = 508,
        LLOG_ORIGIN_HANDLE_DESTROY      = 509,  /* for destroy llog object*/
        LLOG_LAST_OPC
} llog_cmd_t;
#define LLOG_FIRST_OPC LLOG_ORIGIN_HANDLE_CREATE

struct llogd_body {
        struct llog_logid  lgd_logid;
        __u32 lgd_ctxt_idx;
        __u32 lgd_llh_flags;
        __u32 lgd_index;
        __u32 lgd_saved_index;
        __u32 lgd_len;
        __u64 lgd_cur_offset;
} __attribute__((packed));

struct llogd_conn_body {
        struct llog_gen         lgdc_gen;
        struct llog_logid       lgdc_logid;
        __u32                   lgdc_ctxt_idx;
} __attribute__((packed));

struct lov_user_ost_data_join {   /* per-stripe data structure */
        __u64 l_extent_start;     /* extent start*/
        __u64 l_extent_end;       /* extent end*/
        __u64 l_object_id;        /* OST object ID */
        __u64 l_object_gr;        /* OST object group (creating MDS number) */
        __u32 l_ost_gen;          /* generation of this OST index */
        __u32 l_ost_idx;          /* OST index in LOV */
} __attribute__((packed));

struct lov_user_md_join {         /* LOV EA user data (host-endian) */
        __u32 lmm_magic;          /* magic number = LOV_MAGIC_JOIN */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u32 lmm_stripe_count;   /* num stripes in use for this object */
        __u32 lmm_extent_count;   /* extent count of lmm*/
        __u64 lmm_tree_id;        /* mds tree object id */
        __u64 lmm_tree_gen;       /* mds tree object gen */
        struct llog_logid lmm_array_id; /* mds extent desc llog object id */
        struct lov_user_ost_data_join lmm_objects[0]; /* per-stripe data */
} __attribute__((packed));


struct obdo {
        obd_valid               o_valid;        /* hot fields in this obdo */
        obd_id                  o_id;
        obd_gr                  o_gr;
        obd_id                  o_fid;
        obd_size                o_size;         /* o_size-o_blocks == ost_lvb */
        obd_time                o_mtime;
        obd_time                o_atime;
        obd_time                o_ctime;
        obd_blocks              o_blocks;       /* brw: cli sent cached bytes */
        obd_size                o_grant;

        /* 32-bit fields start here: keep an even number of them via padding */
        obd_blksize             o_blksize;      /* optimal IO blocksize */
        obd_mode                o_mode;         /* brw: cli sent cache remain */
        obd_uid                 o_uid;
        obd_gid                 o_gid;
        obd_flag                o_flags;
        obd_count               o_nlink;        /* brw: checksum */
        obd_count               o_generation;
        obd_count               o_misc;         /* brw: o_dropped */
        __u32                   o_easize;       /* epoch in ost writes */
        __u32                   o_mds;
        __u32                   o_stripe_idx;   /* holds stripe idx */
        __u32                   o_padding_1;
        struct lustre_handle    o_handle;       /* brw: lock handle to prolong locks */
        struct llog_cookie      o_lcookie;      /* destroy: unlink cookie from MDS */

        __u64                   o_padding_2;
        __u64                   o_padding_3;
        __u64                   o_padding_4;
        __u64                   o_padding_5;
        __u64                   o_padding_6;
};

#define o_dirty   o_blocks
#define o_undirty o_mode
#define o_dropped o_misc
#define o_cksum   o_nlink

extern void lustre_swab_obdo (struct obdo *o);

/* request structure for OST's */
struct ost_body {
        struct  obdo oa;
};

/* Key for FIEMAP to be used in get_info calls */
struct ll_fiemap_info_key {
        char    name[8];
        struct  obdo oa;
        struct  ll_user_fiemap fiemap;
};

extern void lustre_swab_ost_body (struct ost_body *b);
extern void lustre_swab_ost_last_id(obd_id *id);
extern void lustre_swab_fiemap(struct ll_user_fiemap *fiemap);

extern void lustre_swab_lov_user_md_v1(struct lov_user_md_v1 *lum);
extern void lustre_swab_lov_user_md_v3(struct lov_user_md_v3 *lum);
extern void lustre_swab_lov_user_md_objects(struct lov_user_ost_data *lod,
                                            int stripe_count);
extern void lustre_swab_lov_user_md_join(struct lov_user_md_join *lumj);

/* llog_swab.c */
extern void lustre_swab_llogd_body (struct llogd_body *d);
extern void lustre_swab_llog_hdr (struct llog_log_hdr *h);
extern void lustre_swab_llogd_conn_body (struct llogd_conn_body *d);
extern void lustre_swab_llog_rec(struct llog_rec_hdr  *rec,
                                 struct llog_rec_tail *tail);

struct lustre_cfg;
extern void lustre_swab_lustre_cfg(struct lustre_cfg *lcfg);

/* this will be used when OBD_CONNECT_CHANGE_QS is set */
struct qunit_data {
        __u32 qd_id;    /* ID appiles to (uid, gid) */
        __u32 qd_flags; /* LQUOTA_FLAGS_* affect the responding bits */
        __u64 qd_count; /* acquire/release count (bytes for block quota) */
        __u64 qd_qunit; /* when a master returns the reply to a slave, it will
                         * contain the current corresponding qunit size */
        __u64 padding;
};

#define QDATA_IS_GRP(qdata)    ((qdata)->qd_flags & LQUOTA_FLAGS_GRP)
#define QDATA_IS_BLK(qdata)    ((qdata)->qd_flags & LQUOTA_FLAGS_BLK)
#define QDATA_IS_ADJBLK(qdata) ((qdata)->qd_flags & LQUOTA_FLAGS_ADJBLK)
#define QDATA_IS_ADJINO(qdata) ((qdata)->qd_flags & LQUOTA_FLAGS_ADJINO)
#define QDATA_IS_CHANGE_QS(qdata) ((qdata)->qd_flags & LQUOTA_FLAGS_CHG_QS)

#define QDATA_SET_GRP(qdata)    ((qdata)->qd_flags |= LQUOTA_FLAGS_GRP)
#define QDATA_SET_BLK(qdata)    ((qdata)->qd_flags |= LQUOTA_FLAGS_BLK)
#define QDATA_SET_ADJBLK(qdata) ((qdata)->qd_flags |= LQUOTA_FLAGS_ADJBLK)
#define QDATA_SET_ADJINO(qdata) ((qdata)->qd_flags |= LQUOTA_FLAGS_ADJINO)
#define QDATA_SET_CHANGE_QS(qdata) ((qdata)->qd_flags |= LQUOTA_FLAGS_CHG_QS)

#define QDATA_CLR_GRP(qdata)        ((qdata)->qd_flags &= ~LQUOTA_FLAGS_GRP)
#define QDATA_CLR_CHANGE_QS(qdata)  ((qdata)->qd_flags &= ~LQUOTA_FLAGS_CHG_QS)

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(1, 9, 0, 0)
/* this will be used when OBD_CONNECT_QUOTA64 is set */
struct qunit_data_old2 {
        __u32 qd_id; /* ID appiles to (uid, gid) */
        __u32 qd_flags; /* Quota type (USRQUOTA, GRPQUOTA) occupy one bit;
                         * Block quota or file quota occupy one bit */
        __u64 qd_count; /* acquire/release count (bytes for block quota) */
};
#else
#warning "remove quota code above for format absolete in new release"
#endif

extern void lustre_swab_qdata(struct qunit_data *d);
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(1, 9, 0, 0)
extern void lustre_swab_qdata_old2(struct qunit_data_old2 *d);
#else
#warning "remove quota code above for format absolete in new release"
#endif
extern int quota_get_qdata(void*req, struct qunit_data *qdata,
                           int is_req, int is_exp);
extern int quota_copy_qdata(void *request, struct qunit_data *qdata,
                            int is_req, int is_exp);

typedef enum {
        QUOTA_DQACQ     = 601,
        QUOTA_DQREL     = 602,
        QUOTA_LAST_OPC
} quota_cmd_t;
#define QUOTA_FIRST_OPC QUOTA_DQACQ


enum fld_rpc_opc {
        FLD_QUERY                       = 600,
        FLD_LAST_OPC,
        FLD_FIRST_OPC                   = FLD_QUERY
};

enum seq_rpc_opc {
        SEQ_QUERY                       = 700,
        SEQ_LAST_OPC,
        SEQ_FIRST_OPC                   = SEQ_QUERY
};

enum seq_op {
        SEQ_ALLOC_SUPER = 0,
        SEQ_ALLOC_META = 1
};


#define JOIN_FILE_ALIGN 4096

#define QUOTA_REQUEST   1
#define QUOTA_REPLY     0
#define QUOTA_EXPORT    1
#define QUOTA_IMPORT    0

/* quota check function */
#define QUOTA_RET_OK           0 /* return successfully */
#define QUOTA_RET_NOQUOTA      1 /* not support quota */
#define QUOTA_RET_NOLIMIT      2 /* quota limit isn't set */
#define QUOTA_RET_ACQUOTA      4 /* need to acquire extra quota */
#define QUOTA_RET_INC_PENDING  8 /* pending value is increased */

extern int quota_get_qunit_data_size(__u64 flag);
#endif
