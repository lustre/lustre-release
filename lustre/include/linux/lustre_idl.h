/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 *
 * (Un)packing of OST requests
 *
 * We assume all nodes are either little-endian or big-endian, and we
 * always send messages in the sender's native format.  The receiver
 * detects the message format by checking the 'magic' field of the message
 * (see lustre_msg_swabbed() below).
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

#ifdef __KERNEL__
# include <linux/ioctl.h>
# include <asm/types.h>
# include <linux/types.h>
# include <linux/list.h>
# include <linux/string.h> /* for strncpy, below */
# include <asm/byteorder.h>
#else
#ifdef __CYGWIN__
# include <sys/types.h>
#else
# include <asm/types.h>
# include <stdint.h>
#endif
# include <portals/list.h>
#endif
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
struct obd_uuid {
        __u8 uuid[37];
};

static inline int obd_uuid_equals(struct obd_uuid *u1, struct obd_uuid *u2)
{
        return strcmp(u1->uuid, u2->uuid) == 0;
}

static inline void obd_str2uuid(struct obd_uuid *uuid, char *tmp)
{
        strncpy(uuid->uuid, tmp, sizeof(*uuid));
        uuid->uuid[sizeof(*uuid) - 1] = '\0';
}

extern struct obd_uuid lctl_fake_uuid;

/* FOO_REQUEST_PORTAL is for incoming requests on the FOO
 * FOO_REPLY_PORTAL   is for incoming replies on the FOO
 * FOO_BULK_PORTAL    is for incoming bulk on the FOO
 */

#define CONNMGR_REQUEST_PORTAL  1
#define CONNMGR_REPLY_PORTAL    2
//#define OSC_REQUEST_PORTAL      3
#define OSC_REPLY_PORTAL        4
//#define OSC_BULK_PORTAL         5
#define OST_REQUEST_PORTAL      6
//#define OST_REPLY_PORTAL        7
#define OST_BULK_PORTAL         8
//#define MDC_REQUEST_PORTAL      9
#define MDC_REPLY_PORTAL        10
//#define MDC_BULK_PORTAL         11
#define MDS_REQUEST_PORTAL      12
//#define MDS_REPLY_PORTAL        13
#define MDS_BULK_PORTAL         14
#define LDLM_CB_REQUEST_PORTAL     15
#define LDLM_CB_REPLY_PORTAL       16
#define LDLM_CANCEL_REQUEST_PORTAL     17
#define LDLM_CANCEL_REPLY_PORTAL       18
#define PTLBD_REQUEST_PORTAL           19
#define PTLBD_REPLY_PORTAL             20
#define PTLBD_BULK_PORTAL              21
#define MDS_SETATTR_PORTAL      22
#define MDS_READPAGE_PORTAL     23

#define SVC_KILLED               1
#define SVC_EVENT                2
#define SVC_SIGNAL               4
#define SVC_RUNNING              8
#define SVC_STOPPING            16
#define SVC_STOPPED             32

#define LUSTRE_CONN_NEW          1
#define LUSTRE_CONN_CON          2
#define LUSTRE_CONN_NOTCONN      3
#define LUSTRE_CONN_RECOVER      4
#define LUSTRE_CONN_FULL         5

/* packet types */
#define PTL_RPC_MSG_REQUEST 4711
#define PTL_RPC_MSG_ERR     4712
#define PTL_RPC_MSG_REPLY   4713

#define PTLRPC_MSG_MAGIC    0x0BD00BD0
#define PTLRPC_MSG_VERSION  0x00040002

struct lustre_handle {
        __u64 cookie;
};
#define DEAD_HANDLE_MAGIC 0xdeadbeefcafebabe

/* we depend on this structure to be 8-byte aligned */
/* this type is only endian-adjusted in lustre_unpack_msg() */
struct lustre_msg {
        struct lustre_handle handle;
        __u32 magic;
        __u32 type;
        __u32 version;
        __u32 opc;
        __u64 last_xid;
        __u64 last_committed;
        __u64 transno;
        __u32 status;
        __u32 flags;
        __u32 bufcount;
        __u32 buflens[0];
};

static inline int lustre_msg_swabbed (struct lustre_msg *msg)
{
        return (msg->magic == __swab32 (PTLRPC_MSG_MAGIC));
}

/* Flags that are operation-specific go in the top 16 bits. */
#define MSG_OP_FLAG_MASK   0xffff0000
#define MSG_OP_FLAG_SHIFT  16

/* Flags that apply to all requests are in the bottom 16 bits */
#define MSG_GEN_FLAG_MASK      0x0000ffff
#define MSG_LAST_REPLAY        1
#define MSG_RESENT             2

static inline int lustre_msg_get_flags(struct lustre_msg *msg)
{
        return (msg->flags & MSG_GEN_FLAG_MASK);
}

static inline void lustre_msg_add_flags(struct lustre_msg *msg, int flags)
{
        msg->flags |= MSG_GEN_FLAG_MASK & flags;
}

static inline void lustre_msg_set_flags(struct lustre_msg *msg, int flags)
{
        msg->flags &= ~MSG_GEN_FLAG_MASK;
        lustre_msg_add_flags(msg, flags);
}

static inline int lustre_msg_get_op_flags(struct lustre_msg *msg)
{
        return (msg->flags >> MSG_OP_FLAG_SHIFT);
}

static inline void lustre_msg_add_op_flags(struct lustre_msg *msg, int flags)
{
        msg->flags |= ((flags & MSG_GEN_FLAG_MASK) << MSG_OP_FLAG_SHIFT);
}

static inline void lustre_msg_set_op_flags(struct lustre_msg *msg, int flags)
{
        msg->flags &= ~MSG_OP_FLAG_MASK;
        lustre_msg_add_op_flags(msg, flags);
}

/*
 * Flags for all connect opcodes (MDS_CONNECT, OST_CONNECT)
 */

#define MSG_CONNECT_RECOVERING 0x1
#define MSG_CONNECT_RECONNECT  0x2
#define MSG_CONNECT_REPLAYABLE  0x4

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
        OST_SAN_READ   = 14,
        OST_SAN_WRITE  = 15,
        OST_SYNCFS     = 16,
        OST_LAST_OPC
} ost_cmd_t;
#define OST_FIRST_OPC  OST_REPLY
/* When adding OST RPC opcodes, please update 
 * LAST/FIRST macros used in ptlrpc/ptlrpc_internals.h */


typedef uint64_t        obd_id;
typedef uint64_t        obd_gr;
typedef uint64_t        obd_time;
typedef uint64_t        obd_size;
typedef uint64_t        obd_off;
typedef uint64_t        obd_blocks;
typedef uint32_t        obd_blksize;
typedef uint32_t        obd_mode;
typedef uint32_t        obd_uid;
typedef uint32_t        obd_gid;
typedef uint64_t        obd_rdev;
typedef uint32_t        obd_flag;
typedef uint32_t        obd_count;

#define OBD_FL_INLINEDATA       (0x00000001)
#define OBD_FL_OBDMDEXISTS      (0x00000002)

#define OBD_INLINESZ    60
#define FD_OSTDATA_SIZE sizeof(struct obd_client_handle)

/* Note: 64-bit types are 64-bit aligned in structure */
struct obdo {
        obd_id                  o_id;
        obd_gr                  o_gr;
        obd_time                o_atime;
        obd_time                o_mtime;
        obd_time                o_ctime;
        obd_size                o_size;
        obd_blocks              o_blocks; /* brw: clients sent cached bytes */
        obd_rdev                o_rdev; /* brw: clients/servers sent grant */
        obd_blksize             o_blksize;      /* optimal IO blocksize */
        obd_mode                o_mode;
        obd_uid                 o_uid;
        obd_gid                 o_gid;
        obd_flag                o_flags;
        obd_count               o_nlink; /* brw: checksum */
        obd_count               o_generation;
        obd_flag                o_valid;        /* hot fields in this obdo */
        obd_flag                o_obdflags;
        __u32                   o_easize;
        char                    o_inline[OBD_INLINESZ];
};

extern void lustre_swab_obdo (struct obdo *o);

struct lov_object_id { /* per-child structure */
        __u64 l_object_id;
};

#define LOV_MAGIC  0x0BD00BD0

struct lov_mds_md {
        __u32 lmm_magic;
        __u64 lmm_object_id;       /* lov object id */
        __u32 lmm_stripe_size;     /* size of the stripe */
        __u32 lmm_stripe_offset;   /* starting stripe offset in lmm_objects */
        __u16 lmm_stripe_count;    /* number of stipes in use for this object */
        __u16 lmm_ost_count;       /* how many OST idx are in this LOV md */
        struct lov_object_id lmm_objects[0];
};

#define OBD_MD_FLALL    (0xffffffff)
#define OBD_MD_FLID     (0x00000001)    /* object ID */
#define OBD_MD_FLATIME  (0x00000002)    /* access time */
#define OBD_MD_FLMTIME  (0x00000004)    /* data modification time */
#define OBD_MD_FLCTIME  (0x00000008)    /* change time */
#define OBD_MD_FLSIZE   (0x00000010)    /* size */
#define OBD_MD_FLBLOCKS (0x00000020)    /* allocated blocks count */
#define OBD_MD_FLBLKSZ  (0x00000040)    /* block size */
#define OBD_MD_FLMODE   (0x00000080)    /* access bits (mode & ~S_IFMT) */
#define OBD_MD_FLTYPE   (0x00000100)    /* object type (mode & S_IFMT) */
#define OBD_MD_FLUID    (0x00000200)    /* user ID */
#define OBD_MD_FLGID    (0x00000400)    /* group ID */
#define OBD_MD_FLFLAGS  (0x00000800)    /* flags word */
#define OBD_MD_FLOBDFLG (0x00001000)
#define OBD_MD_FLNLINK  (0x00002000)    /* link count */
#define OBD_MD_FLGENER  (0x00004000)    /* generation number */
#define OBD_MD_FLINLINE (0x00008000)    /* inline data */
#define OBD_MD_FLRDEV   (0x00010000)    /* device number */
#define OBD_MD_FLEASIZE (0x00020000)    /* extended attribute data */
#define OBD_MD_LINKNAME (0x00040000)    /* symbolic link target */
#define OBD_MD_FLHANDLE (0x00080000)    /* file handle */
#define OBD_MD_FLCKSUM  (0x00100000)    /* bulk data checksum */
#define OBD_MD_FLNOTOBD (~(OBD_MD_FLOBDFLG | OBD_MD_FLBLOCKS | OBD_MD_LINKNAME|\
                           OBD_MD_FLEASIZE | OBD_MD_FLHANDLE | OBD_MD_FLCKSUM))

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
        __u32           os_spare[10];
};

extern void lustre_swab_obd_statfs (struct obd_statfs *os);

/* ost_body.data values for OST_BRW */

#define OBD_BRW_READ       0x01
#define OBD_BRW_WRITE      0x02
#define OBD_BRW_RWMASK     (OBD_BRW_READ | OBD_BRW_WRITE)
#define OBD_BRW_CREATE     0x04
#define OBD_BRW_SYNC       0x08
#define OBD_BRW_CHECK      0x10
#define OBD_BRW_FROM_GRANT 0x20

#define OBD_OBJECT_EOF 0xffffffffffffffffULL

struct obd_ioobj {
        obd_id               ioo_id;
        obd_gr               ioo_gr;
        __u32                ioo_type;
        __u32                ioo_bufcnt;
} __attribute__((packed));

extern void lustre_swab_obd_ioobj (struct obd_ioobj *ioo);

/* multiple of 8 bytes => can array */
struct niobuf_remote {
        __u64 offset;
        __u32 len;
        __u32 flags;
} __attribute__((packed));

extern void lustre_swab_niobuf_remote (struct niobuf_remote *nbr);

/* request structure for OST's */

#define OST_REQ_HAS_OA1  0x1

struct ost_body {
        struct  obdo oa;
};

extern void lustre_swab_ost_body (struct ost_body *b);

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
        MDS_GETLOVINFO   = 42,
        MDS_LAST_OPC
} mds_cmd_t;
#define MDS_FIRST_OPC    MDS_GETATTR
/* When adding MDS RPC opcodes, please update 
 * LAST/FIRST macros used in ptlrpc/ptlrpc_internals.h */

/*
 * Do not exceed 63 
 */

#define REINT_SETATTR  1
#define REINT_CREATE   2
#define REINT_LINK     3
#define REINT_UNLINK   4
#define REINT_RENAME   5
#define REINT_OPEN     6
#define REINT_MAX      6

#define IT_INTENT_EXEC   1
#define IT_OPEN_LOOKUP  (1 << 1)
#define IT_OPEN_NEG     (1 << 2)
#define IT_OPEN_POS     (1 << 3)
#define IT_OPEN_CREATE  (1 << 4)
#define IT_OPEN_OPEN    (1 << 5)

struct ll_fid {
        __u64 id;
        __u32 generation;
        __u32 f_type;
};

extern void lustre_swab_ll_fid (struct ll_fid *fid);

#define MDS_STATUS_CONN 1
#define MDS_STATUS_LOV 2

struct mds_status_req {
        __u32  flags;
        __u32  repbuf;
};

extern void lustre_swab_mds_status_req (struct mds_status_req *r);

struct mds_fileh_body {
        struct ll_fid f_fid;
        struct lustre_handle f_handle;
};

extern void lustre_swab_mds_fileh_body (struct mds_fileh_body *f);

struct mds_body {
        struct ll_fid  fid1;
        struct ll_fid  fid2;
        struct lustre_handle handle;
        __u64          size;   /* Offset, in the case of MDS_READPAGE */
        __u64          blocks; /* XID, in the case of MDS_READPAGE */
        __u32          ino;   /* make this a __u64 */
        __u32          valid;
        __u32          fsuid;
        __u32          fsgid;
        __u32          capability;
        __u32          mode;
        __u32          uid;
        __u32          gid;
        __u32          mtime;
        __u32          ctime;
        __u32          atime;
        __u32          flags;
        __u32          rdev;
        __u32          nlink; /* #bytes to read in the case of MDS_READPAGE */
        __u32          generation;
        __u32          suppgid;
        __u32          eadatasize;
};

extern void lustre_swab_mds_body (struct mds_body *b);

/* This is probably redundant with OBD_MD_FLEASIZE, but we need an audit */
#define MDS_OPEN_HAS_EA 1 /* this open has an EA, for a delayed create*/

/* MDS update records */

//struct mds_update_record_hdr {
//        __u32 ur_opcode;
//};

struct mds_rec_setattr {
        __u32           sa_opcode;
        __u32           sa_fsuid;
        __u32           sa_fsgid;
        __u32           sa_cap;
        __u32           sa_reserved;
        __u32           sa_valid;
        struct ll_fid   sa_fid;
        __u32           sa_mode;
        __u32           sa_uid;
        __u32           sa_gid;
        __u32           sa_attr_flags;
        __u64           sa_size;
        __u64           sa_atime;
        __u64           sa_mtime;
        __u64           sa_ctime;
        __u32           sa_suppgid;
};

extern void lustre_swab_mds_rec_setattr (struct mds_rec_setattr *sa);

struct mds_rec_create {
        __u32           cr_opcode;
        __u32           cr_fsuid;
        __u32           cr_fsgid;
        __u32           cr_cap;
        __u32           cr_flags; /* for use with open */
        __u32           cr_mode;
        struct ll_fid   cr_fid;
        struct ll_fid   cr_replayfid;
        __u32           cr_uid;
        __u32           cr_gid;
        __u64           cr_time;
        __u64           cr_rdev;
        __u32           cr_suppgid;
};

extern void lustre_swab_mds_rec_create (struct mds_rec_create *cr);

struct mds_rec_link {
        __u32           lk_opcode;
        __u32           lk_fsuid;
        __u32           lk_fsgid;
        __u32           lk_cap;
        __u32           lk_suppgid1;
        __u32           lk_suppgid2;
        struct ll_fid   lk_fid1;
        struct ll_fid   lk_fid2;
};

extern void lustre_swab_mds_rec_link (struct mds_rec_link *lk);

struct mds_rec_unlink {
        __u32           ul_opcode;
        __u32           ul_fsuid;
        __u32           ul_fsgid;
        __u32           ul_cap;
        __u32           ul_reserved;
        __u32           ul_mode;
        __u32           ul_suppgid;
        struct ll_fid   ul_fid1;
        struct ll_fid   ul_fid2;
};

extern void lustre_swab_mds_rec_unlink (struct mds_rec_unlink *ul);

struct mds_rec_rename {
        __u32           rn_opcode;
        __u32           rn_fsuid;
        __u32           rn_fsgid;
        __u32           rn_cap;
        __u32           rn_suppgid1;
        __u32           rn_suppgid2;
        struct ll_fid   rn_fid1;
        struct ll_fid   rn_fid2;
};

extern void lustre_swab_mds_rec_rename (struct mds_rec_rename *rn);

/*
 *  LOV data structures
 */

#define LOV_RAID0   0
#define LOV_RAIDRR  1

#define LOV_MAX_UUID_BUFFER_SIZE  8192
/* The size of the buffer the lov/mdc reserves for the 
 * array of UUIDs returned by the MDS.  With the current
 * protocol, this will limit the max number of OSTs per LOV */

struct lov_desc {
        __u32 ld_tgt_count;                /* how many OBD's */
        __u32 ld_active_tgt_count;         /* how many active */
        __u32 ld_default_stripe_count;     /* how many objects are used */
        __u64 ld_default_stripe_size;      /* in bytes */
        __u64 ld_default_stripe_offset;    /* in bytes */
        __u32 ld_pattern;                  /* RAID 0,1 etc */
        struct obd_uuid ld_uuid;
};

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
        LDLM_LAST_OPC
} ldlm_cmd_t;
#define LDLM_FIRST_OPC LDLM_ENQUEUE
/* When adding LDLM RPC opcodes, please update 
 * LAST/FIRST macros used in ptlrpc/ptlrpc_internals.h */

#define RES_NAME_SIZE 3
#define RES_VERSION_SIZE 4

struct ldlm_res_id {
        __u64 name[RES_NAME_SIZE];
};

extern void lustre_swab_ldlm_res_id (struct ldlm_res_id *id);

/* lock types */
typedef enum {
        LCK_EX = 1,
        LCK_PW,
        LCK_PR,
        LCK_CW,
        LCK_CR,
        LCK_NL
} ldlm_mode_t;

struct ldlm_extent {
        __u64 start;
        __u64 end;
};

extern void lustre_swab_ldlm_extent (struct ldlm_extent *e);

struct ldlm_intent {
        __u64 opc;
};

extern void lustre_swab_ldlm_intent (struct ldlm_intent *i);

/* Note this unaligned structure; as long as it's only used in ldlm_request
 * below, we're probably fine. */
struct ldlm_resource_desc {
        __u32 lr_type;
        struct ldlm_res_id lr_name;
        __u32 lr_version[RES_VERSION_SIZE];
};

extern void lustre_swab_ldlm_resource_desc (struct ldlm_resource_desc *r);

struct ldlm_lock_desc {
        struct ldlm_resource_desc l_resource;
        ldlm_mode_t l_req_mode;
        ldlm_mode_t l_granted_mode;
        struct ldlm_extent l_extent;
        __u32 l_version[RES_VERSION_SIZE];
};

extern void lustre_swab_ldlm_lock_desc (struct ldlm_lock_desc *l);

struct ldlm_request {
        __u32 lock_flags;
        struct ldlm_lock_desc lock_desc;
        struct lustre_handle lock_handle1;
        struct lustre_handle lock_handle2;
};

extern void lustre_swab_ldlm_request (struct ldlm_request *rq);

struct ldlm_reply {
        __u32 lock_flags;
        __u32 lock_mode;
        struct ldlm_res_id lock_resource_name;
        struct lustre_handle lock_handle;
        struct ldlm_extent lock_extent;   /* XXX make this policy 1 &2 */
        __u64  lock_policy_res1;
        __u64  lock_policy_res2;
};

extern void lustre_swab_ldlm_reply (struct ldlm_reply *r);

/*
 * ptlbd, portal block device requests
 */
typedef enum {
        PTLBD_QUERY = 200,
        PTLBD_READ = 201,
        PTLBD_WRITE = 202,
        PTLBD_FLUSH = 203,
        PTLBD_CONNECT = 204,
        PTLBD_DISCONNECT = 205,
        PTLBD_LAST_OPC
} ptlbd_cmd_t;
#define PTLBD_FIRST_OPC PTLBD_QUERY
/* When adding PTLBD RPC opcodes, please update 
 * LAST/FIRST macros used in ptlrpc/ptlrpc_internals.h */

struct ptlbd_op {
        __u16 op_cmd;
        __u16 op_lun;
        __u16 op_niob_cnt;
        __u16 op__padding;
        __u32 op_block_cnt;
};

extern void lustre_swab_ptlbd_op (struct ptlbd_op *op);

struct ptlbd_niob {
        __u64 n_xid;
        __u64 n_block_nr;
        __u32 n_offset;
        __u32 n_length;
};

extern void lustre_swab_ptlbd_niob (struct ptlbd_niob *n);

struct ptlbd_rsp {
        __u16 r_status;
        __u16 r_error_cnt;
};

extern void lustre_swab_ptlbd_rsp (struct ptlbd_rsp *r);

/*
 * Opcodes for multiple servers.
 */

#define OBD_PING 400

#endif
