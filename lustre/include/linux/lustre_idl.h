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
 * Lustre wire protocol definitions.
 *
 * All structs passing over the wire should be declared here (lov_mds_md
 * being the lone exception).  Structs must be properly aligned to put
 * 64-bit values on an 8-byte boundary.  Any structs being added here
 * must also be added to utils/wirecheck.c and "make newwiretest" run
 * to regenerate the utils/wiretest.c sources.  This allows us to verify
 * that wire structs have the proper alignment/size on all architectures.
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
# include <linux/fs.h> /* to check for FMODE_EXEC, lest we redefine */
#else
#ifdef __CYGWIN__
# include <sys/types.h>
#else
# include <asm/types.h>
# include <stdint.h>
#endif
# include <portals/list.h>
# include <string.h>
#endif

/* Defn's shared with user-space. */
#include <linux/lustre_user.h>

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
        __u8 uuid[40];
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

/* FOO_REQUEST_PORTAL is for incoming requests on the FOO
 * FOO_REPLY_PORTAL   is for incoming replies on the FOO
 * FOO_BULK_PORTAL    is for incoming bulk on the FOO
 */

#define CONNMGR_REQUEST_PORTAL          1
#define CONNMGR_REPLY_PORTAL            2
//#define OSC_REQUEST_PORTAL            3
#define OSC_REPLY_PORTAL                4
//#define OSC_BULK_PORTAL               5
#define OST_REQUEST_PORTAL              6
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
#define PTLBD_REQUEST_PORTAL           19
#define PTLBD_REPLY_PORTAL             20
#define PTLBD_BULK_PORTAL              21
#define MDS_SETATTR_PORTAL             22
#define MDS_READPAGE_PORTAL            23
#define MGMT_REQUEST_PORTAL            24
#define MGMT_REPLY_PORTAL              25
#define MGMT_CLI_REQUEST_PORTAL        26
#define MGMT_CLI_REPLY_PORTAL          27

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

#define PTLRPC_MSG_MAGIC    0x0BD00BD0


#define PTLRPC_MSG_VERSION  0x00000003
#define LUSTRE_MDS_VERSION  (0x00040000|PTLRPC_MSG_VERSION)
#define LUSTRE_OST_VERSION  (0x00040000|PTLRPC_MSG_VERSION)
#define LUSTRE_DLM_VERSION  (0x00040000|PTLRPC_MSG_VERSION)

struct lustre_handle {
        __u64 cookie;
};
#define DEAD_HANDLE_MAGIC 0xdeadbeefcafebabeULL

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
        __u32 conn_cnt;
        __u32 bufcount;
        __u32 buflens[0];
};

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

static inline void lustre_msg_clear_flags(struct lustre_msg *msg, int flags)
{
        msg->flags &= ~(MSG_GEN_FLAG_MASK & flags);
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

#define MSG_CONNECT_RECOVERING  0x1
#define MSG_CONNECT_RECONNECT   0x2
#define MSG_CONNECT_REPLAYABLE  0x4
//#define MSG_CONNECT_PEER        0x8

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
        OST_SYNC       = 16,
        OST_SET_INFO   = 17,
        OST_LAST_OPC
} ost_cmd_t;
#define OST_FIRST_OPC  OST_REPLY

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
typedef uint32_t        obd_flag;
typedef uint32_t        obd_count;

#define OBD_FL_INLINEDATA   (0x00000001)
#define OBD_FL_OBDMDEXISTS  (0x00000002)
#define OBD_FL_DELORPHAN    (0x00000004) /* if set in o_flags delete orphans */
#define OBD_FL_NORPC        (0x00000008) // if set in o_flags set in OSC not OST
#define OBD_FL_IDONLY       (0x00000010) // if set in o_flags only adjust obj id
#define OBD_FL_RECREATE_OBJS (0x00000020) // recreate missing obj

#define OBD_INLINESZ    64

/* Note: 64-bit types are 64-bit aligned in structure */
struct obdo {
        obd_id                  o_id;
        obd_gr                  o_gr;
        obd_time                o_atime;
        obd_time                o_mtime;
        obd_time                o_ctime;
        obd_size                o_size;
        obd_blocks              o_blocks;       /* brw: cli sent cached bytes */
        obd_size                o_grant;
        obd_blksize             o_blksize;      /* optimal IO blocksize */
        obd_mode                o_mode;         /* brw: cli sent cache remain */
        obd_uid                 o_uid;
        obd_gid                 o_gid;
        obd_flag                o_flags;
        obd_count               o_nlink;        /* brw: checksum */
        obd_count               o_generation;
        obd_flag                o_valid;        /* hot fields in this obdo */
        obd_count               o_misc;
        __u32                   o_easize;       /* epoch in ost writes */
        char                    o_inline[OBD_INLINESZ]; /* fid in ost writes */
};

#define o_dirty   o_blocks
#define o_undirty o_mode
#define o_dropped o_misc
#define o_cksum   o_nlink

extern void lustre_swab_obdo (struct obdo *o);

#define LOV_MAGIC_V1      0x0BD10BD0
#define LOV_MAGIC         LOV_MAGIC_V1

#define LOV_PATTERN_RAID0 0x001   /* stripes are used round-robin */
#define LOV_PATTERN_RAID1 0x002   /* stripes are mirrors of each other */
#define LOV_PATTERN_FIRST 0x100   /* first stripe is not in round-robin */

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

#define LOV_MAGIC_V0      0x0BD00BD0

struct lov_ost_data_v0 {          /* per-stripe data structure (little-endian)*/
        __u64 l_object_id;        /* OST object ID */
};

struct lov_mds_md_v0 {            /* LOV EA mds/wire data (little-endian) */
        __u32 lmm_magic;          /* magic number = LOV_MAGIC_V0 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u32 lmm_stripe_size;    /* size of the stripe in bytes (not RAID1) */
        __u32 lmm_stripe_offset;  /* starting stripe offset in lmm_objects */
        __u16 lmm_stripe_count;   /* number of stipes in use for this object */
        __u16 lmm_ost_count;      /* how many OST idx are in this LOV md */
        struct lov_ost_data_v0 lmm_objects[0];
} __attribute__((packed));

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
#define OBD_MD_FLNLINK  (0x00002000)    /* link count */
#define OBD_MD_FLGENER  (0x00004000)    /* generation number */
#define OBD_MD_FLINLINE (0x00008000)    /* inline data */
#define OBD_MD_FLRDEV   (0x00010000)    /* device number */
#define OBD_MD_FLEASIZE (0x00020000)    /* extended attribute data */
#define OBD_MD_LINKNAME (0x00040000)    /* symbolic link target */
#define OBD_MD_FLHANDLE (0x00080000)    /* file handle */
#define OBD_MD_FLCKSUM  (0x00100000)    /* bulk data checksum */
#define OBD_MD_FLQOS    (0x00200000)    /* quality of service stats */
#define OBD_MD_FLOSCOPQ (0x00400000)    /* osc opaque data */
#define OBD_MD_FLCOOKIE (0x00800000)    /* log cancellation cookie */
#define OBD_MD_FLGROUP  (0x01000000)    /* group */
#define OBD_MD_FLIFID   (0x02000000)    /* ->ost write inline fid */
#define OBD_MD_FLEPOCH  (0x04000000)    /* ->ost write easize is epoch */
#define OBD_MD_FLGRANT  (0x08000000)    /* ost preallocation space grant */
#define OBD_MD_FLNOTOBD (~(OBD_MD_FLBLOCKS | OBD_MD_LINKNAME|\
                           OBD_MD_FLEASIZE | OBD_MD_FLHANDLE | OBD_MD_FLCKSUM|\
                           OBD_MD_FLQOS | OBD_MD_FLOSCOPQ | OBD_MD_FLCOOKIE))


static inline struct lustre_handle *obdo_handle(struct obdo *oa)
{
        return (struct lustre_handle *)oa->o_inline;
}

static inline struct llog_cookie *obdo_logcookie(struct obdo *oa)
{
        return (struct llog_cookie *)(oa->o_inline +
                                      sizeof(struct lustre_handle));
}
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
        __u32           os_spare[10];
};

extern void lustre_swab_obd_statfs (struct obd_statfs *os);

/* ost_body.data values for OST_BRW */

#define OBD_BRW_READ       0x01
#define OBD_BRW_WRITE      0x02
#define OBD_BRW_RWMASK     (OBD_BRW_READ | OBD_BRW_WRITE)
#define OBD_BRW_SYNC       0x08
#define OBD_BRW_CHECK      0x10
#define OBD_BRW_FROM_GRANT 0x20 /* the osc manages this under llite */
#define OBD_BRW_GRANTED    0x40 /* the ost manages this */

#define OBD_OBJECT_EOF 0xffffffffffffffffULL

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

/* request structure for OST's */

#define OST_REQ_HAS_OA1  0x1

struct ost_body {
        struct  obdo oa;
};

extern void lustre_swab_ost_body (struct ost_body *b);
extern void lustre_swab_ost_last_id(obd_id *id);

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
        MDS_LAST_OPC
} mds_cmd_t;
#define MDS_FIRST_OPC    MDS_GETATTR

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

/* the disposition of the intent outlines what was executed */
#define DISP_IT_EXECD   1
#define DISP_LOOKUP_EXECD  (1 << 1)
#define DISP_LOOKUP_NEG     (1 << 2)
#define DISP_LOOKUP_POS     (1 << 3)
#define DISP_OPEN_CREATE  (1 << 4)
#define DISP_OPEN_OPEN    (1 << 5)
#define DISP_ENQ_COMPLETE (1<<6)

struct ll_fid {
        __u64 id;
        __u32 generation;
        __u32 f_type;
};

struct ll_recreate_obj {
        __u64 lrc_id;
        __u32 lrc_ost_idx;
};

extern void lustre_swab_ll_fid (struct ll_fid *fid);

#define MDS_STATUS_CONN 1
#define MDS_STATUS_LOV 2

struct mds_status_req {
        __u32  flags;
        __u32  repbuf;
};

extern void lustre_swab_mds_status_req (struct mds_status_req *r);

#define MDS_BFLAG_UNCOMMITTED_WRITES   0x1

struct mds_body {
        struct ll_fid  fid1;
        struct ll_fid  fid2;
        struct lustre_handle handle;
        __u64          size;   /* Offset, in the case of MDS_READPAGE */
        __u64          blocks; /* XID, in the case of MDS_READPAGE */
        __u64          io_epoch;
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
        __u32          flags; /* from vfs for pin/unpin, MDS_BFLAG for close */
        __u32          rdev;
        __u32          nlink; /* #bytes to read in the case of MDS_READPAGE */
        __u32          generation;
        __u32          suppgid;
        __u32          eadatasize;
        __u32          packing;
};

extern void lustre_swab_mds_body (struct mds_body *b);


/* MDS update records */

//struct mds_update_record_hdr {
//        __u32 ur_opcode;
//};

struct mds_rec_setattr {
        __u32           sa_opcode;
        __u32           sa_fsuid;
        __u32           sa_fsgid;
        __u32           sa_cap;
        __u32           sa_suppgid;
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
};

/* Remove this once we declare it in include/linux/fs.h (v21 kernel patch?) */
#ifndef ATTR_CTIME_SET
#define ATTR_CTIME_SET 0x2000
#endif

extern void lustre_swab_mds_rec_setattr (struct mds_rec_setattr *sa);

#ifndef FMODE_READ
#define FMODE_READ               00000001
#define FMODE_WRITE              00000002
#endif
#ifndef FMODE_EXEC
#define FMODE_EXEC               00000004
#endif
#define MDS_OPEN_CREAT           00000100
#define MDS_OPEN_EXCL            00000200
#define MDS_OPEN_TRUNC           00001000
#define MDS_OPEN_APPEND          00002000
#define MDS_OPEN_SYNC            00010000
#define MDS_OPEN_DIRECTORY       00200000

#define MDS_OPEN_DELAY_CREATE  0100000000 /* delay initial object create */
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
        __u32           cr_packing;
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
        __u64           lk_time;
};

extern void lustre_swab_mds_rec_link (struct mds_rec_link *lk);

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
        __u64           rn_time;
};

extern void lustre_swab_mds_rec_rename (struct mds_rec_rename *rn);

/*
 *  LOV data structures
 */

#define LOV_MAX_UUID_BUFFER_SIZE  8192
/* The size of the buffer the lov/mdc reserves for the
 * array of UUIDs returned by the MDS.  With the current
 * protocol, this will limit the max number of OSTs per LOV */

struct lov_desc {
        __u32 ld_tgt_count;                /* how many OBD's */
        __u32 ld_active_tgt_count;         /* how many active */
        __u32 ld_default_stripe_count;     /* how many objects are used */
        __u32 ld_pattern;                  /* PATTERN_RAID0, PATTERN_RAID1 */
        __u64 ld_default_stripe_size;      /* in bytes */
        __u64 ld_default_stripe_offset;    /* in bytes */
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

#define RES_NAME_SIZE 4
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

struct ldlm_flock {
        __u64 start;
        __u64 end;
        __u64 blocking_export;
        pid_t blocking_pid;
        pid_t pid;
};

/* it's important that the fields of the ldlm_extent structure match
 * the first fields of the ldlm_flock structure because there is only
 * one ldlm_swab routine to process the ldlm_policy_data_t union. if
 * this ever changes we will need to swab the union differently based
 * on the resource type. */

typedef union {
        struct ldlm_extent l_extent;
        struct ldlm_flock  l_flock;
} ldlm_policy_data_t;

extern void lustre_swab_ldlm_policy_data (ldlm_policy_data_t *d);

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
} __attribute__((packed));

extern void lustre_swab_ldlm_resource_desc (struct ldlm_resource_desc *r);

struct ldlm_lock_desc {
        struct ldlm_resource_desc l_resource;
        ldlm_mode_t l_req_mode;
        ldlm_mode_t l_granted_mode;
        ldlm_policy_data_t l_policy_data;
        __u32 l_version[RES_VERSION_SIZE];
} __attribute__((packed));

extern void lustre_swab_ldlm_lock_desc (struct ldlm_lock_desc *l);

struct ldlm_request {
        __u32 lock_flags;
        struct ldlm_lock_desc lock_desc;
        struct lustre_handle lock_handle1;
        struct lustre_handle lock_handle2;
} __attribute__((packed));

extern void lustre_swab_ldlm_request (struct ldlm_request *rq);

struct ldlm_reply {
        __u32 lock_flags;
        __u32 lock_mode;
        struct ldlm_res_id lock_resource_name;
        struct lustre_handle lock_handle;
        ldlm_policy_data_t lock_policy_data;
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
 * Opcodes for management/monitoring node.
 */
typedef enum {
        MGMT_CONNECT = 250,
        MGMT_DISCONNECT,
        MGMT_EXCEPTION,         /* node died, etc. */
        MGMT_LAST_OPC
} mgmt_cmd_t;
#define MGMT_FIRST_OPC MGMT_CONNECT

/*
 * Opcodes for multiple servers.
 */

typedef enum {
        OBD_PING = 400,
        OBD_LOG_CANCEL,
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

/* Log data record types - there is no specific reason that these need to
 * be related to the RPC opcodes, but no reason not to (may be handy later?)
 */
typedef enum {
        OST_SZ_REC       = 0x10600000 | (OST_SAN_WRITE << 8),
        OST_RAID1_REC    = 0x10600000 | ((OST_SAN_WRITE + 1) << 8),
        MDS_UNLINK_REC   = 0x10610000 | (MDS_REINT << 8) | REINT_UNLINK,
        OBD_CFG_REC      = 0x10620000,
        PTL_CFG_REC      = 0x10630000,
        LLOG_GEN_REC     = 0x10640000,
        LLOG_HDR_MAGIC   = 0x10645539,
        LLOG_LOGID_MAGIC = 0x1064553a,
} llog_op_type;

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
        __u32                   padding;
        struct llog_rec_tail    lid_tail;
} __attribute__((packed));

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
#define LLOG_CHUNK_SIZE         4096
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
        /* for a catlog the first plain slot is next to it */
        struct obd_uuid         llh_tgtuuid;
        __u32                   llh_reserved[LLOG_HEADER_SIZE/sizeof(__u32) - 23];
        __u32                   llh_bitmap[LLOG_BITMAP_BYTES/sizeof(__u32)];
        struct llog_rec_tail    llh_tail;
} __attribute__((packed));

/* log cookies are used to reference a specific log file and a record therein */
struct llog_cookie {
        struct llog_logid       lgc_lgl;
        __u32                   lgc_subsys;
        __u32                   lgc_index;
        __u32                   lgc_padding;
} __attribute__((packed));

/* llog protocol */
enum llogd_rpc_ops {
        LLOG_ORIGIN_HANDLE_CREATE       = 501,
        LLOG_ORIGIN_HANDLE_NEXT_BLOCK   = 502,
        LLOG_ORIGIN_HANDLE_READ_HEADER  = 503,
        LLOG_ORIGIN_HANDLE_WRITE_REC    = 504,
        LLOG_ORIGIN_HANDLE_CLOSE        = 505,
        LLOG_ORIGIN_CONNECT             = 506,
        LLOG_CATINFO                    = 507,  /* for lfs catinfo */
};

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

extern void lustre_swab_llogd_body (struct llogd_body *d);
extern void lustre_swab_llog_hdr (struct llog_log_hdr *h);
extern void lustre_swab_llogd_conn_body (struct llogd_conn_body *d);

static inline struct ll_fid *obdo_fid(struct obdo *oa)
{
        return (struct ll_fid *)(oa->o_inline + sizeof(struct lustre_handle) +
                                 sizeof(struct llog_cookie));
}

#endif
