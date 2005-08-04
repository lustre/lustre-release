/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
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

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#else
#include <lustre/types.h>
#endif

#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/fs.h>    /* to check for FMODE_EXEC, dev_t, lest we redefine */
#else
#ifdef __CYGWIN__
# include <sys/types.h>
#else
# include <stdint.h>
#endif
#endif

/* Defn's shared with user-space. */
#include <lustre/lustre_user.h>

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
#define LUSTRE_VERSION_MASK 0xffff0000
#define LUSTRE_OBD_VERSION  0x00010000
#define LUSTRE_MDS_VERSION  0x00020000
#define LUSTRE_OST_VERSION  0x00030000
#define LUSTRE_DLM_VERSION  0x00040000
#define LUSTRE_LOG_VERSION  0x00050000
#define LUSTRE_PBD_VERSION  0x00060000

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
#define MSG_REPLAY             4

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
#define MSG_CONNECT_LIBCLIENT   0x10
#define MSG_CONNECT_INITIAL     0x20
#define MSG_CONNECT_ASYNC       0x40

/* Connect flags */

#define OBD_CONNECT_RDONLY 0x1

#define MDS_CONNECT_SUPPORTED  (OBD_CONNECT_RDONLY)
#define OST_CONNECT_SUPPORTED  (0)
#define ECHO_CONNECT_SUPPORTED (0)

/* This structure is used for both request and reply.
 *  
 * If we eventually have separate connect data for different types, which we
 * almost certainly will, then perhaps we stick a union in here. */
struct obd_connect_data {
        __u64 ocd_connect_flags;
        __u64 padding[8];
};

extern void lustre_swab_connect(struct obd_connect_data *ocd);

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
        OST_QUOTACHECK = 18,
        OST_QUOTACTL   = 19,
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
typedef uint64_t        obd_valid;
typedef uint32_t        obd_count;

#define OBD_FL_INLINEDATA    (0x00000001)
#define OBD_FL_OBDMDEXISTS   (0x00000002)
#define OBD_FL_DELORPHAN     (0x00000004) /* if set in o_flags delete orphans */
#define OBD_FL_NORPC         (0x00000008) /* set in o_flags do in OSC not OST */
#define OBD_FL_IDONLY        (0x00000010) /* set in o_flags only adjust obj id*/
#define OBD_FL_RECREATE_OBJS (0x00000020) /* recreate missing obj */
#define OBD_FL_DEBUG_CHECK   (0x00000040) /* echo client/server debug check */
#define OBD_FL_NO_USRQUOTA   (0x00000100) /* the object's owner is over quota */
#define OBD_FL_NO_GRPQUOTA   (0x00000200) /* the object's group is over quota */

#define OBD_INLINESZ    80

/* Note: 64-bit types are 64-bit aligned in structure */
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
        __u32                   o_padding_1;
        __u32                   o_padding_2;
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
#define LOV_PATTERN_CMOBD 0x200

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
#define OBD_MD_FLINLINE    (0x00008000ULL) /* inline data */
#define OBD_MD_FLRDEV      (0x00010000ULL) /* device number */
#define OBD_MD_FLEASIZE    (0x00020000ULL) /* extended attribute data */
#define OBD_MD_LINKNAME    (0x00040000ULL) /* symbolic link target */
#define OBD_MD_FLHANDLE    (0x00080000ULL) /* file handle */
#define OBD_MD_FLCKSUM     (0x00100000ULL) /* bulk data checksum */
#define OBD_MD_FLQOS       (0x00200000ULL) /* quality of service stats */
#define OBD_MD_FLOSCOPQ    (0x00400000ULL) /* osc opaque data */
#define OBD_MD_FLCOOKIE    (0x00800000ULL) /* log cancellation cookie */
#define OBD_MD_FLGROUP     (0x01000000ULL) /* group */
#define OBD_MD_FLIFID      (0x02000000ULL) /* ->ost write inline fid */
#define OBD_MD_FLEPOCH     (0x04000000ULL) /* ->ost write easize is epoch */
#define OBD_MD_FLGRANT     (0x08000000ULL) /* ost preallocation space grant */
#define OBD_MD_FLDIREA     (0x10000000ULL) /* dir's extended attribute data */
#define OBD_MD_FLUSRQUOTA  (0x20000000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLGRPQUOTA  (0x40000000ULL) /* over quota flags sent from ost */

#define OBD_MD_MDS        (0x100000000ULL) /* where an inode lives on */
#define OBD_MD_REINT      (0x200000000ULL) /* reintegrate oa */

#define OBD_MD_FLGETATTR (OBD_MD_FLID    | OBD_MD_FLATIME | OBD_MD_FLMTIME | \
                          OBD_MD_FLCTIME | OBD_MD_FLSIZE  | OBD_MD_FLBLKSZ | \
                          OBD_MD_FLMODE  | OBD_MD_FLTYPE  | OBD_MD_FLUID   | \
                          OBD_MD_FLGID   | OBD_MD_FLFLAGS | OBD_MD_FLNLINK | \
                          OBD_MD_FLGENER | OBD_MD_FLRDEV  | OBD_MD_FLGROUP)

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

#define OBD_BRW_READ            0x01
#define OBD_BRW_WRITE           0x02
#define OBD_BRW_RWMASK          (OBD_BRW_READ | OBD_BRW_WRITE)
#define OBD_BRW_SYNC            0x08
#define OBD_BRW_CHECK           0x10
#define OBD_BRW_FROM_GRANT      0x20 /* the osc manages this under llite */
#define OBD_BRW_GRANTED         0x40 /* the ost manages this */
#define OBD_BRW_DROP            0x80 /* drop the page after IO */

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

/* request structure for OST's */

#define OST_REQ_HAS_OA1  0x1

struct ost_body {
        struct  obdo oa;
};

extern void lustre_swab_ost_body (struct ost_body *b);
extern void lustre_swab_ost_last_id(obd_id *id);

/* lock value block communicated between the filter and llite */

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
//      REINT_CLOSE    = 7,
//      REINT_WRITE    = 8,
        REINT_MAX
} mds_reint_t;

/* the disposition of the intent outlines what was executed */
#define DISP_IT_EXECD     0x01
#define DISP_LOOKUP_EXECD 0x02
#define DISP_LOOKUP_NEG   0x04
#define DISP_LOOKUP_POS   0x08
#define DISP_OPEN_CREATE  0x10
#define DISP_OPEN_OPEN    0x20
#define DISP_ENQ_COMPLETE 0x40

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

#define MDS_BFLAG_UNCOMMITTED_WRITES   0x1

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
        __u32          padding_1; /* also fix lustre_swab_mds_body */
        __u32          padding_2; /* also fix lustre_swab_mds_body */
        __u32          padding_3; /* also fix lustre_swab_mds_body */
        __u32          padding_4; /* also fix lustre_swab_mds_body */
};

extern void lustre_swab_mds_body (struct mds_body *b);

/* XXX: same as if_dqinfo struct in kernel */
struct obd_dqinfo {
        __u64 dqi_bgrace;
        __u64 dqi_igrace;
        __u32 dqi_flags;
        __u32 dqi_valid;
};

/* XXX: same as if_dqblk struct in kernel, plus one padding */
struct obd_dqblk {
        __u64 dqb_bhardlimit;
        __u64 dqb_bsoftlimit;
        __u64 dqb_curspace;
        __u64 dqb_ihardlimit;
        __u64 dqb_isoftlimit;
        __u64 dqb_curinodes;
        __u64 dqb_btime;
        __u64 dqb_itime;
        __u32 dqb_valid;
        __u32 padding;
};

#define Q_QUOTACHECK    0x800100
#define Q_INITQUOTA     0x800101        /* init slave limits */
#define Q_GETOINFO      0x800102        /* get obd quota info */
#define Q_GETOQUOTA     0x800103        /* get obd quotas */

#define Q_TYPESET(oqc, type) \
        ((oqc)->qc_type == type || (oqc)->qc_type == UGQUOTA)

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

struct mds_rec_setattr {
        __u32           sa_opcode;
        __u32           sa_fsuid;
        __u32           sa_fsgid;
        __u32           sa_cap;
        __u32           sa_suppgid;
        __u32           sa_mode;
        struct ll_fid   sa_fid;
        __u64           sa_valid;
        __u64           sa_size;
        __u64           sa_mtime;
        __u64           sa_atime;
        __u64           sa_ctime;
        __u32           sa_uid;
        __u32           sa_gid;
        __u32           sa_attr_flags;
        __u32           sa_padding; /* also fix lustre_swab_mds_rec_setattr */
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
#define MDS_OPEN_OWNEROVERRIDE 0200000000 /* NFSD rw-reopen ro file for owner */
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

/*
 *  LOV data structures
 */

#define LOV_MIN_STRIPE_SIZE 65536   /* maximum PAGE_SIZE (ia64), power of 2 */
#define LOV_MAX_STRIPE_COUNT  160   /* until bug 4424 is fixed */

#define LOV_MAX_UUID_BUFFER_SIZE  8192
/* The size of the buffer the lov/mdc reserves for the
 * array of UUIDs returned by the MDS.  With the current
 * protocol, this will limit the max number of OSTs per LOV */

#define LOV_DESC_MAGIC 0xB0CCDE5C

struct lov_desc {
        __u32 ld_tgt_count;                /* how many OBD's */
        __u32 ld_active_tgt_count;         /* how many active */
        __u32 ld_default_stripe_count;     /* how many objects are used */
        __u32 ld_pattern;                  /* PATTERN_RAID0, PATTERN_RAID1 */
        __u64 ld_default_stripe_size;      /* in bytes */
        __u64 ld_default_stripe_offset;    /* in bytes */
        __u32 ld_padding_1;                /* also fix lustre_swab_lov_desc */
        __u32 ld_padding_2;                /* also fix lustre_swab_lov_desc */
        __u32 ld_padding_3;                /* also fix lustre_swab_lov_desc */
        __u32 ld_padding_4;                /* also fix lustre_swab_lov_desc */
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

typedef enum {
        LDLM_PLAIN     = 10,
        LDLM_EXTENT    = 11,
        LDLM_FLOCK     = 12,
//      LDLM_IBITS     = 13,
        LDLM_MAX_TYPE
} ldlm_type_t;

#define LDLM_MIN_TYPE LDLM_PLAIN

struct ldlm_extent {
        __u64 start;
        __u64 end;
        __u64 gid;
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
} ldlm_policy_data_t;

extern void lustre_swab_ldlm_policy_data (ldlm_policy_data_t *d);

struct ldlm_intent {
        __u64 opc;
};

extern void lustre_swab_ldlm_intent (struct ldlm_intent *i);

struct ldlm_resource_desc {
        ldlm_type_t lr_type;
        __u32 lr_padding;
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

struct ldlm_request {
        __u32 lock_flags;
        __u32 lock_padding;
        struct ldlm_lock_desc lock_desc;
        struct lustre_handle lock_handle1;
        struct lustre_handle lock_handle2;
};

extern void lustre_swab_ldlm_request (struct ldlm_request *rq);

struct ldlm_reply {
        __u32 lock_flags;
        __u32 lock_padding;
        struct ldlm_lock_desc lock_desc;
        struct lustre_handle lock_handle;
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
        __u32                   lci_padding[3];
} __attribute__((packed));

/* Log data record types - there is no specific reason that these need to
 * be related to the RPC opcodes, but no reason not to (may be handy later?)
 */
#define LLOG_OP_MAGIC 0x10600000
#define LLOG_OP_MASK  0xfff00000

typedef enum {
        LLOG_PAD_MAGIC   = LLOG_OP_MAGIC | 0,
        OST_SZ_REC       = LLOG_OP_MAGIC | (OST_SAN_WRITE << 8),
        OST_RAID1_REC    = LLOG_OP_MAGIC | ((OST_SAN_WRITE + 1) << 8),
        MDS_UNLINK_REC   = LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_UNLINK,
        MDS_SETATTR_REC  = LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_SETATTR,
        OBD_CFG_REC      = LLOG_OP_MAGIC | 0x20000,
        PTL_CFG_REC      = LLOG_OP_MAGIC | 0x30000,
        LLOG_GEN_REC     = LLOG_OP_MAGIC | 0x40000,
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
        __u32                   padding[5];
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

extern void lustre_swab_lov_user_md(struct lov_user_md *lum);
extern void lustre_swab_lov_user_md_objects(struct lov_user_md *lum);

/* llog_swab.c */
extern void lustre_swab_llogd_body (struct llogd_body *d);
extern void lustre_swab_llog_hdr (struct llog_log_hdr *h);
extern void lustre_swab_llogd_conn_body (struct llogd_conn_body *d);
extern void lustre_swab_llog_rec(struct llog_rec_hdr  *rec,
                                 struct llog_rec_tail *tail);

struct portals_cfg;
extern void lustre_swab_portals_cfg(struct portals_cfg *pcfg);

struct lustre_cfg;
extern void lustre_swab_lustre_cfg(struct lustre_cfg *lcfg);

static inline struct ll_fid *obdo_fid(struct obdo *oa)
{
        return (struct ll_fid *)(oa->o_inline + sizeof(struct lustre_handle) +
                                 sizeof(struct llog_cookie));
}

/* qutoa */
struct qunit_data {
        __u32 qd_id;
        __u32 qd_type;
        __u32 qd_count;
        __u32 qd_isblk; /* indicating if it's block quota */
};
extern void lustre_swab_qdata(struct qunit_data *d);

typedef enum {
        QUOTA_DQACQ     = 601,
        QUOTA_DQREL     = 602,
} quota_cmd_t;

#endif
