/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * Lustre wire protocol definitions.
 *
 *
 * We assume all nodes are either little-endian or big-endian, and we
 * always send messages in the sender's native format.  The receiver
 * detects the message format by checking the 'magic' field of the message
 * (see lustre_msg_swabbed() below).
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

#include <libcfs/kp30.h>

#include <lustre/types.h>

/* Defn's shared with user-space. */
#include <lustre/lustre_user.h>

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
#define MDS_MDS_PORTAL                 24

#define MGC_REPLY_PORTAL               25
#define MGS_REQUEST_PORTAL             26
#define MGS_REPLY_PORTAL               27
#define OST_REQUEST_PORTAL             28
#define FLD_REQUEST_PORTAL             29
#define SEQ_METADATA_PORTAL            30
#define SEQ_DATA_PORTAL                31
#define SEQ_CONTROLLER_PORTAL          32

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

typedef __u64 mdsno_t;
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

struct lu_fid {
        __u64 f_seq;  /* holds fid sequence. Lustre should support 2 ^ 64
                       * objects, thus even if one sequence has one object we
                       * reach this value. */
        __u32 f_oid;  /* fid number within its sequence. */
        __u32 f_ver;  /* holds fid version. */
};

/*
 * fid constants
 */
enum {
        LUSTRE_ROOT_FID_SEQ  = 1ULL, /* XXX: should go into mkfs. */

        /* initial fid id value */
        LUSTRE_FID_INIT_OID  = 1UL
};

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

static inline int fid_seq_is_sane(__u64 seq)
{
        return seq != 0;
}

static inline void fid_zero(struct lu_fid *fid)
{
        memset(fid, 0, sizeof(*fid));
}

static inline int fid_is_igif(const struct lu_fid *fid)
{
        return fid_seq(fid) == LUSTRE_ROOT_FID_SEQ;
}

#define DFID "[0x%16.16"LPF64"x/0x%8.8x:0x%8.8x]"

#define PFID(fid)     \
        fid_seq(fid), \
        fid_oid(fid), \
        fid_ver(fid)

static inline void fid_cpu_to_le(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        LASSERTF(fid_is_igif(src) || fid_ver(src) == 0, DFID"\n", PFID(src));
        dst->f_seq = cpu_to_le64(fid_seq(src));
        dst->f_oid = cpu_to_le32(fid_oid(src));
        dst->f_ver = cpu_to_le32(fid_ver(src));
}

static inline void fid_le_to_cpu(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = le64_to_cpu(fid_seq(src));
        dst->f_oid = le32_to_cpu(fid_oid(src));
        dst->f_ver = le32_to_cpu(fid_ver(src));
        LASSERTF(fid_is_igif(dst) || fid_ver(dst) == 0, DFID"\n", PFID(dst));
}

static inline void fid_cpu_to_be(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        LASSERTF(fid_is_igif(src) || fid_ver(src) == 0, DFID"\n", PFID(src));
        dst->f_seq = cpu_to_be64(fid_seq(src));
        dst->f_oid = cpu_to_be32(fid_oid(src));
        dst->f_ver = cpu_to_be32(fid_ver(src));
}

static inline void fid_be_to_cpu(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = be64_to_cpu(fid_seq(src));
        dst->f_oid = be32_to_cpu(fid_oid(src));
        dst->f_ver = be32_to_cpu(fid_ver(src));
        LASSERTF(fid_is_igif(dst) || fid_ver(dst) == 0, DFID"\n", PFID(dst));
}

#ifdef __KERNEL__
/*
 * Storage representation for fids.
 *
 * Variable size, first byte contains the length of the whole record.
 */

struct lu_fid_pack {
        char fp_len;
        char fp_area[sizeof(struct lu_fid)];
};

void fid_pack(struct lu_fid_pack *pack, const struct lu_fid *fid,
              struct lu_fid *befider);
int  fid_unpack(const struct lu_fid_pack *pack, struct lu_fid *fid);

/* __KERNEL__ */
#endif

static inline int fid_is_sane(const struct lu_fid *fid)
{
        return
                fid != NULL &&
                ((fid_seq_is_sane(fid_seq(fid)) && fid_oid(fid) != 0
                                                && fid_ver(fid) == 0) ||
                fid_is_igif(fid));
}

static inline int fid_is_zero(const struct lu_fid *fid)
{
        return fid_seq(fid) == 0 && fid_oid(fid) == 0;
}

extern void lustre_swab_lu_fid(struct lu_fid *fid);
extern void lustre_swab_lu_range(struct lu_range *range);

static inline int lu_fid_eq(const struct lu_fid *f0,
                            const struct lu_fid *f1)
{
	/* Check that there is no alignment padding. */
	CLASSERT(sizeof *f0 ==
                 sizeof f0->f_seq + sizeof f0->f_oid + sizeof f0->f_ver);
        LASSERTF(fid_is_igif(f0) || fid_ver(f0) == 0, DFID, PFID(f0));
        LASSERTF(fid_is_igif(f1) || fid_ver(f1) == 0, DFID, PFID(f1));
	return memcmp(f0, f1, sizeof *f0) == 0;
}

/*
 * Layout of readdir pages, as transmitted on wire.
 */
struct lu_dirent {
        struct lu_fid lde_fid;
        __u64         lde_hash;
        __u16         lde_reclen;
        __u16         lde_namelen;
        __u32         lde_pad0;
        char          lde_name[0];
};

struct lu_dirpage {
        __u64            ldp_hash_start;
        __u64            ldp_hash_end;
        __u16            ldp_flags;
        __u16            ldp_pad;
        __u32            ldp_pad0;
        struct lu_dirent ldp_entries[0];
};

enum lu_dirpage_flags {
        LDF_EMPTY = 1 << 0
};

static inline struct lu_dirent *lu_dirent_start(struct lu_dirpage *dp)
{
        if (le16_to_cpu(dp->ldp_flags) & LDF_EMPTY)
                return NULL;
        else
                return dp->ldp_entries;
}

static inline struct lu_dirent *lu_dirent_next(struct lu_dirent *ent)
{
        struct lu_dirent *next;

        if (le16_to_cpu(ent->lde_reclen) != 0)
                next = ((void *)ent) + le16_to_cpu(ent->lde_reclen);
        else
                next = NULL;

        return next;
}

static inline int lu_dirent_size(struct lu_dirent *ent)
{
        if (le16_to_cpu(ent->lde_reclen) == 0) {
                return (sizeof(*ent) +
                        le16_to_cpu(ent->lde_namelen) + 3) & ~3;
        }
        return le16_to_cpu(ent->lde_reclen);
}

#define DIR_END_OFF              0xfffffffffffffffeULL

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

#define lustre_msg lustre_msg_v2
/* we depend on this structure to be 8-byte aligned */
/* this type is only endian-adjusted in lustre_unpack_msg() */
struct lustre_msg_v2 {
        __u32 lm_bufcount;
        __u32 lm_secflvr;
        __u32 lm_magic;
        __u32 lm_repsize;
        __u32 lm_timeout;
        __u32 lm_padding_1;
        __u32 lm_padding_2;
        __u32 lm_padding_3;
        __u32 lm_buflens[0];
};

/* without gss, ptlrpc_body is put at the first buffer. */
struct ptlrpc_body {
        struct lustre_handle pb_handle;
        __u32 pb_type;
        __u32 pb_version;
        __u32 pb_opc;
        __u32 pb_status;
        __u64 pb_last_xid;
        __u64 pb_last_seen;
        __u64 pb_last_committed;
        __u64 pb_transno;
        __u32 pb_flags;
        __u32 pb_op_flags;
        __u32 pb_conn_cnt;
        __u32 pb_padding_1;
        __u32 pb_padding_2;
        __u32 pb_limit;
        __u64 pb_slv;
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

/* Flags that are operation-specific go in the top 16 bits. */
#define MSG_OP_FLAG_MASK   0xffff0000
#define MSG_OP_FLAG_SHIFT  16

/* Flags that apply to all requests are in the bottom 16 bits */
#define MSG_GEN_FLAG_MASK      0x0000ffff
#define MSG_LAST_REPLAY        1
#define MSG_RESENT             2
#define MSG_REPLAY             4
#define MSG_REQ_REPLAY_DONE    8
#define MSG_LOCK_REPLAY_DONE  16

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
#define MSG_CONNECT_NEXT_VER    0x80  /* use next version of lustre_msg */
#define MSG_CONNECT_TRANSNO     0x100 /* report transno */

/* Connect flags */
#define OBD_CONNECT_RDONLY     0x00000001ULL /* client allowed read-only access */
#define OBD_CONNECT_INDEX      0x00000002ULL /* connect to specific LOV idx */
#define OBD_CONNECT_GRANT      0x00000008ULL /* OSC acquires grant at connect */
#define OBD_CONNECT_SRVLOCK    0x00000010ULL /* server takes locks for client */
#define OBD_CONNECT_VERSION    0x00000020ULL /* Server supports versions in ocd */
#define OBD_CONNECT_REQPORTAL  0x00000040ULL /* Separate portal for non-IO reqs */
#define OBD_CONNECT_ACL        0x00000080ULL /* client uses access control lists */
#define OBD_CONNECT_XATTR      0x00000100ULL /* client using extended attributes*/
#define OBD_CONNECT_TRUNCLOCK  0x00000400ULL /* locks on server for punch b=9528 */
#define OBD_CONNECT_IBITS      0x00001000ULL /* support for inodebits locks */
#define OBD_CONNECT_JOIN       0x00002000ULL /* files can be concatenated */
#define OBD_CONNECT_ATTRFID    0x00004000ULL /* Server supports GetAttr By Fid */
#define OBD_CONNECT_NODEVOH    0x00008000ULL /* No open handle for special nodes */
#define OBD_CONNECT_LCL_CLIENT 0x00010000ULL /* local 1.8 client */
#define OBD_CONNECT_RMT_CLIENT 0x00020000ULL /* Remote 1.8 client */
#define OBD_CONNECT_BRW_SIZE   0x00040000ULL /* Max bytes per rpc */
#define OBD_CONNECT_QUOTA64    0x00080000ULL /* 64bit qunit_data.qd_count b=10707*/
#define OBD_CONNECT_MDS_CAPA   0x00100000ULL /* MDS capability */
#define OBD_CONNECT_OSS_CAPA   0x00200000ULL /* OSS capability */
#define OBD_CONNECT_CANCELSET  0x00400000ULL /* Early batched cancels. */
#define OBD_CONNECT_SOM        0x00800000ULL /* SOM feature */
#define OBD_CONNECT_AT         0x01000000ULL /* client uses adaptive timeouts */
#define OBD_CONNECT_LRU_RESIZE 0x02000000ULL /* Lru resize feature. */
#define OBD_CONNECT_MDS_MDS    0x04000000ULL /* MDS-MDS connection*/
#define OBD_CONNECT_REAL       0x08000000ULL /* real connection */
#define OBD_CONNECT_CHANGE_QS  0x10000000ULL /*shrink/enlarge qunit size
                                              *b=10600 */
#define OBD_CONNECT_CKSUM      0x20000000ULL /* support several cksum algos */
#define OBD_CONNECT_FID        0x40000000ULL /* FID is supported by server */

/* also update obd_connect_names[] for lprocfs_rd_connect_flags()
 * and lustre/utils/wirecheck.c */

#ifdef HAVE_LRU_RESIZE_SUPPORT
#define LRU_RESIZE_CONNECT_FLAG OBD_CONNECT_LRU_RESIZE
#else
#define LRU_RESIZE_CONNECT_FLAG 0
#endif

#define MDT_CONNECT_SUPPORTED  (OBD_CONNECT_RDONLY | OBD_CONNECT_VERSION | \
                                OBD_CONNECT_ACL | OBD_CONNECT_XATTR | \
                                OBD_CONNECT_IBITS | OBD_CONNECT_JOIN | \
                                OBD_CONNECT_NODEVOH |/* OBD_CONNECT_ATTRFID |*/\
                                OBD_CONNECT_LCL_CLIENT | \
                                OBD_CONNECT_RMT_CLIENT | \
                                OBD_CONNECT_MDS_CAPA | OBD_CONNECT_OSS_CAPA | \
                                OBD_CONNECT_MDS_MDS | OBD_CONNECT_CANCELSET | \
                                OBD_CONNECT_FID | \
                                LRU_RESIZE_CONNECT_FLAG)
#define OST_CONNECT_SUPPORTED  (OBD_CONNECT_SRVLOCK | OBD_CONNECT_GRANT | \
                                OBD_CONNECT_REQPORTAL | OBD_CONNECT_VERSION | \
                                OBD_CONNECT_TRUNCLOCK | OBD_CONNECT_INDEX | \
                                OBD_CONNECT_BRW_SIZE | OBD_CONNECT_QUOTA64 | \
                                OBD_CONNECT_OSS_CAPA | OBD_CONNECT_CANCELSET | \
                                OBD_CONNECT_FID | OBD_CONNECT_CKSUM | \
                                LRU_RESIZE_CONNECT_FLAG)
#define ECHO_CONNECT_SUPPORTED (0)
#define MGS_CONNECT_SUPPORTED  (OBD_CONNECT_VERSION | OBD_CONNECT_FID)

#define MAX_QUOTA_COUNT32 (0xffffffffULL)

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
        __u64 ocd_connect_flags; /* OBD_CONNECT_* per above */
        __u32 ocd_version;       /* lustre release version number */
        __u32 ocd_grant;         /* initial cache grant amount (bytes) */
        __u32 ocd_index;         /* LOV index to connect to */
        __u32 ocd_brw_size;      /* Maximum BRW size in bytes */
        __u64 ocd_ibits_known;   /* inode bits this client understands */
        __u32 ocd_nllu;          /* non-local-lustre-user */
        __u32 ocd_nllg;          /* non-local-lustre-group */
        __u64 ocd_transno;       /* first transno from client to be replayed */
        __u32 ocd_group;         /* MDS group on OST */
        __u32 ocd_cksum_types;   /* supported checksum algorithms */
        __u64 padding1;          /* also fix lustre_swab_connect */
        __u64 padding2;          /* also fix lustre_swab_connect */
};

extern void lustre_swab_connect(struct obd_connect_data *ocd);

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

/*
 * Set this to delegate DLM locking during obd_punch() to the OSTs. Only OSTs
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

/*
 * This should not be smaller than sizeof(struct lustre_handle) + sizeof(struct
 * llog_cookie) + sizeof(struct ll_fid). Nevertheless struct ll_fid is not
 * longer stored in o_inline, we keep this just for case.
 */
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
        __u32                   o_stripe_idx;   /* holds stripe idx */
        __u32                   o_padding_1;
        char                    o_inline[OBD_INLINESZ];
                                /* lustre_handle + llog_cookie */
};

#define o_dirty   o_blocks
#define o_undirty o_mode
#define o_dropped o_misc
#define o_cksum   o_nlink

extern void lustre_swab_obdo (struct obdo *o);


#define LOV_MAGIC_V1      0x0BD10BD0
#define LOV_MAGIC         LOV_MAGIC_V1
#define LOV_MAGIC_JOIN    0x0BD20BD0

#define LOV_PATTERN_RAID0 0x001   /* stripes are used round-robin */
#define LOV_PATTERN_RAID1 0x002   /* stripes are mirrors of each other */
#define LOV_PATTERN_FIRST 0x100   /* first stripe is not in round-robin */
#define LOV_PATTERN_CMOBD 0x200

#define LOV_OBJECT_GROUP_DEFAULT ~0ULL
#define LOV_OBJECT_GROUP_CLEAR 0ULL

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

extern void lustre_swab_lov_mds_md(struct lov_mds_md *llm);

#define MAX_MD_SIZE (sizeof(struct lov_mds_md) + 4 * sizeof(struct lov_ost_data))
#define MIN_MD_SIZE (sizeof(struct lov_mds_md) + 1 * sizeof(struct lov_ost_data))

#define XATTR_NAME_ACL_ACCESS   "system.posix_acl_access"
#define XATTR_NAME_ACL_DEFAULT  "system.posix_acl_default"
#define XATTR_NAME_LOV          "trusted.lov"

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
#define OBD_MD_FLFID       (0x02000000ULL) /* ->ost write inline fid */
#define OBD_MD_FLEPOCH     (0x04000000ULL) /* ->ost write easize is epoch */
                                           /* ->mds if epoch opens or closes */
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

#define OBD_MD_FLRMTLSETFACL    (0x0001000000000000ULL) /* lfs lsetfacl case */
#define OBD_MD_FLRMTLGETFACL    (0x0002000000000000ULL) /* lfs lgetfacl case */
#define OBD_MD_FLRMTRSETFACL    (0x0004000000000000ULL) /* lfs rsetfacl case */
#define OBD_MD_FLRMTRGETFACL    (0x0008000000000000ULL) /* lfs rgetfacl case */

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

/* request structure for OST's */

struct ost_body {
        struct  obdo oa;
};

extern void lustre_swab_ost_body (struct ost_body *b);
extern void lustre_swab_ost_last_id(obd_id *id);

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
        MDS_SETXATTR     = 50, /* obsolete, now it's MDS_REINT op */
        MDS_WRITEPAGE    = 51,
        MDS_IS_SUBDIR    = 52,
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
} mds_reint_t, mdt_reint_t;

extern void lustre_swab_generic_32s (__u32 *val);

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

struct ll_fid {
        __u64 id;         /* holds object id */
        __u32 generation; /* holds object generation */

        __u32 f_type;     /* holds object type or stripe idx when passing it to
                           * OST for saving into EA. */
};

extern void lustre_swab_ll_fid (struct ll_fid *fid);

#define MDS_STATUS_CONN 1
#define MDS_STATUS_LOV 2

struct mds_status_req {
        __u32  flags;
        __u32  repbuf;
};

extern void lustre_swab_mds_status_req (struct mds_status_req *r);

/* mdt_thread_info.mti_flags. */
enum md_op_flags {
        /* The flag indicates Size-on-MDS attributes are changed. */
        MF_SOM_CHANGE           = (1 << 0),
        /* Flags indicates an epoch opens or closes. */
        MF_EPOCH_OPEN           = (1 << 1),
        MF_EPOCH_CLOSE          = (1 << 2),
        MF_MDC_CANCEL_FID1      = (1 << 3),
        MF_MDC_CANCEL_FID2      = (1 << 4),
        MF_MDC_CANCEL_FID3      = (1 << 5),
        MF_MDC_CANCEL_FID4      = (1 << 6),
};

#define MF_SOM_LOCAL_FLAGS (MF_MDC_CANCEL_FID1 | MF_MDC_CANCEL_FID2 | \
                            MF_MDC_CANCEL_FID3 | MF_MDC_CANCEL_FID4)

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

/* If MDS_BFLAG_EXT_FLAGS is set it means we requested EXT3_*_FL inode flags
 * and we pass these straight through.  Otherwise we need to convert from
 * S_* flags to their EXT3_*_FL equivalents (see bug 9486). */
static inline int ll_inode_to_ext_flags(int oflags, int iflags)
{
        return (oflags & MDS_BFLAG_EXT_FLAGS) ? (oflags & ~MDS_BFLAG_EXT_FLAGS):
               (((iflags & S_SYNC)      ? MDS_SYNC_FL      : 0) |
                ((iflags & S_NOATIME)   ? MDS_NOATIME_FL   : 0) |
                ((iflags & S_APPEND)    ? MDS_APPEND_FL    : 0) |
#if defined(S_DIRSYNC)
                ((iflags & S_DIRSYNC)   ? MDS_DIRSYNC_FL   : 0) |
#endif
                ((iflags & S_IMMUTABLE) ? MDS_IMMUTABLE_FL : 0));
}
#endif

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
extern void lustre_swab_mdt_body (struct mdt_body *b);

struct mdt_epoch {
        struct lustre_handle handle;
        __u64  ioepoch;
        __u32  flags;
        __u32  padding;
};

extern void lustre_swab_mdt_epoch (struct mdt_epoch *b);

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

/* inode access permission for remote user, the inode info are omitted,
 * for client knows them. */
struct mds_remote_perm {
        __u32           rp_uid;
        __u32           rp_gid;
        __u32           rp_fsuid;
        __u32           rp_fsgid;
        __u32           rp_access_perm; /* MAY_READ/WRITE/EXEC */
};

/* permissions for md_perm.mp_perm */
enum {
        CFS_SETUID_PERM = 0x01,
        CFS_SETGID_PERM = 0x02,
        CFS_SETGRP_PERM = 0x04,
        CFS_RMTACL_PERM = 0x08
};

extern void lustre_swab_mds_remote_perm(struct mds_remote_perm *p);

struct mdt_remote_perm {
        __u32           rp_uid;
        __u32           rp_gid;
        __u32           rp_fsuid;
        __u32           rp_fsgid;
        __u32           rp_access_perm; /* MAY_READ/WRITE/EXEC */
};

extern void lustre_swab_mdt_remote_perm(struct mdt_remote_perm *p);

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

extern void lustre_swab_mds_rec_setattr (struct mds_rec_setattr *sa);

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

extern void lustre_swab_mdt_rec_setattr (struct mdt_rec_setattr *sa);

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

#ifndef FMODE_READ
#define FMODE_READ               00000001
#define FMODE_WRITE              00000002
#endif

#define FMODE_EPOCH              01000000
#define FMODE_EPOCHLCK           02000000
#define FMODE_SOM                04000000
#define FMODE_CLOSED             0

#define MDS_OPEN_CREATED         00000010
#define MDS_OPEN_CROSS           00000020

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
#define MDS_CREATE_RMT_ACL    01000000000 /* indicate create on remote server
                                           * with default ACL */
#define MDS_CREATE_SLAVE_OBJ  02000000000 /* indicate create slave object
                                           * actually, this is for create, not
                                           * conflict with other open flags */
#define MDS_OPEN_LOCK         04000000000 /* This open requires open lock */
#define MDS_OPEN_HAS_EA      010000000000 /* specify object create pattern */
#define MDS_OPEN_HAS_OBJS    020000000000 /* Just set the EA the obj exist */

/* permission for create non-directory file */
#define MAY_CREATE      (1 << 7)
/* permission for create directory file */
#define MAY_LINK        (1 << 8)
/* permission for delete from the directory */
#define MAY_UNLINK      (1 << 9)
/* source's permission for rename */
#define MAY_RENAME_SRC  (1 << 10)
/* target's permission for rename */
#define MAY_RENAME_TAR  (1 << 11)
/* part (parent's) VTX permission check */
#define MAY_VTX_PART    (1 << 12)
/* full VTX permission check */
#define MAY_VTX_FULL    (1 << 13)
/* lfs rgetfacl permission check */
#define MAY_RGETFACL    (1 << 14)

enum {
        MDS_CHECK_SPLIT  = 1 << 0,
        MDS_CROSS_REF    = 1 << 1,
        MDS_VTX_BYPASS   = 1 << 2,
        MDS_PERM_BYPASS  = 1 << 3
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

extern void lustre_swab_mdt_rec_join (struct mdt_rec_join *jr);

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
        struct lustre_handle cr_old_handle; /* u64 handle in case of open replay */
        __u64           cr_time;
        __u64           cr_rdev;
        __u64           cr_ioepoch;
        __u64           cr_padding_1; /* pad for 64 bits*/
        __u32           cr_mode;
        __u32           cr_bias;
        __u32           cr_flags;     /* for use with open */
        __u32           cr_padding_2;
        __u32           cr_padding_3;
        __u32           cr_padding_4;
};

extern void lustre_swab_mdt_rec_create (struct mdt_rec_create *cr);

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
        __u32           ul_suppgid2;
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

struct mdt_rec_reint {
        __u32           rr_opcode;
        __u32           rr_fsuid;
        __u32           rr_fsgid;
        __u32           rr_cap;
        __u32           rr_suppgid1;
        __u32           rr_suppgid2;
        struct lu_fid   rr_fid1;
        struct lu_fid   rr_fid2;
        __u64           rr_mtime;
        __u64           rr_atime;
        __u64           rr_ctime;
        __u64           rr_size;
        __u64           rr_blocks;
        __u32           rr_bias;
        __u32           rr_mode;
        __u32           rr_padding_1; /* also fix lustre_swab_mdt_rec_reint */
        __u32           rr_padding_2; /* also fix lustre_swab_mdt_rec_reint */
        __u32           rr_padding_3; /* also fix lustre_swab_mdt_rec_reint */
        __u32           rr_padding_4; /* also fix lustre_swab_mdt_rec_reint */
};

extern void lustre_swab_mdt_rec_reint(struct mdt_rec_reint *rr);

struct lmv_desc {
        __u32 ld_tgt_count;                /* how many MDS's */
        __u32 ld_active_tgt_count;         /* how many active */
        struct obd_uuid ld_uuid;
};

extern void lustre_swab_lmv_desc (struct lmv_desc *ld);

struct md_fld {
        seqno_t mf_seq;
        mdsno_t mf_mds;
};

extern void lustre_swab_md_fld (struct md_fld *mf);

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
        LCK_EX      = 1,
        LCK_PW      = 2,
        LCK_PR      = 4,
        LCK_CW      = 8,
        LCK_CR      = 16,
        LCK_NL      = 32,
        LCK_GROUP   = 64,
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

extern void lustre_swab_ldlm_request (struct ldlm_request *rq);

/* If LDLM_ENQUEUE, 1 slot is already occupied, 1 is available.
 * Otherwise, 2 are available. */
#define ldlm_request_bufsize(count,type)                                \
({                                                                      \
        int _avail = LDLM_LOCKREQ_HANDLES;                              \
        _avail -= (type == LDLM_ENQUEUE ? LDLM_ENQUEUE_CANCEL_OFF : 0); \
        sizeof(struct ldlm_request) +                                   \
        (count > _avail ? count - _avail : 0) *                         \
        sizeof(struct lustre_handle);                                   \
})

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
        __u32                   lsc_ioepoch;
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
        LLOG_ORIGIN_HANDLE_PREV_BLOCK   = 508,
        LLOG_ORIGIN_HANDLE_DESTROY      = 509,  /* for destroy llog object*/
        LLOG_LAST_OPC,
        LLOG_FIRST_OPC                  = LLOG_ORIGIN_HANDLE_CREATE
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

extern void lustre_swab_lov_user_md(struct lov_user_md *lum);
extern void lustre_swab_lov_user_md_objects(struct lov_user_md *lum);
extern void lustre_swab_lov_user_md_join(struct lov_user_md_join *lumj);

/* llog_swab.c */
extern void lustre_swab_llogd_body (struct llogd_body *d);
extern void lustre_swab_llog_hdr (struct llog_log_hdr *h);
extern void lustre_swab_llogd_conn_body (struct llogd_conn_body *d);
extern void lustre_swab_llog_rec(struct llog_rec_hdr  *rec,
                                 struct llog_rec_tail *tail);

struct lustre_cfg;
extern void lustre_swab_lustre_cfg(struct lustre_cfg *lcfg);

/* quota. fixed by tianzy for bug10707 */
#define QUOTA_IS_GRP   0X1UL  /* 0 is user, 1 is group. Used by qd_flags*/
#define QUOTA_IS_BLOCK 0x2UL  /* 0 is inode, 1 is block. Used by qd_flags*/

struct qunit_data {
        __u32 qd_id; /* ID appiles to (uid, gid) */
        __u32 qd_flags; /* Quota type (USRQUOTA, GRPQUOTA) occupy one bit;
                         * Block quota or file quota occupy one bit */
        __u64 qd_count; /* acquire/release count (bytes for block quota) */
};

struct qunit_data_old {
        __u32 qd_id;    /* ID appiles to (uid, gid) */
        __u32 qd_type;  /* Quota type (USRQUOTA, GRPQUOTA) */
        __u32 qd_count; /* acquire/release count (bytes for block quota) */
        __u32 qd_isblk; /* Block quota or file quota */
};

extern void lustre_swab_qdata(struct qunit_data *d);
extern void lustre_swab_qdata_old(struct qunit_data_old *d);
extern struct qunit_data *lustre_quota_old_to_new(struct qunit_data_old *d);
extern struct qunit_data_old *lustre_quota_new_to_old(struct qunit_data *d);

typedef enum {
        QUOTA_DQACQ     = 601,
        QUOTA_DQREL     = 602,
} quota_cmd_t;

#define JOIN_FILE_ALIGN 4096

/* security opcodes */
typedef enum {
        SEC_CTX_INIT            = 801,
        SEC_CTX_INIT_CONT       = 802,
        SEC_CTX_FINI            = 803,
        SEC_LAST_OPC,
        SEC_FIRST_OPC           = SEC_CTX_INIT
} sec_cmd_t;

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

extern void lustre_swab_lustre_capa(struct lustre_capa *c);

/* lustre_capa.lc_opc */
enum {
        CAPA_OPC_BODY_WRITE   = 1<<0,  /* write object data */
        CAPA_OPC_BODY_READ    = 1<<1,  /* read object data */
        CAPA_OPC_INDEX_LOOKUP = 1<<2,  /* lookup object fid */
        CAPA_OPC_INDEX_INSERT = 1<<3,  /* insert object fid */
        CAPA_OPC_INDEX_DELETE = 1<<4,  /* delete object fid */
        CAPA_OPC_OSS_WRITE    = 1<<5,  /* write oss object data */
        CAPA_OPC_OSS_READ     = 1<<6,  /* read oss object data */
        CAPA_OPC_OSS_TRUNC    = 1<<7,  /* truncate oss object */
        CAPA_OPC_META_WRITE   = 1<<8,  /* write object meta data */
        CAPA_OPC_META_READ    = 1<<9,  /* read object meta data */

};

#define CAPA_OPC_OSS_RW (CAPA_OPC_OSS_READ | CAPA_OPC_OSS_WRITE)
#define CAPA_OPC_MDS_ONLY                                                   \
        (CAPA_OPC_BODY_WRITE | CAPA_OPC_BODY_READ | CAPA_OPC_INDEX_LOOKUP | \
         CAPA_OPC_INDEX_INSERT | CAPA_OPC_INDEX_DELETE)
#define CAPA_OPC_OSS_ONLY                                                   \
        (CAPA_OPC_OSS_WRITE | CAPA_OPC_OSS_READ | CAPA_OPC_OSS_TRUNC)
#define CAPA_OPC_MDS_DEFAULT ~CAPA_OPC_OSS_ONLY
#define CAPA_OPC_OSS_DEFAULT ~(CAPA_OPC_MDS_ONLY | CAPA_OPC_OSS_ONLY)

/* MDS capability covers object capability for operations of body r/w
 * (dir readpage/sendpage), index lookup/insert/delete and meta data r/w,
 * while OSS capability only covers object capability for operations of
 * oss data(file content) r/w/truncate.
 */
static inline int capa_for_mds(struct lustre_capa *c)
{
        return (c->lc_opc & CAPA_OPC_INDEX_LOOKUP) != 0;
}

static inline int capa_for_oss(struct lustre_capa *c)
{
        return (c->lc_opc & CAPA_OPC_INDEX_LOOKUP) == 0;
}

/* lustre_capa.lc_hmac_alg */
enum {
        CAPA_HMAC_ALG_SHA1 = 1, /* sha1 algorithm */
        CAPA_HMAC_ALG_MAX,
};

#define CAPA_FL_MASK            0x00ffffff
#define CAPA_HMAC_ALG_MASK      0xff000000

struct lustre_capa_key {
        __u64   lk_mdsid;     /* mds# */
        __u32   lk_keyid;     /* key# */
        __u32   lk_padding;
        __u8    lk_key[CAPA_HMAC_KEY_MAX_LEN];    /* key */
} __attribute__((packed));

extern void lustre_swab_lustre_capa_key(struct lustre_capa_key *k);

/* quota check function */
#define QUOTA_RET_OK           0 /* return successfully */
#define QUOTA_RET_NOQUOTA      1 /* not support quota */
#define QUOTA_RET_NOLIMIT      2 /* quota limit isn't set */
#define QUOTA_RET_ACQUOTA      3 /* need to acquire extra quota */
#endif
