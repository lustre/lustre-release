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
 */

#ifndef _LUSTRE_IDL_H_
#define _LUSTRE_IDL_H_

#ifdef __KERNEL__
# include <linux/ioctl.h>
# include <asm/types.h>
# include <linux/types.h>
# include <linux/list.h>
#else
# define __KERNEL__
# include <asm/types.h>
# include <linux/list.h>
# undef __KERNEL__
# include <stdint.h>
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
typedef __u8 uuid_t[37];

/* FOO_REQUEST_PORTAL is for incoming requests on the FOO
 * FOO_REPLY_PORTAL   is for incoming replies on the FOO
 * FOO_BULK_PORTAL    is for incoming bulk on the FOO
 */

#define CONNMGR_REQUEST_PORTAL  1
#define CONNMGR_REPLY_PORTAL    2
#define OSC_REQUEST_PORTAL      3
#define OSC_REPLY_PORTAL        4
#define OSC_BULK_PORTAL         5
#define OST_REQUEST_PORTAL      6
#define OST_REPLY_PORTAL        7
#define OST_BULK_PORTAL         8
#define MDC_REQUEST_PORTAL      9
#define MDC_REPLY_PORTAL        10
#define MDC_BULK_PORTAL         11
#define MDS_REQUEST_PORTAL      12
#define MDS_REPLY_PORTAL        13
#define MDS_BULK_PORTAL         14
#define LDLM_REQUEST_PORTAL     15
#define LDLM_REPLY_PORTAL       16
#define LDLM_CLI_REQUEST_PORTAL 17
#define LDLM_CLI_REPLY_PORTAL   18

#define SVC_KILLED               1
#define SVC_EVENT                2
#define SVC_SIGNAL               4
#define SVC_RUNNING              8
#define SVC_STOPPING            16
#define SVC_STOPPED             32

#define RECOVD_STOPPING          1  /* how cleanup tells recovd to quit */
#define RECOVD_IDLE              2  /* normal state */
#define RECOVD_STOPPED           4  /* after recovd has stopped */
#define RECOVD_FAIL              8  /* RPC timeout: wakeup recovd, sets flag */
#define RECOVD_TIMEOUT          16  /* set when recovd detects a timeout */
#define RECOVD_UPCALL_WAIT      32  /* an upcall has been placed */
#define RECOVD_UPCALL_ANSWER    64  /* an upcall has been answered */

#define LUSTRE_CONN_NEW          1
#define LUSTRE_CONN_CON          2
#define LUSTRE_CONN_RECOVD       3
#define LUSTRE_CONN_FULL         4

/* packet types */
#define PTL_RPC_MSG_REQUEST 4711
#define PTL_RPC_MSG_ERR 4712
#define PTL_RPC_MSG_OK           0

#define PTL_RPC_TYPE_REQUEST     2
#define PTL_RPC_TYPE_REPLY       3

#define PTLRPC_MSG_MAGIC (cpu_to_le32(0x0BD00BD0))
#define PTLRPC_MSG_VERSION (cpu_to_le32(0x00040001))

struct lustre_handle {
        __u64 addr;
        __u64 cookie;
};

/* we depend on this structure to be 8-byte aligned */
struct lustre_msg {
        __u64 addr;
        __u64 cookie; /* security token */
        __u32 magic;
        __u32 type;
        __u32 version;
        __u32 opc;
        __u64 last_rcvd;
        __u64 last_committed;
        __u64 transno;
        __u32 status;
        __u32 bufcount;
        __u32 buflens[0];
};

#define CONNMGR_REPLY	0
#define CONNMGR_CONNECT	1

/*
 *   OST requests: OBDO & OBD request records
 */

/* opcodes */
#define OST_REPLY      0	/* reply ? */
#define OST_GETATTR    1
#define OST_SETATTR    2
#define OST_READ       3
#define OST_WRITE      4
#define OST_CREATE     5 
#define OST_DESTROY    6 
#define OST_GET_INFO   7 
#define OST_CONNECT    8 
#define OST_DISCONNECT 9 
#define OST_PUNCH      10
#define OST_OPEN       11
#define OST_CLOSE      12
#define OST_STATFS     13


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

/* Note: 64-bit types are 64-bit aligned in structure */
struct obdo {
        obd_id                  o_id;
        obd_gr                  o_gr;
        obd_time                o_atime;
        obd_time                o_mtime;
        obd_time                o_ctime;
        obd_size                o_size;
        obd_blocks              o_blocks;
        obd_rdev                o_rdev;
        obd_blksize             o_blksize;
        obd_mode                o_mode;
        obd_uid                 o_uid;
        obd_gid                 o_gid;
        obd_flag                o_flags;
        obd_count               o_nlink;
        obd_count               o_generation;
        obd_flag                o_valid;        /* hot fields in this obdo */
        obd_flag                o_obdflags;
        __u32                   o_easize;
        char                    o_inline[OBD_INLINESZ];
};

struct lov_object_id { /* per-child structure */
        __u64 l_object_id;
};

#define LOV_MAGIC  0x0BD00BD0

struct lov_stripe_md {
        __u32 lmd_magic;
        __u32 lmd_easize;          /* packed size of extended */
        __u64 lmd_object_id;       /* lov object id */
        __u64 lmd_stripe_offset;   /* offset of the stripe */ 
        __u64 lmd_stripe_size;     /* size of the stripe */
        __u32 lmd_stripe_count;    /* how many objects are being striped */
        __u32 lmd_stripe_pattern;  /* per-lov object stripe pattern */
        struct lov_object_id lmd_objects[0];
};

#define OBD_MD_FLALL    (0xffffffff)
#define OBD_MD_FLID     (0x00000001)
#define OBD_MD_FLATIME  (0x00000002)
#define OBD_MD_FLMTIME  (0x00000004)
#define OBD_MD_FLCTIME  (0x00000008)
#define OBD_MD_FLSIZE   (0x00000010)
#define OBD_MD_FLBLOCKS (0x00000020)
#define OBD_MD_FLBLKSZ  (0x00000040)
#define OBD_MD_FLMODE   (0x00000080)
#define OBD_MD_FLTYPE   (0x00000100)
#define OBD_MD_FLUID    (0x00000200)
#define OBD_MD_FLGID    (0x00000400)
#define OBD_MD_FLFLAGS  (0x00000800)
#define OBD_MD_FLOBDFLG (0x00001000)
#define OBD_MD_FLNLINK  (0x00002000)
#define OBD_MD_FLGENER  (0x00004000)
#define OBD_MD_FLINLINE (0x00008000)
#define OBD_MD_FLRDEV   (0x00010000)
#define OBD_MD_FLEASIZE (0x00020000)
#define OBD_MD_LINKNAME (0x00040000)
#define OBD_MD_FLNOTOBD (~(OBD_MD_FLOBDFLG | OBD_MD_FLBLOCKS | OBD_MD_LINKNAME))

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
        __u32           os_spare[12];
};

/* ost_body.data values for OST_BRW */

#define OBD_BRW_READ	0x1
#define OBD_BRW_WRITE	0x2
#define OBD_BRW_RWMASK	(OBD_BRW_READ | OBD_BRW_WRITE)
#define OBD_BRW_CREATE	0x4

struct obd_ioobj {
        obd_id    ioo_id;
        obd_gr    ioo_gr;
        __u32     ioo_type;
        __u32     ioo_bufcnt;
};

struct niobuf_remote {
        __u64 offset;
        __u32 len;
        __u32 xid;
        __u32 flags;
};

#define CONNMGR_REPLY	0
#define CONNMGR_CONNECT	1

struct connmgr_body {
        __u64 conn;
        __u64 conn_token;
        __u32 generation;
        __u8  conn_uuid[37];
};

/* request structure for OST's */

#define OST_REQ_HAS_OA1  0x1

struct ost_body {
        struct  obdo oa;
};

/*
 *   MDS REQ RECORDS
 */

/* opcodes */
#define MDS_GETATTR    1
#define MDS_OPEN       2
#define MDS_CLOSE      3
#define MDS_REINT      4
#define MDS_READPAGE   6
#define MDS_CONNECT    7
#define MDS_DISCONNECT 8
#define MDS_GETSTATUS  9
#define MDS_STATFS     10
#define MDS_GETLOVINFO 11

#define REINT_SETATTR  1
#define REINT_CREATE   2
#define REINT_LINK     3
#define REINT_UNLINK   4
#define REINT_RENAME   5
#define REINT_RECREATE 6
#define REINT_MAX      6

struct ll_fid {
        __u64 id;
        __u32 generation;
        __u32 f_type;
};


#define MDS_STATUS_CONN 1
#define MDS_STATUS_LOV 2

struct mds_status_req { 
        __u32  flags;
        __u32  repbuf;
};

struct mds_conn_status { 
        struct ll_fid rootfid;
        __u64          xid;
        __u64          last_committed;
        __u64          last_rcvd;
        /* XXX preallocated quota & obj fields here */
};

struct mds_body {
        struct ll_fid  fid1;
        struct ll_fid  fid2;
        __u64          size;
        __u64          extra;
        __u32          valid;
        __u32          mode;
        __u32          uid;
        __u32          gid;
        __u32          mtime;
        __u32          ctime;
        __u32          atime;
        __u32          flags;
        __u32          major;
        __u32          minor;
        __u32          ino;
        __u32          nlink;
        __u32          generation;
        __u32          last_xid;
};

/* MDS update records */
struct mds_update_record_hdr {
        __u32 ur_opcode;
};

struct mds_rec_setattr {
        __u32           sa_opcode;
        struct ll_fid   sa_fid;
        __u32           sa_valid;
        __u32           sa_mode;
        __u32           sa_uid;
        __u32           sa_gid;
        __u64           sa_size;
        __u64           sa_atime;
        __u64           sa_mtime;
        __u64           sa_ctime;
        __u32           sa_attr_flags;
};

struct mds_rec_create {
        __u32           cr_opcode;
        struct ll_fid   cr_fid;
        __u32           cr_uid;
        __u32           cr_gid;
        __u64           cr_time;
        __u32           cr_mode;
        __u64           cr_rdev;
};

struct mds_rec_link {
        __u32           lk_opcode;
        struct ll_fid   lk_fid1;
        struct ll_fid   lk_fid2;
};

struct mds_rec_unlink {
        __u32           ul_opcode;
        struct ll_fid   ul_fid1;
        struct ll_fid   ul_fid2;
};

struct mds_rec_rename {
        __u32           rn_opcode;
        struct ll_fid   rn_fid1;
        struct ll_fid   rn_fid2;
};


/* 
 *  LOV data structures
 */

#define LOV_RAID0   0
#define LOV_RAIDRR  1

struct lov_desc { 
        __u32 ld_tgt_count;                /* how many OBD's */
        __u32 ld_default_stripe_count;     /* how many objects are used */
        __u64 ld_default_stripe_size;      /* in bytes */
        __u64 ld_default_stripe_offset;    /* in bytes */
        __u32 ld_pattern;                  /* RAID 0,1 etc */
         uuid_t ld_uuid;
}; 

/*
 *   LDLM requests:
 */
/* opcodes -- MUST be distinct from OST/MDS opcodes */
#define LDLM_ENQUEUE       101
#define LDLM_CONVERT       102
#define LDLM_CANCEL        103
#define LDLM_BL_CALLBACK   104
#define LDLM_CP_CALLBACK   105

#define RES_NAME_SIZE 3
#define RES_VERSION_SIZE 4

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

struct ldlm_intent {
        __u64 opc;
};

/* Note this unaligned structure; as long as it's only used in ldlm_request
 * below, we're probably fine. */
struct ldlm_resource_desc {
        __u32 lr_type;
        __u64 lr_name[RES_NAME_SIZE];
        __u32 lr_version[RES_VERSION_SIZE];
};

struct ldlm_lock_desc {
        struct ldlm_resource_desc l_resource;
        ldlm_mode_t l_req_mode;
        ldlm_mode_t l_granted_mode;
        struct ldlm_extent l_extent;
        __u32 l_version[RES_VERSION_SIZE];
};

struct ldlm_request {
        __u32 lock_flags;
        struct ldlm_lock_desc lock_desc;
        struct lustre_handle lock_handle1;
        struct lustre_handle lock_handle2;
};

struct ldlm_reply {
        __u32 lock_flags;
        __u32 lock_mode;
        __u64 lock_resource_name[RES_NAME_SIZE];
        struct lustre_handle lock_handle;
        struct ldlm_extent lock_extent;   /* XXX make this policy 1 &2 */
        __u64  lock_policy_res1;
        __u64  lock_policy_res2;
};
#endif
