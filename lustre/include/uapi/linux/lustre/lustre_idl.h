/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre wire protocol definitions.
 */

/*
 * Lustre wire protocol definitions.
 *
 * ALL structs passing over the wire should be declared here.  Structs
 * that are used in interfaces with userspace should go in lustre_user.h.
 *
 * All structs being declared here should be built from simple fixed-size
 * types defined in linux/types.h or be built from other types or
 * structs also declared in this file.  Similarly, all flags and magic
 * values in those structs should also be declared here.  This ensures
 * that the Lustre wire protocol is not influenced by external dependencies.
 *
 * The only other acceptable items in this file are VERY SIMPLE accessor
 * functions to avoid callers grubbing inside the structures. Nothing that
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
 */

#ifndef _LUSTRE_IDL_H_
#define _LUSTRE_IDL_H_

#include <asm/byteorder.h>
#include <linux/errno.h>
#include <linux/fiemap.h>
#include <linux/types.h>
#include <linux/lnet/nidstr.h>
#include <linux/lnet/lnet-types.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_ver.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*
 *  GENERAL STUFF
 */
/* FOO_REQUEST_PORTAL is for incoming requests on the FOO
 * FOO_REPLY_PORTAL   is for incoming replies on the FOO
 * FOO_BULK_PORTAL    is for incoming bulk on the FOO
 */

#define CONNMGR_REQUEST_PORTAL          1
#define CONNMGR_REPLY_PORTAL            2
#define OSC_REPLY_PORTAL                4
#define OST_IO_PORTAL                   6
#define OST_CREATE_PORTAL               7
#define OST_BULK_PORTAL                 8
#define MDC_REPLY_PORTAL               10
#define MDS_REQUEST_PORTAL             12
#define MDS_IO_PORTAL			13
#define MDS_BULK_PORTAL                14
#define LDLM_CB_REQUEST_PORTAL         15
#define LDLM_CB_REPLY_PORTAL           16
#define LDLM_CANCEL_REQUEST_PORTAL     17
#define LDLM_CANCEL_REPLY_PORTAL       18
/* #define MDS_SETATTR_PORTAL             22 obsolete after 2.13 */
#define MDS_READPAGE_PORTAL            23
#define OUT_PORTAL			24
#define MGC_REPLY_PORTAL               25
#define MGS_REQUEST_PORTAL             26
#define MGS_REPLY_PORTAL               27
#define OST_REQUEST_PORTAL             28
#define FLD_REQUEST_PORTAL             29
#define SEQ_METADATA_PORTAL            30
#define SEQ_DATA_PORTAL                31
#define SEQ_CONTROLLER_PORTAL          32
#define MGS_BULK_PORTAL                33
/* #define DVS_PORTAL			63 */
/* reserved for Cray DVS - spitzcor@cray.com, roe@cray.com, n8851@cray.com */

/**
 * Describes a range of sequence, lsr_start is included but lsr_end is
 * not in the range.
 * Same structure is used in fld module where lsr_index field holds mdt id
 * of the home mdt.
 */
struct lu_seq_range {
	__u64 lsr_start;
	__u64 lsr_end;
	__u32 lsr_index;
	__u32 lsr_flags;
};

struct lu_seq_range_array {
	__u32 lsra_count;
	__u32 lsra_padding;
	struct lu_seq_range lsra_lsr[];
};

#define LU_SEQ_RANGE_MDT	0x0
#define LU_SEQ_RANGE_OST	0x1
#define LU_SEQ_RANGE_ANY	0x3

#define LU_SEQ_RANGE_MASK	0x3

extern void lustre_lma_swab(struct lustre_mdt_attrs *lma);
extern void lustre_lma_init(struct lustre_mdt_attrs *lma,
			    const struct lu_fid *fid,
			    __u32 compat, __u32 incompat);
extern void lustre_loa_swab(struct lustre_ost_attrs *loa,
			    bool to_cpu);
extern void lustre_loa_init(struct lustre_ost_attrs *loa,
			    const struct lu_fid *fid,
			    __u32 compat, __u32 incompat);

/* copytool can use any nonnegative integer to represent archive-Ids during
 * register with MDT thru kuc.
 * archive num = 0 => all
 * archive num from 1 to MAX_U32
 */
#define LL_HSM_ORIGIN_MAX_ARCHIVE	(sizeof(__u32) * 8)
/* the max count of archive ids that one agent can support */
#define LL_HSM_MAX_ARCHIVES_PER_AGENT	1024

/**
 * HSM on-disk attributes stored in a separate xattr.
 */
struct hsm_attrs {
	/** Bitfield for supported data in this structure. For future use. */
	__u32	hsm_compat;

	/** HSM flags, see hsm_flags enum below */
	__u32	hsm_flags;
	/** backend archive id associated with the file */
	__u64	hsm_arch_id;
	/** version associated with the last archiving, if any */
	__u64	hsm_arch_ver;
};
extern void lustre_hsm_swab(struct hsm_attrs *attrs);

static inline void lov_foreign_hsm_to_cpu(struct lov_hsm_base *dst,
					  const struct lov_foreign_md *lfm)
{
	struct lov_hsm_base *src = (struct lov_hsm_base *)lfm->lfm_value;

	dst->lhb_archive_id = __le64_to_cpu(src->lhb_archive_id);
	dst->lhb_archive_ver = __le64_to_cpu(src->lhb_archive_ver);
	memcpy(dst->lhb_uuid, src->lhb_uuid, sizeof(dst->lhb_uuid));
}

static inline void lov_foreign_hsm_to_le(struct lov_foreign_md *lfm,
					 struct lov_hsm_base *src)
{
	struct lov_hsm_base *dst = (struct lov_hsm_base *)lfm->lfm_value;

	dst->lhb_archive_id = __cpu_to_le64(dst->lhb_archive_id);
	dst->lhb_archive_ver = __cpu_to_le64(dst->lhb_archive_ver);
	memcpy(dst->lhb_uuid, src->lhb_uuid, sizeof(dst->lhb_uuid));
}

/**
 * fid constants
 */
enum {
	/** LASTID file has zero OID */
	LUSTRE_FID_LASTID_OID = 0UL,
	/** initial fid id value */
	LUSTRE_FID_INIT_OID  = 1UL,
};

/**
 * Different FID Format
 * http://arch.lustre.org/index.php?title=Interoperability_fids_zfs#NEW.0
 *
 * FID:
 * File IDentifier generated by client from range allocated by the seq service.
 * First 0x400 sequences [2^33, 2^33 + 0x400] are reserved for system use. Note
 * that on ldiskfs MDTs that IGIF FIDs can use inode numbers starting at 12,
 * but this is in the IGIF SEQ rangeand does not conflict with assigned FIDs.
 *
 * IGIF:
 * Inode and Generation In FID, a surrogate FID used to globally identify an
 * existing object on OLD formatted MDT file system. This would only be used on
 * MDT0 in a DNE filesystem, because there are not expected to be any OLD
 * formatted DNE filesystems. Belongs to a sequence in [12, 2^32 - 1] range,
 * where sequence number is inode number, and inode generation is used as OID.
 * NOTE: This assumes no more than 2^32-1 inodes exist in the MDT filesystem,
 * which is the maximum possible for an ldiskfs backend. NOTE: This assumes
 * that the reserved ext3/ext4/ldiskfs inode numbers [0-11] are never visible
 * to clients, which has always been true.
 *
 * IDIF:
 * Object ID in FID, a surrogate FID used to globally identify an existing
 * object on OLD formatted OST file system. Belongs to a sequence in
 * [2^32, 2^33 - 1]. Sequence number is calculated as:
 *	1 << 32 | (ost_index << 16) | ((objid >> 32) & 0xffff)
 * that is, SEQ consists of 16-bit OST index, and higher 16 bits of object ID.
 * The generation of unique SEQ values per OST allows the IDIF FIDs to be
 * identified in the FLD correctly. The OID field is calculated as:
 *	objid & 0xffffffff
 * that is, it consists of lower 32 bits of object ID. NOTE This assumes that
 * no more than 2^48-1 objects have ever been created on an OST, and that no
 * more than 65535 OSTs are in use. Both are very reasonable assumptions (can
 * uniquely map all objects on an OST that created 1M objects per second for 9
 * years, or combinations thereof).
 *
 * OST_MDT0:
 * Surrogate FID used to identify an existing object on OLD formatted OST
 * filesystem. Belongs to the reserved sequence 0, and is used internally prior
 * to the introduction of FID-on-OST, at which point IDIF will be used to
 * identify objects as residing on a specific OST.
 *
 * LLOG:
 * For Lustre Log objects the object sequence 1 is used. This is compatible with
 * both OLD and NEW.1 namespaces, as this SEQ number is in the ext3/ldiskfs
 * reserved inode range and does not conflict with IGIF sequence numbers.
 *
 * ECHO:
 * For testing OST IO performance the object sequence 2 is used. This is
 * compatible with both OLD and NEW.1 namespaces, as this SEQ number is in the
 * ext3/ldiskfs reserved inode range and does not conflict with IGIF sequence
 * numbers.
 *
 * OST_MDT1 .. OST_MAX:
 * For testing with multiple MDTs the object sequence 3 through 9 is used,
 * allowing direct mapping of MDTs 1 through 7 respectively, for a total of 8
 * MDTs including OST_MDT0. This matches the legacy CMD project "group"
 * mappings. However, this SEQ range is only for testing prior to any production
 * DNE release, as the objects in this range conflict across all OSTs, as the
 * OST index is not part of the FID.
 *
 *
 * For compatibility with existing OLD OST network protocol structures, the FID
 * must map onto the o_id and o_gr in a manner that ensures existing objects are
 * identified consistently for IO, as well as onto the lock namespace to ensure
 * both IDIFs map onto the same objects for IO as well as resources in the DLM.
 *
 * DLM OLD OBIF/IDIF:
 * resource[] = {o_id, o_seq, 0, 0};  // o_seq == 0 for production releases
 *
 * DLM NEW.1 FID (this is the same for both the MDT and OST):
 * resource[] = {SEQ, OID, VER, HASH};
 *
 * Note that for mapping IDIF values to DLM resource names the o_id may be
 * larger than the 2^33 reserved sequence numbers for IDIF, so it is possible
 * for the o_id numbers to overlap FID SEQ numbers in the resource. However, in
 * all production releases the OLD o_seq field is always zero, and all valid FID
 * OID values are non-zero, so the lock resources will not collide.
 *
 * For objects within the IDIF range, group extraction (non-CMD) will be:
 * o_id = (fid->f_seq & 0x7fff) << 16 | fid->f_oid;
 * o_seq = 0;  // formerly group number
 */

/**
 * Note that reserved SEQ numbers below 12 will conflict with ldiskfs
 * inodes in the IGIF namespace, so these reserved SEQ numbers can be
 * used for other purposes and not risk collisions with existing inodes.
 */
enum fid_seq {
	FID_SEQ_OST_MDT0	= 0,
	FID_SEQ_LLOG		= 1, /* unnamed llogs */
	FID_SEQ_ECHO		= 2,
	FID_SEQ_UNUSED_START	= 3, /* Unused */
	FID_SEQ_UNUSED_END	= 9, /* Unused */
	FID_SEQ_LLOG_NAME	= 10, /* named llogs */
	FID_SEQ_RSVD		= 11,
	FID_SEQ_IGIF		= 12,
	FID_SEQ_IGIF_MAX	= 0x0ffffffffULL,
	FID_SEQ_IDIF		= 0x100000000ULL,
	FID_SEQ_IDIF_MAX	= 0x1ffffffffULL,
	/* Normal FID sequence starts from this value, i.e. 1<<33 */
	FID_SEQ_START		= 0x200000000ULL,
	/* sequence for local pre-defined FIDs listed in local_oid */
	FID_SEQ_LOCAL_FILE	= 0x200000001ULL,
	FID_SEQ_DOT_LUSTRE	= 0x200000002ULL,
	/* named FIDs generated by local_object_storage library */
	FID_SEQ_LOCAL_NAME	= 0x200000003ULL,
	/* current FLD will only cache the fid seq, instead of oid on the client
	 * side, if the FID needs to be exposed to clients, it needs to make
	 * sure all of fids under one seq will be located in one MDT.
	 */
	FID_SEQ_SPECIAL		= 0x200000004ULL,
	FID_SEQ_QUOTA		= 0x200000005ULL,
	FID_SEQ_QUOTA_GLB	= 0x200000006ULL,
	FID_SEQ_ROOT		= 0x200000007ULL,  /* Located on MDT0 */
	FID_SEQ_LAYOUT_RBTREE	= 0x200000008ULL,
	/* sequence is used for update logs of cross-MDT operation */
	FID_SEQ_UPDATE_LOG	= 0x200000009ULL,
	/* DNE recovery logs in update_logs_dir  */
	FID_SEQ_UPDATE_LOG_DIR	= 0x20000000aULL,
	FID_SEQ_NORMAL		= 0x200000400ULL,
	FID_SEQ_LOV_DEFAULT	= 0xffffffffffffffffULL
};

#define OBIF_OID_MAX_BITS           32
#define OBIF_MAX_OID                ((1ULL << OBIF_OID_MAX_BITS) - 1)
#define IDIF_OID_MAX_BITS           48
#define IDIF_MAX_OID                ((1ULL << IDIF_OID_MAX_BITS) - 1)

/** OID for FID_SEQ_SPECIAL */
enum special_oid {
	/* Big Filesystem Lock to serialize rename operations */
	FID_OID_SPECIAL_BFL     = 1UL,
};

/** OID for FID_SEQ_DOT_LUSTRE */
enum dot_lustre_oid {
	FID_OID_DOT_LUSTRE	= 1UL,
	FID_OID_DOT_LUSTRE_OBF	= 2UL,
	FID_OID_DOT_LUSTRE_LPF	= 3UL,
};

/** OID for FID_SEQ_ROOT */
enum root_oid {
	FID_OID_ROOT		= 1UL,
	FID_OID_ECHO_ROOT	= 2UL,
};

struct lu_orphan_rec {
	/* The MDT-object's FID referenced by the orphan OST-object */
	struct lu_fid	lor_fid;
	__u32		lor_uid;
	__u32		lor_gid;
};

struct lu_orphan_ent {
	/* The orphan OST-object's FID */
	struct lu_fid		loe_key;
	struct lu_orphan_rec	loe_rec;
};

struct lu_orphan_rec_v2 {
	struct lu_orphan_rec	lor_rec;
	struct ost_layout	lor_layout;
	__u32			lor_padding;
};

struct lu_orphan_ent_v2 {
	/* The orphan OST-object's FID */
	struct lu_fid		loe_key;
	struct lu_orphan_rec_v2	loe_rec;
};

struct lu_orphan_rec_v3 {
	struct lu_orphan_rec	lor_rec;
	struct ost_layout	lor_layout;
	/* The OST-object declared layout version in PFID EA.*/
	__u32			lor_layout_version;
	/* The OST-object declared layout range (of version) in PFID EA.*/
	__u32			lor_range;
	__u32			lor_padding_1;
	__u64			lor_padding_2;
};

struct lu_orphan_ent_v3 {
	/* The orphan OST-object's FID */
	struct lu_fid		loe_key;
	struct lu_orphan_rec_v3	loe_rec;
};

/** @} lu_fid */

/** \defgroup lu_dir lu_dir
 * @{
 */

/**
 * Enumeration of possible directory entry attributes.
 *
 * Attributes follow directory entry header in the order they appear in this
 * enumeration.
 */
enum lu_dirent_attrs {
	LUDA_FID		= 0x0001,
	LUDA_TYPE		= 0x0002,
	LUDA_64BITHASH		= 0x0004,

	/* for MDT internal use only, not visible to client */

	/* Something in the record is unknown, to be verified in further. */
	LUDA_UNKNOWN		= 0x0400,
	/* Ignore this record, go to next directly. */
	LUDA_IGNORE		= 0x0800,
	/* The system is upgraded, has beed or to be repaired (dryrun). */
	LUDA_UPGRADE		= 0x1000,
	/* The dirent has been repaired, or to be repaired (dryrun). */
	LUDA_REPAIR		= 0x2000,
	/* Only check but not repair the dirent inconsistency */
	LUDA_VERIFY_DRYRUN	= 0x4000,
	/* Verify the dirent consistency */
	LUDA_VERIFY		= 0x8000,
};

#define LU_DIRENT_ATTRS_MASK	0xff00

/**
 * Layout of readdir pages, as transmitted on wire.
 */
struct lu_dirent {
	/** valid if LUDA_FID is set. */
	struct lu_fid lde_fid;
	/** a unique entry identifier: a hash or an offset. */
	__u64         lde_hash;
	/** total record length, including all attributes. */
	__u16         lde_reclen;
	/** name length */
	__u16         lde_namelen;
	/** optional variable size attributes following this entry.
	 *  taken from enum lu_dirent_attrs.
	 */
	__u32         lde_attrs;
	/** name is followed by the attributes indicated in ->ldp_attrs, in
	 *  their natural order. After the last attribute, padding bytes are
	 *  added to make ->lde_reclen a multiple of 8.
	 */
	char          lde_name[];
};

/*
 * Definitions of optional directory entry attributes formats.
 *
 * Individual attributes do not have their length encoded in a generic way. It
 * is assumed that consumer of an attribute knows its format. This means that
 * it is impossible to skip over an unknown attribute, except by skipping over
 * all remaining attributes (by using ->lde_reclen), which is not too
 * constraining, because new server versions will append new attributes at
 * the end of an entry.
 */

/**
 * Fid directory attribute: a fid of an object referenced by the entry. This
 * will be almost always requested by the client and supplied by the server.
 *
 * Aligned to 8 bytes.
 */
/* To have compatibility with 1.8, lets have fid in lu_dirent struct. */

/**
 * File type.
 *
 * Aligned to 2 bytes.
 */
struct luda_type {
	__u16 lt_type;
};

struct lu_dirpage {
	__u64            ldp_hash_start;
	__u64            ldp_hash_end;
	__u32            ldp_flags;
	__u32            ldp_pad0;
	struct lu_dirent ldp_entries[];
};

enum lu_dirpage_flags {
	LDF_EMPTY   = 1 << 0, /* dirpage contains no entry. */
	LDF_COLLIDE = 1 << 1, /* last entry lde_hash == ldp_hash_end */
};

static inline struct lu_dirent *lu_dirent_start(struct lu_dirpage *dp)
{
	if (__le32_to_cpu(dp->ldp_flags) & LDF_EMPTY)
		return NULL;
	else
		return dp->ldp_entries;
}

static inline struct lu_dirent *lu_dirent_next(struct lu_dirent *ent)
{
	struct lu_dirent *next;

	if (__le16_to_cpu(ent->lde_reclen) != 0)
		next = ((void *)ent) + __le16_to_cpu(ent->lde_reclen);
	else
		next = NULL;

	return next;
}

static inline __kernel_size_t lu_dirent_calc_size(size_t namelen, __u16 attr)
{
	__kernel_size_t size;

	if (attr & LUDA_TYPE) {
		const __kernel_size_t align = sizeof(struct luda_type) - 1;

		size = (sizeof(struct lu_dirent) + namelen + 1 + align) &
		       ~align;
		size += sizeof(struct luda_type);
	} else {
		size = sizeof(struct lu_dirent) + namelen + 1;
	}

	return (size + 7) & ~7;
}

static inline __u16 lu_dirent_type_get(struct lu_dirent *ent)
{
	__u16 type = 0;
	struct luda_type *lt;
	int len = 0;

	if (__le32_to_cpu(ent->lde_attrs) & LUDA_TYPE) {
		const unsigned int align = sizeof(struct luda_type) - 1;

		len = __le16_to_cpu(ent->lde_namelen);
		len = (len + align) & ~align;
		lt = (void *)ent->lde_name + len;
		type = __le16_to_cpu(lt->lt_type);
	}

	return type;
}

#define MDS_DIR_END_OFF 0xfffffffffffffffeULL

/**
 * MDS_READPAGE page size
 *
 * This is the directory page size packed in MDS_READPAGE RPC.
 * It's different than PAGE_SIZE because the client needs to
 * access the struct lu_dirpage header packed at the beginning of
 * the "page" and without this there isn't any way to know find the
 * lu_dirpage header is if client and server PAGE_SIZE differ.
 */
#define LU_PAGE_SHIFT 12
#define LU_PAGE_SIZE  (1UL << LU_PAGE_SHIFT)
#define LU_PAGE_MASK  (~(LU_PAGE_SIZE - 1))

#define LU_PAGE_COUNT (1 << (PAGE_SHIFT - LU_PAGE_SHIFT))

/** @} lu_dir */

struct lustre_handle {
	__u64 cookie;
};
#define DEAD_HANDLE_MAGIC 0xdeadbeefcafebabeULL

static inline bool lustre_handle_is_used(const struct lustre_handle *lh)
{
	return lh->cookie != 0;
}

static inline bool lustre_handle_equal(const struct lustre_handle *lh1,
				       const struct lustre_handle *lh2)
{
	return lh1->cookie == lh2->cookie;
}

static inline void lustre_handle_copy(struct lustre_handle *tgt,
				      const struct lustre_handle *src)
{
	tgt->cookie = src->cookie;
}

/* lustre_msg struct magic.  DON'T use swabbed values of MAGIC as magic! */
enum lustre_msg_magic {
	LUSTRE_MSG_MAGIC_V2		= 0x0BD00BD3,
	LUSTRE_MSG_MAGIC_V2_SWABBED	= 0xD30BD00B,
	LUSTRE_MSG_MAGIC		= LUSTRE_MSG_MAGIC_V2
};

/* flags for lm_flags */
enum lustre_msghdr {
	MSGHDR_AT_SUPPORT	= 0x1,	/* lm_cksum valid early reply msg */
	MSGHDR_CKSUM_INCOMPAT18	= 0x2,	/* compat for 1.8, need beyond 2.8.0 */
};

#define lustre_msg lustre_msg_v2
/* we depend on this structure to be 8-byte aligned */
/* this type is only endian-adjusted in lustre_unpack_msg() */
struct lustre_msg_v2 {
	__u32 lm_bufcount;	/* number of buffers in lm_buflens[] */
	__u32 lm_secflvr;	/* 0 = no crypto, or sptlrpc security flavour */
	__u32 lm_magic;		/* RPC version magic = LUSTRE_MSG_MAGIC_V2 */
	__u32 lm_repsize;	/* size of preallocated reply buffer */
	__u32 lm_cksum;		/* CRC32 of ptlrpc_body early reply messages */
	__u32 lm_flags;		/* enum lustre_msghdr MSGHDR_* flags */
	__u32 lm_opc;		/* SUB request opcode in a batch request */
	__u32 lm_padding_3;	/* unused */
	/* length of additional buffers in bytes
	 * message buffers are packed after padded lm_buflens[] array,
	 * padded to a multiple of 8 bytes each to align contents.
	 */
	__u32 lm_buflens[];
};

/* The returned result of the SUB request in a batch request */
#define lm_result	lm_opc

/* ptlrpc_body packet pb_types */
#define PTL_RPC_MSG_REQUEST	4711	/* normal RPC request message */
#define PTL_RPC_MSG_ERR		4712	/* error reply if request unprocessed */
#define PTL_RPC_MSG_REPLY	4713	/* normal RPC reply message */

/* ptlrpc_body pb_version ((target_version << 16) | rpc_version) */
enum lustre_msg_version {
	PTLRPC_MSG_VERSION	= 0x00000003,
	LUSTRE_VERSION_MASK	= 0xffff0000,
	LUSTRE_OBD_VERSION	= 0x00010000,
	LUSTRE_MDS_VERSION	= 0x00020000,
	LUSTRE_OST_VERSION	= 0x00030000,
	LUSTRE_DLM_VERSION	= 0x00040000,
	LUSTRE_LOG_VERSION	= 0x00050000,
	LUSTRE_MGS_VERSION	= 0x00060000,
};

/* pb_flags that apply to all request messages */
/* #define MSG_LAST_REPLAY	0x0001 obsolete 2.0 => {REQ,LOCK}_REPLAY_DONE */
#define MSG_RESENT		0x0002 /* was previously sent, no reply seen */
#define MSG_REPLAY		0x0004 /* was processed, got reply, recovery */
/* #define MSG_AT_SUPPORT	0x0008 obsolete since 1.5, AT always enabled */
/* #define MSG_DELAY_REPLAY	0x0010 obsolete since 2.0 */
/* #define MSG_VERSION_REPLAY	0x0020 obsolete since 1.8.2, VBR always on */
#define MSG_REQ_REPLAY_DONE	0x0040 /* request replay over, locks next */
#define MSG_LOCK_REPLAY_DONE	0x0080 /* lock replay over, client done */

/* pb_op_flags for connect opcodes: MDS_CONNECT, OST_CONNECT, MGS_CONNECT */
#define MSG_CONNECT_RECOVERING	0x00000001 /* target is in recovery */
#define MSG_CONNECT_RECONNECT	0x00000002 /* tgt already has client import */
#define MSG_CONNECT_REPLAYABLE	0x00000004 /* target supports RPC replay */
/* #define MSG_CONNECT_PEER	0x00000008 obsolete since 1.2, removed in 1.5 */
#define MSG_CONNECT_LIBCLIENT	0x00000010 /* obsolete since 2.3, removed 2.6 */
#define MSG_CONNECT_INITIAL	0x00000020 /* first client connection attempt */
/* #define MSG_CONNECT_ASYNC	0x00000040 obsolete since 1.5 */
#define MSG_CONNECT_NEXT_VER	0x00000080 /* use next version of lustre_msg */
#define MSG_CONNECT_TRANSNO	0x00000100 /* client sent transno in replay */
#define MSG_PACK_UID_GID	0x00000200 /* thread UID/GID in ptlrpc_body */
#define MSG_PACK_PROJID		0x00000400 /* thread PROJID in ptlrpc_body */

/* number of previous object versions in pb_pre_versions[] */
#define PTLRPC_NUM_VERSIONS     4
/* without gss, ptlrpc_body is put at the first buffer. */
struct ptlrpc_body_v3 {
	struct lustre_handle pb_handle;
	__u32 pb_type;		/* request/reply/err type: PTL_RPC_MSG_* */
	__u32 pb_version;	/* LUSTRE_*_VERSION | PTLRPC_MSG_VERSION */
	__u32 pb_opc;		/* RPC opcodes: MDS_*, OST_*, LDLM_, ... */
	__u32 pb_status;	/* negative Linux x86 error number */
	__u64 pb_last_xid;	/* highest replied XID w/o lower unreplied XID*/
	__u16 pb_tag;		/* multiple modifying RPCs virtual slot index */
	__u16 pb_padding0;
	__u32 pb_projid;	/* req: inode projid, use by tbf rules */
	__u64 pb_last_committed;/* rep: highest pb_transno committed to disk */
	__u64 pb_transno;	/* server-assigned transno for modifying RPCs */
	__u32 pb_flags;		/* req: MSG_* flags */
	__u32 pb_op_flags;	/* req: MSG_CONNECT_* flags */
	__u32 pb_conn_cnt;	/* connect instance of this client on server */
	__u32 pb_timeout;	/* req: max wait time; rep: service estimate */
	__u32 pb_service_time;	/* rep: server arrival to reply in seconds */
	__u32 pb_limit;		/* rep: dynamic DLM LRU lock count limit */
	__u64 pb_slv;		/* rep: dynamic DLM LRU server lock volume */
	/* VBR: rep: previous pb_version(s) of objects modified by this RPC */
	__u64 pb_pre_versions[PTLRPC_NUM_VERSIONS];
	__u64 pb_mbits;	/**< match bits for bulk request */
	/* padding for future needs - fix lustre_swab_ptlrpc_body() also */
	__u64 pb_padding64_0;
	__u64 pb_padding64_1;
	__u32 pb_uid;		/* req: process uid, use by tbf rules */
	__u32 pb_gid;		/* req: process gid, use by tbf rules */
	char  pb_jobid[LUSTRE_JOBID_SIZE]; /* req: ASCII jobid from env + NUL */
};
#define ptlrpc_body     ptlrpc_body_v3

struct ptlrpc_body_v2 {
	struct lustre_handle pb_handle;
	__u32 pb_type;
	__u32 pb_version;
	__u32 pb_opc;
	__u32 pb_status;
	__u64 pb_last_xid; /* highest replied XID without lower unreplied XID */
	__u16 pb_tag;      /* virtual slot idx for multiple modifying RPCs */
	__u16 pb_padding0;
	__u32 pb_projid;   /* req: inode projid, use by tbf rules */
	__u64 pb_last_committed;
	__u64 pb_transno;
	__u32 pb_flags;
	__u32 pb_op_flags;
	__u32 pb_conn_cnt;
	__u32 pb_timeout;  /* for req, the deadline, for rep, the service est */
	__u32 pb_service_time; /* rep: actual service time, req: net_latency */
	__u32 pb_limit;
	__u64 pb_slv;
	/* VBR: pre-versions */
	__u64 pb_pre_versions[PTLRPC_NUM_VERSIONS];
	__u64 pb_mbits;	/**< unused in V2 */
	/* padding for future needs */
	__u64 pb_padding64_0;
	__u64 pb_padding64_1;
	__u32 pb_uid;		/* req: process uid, use by tbf rules */
	__u32 pb_gid;		/* req: process gid, use by tbf rules */
};

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

/** only use in req->rq_{req,rep}_swab_mask */
#define MSG_PTLRPC_HEADER_OFF           31

/* Connect flags */
#define OBD_CONNECT_RDONLY			0x1ULL /* client is read-only */
#define OBD_CONNECT_INDEX			0x2ULL /* connect to LOV idx */
#define OBD_CONNECT_MDS				0x4ULL /* connect MDT to OST */
#define OBD_CONNECT_GRANT			0x8ULL /* fetch grant connect */
#define OBD_CONNECT_SRVLOCK		       0x10ULL /* server lock for RPC */
#define OBD_CONNECT_VERSION		       0x20ULL /* versions in OCD */
#define OBD_CONNECT_MGS_NIDLIST		       0x40ULL /* MGS nidlist protocol */
#define OBD_CONNECT_ACL			       0x80ULL /* access control list */
#define OBD_CONNECT_XATTR		      0x100ULL /* extended attributes */
#define OBD_CONNECT_LARGE_ACL		      0x200ULL /* over 32 ACL entries */
/* was OBD_CONNECT_TRUNCLOCK		      0x400ULL  * server locks punch */
/* temporary reuse until 2.21.53 to indicate pre-2.15 client, see LU-15478 */
#define OBD_CONNECT_OLD_FALLOC		      0x400ULL /* no o_valid flags */
#define OBD_CONNECT_TRANSNO		      0x800ULL /* replay send transno */
#define OBD_CONNECT_IBITS		     0x1000ULL /* not checked 2.11+ */
#define OBD_CONNECT_BARRIER		     0x2000ULL /* write barrier */
#define OBD_CONNECT_ATTRFID		     0x4000ULL /* Server GetAttr FID */
#define OBD_CONNECT_NODEVOH		     0x8000ULL /* No open handle spec */
#define OBD_CONNECT_RMT_CLIENT		    0x10000ULL /* Never used, gone 2.9*/
#define OBD_CONNECT_RMT_CLIENT_FORCE	    0x20000ULL /* Never used, gone 2.9*/
#define OBD_CONNECT_BRW_SIZE		    0x40000ULL /* Max bytes per rpc */
#define OBD_CONNECT_QUOTA64		    0x80000ULL /* Unused since 2.4 */
#define OBD_CONNECT_MDS_CAPA		   0x100000ULL /* Unused since 2.7 */
#define OBD_CONNECT_OSS_CAPA		   0x200000ULL /* Unused since 2.7 */
#define OBD_CONNECT_CANCELSET		   0x400000ULL /* Early batch cancel */
#define OBD_CONNECT_SOM			   0x800000ULL /* Unused since 2.7 */
#define OBD_CONNECT_AT			  0x1000000ULL /* client uses AT */
#define OBD_CONNECT_LRU_RESIZE		  0x2000000ULL /* LRU resize feature */
#define OBD_CONNECT_MDS_MDS		  0x4000000ULL /* MDS-MDS connection */
#define OBD_CONNECT_REAL		  0x8000000ULL /* Unused since 2.8 */
#define OBD_CONNECT_CHANGE_QS		 0x10000000ULL /* Unused since 2.4 */
#define OBD_CONNECT_CKSUM		 0x20000000ULL /* cksum algo choice */
#define OBD_CONNECT_FID			 0x40000000ULL /* server handles FIDs */
#define OBD_CONNECT_VBR			 0x80000000ULL /* version based recov */
#define OBD_CONNECT_LOV_V3		0x100000000ULL /* client LOV v3 EA */
#define OBD_CONNECT_GRANT_SHRINK	0x200000000ULL /* handle grant shrink */
#define OBD_CONNECT_SKIP_ORPHAN		0x400000000ULL /* no orph objid reuse */
#define OBD_CONNECT_MAX_EASIZE		0x800000000ULL /* EA size in reply */
#define OBD_CONNECT_FULL20	       0x1000000000ULL /* it is 2.0 client */
#define OBD_CONNECT_LAYOUTLOCK	       0x2000000000ULL /* client layout lock */
#define OBD_CONNECT_64BITHASH	       0x4000000000ULL /* 64-bits dir hash */
#define OBD_CONNECT_MAXBYTES	       0x8000000000ULL /* max stripe size */
#define OBD_CONNECT_IMP_RECOV	      0x10000000000ULL /* imp recov support */
#define OBD_CONNECT_JOBSTATS	      0x20000000000ULL /* ptlrpc_body jobid */
#define OBD_CONNECT_UMASK	      0x40000000000ULL /* create client umask */
/* client -EINPROGRESS RPC error handling */
#define OBD_CONNECT_EINPROGRESS	      0x80000000000ULL
/* extra grant params for space reservation */
#define OBD_CONNECT_GRANT_PARAM	     0x100000000000ULL
#define OBD_CONNECT_FLOCK_OWNER	     0x200000000000ULL /* unused since 2.0 */
#define OBD_CONNECT_LVB_TYPE	     0x400000000000ULL /* variable LVB type */
#define OBD_CONNECT_NANOSEC_TIME     0x800000000000ULL /* nanosec timestamp */
#define OBD_CONNECT_LIGHTWEIGHT	    0x1000000000000ULL /* lightweight connect */
#define OBD_CONNECT_SHORTIO	    0x2000000000000ULL /* short io */
#define OBD_CONNECT_PINGLESS	    0x4000000000000ULL /* pings not required */
#define OBD_CONNECT_FLOCK_DEAD	    0x8000000000000ULL /* flk deadlock detect */
#define OBD_CONNECT_DISP_STRIPE	   0x10000000000000ULL /* create stripe disp */
#define OBD_CONNECT_OPEN_BY_FID	   0x20000000000000ULL /* open by FID won't pack
							* name in request
							*/
#define OBD_CONNECT_LFSCK	   0x40000000000000ULL /* allow online LFSCK */
#define OBD_CONNECT_UNLINK_CLOSE  0x100000000000000ULL /* unlink closes file */
#define OBD_CONNECT_MULTIMODRPCS  0x200000000000000ULL /* allow multiple change
							* RPCs in parallel
							*/
#define OBD_CONNECT_DIR_STRIPE	  0x400000000000000ULL /* striped DNE dir */
#define OBD_CONNECT_SUBTREE	  0x800000000000000ULL /* fileset mount, deprecated since 2.17.0 */
/* was OBD_CONNECT_LOCKAHEAD_OLD 0x1000000000000000ULL old lockahead 2.12-2.13*/
#define OBD_CONNECT_BULK_MBITS	 0x2000000000000000ULL /* ptlrpc_body matchbit*/
#define OBD_CONNECT_OBDOPACK	 0x4000000000000000ULL /* compact OUT obdo */
#define OBD_CONNECT_FLAGS2	 0x8000000000000000ULL /* second flags word */
/* ocd_connect_flags2 flags */
#define OBD_CONNECT2_FILE_SECCTX		0x1ULL /* security context */
#define OBD_CONNECT2_LOCKAHEAD			0x2ULL /* ladvise lockahead */
#define OBD_CONNECT2_DIR_MIGRATE		0x4ULL /* migrate striped dir */
#define OBD_CONNECT2_SUM_STATFS			0x8ULL /* MDT aggregate statfs*/
#define OBD_CONNECT2_OVERSTRIPING	       0x10ULL /* OST overstriping */
#define OBD_CONNECT2_FLR		       0x20ULL /* FLR mirror handling */
#define OBD_CONNECT2_WBC_INTENTS	       0x40ULL /* MDS wb cache intent */
#define OBD_CONNECT2_LOCK_CONVERT	       0x80ULL /* IBITS lock convert */
#define OBD_CONNECT2_ARCHIVE_ID_ARRAY	      0x100ULL /* HSM archive_id array*/
#define OBD_CONNECT2_INC_XID		      0x200ULL /* Increasing xid */
#define OBD_CONNECT2_SELINUX_POLICY	      0x400ULL /* cli SELinux policy */
#define OBD_CONNECT2_LSOM		      0x800ULL /* Lazy Size on MDT */
#define OBD_CONNECT2_PCC		     0x1000ULL /* Persist Client Cache*/
#define OBD_CONNECT2_CRUSH		     0x2000ULL /* CRUSH dir hash */
#define OBD_CONNECT2_ASYNC_DISCARD	     0x4000ULL /* async DoM discard */
#define OBD_CONNECT2_ENCRYPT		     0x8000ULL /* client disk encrypt */
#define OBD_CONNECT2_FIDMAP		    0x10000ULL /* MDT migrate FID map */
#define OBD_CONNECT2_GETATTR_PFID	    0x20000ULL /* parent FID getattr */
#define OBD_CONNECT2_LSEEK		    0x40000ULL /* SEEK_HOLE/DATA RPC */
#define OBD_CONNECT2_DOM_LVB		    0x80000ULL /* DoM glimpse in LVB */
#define OBD_CONNECT2_REP_MBITS		   0x100000ULL /* reply mbits, not XID*/
#define OBD_CONNECT2_MODE_CONVERT	   0x200000ULL /* LDLM mode convert */
#define OBD_CONNECT2_BATCH_RPC		   0x400000ULL /* Multi-op batch RPCs */
#define OBD_CONNECT2_PCCRO		   0x800000ULL /* PCC read-only */
#define OBD_CONNECT2_MNE_TYPE		  0x1000000ULL /* mne_nid_type IPv6 */
#define OBD_CONNECT2_LOCK_CONTENTION	  0x2000000ULL /* contention detect */
#define OBD_CONNECT2_ATOMIC_OPEN_LOCK	  0x4000000ULL /* lock on first open */
#define OBD_CONNECT2_ENCRYPT_NAME	  0x8000000ULL /* name encrypt */
/* client handle DMV inheritance */
#define OBD_CONNECT2_DMV_IMP_INHERIT	 0x20000000ULL
#define OBD_CONNECT2_ENCRYPT_FID2PATH	 0x40000000ULL /* fid2path enc file */
/* For MDS+OSS rolling upgrade interop with 2.16+older, ignored after 2.20.53 */
#define OBD_CONNECT2_REPLAY_CREATE	 0x80000000ULL /* replay OST_CREATE */
/* understands large/IPv6 NIDs */
#define OBD_CONNECT2_LARGE_NID		0x100000000ULL
#define OBD_CONNECT2_COMPRESS		0x200000000ULL /* compressed file */
/* only ZFS servers require a change to support unaligned DIO, so this flag is
 * ignored for ldiskfs servers
 */
#define OBD_CONNECT2_UNALIGNED_DIO	0x400000000ULL /* unaligned DIO */
#define OBD_CONNECT2_CONN_POLICY	0x800000000ULL /* server-side connection policy */
#define OBD_CONNECT2_SPARSE            0x1000000000ULL /* sparse LNet read */
#define OBD_CONNECT2_MIRROR_ID_FIX     0x2000000000ULL /* rr_mirror_id move */
#define OBD_CONNECT2_UPDATE_LAYOUT     0x4000000000ULL /* update compressibility */
#define OBD_CONNECT2_READDIR_OPEN	0x8000000000ULL /* read first dir page on open */
#define OBD_CONNECT2_FLR_EC	       0x10000000000ULL	/* parity support */
/* XXX README XXX README XXX README XXX README XXX README XXX README XXX
 * Please DO NOT add OBD_CONNECT flags before first ensuring that this value
 * is not in use by some other branch/patch.  Email adilger@whamcloud.com
 * to reserve the new OBD_CONNECT value for use by your feature. Then, submit
 * a small patch against master and LTS branches that ONLY adds the new flag,
 * updates obd_connect_names[], adds the flag to check_obd_connect_data(),
 * and updates wiretests accordingly, so it can be approved and landed easily
 * to reserve the flag for future use by your feature (submitted separately).
 */

#define OCD_HAS_FLAG(ocd, flag)  \
	(!!((ocd)->ocd_connect_flags & OBD_CONNECT_##flag))
#define OCD_HAS_FLAG2(ocd, flag2) (OCD_HAS_FLAG(ocd, FLAGS2) && \
	 !!((ocd)->ocd_connect_flags2 & OBD_CONNECT2_##flag2))


#ifdef HAVE_LRU_RESIZE_SUPPORT
#define LRU_RESIZE_CONNECT_FLAG OBD_CONNECT_LRU_RESIZE
#else
#define LRU_RESIZE_CONNECT_FLAG 0
#endif

#define MDT_CONNECT_SUPPORTED  (OBD_CONNECT_RDONLY | OBD_CONNECT_VERSION | \
				OBD_CONNECT_ACL | OBD_CONNECT_XATTR | \
				OBD_CONNECT_IBITS | OBD_CONNECT_NODEVOH | \
				OBD_CONNECT_ATTRFID | OBD_CONNECT_CANCELSET | \
				OBD_CONNECT_AT | OBD_CONNECT_BRW_SIZE | \
				OBD_CONNECT_MDS_MDS | OBD_CONNECT_FID | \
				LRU_RESIZE_CONNECT_FLAG | OBD_CONNECT_VBR | \
				OBD_CONNECT_LOV_V3 | OBD_CONNECT_FULL20 | \
				OBD_CONNECT_64BITHASH | OBD_CONNECT_JOBSTATS | \
				OBD_CONNECT_EINPROGRESS | \
				OBD_CONNECT_LIGHTWEIGHT | OBD_CONNECT_UMASK | \
				OBD_CONNECT_LVB_TYPE | OBD_CONNECT_LAYOUTLOCK |\
				OBD_CONNECT_PINGLESS | OBD_CONNECT_MAX_EASIZE |\
				OBD_CONNECT_FLOCK_DEAD | \
				OBD_CONNECT_DISP_STRIPE | OBD_CONNECT_LFSCK | \
				OBD_CONNECT_OPEN_BY_FID | \
				OBD_CONNECT_DIR_STRIPE | OBD_CONNECT_GRANT | \
				OBD_CONNECT_SRVLOCK | OBD_CONNECT_BULK_MBITS |\
				OBD_CONNECT_CKSUM |\
				OBD_CONNECT_MULTIMODRPCS |\
				OBD_CONNECT_SUBTREE | OBD_CONNECT_LARGE_ACL |\
				OBD_CONNECT_GRANT_PARAM | \
				OBD_CONNECT_GRANT_SHRINK | \
				OBD_CONNECT_SHORTIO | OBD_CONNECT_FLAGS2)

#define MDT_CONNECT_SUPPORTED2 (OBD_CONNECT2_FILE_SECCTX | \
				OBD_CONNECT2_DIR_MIGRATE | \
				OBD_CONNECT2_SUM_STATFS | \
				OBD_CONNECT2_OVERSTRIPING | \
				OBD_CONNECT2_FLR |\
				OBD_CONNECT2_LOCK_CONVERT | \
				OBD_CONNECT2_ARCHIVE_ID_ARRAY | \
				OBD_CONNECT2_INC_XID | \
				OBD_CONNECT2_SELINUX_POLICY | \
				OBD_CONNECT2_LSOM | \
				OBD_CONNECT2_ASYNC_DISCARD | \
				OBD_CONNECT2_PCC | \
				OBD_CONNECT2_CRUSH | \
				OBD_CONNECT2_ENCRYPT | \
				OBD_CONNECT2_GETATTR_PFID |\
				OBD_CONNECT2_LSEEK | OBD_CONNECT2_DOM_LVB |\
				OBD_CONNECT2_REP_MBITS | \
				OBD_CONNECT2_ATOMIC_OPEN_LOCK | \
				OBD_CONNECT2_BATCH_RPC | \
				OBD_CONNECT2_ENCRYPT_NAME | \
				OBD_CONNECT2_ENCRYPT_FID2PATH | \
				OBD_CONNECT2_DMV_IMP_INHERIT |\
				OBD_CONNECT2_UNALIGNED_DIO | \
				OBD_CONNECT2_PCCRO | \
				OBD_CONNECT2_MIRROR_ID_FIX)

#define OST_CONNECT_SUPPORTED  (OBD_CONNECT_SRVLOCK | OBD_CONNECT_GRANT | \
				OBD_CONNECT_VERSION | OBD_CONNECT_INDEX | \
				OBD_CONNECT_BRW_SIZE | OBD_CONNECT_CANCELSET | \
				OBD_CONNECT_AT | LRU_RESIZE_CONNECT_FLAG | \
				OBD_CONNECT_CKSUM | OBD_CONNECT_VBR | \
				OBD_CONNECT_MDS | OBD_CONNECT_SKIP_ORPHAN | \
				OBD_CONNECT_GRANT_SHRINK | OBD_CONNECT_FULL20 |\
				OBD_CONNECT_64BITHASH | OBD_CONNECT_MAXBYTES | \
				OBD_CONNECT_MAX_EASIZE | \
				OBD_CONNECT_EINPROGRESS | \
				OBD_CONNECT_JOBSTATS | \
				OBD_CONNECT_LIGHTWEIGHT | OBD_CONNECT_LVB_TYPE|\
				OBD_CONNECT_LAYOUTLOCK | OBD_CONNECT_FID | \
				OBD_CONNECT_PINGLESS | OBD_CONNECT_LFSCK | \
				OBD_CONNECT_BULK_MBITS | \
				OBD_CONNECT_GRANT_PARAM | \
				OBD_CONNECT_SHORTIO | OBD_CONNECT_FLAGS2)

#define OST_CONNECT_SUPPORTED2 (OBD_CONNECT2_LOCKAHEAD | OBD_CONNECT2_INC_XID |\
				OBD_CONNECT2_ENCRYPT | OBD_CONNECT2_LSEEK |\
				OBD_CONNECT2_REP_MBITS |\
				OBD_CONNECT2_REPLAY_CREATE |\
				OBD_CONNECT2_UNALIGNED_DIO)

#define ECHO_CONNECT_SUPPORTED (OBD_CONNECT_FID | OBD_CONNECT_FLAGS2)
#define ECHO_CONNECT_SUPPORTED2 OBD_CONNECT2_REP_MBITS

#define MGS_CONNECT_SUPPORTED  (OBD_CONNECT_VERSION | OBD_CONNECT_AT | \
				OBD_CONNECT_FULL20 | OBD_CONNECT_IMP_RECOV | \
				OBD_CONNECT_PINGLESS |\
				OBD_CONNECT_BULK_MBITS | OBD_CONNECT_BARRIER | \
				OBD_CONNECT_MGS_NIDLIST | \
				OBD_CONNECT_FLAGS2)

#define MGS_CONNECT_SUPPORTED2	OBD_CONNECT2_REP_MBITS | \
				OBD_CONNECT2_LARGE_NID

/* Features required for this version of the client to work with server */
#define CLIENT_CONNECT_MDT_REQD (OBD_CONNECT_FID |	\
				 OBD_CONNECT_ATTRFID |	\
				 OBD_CONNECT_FULL20)

/* INODE LOCK PARTS */
enum mds_ibits_locks {
	MDS_INODELOCK_NONE	= 0x000000000, /* no lock bits are used */
	MDS_INODELOCK_LOOKUP	= 0x000000001, /* For namespace, dentry etc Was
						* used to protect permission
						* (mode, owner, group, etc)
						* before 2.4.
						*/
	MDS_INODELOCK_UPDATE	= 0x000000002, /* size, links, timestamps */
	MDS_INODELOCK_OPEN	= 0x000000004, /* For opened files */
	MDS_INODELOCK_LAYOUT	= 0x000000008, /* for layout */

	/* The PERM bit is added in 2.4, and is used to protect permission
	 * (mode, owner, group, ACL, etc.) separate from LOOKUP lock.
	 * For remote directories (in DNE) these locks will be granted by
	 * different MDTs (different LDLM namespace).
	 *
	 * For local directory, the MDT always grants UPDATE|PERM together.
	 * For remote directory, master MDT (where remote directory is) grants
	 * UPDATE|PERM, and remote MDT (where name entry is) grants LOOKUP_LOCK.
	 */
	MDS_INODELOCK_PERM	= 0x000000010,
	MDS_INODELOCK_XATTR	= 0x000000020, /* non-permission extended attrs */
	MDS_INODELOCK_DOM	= 0x000000040, /* Data for Data-on-MDT files */
	/* Do not forget to increase MDS_INODELOCK_NUMBITS when adding bits */

	/* Reserve to make 64bit, not used anywhere, therefore
	 * MDS_INODELOCK_NUMBITS is not increased for this member
	 */
	MDS_INODELOCK_64BIT	= 0x100000000,
};
#define MDS_INODELOCK_NUMBITS 7
/* This FULL lock is useful to take on unlink sort of operations */
#define MDS_INODELOCK_FULL ((1 << MDS_INODELOCK_NUMBITS) - 1)
/* DOM lock shouldn't be canceled early, use this macro for ELC */
#define MDS_INODELOCK_ELC (MDS_INODELOCK_FULL & ~MDS_INODELOCK_DOM)

/* This structure is used for both request and reply.
 *
 * If we eventually have separate connect data for different types, which we
 * almost certainly will, then perhaps we stick a union in here.
 */
struct obd_connect_data {
	__u64 ocd_connect_flags; /* OBD_CONNECT_* per above */
	__u32 ocd_version;	 /* lustre release version number */
	__u32 ocd_grant;	 /* initial cache grant amount (bytes) */
	__u32 ocd_index;	 /* LOV index to connect to */
	__u32 ocd_brw_size;	 /* Maximum BRW size in bytes */
	enum mds_ibits_locks ocd_ibits_known; /* inode bits this client understands */
	__u8  ocd_grant_blkbits; /* log2 of the backend filesystem blocksize */
	__u8  ocd_grant_inobits; /* log2 of the per-inode space consumption */
	__u16 ocd_grant_tax_kb;	 /* extent insertion overhead, in 1K blocks */
	__u32 ocd_grant_max_blks;/* maximum number of blocks per extent */
	__u64 ocd_transno;	 /* first transno from client to be replayed */
	__u32 ocd_group;	 /* MDS group on OST */
	__u32 ocd_cksum_types;	 /* supported checksum algorithms */
	__u32 ocd_max_easize;	 /* How big LOV EA can be on MDS */
	__u32 ocd_instance;	 /* instance # of this target */
	__u64 ocd_maxbytes;	 /* Maximum stripe size in bytes */
	/* Fields after ocd_maxbytes are only accessible by the receiver
	 * if the corresponding flag in ocd_connect_flags is set. Accessing
	 * any field after ocd_maxbytes on the receiver without a valid flag
	 * may result in out-of-bound memory access and kernel oops.
	 */
	__u16 ocd_maxmodrpcs;	 /* Maximum modify RPCs in parallel */
	__u8  ocd_conn_policy;	 /* bitmask for client/server to communicate about policy */
	__u8  padding0;		 /* READ BELOW! also fix lustre_swab_connect */
	__u32 padding1;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 ocd_connect_flags2;/* OBD_CONNECT2_* per above */
	__u64 ocd_compr_type;	 /* bitmask of supported compression types */
	__u64 padding4;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 padding5;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 padding6;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 padding7;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 padding8;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 padding9;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 paddingA;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 paddingB;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 paddingC;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 paddingD;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 paddingE;		 /* READ BELOW! also fix lustre_swab_connect */
	__u64 paddingF;		 /* added 2.1.0. also fix lustre_swab_connect */
};
/* XXX README XXX README XXX README XXX README XXX README XXX README XXX
 * Please DO NOT use any fields before first ensuring that this field is
 * not in use by some other branch/patch.  Email adilger@whamcloud.com to
 * reserve the new obd_connect_data field for use by your feature. Then, submit
 * a small patch against master and LTS branch that ONLY adds the new field,
 * updates lustre_swab_connect(), along with the matching OBD_CONNECT flag,
 * and updates wiretests accordingly,so it can be approved and landed easily
 * to reserve the field for future use by your feature (submitted separately).
 */

/*
 * Supported checksum algorithms. Up to 32 checksum types are supported.
 * (32-bit mask stored in obd_connect_data::ocd_cksum_types)
 * Please update DECLARE_CKSUM_NAME in obd_cksum.h when adding a new
 * algorithm and also the OBD_FL_CKSUM* flags, OBD_CKSUM_ALL flag,
 * OBD_FL_CKSUM_ALL flag and potentially OBD_CKSUM_T10_ALL flag.
 */
enum cksum_types {
	OBD_CKSUM_CRC32		= 0x00000001,
	OBD_CKSUM_ADLER		= 0x00000002,
	OBD_CKSUM_CRC32C	= 0x00000004,
	OBD_CKSUM_RESERVED	= 0x00000008,
	OBD_CKSUM_T10IP512	= 0x00000010,
	OBD_CKSUM_T10IP4K	= 0x00000020,
	OBD_CKSUM_T10CRC512	= 0x00000040,
	OBD_CKSUM_T10CRC4K	= 0x00000080,
};

#define OBD_CKSUM_T10_ALL (OBD_CKSUM_T10IP512 | OBD_CKSUM_T10IP4K | \
	OBD_CKSUM_T10CRC512 | OBD_CKSUM_T10CRC4K)

#define OBD_CKSUM_ALL (OBD_CKSUM_CRC32 | OBD_CKSUM_ADLER | OBD_CKSUM_CRC32C | \
		       OBD_CKSUM_T10_ALL)

/*
 * The default checksum algorithm used on top of T10PI GRD tags for RPC.
 * Considering that the checksum-of-checksums is only computing CRC32 on a
 * 4KB chunk of GRD tags for a 1MB RPC for 512B sectors, or 16KB of GRD
 * tags for 16MB of 4KB sectors, this is only 1/256 or 1/1024 of the
 * total data being checksummed, so the checksum type used here should not
 * affect overall system performance noticeably.
 */
#define OBD_CKSUM_T10_TOP OBD_CKSUM_ADLER

/*
 * Explicitly define the meaning of the bits in ocd_conn_policy,
 * for server-side connection policy.
 */
enum conn_policy_flags {
	BYPASS_SOFT_BLOCK = 0,
	CONN_POLICY_FLAGS_NUM = 8,
};

/*
 *   OST requests: OBDO & OBD request records
 */

/* opcodes */
enum ost_cmd {
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
	OST_QUOTACHECK = 18, /* not used since 2.4 */
	OST_QUOTACTL   = 19,
	OST_QUOTA_ADJUST_QUNIT = 20, /* not used since 2.4 */
	OST_LADVISE    = 21,
	OST_FALLOCATE  = 22,
	OST_SEEK       = 23,
	OST_LAST_OPC /* must be < 33 to avoid MDS_GETATTR */
};
#define OST_FIRST_OPC  OST_REPLY

enum obdo_flags {
	OBD_FL_INLINEDATA   = 0x00000001,
	OBD_FL_OBDMDEXISTS  = 0x00000002,
	OBD_FL_DELORPHAN    = 0x00000004, /* if set in o_flags delete orphans */
	OBD_FL_NORPC        = 0x00000008, /* set in o_flags do in OSC not OST */
	OBD_FL_IDONLY       = 0x00000010, /* set in o_flags only adjust obj id*/
	OBD_FL_RECREATE_OBJS = 0x00000020, /* recreate missing obj */
	OBD_FL_DEBUG_CHECK  = 0x00000040, /* echo client/server debug check */
	OBD_FL_NO_PRJQUOTA  = 0x00000080, /* the object's project is over
					   * quota
					   */
	OBD_FL_NO_USRQUOTA  = 0x00000100, /* the object's owner is over quota */
	OBD_FL_NO_GRPQUOTA  = 0x00000200, /* the object's group is over quota */
	OBD_FL_CREATE_CROW  = 0x00000400, /* object should be create on write */
	OBD_FL_SRVLOCK      = 0x00000800, /* delegate DLM locking to server */
	OBD_FL_CKSUM_CRC32  = 0x00001000, /* CRC32 checksum type */
	OBD_FL_CKSUM_ADLER  = 0x00002000, /* ADLER checksum type */
	OBD_FL_CKSUM_CRC32C = 0x00004000, /* CRC32C checksum type */
	OBD_FL_CKSUM_T10IP512  = 0x00005000, /* T10PI IP cksum, 512B sector */
	OBD_FL_CKSUM_T10IP4K   = 0x00006000, /* T10PI IP cksum, 4KB sector */
	OBD_FL_CKSUM_T10CRC512 = 0x00007000, /* T10PI CRC cksum, 512B sector */
	OBD_FL_CKSUM_T10CRC4K  = 0x00008000, /* T10PI CRC cksum, 4KB sector */
	OBD_FL_CKSUM_RSVD3  = 0x00010000, /* for future cksum types */
	OBD_FL_SHRINK_GRANT = 0x00020000, /* object shrink the grant */
	OBD_FL_MMAP         = 0x00040000, /* object is mmapped on the client.
					   *  XXX: obsoleted - reserved for old
					   *  clients prior than 2.2
					   */
	OBD_FL_RECOV_RESEND = 0x00080000, /* recoverable resent */
	OBD_FL_NOSPC_BLK    = 0x00100000, /* no more block space on OST */
	OBD_FL_FLUSH	    = 0x00200000, /* flush pages on the OST */
	OBD_FL_SHORT_IO	    = 0x00400000, /* short io request */
	OBD_FL_ROOT_SQUASH  = 0x00800000, /* root squash */
	OBD_FL_ROOT_PRJQUOTA  = 0x01000000, /* check prj quota for root */
	/* OBD_FL_LOCAL_MASK = 0xF0000000, was local-only flags until 2.10 */

	/*
	 * Note that while the original checksum values were separate bits,
	 * in 2.x we can actually allow all values from 1-31. T10-PI checksum
	 * types already use values which are not separate bits.
	 */
	OBD_FL_CKSUM_ALL    = OBD_FL_CKSUM_CRC32 | OBD_FL_CKSUM_ADLER |
			      OBD_FL_CKSUM_CRC32C | OBD_FL_CKSUM_T10IP512 |
			      OBD_FL_CKSUM_T10IP4K | OBD_FL_CKSUM_T10CRC512 |
			      OBD_FL_CKSUM_T10CRC4K,

	OBD_FL_NO_QUOTA_ALL = OBD_FL_NO_USRQUOTA | OBD_FL_NO_GRPQUOTA |
			      OBD_FL_NO_PRJQUOTA,
};

/*
 * All LOV EA magics should have the same postfix, if some new version
 * Lustre instroduces new LOV EA magic, then when down-grade to an old
 * Lustre, even though the old version system does not recognizes such
 * new magic, it still can distinguish the corrupted cases by checking
 * the magic's postfix.
 */
#define LOV_MAGIC_MAGIC 0x0BD0
#define LOV_MAGIC_MASK  0xFFFF

#define LOV_MAGIC_BAD		(0x0BAD0000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_V1		(0x0BD10000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_JOIN_V1	(0x0BD20000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_V3		(0x0BD30000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_MIGRATE	(0x0BD40000 | LOV_MAGIC_MAGIC)
/* reserved for specifying OSTs */
#define LOV_MAGIC_SPECIFIC	(0x0BD50000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC		LOV_MAGIC_V1
#define LOV_MAGIC_COMP_V1	(0x0BD60000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_FOREIGN	(0x0BD70000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_SEL		(0x0BD80000 | LOV_MAGIC_MAGIC)

/*
 * magic for fully defined striping
 * the idea is that we should have different magics for striping "hints"
 * (struct lov_user_md_v[13]) and defined ready-to-use striping (struct
 * lov_mds_md_v[13]). at the moment the magics are used in wire protocol,
 * we can't just change it w/o long way preparation, but we still need a
 * mechanism to allow LOD to differentiate hint versus ready striping.
 * so, at the moment we do a trick: MDT knows what to expect from request
 * depending on the case (replay uses ready striping, non-replay req uses
 * hints), so MDT replaces magic with appropriate one and now LOD can
 * easily understand what's inside -bzzz
 *
 * those *_DEF magics are only used on server side internally, they
 * won't be put on wire or disk.
 */
#define LOV_MAGIC_DEFINED		0x10000000
#define LOV_MAGIC_V1_DEFINED		(LOV_MAGIC_DEFINED | LOV_MAGIC_V1)
#define LOV_MAGIC_V3_DEFINED		(LOV_MAGIC_DEFINED | LOV_MAGIC_V3)
#define LOV_MAGIC_COMP_V1_DEFINED	(LOV_MAGIC_DEFINED | LOV_MAGIC_COMP_V1)

#define lov_pattern(pattern)		(pattern & ~LOV_PATTERN_F_MASK)
#define lov_pattern_flags(pattern)	(pattern & LOV_PATTERN_F_MASK)

#define lov_ost_data lov_ost_data_v1
struct lov_ost_data_v1 {          /* per-stripe data structure (little-endian)*/
	struct ost_id l_ost_oi;	  /* OST object ID */
	union {
		__u32 l_ost_type; /* type of data stored in OST object */
		__u32 l_ost_gen;  /* generation of this l_ost_idx */
	};
	__u32 l_ost_idx;          /* OST index in LOV (lov_tgt_desc->tgts) */
};

#define lov_mds_md lov_mds_md_v1
struct lov_mds_md_v1 {            /* LOV EA mds/wire data (little-endian) */
	__u32			lmm_magic;        /* LOV_MAGIC_V1 */
	enum lov_pattern	lmm_pattern;      /* LOV_PATTERN_RAID0, ... */
	struct ost_id		lmm_oi;	          /* LOV object ID */
	__u32			lmm_stripe_size;  /* size of stripe in bytes */
	__u16			lmm_stripe_count; /* OST stripes in layout */
	__u16			lmm_layout_gen;   /* layout generation number */
	struct lov_ost_data_v1  lmm_objects[];    /* per-stripe data */
};

#define MAX_MD_SIZE_OLD (sizeof(struct lov_mds_md) +			\
			 4 * sizeof(struct lov_ost_data))
#define MAX_MD_SIZE (sizeof(struct lov_comp_md_v1) +			\
		     4 * (sizeof(struct lov_comp_md_entry_v1) +		\
			  MAX_MD_SIZE_OLD))
#define MIN_MD_SIZE (sizeof(struct lov_mds_md) + 1 *			\
		     sizeof(struct lov_ost_data))

/* default MDT reply size allocated, should the striping be bigger, it will be
 * reallocated in mdt_fix_reply. 100 stipes ~= 2.5KB of data.
 */
#define DEF_REP_MD_SIZE (sizeof(struct lov_mds_md) + \
			 100 * sizeof(struct lov_ost_data))

#define XATTR_NAME_ACL_ACCESS   "system.posix_acl_access"
#define XATTR_NAME_ACL_DEFAULT  "system.posix_acl_default"
#define XATTR_USER_PREFIX       "user."
#define XATTR_TRUSTED_PREFIX    "trusted."
#define XATTR_SECURITY_PREFIX   "security."
#define XATTR_ENCRYPTION_PREFIX	"encryption."

#define XATTR_NAME_SOM		"trusted.som"
#define XATTR_NAME_LOV          "trusted.lov"
#define XATTR_NAME_LMA          "trusted.lma"
#define XATTR_NAME_LMV          "trusted.lmv"
#define XATTR_NAME_DEFAULT_LMV	"trusted.dmv"
#define XATTR_NAME_LINK         "trusted.link"
#define XATTR_NAME_FID          "trusted.fid"
#define XATTR_NAME_VERSION      "trusted.version"
#define XATTR_NAME_SOM		"trusted.som"
#define XATTR_NAME_HSM		"trusted.hsm"
#define XATTR_NAME_LFSCK_BITMAP "trusted.lfsck_bitmap"
#define XATTR_NAME_DUMMY	"trusted.dummy"
#define XATTR_NAME_PROJID	"trusted.projid"
#define XATTR_NAME_DATAVER	"trusted.dataver"
#define XATTR_NAME_PIN		"trusted.pin"

#define LL_XATTR_NAME_ENCRYPTION_CONTEXT_OLD XATTR_SECURITY_PREFIX"c"
#define LL_XATTR_NAME_ENCRYPTION_CONTEXT XATTR_ENCRYPTION_PREFIX"c"

#define XATTR_NAME_LFSCK_NAMESPACE "trusted.lfsck_ns"
#define XATTR_NAME_MAX_LEN	32 /* increase this, if there is longer name. */

#define XATTR_NAME_JOB_DEFAULT	"user.job"
/* longest allowed jobid xattr name is "user." + 7 chars + null terminator */
#define XATTR_JOB_MAX_LEN	13

struct lov_mds_md_v3 {            /* LOV EA mds/wire data (little-endian) */
	__u32			lmm_magic;        /* LOV_MAGIC_V3 */
	enum lov_pattern	lmm_pattern;      /* LOV_PATTERN_RAID0, ... */
	struct ost_id		lmm_oi;	          /* LOV object ID */
	__u32			lmm_stripe_size;  /* size of stripe in bytes */
	__u16			lmm_stripe_count; /* OST stripes in layout */
	__u16			lmm_layout_gen;   /* layout generation number */
	char                    lmm_pool_name[LOV_MAXPOOLNAME + 1];
	struct lov_ost_data_v1  lmm_objects[];    /* per-stripe data */
};

static inline __u32 lov_mds_md_size(__u16 stripes, __u32 lmm_magic)
{
	if (stripes <= LOV_ALL_STRIPES && stripes >= LOV_ALL_STRIPES_WIDE)
		stripes = 0;

	if (lmm_magic == LOV_MAGIC_V1)
		return sizeof(struct lov_mds_md_v1) +
				stripes * sizeof(struct lov_ost_data_v1);
	else /* LOV_MAGIC_V3 and LOV_MAGIC_SPECIFIC */
		return sizeof(struct lov_mds_md_v3) +
				stripes * sizeof(struct lov_ost_data_v1);
}

static inline __u32
lov_mds_md_max_stripe_count(__kernel_size_t buf_size, __u32 lmm_magic)
{
	switch (lmm_magic) {
	case LOV_MAGIC_V1: {
		struct lov_mds_md_v1 lmm;

		if (buf_size < sizeof(lmm))
			return 0;

		return (buf_size - sizeof(lmm)) / sizeof(lmm.lmm_objects[0]);
	}
	case LOV_MAGIC_V3: {
		struct lov_mds_md_v3 lmm;

		if (buf_size < sizeof(lmm))
			return 0;

		return (buf_size - sizeof(lmm)) / sizeof(lmm.lmm_objects[0]);
	}
	default:
		return 0;
	}
}

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
#define OBD_MD_DOM_SIZE    (0x00001000ULL) /* Data-on-MDT component size */
#define OBD_MD_FLNLINK     (0x00002000ULL) /* link count */
#define OBD_MD_FLPARENT    (0x00004000ULL) /* parent FID */
#define OBD_MD_LAYOUT_VERSION (0x00008000ULL) /* OST object layout version */
#define OBD_MD_FLRDEV      (0x00010000ULL) /* device number */
#define OBD_MD_FLEASIZE    (0x00020000ULL) /* extended attribute data */
#define OBD_MD_LINKNAME    (0x00040000ULL) /* symbolic link target */
#define OBD_MD_FLHANDLE    (0x00080000ULL) /* file/lock handle */
#define OBD_MD_FLCKSUM     (0x00100000ULL) /* bulk data checksum */
/*	OBD_MD_FLQOS       (0x00200000ULL) has never been used */
/*	OBD_MD_FLCOOKIE    (0x00800000ULL) obsolete in 2.8 */
#define OBD_MD_FLPRJQUOTA  (0x00400000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLGROUP     (0x01000000ULL) /* group */
#define OBD_MD_FLFID       (0x02000000ULL) /* ->ost write inline fid */
/*	OBD_MD_FLEPOCH     (0x04000000ULL) obsolete 2.7.50 */
#define OBD_MD_FLGRANT     (0x08000000ULL) /* ost preallocation space grant */
#define OBD_MD_FLDIREA     (0x10000000ULL) /* dir's extended attribute data */
#define OBD_MD_FLUSRQUOTA  (0x20000000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLGRPQUOTA  (0x40000000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLMODEASIZE (0x80000000ULL) /* EA size will be changed */

#define OBD_MD_MDS         (0x0000000100000000ULL) /* where an inode lives on */
/*	OBD_MD_REINT       (0x0000000200000000ULL) obsolete 1.8 */
#define OBD_MD_MEA         (0x0000000400000000ULL) /* CMD split EA  */
#define OBD_MD_TSTATE      (0x0000000800000000ULL) /* transient state field */

#define OBD_MD_FLXATTR       (0x0000001000000000ULL) /* xattr */
#define OBD_MD_FLXATTRLS     (0x0000002000000000ULL) /* xattr list */
#define OBD_MD_FLXATTRRM     (0x0000004000000000ULL) /* xattr remove */
#define OBD_MD_FLACL         (0x0000008000000000ULL) /* ACL */
#define OBD_MD_FLAGSTATFS    (0x0000010000000000ULL) /* aggregated statfs */
/*	OBD_MD_FLMDSCAPA     (0x0000020000000000ULL) obsolete 2.7.54 */
/*	OBD_MD_FLOSSCAPA     (0x0000040000000000ULL) obsolete 2.7.54 */
/*      OBD_MD_FLCKSPLIT     (0x0000080000000000ULL) obsolete 2.3.58*/
#define OBD_MD_FLCROSSREF    (0x0000100000000000ULL) /* Cross-ref case */
#define OBD_MD_FLGETATTRLOCK (0x0000200000000000ULL) /* Get IOEpoch attributes
						      * under lock; for xattr
						      * requests means the
						      * client holds the lock
						      */
#define OBD_MD_FLOBJCOUNT    (0x0000400000000000ULL) /* for multiple destroy */

#define OBD_MD_FLDATAVERSION (0x0010000000000000ULL) /* iversion sum */
#define OBD_MD_CLOSE_INTENT_EXECED (0x0020000000000000ULL) /* intent executed */

#define OBD_MD_DEFAULT_MEA   (0x0040000000000000ULL) /* default MEA */
#define OBD_MD_FLOSTLAYOUT   (0x0080000000000000ULL) /* contain ost_layout */
#define OBD_MD_FLPROJID      (0x0100000000000000ULL) /* project ID */
#define OBD_MD_SECCTX        (0x0200000000000000ULL) /* embed security xattr */
#define OBD_MD_FLLAZYSIZE    (0x0400000000000000ULL) /* Lazy size */
#define OBD_MD_FLLAZYBLOCKS  (0x0800000000000000ULL) /* Lazy blocks */
#define OBD_MD_FLBTIME       (0x1000000000000000ULL) /* birth time */
#define OBD_MD_ENCCTX        (0x2000000000000000ULL) /* embed encryption ctx */
#define OBD_MD_NAMEHASH      (0x4000000000000000ULL) /* use hash instead of name
						      * in case of encryption
						      */

#define OBD_MD_FLALLQUOTA (OBD_MD_FLUSRQUOTA | \
			   OBD_MD_FLGRPQUOTA | \
			   OBD_MD_FLPRJQUOTA)

#define OBD_MD_FLGETATTR (OBD_MD_FLID    | OBD_MD_FLATIME | OBD_MD_FLMTIME | \
			  OBD_MD_FLCTIME | OBD_MD_FLSIZE  | OBD_MD_FLBLKSZ | \
			  OBD_MD_FLMODE  | OBD_MD_FLTYPE  | OBD_MD_FLUID   | \
			  OBD_MD_FLGID   | OBD_MD_FLFLAGS | OBD_MD_FLNLINK | \
			  OBD_MD_FLPARENT | OBD_MD_FLRDEV  | OBD_MD_FLGROUP | \
			  OBD_MD_FLPROJID | OBD_MD_FLBTIME)

#define OBD_MD_FLXATTRALL (OBD_MD_FLXATTR | OBD_MD_FLXATTRLS)

/* don't forget obdo_fid which is way down at the bottom so it can
 * come after the definition of llog_cookie
 */

enum hss_valid {
	HSS_SETMASK	= 0x01,
	HSS_CLEARMASK	= 0x02,
	HSS_ARCHIVE_ID	= 0x04,
};

struct hsm_state_set {
	__u32	hss_valid;
	__u32	hss_archive_id;
	__u64	hss_setmask;
	__u64	hss_clearmask;
};

/* ost_body.data values for OST_BRW */

#define OBD_BRW_READ            0x01
#define OBD_BRW_WRITE           0x02
#define OBD_BRW_RWMASK          (OBD_BRW_READ | OBD_BRW_WRITE)
#define OBD_BRW_NDELAY		0x04 /* Non-delay RPC should be issued for
				      * this page. Non-delay RPCs have bit
				      * rq_no_delay set.
				      */
#define OBD_BRW_SYNC            0x08 /* part of sync transfer, not in grant */
#define OBD_BRW_CHECK           0x10
#define OBD_BRW_FROM_GRANT      0x20 /* the osc manages this under llite */
#define OBD_BRW_GRANTED         0x40 /* the ost manages this */
/* OBD_BRW_NOCACHE is currently neither set nor tested */
#define OBD_BRW_NOCACHE         0x80 /* this page is a part of non-cached IO */
#define OBD_BRW_NOQUOTA        0x100 /* do not enforce quota */
#define OBD_BRW_SRVLOCK        0x200 /* Client holds no lock over this page */
#define OBD_BRW_ASYNC          0x400 /* Server may delay commit to disk */
#define OBD_BRW_MEMALLOC       0x800 /* Client runs in the "kswapd" context */
#define OBD_BRW_OVER_USRQUOTA 0x1000 /* Running out of user quota */
#define OBD_BRW_OVER_GRPQUOTA 0x2000 /* Running out of group quota */
#define OBD_BRW_SOFT_SYNC     0x4000 /* flag notifies server that client is
				      * running low on space for unstable
				      * pages; asking it to sync quickly
				      */
#define OBD_BRW_OVER_PRJQUOTA 0x8000 /* Running out of project quota */
#define OBD_BRW_ROOT_PRJQUOTA 0x10000 /* check project quota for root */
#define OBD_BRW_RDMA_ONLY    0x20000 /* RPC contains RDMA-only pages*/
#define OBD_BRW_SYS_RESOURCE 0x40000 /* page has CAP_SYS_RESOURCE */
#define OBD_BRW_COMPRESSED   0x80000 /* data compressed on client */
/* client compressed data optimistically but server must check file size */
#define OBD_BRW_SPECULATIVE_COMPR  0x100000

#define OBD_BRW_OVER_ALLQUOTA (OBD_BRW_OVER_USRQUOTA | \
			       OBD_BRW_OVER_GRPQUOTA | \
			       OBD_BRW_OVER_PRJQUOTA)

#define OBD_BRW_DONE	0x40000000UL   /*
					* osd-ldiskfs inernal,
					* IO has been issued before
					*/
#define OBD_BRW_LOCAL1	0x80000000UL	/*
					 * osd-ldiskfs internal,
					 * page mapped to real block
					 */

#define OBD_BRW_LOCALS (OBD_BRW_LOCAL1 | OBD_BRW_DONE)

#define OBD_MAX_GRANT 0x7fffffffUL /* Max grant allowed to one client: 2 GiB */

#define OBD_OBJECT_EOF LUSTRE_EOF

#define OST_MIN_PRECREATE 32
#define OST_MAX_PRECREATE 20000

struct obd_ioobj {
	/* object ID, if multi-obj BRW */
	struct ost_id	ioo_oid;
	/* low 16 bits were o_mode before 2.4, now (PTLRPC_BULK_OPS_LIMIT - 1)
	 * in high 16 bits in 2.4 and later.
	 * With OBD_CONNECT2_UNALIGNED_DIO udio uses low 4 bits for offset
	 */
	__u32		ioo_max_brw;
	/* number of niobufs for this object */
	__u32		ioo_bufcnt;
};

/* NOTE: IOOBJ_MAX_BRW_BITS defines the _offset_ of the max_brw field in
 * ioo_max_brw, NOT the maximum number of bits in PTLRPC_BULK_OPS_BITS.
 * That said, ioo_max_brw is a 32-bit field so the limit is also 16 bits.
 */
#define IOOBJ_MAX_BRW_BITS	16
#define IOOBJ_OFFSET_BITS	4
#define IOOBJ_OFFSET_MASK	((1u << IOOBJ_OFFSET_BITS) - 1)

#define ioobj_page_interop_offset(ioo) ((ioo)->ioo_max_brw & IOOBJ_OFFSET_MASK)
#define ioobj_max_brw_get(ioo)	(((ioo)->ioo_max_brw >> IOOBJ_MAX_BRW_BITS) + 1)
#define ioobj_max_brw_set(ioo, num, offset)				\
do {									\
	(ioo)->ioo_max_brw = ((num) - 1) << IOOBJ_MAX_BRW_BITS;		\
	(ioo)->ioo_max_brw |= (offset) & IOOBJ_OFFSET_MASK;		\
} while (0)

/* multiple of 8 bytes => can array */
struct niobuf_remote {
	__u64	rnb_offset;
	__u32	rnb_len;
	__u32	rnb_flags;
};

/* lock value block communicated between the filter and llite */

/* OST_LVB_ERR_INIT is needed because the return code in rc is
 * negative, i.e. because ((MASK + rc) & MASK) != MASK.
 */
#define OST_LVB_ERR_INIT 0xffbadbad80000000ULL
#define OST_LVB_ERR_MASK 0xffbadbad00000000ULL
#define OST_LVB_IS_ERR(blocks)						\
	((blocks & OST_LVB_ERR_MASK) == OST_LVB_ERR_MASK)
#define OST_LVB_SET_ERR(blocks, rc) blocks = OST_LVB_ERR_INIT + rc
#define OST_LVB_GET_ERR(blocks)    (int)(blocks - OST_LVB_ERR_INIT)

struct ost_lvb_v1 {
	__u64	lvb_size;
	__s64	lvb_mtime;
	__s64	lvb_atime;
	__s64	lvb_ctime;
	__u64	lvb_blocks;
};

struct ost_lvb {
	__u64	lvb_size;
	__s64	lvb_mtime;
	__s64	lvb_atime;
	__s64	lvb_ctime;
	__u64	lvb_blocks;
	__u32	lvb_mtime_ns;
	__u32	lvb_atime_ns;
	__u32	lvb_ctime_ns;
	__u32	lvb_padding;
};

/*
 *   lquota data structures
 */

/* The lquota_id structure is an union of all the possible identifier types that
 * can be used with quota, this includes:
 * - 64-bit user ID
 * - 64-bit group ID
 * - a FID which can be used for per-directory quota in the future
 */
union lquota_id {
	struct lu_fid	qid_fid; /* FID for per-directory quota */
	__u64		qid_uid; /* user identifier */
	__u64		qid_gid; /* group identifier */
	__u64		qid_projid; /* project identifier */
};

/* quotactl management */
struct obd_quotactl {
	__u32			qc_cmd;
	__u32			qc_type; /* see Q_* flag below */
	__u32			qc_id;
	__u32			qc_stat;
	struct obd_dqinfo	qc_dqinfo;
	struct obd_dqblk	qc_dqblk;
	char			qc_poolname[];
};

#define qc_iter_md_offset	qc_dqblk.dqb_bhardlimit
#define qc_iter_dt_offset	qc_dqblk.dqb_ihardlimit
#define qc_iter_md_buflen	qc_dqblk.dqb_bsoftlimit
#define qc_iter_dt_buflen	qc_dqblk.dqb_isoftlimit
#define qc_iter_list		qc_dqblk.dqb_curspace
#define qc_iter_qid_start	qc_dqblk.dqb_curinodes
#define qc_iter_qid_end		qc_dqblk.dqb_btime

#define Q_COPY(out, in, member) (out)->member = (in)->member

#define QCTL_COPY_NO_PNAME(out, in)					\
do {									\
	Q_COPY(out, in, qc_cmd);					\
	Q_COPY(out, in, qc_type);					\
	Q_COPY(out, in, qc_id);						\
	Q_COPY(out, in, qc_stat);					\
	Q_COPY(out, in, qc_dqinfo);					\
	Q_COPY(out, in, qc_dqblk);					\
} while (0)

/* NOTE:
 * - in and out maybe a type of struct if_quotactl or struct obd_quotactl
 * - in and out need not be of the same type.
 */
#define QCTL_COPY(out, in)						\
do {									\
	QCTL_COPY_NO_PNAME(out, in);					\
	if (LUSTRE_Q_CMD_IS_POOL(in->qc_cmd)) {				\
		size_t len = strnlen(in->qc_poolname, LOV_MAXPOOLNAME);	\
									\
		memcpy(out->qc_poolname, in->qc_poolname, len);		\
		out->qc_poolname[len] = '\0';				\
	}								\
} while (0)

/* Body of quota request used for quota acquire/release RPCs between quota
 * master (aka QMT) and slaves (ak QSD).
 */
struct quota_body {
	struct lu_fid	qb_fid;     /* FID of global index packing the pool ID
				     * and type (data or metadata) as well as
				     * the quota type (user or group).
				     */
	union lquota_id	qb_id;      /* uid or gid or directory FID */
	__u32		qb_flags;   /* see below */
	__u32		qb_padding;
	__u64		qb_count;   /* acquire/release count (kbytes/inodes) */
	__u64		qb_usage;   /* current slave usage (kbytes/inodes) */
	__u64		qb_slv_ver; /* slave index file version */
	struct lustre_handle	qb_lockh;     /* per-ID lock handle */
	struct lustre_handle	qb_glb_lockh; /* global lock handle */
	__u64		qb_padding1[4];
};

/* When the quota_body is used in the reply of quota global intent
 * lock (IT_QUOTA_CONN) reply, qb_fid contains slave index file FID.
 */
#define qb_slv_fid	qb_fid
/* qb_usage is the current qunit (in kbytes/inodes) when quota_body is used in
 * quota reply
 */
#define qb_qunit	qb_usage

#define QUOTA_DQACQ_FL_ACQ	0x1  /* acquire quota */
#define QUOTA_DQACQ_FL_PREACQ	0x2  /* pre-acquire */
#define QUOTA_DQACQ_FL_REL	0x4  /* release quota */
#define QUOTA_DQACQ_FL_REPORT	0x8  /* report usage */

/* Quota types currently supported */
enum lquota_type {
	LQUOTA_TYPE_USR	= 0x00, /* maps to USRQUOTA */
	LQUOTA_TYPE_GRP	= 0x01, /* maps to GRPQUOTA */
	LQUOTA_TYPE_PRJ	= 0x02, /* maps to PRJQUOTA */
	LQUOTA_TYPE_MAX
};

/* There are 2 different resource types on which a quota limit can be enforced:
 * - inodes on the MDTs
 * - blocks on the OSTs
 */
enum lquota_res_type {
	LQUOTA_RES_MD		= 0x01, /* skip 0 to avoid null oid in FID */
	LQUOTA_RES_DT		= 0x02,
	LQUOTA_LAST_RES,
	LQUOTA_FIRST_RES	= LQUOTA_RES_MD
};
#define LQUOTA_NR_RES (LQUOTA_LAST_RES - LQUOTA_FIRST_RES + 1)

/*
 * Space accounting support
 * Format of an accounting record, providing disk usage information for a given
 * user or group
 */
struct lquota_acct_rec { /* 16 bytes */
	__u64 bspace;  /* current space in use */
	__u64 ispace;  /* current # inodes in use */
};

/*
 * Global quota index support
 * Format of a global record, providing global quota settings for a given quota
 * identifier
 */
struct lquota_glb_rec { /* 32 bytes */
	__u64 qbr_hardlimit; /* quota hard limit, in #inodes or kbytes */
	__u64 qbr_softlimit; /* quota soft limit, in #inodes or kbytes */
	__u64 qbr_time;      /* grace time, in seconds */
	__u64 qbr_granted;   /* amount granted to slaves (inodes or KiB) */
};

/*
 * Slave index support
 * Format of a slave record, recording how much space is granted to a given
 * slave
 */
struct lquota_slv_rec { /* 8 bytes */
	__u64 qsr_granted; /* space granted to the slave for the key=ID,
			    * in #inodes or kbytes
			    */
};

/* Data structures associated with the quota locks */

/* Glimpse descriptor used for the index & per-ID quota locks */
struct ldlm_gl_lquota_desc {
	union lquota_id	gl_id;    /* quota ID subject to the glimpse */
	__u64		gl_flags; /* see LQUOTA_FL* below */
	__u64		gl_ver;   /* new index version */
	__u64		gl_hardlimit; /* new hardlimit or qunit value */
	__u64		gl_softlimit; /* new softlimit */
	__u64		gl_time;
	__u64		gl_pad2;
};
#define gl_qunit	gl_hardlimit /* current qunit value used when
				      * glimpsing per-ID quota locks
				      */

/* quota glimpse flags */
#define LQUOTA_FL_EDQUOT 0x1 /* user/group out of quota space on QMT */

/* LVB used with quota (global and per-ID) locks */
struct lquota_lvb {
	__u64	lvb_flags;	/* see LQUOTA_FL* above */
	__u64	lvb_id_may_rel; /* space that might be released later */
	__u64	lvb_id_rel;     /* space released by the slave for this ID */
	__u64	lvb_id_qunit;   /* current qunit value */
	__u64	lvb_pad1;
};

/* LVB used with global quota lock */
#define lvb_glb_ver  lvb_id_may_rel /* current version of the global index */

/* op codes */
enum quota_cmd {
	QUOTA_DQACQ	= 601,
	QUOTA_DQREL	= 602,
	QUOTA_LAST_OPC
};
#define QUOTA_FIRST_OPC	QUOTA_DQACQ

/*
 *   MDS REQ RECORDS
 */

/* opcodes */
enum mds_cmd {
	MDS_GETATTR		= 33,
	MDS_GETATTR_NAME	= 34,
	MDS_CLOSE		= 35,
	MDS_REINT		= 36,
	MDS_READPAGE		= 37,
	MDS_CONNECT		= 38,
	MDS_DISCONNECT		= 39,
	MDS_GET_ROOT		= 40,
	MDS_STATFS		= 41,
	MDS_PIN			= 42, /* obsolete, never used in a release */
	MDS_UNPIN		= 43, /* obsolete, never used in a release */
	MDS_SYNC		= 44,
	MDS_DONE_WRITING	= 45, /* obsolete since 2.8.0 */
	MDS_SET_INFO		= 46,
	MDS_QUOTACHECK		= 47, /* not used since 2.4 */
	MDS_QUOTACTL		= 48,
	MDS_GETXATTR		= 49,
	MDS_SETXATTR		= 50, /* obsolete, now it's MDS_REINT op */
	MDS_WRITEPAGE		= 51,
	MDS_IS_SUBDIR		= 52, /* obsolete, never used in a release */
	MDS_GET_INFO		= 53,
	MDS_HSM_STATE_GET	= 54,
	MDS_HSM_STATE_SET	= 55,
	MDS_HSM_ACTION		= 56,
	MDS_HSM_PROGRESS	= 57,
	MDS_HSM_REQUEST		= 58,
	MDS_HSM_CT_REGISTER	= 59,
	MDS_HSM_CT_UNREGISTER	= 60,
	MDS_SWAP_LAYOUTS	= 61,
	MDS_RMFID		= 62,
	MDS_BATCH		= 63,
	MDS_HSM_DATA_VERSION	= 64,
	MDS_LAST_OPC
};

#define MDS_FIRST_OPC    MDS_GETATTR


/* opcodes for object update */
enum update_cmd {
	OUT_UPDATE	= 1000,
	OUT_UPDATE_LAST_OPC
};

#define OUT_UPDATE_FIRST_OPC    OUT_UPDATE

/*
 * Do not exceed 63
 */

enum mds_reint_op {
	REINT_SETATTR  = 1,
	REINT_CREATE   = 2,
	REINT_LINK     = 3,
	REINT_UNLINK   = 4,
	REINT_RENAME   = 5,
	REINT_OPEN     = 6,
	REINT_SETXATTR = 7,
	REINT_RMENTRY  = 8,
	REINT_MIGRATE  = 9,
	REINT_RESYNC   = 10,
	REINT_MAX
};

/* the disposition of the intent outlines what was executed */
#define DISP_IT_EXECD        0x00000001
#define DISP_LOOKUP_EXECD    0x00000002
#define DISP_LOOKUP_NEG      0x00000004
#define DISP_LOOKUP_POS      0x00000008
#define DISP_OPEN_CREATE     0x00000010
#define DISP_OPEN_OPEN       0x00000020
#define DISP_ENQ_COMPLETE    0x00400000		/* obsolete and unused */
#define DISP_ENQ_OPEN_REF    0x00800000
#define DISP_ENQ_CREATE_REF  0x01000000
#define DISP_OPEN_LOCK       0x02000000
#define DISP_OPEN_LEASE      0x04000000
#define DISP_OPEN_STRIPE     0x08000000
#define DISP_OPEN_DENY	     0x10000000

/* NOTE: until Lustre 1.8.7/2.1.1 the fid_ver() was packed into name[2],
 * but was moved into name[1] along with the OID to avoid consuming the
 * name[2,3] fields that need to be used for the quota id (also a FID).
 */
enum {
	LUSTRE_RES_ID_SEQ_OFF = 0,
	LUSTRE_RES_ID_VER_OID_OFF = 1,
	LUSTRE_RES_ID_WAS_VER_OFF = 2, /* see note above */
	LUSTRE_RES_ID_QUOTA_SEQ_OFF = 2,
	LUSTRE_RES_ID_QUOTA_VER_OID_OFF = 3,
	LUSTRE_RES_ID_HSH_OFF = 3
};

#define MDS_STATUS_CONN 1
#define MDS_STATUS_LOV 2

enum {
	/* these should be identical to their EXT4_*_FL counterparts, they are
	 * redefined here only to avoid dragging in fs/ext4/ext4.h
	 */
	LUSTRE_UNRM_FL		= 0x00000002, /* Undelete */
	LUSTRE_COMPR_FL		= 0x00000004, /* Compress file */
	LUSTRE_SYNC_FL		= 0x00000008, /* Synchronous updates */
	LUSTRE_IMMUTABLE_FL	= 0x00000010, /* Immutable file */
	LUSTRE_APPEND_FL	= 0x00000020, /* file writes may only append */
	LUSTRE_NODUMP_FL	= 0x00000040, /* do not dump file */
	LUSTRE_NOATIME_FL	= 0x00000080, /* do not update atime */
	LUSTRE_NOCOMPR_FL	= 0x00000400, /* Don't compress */
	COMPAT_ENCRYPT_FL	= 0x00000800, /* filter out FS_ENCRYPT_FL */
	LUSTRE_INDEX_FL		= 0x00001000, /* hash-indexed directory */
	LUSTRE_EXTENTS_FL	= 0x00080000, /* Inode uses extents */
	LUSTRE_JOURNAL_DATA_FL	= 0x00004000, /* file should be journaled */
	LUSTRE_DIRSYNC_FL	= 0x00010000, /* dirsync behaviour (dir only) */
	LUSTRE_TOPDIR_FL	= 0x00020000, /* Top of directory hierarchies*/
	LUSTRE_VERITY_FL	= 0x00100000, /* Verity protected inode */
	LUSTRE_INLINE_DATA_FL	= 0x10000000, /* Inode has inline data. */
	LUSTRE_PROJINHERIT_FL	= 0x20000000, /* Create with parents projid */
	LUSTRE_CASEFOLD_FL	= 0x40000000, /* Casefolded directory */

	/* These flags will not be identical to any EXT4_*_FL counterparts,
	 * and only reserved for lustre purpose. Note: these flags might
	 * be conflict with some of EXT4 flags, so
	 * 1. these conflict flags needs to be removed when the flag is
	 * wired by la_flags see osd_attr_get().
	 * 2. If these flags needs to be stored into inode, they will be
	 * stored in LMA. see LMAI_XXXX
	 */
	LUSTRE_ORPHAN_FL	= 0x00002000,
	LUSTRE_SET_SYNC_FL	= 0x00040000, /* Synchronous setattr on OSTs */
	LUSTRE_ENCRYPT_FL	= 0x00800000, /* encrypted file */

	LUSTRE_LMA_FL_MASKS	= LUSTRE_ENCRYPT_FL | LUSTRE_ORPHAN_FL,
};

#define LUSTRE_FL_USER_MODIFIABLE (LUSTRE_SYNC_FL	| \
				   LUSTRE_IMMUTABLE_FL	| \
				   LUSTRE_APPEND_FL	| \
				   LUSTRE_NODUMP_FL	| \
				   LUSTRE_NOATIME_FL	| \
				   LUSTRE_NOCOMPR_FL	| \
				   LUSTRE_NOATIME_FL	| \
				   LUSTRE_DIRSYNC_FL	| \
				   LUSTRE_TOPDIR_FL	| \
				   LUSTRE_PROJINHERIT_FL)

#define LUSTRE_FL_USER_VISIBLE (LUSTRE_FL_USER_MODIFIABLE | \
				LUSTRE_UNRM_FL		  | \
				COMPAT_ENCRYPT_FL	  | \
				LUSTRE_COMPR_FL		  | \
				LUSTRE_NOCOMPR_FL	  | \
				LUSTRE_ENCRYPT_FL	  | \
				LUSTRE_INDEX_FL		  | \
				LUSTRE_JOURNAL_DATA_FL    | \
				LUSTRE_EXTENTS_FL	  | \
				LUSTRE_VERITY_FL	  | \
				LUSTRE_INLINE_DATA_FL	  | \
				LUSTRE_CASEFOLD_FL)

#ifndef FS_XFLAG_SYNC
#define FS_XFLAG_SYNC		0x00000020	/* all writes synchronous */
#endif
#ifndef FS_XFLAG_NOATIME
#define FS_XFLAG_NOATIME	0x00000040	/* do not update access time */
#endif
#ifndef FS_XFLAG_IMMUTABLE
#define FS_XFLAG_IMMUTABLE	0x00000008	/* file cannot be modified */
#endif
#ifndef FS_XFLAG_APPEND
#define FS_XFLAG_APPEND		0x00000010	/* all writes append */
#endif
#ifndef FS_XFLAG_PROJINHERIT
#define FS_XFLAG_PROJINHERIT	0x00000200	/* create with parents projid */
#endif

/* 64 possible states */
enum md_transient_state {
	MS_RESTORE	= (1 << 0),	/* restore is running */
};

struct mdt_body {
	struct lu_fid mbo_fid1;
	struct lu_fid mbo_fid2;
	struct lustre_handle mbo_open_handle;
	__u64	mbo_valid;
	__u64	mbo_size; /* Offset, in the case of MDS_READPAGE */
	__s64	mbo_mtime;
	__s64	mbo_atime;
	__s64	mbo_ctime;
	__u64	mbo_blocks; /* XID, in the case of MDS_READPAGE */
	__u64	mbo_version; /* was mbo_ioepoch before 2.11 */
	__u64	mbo_t_state; /* transient file state defined in
			      * enum md_transient_state
			      * was "ino" until 2.4.0
			      */
	__u32	mbo_fsuid;
	__u32	mbo_fsgid;
	__u32	mbo_capability;
	__u32	mbo_mode;
	__u32	mbo_uid;
	__u32	mbo_gid;
	__u32	mbo_flags; /* most replies: LUSTRE_*_FL file attributes,
			    * data_version: OBD_FL_* flags
			    */
	__u32	mbo_rdev;
	__u32	mbo_nlink; /* #bytes to read in the case of MDS_READPAGE */
	__u32	mbo_layout_gen; /* was "generation" until 2.4.0 */
	__u32	mbo_suppgid;
	__u32	mbo_eadatasize;
	__u32	mbo_aclsize;
	__u32	mbo_max_mdsize;
	__u32	mbo_unused3; /* was max_cookiesize until 2.8 */
	__u32	mbo_uid_h; /* high 32-bits of uid, for FUID */
	__u32	mbo_gid_h; /* high 32-bits of gid, for FUID */
	__u32	mbo_projid;
	__u64	mbo_dom_size; /* size of DOM component */
	__u64	mbo_dom_blocks; /* blocks consumed by DOM component */
	__u64	mbo_btime;
	__u64	mbo_padding_9; /* also fix lustre_swab_mdt_body */
	__u64	mbo_padding_10;
}; /* 216 */

struct mdt_ioepoch {
	struct lustre_handle mio_open_handle;
	__u64 mio_unused1; /* was ioepoch */
	__u32 mio_unused2; /* was flags */
	__u32 mio_padding;
};

/* permissions for md_perm.mp_perm */
enum {
	CFS_SETUID_PERM = 0x01,
	CFS_SETGID_PERM = 0x02,
	CFS_SETGRP_PERM = 0x04,
};

struct mdt_rec_setattr {
	__u32           sa_opcode;
	__u32           sa_cap;
	__u32           sa_fsuid;
	__u32           sa_fsuid_h;
	__u32           sa_fsgid;
	__u32           sa_fsgid_h;
	__u32           sa_suppgid;
	__u32           sa_suppgid_h;
	__u32           sa_padding_1;
	__u32           sa_padding_1_h;
	struct lu_fid   sa_fid;
	__u64           sa_valid;
	__u32           sa_uid;
	__u32           sa_gid;
	__u64           sa_size;
	__u64           sa_blocks;
	__s64		sa_mtime;
	__s64		sa_atime;
	__s64		sa_ctime;
	__u32           sa_attr_flags;
	__u32           sa_mode;
	__u32           sa_bias;      /* some operation flags */
	__u32		sa_projid;
	__u32           sa_padding_4;
	__u32           sa_padding_5;
};

/*
 * Attribute flags used in mdt_rec_setattr::sa_valid.
 * The kernel's #defines for ATTR_* should not be used over the network
 * since the client and MDS may run different kernels (see bug 13828)
 * Therefore, we should only use MDS_ATTR_* attributes for sa_valid.
 */
enum mds_attr_flags {
	MDS_ATTR_MODE =		      0x1ULL, /* = 1 */
	MDS_ATTR_UID =		      0x2ULL, /* = 2 */
	MDS_ATTR_GID =		      0x4ULL, /* = 4 */
	MDS_ATTR_SIZE =		      0x8ULL, /* = 8 */
	MDS_ATTR_ATIME =	     0x10ULL, /* = 16 */
	MDS_ATTR_MTIME =	     0x20ULL, /* = 32 */
	MDS_ATTR_CTIME =	     0x40ULL, /* = 64 */
	MDS_ATTR_ATIME_SET =	     0x80ULL, /* = 128 */
	MDS_ATTR_MTIME_SET =	    0x100ULL, /* = 256 */
	MDS_ATTR_FORCE =	    0x200ULL, /* = 512, change it */
	MDS_ATTR_ATTR_FLAG =	    0x400ULL, /* = 1024 */
	MDS_ATTR_KILL_SUID =	    0x800ULL, /* = 2048 */
	MDS_ATTR_KILL_SGID =	   0x1000ULL, /* = 4096 */
	MDS_ATTR_CTIME_SET =	   0x2000ULL, /* = 8192 */
	MDS_ATTR_FROM_OPEN =	   0x4000ULL, /* = 16384, from open O_TRUNC */
	MDS_ATTR_BLOCKS =	   0x8000ULL, /* = 32768 */
	MDS_ATTR_PROJID =	  0x10000ULL, /* = 65536 */
	MDS_ATTR_LSIZE =	  0x20000ULL, /* = 131072 */
	MDS_ATTR_LBLOCKS =	  0x40000ULL, /* = 262144 */
	MDS_ATTR_OVERRIDE =	0x2000000ULL, /* = 33554432 */
};

enum mds_op_bias {
/*	MDS_CHECK_SPLIT		= 1 << 0, obsolete before 2.3.58 */
	/* used for remote object getattr/open by name: in the original
	 * getattr/open request, MDT found the object against name is on another
	 * MDT, then packed FID and LOOKUP lock in reply and returned -EREMOTE,
	 * and client knew it's a remote object, then set this flag in
	 * getattr/open request and sent to the corresponding MDT to finish
	 * getattr/open, which fetched attributes and UPDATE lock/opened file.
	 */
	MDS_CROSS_REF		= 1 << 1,
/*	MDS_VTX_BYPASS		= 1 << 2, obsolete since 2.3.54 */
	MDS_PERM_BYPASS		= 1 << 3,
/*	MDS_SOM			= 1 << 4, obsolete since 2.8.0 */
	MDS_QUOTA_IGNORE	= 1 << 5,
/*	MDS_CLOSE_CLEANUP	= 1 << 6, obsolete since 2.3.51 */
	MDS_KEEP_ORPHAN		= 1 << 7,
	MDS_RECOV_OPEN		= 1 << 8,
	MDS_DATA_MODIFIED	= 1 << 9,
	MDS_CREATE_VOLATILE	= 1 << 10,
	MDS_OWNEROVERRIDE	= 1 << 11,
	MDS_HSM_RELEASE		= 1 << 12,
	MDS_CLOSE_MIGRATE	= 1 << 13,
	MDS_CLOSE_LAYOUT_SWAP	= 1 << 14,
	MDS_CLOSE_LAYOUT_MERGE	= 1 << 15,
	MDS_CLOSE_RESYNC_DONE	= 1 << 16,
	MDS_CLOSE_LAYOUT_SPLIT	= 1 << 17,
	MDS_TRUNC_KEEP_LEASE	= 1 << 18,
	MDS_PCC_ATTACH		= 1 << 19,
	MDS_CLOSE_UPDATE_TIMES	= 1 << 20,
	/* setstripe create only, don't restripe if target exists */
	MDS_SETSTRIPE_CREATE	= 1 << 21,
	MDS_FID_OP		= 1 << 22,
	/* migrate dirent only */
	MDS_MIGRATE_NSONLY	= 1 << 23,
	/* create with default LMV from client */
	MDS_CREATE_DEFAULT_LMV	= 1 << 24,
	/* Compat flag with clients that do not send old and new data version
	 * after swap layout */
	MDS_CLOSE_LAYOUT_SWAP_HSM	= 1 << 25,
};

#define MDS_CLOSE_INTENT (MDS_HSM_RELEASE | MDS_CLOSE_LAYOUT_SWAP |         \
			  MDS_CLOSE_LAYOUT_MERGE | MDS_CLOSE_LAYOUT_SPLIT | \
			  MDS_CLOSE_RESYNC_DONE)

/* instance of mdt_reint_rec */
struct mdt_rec_create {
	__u32		cr_opcode;
	__u32		cr_cap;
	__u32		cr_fsuid;
	__u32		cr_fsuid_h;
	__u32		cr_fsgid;
	__u32		cr_fsgid_h;
	__u32		cr_suppgid1;
	__u32		cr_suppgid1_h;
	__u32		cr_suppgid2;
	__u32		cr_suppgid2_h;
	struct lu_fid	cr_fid1;
	struct lu_fid	cr_fid2;
	struct lustre_handle cr_open_handle_old; /* in case of open replay */
	__s64		cr_time;
	union {
		__u64		cr_rdev;
		__u32		cr_archive_id;
	};
	__u64		cr_ioepoch;
	__u64		cr_padding_1;   /* rr_blocks */
	__u32		cr_mode;
	__u32		cr_bias;
	/* use of helpers set/get_mrc_cr_flags() is needed to access
	 * 64 bits cr_flags [cr_flags_l, cr_flags_h]
	 */
	__u32		cr_flags_l;	/* for use with open, low  32 bits  */
	__u32		cr_flags_h;	/* for use with open, high 32 bits */
	__u32		cr_umask;	/* umask for create */
	__u32		cr_padding_4;   /* rr_padding_4 */
};

/* instance of mdt_reint_rec */
struct mdt_rec_link {
	__u32           lk_opcode;
	__u32           lk_cap;
	__u32           lk_fsuid;
	__u32           lk_fsuid_h;
	__u32           lk_fsgid;
	__u32           lk_fsgid_h;
	__u32           lk_suppgid1;
	__u32           lk_suppgid1_h;
	__u32           lk_suppgid2;
	__u32           lk_suppgid2_h;
	struct lu_fid   lk_fid1;
	struct lu_fid   lk_fid2;
	__s64		lk_time;
	__u64           lk_padding_1;   /* rr_atime */
	__u64           lk_padding_2;   /* rr_ctime */
	__u64           lk_padding_3;   /* rr_size */
	__u64           lk_padding_4;   /* rr_blocks */
	__u32           lk_bias;
	__u32           lk_padding_5;   /* rr_mode */
	__u32           lk_padding_6;   /* rr_flags */
	__u32           lk_padding_7;   /* rr_padding_2 */
	__u32           lk_padding_8;   /* rr_padding_3 */
	__u32           lk_padding_9;   /* rr_padding_4 */
};

/* instance of mdt_reint_rec */
struct mdt_rec_unlink {
	__u32           ul_opcode;
	__u32           ul_cap;
	__u32           ul_fsuid;
	__u32           ul_fsuid_h;
	__u32           ul_fsgid;
	__u32           ul_fsgid_h;
	__u32           ul_suppgid1;
	__u32           ul_suppgid1_h;
	__u32           ul_suppgid2;
	__u32           ul_suppgid2_h;
	struct lu_fid   ul_fid1;
	struct lu_fid   ul_fid2;
	__s64		ul_time;
	__u64           ul_padding_2;   /* rr_atime */
	__u64           ul_padding_3;   /* rr_ctime */
	__u64           ul_padding_4;   /* rr_size */
	__u64           ul_padding_5;   /* rr_blocks */
	__u32           ul_bias;
	__u32           ul_mode;
	__u32           ul_padding_6;   /* rr_flags */
	__u32           ul_padding_7;   /* rr_padding_2 */
	__u32           ul_padding_8;   /* rr_padding_3 */
	__u32           ul_padding_9;   /* rr_padding_4 */
};

/* instance of mdt_reint_rec */
struct mdt_rec_rename {
	__u32           rn_opcode;
	__u32           rn_cap;
	__u32           rn_fsuid;
	__u32           rn_fsuid_h;
	__u32           rn_fsgid;
	__u32           rn_fsgid_h;
	__u32           rn_suppgid1;
	__u32           rn_suppgid1_h;
	__u32           rn_suppgid2;
	__u32           rn_suppgid2_h;
	struct lu_fid   rn_fid1;
	struct lu_fid   rn_fid2;
	__s64		rn_time;
	__u64           rn_padding_1;   /* rr_atime */
	__u64           rn_padding_2;   /* rr_ctime */
	__u64           rn_padding_3;   /* rr_size */
	__u64           rn_padding_4;   /* rr_blocks */
	__u32           rn_bias;        /* some operation flags */
	__u32           rn_mode;        /* cross-ref rename has mode */
	__u32           rn_padding_5;   /* rr_flags */
	__u32           rn_padding_6;   /* rr_padding_2 */
	__u32           rn_padding_7;   /* rr_padding_3 */
	__u32           rn_padding_8;   /* rr_padding_4 */
};

/* instance of mdt_reint_rec */
struct mdt_rec_setxattr {
	__u32           sx_opcode;
	__u32           sx_cap;
	__u32           sx_fsuid;
	__u32           sx_fsuid_h;
	__u32           sx_fsgid;
	__u32           sx_fsgid_h;
	__u32           sx_suppgid1;
	__u32           sx_suppgid1_h;
	__u32           sx_suppgid2;
	__u32           sx_suppgid2_h;
	struct lu_fid   sx_fid;
	__u64           sx_padding_1;   /* These three are rr_fid2 */
	__u32           sx_padding_2;
	__u32           sx_padding_3;
	__u64           sx_valid;
	__s64		sx_time;
	__u64           sx_padding_5;   /* rr_ctime */
	__u64           sx_padding_6;   /* rr_size */
	__u64           sx_padding_7;   /* rr_blocks */
	__u32           sx_size;
	__u32           sx_flags;
	__u32           sx_padding_8;   /* rr_flags */
	__u32           sx_padding_9;   /* rr_padding_2 */
	__u32           sx_padding_10;  /* rr_padding_3 */
	__u32           sx_padding_11;  /* rr_padding_4 */
};

/* instance of mdt_reint_rec. FLR: for file resync MDS_REINT_RESYNC RPC. */
struct mdt_rec_resync {
	__u32           rs_opcode;
	__u32           rs_cap;
	__u32           rs_fsuid;
	__u32           rs_fsuid_h;
	__u32           rs_fsgid;
	__u32           rs_fsgid_h;
	__u32           rs_suppgid1;
	__u32           rs_suppgid1_h;
	__u32           rs_suppgid2;
	__u32           rs_suppgid2_h;
	struct lu_fid   rs_fid;
	__u8		rs_padding0[sizeof(struct lu_fid)];
	struct lustre_handle rs_lease_handle;	/* rr_mtime */
	__s64		rs_padding1;	/* rr_atime */
	__s64		rs_padding2;	/* rr_ctime */
	__u64           rs_padding3;	/* rr_size */
	__u64           rs_padding4;	/* rr_blocks */
	__u32           rs_bias;
	__u32           rs_padding5;	/* rr_mode */
	__u32           rs_padding6;	/* rr_flags */
	__u32           rs_padding7;	/* rr_flags_h */
	/* The rr_mirror_id_old field used the last reserved field
	 * in mdt_rec_reint but is not used for any other reint type.
	 * There are lots of unused fields in this strict that could be
	 * used instead, so rr_umask was chosen for rs_mirror_id_new
	 * since it is unlikely that a file resync operation will ever
	 * need it.  The other unused fields could potentially be needed
	 * eventually (timestamps or size/blocks) so they were not used.
	 */
	__u32           rs_mirror_id_new; /* rr_umask */
	__u16           rs_mirror_id_old; /* deprecated 2.16.0 */
	__u16           rs_padding9;	/* rr_padding_4 */
};

/*
 * mdt_rec_reint is the template for all mdt_reint_xxx structures.
 * Do NOT change the size of various members, otherwise the value
 * will be broken in lustre_swab_mdt_rec_reint().
 *
 * If you add new members in other mdt_reint_xxx structres and need to use the
 * rr_padding_x fields, then update lustre_swab_mdt_rec_reint() also.
 */
struct mdt_rec_reint {
	__u32           rr_opcode;
	__u32           rr_cap;
	__u32           rr_fsuid;
	__u32           rr_fsuid_h;
	__u32           rr_fsgid;
	__u32           rr_fsgid_h;
	__u32           rr_suppgid1;
	__u32           rr_suppgid1_h;
	__u32           rr_suppgid2;
	__u32           rr_suppgid2_h;
	struct lu_fid   rr_fid1;
	struct lu_fid   rr_fid2;
	__s64		rr_mtime;
	__s64		rr_atime;
	__s64		rr_ctime;
	__u64           rr_size;
	__u64           rr_blocks;
	__u32           rr_bias;
	__u32           rr_mode;
	__u32           rr_flags;
	__u32           rr_flags_h;
	__u32           rr_umask;
	__u16		rr_mirror_id_old; /* deprecated 2.16.0 */
	__u16           rr_padding_4; /* also fix lustre_swab_mdt_rec_reint */
};
#define rr_mirror_id_new rr_umask

#define LMV_DESC_QOS_MAXAGE_DEFAULT 60  /* Seconds */

/* lmv structures */
struct lmv_desc {
	__u32 ld_tgt_count;		/* how many MDS's */
	__u32 ld_active_tgt_count;	/* how many active */
	__u32 ld_default_stripe_count;	/* how many objects are used */
	__u32 ld_pattern;		/* default hash pattern */
	__u64 ld_default_hash_size;
	__u64 ld_padding_1;		/* also fix lustre_swab_lmv_desc */
	__u32 ld_padding_2;		/* also fix lustre_swab_lmv_desc */
	__u32 ld_qos_maxage;		/* in second */
	__u32 ld_padding_3;		/* also fix lustre_swab_lmv_desc */
	__u32 ld_padding_4;		/* also fix lustre_swab_lmv_desc */
	struct obd_uuid ld_uuid;
};

/* LMV layout EA, and it will be stored both in master and slave object */
struct lmv_mds_md_v1 {
	__u32 lmv_magic;
	__u32 lmv_stripe_count;
	__u32 lmv_master_mdt_index;	/* On master object, it is master
					 * MDT index, on slave object, it
					 * is stripe index of the slave obj
					 */
	__u32 lmv_hash_type;		/* dir stripe policy, i.e. indicate
					 * which hash function to be used,
					 * Note: only lower 16 bits is being
					 * used for now. Higher 16 bits will
					 * be used to mark the object status,
					 * for example migrating or dead.
					 */
	__u32 lmv_layout_version;	/* increased each time layout changed,
					 * by directory migration, restripe
					 * and LFSCK.
					 */
	__u32 lmv_migrate_offset;	/* once this is set, it means this
					 * directory is been migrated, stripes
					 * before this offset belong to target,
					 * from this to source.
					 */
	__u32 lmv_migrate_hash;		/* hash type of source stripes of
					 * migrating directory
					 */
	__u32 lmv_padding2;
	__u64 lmv_padding3;
	char lmv_pool_name[LOV_MAXPOOLNAME + 1];	/* pool name */
	struct lu_fid lmv_stripe_fids[];	/* FIDs for each stripe */
};

/* stripe count before directory split */
#define lmv_split_offset	lmv_migrate_offset
/* stripe count after directory merge */
#define lmv_merge_offset	lmv_migrate_offset
/* directory hash type after merge */
#define lmv_merge_hash		lmv_migrate_hash

/* foreign LMV EA */
struct lmv_foreign_md {
	__u32 lfm_magic;	/* magic number = LMV_MAGIC_FOREIGN */
	__u32 lfm_length;	/* length of lfm_value */
	__u32 lfm_type;		/* type, see LU_FOREIGN_TYPE_ */
	__u32 lfm_flags;	/* flags, type specific */
	char lfm_value[];	/* free format value */
};

#define LMV_MAGIC_V1	0x0CD20CD0    /* normal stripe lmv magic */
#define LMV_MAGIC	LMV_MAGIC_V1

/* #define LMV_USER_MAGIC 0x0CD30CD0 */
#define LMV_MAGIC_STRIPE 0x0CD40CD0 /* magic for dir sub_stripe */
#define LMV_MAGIC_FOREIGN 0x0CD50CD0 /* magic for lmv foreign */

/**
 * The FNV-1a hash algorithm is as follows:
 *	hash = FNV_offset_basis
 *	for each octet_of_data to be hashed
 *		hash = hash XOR octet_of_data
 *		hash = hash × FNV_prime
 *	return hash
 * http://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function#FNV-1a_hash
 *
 * http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-reference-source
 * FNV_prime is 2^40 + 2^8 + 0xb3 = 0x100000001b3ULL
 **/
#define LUSTRE_FNV_1A_64_PRIME	0x100000001b3ULL
#define LUSTRE_FNV_1A_64_OFFSET_BIAS 0xcbf29ce484222325ULL
static inline __u64 lustre_hash_fnv_1a_64(const void *buf, __kernel_size_t size)
{
	__u64 hash = LUSTRE_FNV_1A_64_OFFSET_BIAS;
	const unsigned char *p = buf;
	__kernel_size_t i;

	for (i = 0; i < size; i++) {
		hash ^= p[i];
		hash *= LUSTRE_FNV_1A_64_PRIME;
	}

	return hash;
}

/* CRUSH placement group count */
#define LMV_CRUSH_PG_COUNT	4096

union lmv_mds_md {
	__u32			 lmv_magic;
	struct lmv_mds_md_v1	 lmv_md_v1;
	struct lmv_user_md	 lmv_user_md;
	struct lmv_foreign_md	 lmv_foreign_md;
};

static inline __kernel_ssize_t lmv_mds_md_size(int stripe_count,
					       unsigned int lmm_magic)
{
	__kernel_ssize_t len = -EINVAL;

	switch (lmm_magic) {
	case LMV_MAGIC_V1: {
		struct lmv_mds_md_v1 *lmm1;

		len = sizeof(*lmm1);
		len += stripe_count * sizeof(lmm1->lmv_stripe_fids[0]);
		break; }
	default:
		break;
	}
	return len;
}

static inline int lmv_mds_md_stripe_count_get(const union lmv_mds_md *lmm)
{
	switch (__le32_to_cpu(lmm->lmv_magic)) {
	case LMV_MAGIC_V1:
		return __le32_to_cpu(lmm->lmv_md_v1.lmv_stripe_count);
	case LMV_USER_MAGIC:
		return __le32_to_cpu(lmm->lmv_user_md.lum_stripe_count);
	default:
		return -EINVAL;
	}
}

static inline int lmv_mds_md_hash_type_get(const union lmv_mds_md *lmm)
{
	switch (__le32_to_cpu(lmm->lmv_magic)) {
	case LMV_MAGIC_V1:
		return __le32_to_cpu(lmm->lmv_md_v1.lmv_hash_type);
	case LMV_USER_MAGIC:
		return __le32_to_cpu(lmm->lmv_user_md.lum_hash_type);
	default:
		return -EINVAL;
	}
}

enum fld_rpc_opc {
	FLD_QUERY	= 900,
	FLD_READ	= 901,
	FLD_LAST_OPC,
	FLD_FIRST_OPC   = FLD_QUERY
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

enum fld_op {
	FLD_CREATE = 0,
	FLD_DELETE = 1,
	FLD_LOOKUP = 2,
};

/* LFSCK opcodes */
enum lfsck_cmd {
	LFSCK_NOTIFY		= 1101,
	LFSCK_QUERY		= 1102,
	LFSCK_LAST_OPC,
	LFSCK_FIRST_OPC		= LFSCK_NOTIFY
};

/*
 *  LOV data structures
 */

#define LOV_MAX_UUID_BUFFER_SIZE  8192
/* The size of the buffer the lov/mdc reserves for the
 * array of UUIDs returned by the MDS.  With the current
 * protocol, this will limit the max number of OSTs per LOV
 */

#define LOV_DESC_MAGIC 0xB0CCDE5C
#define LOV_DESC_QOS_MAXAGE_DEFAULT 5  /* Seconds */
#define LOV_DESC_STRIPE_SIZE_DEFAULT (4 << LNET_MTU_BITS)

/* LOV settings descriptor (should only contain static info) */
struct lov_desc {
	__u32 ld_tgt_count;		/* how many OBD's */
	__u32 ld_active_tgt_count;	/* how many active */
	__s32 ld_default_stripe_count;	/* how many objects are used */
	enum lov_pattern ld_pattern;	/* default LOV_PATTERN_RAID0 */
	__u64 ld_default_stripe_size;	/* in bytes */
	__s64 ld_default_stripe_offset;	/* starting OST index */
	__u32 ld_padding_0;		/* unused */
	__u32 ld_qos_maxage;		/* in second */
	__u32 ld_padding_1;		/* also fix lustre_swab_lov_desc */
	__u32 ld_padding_2;		/* also fix lustre_swab_lov_desc */
	struct obd_uuid ld_uuid;
};

#define ld_magic ld_active_tgt_count       /* for swabbing from llogs */

/*
 *   LDLM requests:
 */
/* opcodes -- MUST be distinct from OST/MDS opcodes */
enum ldlm_cmd {
	LDLM_ENQUEUE     = 101,
	LDLM_CONVERT     = 102,
	LDLM_CANCEL      = 103,
	LDLM_BL_CALLBACK = 104,
	LDLM_CP_CALLBACK = 105,
	LDLM_GL_CALLBACK = 106,
	LDLM_SET_INFO    = 107,
	LDLM_LAST_OPC
};
#define LDLM_FIRST_OPC LDLM_ENQUEUE

#define RES_NAME_SIZE 4
struct ldlm_res_id {
	__u64 name[RES_NAME_SIZE];
};

#define DLDLMRES	"[%#llx:%#llx:%#llx].%#llx"
#define PLDLMRES(res)	(unsigned long long)(res)->lr_name.name[0],	\
			(unsigned long long)(res)->lr_name.name[1],	\
			(unsigned long long)(res)->lr_name.name[2],	\
			(unsigned long long)(res)->lr_name.name[3]

/* lock types */
enum ldlm_mode {
	LCK_MODE_MIN	= 0,
	LCK_EX		= 1,
	LCK_PW		= 2,
	LCK_PR		= 4,
	LCK_CW		= 8,
	LCK_CR		= 16,
	LCK_NL		= 32,
	LCK_GROUP	= 64,
	LCK_COS		= 128,
	LCK_TXN		= 256,
	LCK_MODE_END
};

#define LCK_MINMODE	LCK_MODE_MIN /* deprecated since 2.16.0 */
#define LCK_MAXMODE	LCK_MODE_MAX /* deprecated since 2.16.0 */
#define LCK_MODE_NUM    9

enum ldlm_type {
	LDLM_PLAIN	= 10,
	LDLM_EXTENT	= 11,
	LDLM_FLOCK	= 12,
	LDLM_IBITS	= 13,
	LDLM_TYPE_END,
	LDLM_TYPE_MIN   = LDLM_PLAIN
};

#define LDLM_TYPE_MAX	LDLM_TYPE_END /* deprecated since 2.16.0 */


struct ldlm_extent {
	__u64 start;
	__u64 end;
	__u64 gid;
};

static inline bool ldlm_extent_equal(const struct ldlm_extent *ex1,
				    const struct ldlm_extent *ex2)
{
	return ex1->start == ex2->start && ex1->end == ex2->end;
}

struct ldlm_inodebits {
	enum mds_ibits_locks bits;
	union {
		enum mds_ibits_locks try_bits; /* optional bits to try */
		enum mds_ibits_locks cancel_bits; /* for lock convert */
	};
	__u64 li_gid;
	__u32 li_padding;
	__u32 li_initiator_id; /* index of MDT that initiated this lock */
};

struct ldlm_flock_wire {
	__u64 lfw_start;
	__u64 lfw_end;
	__u64 lfw_owner;
	__u32 lfw_padding;
	__u32 lfw_pid;
};

/* it's important that the fields of the ldlm_extent structure match
 * the first fields of the ldlm_flock structure because there is only
 * one ldlm_swab routine to process the ldlm_policy_data_t union. if
 * this ever changes we will need to swab the union differently based
 * on the resource type.
 */

union ldlm_wire_policy_data {
	struct ldlm_extent	l_extent;
	struct ldlm_flock_wire	l_flock;
	struct ldlm_inodebits	l_inodebits;
};

struct barrier_lvb {
	__u32	lvb_status;
	__u32	lvb_index;
	__u64	lvb_padding;
};

struct ldlm_gl_barrier_desc {
	__u32	lgbd_status;
	__u32	lgbd_timeout;
	__u64	lgbd_padding;
};

union ldlm_gl_desc {
	struct ldlm_gl_lquota_desc	lquota_desc;
	struct ldlm_gl_barrier_desc	barrier_desc;
};

enum ldlm_intent_flags {
	IT_OPEN        = 0x00000001,
	IT_CREAT       = 0x00000002,
	IT_OPEN_CREAT  = IT_OPEN | IT_CREAT, /* To allow case label. */
	IT_READDIR     = 0x00000004, /* Used by mdc, not put on the wire. */
	IT_GETATTR     = 0x00000008,
	IT_LOOKUP      = 0x00000010,
/*	IT_UNLINK      = 0x00000020, Obsolete. */
/*	IT_TRUNC       = 0x00000040, Obsolete. */
	IT_GETXATTR    = 0x00000080,
/*	IT_EXEC        = 0x00000100, Obsolete. */
/*	IT_PIN         = 0x00000200, Obsolete. */
	IT_LAYOUT      = 0x00000400,
	IT_QUOTA_DQACQ = 0x00000800,
	IT_QUOTA_CONN  = 0x00001000,
/*	IT_SETXATTR    = 0x00002000, Obsolete. */
	IT_GLIMPSE     = 0x00004000,
	IT_BRW	       = 0x00008000,
};

struct ldlm_intent {
	__u64 opc;
};

struct ldlm_resource_desc {
	enum ldlm_type	   lr_type;
	__u32		   lr_pad; /* also fix lustre_swab_ldlm_resource_desc */
	struct ldlm_res_id lr_name;
};

struct ldlm_lock_desc {
	struct ldlm_resource_desc	l_resource;
	enum ldlm_mode			l_req_mode;
	enum ldlm_mode			l_granted_mode;
	union ldlm_wire_policy_data	l_policy_data;
};

#define LDLM_LOCKREQ_HANDLES 2
#define LDLM_ENQUEUE_CANCEL_OFF 1

struct ldlm_request {
	__u32			lock_flags; /* LDLM_FL_*,(lustre_dlm_flags.h) */
	__u32			lock_count; /* Num of locks in lock_handle[] */
	struct ldlm_lock_desc	lock_desc;  /* lock descriptor */
	struct lustre_handle	lock_handle[]; /* was LDLM_LOCKREQ_HANDLES */
};

struct ldlm_reply {
	__u32			 lock_flags;
	__u32			 lock_padding; /* fix lustre_swab_ldlm_reply */
	struct ldlm_lock_desc	 lock_desc;
	struct lustre_handle	 lock_handle;
	__u64			 lock_policy_res1;
	__u64			 lock_policy_res2;
};

#define ldlm_flags_to_wire(flags)    ((__u32)(flags))
#define ldlm_flags_from_wire(flags)  ((__u64)(flags))

/*
 * Opcodes for mountconf (mgs and mgc)
 */
enum mgs_cmd {
	MGS_CONNECT	= 250,
	MGS_DISCONNECT	= 251,
	MGS_EXCEPTION	= 252,	/* node died, etc. */
	MGS_TARGET_REG	= 253,	/* whenever target starts up */
	MGS_TARGET_DEL	= 254,
	MGS_SET_INFO	= 255,
	MGS_CONFIG_READ	= 256,
	MGS_LAST_OPC,
	MGS_FIRST_OPC	= MGS_CONNECT
};

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 18, 53, 0)
#define MGS_PARAM_MAXLEN 1024
#define KEY_SET_INFO "set_info"

struct mgs_send_param {
	char		mgs_param[MGS_PARAM_MAXLEN];
};
#endif

/* We pass this info to the MGS so it can write config logs */
#define MTI_NAME_MAXLEN  64
#define MTI_PARAM_MAXLEN 4096
#define MTI_NIDS_MAX     32

struct mgs_target_info {
	__u32		mti_lustre_ver;
	__u32		mti_stripe_index;
	__u32		mti_config_ver;
	__u32		mti_flags;    /* LDD_F_* */
	__u32		mti_nid_count;
	__u32		mti_instance; /* Running instance of target */
	char		mti_fsname[MTI_NAME_MAXLEN];
	char		mti_svname[MTI_NAME_MAXLEN];
	char		mti_uuid[sizeof(struct obd_uuid)];
	__u64		mti_nids[MTI_NIDS_MAX]; /* host nids (lnet_nid_t) */
	char		mti_params[MTI_PARAM_MAXLEN];
	char		mti_nidlist[][LNET_NIDSTR_SIZE];
} __attribute__((packed));

enum mgs_nidlist_flags {
	NIDLIST_APPEND		= 0x00000001, /* append NIDs to nidtable */
	NIDLIST_IN_BULK		= 0x00000002, /* nidlist in bulk */
	NIDLIST_COMPRESSED	= 0x00000004, /* nidlist is compressed */
};

#define MTN_NIDSTR_SIZE LNET_NIDSTR_SIZE
#define NIDLIST_SIZE(count) (MTN_NIDSTR_SIZE * count)

struct mgs_target_nidlist {
	__u32	mtn_flags; /* flags from mgs_nids_info_flags */
	__u32	mtn_nids;  /* amount of nids in list */
	char	mtn_inline_list[][MTN_NIDSTR_SIZE];
} __attribute__((packed));

struct mgs_nidtbl_entry {
	__u64		mne_version;	/* table version of this entry */
	__u32		mne_instance;	/* target instance # */
	__u32		mne_index;	/* target index */
	__u32		mne_length;	/* length of this entry - by bytes */
	__u8		mne_type;	/* target type LDD_F_SV_TYPE_OST/MDT */
	__u8		mne_nid_type;	/* type of NID. for IPv6. */
	__u8		mne_nid_size;	/* size of each NID, by bytes */
	__u8		mne_nid_count;	/* # of NIDs in buffer */
	union {
		DECLARE_FLEX_ARRAY(lnet_nid_t, nids); /* variable size buffer for NIDs. */
		DECLARE_FLEX_ARRAY(struct lnet_nid, nidlist);
	} u;
};

enum mgs_cfg_type {
	MGS_CFG_T_CONFIG	= 0,
	MGS_CFG_T_SPTLRPC	= 1,
	MGS_CFG_T_RECOVER	= 2,
	MGS_CFG_T_PARAMS	= 3,
	MGS_CFG_T_NODEMAP	= 4,
	MGS_CFG_T_BARRIER	= 5,
	MGS_CFG_T_MAX
};

struct mgs_config_body {
	char     mcb_name[MTI_NAME_MAXLEN]; /* logname */
	__u64    mcb_offset;    /* next index of config log to request */
	__u16    mcb_type;      /* type of log: MGS_CFG_T_[CONFIG|RECOVER] */
	union {
		__u8	mcb_nm_cur_pass;  /* mcb_type == MGS_CFG_T_NODEMAP */
		__u8	mcb_rec_nid_size; /* mcb_type == MGS_CFG_T_RECOVER */
	};
	__u8     mcb_bits;      /* bits unit size of config log */
	__u32    mcb_units;     /* # of units for bulk transfer */
};

struct mgs_config_res {
	__u64    mcr_offset;    /* index of last config log */
	union {
		__u64    mcr_size; /* size of the log */
		__u64	 mcr_nm_cur_pass; /* current nodemap config pass */
	};
};

/* Config marker flags (in config log) */
#define CM_START       0x01
#define CM_END         0x02
#define CM_SKIP        0x04
#define CM_UPGRADE146  0x08
#define CM_EXCLUDE     0x10
#define CM_START_SKIP (CM_START | CM_SKIP)

struct cfg_marker {
	__u32	cm_step;       /* aka config version */
	__u32	cm_flags;
	__u32	cm_vers;       /* lustre release version number */
	__u32	cm_padding;    /* 64 bit align */
	__s64	cm_createtime; /*when this record was first created */
	__s64	cm_canceltime; /*when this record is no longer valid*/
	char	cm_tgtname[MTI_NAME_MAXLEN];
	char	cm_comment[MTI_NAME_MAXLEN];
};

/*
 * Opcodes for multiple servers.
 */
enum obd_cmd {
	OBD_PING	= 400,
/*	OBD_LOG_CANCEL	= 401, obsolete since 1.5 */
/*	OBD_QC_CALLBACK	= 402, obsolete since 2.4 */
	OBD_IDX_READ	= 403,
	OBD_LAST_OPC,
	OBD_FIRST_OPC = OBD_PING
};

/**
 * llog contexts indices.
 *
 * There is compatibility problem with indexes below, they are not
 * continuous and must keep their numbers for compatibility needs.
 * See LU-5218 for details.
 */
enum llog_ctxt_id {
	LLOG_CONFIG_ORIG_CTXT  =  0,
	LLOG_CONFIG_REPL_CTXT = 1,
	LLOG_MDS_OST_ORIG_CTXT = 2,
	LLOG_MDS_OST_REPL_CTXT = 3, /* kept just to avoid re-assignment */
	LLOG_SIZE_ORIG_CTXT = 4,
	LLOG_SIZE_REPL_CTXT = 5,
	LLOG_TEST_ORIG_CTXT = 8,
	LLOG_TEST_REPL_CTXT = 9, /* kept just to avoid re-assignment */
	LLOG_CHANGELOG_ORIG_CTXT = 12, /**< changelog generation on mdd */
	LLOG_CHANGELOG_REPL_CTXT = 13, /**< changelog access on clients */
	/* for multiple changelog consumers */
	LLOG_CHANGELOG_USER_ORIG_CTXT = 14,
	LLOG_AGENT_ORIG_CTXT = 15, /**< agent requests generation on cdt */
	LLOG_UPDATELOG_ORIG_CTXT = 16, /* update log. reserve for the client */
	LLOG_UPDATELOG_REPL_CTXT = 17, /* update log. reserve for the client */
	LLOG_MAX_CTXTS
};

/** Identifier for a single log object */
struct llog_logid {
	struct ost_id	lgl_oi;
	__u32		lgl_ogen;
} __attribute__((packed));

/** Records written to the CATALOGS list */
#define CATLIST "CATALOGS"
struct llog_catid {
	struct llog_logid	lci_logid;
	__u32			lci_padding1;
	__u32			lci_padding2;
	__u32			lci_padding3;
} __attribute__((packed));

/* Log data record types - there is no specific reason that these need to
 * be related to the RPC opcodes, but no reason not to (may be handy later?)
 */
#define LLOG_OP_MAGIC 0x10600000
#define LLOG_OP_MASK  0xfff00000

enum llog_op_type {
	LLOG_PAD_MAGIC		= LLOG_OP_MAGIC | 0x00000,
	OST_SZ_REC		= LLOG_OP_MAGIC | 0x00f00,
	/* OST_RAID1_REC	= LLOG_OP_MAGIC | 0x01000, never used */
	MDS_UNLINK_REC		= LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) |
				  REINT_UNLINK, /* obsolete after 2.5.0 */
	MDS_UNLINK64_REC	= LLOG_OP_MAGIC | 0x90000 | (MDS_REINT << 8) |
				  REINT_UNLINK,
	/* MDS_SETATTR_REC	= LLOG_OP_MAGIC | 0x12401, obsolete 1.8.0 */
	MDS_SETATTR64_REC	= LLOG_OP_MAGIC | 0x90000 | (MDS_REINT << 8) |
				  REINT_SETATTR,
	OBD_CFG_REC		= LLOG_OP_MAGIC | 0x20000,
	/* PTL_CFG_REC		= LLOG_OP_MAGIC | 0x30000, obsolete 1.4.0 */
	LLOG_GEN_REC		= LLOG_OP_MAGIC | 0x40000,
	/* LLOG_JOIN_REC	= LLOG_OP_MAGIC | 0x50000, obsolete  1.8.0 */
	CHANGELOG_REC		= LLOG_OP_MAGIC | 0x60000,
	CHANGELOG_USER_REC	= LLOG_OP_MAGIC | 0x70000,
	CHANGELOG_USER_REC2	= LLOG_OP_MAGIC | 0x70002,
	HSM_AGENT_REC		= LLOG_OP_MAGIC | 0x80000,
	UPDATE_REC		= LLOG_OP_MAGIC | 0xa0000, /* Resevered to avoid
							    * use on client.
							    */
	LLOG_HDR_MAGIC		= LLOG_OP_MAGIC | 0x45539,
	LLOG_LOGID_MAGIC	= LLOG_OP_MAGIC | 0x4553b,
};

#define LLOG_REC_HDR_NEEDS_SWABBING(r) \
	(((r)->lrh_type & __swab32(LLOG_OP_MASK)) == __swab32(LLOG_OP_MAGIC))

/** Log record header - stored in little endian order.
 * Each record must start with this struct, end with a llog_rec_tail,
 * and be a multiple of 256 bits in size.
 */
struct llog_rec_hdr {
	__u32	lrh_len;
	__u32	lrh_index;
	__u32	lrh_type;
	__u32	lrh_id;
} __attribute__((packed));

struct llog_rec_tail {
	__u32	lrt_len;
	__u32	lrt_index;
} __attribute__((packed));

static inline struct llog_rec_tail *llog_get_rec_tail(struct llog_rec_hdr *rec)
{
	return (struct llog_rec_tail *)((char *)rec + rec->lrh_len -
					sizeof(struct llog_rec_tail));
}

/* Where data follow just after header */
#define REC_DATA(ptr)						\
	((void *)((char *)ptr + sizeof(struct llog_rec_hdr)))

#define REC_DATA_LEN(rec)					\
	(rec->lrh_len - sizeof(struct llog_rec_hdr) -		\
	 sizeof(struct llog_rec_tail))

#define REC_TAIL(rec)						\
	((struct llog_rec_tail *)((char *)rec + rec->lrh_len -	\
			sizeof(struct llog_rec_tail)))

struct llog_logid_rec {
	struct llog_rec_hdr	lid_hdr;
	struct llog_logid	lid_id;
	__u32			lid_padding1;
	__u64			lid_padding2;
	__u64			lid_padding3;
	struct llog_rec_tail	lid_tail;
} __attribute__((packed));

struct llog_unlink_rec {
	struct llog_rec_hdr	lur_hdr;
	__u64			lur_oid;
	__u32			lur_oseq;
	__u32			lur_count;
	struct llog_rec_tail	lur_tail;
} __attribute__((packed));

struct llog_unlink64_rec {
	struct llog_rec_hdr	lur_hdr;
	struct lu_fid		lur_fid;
	__u32			lur_count; /* to destroy the lost precreated */
	__u32			lur_padding1;
	__u64			lur_padding2;
	__u64			lur_padding3;
	struct llog_rec_tail    lur_tail;
} __attribute__((packed));

struct llog_setattr64_rec {
	struct llog_rec_hdr	lsr_hdr;
	struct ost_id		lsr_oi;
	__u32			lsr_uid;
	__u32			lsr_uid_h;
	__u32			lsr_gid;
	__u32			lsr_gid_h;
	__u64			lsr_valid;
	struct llog_rec_tail    lsr_tail;
} __attribute__((packed));

/* Extended to support project quota */
struct llog_setattr64_rec_v2 {
	struct llog_rec_hdr	lsr_hdr;
	struct ost_id		lsr_oi;
	__u32			lsr_uid;
	__u32			lsr_uid_h;
	__u32			lsr_gid;
	__u32			lsr_gid_h;
	__u64			lsr_valid;
	__u32			lsr_projid;
	__u32			lsr_layout_version;
	__u64			lsr_padding2;
	__u64			lsr_padding3;
	struct llog_rec_tail	lsr_tail;
} __attribute__((packed));

struct llog_size_change_rec {
	struct llog_rec_hdr	lsc_hdr;
	struct ll_fid		lsc_fid;
	__u32			lsc_ioepoch;
	__u32			lsc_padding1;
	__u64			lsc_padding2;
	__u64			lsc_padding3;
	struct llog_rec_tail	lsc_tail;
} __attribute__((packed));

#define CHANGELOG_MAGIC 0xca103000

/** \a changelog_rec_type's that can't be masked */
#define CHANGELOG_MINMASK BIT(CL_MARK)
/** bits covering all \a changelog_rec_type's */
#define CHANGELOG_ALLMASK (BIT(CL_LAST) - 1)
/** default \a changelog_rec_type mask. Allow all of them, except
 * CL_ATIME since it can really be time consuming, and not necessary
 * under normal use.
 * Remove also CL_OPEN, CL_GETXATTR and CL_DN_OPEN from default list as it can
 * be costly and only necessary for audit purpose.
 */
#define CHANGELOG_DEFMASK (CHANGELOG_ALLMASK & \
	~(BIT(CL_ATIME) | BIT(CL_OPEN) | BIT(CL_GETXATTR) | BIT(CL_DN_OPEN)))

/* changelog llog name, needed by client replicators */
#define CHANGELOG_CATALOG "changelog_catalog"

struct changelog_setinfo {
	__u64 cs_recno;
	__u32 cs_id;
} __attribute__((packed));

/** changelog record */
struct llog_changelog_rec {
	struct llog_rec_hdr  cr_hdr;
	struct changelog_rec cr; /**< Variable length field */
	struct llog_rec_tail cr_do_not_use; /**< for_sizeof_only */
} __attribute__((packed));

#define CHANGELOG_USER_PREFIX "cl"
#define CHANGELOG_USER_NAMELEN 16 /* base name including NUL terminator */
#define CHANGELOG_USER_NAMELEN_FULL 30 /* basename plus 'cl$ID-' prefix */

struct llog_changelog_user_rec {
	struct llog_rec_hdr   cur_hdr;
	__u32                 cur_id;
	__u32                 cur_time; /* relative time comparisons only */
	__u64                 cur_endrec;
	struct llog_rec_tail  cur_tail;
} __attribute__((packed));

/* this is twice the size of CHANGELOG_USER_REC */
struct llog_changelog_user_rec2 {
	struct llog_rec_hdr	cur_hdr;
	__u32			cur_id;
	__u32			cur_time; /* relative time comparisons only */
	__u64			cur_endrec;
	__u32			cur_mask;
	__u32			cur_padding1;
	char			cur_name[CHANGELOG_USER_NAMELEN];
	__u64			cur_padding2;
	__u64			cur_padding3;
	struct llog_rec_tail	cur_tail;
} __attribute__((packed));

enum agent_req_status {
	ARS_WAITING,
	ARS_STARTED,
	ARS_FAILED,
	ARS_CANCELED,
	ARS_SUCCEED,
};

static inline const char *agent_req_status2name(enum agent_req_status ars)
{
	switch (ars) {
	case ARS_WAITING:
		return "WAITING";
	case ARS_STARTED:
		return "STARTED";
	case ARS_FAILED:
		return "FAILED";
	case ARS_CANCELED:
		return "CANCELED";
	case ARS_SUCCEED:
		return "SUCCEED";
	default:
		return "UNKNOWN";
	}
}

struct llog_agent_req_rec {
	struct llog_rec_hdr	arr_hdr;	/**< record header */
	__u32			arr_status;	/**< status of the request */
						/* must match enum
						 * agent_req_status
						 */
	__u32			arr_archive_id;	/**< backend archive number */
	__u64			arr_flags;	/**< req flags */
	__u64			arr_compound_id; /** < compound cookie,
						  * ignored
						  */
	__u64			arr_req_create;	/**< req. creation time */
	__u64			arr_req_change;	/**< req. status change time */
	struct hsm_action_item	arr_hai;	/**< req. to the agent */
	struct llog_rec_tail	arr_tail; /**< record tail for_sizezof_only */
} __attribute__((packed));

/* Old llog gen for compatibility */
struct llog_gen {
	__u64 mnt_cnt;
	__u64 conn_cnt;
} __attribute__((packed));

struct llog_gen_rec {
	struct llog_rec_hdr	lgr_hdr;
	struct llog_gen		lgr_gen;
	__u64			padding1;
	__u64			padding2;
	__u64			padding3;
	struct llog_rec_tail	lgr_tail;
};

/* flags for the logs */
enum llog_flag {
	LLOG_F_ZAP_WHEN_EMPTY	= 0x1,
	LLOG_F_IS_CAT		= 0x2,
	LLOG_F_IS_PLAIN		= 0x4,
	LLOG_F_EXT_JOBID	= 0x8,
	LLOG_F_IS_FIXSIZE	= 0x10,
	LLOG_F_EXT_EXTRA_FLAGS  = 0x20,
	LLOG_F_EXT_X_UIDGID	= 0x40,
	LLOG_F_EXT_X_NID	= 0x80,
	LLOG_F_EXT_X_OMODE	= 0x100,
	LLOG_F_EXT_X_XATTR	= 0x200,
	LLOG_F_RM_ON_ERR	= 0x400,
	LLOG_F_MAX_AGE		= 0x800,
	LLOG_F_EXT_X_NID_BE	= 0x1000,
	LLOG_F_UNLCK_SEM	= 0x2000,

	/* Note: Flags covered by LLOG_F_EXT_MASK will be inherited from
	 * catlog to plain log, so do not add LLOG_F_IS_FIXSIZE here,
	 * because the catlog record is usually fixed size, but its plain
	 * log record can be variable
	 */
	LLOG_F_EXT_MASK = LLOG_F_EXT_JOBID | LLOG_F_EXT_EXTRA_FLAGS |
			  LLOG_F_EXT_X_UIDGID | LLOG_F_EXT_X_NID |
			  LLOG_F_EXT_X_OMODE | LLOG_F_EXT_X_XATTR |
			  LLOG_F_EXT_X_NID_BE | LLOG_F_UNLCK_SEM,
};

/* On-disk header structure of each log object, stored in little endian order */
#define LLOG_MIN_CHUNK_SIZE	8192
#define LLOG_HEADER_SIZE        (96) /* sizeof (llog_log_hdr) + sizeof(llh_tail)
				      * - sizeof(llh_bitmap)
				      */
#define LLOG_BITMAP_BYTES       (LLOG_MIN_CHUNK_SIZE - LLOG_HEADER_SIZE)
#define LLOG_MIN_REC_SIZE       (24) /* round(llog_rec_hdr + llog_rec_tail) */

struct llog_log_hdr {
	struct llog_rec_hdr	llh_hdr;
	__s64			llh_timestamp;
	__u32			llh_count;
	__u32			llh_bitmap_offset;
	__u32			llh_size;
	__u32			llh_flags;
	/* for a catalog the first/oldest and still in-use plain slot is just
	 * next to it. It will serve as the upper limit after Catalog has
	 * wrapped around
	 */
	__u32			llh_cat_idx;
	struct obd_uuid		llh_tgtuuid;
	__u32			llh_reserved[LLOG_HEADER_SIZE/sizeof(__u32)-23];
	/* These fields must always be at the end of the llog_log_hdr.
	 * Note: llh_bitmap size is variable because llog chunk size could be
	 * bigger than LLOG_MIN_CHUNK_SIZE, i.e. sizeof(llog_log_hdr) > 8192
	 * bytes, and the real size is stored in llh_hdr.lrh_len, which means
	 * llh_tail should only be refered by LLOG_HDR_TAIL().
	 * But this structure is also used by client/server llog interface
	 * (see llog_client.c), it will be kept in its original way to avoid
	 * compatiblity issue.
	 */
	__u32			llh_bitmap[LLOG_BITMAP_BYTES / sizeof(__u32)];
	struct llog_rec_tail	llh_tail;
} __attribute__((packed));
#undef LLOG_HEADER_SIZE
#undef LLOG_BITMAP_BYTES

#define LLOG_HDR_BITMAP_SIZE(llh)	(__u32)((llh->llh_hdr.lrh_len -	\
					 llh->llh_bitmap_offset -	\
					 sizeof(llh->llh_tail)) * 8)
#define LLOG_HDR_BITMAP(llh)	(__u32 *)((char *)(llh) +		\
					  (llh)->llh_bitmap_offset)
#define LLOG_HDR_TAIL(llh)	((struct llog_rec_tail *)((char *)llh +	\
						 llh->llh_hdr.lrh_len -	\
						 sizeof(llh->llh_tail)))

/* log cookies are used to reference a specific log file and a record therein,
 * and pass record offset from llog_process_thread to llog_write
 */
struct llog_cookie {
	union {
		struct llog_logid	lgc_lgl;
		__u64			lgc_offset;
	};
	__u32				lgc_subsys;
	__u32				lgc_index;
	__u32				lgc_padding;
} __attribute__((packed));

/** llog protocol */
enum llogd_rpc_ops {
	LLOG_ORIGIN_HANDLE_CREATE	= 501,
	LLOG_ORIGIN_HANDLE_NEXT_BLOCK	= 502,
	LLOG_ORIGIN_HANDLE_READ_HEADER	= 503,
/*	LLOG_ORIGIN_HANDLE_WRITE_REC	= 504, Obsolete by 2.1. */
/*	LLOG_ORIGIN_HANDLE_CLOSE	= 505, Obsolete by 1.8. */
/*	LLOG_ORIGIN_CONNECT		= 506, Obsolete by 2.4. */
/*	LLOG_CATINFO			= 507, Obsolete by 2.3. */
	LLOG_ORIGIN_HANDLE_PREV_BLOCK	= 508,
	LLOG_ORIGIN_HANDLE_DESTROY	= 509, /* Obsolete by 2.11. */
	LLOG_LAST_OPC,
	LLOG_FIRST_OPC			= LLOG_ORIGIN_HANDLE_CREATE
};

struct llogd_body {
	struct llog_logid	 lgd_logid;
	__u32			 lgd_ctxt_idx;
	__u32			 lgd_llh_flags;
	__u32			 lgd_index;
	__u32			 lgd_saved_index;
	__u32			 lgd_len;
	__u64			 lgd_cur_offset;
} __attribute__((packed));

struct llogd_conn_body {
	struct llog_gen		lgdc_gen;
	struct llog_logid	lgdc_logid;
	__u32			lgdc_ctxt_idx;
} __attribute__((packed));

/* Note: 64-bit types are 64-bit aligned in structure */
struct obdo {
	__u64			o_valid;	/* hot fields in this obdo */
	struct ost_id		o_oi;
	__u64			o_parent_seq;
	__u64			o_size;		/* o_size-o_blocks == ost_lvb */
	__s64			o_mtime;
	__s64			o_atime;
	__s64			o_ctime;
	__u64			o_blocks;	/* brw: cli sent cached bytes */
	__u64			o_grant;

	/* 32-bit fields start here: keep an even number of them via padding */
	__u32			o_blksize;	/* optimal IO blocksize */
	__u32			o_mode;		/* brw: cli sent cache remain */
	__u32			o_uid;
	__u32			o_gid;
	__u32			o_flags;
	__u32			o_nlink;	/* brw: checksum */
	__u32			o_parent_oid;
	__u32			o_misc;		/* brw: o_dropped */

	__u64			o_ioepoch;	/* epoch in ost writes */
	__u32			o_stripe_idx;	/* holds stripe idx */
	__u32			o_parent_ver;
	struct lustre_handle	o_handle;	/* brw: prolong locks on IO */
	/* Originally, the field is llog_cookie for destroy with unlink cookie
	 * from MDS, it is obsolete in 2.8. Then reuse it by client to transfer
	 * layout and PFL information in IO, setattr RPCs. Since llog_cookie is
	 * not used on wire any longer, remove it from the obdo, then it can be
	 * enlarged freely in the further without affect related RPCs.
	 *
	 * sizeof(ost_layout) + sieof(__u32) == sizeof(llog_cookie).
	 */
	struct ost_layout	o_layout;
	__u32			o_layout_version;
	__u32			o_uid_h;
	__u32			o_gid_h;

	__u64			o_data_version;	/* getattr: sum of iversion for
						 * each stripe.
						 * brw: grant space consumed on
						 * the client for the write
						 */
	__u32			o_projid;
	__u32			o_padding_4;	/* fix lustre_swab_obdo() */
	__u64			o_padding_5;
	__u64			o_padding_6;
};

#define o_dirty   o_blocks
#define o_undirty o_mode
#define o_dropped o_misc
#define o_cksum   o_nlink
#define o_grant_used o_data_version
#define o_falloc_mode o_nlink

struct lfsck_request {
	__u32		lr_event;
	__u32		lr_index;
	__u32		lr_flags;
	__u32		lr_valid;
	union {
		__u32	lr_speed;
		__u32	lr_status;
	};
	__u16		lr_version;
	__u16		lr_active;
	__u16		lr_param;
	__u16		lr_async_windows;
	__u32		lr_flags2;
	struct lu_fid	lr_fid;
	struct lu_fid	lr_fid2;
	__u32		lr_comp_id;
	__u32		lr_padding_0;
	__u64		lr_padding_1;
	__u64		lr_padding_2;
	__u64		lr_padding_3;
};

struct lfsck_reply {
	__u32		lr_status;
	__u32		lr_padding_1;
	__u64		lr_repaired;
};

enum lfsck_events {
	LE_LASTID_REBUILDING	= 1,
	LE_LASTID_REBUILT	= 2,
	LE_PHASE1_DONE		= 3,
	LE_PHASE2_DONE		= 4,
	LE_START		= 5,
	LE_STOP			= 6,
	LE_QUERY		= 7,
	/* LE_FID_ACCESSED	= 8, moved to lfsck_events_local */
	LE_PEER_EXIT		= 9,
	LE_CONDITIONAL_DESTROY	= 10,
	LE_PAIRS_VERIFY		= 11,
	LE_SET_LMV_MASTER	= 15,
	LE_SET_LMV_SLAVE	= 16,
};

enum lfsck_event_flags {
	LEF_TO_OST		= 0x00000001,
	LEF_FROM_OST		= 0x00000002,
	LEF_SET_LMV_HASH	= 0x00000004,
	LEF_SET_LMV_ALL		= 0x00000008,
	LEF_RECHECK_NAME_HASH	= 0x00000010,
	LEF_QUERY_ALL		= 0x00000020,
};

/* request structure for OST's */
struct ost_body {
	struct obdo oa;
};

/* Key for FIEMAP to be used in get_info calls */
struct ll_fiemap_info_key {
	char		lfik_name[8];
	struct obdo	lfik_oa;
	struct fiemap	lfik_fiemap;
};

#define IDX_INFO_MAGIC 0x3D37CC37

/* List of flags used in idx_info::ii_flags */
enum idx_info_flags {
	II_FL_NOHASH	= 1 << 0, /* client doesn't care about hash value */
	II_FL_VARKEY	= 1 << 1, /* keys can be of variable size */
	II_FL_VARREC	= 1 << 2, /* records can be of variable size */
	II_FL_NONUNQ	= 1 << 3, /* index supports non-unique keys */
	II_FL_NOKEY	= 1 << 4, /* client doesn't care about key */
};

/* Index file transfer through the network. The server serializes the index into
 * a byte stream which is sent to the client via a bulk transfer
 */
struct idx_info {
	__u32		ii_magic;

	/* reply: see idx_info_flags below */
	__u32		ii_flags; /* II_FK_* flags */

	/* request & reply: number of lu_idxpage (to be) transferred */
	__u16		ii_count;
	__u16		ii_pad0;

	/* request: requested attributes passed down to the iterator API */
	__u32		ii_attrs;

	/* request & reply: index file identifier (FID) */
	struct lu_fid	ii_fid;

	/* reply: version of the index file before starting to walk the index.
	 * Please note that the version can be modified at any time during the
	 * transfer
	 */
	__u64		ii_version;

	/* request: hash to start with:
	 * reply: hash of the first entry of the first lu_idxpage and hash
	 *        of the entry to read next if any
	 */
	__u64		ii_hash_start;
	__u64		ii_hash_end;

	/* reply: keys size in lu_idxpages, minimal one if II_FL_VARKEY set */
	__u16		ii_keysize;

	/* reply: size of records in lu_idxpages, minimal one if II_FL_VARREC */
	__u16		ii_recsize;

	__u32		ii_pad1;
	__u64		ii_pad2;
	__u64		ii_pad3;
};

#define II_END_OFF	MDS_DIR_END_OFF /* all entries have been read */

#define LIP_MAGIC 0x8A6D6B6C

/* 4KB (= LU_PAGE_SIZE) container gathering key/record pairs */
struct lu_idxpage {
	/* 16-byte header */
	__u32	lip_magic;
	__u16	lip_flags;
	__u16	lip_nr;   /* number of entries in the container */
	__u64	lip_pad0; /* additional padding for future use */

	/* key/record pairs are stored in the remaining 4080 bytes.
	 * depending upon the flags in idx_info::ii_flags, each key/record
	 * pair might be preceded by:
	 * - a hash value
	 * - the key size (II_FL_VARKEY is set)
	 * - the record size (II_FL_VARREC is set)
	 *
	 * For the time being, we only support fixed-size key & record.
	 */
	char	lip_entries[];
};

#define LIP_HDR_SIZE (offsetof(struct lu_idxpage, lip_entries))

/* Gather all possible type associated with a 4KB container */
union lu_page {
	struct lu_dirpage	lp_dir; /* for MDS_READPAGE */
	struct lu_idxpage	lp_idx; /* for OBD_IDX_READ */
	char			lp_array[LU_PAGE_SIZE];
};

/* security opcodes */
enum sec_cmd {
	SEC_CTX_INIT		= 801,
	SEC_CTX_INIT_CONT	= 802,
	SEC_CTX_FINI		= 803,
	SEC_LAST_OPC,
	SEC_FIRST_OPC		 = SEC_CTX_INIT,
};

/** The link ea holds 1 \a link_ea_entry for each hardlink */
#define LINK_EA_MAGIC 0x11EAF1DFUL
struct link_ea_header {
	__u32 leh_magic;
	__u32 leh_reccount;
	__u64 leh_len;	/* total size */
	__u32 leh_overflow_time;
	__u32 leh_padding;
};

/** Hardlink data is name and parent fid.
 * Stored in this crazy struct for maximum packing and endian-neutrality
 */
struct link_ea_entry {
	unsigned char      lee_reclen[2]; /* __u16 big-endian, unaligned */
	unsigned char      lee_parent_fid[sizeof(struct lu_fid)];
	char               lee_name[];
} __attribute__((packed));

/** fid2path request/reply structure */
struct getinfo_fid2path {
	struct lu_fid	gf_fid;
	__u64		gf_recno;
	__u32		gf_linkno;
	__u32		gf_pathlen;
	union {
		DECLARE_FLEX_ARRAY(char, gf_path);
		DECLARE_FLEX_ARRAY(struct lu_fid, gf_root_fid);
	} gf_u;
} __attribute__((packed));

/** path2parent request/reply structures */
struct getparent {
	struct lu_fid	gp_fid;         /**< parent FID */
	__u32		gp_linkno;	/**< hardlink number */
	__u32		gp_name_size;   /**< size of the name field */
	char		gp_name[];      /**< zero-terminated link name */
} __attribute__((packed));

enum layout_intent_opc {
	LAYOUT_INTENT_ACCESS	= 0,	/** generic access */
	LAYOUT_INTENT_READ	= 1,	/** not used */
	LAYOUT_INTENT_WRITE	= 2,	/** write file, for comp layout */
	LAYOUT_INTENT_GLIMPSE	= 3,	/** not used */
	LAYOUT_INTENT_TRUNC	= 4,	/** truncate file, for comp layout */
	LAYOUT_INTENT_RELEASE	= 5,	/** reserved for HSM release */
	LAYOUT_INTENT_RESTORE	= 6,	/** reserved for HSM restore */
	LAYOUT_INTENT_PCCRO_SET	= 7,	/** set read-only layout for PCC */
	LAYOUT_INTENT_PCCRO_CLEAR = 8,	/** clear read-only layout */
	LAYOUT_INTENT_CHANGE    = 9,    /** change layout flag */
};

/**
 * used for lai_flags/lai_values, 32bit field; if a bit is set in lai_flags,
 * and the corresponding bit value in lai_values determines whether that state
 * should be set or cleared.
 */
enum layout_intent_flags {
	LAIF_INCOMPRESSIBLE	= 1U << 0,   /* 0x0001 change compressibility */
};

/* enqueue layout lock with intent */
struct layout_intent {
	__u32 lai_opc;	/* intent operation for enqueue, read, write etc */
	__u32 lai_flags;
	struct lu_extent lai_extent;
} __attribute__((packed));

/**
 * On the wire version of hsm_progress structure.
 *
 * Contains the userspace hsm_progress and some internal fields.
 */
struct hsm_progress_kernel {
	/* Field taken from struct hsm_progress */
	struct lu_fid		hpk_fid;
	__u64			hpk_cookie;
	struct hsm_extent	hpk_extent;
	__u16			hpk_flags;
	__u16			hpk_errval; /* positive val */
	__u32			hpk_padding1;
	/* Additional fields */
	__u64			hpk_data_version;
	__u64			hpk_padding2;
} __attribute__((packed));

/**
 * OUT_UPDATE RPC Format
 *
 * During the cross-ref operation, the Master MDT, which the client send the
 * request to, will disassembly the operation into object updates, then OSP
 * will send these updates to the remote MDT to be executed.
 *
 * An UPDATE_OBJ RPC does a list of updates.  Each update belongs to an
 * operation and does a type of modification to an object.
 *
 * Request Format
 *
 *   update_buf
 *   update (1st)
 *   update (2nd)
 *   ...
 *   update (ub_count-th)
 *
 * ub_count must be less than or equal to UPDATE_PER_RPC_MAX.
 *
 * Reply Format
 *
 *   update_reply
 *   rc [+ buffers] (1st)
 *   rc [+ buffers] (2st)
 *   ...
 *   rc [+ buffers] (nr_count-th)
 *
 * ur_count must be less than or equal to UPDATE_PER_RPC_MAX and should usually
 * be equal to ub_count.
 */

/**
 * Type of each update, if adding/deleting update, please also update
 * update_opcode in lustre/target/out_lib.c.
 */
enum update_type {
	OUT_START		= 0,
	OUT_CREATE		= 1,
	OUT_DESTROY		= 2,
	OUT_REF_ADD		= 3,
	OUT_REF_DEL		= 4,
	OUT_ATTR_SET		= 5,
	OUT_ATTR_GET		= 6,
	OUT_XATTR_SET		= 7,
	OUT_XATTR_GET		= 8,
	OUT_INDEX_LOOKUP	= 9,
	OUT_INDEX_INSERT	= 10,
	OUT_INDEX_DELETE	= 11,
	OUT_WRITE		= 12,
	OUT_XATTR_DEL		= 13,
	OUT_PUNCH		= 14,
	OUT_READ		= 15,
	OUT_NOOP		= 16,
	OUT_XATTR_LIST		= 17,
	OUT_LAST
};

enum update_flag {
	UPDATE_FL_OST		= 0x00000001,	/* op from OST (not MDT) */
	UPDATE_FL_SYNC		= 0x00000002,	/* commit before replying */
	UPDATE_FL_COMMITTED	= 0x00000004,	/* op committed globally */
	UPDATE_FL_NOLOG		= 0x00000008	/* for idempotent updates */
};

struct object_update_param {
	__u16	oup_len;	/* length of this parameter */
	__u16	oup_padding;
	__u32	oup_padding2;
	char	oup_buf[];
} __attribute__((packed));

/* object update */
struct object_update {
	__u16		ou_type;		/* enum update_type */
	__u16		ou_params_count;	/* update parameters count */
	__u32		ou_result_size;		/* how many bytes can return */
	__u32		ou_flags;		/* enum update_flag */
	__u32		ou_padding1;		/* padding 1 */
	__u64		ou_batchid;		/* op transno on master */
	struct lu_fid	ou_fid;			/* object to be updated */
	struct object_update_param ou_params[]; /* update params */
};

#define	UPDATE_REQUEST_MAGIC_V1	0xBDDE0001
#define	UPDATE_REQUEST_MAGIC_V2	0xBDDE0002
#define	UPDATE_REQUEST_MAGIC	UPDATE_REQUEST_MAGIC_V2
/* Hold object_updates sending to the remote OUT in single RPC */
struct object_update_request {
	__u32			ourq_magic;
	__u16			ourq_count;	/* number of ourq_updates[] */
	__u16			ourq_padding;
	struct object_update	ourq_updates[];
};

#define OUT_UPDATE_HEADER_MAGIC		0xBDDF0001
#define OUT_UPDATE_MAX_INLINE_SIZE	4096
/* Header for updates request between MDTs */
struct out_update_header {
	__u32		ouh_magic;
	__u32		ouh_count;
	__u32		ouh_inline_length;
	__u32		ouh_reply_size;
	__u32		ouh_inline_data[];
};

struct out_update_buffer {
	__u32	oub_size;
	__u32	oub_padding;
};

/* the result of object update */
struct object_update_result {
	__u32   our_rc;
	__u16   our_datalen;
	__u16   our_padding;
	__u32   our_data[];
};

#define UPDATE_REPLY_MAGIC_V1	0x00BD0001
#define UPDATE_REPLY_MAGIC_V2	0x00BD0002
#define UPDATE_REPLY_MAGIC	UPDATE_REPLY_MAGIC_V2
/* Hold object_update_results being replied from the remote OUT. */
struct object_update_reply {
	__u32	ourp_magic;
	__u16	ourp_count;
	__u16	ourp_padding;
	__u16	ourp_lens[];
};

/* read update result */
struct out_read_reply {
	__u32	orr_size;
	__u32	orr_padding;
	__u64	orr_offset;
	char	orr_data[];
};

#define BUT_REQUEST_MAGIC	0xBADE0001
/* Hold batched updates sending to the remote target in a single RPC */
struct batch_update_request {
	/* Magic number: BUT_REQUEST_MAGIC. */
	__u32			burq_magic;
	/* Number of sub requests packed in this batched RPC: burq_reqmsg[]. */
	__u16			burq_count;
	/* Unused padding field. */
	__u16			burq_padding;
	/*
	 * Sub request message array. As message feild buffers for each sub
	 * request are packed after padded lustre_msg.lm_buflens[] arrary, thus
	 * it can locate the next request message via the function
	 * @batch_update_reqmsg_next() in lustre/include/obj_update.h
	 */
	struct lustre_msg	burq_reqmsg[];
};

#define BUT_HEADER_MAGIC	0xBADF0001
/* Header for Batched UpdaTes request */
struct but_update_header {
	/* Magic number: BUT_HEADER_MAGIC */
	__u32	buh_magic;
	/*
	 * When the total request buffer length is less than MAX_INLINE_SIZE,
	 * @buh_count is set with 1 and the batched RPC reqeust can be packed
	 * inline.
	 * Otherwise, @buh_count indicates the IO vector count transferring in
	 * bulk I/O.
	 */
	__u32	buh_count;
	/* inline buffer length when the batched RPC can be packed inline. */
	__u32	buh_inline_length;
	/* The reply buffer size the client prepared. */
	__u32	buh_reply_size;
	/* Sub request count in this batched RPC. */
	__u32	buh_update_count;
	/* Unused padding field. */
	__u32	buh_padding;
	/* Inline buffer used when the RPC request can be packed inline. */
	__u32	buh_inline_data[];
};

struct but_update_buffer {
	__u32	bub_size;
	__u32	bub_padding;
};

#define BUT_REPLY_MAGIC	0x00AD0001
/* Batched reply received from a remote targer in a batched RPC. */
struct batch_update_reply {
	/* Magic number: BUT_REPLY_MAGIC. */
	__u32			burp_magic;
	/* Successful returned sub requests. */
	__u16			burp_count;
	/* Unused padding field. */
	__u16			burp_padding;
	/*
	 * Sub reply message array.
	 * It can locate the next reply message buffer via the function
	 * @batch_update_repmsg_next() in lustre/include/obj_update.h
	 */
	struct lustre_msg	burp_repmsg[];
};

/**
 * Batch update opcode.
 */
enum batch_update_cmd {
	BUT_GETATTR	= 1,
	BUT_LAST_OPC,
	BUT_FIRST_OPC	= BUT_GETATTR,
};

/** layout swap request structure
 * fid1 and fid2 are in mdt_body
 */
struct mdc_swap_layouts {
	__u64           msl_flags;
} __attribute__((packed));

#define INLINE_RESYNC_ARRAY_SIZE	15
struct close_data_resync_done {
	__u32	resync_count;
	__u32	resync_ids_inline[INLINE_RESYNC_ARRAY_SIZE];
};

struct close_data {
	struct lustre_handle	cd_handle;
	struct lu_fid		cd_fid;
	__u64			cd_data_version;
	union {
		__u64				cd_reserved[8];
		struct close_data_resync_done	cd_resync;
		/* split close */
		__u16				cd_mirror_id;
		/* PCC release */
		__u32				cd_archive_id;
		/* migrate swap layout */
		__u64				cd_data_version2;
	};
};

/* Update llog format */
struct update_op {
	struct lu_fid	uop_fid;
	__u16		uop_type;
	__u16		uop_param_count;
	__u16		uop_params_off[];
} __attribute__((packed));

struct update_ops {
	DECLARE_FLEX_ARRAY(struct update_op, uops_op);
};

struct update_params {
	DECLARE_FLEX_ARRAY(struct object_update_param, up_params);
};

enum update_records_flag {
	UPDATE_RECORD_CONTINUE = 1 >> 0,
};
/*
 * This is the update record format used to store the updates in
 * disk. All updates of the operation will be stored in ur_ops.
 * All of parameters for updates of the operation will be stored
 * in ur_params.
 * To save the space of the record, parameters in ur_ops will only
 * remember their offset in ur_params, so to avoid storing duplicate
 * parameters in ur_params, which can help us save a lot space for
 * operation like creating striped directory.
 */
struct update_records {
	__u64			ur_master_transno;
	__u64			ur_batchid;
	__u32			ur_flags;
	/* If the operation includes multiple updates, then ur_index
	 * means the index of the update inside the whole updates.
	 */
	__u32			ur_index;
	__u32			ur_update_count;
	__u32			ur_param_count;
	struct update_ops	ur_ops;
	 /* Note ur_ops has a variable size, so comment out
	  * the following ur_params, in case some use it directly
	  * update_records->ur_params
	  *
	  * struct update_params	ur_params;
	  */
};

struct llog_update_record {
	struct llog_rec_hdr     lur_hdr;
	struct update_records   lur_update_rec;
	/* Note ur_update_rec has a variable size, so comment out
	 * the following ur_tail, in case someone use it directly
	 *
	 * struct llog_rec_tail lur_tail;
	 */
};

/* sepol string format is:
 * <1-digit for SELinux status>:<policy name>:<policy version>:<policy hash>
 */
/* Max length of the sepol string
 * Should be large enough to contain a sha512sum of the policy
 */
#define SELINUX_MODE_LEN 1
#define SELINUX_POLICY_VER_LEN 3 /* 3 chars to leave room for the future */
#define SELINUX_POLICY_HASH_LEN 64
#define LUSTRE_NODEMAP_SEPOL_LENGTH (SELINUX_MODE_LEN + NAME_MAX + \
				     SELINUX_POLICY_VER_LEN + \
				     SELINUX_POLICY_HASH_LEN + 3)

/** enums containing the types of ids contained in a nodemap
 * kept so other modules (mgs, mdt, etc) can define the type
 * of search easily
 */
enum nodemap_id_type {
	NODEMAP_UID		= 0,
	NODEMAP_GID		= 1,
	NODEMAP_PROJID		= 2,
};

enum nodemap_tree_type {
	NODEMAP_FS_TO_CLIENT	= 0,
	NODEMAP_CLIENT_TO_FS	= 1,
};

enum nodemap_mapping_modes {
	NODEMAP_MAP_BOTH_LEGACY	= 0x0,  /* for compatibility */
	NODEMAP_MAP_UID		= 0x01,
	NODEMAP_MAP_GID		= 0x02,
	NODEMAP_MAP_BOTH	= 0x03, /* for compatibility */
	NODEMAP_MAP_PROJID	= 0x04,
	NODEMAP_MAP_ALL		= NODEMAP_MAP_UID |
				  NODEMAP_MAP_GID |
				  NODEMAP_MAP_PROJID,
};

enum nodemap_rbac_roles {
	NODEMAP_RBAC_FILE_PERMS		= 0x00000001,
	NODEMAP_RBAC_DNE_OPS		= 0x00000002,
	NODEMAP_RBAC_QUOTA_OPS		= 0x00000004,
	NODEMAP_RBAC_BYFID_OPS		= 0x00000008,
	NODEMAP_RBAC_CHLG_OPS		= 0x00000010,
	NODEMAP_RBAC_FSCRYPT_ADMIN	= 0x00000020,
	NODEMAP_RBAC_SERVER_UPCALL	= 0x00000040,
	NODEMAP_RBAC_IGN_ROOT_PRJQUOTA	= 0x00000080,
	NODEMAP_RBAC_HSM_OPS		= 0x00000100,
	NODEMAP_RBAC_LOCAL_ADMIN	= 0x00000200,
	NODEMAP_RBAC_NONE	= (__u32)~(NODEMAP_RBAC_FILE_PERMS	|
					   NODEMAP_RBAC_DNE_OPS	|
					   NODEMAP_RBAC_QUOTA_OPS	|
					   NODEMAP_RBAC_BYFID_OPS	|
					   NODEMAP_RBAC_CHLG_OPS	|
					   NODEMAP_RBAC_FSCRYPT_ADMIN	|
					   NODEMAP_RBAC_SERVER_UPCALL	|
					   NODEMAP_RBAC_IGN_ROOT_PRJQUOTA |
					   NODEMAP_RBAC_HSM_OPS		|
					   NODEMAP_RBAC_LOCAL_ADMIN),
	NODEMAP_RBAC_ALL	= 0xFFFFFFFF, /* future caps ON by default */
};

enum nodemap_raise_privs {
	NODEMAP_RAISE_PRIV_RAISE	= 0x00000001,
	NODEMAP_RAISE_PRIV_ADMIN	= 0x00000002,
	NODEMAP_RAISE_PRIV_TRUSTED	= 0x00000004,
	NODEMAP_RAISE_PRIV_DENY_UNKN	= 0x00000008,
	NODEMAP_RAISE_PRIV_RO		= 0x00000010,
	NODEMAP_RAISE_PRIV_RBAC		= 0x00000020,
	NODEMAP_RAISE_PRIV_FORBID_ENC	= 0x00000040,
	NODEMAP_RAISE_PRIV_CAPS		= 0x00000080,
	NODEMAP_RAISE_PRIV_NONE	= (__u32)~(NODEMAP_RAISE_PRIV_RAISE	|
					   NODEMAP_RAISE_PRIV_ADMIN	|
					   NODEMAP_RAISE_PRIV_TRUSTED	|
					   NODEMAP_RAISE_PRIV_DENY_UNKN	|
					   NODEMAP_RAISE_PRIV_RO	|
					   NODEMAP_RAISE_PRIV_RBAC	|
					   NODEMAP_RAISE_PRIV_FORBID_ENC|
					   NODEMAP_RAISE_PRIV_CAPS),
	NODEMAP_RAISE_PRIV_ALL	= 0xFFFFFFFF, /* future privs RAISED by def */
};

enum nodemap_cap_type {
	NODEMAP_CAP_OFF		= 0,
	NODEMAP_CAP_MASK	= 1,
	NODEMAP_CAP_SET		= 2,
};


/*
 * rawobj stuff for GSS
 */
typedef struct netobj_s {
	__u32 len;
	__u8 data[];
} netobj_t;

typedef struct rawobj_s {
	__u32 len;
	__u8 *data;
} rawobj_t;

/*
 * GSS headers
 * following 3 headers must have the same sizes and offsets
 */
struct gss_header {
	__u8 gh_version;     /* gss version */
	__u8 gh_sp;          /* sec part */
	__u16 gh_pad0;
	__u32 gh_flags;       /* wrap flags */
	__u32 gh_proc;        /* proc */
	__u32 gh_seq;         /* sequence */
	__u32 gh_svc;         /* service */
	__u32 gh_pad1;
	__u32 gh_pad2;
	__u32 gh_pad3;
	netobj_t gh_handle;      /* context handle */
};

struct gss_rep_header {
	__u8 gh_version;
	__u8 gh_sp;
	__u16 gh_pad0;
	__u32 gh_flags;
	__u32 gh_proc;
	__u32 gh_major;
	__u32 gh_minor;
	__u32 gh_seqwin;
	__u32 gh_pad2;
	__u32 gh_pad3;
	netobj_t gh_handle;
};

struct gss_err_header {
	__u8 gh_version;
	__u8 gh_sp;
	__u16 gh_pad0;
	__u32 gh_flags;
	__u32 gh_proc;
	__u32 gh_major;
	__u32 gh_minor;
	__u32 gh_pad1;
	__u32 gh_pad2;
	__u32 gh_pad3;
	netobj_t gh_handle;
};

/*
 * GSS part of wire context information sent from client, saved and
 * used later by server.
 */
struct gss_wire_ctx {
	__u32 gw_flags;
	__u32 gw_proc;
	__u32 gw_seq;
	__u32 gw_svc;
	rawobj_t gw_handle;
};

/* This is the lu_ladvise struct which goes out on the wire.
 * Corresponds to the userspace arg llapi_lu_ladvise.
 * value[1-4] are unspecified fields, used differently by different advices
 */
struct lu_ladvise {
	__u16 lla_advice;	/* advice type */
	__u16 lla_value1;	/* values for different advice types */
	__u32 lla_value2;
	__u64 lla_start;	/* first byte of extent for advice */
	__u64 lla_end;		/* last byte of extent for advice */
	__u32 lla_value3;
	__u32 lla_value4;
};

/* This is the ladvise_hdr which goes on the wire, corresponds to the userspace
 * arg llapi_ladvise_hdr.
 * value[1-3] are unspecified fields, used differently by different advices
 */
struct ladvise_hdr {
	__u32			lah_magic;	/* LADVISE_MAGIC */
	__u32			lah_count;	/* number of advices */
	__u64			lah_flags;	/* from enum ladvise_flag */
	__u32			lah_value1;	/* unused */
	__u32			lah_value2;	/* unused */
	__u64			lah_value3;	/* unused */
	struct lu_ladvise	lah_advise[];	/* advices in this header */
};

#if defined(__cplusplus)
}
#endif

#endif
/** @} lustreidl */
