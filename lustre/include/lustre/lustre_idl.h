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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre/lustre_idl.h
 *
 * Lustre wire protocol definitions.
 */

/** \defgroup lustreidl lustreidl
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
 *
 * @{
 */

#ifndef _LUSTRE_IDL_H_
#define _LUSTRE_IDL_H_

#include <libcfs/libcfs.h> /* for LASSERT, LPUX64, etc */

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

/* Portal 63 is reserved for the Cray Inc DVS - nic@cray.com, roe@cray.com, n8851@cray.com */

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

typedef __u32 mdsno_t;
typedef __u64 seqno_t;
typedef __u64 obd_id;
typedef __u64 obd_seq;
typedef __s64 obd_time;
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

/**
 * Describes a range of sequence, lsr_start is included but lsr_end is
 * not in the range.
 * Same structure is used in fld module where lsr_index field holds mdt id
 * of the home mdt.
 */

#define LU_SEQ_RANGE_MDT        0x0
#define LU_SEQ_RANGE_OST        0x1

struct lu_seq_range {
        __u64 lsr_start;
        __u64 lsr_end;
        __u32 lsr_index;
        __u32 lsr_flags;
};

/**
 * returns  width of given range \a r
 */

static inline __u64 range_space(const struct lu_seq_range *range)
{
        return range->lsr_end - range->lsr_start;
}

/**
 * initialize range to zero
 */

static inline void range_init(struct lu_seq_range *range)
{
        range->lsr_start = range->lsr_end = range->lsr_index = 0;
}

/**
 * check if given seq id \a s is within given range \a r
 */

static inline int range_within(const struct lu_seq_range *range,
                               __u64 s)
{
        return s >= range->lsr_start && s < range->lsr_end;
}

static inline int range_is_sane(const struct lu_seq_range *range)
{
        return (range->lsr_end >= range->lsr_start);
}

static inline int range_is_zero(const struct lu_seq_range *range)
{
        return (range->lsr_start == 0 && range->lsr_end == 0);
}

static inline int range_is_exhausted(const struct lu_seq_range *range)

{
        return range_space(range) == 0;
}

/* return 0 if two range have the same location */
static inline int range_compare_loc(const struct lu_seq_range *r1,
                                    const struct lu_seq_range *r2)
{
        return r1->lsr_index != r2->lsr_index ||
               r1->lsr_flags != r2->lsr_flags;
}

#define DRANGE "[%#16.16"LPF64"x-%#16.16"LPF64"x):%x:%x"

#define PRANGE(range)      \
        (range)->lsr_start, \
        (range)->lsr_end,    \
        (range)->lsr_index,  \
        (range)->lsr_flags

/** \defgroup lu_fid lu_fid
 * @{ */

/**
 * Flags for lustre_mdt_attrs::lma_compat and lustre_mdt_attrs::lma_incompat.
 */
enum lma_compat {
        LMAC_HSM = 0x00000001,
        LMAC_SOM = 0x00000002,
};

/**
 * Masks for all features that should be supported by a Lustre version to
 * access a specific file.
 * This information is stored in lustre_mdt_attrs::lma_incompat.
 *
 * NOTE: No incompat feature should be added before bug #17670 is landed.
 */
#define LMA_INCOMPAT_SUPP 0x0

/**
 * Following struct for MDT attributes, that will be kept inode's EA.
 * Introduced in 2.0 release (please see b15993, for details)
 */
struct lustre_mdt_attrs {
        /**
         * Bitfield for supported data in this structure. From enum lma_compat.
         * lma_self_fid and lma_flags are always available.
         */
        __u32   lma_compat;
        /**
         * Per-file incompat feature list. Lustre version should support all
         * flags set in this field. The supported feature mask is available in
         * LMA_INCOMPAT_SUPP.
         */
        __u32   lma_incompat;
        /** FID of this inode */
        struct lu_fid  lma_self_fid;
        /** mdt/ost type, others */
        __u64   lma_flags;
        /* IO Epoch SOM attributes belongs to */
        __u64   lma_ioepoch;
        /** total file size in objects */
        __u64   lma_som_size;
        /** total fs blocks in objects */
        __u64   lma_som_blocks;
        /** mds mount id the size is valid for */
        __u64   lma_som_mountid;
};

/**
 * Fill \a lma with its first content.
 * Only fid is stored.
 */
static inline void lustre_lma_init(struct lustre_mdt_attrs *lma,
                                   const struct lu_fid *fid)
{
        lma->lma_compat      = 0;
        lma->lma_incompat    = 0;
        memcpy(&lma->lma_self_fid, fid, sizeof(*fid));
        lma->lma_flags       = 0;
        lma->lma_ioepoch     = 0;
        lma->lma_som_size    = 0;
        lma->lma_som_blocks  = 0;
        lma->lma_som_mountid = 0;

        /* If a field is added in struct lustre_mdt_attrs, zero it explicitly
         * and change the test below. */
        LASSERT(sizeof(*lma) ==
                (offsetof(struct lustre_mdt_attrs, lma_som_mountid) +
                 sizeof(lma->lma_som_mountid)));
};

extern void lustre_swab_lu_fid(struct lu_fid *fid);

/**
 * Swab, if needed, lustre_mdt_attr struct to on-disk format.
 * Otherwise, do not touch it.
 */
static inline void lustre_lma_swab(struct lustre_mdt_attrs *lma)
{
        /* Use LUSTRE_MSG_MAGIC to detect local endianess. */
        if (LUSTRE_MSG_MAGIC != cpu_to_le32(LUSTRE_MSG_MAGIC)) {
                __swab32s(&lma->lma_compat);
                __swab32s(&lma->lma_incompat);
                lustre_swab_lu_fid(&lma->lma_self_fid);
                __swab64s(&lma->lma_flags);
                __swab64s(&lma->lma_ioepoch);
                __swab64s(&lma->lma_som_size);
                __swab64s(&lma->lma_som_blocks);
                __swab64s(&lma->lma_som_mountid);
        }
};

/* This is the maximum number of MDTs allowed in CMD testing until such
 * a time that FID-on-OST is implemented.  This is due to the limitations
 * of packing non-0-MDT numbers into the FID SEQ namespace.  Once FID-on-OST
 * is implemented this limit will be virtually unlimited. */
#define MAX_MDT_COUNT 8


/**
 * fid constants
 */
enum {
        /** initial fid id value */
        LUSTRE_FID_INIT_OID  = 1UL
};

/** returns fid object sequence */
static inline __u64 fid_seq(const struct lu_fid *fid)
{
        return fid->f_seq;
}

/** returns fid object id */
static inline __u32 fid_oid(const struct lu_fid *fid)
{
        return fid->f_oid;
}

/** returns fid object version */
static inline __u32 fid_ver(const struct lu_fid *fid)
{
        return fid->f_ver;
}

static inline void fid_zero(struct lu_fid *fid)
{
        memset(fid, 0, sizeof(*fid));
}

static inline obd_id fid_ver_oid(const struct lu_fid *fid)
{
        return ((__u64)fid_ver(fid) << 32 | fid_oid(fid));
}

/**
 * Note that reserved SEQ numbers below 12 will conflict with ldiskfs
 * inodes in the IGIF namespace, so these reserved SEQ numbers can be
 * used for other purposes and not risk collisions with existing inodes.
 *
 * Different FID Format
 * http://arch.lustre.org/index.php?title=Interoperability_fids_zfs#NEW.0
 */
enum fid_seq {
        FID_SEQ_OST_MDT0   = 0,
        FID_SEQ_LLOG       = 1,
        FID_SEQ_ECHO       = 2,
        FID_SEQ_OST_MDT1   = 3,
        FID_SEQ_OST_MAX    = 9, /* Max MDT count before OST_on_FID */
        FID_SEQ_RSVD       = 11,
        FID_SEQ_IGIF       = 12,
        FID_SEQ_IGIF_MAX   = 0x0ffffffffULL,
        FID_SEQ_IDIF       = 0x100000000ULL,
        FID_SEQ_IDIF_MAX   = 0x1ffffffffULL,
        /* Normal FID sequence starts from this value, i.e. 1<<33 */
        FID_SEQ_START      = 0x200000000ULL,
        FID_SEQ_LOCAL_FILE = 0x200000001ULL,
        FID_SEQ_DOT_LUSTRE = 0x200000002ULL,
        FID_SEQ_NORMAL     = 0x200000400ULL
};

#define OBIF_OID_MAX_BITS           32
#define OBIF_MAX_OID                (1ULL << OBIF_OID_MAX_BITS)
#define OBIF_OID_MASK               ((1ULL << OBIF_OID_MAX_BITS) - 1)
#define IDIF_OID_MAX_BITS           48
#define IDIF_MAX_OID                (1ULL << IDIF_OID_MAX_BITS)
#define IDIF_OID_MASK               ((1ULL << IDIF_OID_MAX_BITS) - 1)


static inline int fid_seq_is_mdt0(obd_seq seq)
{
        return (seq == FID_SEQ_OST_MDT0);
}

static inline int fid_seq_is_cmd(const __u64 seq)
{
        return (seq >= FID_SEQ_OST_MDT1 && seq <= FID_SEQ_OST_MAX);
};

static inline int fid_seq_is_mdt(const __u64 seq)
{
        return seq == FID_SEQ_OST_MDT0 ||
               (seq >= FID_SEQ_OST_MDT1 && seq <= FID_SEQ_OST_MAX);
};

static inline int fid_seq_is_rsvd(const __u64 seq)
{
        return seq <= FID_SEQ_RSVD;
};

static inline int fid_is_mdt0(const struct lu_fid *fid)
{
        return fid_seq_is_mdt0(fid_seq(fid));
}

/**
 * Check if a fid is igif or not.
 * \param fid the fid to be tested.
 * \return true if the fid is a igif; otherwise false.
 */
static inline int fid_seq_is_igif(const __u64 seq)
{
        return seq >= FID_SEQ_IGIF && seq <= FID_SEQ_IGIF_MAX;
}

static inline int fid_is_igif(const struct lu_fid *fid)
{
        return fid_seq_is_igif(fid_seq(fid));
}

/**
 * Check if a fid is idif or not.
 * \param fid the fid to be tested.
 * \return true if the fid is a idif; otherwise false.
 */
static inline int fid_seq_is_idif(const __u64 seq)
{
        return seq >= FID_SEQ_IDIF && seq <= FID_SEQ_IDIF_MAX;
}

static inline int fid_is_idif(const struct lu_fid *fid)
{
        return fid_seq_is_idif(fid_seq(fid));
}

struct ost_id {
        obd_id                 oi_id;
        obd_seq                oi_seq;
};

static inline int fid_seq_is_norm(const __u64 seq)
{
        return (seq >= FID_SEQ_NORMAL);
}

static inline int fid_is_norm(const struct lu_fid *fid)
{
        return fid_seq_is_norm(fid_seq(fid));
}

/* convert an OST objid into an IDIF FID SEQ number */
static inline obd_seq fid_idif_seq(obd_id id, __u32 ost_idx)
{
        return FID_SEQ_IDIF | (ost_idx << 16) | ((id >> 32) & 0xffff);
}

/* convert a packed IDIF FID into an OST objid */
static inline obd_id fid_idif_id(obd_seq seq, __u32 oid, __u32 ver)
{
        return ((__u64)ver << 48) | ((seq & 0xffff) << 32) | oid;
}

/* unpack an ostid (id/seq) from a wire/disk structure into an IDIF FID */
static inline void ostid_idif_unpack(struct ost_id *ostid,
                                     struct lu_fid *fid, __u32 ost_idx)
{
        fid->f_seq = fid_idif_seq(ostid->oi_id, ost_idx);
        fid->f_oid = ostid->oi_id;       /* truncate to 32 bits by assignment */
        fid->f_ver = ostid->oi_id >> 48; /* in theory, not currently used */
}

/* unpack an ostid (id/seq) from a wire/disk structure into a non-IDIF FID */
static inline void ostid_fid_unpack(struct ost_id *ostid, struct lu_fid *fid)
{
        fid->f_seq = ostid->oi_seq;
        fid->f_oid = ostid->oi_id;       /* truncate to 32 bits by assignment */
        fid->f_ver = ostid->oi_id >> 32; /* in theory, not currently used */
}

/* Unpack an OST object id/seq (group) into a FID.  This is needed for
 * converting all obdo, lmm, lsm, etc. 64-bit id/seq pairs into proper
 * FIDs.  Note that if an id/seq is already in FID/IDIF format it will
 * be passed through unchanged.  Only legacy OST objects in "group 0"
 * will be mapped into the IDIF namespace so that they can fit into the
 * struct lu_fid fields without loss.  For reference see:
 * http://arch.lustre.org/index.php?title=Interoperability_fids_zfs
 */
static inline int fid_ostid_unpack(struct lu_fid *fid, struct ost_id *ostid,
                                   __u32 ost_idx)
{
        if (ost_idx > 0xffff) {
                CERROR("bad ost_idx, seq:"LPU64" id:"LPU64" ost_idx:%u\n",
                       ostid->oi_seq, ostid->oi_id, ost_idx);
                return -EBADF;
        }

        if (fid_seq_is_mdt0(ostid->oi_seq)) {
                /* This is a "legacy" (old 1.x/2.early) OST object in "group 0"
                 * that we map into the IDIF namespace.  It allows up to 2^48
                 * objects per OST, as this is the object namespace that has
                 * been in production for years.  This can handle create rates
                 * of 1M objects/s/OST for 9 years, or combinations thereof. */
                if (ostid->oi_id >= IDIF_MAX_OID) {
                         CERROR("bad MDT0 id, seq:"LPU64" id:"LPU64" ost_idx:%u\n",
                                ostid->oi_seq, ostid->oi_id, ost_idx);
                         return -EBADF;
                }
                ostid_idif_unpack(ostid, fid, ost_idx);

        } else if (fid_seq_is_rsvd(ostid->oi_seq)) {
                /* These are legacy OST objects for LLOG/ECHO and CMD testing.
                 * We only support 2^32 objects in these groups, and cannot
                 * uniquely identify them in the system (i.e. they are the
                 * duplicated on all OSTs), but this is not strictly required
                 * for the old object protocol, which has a separate ost_idx. */
                if (ostid->oi_id >= 0xffffffffULL) {
                         CERROR("bad RSVD id, seq:"LPU64" id:"LPU64" ost_idx:%u\n",
                                ostid->oi_seq, ostid->oi_id, ost_idx);
                         return -EBADF;
                }
                ostid_fid_unpack(ostid, fid);

        } else if (unlikely(fid_seq_is_igif(ostid->oi_seq))) {
                /* This is an MDT inode number, which should never collide with
                 * proper OST object IDs, and is probably a broken filesystem */
                CERROR("bad IGIF, seq:"LPU64" id:"LPU64" ost_idx:%u\n",
                       ostid->oi_seq, ostid->oi_id, ost_idx);
                return -EBADF;

        } else /* if (fid_seq_is_idif(seq) || fid_seq_is_norm(seq)) */ {
               /* This is either an IDIF object, which identifies objects across
                * all OSTs, or a regular FID.  The IDIF namespace maps legacy
                * OST objects into the FID namespace.  In both cases, we just
                * pass the FID through, no conversion needed. */
                ostid_fid_unpack(ostid, fid);
        }

        return 0;
}

/* pack an IDIF FID into an ostid (id/seq) for the wire/disk */
static inline void ostid_idif_pack(struct lu_fid *fid, struct ost_id *ostid)
{
        ostid->oi_seq = FID_SEQ_OST_MDT0;
        ostid->oi_id  = fid_idif_id(fid->f_seq, fid->f_oid, fid->f_ver);
}

/* pack a non-IDIF FID into an ostid (id/seq) for the wire/disk */
static inline void ostid_fid_pack(struct lu_fid *fid, struct ost_id *ostid)
{
        ostid->oi_seq = fid_seq(fid);
        ostid->oi_id  = fid_ver_oid(fid);
}

/* pack any OST FID into an ostid (id/seq) for the wire/disk */
static inline int fid_ostid_pack(struct lu_fid *fid, struct ost_id *ostid)
{
        if (unlikely(fid_seq_is_igif(fid->f_seq))) {
                CERROR("bad IGIF, "DFID"\n", PFID(fid));
                return -EBADF;
        }

        if (fid_is_idif(fid))
                ostid_idif_pack(fid, ostid);
        else
                ostid_fid_pack(fid, ostid);

        return 0;
}

/* extract OST sequence (group) from a wire ost_id (id/seq) pair */
static inline obd_seq ostid_seq(struct ost_id *ostid)
{
        if (unlikely(fid_seq_is_igif(ostid->oi_seq)))
                CWARN("bad IGIF, oi_seq: "LPU64" oi_id: "LPX64"\n",
                      ostid->oi_seq, ostid->oi_id);

        if (unlikely(fid_seq_is_idif(ostid->oi_seq)))
                return FID_SEQ_OST_MDT0;

        return ostid->oi_seq;
}

/* extract OST objid from a wire ost_id (id/seq) pair */
static inline obd_id ostid_id(struct ost_id *ostid)
{
        if (ostid->oi_seq == FID_SEQ_OST_MDT0)
                return ostid->oi_id & IDIF_OID_MASK;

        if (fid_seq_is_rsvd(ostid->oi_seq))
                return ostid->oi_id & OBIF_OID_MASK;

        if (fid_seq_is_idif(ostid->oi_seq))
                return fid_idif_id(ostid->oi_seq, ostid->oi_id, 0);

        return ostid->oi_id;
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
 * Build igif from the inode number/generation.
 */
#define LU_IGIF_BUILD(fid, ino, gen)                    \
do {                                                    \
        fid->f_seq = ino;                               \
        fid->f_oid = gen;                               \
        fid->f_ver = 0;                                 \
} while(0)
static inline void lu_igif_build(struct lu_fid *fid, __u32 ino, __u32 gen)
{
        LU_IGIF_BUILD(fid, ino, gen);
        LASSERT(fid_is_igif(fid));
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

/*
 * Fids are transmitted across network (in the sender byte-ordering),
 * and stored on disk in big-endian order.
 */
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

static inline int fid_is_sane(const struct lu_fid *fid)
{
        return
                fid != NULL &&
                ((fid_seq(fid) >= FID_SEQ_START && fid_oid(fid) != 0
                                                && fid_ver(fid) == 0) ||
                fid_is_igif(fid));
}

static inline int fid_is_zero(const struct lu_fid *fid)
{
        return fid_seq(fid) == 0 && fid_oid(fid) == 0;
}

extern void lustre_swab_lu_fid(struct lu_fid *fid);
extern void lustre_swab_lu_seq_range(struct lu_seq_range *range);

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

#define __diff_normalize(val0, val1)                            \
({                                                              \
        typeof(val0) __val0 = (val0);                           \
        typeof(val1) __val1 = (val1);                           \
                                                                \
        (__val0 == __val1 ? 0 : __val0 > __val1 ? +1 : -1);     \
})

static inline int lu_fid_cmp(const struct lu_fid *f0,
                             const struct lu_fid *f1)
{
        return
                __diff_normalize(fid_seq(f0), fid_seq(f1)) ?:
                __diff_normalize(fid_oid(f0), fid_oid(f1)) ?:
                __diff_normalize(fid_ver(f0), fid_ver(f1));
}

/** @} lu_fid */

/** \defgroup lu_dir lu_dir
 * @{ */

/**
 * Enumeration of possible directory entry attributes.
 *
 * Attributes follow directory entry header in the order they appear in this
 * enumeration.
 */
enum lu_dirent_attrs {
        LUDA_FID    = 0x0001,
        LUDA_TYPE   = 0x0002,
};

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
        char          lde_name[0];
};

/*
 * Definitions of optional directory entry attributes formats.
 *
 * Individual attributes do not have their length encoded in a generic way. It
 * is assumed that consumer of an attribute knows its format. This means that
 * it is impossible to skip over an unknown attribute, except by skipping over all
 * remaining attributes (by using ->lde_reclen), which is not too
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
        struct lu_dirent ldp_entries[0];
};

enum lu_dirpage_flags {
        LDF_EMPTY = 1 << 0
};

static inline struct lu_dirent *lu_dirent_start(struct lu_dirpage *dp)
{
        if (le32_to_cpu(dp->ldp_flags) & LDF_EMPTY)
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

static inline int lu_dirent_calc_size(int namelen, __u16 attr)
{
        int size;

        if (attr & LUDA_TYPE) {
                const unsigned align = sizeof(struct luda_type) - 1;
                size = (sizeof(struct lu_dirent) + namelen + align) & ~align;
                size += sizeof(struct luda_type);
        } else
                size = sizeof(struct lu_dirent) + namelen;

        return (size + 7) & ~7;
}

static inline int lu_dirent_size(struct lu_dirent *ent)
{
        if (le16_to_cpu(ent->lde_reclen) == 0) {
                return lu_dirent_calc_size(le16_to_cpu(ent->lde_namelen),
                                           le32_to_cpu(ent->lde_attrs));
        }
        return le16_to_cpu(ent->lde_reclen);
}

#define DIR_END_OFF              0xfffffffffffffffeULL

/** @} lu_dir */

struct lustre_handle {
        __u64 cookie;
};
#define DEAD_HANDLE_MAGIC 0xdeadbeefcafebabeULL

static inline int lustre_handle_is_used(struct lustre_handle *lh)
{
        return lh->cookie != 0ull;
}

static inline int lustre_handle_equal(const struct lustre_handle *lh1,
                                      const struct lustre_handle *lh2)
{
        return lh1->cookie == lh2->cookie;
}

static inline void lustre_handle_copy(struct lustre_handle *tgt,
                                      struct lustre_handle *src)
{
        tgt->cookie = src->cookie;
}

/* flags for lm_flags */
#define MSGHDR_AT_SUPPORT               0x1
#define MSGHDR_CKSUM_INCOMPAT18         0x2

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

/* without gss, ptlrpc_body is put at the first buffer. */
#define PTLRPC_NUM_VERSIONS     4
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

/** only use in req->rq_{req,rep}_swab_mask */
#define MSG_PTLRPC_HEADER_OFF           31

/* Flags that are operation-specific go in the top 16 bits. */
#define MSG_OP_FLAG_MASK   0xffff0000
#define MSG_OP_FLAG_SHIFT  16

/* Flags that apply to all requests are in the bottom 16 bits */
#define MSG_GEN_FLAG_MASK     0x0000ffff
#define MSG_LAST_REPLAY           0x0001
#define MSG_RESENT                0x0002
#define MSG_REPLAY                0x0004
/* #define MSG_AT_SUPPORT         0x0008
 * This was used in early prototypes of adaptive timeouts, and while there
 * shouldn't be any users of that code there also isn't a need for using this
 * bits. Defer usage until at least 1.10 to avoid potential conflict. */
#define MSG_DELAY_REPLAY          0x0010
#define MSG_VERSION_REPLAY        0x0020
#define MSG_REQ_REPLAY_DONE       0x0040
#define MSG_LOCK_REPLAY_DONE      0x0080

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
#define MSG_CONNECT_TRANSNO     0x00000100 /* report transno */

/* Connect flags */
#define OBD_CONNECT_RDONLY                0x1ULL /*client has read-only access*/
#define OBD_CONNECT_INDEX                 0x2ULL /*connect specific LOV idx */
#define OBD_CONNECT_MDS                   0x4ULL /*connect from MDT to OST */
#define OBD_CONNECT_GRANT                 0x8ULL /*OSC gets grant at connect */
#define OBD_CONNECT_SRVLOCK              0x10ULL /*server takes locks for cli */
#define OBD_CONNECT_VERSION              0x20ULL /*Lustre versions in ocd */
#define OBD_CONNECT_REQPORTAL            0x40ULL /*Separate non-IO req portal */
#define OBD_CONNECT_ACL                  0x80ULL /*access control lists */
#define OBD_CONNECT_XATTR               0x100ULL /*client use extended attr */
#define OBD_CONNECT_CROW                0x200ULL /*MDS+OST create obj on write*/
#define OBD_CONNECT_TRUNCLOCK           0x400ULL /*locks on server for punch */
#define OBD_CONNECT_TRANSNO             0x800ULL /*replay sends init transno */
#define OBD_CONNECT_IBITS              0x1000ULL /*support for inodebits locks*/
#define OBD_CONNECT_JOIN               0x2000ULL /*files can be concatenated.
                                                  *We do not support JOIN FILE
                                                  *anymore, reserve this flags
                                                  *just for preventing such bit
                                                  *to be reused.*/
#define OBD_CONNECT_ATTRFID            0x4000ULL /*Server can GetAttr By Fid*/
#define OBD_CONNECT_NODEVOH            0x8000ULL /*No open hndl on specl nodes*/
#define OBD_CONNECT_RMT_CLIENT        0x10000ULL /*Remote client */
#define OBD_CONNECT_RMT_CLIENT_FORCE  0x20000ULL /*Remote client by force */
#define OBD_CONNECT_BRW_SIZE          0x40000ULL /*Max bytes per rpc */
#define OBD_CONNECT_QUOTA64           0x80000ULL /*64bit qunit_data.qd_count */
#define OBD_CONNECT_MDS_CAPA         0x100000ULL /*MDS capability */
#define OBD_CONNECT_OSS_CAPA         0x200000ULL /*OSS capability */
#define OBD_CONNECT_CANCELSET        0x400000ULL /*Early batched cancels. */
#define OBD_CONNECT_SOM              0x800000ULL /*Size on MDS */
#define OBD_CONNECT_AT              0x1000000ULL /*client uses AT */
#define OBD_CONNECT_LRU_RESIZE      0x2000000ULL /*LRU resize feature. */
#define OBD_CONNECT_MDS_MDS         0x4000000ULL /*MDS-MDS connection */
#define OBD_CONNECT_REAL            0x8000000ULL /*real connection */
#define OBD_CONNECT_CHANGE_QS      0x10000000ULL /*shrink/enlarge qunit */
#define OBD_CONNECT_CKSUM          0x20000000ULL /*support several cksum algos*/
#define OBD_CONNECT_FID            0x40000000ULL /*FID is supported by server */
#define OBD_CONNECT_VBR            0x80000000ULL /*version based recovery */
#define OBD_CONNECT_LOV_V3        0x100000000ULL /*client supports LOV v3 EA */
#define OBD_CONNECT_GRANT_SHRINK  0x200000000ULL /* support grant shrink */
#define OBD_CONNECT_SKIP_ORPHAN   0x400000000ULL /* don't reuse orphan objids */
#define OBD_CONNECT_MAX_EASIZE    0x800000000ULL /* preserved for large EA */
#define OBD_CONNECT_FULL20       0x1000000000ULL /* it is 2.0 client */
#define OBD_CONNECT_LAYOUTLOCK   0x2000000000ULL /* client supports layout lock */
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
                                OBD_CONNECT_NODEVOH | OBD_CONNECT_ATTRFID | \
                                OBD_CONNECT_CANCELSET | OBD_CONNECT_AT | \
                                OBD_CONNECT_RMT_CLIENT | \
                                OBD_CONNECT_RMT_CLIENT_FORCE | \
                                OBD_CONNECT_MDS_CAPA | OBD_CONNECT_OSS_CAPA | \
                                OBD_CONNECT_MDS_MDS | OBD_CONNECT_FID | \
                                LRU_RESIZE_CONNECT_FLAG | OBD_CONNECT_VBR | \
                                OBD_CONNECT_LOV_V3 | OBD_CONNECT_SOM | \
                                OBD_CONNECT_FULL20)
#define OST_CONNECT_SUPPORTED  (OBD_CONNECT_SRVLOCK | OBD_CONNECT_GRANT | \
                                OBD_CONNECT_REQPORTAL | OBD_CONNECT_VERSION | \
                                OBD_CONNECT_TRUNCLOCK | OBD_CONNECT_INDEX | \
                                OBD_CONNECT_BRW_SIZE | OBD_CONNECT_QUOTA64 | \
                                OBD_CONNECT_CANCELSET | OBD_CONNECT_AT | \
                                LRU_RESIZE_CONNECT_FLAG | OBD_CONNECT_CKSUM | \
                                OBD_CONNECT_CHANGE_QS | \
                                OBD_CONNECT_OSS_CAPA  | OBD_CONNECT_RMT_CLIENT | \
                                OBD_CONNECT_RMT_CLIENT_FORCE | OBD_CONNECT_VBR | \
                                OBD_CONNECT_MDS | OBD_CONNECT_SKIP_ORPHAN | \
                                OBD_CONNECT_GRANT_SHRINK | OBD_CONNECT_FULL20)
#define ECHO_CONNECT_SUPPORTED (0)
#define MGS_CONNECT_SUPPORTED  (OBD_CONNECT_VERSION | OBD_CONNECT_AT | \
                                OBD_CONNECT_FULL20)

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
        OST_QUOTA_ADJUST_QUNIT = 20,
        OST_LAST_OPC
} ost_cmd_t;
#define OST_FIRST_OPC  OST_REPLY

enum obdo_flags {
        OBD_FL_INLINEDATA   = 0x00000001,
        OBD_FL_OBDMDEXISTS  = 0x00000002,
        OBD_FL_DELORPHAN    = 0x00000004, /* if set in o_flags delete orphans */
        OBD_FL_NORPC        = 0x00000008, /* set in o_flags do in OSC not OST */
        OBD_FL_IDONLY       = 0x00000010, /* set in o_flags only adjust obj id*/
        OBD_FL_RECREATE_OBJS= 0x00000020, /* recreate missing obj */
        OBD_FL_DEBUG_CHECK  = 0x00000040, /* echo client/server debug check */
        OBD_FL_NO_USRQUOTA  = 0x00000100, /* the object's owner is over quota */
        OBD_FL_NO_GRPQUOTA  = 0x00000200, /* the object's group is over quota */
        OBD_FL_CREATE_CROW  = 0x00000400, /* object should be create on write */
        OBD_FL_SRVLOCK      = 0x00000800, /* delegate DLM locking to server */
        OBD_FL_CKSUM_CRC32  = 0x00001000, /* CRC32 checksum type */
        OBD_FL_CKSUM_ADLER  = 0x00002000, /* ADLER checksum type */
        OBD_FL_CKSUM_RSVD1  = 0x00004000, /* for future cksum types */
        OBD_FL_CKSUM_RSVD2  = 0x00008000, /* for future cksum types */
        OBD_FL_CKSUM_RSVD3  = 0x00010000, /* for future cksum types */
        OBD_FL_SHRINK_GRANT = 0x00020000, /* object shrink the grant */
        OBD_FL_MMAP         = 0x00040000, /* object is mmapped on the client */
        OBD_FL_RECOV_RESEND = 0x00080000, /* recoverable resent */

        OBD_FL_CKSUM_ALL    = OBD_FL_CKSUM_CRC32 | OBD_FL_CKSUM_ADLER,

        /* mask for local-only flag, which won't be sent over network */
        OBD_FL_LOCAL_MASK   = 0xF0000000,
};

#define LOV_MAGIC_V1      0x0BD10BD0
#define LOV_MAGIC         LOV_MAGIC_V1
#define LOV_MAGIC_JOIN_V1 0x0BD20BD0
#define LOV_MAGIC_V3      0x0BD30BD0

#define LOV_PATTERN_RAID0 0x001   /* stripes are used round-robin */
#define LOV_PATTERN_RAID1 0x002   /* stripes are mirrors of each other */
#define LOV_PATTERN_FIRST 0x100   /* first stripe is not in round-robin */
#define LOV_PATTERN_CMOBD 0x200

#define LOV_OBJECT_GROUP_DEFAULT ~0ULL
#define LOV_OBJECT_GROUP_CLEAR 0ULL

#define lov_ost_data lov_ost_data_v1
struct lov_ost_data_v1 {          /* per-stripe data structure (little-endian)*/
        __u64 l_object_id;        /* OST object ID */
        __u64 l_object_seq;       /* OST object seq number */
        __u32 l_ost_gen;          /* generation of this l_ost_idx */
        __u32 l_ost_idx;          /* OST index in LOV (lov_tgt_desc->tgts) */
};

#define lov_mds_md lov_mds_md_v1
struct lov_mds_md_v1 {            /* LOV EA mds/wire data (little-endian) */
        __u32 lmm_magic;          /* magic number = LOV_MAGIC_V1 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_seq;     /* LOV object seq number */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u32 lmm_stripe_count;   /* num stripes in use for this object */
        struct lov_ost_data_v1 lmm_objects[0]; /* per-stripe data */
};

/* extern void lustre_swab_lov_mds_md(struct lov_mds_md *llm); */

#define MAX_MD_SIZE (sizeof(struct lov_mds_md) + 4 * sizeof(struct lov_ost_data))
#define MIN_MD_SIZE (sizeof(struct lov_mds_md) + 1 * sizeof(struct lov_ost_data))

#define XATTR_NAME_ACL_ACCESS   "system.posix_acl_access"
#define XATTR_NAME_ACL_DEFAULT  "system.posix_acl_default"
#define XATTR_USER_PREFIX       "user."
#define XATTR_TRUSTED_PREFIX    "trusted."
#define XATTR_SECURITY_PREFIX   "security."
#define XATTR_LUSTRE_PREFIX     "lustre."

#define XATTR_NAME_LOV          "trusted.lov"
#define XATTR_NAME_LMA          "trusted.lma"
#define XATTR_NAME_LMV          "trusted.lmv"
#define XATTR_NAME_LINK         "trusted.link"


struct lov_mds_md_v3 {            /* LOV EA mds/wire data (little-endian) */
        __u32 lmm_magic;          /* magic number = LOV_MAGIC_V3 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_seq;     /* LOV object seq number */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u32 lmm_stripe_count;   /* num stripes in use for this object */
        char  lmm_pool_name[LOV_MAXPOOLNAME]; /* must be 32bit aligned */
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
/*#define OBD_MD_FLINLINE    (0x00008000ULL)  inline data. used until 1.6.5 */
#define OBD_MD_FLRDEV      (0x00010000ULL) /* device number */
#define OBD_MD_FLEASIZE    (0x00020000ULL) /* extended attribute data */
#define OBD_MD_LINKNAME    (0x00040000ULL) /* symbolic link target */
#define OBD_MD_FLHANDLE    (0x00080000ULL) /* file/lock handle */
#define OBD_MD_FLCKSUM     (0x00100000ULL) /* bulk data checksum */
#define OBD_MD_FLQOS       (0x00200000ULL) /* quality of service stats */
/*#define OBD_MD_FLOSCOPQ    (0x00400000ULL) osc opaque data, never used */
#define OBD_MD_FLCOOKIE    (0x00800000ULL) /* log cancellation cookie */
#define OBD_MD_FLGROUP     (0x01000000ULL) /* group */
#define OBD_MD_FLFID       (0x02000000ULL) /* ->ost write inline fid */
#define OBD_MD_FLEPOCH     (0x04000000ULL) /* ->ost write with ioepoch */
                                           /* ->mds if epoch opens or closes */
#define OBD_MD_FLGRANT     (0x08000000ULL) /* ost preallocation space grant */
#define OBD_MD_FLDIREA     (0x10000000ULL) /* dir's extended attribute data */
#define OBD_MD_FLUSRQUOTA  (0x20000000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLGRPQUOTA  (0x40000000ULL) /* over quota flags sent from ost */
#define OBD_MD_FLMODEASIZE (0x80000000ULL) /* EA size will be changed */

#define OBD_MD_MDS         (0x0000000100000000ULL) /* where an inode lives on */
#define OBD_MD_REINT       (0x0000000200000000ULL) /* reintegrate oa */
#define OBD_MD_MEA         (0x0000000400000000ULL) /* CMD split EA  */
#define OBD_MD_MDTIDX      (0x0000000800000000ULL) /* Get MDT index  */

#define OBD_MD_FLXATTR     (0x0000001000000000ULL) /* xattr */
#define OBD_MD_FLXATTRLS   (0x0000002000000000ULL) /* xattr list */
#define OBD_MD_FLXATTRRM   (0x0000004000000000ULL) /* xattr remove */
#define OBD_MD_FLACL       (0x0000008000000000ULL) /* ACL */
#define OBD_MD_FLRMTPERM   (0x0000010000000000ULL) /* remote permission */
#define OBD_MD_FLMDSCAPA   (0x0000020000000000ULL) /* MDS capability */
#define OBD_MD_FLOSSCAPA   (0x0000040000000000ULL) /* OSS capability */
#define OBD_MD_FLCKSPLIT   (0x0000080000000000ULL) /* Check split on server */
#define OBD_MD_FLCROSSREF  (0x0000100000000000ULL) /* Cross-ref case */
#define OBD_MD_FLGETATTRLOCK (0x0000200000000000ULL) /* Get IOEpoch attributes
                                                      * under lock */
#define OBD_FL_TRUNC       (0x0000200000000000ULL) /* for filter_truncate */

#define OBD_MD_FLRMTLSETFACL    (0x0001000000000000ULL) /* lfs lsetfacl case */
#define OBD_MD_FLRMTLGETFACL    (0x0002000000000000ULL) /* lfs lgetfacl case */
#define OBD_MD_FLRMTRSETFACL    (0x0004000000000000ULL) /* lfs rsetfacl case */
#define OBD_MD_FLRMTRGETFACL    (0x0008000000000000ULL) /* lfs rgetfacl case */

#define OBD_MD_FLGETATTR (OBD_MD_FLID    | OBD_MD_FLATIME | OBD_MD_FLMTIME | \
                          OBD_MD_FLCTIME | OBD_MD_FLSIZE  | OBD_MD_FLBLKSZ | \
                          OBD_MD_FLMODE  | OBD_MD_FLTYPE  | OBD_MD_FLUID   | \
                          OBD_MD_FLGID   | OBD_MD_FLFLAGS | OBD_MD_FLNLINK | \
                          OBD_MD_FLGENER | OBD_MD_FLRDEV  | OBD_MD_FLGROUP)

/* don't forget obdo_fid which is way down at the bottom so it can
 * come after the definition of llog_cookie */


extern void lustre_swab_obd_statfs (struct obd_statfs *os);
#define OBD_STATFS_NODELAY      0x0001  /* requests should be send without delay
                                         * and resends for avoid deadlocks */
#define OBD_STATFS_FROM_CACHE   0x0002  /* the statfs callback should not update
                                         * obd_osfs_age */
#define OBD_STATFS_PTLRPCD      0x0004  /* requests will be sent via ptlrpcd
                                         * instead of a specific set. This
                                         * means that we cannot rely on the set
                                         * interpret routine to be called.
                                         * lov_statfs_fini() must thus be called
                                         * by the request interpret routine */

/* ost_body.data values for OST_BRW */

#define OBD_BRW_READ            0x01
#define OBD_BRW_WRITE           0x02
#define OBD_BRW_RWMASK          (OBD_BRW_READ | OBD_BRW_WRITE)
#define OBD_BRW_SYNC            0x08 /* this page is a part of synchronous
                                      * transfer and is not accounted in
                                      * the grant. */
#define OBD_BRW_CHECK           0x10
#define OBD_BRW_FROM_GRANT      0x20 /* the osc manages this under llite */
#define OBD_BRW_GRANTED         0x40 /* the ost manages this */
#define OBD_BRW_NOCACHE         0x80 /* this page is a part of non-cached IO */
#define OBD_BRW_NOQUOTA        0x100
#define OBD_BRW_SRVLOCK        0x200 /* Client holds no lock over this page */
#define OBD_BRW_ASYNC          0x400 /* Server may delay commit to disk */
#define OBD_BRW_MEMALLOC       0x800 /* Client runs in the "kswapd" context */

#define OBD_OBJECT_EOF 0xffffffffffffffffULL

#define OST_MIN_PRECREATE 32
#define OST_MAX_PRECREATE 20000

struct obd_ioobj {
        obd_id               ioo_id;
        obd_seq              ioo_seq;
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
        __u64     lvb_size;
        obd_time  lvb_mtime;
        obd_time  lvb_atime;
        obd_time  lvb_ctime;
        __u64     lvb_blocks;
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
        MDS_GET_INFO     = 53,
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
        /* There is a pending attribute update. */
        MF_SOM_AU               = (1 << 7),
        /* Cancel OST locks while getattr OST attributes. */
        MF_GETATTR_LOCK         = (1 << 8),
};

#define MF_SOM_LOCAL_FLAGS (MF_SOM_CHANGE | MF_EPOCH_OPEN | MF_EPOCH_CLOSE)

#define MDS_BFLAG_UNCOMMITTED_WRITES   0x1

/* these should be identical to their EXT3_*_FL counterparts, and are
 * redefined here only to avoid dragging in ext3_fs.h */
#define MDS_SYNC_FL             0x00000008 /* Synchronous updates */
#define MDS_IMMUTABLE_FL        0x00000010 /* Immutable file */
#define MDS_APPEND_FL           0x00000020 /* writes to file may only append */
#define MDS_NOATIME_FL          0x00000080 /* do not update atime */
#define MDS_DIRSYNC_FL          0x00010000 /* dirsync behaviour (dir only) */

#ifdef __KERNEL__
/* Convert wire MDS_*_FL to corresponding client local VFS S_* values
 * for the client inode i_flags.  The MDS_*_FL are the Lustre wire
 * protocol equivalents of LDISKFS_*_FL values stored on disk, while
 * the S_* flags are kernel-internal values that change between kernel
 * versions.  These flags are set/cleared via FSFILT_IOC_{GET,SET}_FLAGS.
 * See b=16526 for a full history. */
static inline int ll_ext_to_inode_flags(int flags)
{
        return (((flags & MDS_SYNC_FL)      ? S_SYNC      : 0) |
                ((flags & MDS_NOATIME_FL)   ? S_NOATIME   : 0) |
                ((flags & MDS_APPEND_FL)    ? S_APPEND    : 0) |
#if defined(S_DIRSYNC)
                ((flags & MDS_DIRSYNC_FL)   ? S_DIRSYNC   : 0) |
#endif
                ((flags & MDS_IMMUTABLE_FL) ? S_IMMUTABLE : 0));
}

static inline int ll_inode_to_ext_flags(int iflags)
{
        return (((iflags & S_SYNC)      ? MDS_SYNC_FL      : 0) |
                ((iflags & S_NOATIME)   ? MDS_NOATIME_FL   : 0) |
                ((iflags & S_APPEND)    ? MDS_APPEND_FL    : 0) |
#if defined(S_DIRSYNC)
                ((iflags & S_DIRSYNC)   ? MDS_DIRSYNC_FL   : 0) |
#endif
                ((iflags & S_IMMUTABLE) ? MDS_IMMUTABLE_FL : 0));
}
#endif

/*
 * while mds_body is to interact with 1.6, mdt_body is to interact with 2.0.
 * both of them should have the same fields layout, because at client side
 * one could be dynamically cast to the other.
 *
 * mdt_body has large size than mds_body, with unused padding (48 bytes)
 * at the end. client always use size of mdt_body to prepare request/reply
 * buffers, and actual data could be interepeted as mdt_body or mds_body
 * accordingly.
 */
struct mds_body {
        struct ll_fid  fid1;
        struct ll_fid  fid2;
        struct lustre_handle handle;
        __u64          valid;
        __u64          size;   /* Offset, in the case of MDS_READPAGE */
        obd_time       mtime;
        obd_time       atime;
        obd_time       ctime;
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
        __u32          max_cookiesize;
        __u32          padding_4; /* also fix lustre_swab_mds_body */
};

extern void lustre_swab_mds_body (struct mds_body *b);

struct mdt_body {
        struct lu_fid  fid1;
        struct lu_fid  fid2;
        struct lustre_handle handle;
        __u64          valid;
        __u64          size;   /* Offset, in the case of MDS_READPAGE */
       obd_time        mtime;
       obd_time        atime;
       obd_time        ctime;
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
        __u32          uid_h; /* high 32-bits of uid, for FUID */
        __u32          gid_h; /* high 32-bits of gid, for FUID */
        __u32          padding_5; /* also fix lustre_swab_mdt_body */
        __u64          padding_6;
        __u64          padding_7;
        __u64          padding_8;
        __u64          padding_9;
        __u64          padding_10;
}; /* 216 */

extern void lustre_swab_mdt_body (struct mdt_body *b);

struct mdt_ioepoch {
        struct lustre_handle handle;
        __u64  ioepoch;
        __u32  flags;
        __u32  padding;
};

extern void lustre_swab_mdt_ioepoch (struct mdt_ioepoch *b);

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

#define QCTL_COPY(out, in)              \
do {                                    \
        Q_COPY(out, in, qc_cmd);        \
        Q_COPY(out, in, qc_type);       \
        Q_COPY(out, in, qc_id);         \
        Q_COPY(out, in, qc_stat);       \
        Q_COPY(out, in, qc_dqinfo);     \
        Q_COPY(out, in, qc_dqblk);      \
} while (0)

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

/* flags is shared among quota structures */
#define LQUOTA_FLAGS_GRP       1UL   /* 0 is user, 1 is group */
#define LQUOTA_FLAGS_BLK       2UL   /* 0 is inode, 1 is block */
#define LQUOTA_FLAGS_ADJBLK    4UL   /* adjust the block qunit size */
#define LQUOTA_FLAGS_ADJINO    8UL   /* adjust the inode qunit size */
#define LQUOTA_FLAGS_CHG_QS   16UL   /* indicate whether it has capability of
                                      * OBD_CONNECT_CHANGE_QS */
#define LQUOTA_FLAGS_RECOVERY 32UL   /* recovery is going on a uid/gid */
#define LQUOTA_FLAGS_SETQUOTA 64UL   /* being setquota on a uid/gid */

/* flags is specific for quota_adjust_qunit */
#define LQUOTA_QAQ_CREATE_LQS  (1 << 31) /* when it is set, need create lqs */

/* the status of lqs_flags in struct lustre_qunit_size  */
#define LQUOTA_QUNIT_FLAGS (LQUOTA_FLAGS_GRP | LQUOTA_FLAGS_BLK)

#define QAQ_IS_GRP(qaq)    ((qaq)->qaq_flags & LQUOTA_FLAGS_GRP)
#define QAQ_IS_ADJBLK(qaq) ((qaq)->qaq_flags & LQUOTA_FLAGS_ADJBLK)
#define QAQ_IS_ADJINO(qaq) ((qaq)->qaq_flags & LQUOTA_FLAGS_ADJINO)
#define QAQ_IS_CREATE_LQS(qaq)  ((qaq)->qaq_flags & LQUOTA_QAQ_CREATE_LQS)

#define QAQ_SET_GRP(qaq)    ((qaq)->qaq_flags |= LQUOTA_FLAGS_GRP)
#define QAQ_SET_ADJBLK(qaq) ((qaq)->qaq_flags |= LQUOTA_FLAGS_ADJBLK)
#define QAQ_SET_ADJINO(qaq) ((qaq)->qaq_flags |= LQUOTA_FLAGS_ADJINO)
#define QAQ_SET_CREATE_LQS(qaq) ((qaq)->qaq_flags |= LQUOTA_QAQ_CREATE_LQS)

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
        CFS_RMTACL_PERM = 0x08,
        CFS_RMTOWN_PERM = 0x10
};

extern void lustre_swab_mds_remote_perm(struct mds_remote_perm *p);

struct mdt_remote_perm {
        __u32           rp_uid;
        __u32           rp_gid;
        __u32           rp_fsuid;
        __u32           rp_fsuid_h;
        __u32           rp_fsgid;
        __u32           rp_fsgid_h;
        __u32           rp_access_perm; /* MAY_READ/WRITE/EXEC */
};

extern void lustre_swab_mdt_remote_perm(struct mdt_remote_perm *p);

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
        obd_time        sa_mtime;
        obd_time        sa_atime;
        obd_time        sa_ctime;
        __u32           sa_attr_flags;
        __u32           sa_mode;
        __u32           sa_padding_2;
        __u32           sa_padding_3;
        __u32           sa_padding_4;
        __u32           sa_padding_5;
};

extern void lustre_swab_mdt_rec_setattr (struct mdt_rec_setattr *sa);

/*
 * Attribute flags used in mdt_rec_setattr::sa_valid.
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

/* IO Epoch is opened on a closed file. */
#define FMODE_EPOCH              01000000
/* IO Epoch is opened on a file truncate. */
#define FMODE_TRUNC              02000000
/* Size-on-MDS Attribute Update is pending. */
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
#define MDS_OPEN_JOIN_FILE     0400000000 /* open for join file.
                                           * We do not support JOIN FILE
                                           * anymore, reserve this flags
                                           * just for preventing such bit
                                           * to be reused. */
#define MDS_CREATE_RMT_ACL    01000000000 /* indicate create on remote server
                                           * with default ACL */
#define MDS_CREATE_SLAVE_OBJ  02000000000 /* indicate create slave object
                                           * actually, this is for create, not
                                           * conflict with other open flags */
#define MDS_OPEN_LOCK         04000000000 /* This open requires open lock */
#define MDS_OPEN_HAS_EA      010000000000 /* specify object create pattern */
#define MDS_OPEN_HAS_OBJS    020000000000 /* Just set the EA the obj exist */
#define MDS_OPEN_NORESTORE  0100000000000ULL /* Do not restore file at open */
#define MDS_OPEN_NEWSTRIPE  0200000000000ULL /* New stripe needed (restripe or
                                              * hsm restore) */

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
        MDS_CHECK_SPLIT   = 1 << 0,
        MDS_CROSS_REF     = 1 << 1,
        MDS_VTX_BYPASS    = 1 << 2,
        MDS_PERM_BYPASS   = 1 << 3,
        MDS_SOM           = 1 << 4,
        MDS_QUOTA_IGNORE  = 1 << 5,
        MDS_CLOSE_CLEANUP = 1 << 6,
        MDS_KEEP_ORPHAN   = 1 << 7
};

/* instance of mdt_reint_rec */
struct mdt_rec_create {
        __u32           cr_opcode;
        __u32           cr_cap;
        __u32           cr_fsuid;
        __u32           cr_fsuid_h;
        __u32           cr_fsgid;
        __u32           cr_fsgid_h;
        __u32           cr_suppgid1;
        __u32           cr_suppgid1_h;
        __u32           cr_suppgid2;
        __u32           cr_suppgid2_h;
        struct lu_fid   cr_fid1;
        struct lu_fid   cr_fid2;
        struct lustre_handle cr_old_handle; /* handle in case of open replay */
        obd_time        cr_time;
        __u64           cr_rdev;
        __u64           cr_ioepoch;
        __u64           cr_padding_1;   /* rr_blocks */
        __u32           cr_mode;
        __u32           cr_bias;
        /* use of helpers set/get_mrc_cr_flags() is needed to access
         * 64 bits cr_flags [cr_flags_l, cr_flags_h], this is done to
         * extend cr_flags size without breaking 1.8 compat */
        __u32           cr_flags_l;     /* for use with open, low  32 bits  */
        __u32           cr_flags_h;     /* for use with open, high 32 bits */
        __u32           cr_padding_3;   /* rr_padding_3 */
        __u32           cr_padding_4;   /* rr_padding_4 */
};

static inline void set_mrc_cr_flags(struct mdt_rec_create *mrc, __u64 flags)
{
        mrc->cr_flags_l = (__u32)(flags & 0xFFFFFFFFUll);
        mrc->cr_flags_h = (__u32)(flags >> 32);
}

static inline __u64 get_mrc_cr_flags(struct mdt_rec_create *mrc)
{
        return ((__u64)(mrc->cr_flags_l) | ((__u64)mrc->cr_flags_h << 32));
}

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
        obd_time        lk_time;
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
        obd_time        ul_time;
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
        obd_time        rn_time;
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
        obd_time        sx_time;
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
        obd_time        rr_mtime;
        obd_time        rr_atime;
        obd_time        rr_ctime;
        __u64           rr_size;
        __u64           rr_blocks;
        __u32           rr_bias;
        __u32           rr_mode;
        __u32           rr_flags;
        __u32           rr_padding_2; /* also fix lustre_swab_mdt_rec_reint */
        __u32           rr_padding_3; /* also fix lustre_swab_mdt_rec_reint */
        __u32           rr_padding_4; /* also fix lustre_swab_mdt_rec_reint */
};

extern void lustre_swab_mdt_rec_reint(struct mdt_rec_reint *rr);

struct lmv_desc {
        __u32 ld_tgt_count;                /* how many MDS's */
        __u32 ld_active_tgt_count;         /* how many active */
        __u32 ld_default_stripe_count;     /* how many objects are used */
        __u32 ld_pattern;                  /* default MEA_MAGIC_* */
        __u64 ld_default_hash_size;
        __u64 ld_padding_1;                /* also fix lustre_swab_lmv_desc */
        __u32 ld_padding_2;                /* also fix lustre_swab_lmv_desc */
        __u32 ld_qos_maxage;               /* in second */
        __u32 ld_padding_3;                /* also fix lustre_swab_lmv_desc */
        __u32 ld_padding_4;                /* also fix lustre_swab_lmv_desc */
        struct obd_uuid ld_uuid;
};

extern void lustre_swab_lmv_desc (struct lmv_desc *ld);

/* TODO: lmv_stripe_md should contain mds capabilities for all slave fids */
struct lmv_stripe_md {
        __u32         mea_magic;
        __u32         mea_count;
        __u32         mea_master;
        __u32         mea_padding;
        char          mea_pool_name[LOV_MAXPOOLNAME];
        struct lu_fid mea_ids[0];
};

extern void lustre_swab_lmv_stripe_md(struct lmv_stripe_md *mea);

/* lmv structures */
#define MEA_MAGIC_LAST_CHAR      0xb2221ca1
#define MEA_MAGIC_ALL_CHARS      0xb222a11c
#define MEA_MAGIC_HASH_SEGMENT   0xb222a11b

#define MAX_HASH_SIZE_32         0x7fffffffUL
#define MAX_HASH_SIZE            0x7fffffffffffffffULL
#define MAX_HASH_HIGHEST_BIT     0x1000000000000000ULL

struct md_fld {
        seqno_t mf_seq;
        mdsno_t mf_mds;
};

extern void lustre_swab_md_fld (struct md_fld *mf);

enum fld_rpc_opc {
        FLD_QUERY                       = 900,
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

#define LOV_MIN_STRIPE_BITS 16   /* maximum PAGE_SIZE (ia64), power of 2 */
#define LOV_MIN_STRIPE_SIZE (1<<LOV_MIN_STRIPE_BITS)
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
        LDLM_SET_INFO    = 107,
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
        LCK_COS     = 128,
        LCK_MAXMODE
} ldlm_mode_t;

#define LCK_MODE_NUM    8

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
 * on the resource type. */

typedef union {
        struct ldlm_extent l_extent;
        struct ldlm_flock_wire l_flock;
        struct ldlm_inodebits l_inodebits;
} ldlm_wire_policy_data_t;

extern void lustre_swab_ldlm_policy_data (ldlm_wire_policy_data_t *d);

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
        ldlm_wire_policy_data_t l_policy_data;
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
        obd_time          cm_createtime; /*when this record was first created */
        obd_time          cm_canceltime; /*when this record is no longer valid*/
        char              cm_tgtname[MTI_NAME_MAXLEN];
        char              cm_comment[MTI_NAME_MAXLEN];
};

extern void lustre_swab_cfg_marker(struct cfg_marker *marker,
                                   int swab, int size);

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

/** Identifier for a single log object */
struct llog_logid {
        __u64                   lgl_oid;
        __u64                   lgl_oseq;
        __u32                   lgl_ogen;
} __attribute__((packed));

/** Records written to the CATALOGS list */
#define CATLIST "CATALOGS"
struct llog_catid {
        struct llog_logid       lci_logid;
        __u32                   lci_padding1;
        __u32                   lci_padding2;
        __u32                   lci_padding3;
} __attribute__((packed));

/* Log data record types - there is no specific reason that these need to
 * be related to the RPC opcodes, but no reason not to (may be handy later?)
 */
#define LLOG_OP_MAGIC 0x10600000
#define LLOG_OP_MASK  0xfff00000

typedef enum {
        LLOG_PAD_MAGIC     = LLOG_OP_MAGIC | 0x00000,
        OST_SZ_REC         = LLOG_OP_MAGIC | 0x00f00,
        OST_RAID1_REC      = LLOG_OP_MAGIC | 0x01000,
        MDS_UNLINK_REC     = LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_UNLINK,
        MDS_SETATTR_REC    = LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_SETATTR,
        MDS_SETATTR64_REC  = LLOG_OP_MAGIC | 0x90000 | (MDS_REINT << 8) | REINT_SETATTR,
        OBD_CFG_REC        = LLOG_OP_MAGIC | 0x20000,
        PTL_CFG_REC        = LLOG_OP_MAGIC | 0x30000, /* obsolete */
        LLOG_GEN_REC       = LLOG_OP_MAGIC | 0x40000,
        LLOG_JOIN_REC      = LLOG_OP_MAGIC | 0x50000, /* obsolete */
        CHANGELOG_REC      = LLOG_OP_MAGIC | 0x60000,
        CHANGELOG_USER_REC = LLOG_OP_MAGIC | 0x70000,
        LLOG_HDR_MAGIC     = LLOG_OP_MAGIC | 0x45539,
        LLOG_LOGID_MAGIC   = LLOG_OP_MAGIC | 0x4553b,
} llog_op_type;

/*
 * for now, continue to support old pad records which have 0 for their
 * type but still need to be swabbed for their length
 */
#define LLOG_REC_HDR_NEEDS_SWABBING(r)                                  \
        (((r)->lrh_type & __swab32(LLOG_OP_MASK)) ==                    \
         __swab32(LLOG_OP_MAGIC) ||                                     \
         (((r)->lrh_type == 0) && ((r)->lrh_len > LLOG_CHUNK_SIZE)))

/** Log record header - stored in little endian order.
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

struct llog_create_rec {
        struct llog_rec_hdr     lcr_hdr;
        struct ll_fid           lcr_fid;
        obd_id                  lcr_oid;
        obd_count               lcr_oseq;
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
        obd_count               lur_oseq;
        obd_count               lur_count;
        struct llog_rec_tail    lur_tail;
} __attribute__((packed));

struct llog_setattr_rec {
        struct llog_rec_hdr     lsr_hdr;
        obd_id                  lsr_oid;
        obd_count               lsr_oseq;
        __u32                   lsr_uid;
        __u32                   lsr_gid;
        __u32                   padding;
        struct llog_rec_tail    lsr_tail;
} __attribute__((packed));

struct llog_setattr64_rec {
        struct llog_rec_hdr     lsr_hdr;
        obd_id                  lsr_oid;
        obd_count               lsr_oseq;
        __u32                   padding;
        __u32                   lsr_uid;
        __u32                   lsr_uid_h;
        __u32                   lsr_gid;
        __u32                   lsr_gid_h;
        struct llog_rec_tail    lsr_tail;
} __attribute__((packed));

struct llog_size_change_rec {
        struct llog_rec_hdr     lsc_hdr;
        struct ll_fid           lsc_fid;
        __u32                   lsc_ioepoch;
        __u32                   padding;
        struct llog_rec_tail    lsc_tail;
} __attribute__((packed));

#define CHANGELOG_MAGIC 0xca103000

/** \a changelog_rec_type's that can't be masked */
#define CHANGELOG_MINMASK (1 << CL_MARK)
/** bits covering all \a changelog_rec_type's */
#define CHANGELOG_ALLMASK 0XFFFFFFFF
/** default \a changelog_rec_type mask */
#define CHANGELOG_DEFMASK CHANGELOG_ALLMASK & ~(1 << CL_ATIME)

/* changelog llog name, needed by client replicators */
#define CHANGELOG_CATALOG "changelog_catalog"

struct changelog_setinfo {
        __u64 cs_recno;
        __u32 cs_id;
} __attribute__((packed));

/** changelog record */
struct llog_changelog_rec {
        struct llog_rec_hdr  cr_hdr;
        struct changelog_rec cr;
        struct llog_rec_tail cr_tail; /**< for_sizezof_only */
} __attribute__((packed));

#define CHANGELOG_USER_PREFIX "cl"

struct llog_changelog_user_rec {
        struct llog_rec_hdr   cur_hdr;
        __u32                 cur_id;
        __u32                 cur_padding;
        __u64                 cur_endrec;
        struct llog_rec_tail  cur_tail;
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
        obd_time                llh_timestamp;
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

/** log cookies are used to reference a specific log file and a record therein */
struct llog_cookie {
        struct llog_logid       lgc_lgl;
        __u32                   lgc_subsys;
        __u32                   lgc_index;
        __u32                   lgc_padding;
} __attribute__((packed));

/** llog protocol */
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

/* Note: 64-bit types are 64-bit aligned in structure */
struct obdo {
        obd_valid               o_valid;        /* hot fields in this obdo */
        struct ost_id           o_oi;
        obd_id                  o_parent_seq;
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
        obd_count               o_parent_oid;
        obd_count               o_misc;         /* brw: o_dropped */
        __u64                   o_ioepoch;      /* epoch in ost writes */
        __u32                   o_stripe_idx;   /* holds stripe idx */
        __u32                   o_parent_ver;
        struct lustre_handle    o_handle;       /* brw: lock handle to prolong locks */
        struct llog_cookie      o_lcookie;      /* destroy: unlink cookie from MDS */

        __u32                   o_uid_h;
        __u32                   o_gid_h;
        __u64                   o_padding_3;
        __u64                   o_padding_4;
        __u64                   o_padding_5;
        __u64                   o_padding_6;
};

#define o_id     o_oi.oi_id
#define o_seq    o_oi.oi_seq
#define o_dirty   o_blocks
#define o_undirty o_mode
#define o_dropped o_misc
#define o_cksum   o_nlink

static inline void lustre_set_wire_obdo(struct obdo *wobdo, struct obdo *lobdo)
{
        memcpy(wobdo, lobdo, sizeof(*lobdo));
        wobdo->o_flags &= ~OBD_FL_LOCAL_MASK;
}

static inline void lustre_get_wire_obdo(struct obdo *lobdo, struct obdo *wobdo)
{
        obd_flag local_flags = 0;

        if (lobdo->o_valid & OBD_MD_FLFLAGS)
                 local_flags = lobdo->o_flags & OBD_FL_LOCAL_MASK;

        LASSERT(!(wobdo->o_flags & OBD_FL_LOCAL_MASK));

        memcpy(lobdo, wobdo, sizeof(*lobdo));
        if (local_flags != 0) {
                 lobdo->o_valid |= OBD_MD_FLFLAGS;
                 lobdo->o_flags &= ~OBD_FL_LOCAL_MASK;
                 lobdo->o_flags |= local_flags;
        }
}

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
extern void lustre_swab_lov_mds_md(struct lov_mds_md *lmm);

/* llog_swab.c */
extern void lustre_swab_llogd_body (struct llogd_body *d);
extern void lustre_swab_llog_hdr (struct llog_log_hdr *h);
extern void lustre_swab_llogd_conn_body (struct llogd_conn_body *d);
extern void lustre_swab_llog_rec(struct llog_rec_hdr  *rec,
                                 struct llog_rec_tail *tail);

struct lustre_cfg;
extern void lustre_swab_lustre_cfg(struct lustre_cfg *lcfg);

/* Functions for dumping PTLRPC fields */
void dump_rniobuf(struct niobuf_remote *rnb);
void dump_ioo(struct obd_ioobj *nb);
void dump_obdo(struct obdo *oa);
void dump_ost_body(struct ost_body *ob);
void dump_rcs(__u32 *rc);

/* this will be used when OBD_CONNECT_CHANGE_QS is set */
struct qunit_data {
        /**
         * ID appiles to (uid, gid)
         */
        __u32 qd_id;
        /**
         * LQUOTA_FLAGS_* affect the responding bits
         */
        __u32 qd_flags;
        /**
         * acquire/release count (bytes for block quota)
         */
        __u64 qd_count;
        /**
         * when a master returns the reply to a slave, it will
         * contain the current corresponding qunit size
         */
        __u64 qd_qunit;
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

extern void lustre_swab_qdata(struct qunit_data *d);
extern struct qunit_data *quota_get_qdata(void *req, int is_req, int is_exp);
extern int quota_copy_qdata(void *request, struct qunit_data *qdata,
                            int is_req, int is_exp);

typedef enum {
        QUOTA_DQACQ     = 601,
        QUOTA_DQREL     = 602,
        QUOTA_LAST_OPC
} quota_cmd_t;
#define QUOTA_FIRST_OPC QUOTA_DQACQ

#define QUOTA_REQUEST   1
#define QUOTA_REPLY     0
#define QUOTA_EXPORT    1
#define QUOTA_IMPORT    0

/* quota check function */
#define QUOTA_RET_OK           0 /**< return successfully */
#define QUOTA_RET_NOQUOTA      1 /**< not support quota */
#define QUOTA_RET_NOLIMIT      2 /**< quota limit isn't set */
#define QUOTA_RET_ACQUOTA      4 /**< need to acquire extra quota */


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
        struct lu_fid   lc_fid;         /** fid */
        __u64           lc_opc;         /** operations allowed */
        __u64           lc_uid;         /** file owner */
        __u64           lc_gid;         /** file group */
        __u32           lc_flags;       /** HMAC algorithm & flags */
        __u32           lc_keyid;       /** key# used for the capability */
        __u32           lc_timeout;     /** capa timeout value (sec) */
        __u32           lc_expiry;      /** expiry time (sec) */
        __u8            lc_hmac[CAPA_HMAC_MAX_LEN];   /** HMAC */
} __attribute__((packed));

extern void lustre_swab_lustre_capa(struct lustre_capa *c);

/** lustre_capa::lc_opc */
enum {
        CAPA_OPC_BODY_WRITE   = 1<<0,  /**< write object data */
        CAPA_OPC_BODY_READ    = 1<<1,  /**< read object data */
        CAPA_OPC_INDEX_LOOKUP = 1<<2,  /**< lookup object fid */
        CAPA_OPC_INDEX_INSERT = 1<<3,  /**< insert object fid */
        CAPA_OPC_INDEX_DELETE = 1<<4,  /**< delete object fid */
        CAPA_OPC_OSS_WRITE    = 1<<5,  /**< write oss object data */
        CAPA_OPC_OSS_READ     = 1<<6,  /**< read oss object data */
        CAPA_OPC_OSS_TRUNC    = 1<<7,  /**< truncate oss object */
        CAPA_OPC_OSS_DESTROY  = 1<<8,  /**< destroy oss object */
        CAPA_OPC_META_WRITE   = 1<<9,  /**< write object meta data */
        CAPA_OPC_META_READ    = 1<<10, /**< read object meta data */
};

#define CAPA_OPC_OSS_RW (CAPA_OPC_OSS_READ | CAPA_OPC_OSS_WRITE)
#define CAPA_OPC_MDS_ONLY                                                   \
        (CAPA_OPC_BODY_WRITE | CAPA_OPC_BODY_READ | CAPA_OPC_INDEX_LOOKUP | \
         CAPA_OPC_INDEX_INSERT | CAPA_OPC_INDEX_DELETE)
#define CAPA_OPC_OSS_ONLY                                                   \
        (CAPA_OPC_OSS_WRITE | CAPA_OPC_OSS_READ | CAPA_OPC_OSS_TRUNC |      \
         CAPA_OPC_OSS_DESTROY)
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

/* lustre_capa::lc_hmac_alg */
enum {
        CAPA_HMAC_ALG_SHA1 = 1, /**< sha1 algorithm */
        CAPA_HMAC_ALG_MAX,
};

#define CAPA_FL_MASK            0x00ffffff
#define CAPA_HMAC_ALG_MASK      0xff000000

struct lustre_capa_key {
        __u64   lk_seq;       /**< mds# */
        __u32   lk_keyid;     /**< key# */
        __u32   lk_padding;
        __u8    lk_key[CAPA_HMAC_KEY_MAX_LEN];    /**< key */
} __attribute__((packed));

extern void lustre_swab_lustre_capa_key(struct lustre_capa_key *k);

/** The link ea holds 1 \a link_ea_entry for each hardlink */
#define LINK_EA_MAGIC 0x11EAF1DFUL
struct link_ea_header {
        __u32 leh_magic;
        __u32 leh_reccount;
        __u64 leh_len;      /* total size */
        /* future use */
        __u32 padding1;
        __u32 padding2;
};

/** Hardlink data is name and parent fid.
 * Stored in this crazy struct for maximum packing and endian-neutrality
 */
struct link_ea_entry {
        /** __u16 stored big-endian, unaligned */
        unsigned char      lee_reclen[2];
        unsigned char      lee_parent_fid[sizeof(struct lu_fid)];
        char               lee_name[0];
}__attribute__((packed));

/** fid2path request/reply structure */
struct getinfo_fid2path {
        struct lu_fid   gf_fid;
        __u64           gf_recno;
        __u32           gf_linkno;
        __u32           gf_pathlen;
        char            gf_path[0];
} __attribute__((packed));

void lustre_swab_fid2path (struct getinfo_fid2path *gf);


#endif
/** @} lustreidl */
