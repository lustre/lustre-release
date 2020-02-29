/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre/lustre_user.h
 *
 * Lustre public user-space interface definitions.
 */

#ifndef _LUSTRE_USER_H
#define _LUSTRE_USER_H

/** \defgroup lustreuser lustreuser
 *
 * @{
 */

#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/quota.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/lustre/lustre_fiemap.h>

#ifndef __KERNEL__
# include <stdbool.h>
# include <stdio.h> /* snprintf() */
# include <sys/stat.h>
# define FILEID_LUSTRE 0x97 /* for name_to_handle_at() (and llapi_fd2fid()) */
#endif /* !__KERNEL__ */

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef __STRICT_ANSI__
#define typeof  __typeof__
#endif

/*
 * This is a temporary solution of adding quota type.
 * Should be removed as soon as system header is updated.
 */
#undef LL_MAXQUOTAS
#define LL_MAXQUOTAS 3
#undef INITQFNAMES
#define INITQFNAMES { \
    "user",	/* USRQUOTA */ \
    "group",	/* GRPQUOTA */ \
    "project",	/* PRJQUOTA */ \
    "undefined", \
};
#ifndef USRQUOTA
#define USRQUOTA 0
#endif
#ifndef GRPQUOTA
#define GRPQUOTA 1
#endif
#ifndef PRJQUOTA
#define PRJQUOTA 2
#endif

/*
 * We need to always use 64bit version because the structure
 * is shared across entire cluster where 32bit and 64bit machines
 * are co-existing.
 */
#if __BITS_PER_LONG != 64 || defined(__ARCH_WANT_STAT64)
typedef struct stat64   lstat_t;
#define lstat_f  lstat64
#define fstat_f         fstat64
#define fstatat_f       fstatat64
#else
typedef struct stat     lstat_t;
#define lstat_f  lstat
#define fstat_f         fstat
#define fstatat_f       fstatat
#endif

#ifndef STATX_BASIC_STATS
/*
 * Timestamp structure for the timestamps in struct statx.
 *
 * tv_sec holds the number of seconds before (negative) or after (positive)
 * 00:00:00 1st January 1970 UTC.
 *
 * tv_nsec holds a number of nanoseconds (0..999,999,999) after the tv_sec time.
 *
 * __reserved is held in case we need a yet finer resolution.
 */
struct statx_timestamp {
	__s64	tv_sec;
	__u32	tv_nsec;
	__s32	__reserved;
};

/*
 * Structures for the extended file attribute retrieval system call
 * (statx()).
 *
 * The caller passes a mask of what they're specifically interested in as a
 * parameter to statx().  What statx() actually got will be indicated in
 * st_mask upon return.
 *
 * For each bit in the mask argument:
 *
 * - if the datum is not supported:
 *
 *   - the bit will be cleared, and
 *
 *   - the datum will be set to an appropriate fabricated value if one is
 *     available (eg. CIFS can take a default uid and gid), otherwise
 *
 *   - the field will be cleared;
 *
 * - otherwise, if explicitly requested:
 *
 *   - the datum will be synchronised to the server if AT_STATX_FORCE_SYNC is
 *     set or if the datum is considered out of date, and
 *
 *   - the field will be filled in and the bit will be set;
 *
 * - otherwise, if not requested, but available in approximate form without any
 *   effort, it will be filled in anyway, and the bit will be set upon return
 *   (it might not be up to date, however, and no attempt will be made to
 *   synchronise the internal state first);
 *
 * - otherwise the field and the bit will be cleared before returning.
 *
 * Items in STATX_BASIC_STATS may be marked unavailable on return, but they
 * will have values installed for compatibility purposes so that stat() and
 * co. can be emulated in userspace.
 */
struct statx {
	/* 0x00 */
	__u32	stx_mask;	/* What results were written [uncond] */
	__u32	stx_blksize;	/* Preferred general I/O size [uncond] */
	__u64	stx_attributes;	/* Flags conveying information about the file [uncond] */
	/* 0x10 */
	__u32	stx_nlink;	/* Number of hard links */
	__u32	stx_uid;	/* User ID of owner */
	__u32	stx_gid;	/* Group ID of owner */
	__u16	stx_mode;	/* File mode */
	__u16	__spare0[1];
	/* 0x20 */
	__u64	stx_ino;	/* Inode number */
	__u64	stx_size;	/* File size */
	__u64	stx_blocks;	/* Number of 512-byte blocks allocated */
	__u64	stx_attributes_mask; /* Mask to show what's supported in stx_attributes */
	/* 0x40 */
	struct statx_timestamp	stx_atime;	/* Last access time */
	struct statx_timestamp	stx_btime;	/* File creation time */
	struct statx_timestamp	stx_ctime;	/* Last attribute change time */
	struct statx_timestamp	stx_mtime;	/* Last data modification time */
	/* 0x80 */
	__u32	stx_rdev_major;	/* Device ID of special file [if bdev/cdev] */
	__u32	stx_rdev_minor;
	__u32	stx_dev_major;	/* ID of device containing file [uncond] */
	__u32	stx_dev_minor;
	/* 0x90 */
	__u64	__spare2[14];	/* Spare space for future expansion */
	/* 0x100 */
};

/*
 * Flags to be stx_mask
 *
 * Query request/result mask for statx() and struct statx::stx_mask.
 *
 * These bits should be set in the mask argument of statx() to request
 * particular items when calling statx().
 */
#define STATX_TYPE		0x00000001U	/* Want/got stx_mode & S_IFMT */
#define STATX_MODE		0x00000002U	/* Want/got stx_mode & ~S_IFMT */
#define STATX_NLINK		0x00000004U	/* Want/got stx_nlink */
#define STATX_UID		0x00000008U	/* Want/got stx_uid */
#define STATX_GID		0x00000010U	/* Want/got stx_gid */
#define STATX_ATIME		0x00000020U	/* Want/got stx_atime */
#define STATX_MTIME		0x00000040U	/* Want/got stx_mtime */
#define STATX_CTIME		0x00000080U	/* Want/got stx_ctime */
#define STATX_INO		0x00000100U	/* Want/got stx_ino */
#define STATX_SIZE		0x00000200U	/* Want/got stx_size */
#define STATX_BLOCKS		0x00000400U	/* Want/got stx_blocks */
#define STATX_BASIC_STATS	0x000007ffU	/* The stuff in the normal stat struct */
#define STATX_BTIME		0x00000800U	/* Want/got stx_btime */
#define STATX_ALL		0x00000fffU	/* All currently supported flags */
#define STATX__RESERVED		0x80000000U	/* Reserved for future struct statx expansion */

/*
 * Attributes to be found in stx_attributes and masked in stx_attributes_mask.
 *
 * These give information about the features or the state of a file that might
 * be of use to ordinary userspace programs such as GUIs or ls rather than
 * specialised tools.
 *
 * Note that the flags marked [I] correspond to generic FS_IOC_FLAGS
 * semantically.  Where possible, the numerical value is picked to correspond
 * also.
 */
#define STATX_ATTR_COMPRESSED		0x00000004 /* [I] File is compressed by the fs */
#define STATX_ATTR_IMMUTABLE		0x00000010 /* [I] File is marked immutable */
#define STATX_ATTR_APPEND		0x00000020 /* [I] File is append-only */
#define STATX_ATTR_NODUMP		0x00000040 /* [I] File is not to be dumped */
#define STATX_ATTR_ENCRYPTED		0x00000800 /* [I] File requires key to decrypt in fs */

#define STATX_ATTR_AUTOMOUNT		0x00001000 /* Dir: Automount trigger */

#endif

typedef struct statx lstatx_t;

#define HAVE_LOV_USER_MDS_DATA

#define LUSTRE_EOF 0xffffffffffffffffULL

/* for statfs() */
#define LL_SUPER_MAGIC 0x0BD00BD0

#define FSFILT_IOC_GETVERSION		_IOR('f', 3, long)

/* FIEMAP flags supported by Lustre */
#define LUSTRE_FIEMAP_FLAGS_COMPAT (FIEMAP_FLAG_SYNC | FIEMAP_FLAG_DEVICE_ORDER)

enum obd_statfs_state {
	OS_STATE_DEGRADED	= 0x00000001, /**< RAID degraded/rebuilding */
	OS_STATE_READONLY	= 0x00000002, /**< filesystem is read-only */
	OS_STATE_NOPRECREATE	= 0x00000004, /**< no object precreation */
	OS_STATE_UNUSED1	= 0x00000008, /**< obsolete 1.6, was EROFS=30 */
	OS_STATE_UNUSED2	= 0x00000010, /**< obsolete 1.6, was EROFS=30 */
	OS_STATE_ENOSPC		= 0x00000020, /**< not enough free space */
	OS_STATE_ENOINO		= 0x00000040, /**< not enough inodes */
	OS_STATE_SUM		= 0x00000100, /**< aggregated for all tagrets */
	OS_STATE_NONROT		= 0x00000200, /**< non-rotational device */
};

/** filesystem statistics/attributes for target device */
struct obd_statfs {
	__u64		os_type;	/* EXT4_SUPER_MAGIC, UBERBLOCK_MAGIC */
	__u64		os_blocks;	/* total size in #os_bsize blocks */
	__u64		os_bfree;	/* number of unused blocks */
	__u64		os_bavail;	/* blocks available for allocation */
	__u64		os_files;	/* total number of objects */
	__u64		os_ffree;	/* # objects that could be created */
	__u8		os_fsid[40];	/* identifier for filesystem */
	__u32		os_bsize;	/* block size in bytes for os_blocks */
	__u32		os_namelen;	/* maximum length of filename in bytes*/
	__u64		os_maxbytes;	/* maximum object size in bytes */
	__u32		os_state;       /**< obd_statfs_state OS_STATE_* flag */
	__u32		os_fprecreated;	/* objs available now to the caller */
					/* used in QoS code to find preferred
					 * OSTs */
	__u32           os_granted;	/* space granted for MDS */
	__u32           os_spare3;	/* Unused padding fields.  Remember */
	__u32           os_spare4;	/* to fix lustre_swab_obd_statfs() */
	__u32           os_spare5;
	__u32           os_spare6;
	__u32           os_spare7;
	__u32           os_spare8;
	__u32           os_spare9;
};

/**
 * File IDentifier.
 *
 * FID is a cluster-wide unique identifier of a file or an object (stripe).
 * FIDs are never reused.
 **/
struct lu_fid {
       /**
	* FID sequence. Sequence is a unit of migration: all files (objects)
	* with FIDs from a given sequence are stored on the same server.
	* Lustre should support 2^64 objects, so even if each sequence
	* has only a single object we can still enumerate 2^64 objects.
	**/
	__u64 f_seq;
	/* FID number within sequence. */
	__u32 f_oid;
	/**
	 * FID version, used to distinguish different versions (in the sense
	 * of snapshots, etc.) of the same file system object. Not currently
	 * used.
	 **/
	__u32 f_ver;
};

static inline bool fid_is_zero(const struct lu_fid *fid)
{
	return fid->f_seq == 0 && fid->f_oid == 0;
}

/* Currently, the filter_fid::ff_parent::f_ver is not the real parent
 * MDT-object's FID::f_ver, instead it is the OST-object index in its
 * parent MDT-object's layout EA. */
#define f_stripe_idx f_ver

struct ost_layout {
	__u32	ol_stripe_size;
	__u32	ol_stripe_count;
	__u64	ol_comp_start;
	__u64	ol_comp_end;
	__u32	ol_comp_id;
} __attribute__((packed));

/* The filter_fid structure has changed several times over its lifetime.
 * For a long time "trusted.fid" held the MDT inode parent FID/IGIF and
 * stripe_index and the "self FID" (objid/seq) to be able to recover the
 * OST objects in case of corruption.  With the move to 2.4 and OSD-API for
 * the OST, the "trusted.lma" xattr was added to the OST objects to store
 * the "self FID" to be consistent with the MDT on-disk format, and the
 * filter_fid only stored the MDT inode parent FID and stripe index.
 *
 * In 2.10, the addition of PFL composite layouts required more information
 * to be stored into the filter_fid in order to be able to identify which
 * component the OST object belonged.  As well, the stripe size may vary
 * between components, so it was no longer safe to assume the stripe size
 * or stripe_count of a file.  This is also more robust for plain layouts.
 *
 * For ldiskfs OSTs that were formatted with 256-byte inodes, there is not
 * enough space to store both the filter_fid and LMA in the inode, so they
 * are packed into struct lustre_ost_attrs on disk in trusted.lma to avoid
 * an extra seek for every OST object access.
 *
 * In 2.11, FLR mirror layouts also need to store the layout version and
 * range so that writes to old versions of the layout are not allowed.
 * That ensures that mirrored objects are not modified by evicted clients,
 * and ensures that the components are correctly marked stale on the MDT.
 */
struct filter_fid_18_23 {
	struct lu_fid		ff_parent;	/* stripe_idx in f_ver */
	__u64			ff_objid;
	__u64			ff_seq;
};

struct filter_fid_24_29 {
	struct lu_fid		ff_parent;	/* stripe_idx in f_ver */
};

struct filter_fid_210 {
	struct lu_fid		ff_parent;	/* stripe_idx in f_ver */
	struct ost_layout	ff_layout;
};

struct filter_fid {
	struct lu_fid		ff_parent;	/* stripe_idx in f_ver */
	struct ost_layout	ff_layout;
	__u32			ff_layout_version;
	__u32			ff_range; /* range of layout version that
					   * write are allowed */
} __attribute__((packed));

/* Userspace should treat lu_fid as opaque, and only use the following methods
 * to print or parse them.  Other functions (e.g. compare, swab) could be moved
 * here from lustre_idl.h if needed. */
struct lu_fid;

enum lma_compat {
	LMAC_HSM	 = 0x00000001,
/*	LMAC_SOM	 = 0x00000002, obsolete since 2.8.0 */
	LMAC_NOT_IN_OI	 = 0x00000004, /* the object does NOT need OI mapping */
	LMAC_FID_ON_OST  = 0x00000008, /* For OST-object, its OI mapping is
				       * under /O/<seq>/d<x>. */
	LMAC_STRIPE_INFO = 0x00000010, /* stripe info in the LMA EA. */
	LMAC_COMP_INFO	 = 0x00000020, /* Component info in the LMA EA. */
	LMAC_IDX_BACKUP  = 0x00000040, /* Has index backup. */
};

/**
 * Masks for all features that should be supported by a Lustre version to
 * access a specific file.
 * This information is stored in lustre_mdt_attrs::lma_incompat.
 */
enum lma_incompat {
	LMAI_RELEASED		= 0x00000001, /* file is released */
	LMAI_AGENT		= 0x00000002, /* agent inode */
	LMAI_REMOTE_PARENT	= 0x00000004, /* the parent of the object
						 is on the remote MDT */
	LMAI_STRIPED		= 0x00000008, /* striped directory inode */
	LMAI_ORPHAN		= 0x00000010, /* inode is orphan */
	LMA_INCOMPAT_SUPP	= (LMAI_AGENT | LMAI_REMOTE_PARENT | \
				   LMAI_STRIPED | LMAI_ORPHAN)
};


/**
 * Following struct for object attributes, that will be kept inode's EA.
 * Introduced in 2.0 release (please see b15993, for details)
 * Added to all objects since Lustre 2.4 as contains self FID
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
};

struct lustre_ost_attrs {
	/* Use lustre_mdt_attrs directly for now, need a common header
	 * structure if want to change lustre_mdt_attrs in future. */
	struct lustre_mdt_attrs loa_lma;

	/* Below five elements are for OST-object's PFID EA, the
	 * lma_parent_fid::f_ver is composed of the stripe_count (high 16 bits)
	 * and the stripe_index (low 16 bits), the size should not exceed
	 * 5 * sizeof(__u64)) to be accessable by old Lustre. If the flag
	 * LMAC_STRIPE_INFO is set, then loa_parent_fid and loa_stripe_size
	 * are valid; if the flag LMAC_COMP_INFO is set, then the next three
	 * loa_comp_* elements are valid. */
	struct lu_fid	loa_parent_fid;
	__u32		loa_stripe_size;
	__u32		loa_comp_id;
	__u64		loa_comp_start;
	__u64		loa_comp_end;
};

/**
 * Prior to 2.4, the LMA structure also included SOM attributes which has since
 * been moved to a dedicated xattr
 * lma_flags was also removed because of lma_compat/incompat fields.
 */
#define LMA_OLD_SIZE (sizeof(struct lustre_mdt_attrs) + 5 * sizeof(__u64))

enum lustre_som_flags {
	/* Unknow or no SoM data, must get size from OSTs. */
	SOM_FL_UNKNOWN	= 0x0000,
	/* Known strictly correct, FLR or DoM file (SoM guaranteed). */
	SOM_FL_STRICT	= 0x0001,
	/* Known stale - was right at some point in the past, but it is
	 * known (or likely) to be incorrect now (e.g. opened for write). */
	SOM_FL_STALE	= 0x0002,
	/* Approximate, may never have been strictly correct,
	 * need to sync SOM data to achieve eventual consistency. */
	SOM_FL_LAZY	= 0x0004,
};

struct lustre_som_attrs {
	__u16	lsa_valid;
	__u16	lsa_reserved[3];
	__u64	lsa_size;
	__u64	lsa_blocks;
};

/**
 * OST object IDentifier.
 */
struct ost_id {
	union {
		struct {
			__u64	oi_id;
			__u64	oi_seq;
		} oi;
		struct lu_fid oi_fid;
	};
};

#define DOSTID "%#llx:%llu"
#define POSTID(oi) ((unsigned long long)ostid_seq(oi)), \
		   ((unsigned long long)ostid_id(oi))

struct ll_futimes_3 {
	__u64 lfu_atime_sec;
	__u64 lfu_atime_nsec;
	__u64 lfu_mtime_sec;
	__u64 lfu_mtime_nsec;
	__u64 lfu_ctime_sec;
	__u64 lfu_ctime_nsec;
};

/*
 * Maximum number of mirrors currently implemented.
 */
#define LUSTRE_MIRROR_COUNT_MAX		16

/* Lease types for use as arg and return of LL_IOC_{GET,SET}_LEASE ioctl. */
enum ll_lease_mode {
	LL_LEASE_RDLCK	= 0x01,
	LL_LEASE_WRLCK	= 0x02,
	LL_LEASE_UNLCK	= 0x04,
};

enum ll_lease_flags {
	LL_LEASE_RESYNC		= 0x1,
	LL_LEASE_RESYNC_DONE	= 0x2,
	LL_LEASE_LAYOUT_MERGE	= 0x4,
	LL_LEASE_LAYOUT_SPLIT	= 0x8,
};

#define IOC_IDS_MAX	4096
struct ll_ioc_lease {
	__u32		lil_mode;
	__u32		lil_flags;
	__u32		lil_count;
	__u32		lil_ids[0];
};

struct ll_ioc_lease_id {
	__u32		lil_mode;
	__u32		lil_flags;
	__u32		lil_count;
	__u16		lil_mirror_id;
	__u16		lil_padding1;
	__u64		lil_padding2;
	__u32		lil_ids[0];
};

/*
 * The ioctl naming rules:
 * LL_*     - works on the currently opened filehandle instead of parent dir
 * *_OBD_*  - gets data for both OSC or MDC (LOV, LMV indirectly)
 * *_MDC_*  - gets/sets data related to MDC
 * *_LOV_*  - gets/sets data related to OSC/LOV
 * *FILE*   - called on parent dir and passes in a filename
 * *STRIPE* - set/get lov_user_md
 * *INFO    - set/get lov_user_mds_data
 */
/*	lustre_ioctl.h			101-150 */
#define LL_IOC_GETFLAGS                 _IOR ('f', 151, long)
#define LL_IOC_SETFLAGS                 _IOW ('f', 152, long)
#define LL_IOC_CLRFLAGS                 _IOW ('f', 153, long)
#define LL_IOC_LOV_SETSTRIPE            _IOW ('f', 154, long)
#define LL_IOC_LOV_SETSTRIPE_NEW	_IOWR('f', 154, struct lov_user_md)
#define LL_IOC_LOV_GETSTRIPE            _IOW ('f', 155, long)
#define LL_IOC_LOV_GETSTRIPE_NEW	_IOR('f', 155, struct lov_user_md)
#define LL_IOC_LOV_SETEA                _IOW ('f', 156, long)
/*	LL_IOC_RECREATE_OBJ             157 obsolete */
/*	LL_IOC_RECREATE_FID             157 obsolete */
#define LL_IOC_GROUP_LOCK               _IOW ('f', 158, long)
#define LL_IOC_GROUP_UNLOCK             _IOW ('f', 159, long)
/*	LL_IOC_QUOTACHECK               160 OBD_IOC_QUOTACHECK */
/*	LL_IOC_POLL_QUOTACHECK		161 OBD_IOC_POLL_QUOTACHECK */
/*	LL_IOC_QUOTACTL			162 OBD_IOC_QUOTACTL */
#define IOC_OBD_STATFS                  _IOWR('f', 164, struct obd_statfs *)
/*	IOC_LOV_GETINFO                 165 obsolete */
#define LL_IOC_FLUSHCTX                 _IOW ('f', 166, long)
/*	LL_IOC_RMTACL                   167 obsolete */
#define LL_IOC_GETOBDCOUNT              _IOR ('f', 168, long)
#define LL_IOC_LLOOP_ATTACH             _IOWR('f', 169, long)
#define LL_IOC_LLOOP_DETACH             _IOWR('f', 170, long)
#define LL_IOC_LLOOP_INFO               _IOWR('f', 171, struct lu_fid)
#define LL_IOC_LLOOP_DETACH_BYDEV       _IOWR('f', 172, long)
#define LL_IOC_PATH2FID                 _IOR ('f', 173, long)
#define LL_IOC_GET_CONNECT_FLAGS        _IOWR('f', 174, __u64 *)
#define LL_IOC_GET_MDTIDX               _IOR ('f', 175, int)
#define LL_IOC_FUTIMES_3		_IOWR('f', 176, struct ll_futimes_3)
#define LL_IOC_FLR_SET_MIRROR		_IOW ('f', 177, long)
/*	lustre_ioctl.h			177-210 */
#define LL_IOC_HSM_STATE_GET		_IOR('f', 211, struct hsm_user_state)
#define LL_IOC_HSM_STATE_SET		_IOW('f', 212, struct hsm_state_set)
#define LL_IOC_HSM_CT_START		_IOW('f', 213, struct lustre_kernelcomm)
#define LL_IOC_HSM_COPY_START		_IOW('f', 214, struct hsm_copy *)
#define LL_IOC_HSM_COPY_END		_IOW('f', 215, struct hsm_copy *)
#define LL_IOC_HSM_PROGRESS		_IOW('f', 216, struct hsm_user_request)
#define LL_IOC_HSM_REQUEST		_IOW('f', 217, struct hsm_user_request)
#define LL_IOC_DATA_VERSION		_IOR('f', 218, struct ioc_data_version)
#define LL_IOC_LOV_SWAP_LAYOUTS		_IOW('f', 219, \
						struct lustre_swap_layouts)
#define LL_IOC_HSM_ACTION		_IOR('f', 220, \
						struct hsm_current_action)
/*	lustre_ioctl.h			221-232 */
#define LL_IOC_LMV_SETSTRIPE		_IOWR('f', 240, struct lmv_user_md)
#define LL_IOC_LMV_GETSTRIPE		_IOWR('f', 241, struct lmv_user_md)
#define LL_IOC_REMOVE_ENTRY		_IOWR('f', 242, __u64)
#define LL_IOC_RMFID			_IOR('f', 242, struct fid_array)
#define LL_IOC_SET_LEASE		_IOWR('f', 243, struct ll_ioc_lease)
#define LL_IOC_SET_LEASE_OLD		_IOWR('f', 243, long)
#define LL_IOC_GET_LEASE		_IO('f', 244)
#define LL_IOC_HSM_IMPORT		_IOWR('f', 245, struct hsm_user_import)
#define LL_IOC_LMV_SET_DEFAULT_STRIPE	_IOWR('f', 246, struct lmv_user_md)
#define LL_IOC_MIGRATE			_IOR('f', 247, int)
#define LL_IOC_FID2MDTIDX		_IOWR('f', 248, struct lu_fid)
#define LL_IOC_GETPARENT		_IOWR('f', 249, struct getparent)
#define LL_IOC_LADVISE			_IOR('f', 250, struct llapi_lu_ladvise)

#ifndef	FS_IOC_FSGETXATTR
/*
 * Structure for FS_IOC_FSGETXATTR and FS_IOC_FSSETXATTR.
*/
struct fsxattr {
	__u32           fsx_xflags;     /* xflags field value (get/set) */
	__u32           fsx_extsize;    /* extsize field value (get/set)*/
	__u32           fsx_nextents;   /* nextents field value (get)   */
	__u32           fsx_projid;     /* project identifier (get/set) */
	unsigned char   fsx_pad[12];
};
#define FS_IOC_FSGETXATTR		_IOR('X', 31, struct fsxattr)
#define FS_IOC_FSSETXATTR		_IOW('X', 32, struct fsxattr)
#endif
#define LL_IOC_FSGETXATTR		FS_IOC_FSGETXATTR
#define LL_IOC_FSSETXATTR		FS_IOC_FSSETXATTR
#ifndef FS_XFLAG_PROJINHERIT
#define FS_XFLAG_PROJINHERIT		0x00000200
#endif


#define LL_STATFS_LMV		1
#define LL_STATFS_LOV		2
#define LL_STATFS_NODELAY	4

#define IOC_MDC_TYPE		'i'
#define IOC_MDC_LOOKUP		_IOWR(IOC_MDC_TYPE, 20, struct obd_device *)
#define IOC_MDC_GETFILESTRIPE	_IOWR(IOC_MDC_TYPE, 21, struct lov_user_md *)
#ifdef HAVE_LOV_USER_MDS_DATA
#define IOC_MDC_GETFILEINFO_OLD	_IOWR(IOC_MDC_TYPE, 22, struct lov_user_mds_data_v1 *)
#define IOC_MDC_GETFILEINFO	_IOWR(IOC_MDC_TYPE, 22, struct lov_user_mds_data)
#define LL_IOC_MDC_GETINFO_OLD	_IOWR(IOC_MDC_TYPE, 23, struct lov_user_mds_data_v1 *)
#define LL_IOC_MDC_GETINFO	_IOWR(IOC_MDC_TYPE, 23, struct lov_user_mds_data)
#endif

#define MAX_OBD_NAME 128 /* If this changes, a NEW ioctl must be added */

/* Define O_LOV_DELAY_CREATE to be a mask that is not useful for regular
 * files, but are unlikely to be used in practice and are not harmful if
 * used incorrectly.  O_NOCTTY and FASYNC are only meaningful for character
 * devices and are safe for use on new files. See LU-4209. */
/* To be compatible with old statically linked binary we keep the check for
 * the older 0100000000 flag.  This is already removed upstream.  LU-812. */
#define O_LOV_DELAY_CREATE_1_8	0100000000 /* FMODE_NONOTIFY masked in 2.6.36 */
#ifndef FASYNC
#define FASYNC			00020000   /* fcntl, for BSD compatibility */
#endif
#define O_LOV_DELAY_CREATE_MASK	(O_NOCTTY | FASYNC)
#define O_LOV_DELAY_CREATE		(O_LOV_DELAY_CREATE_1_8 | \
					 O_LOV_DELAY_CREATE_MASK)

#define LL_FILE_IGNORE_LOCK     0x00000001
#define LL_FILE_GROUP_LOCKED    0x00000002
#define LL_FILE_READAHEA        0x00000004
#define LL_FILE_LOCKED_DIRECTIO 0x00000008 /* client-side locks with dio */
#define LL_FILE_LOCKLESS_IO     0x00000010 /* server-side locks with cio */

#define LOV_USER_MAGIC_V1	0x0BD10BD0
#define LOV_USER_MAGIC		LOV_USER_MAGIC_V1
#define LOV_USER_MAGIC_JOIN_V1	0x0BD20BD0
#define LOV_USER_MAGIC_V3	0x0BD30BD0
/* 0x0BD40BD0 is occupied by LOV_MAGIC_MIGRATE */
#define LOV_USER_MAGIC_SPECIFIC 0x0BD50BD0	/* for specific OSTs */
#define LOV_USER_MAGIC_COMP_V1	0x0BD60BD0

#define LMV_USER_MAGIC		0x0CD30CD0    /* default lmv magic */
#define LMV_USER_MAGIC_V0	0x0CD20CD0    /* old default lmv magic*/
#define LMV_USER_MAGIC_SPECIFIC	0x0CD40CD0

#define LOV_PATTERN_NONE	0x000
#define LOV_PATTERN_RAID0	0x001
#define LOV_PATTERN_RAID1	0x002
#define LOV_PATTERN_MDT		0x100
#define LOV_PATTERN_CMOBD	0x200

#define LOV_PATTERN_F_MASK	0xffff0000
#define LOV_PATTERN_F_HOLE	0x40000000 /* there is hole in LOV EA */
#define LOV_PATTERN_F_RELEASED	0x80000000 /* HSM released file */
#define LOV_PATTERN_DEFAULT	0xffffffff

static inline bool lov_pattern_supported(__u32 pattern)
{
	return (pattern & ~LOV_PATTERN_F_RELEASED) == LOV_PATTERN_RAID0 ||
	       (pattern & ~LOV_PATTERN_F_RELEASED) == LOV_PATTERN_MDT;
}

#define LOV_MAXPOOLNAME 15
#define LOV_POOLNAMEF "%.15s"

#define LOV_MIN_STRIPE_BITS 16   /* maximum PAGE_SIZE (ia64), power of 2 */
#define LOV_MIN_STRIPE_SIZE (1 << LOV_MIN_STRIPE_BITS)
#define LOV_MAX_STRIPE_COUNT_OLD 160
/* This calculation is crafted so that input of 4096 will result in 160
 * which in turn is equal to old maximal stripe count.
 * XXX: In fact this is too simpified for now, what it also need is to get
 * ea_type argument to clearly know how much space each stripe consumes.
 *
 * The limit of 12 pages is somewhat arbitrary, but is a reasonably large
 * allocation that is sufficient for the current generation of systems.
 *
 * (max buffer size - lov+rpc header) / sizeof(struct lov_ost_data_v1) */
#define LOV_MAX_STRIPE_COUNT 2000  /* ((12 * 4096 - 256) / 24) */
#define LOV_ALL_STRIPES       0xffff /* only valid for directories */
#define LOV_V1_INSANE_STRIPE_COUNT 65532 /* maximum stripe count bz13933 */

#define XATTR_LUSTRE_PREFIX	"lustre."
#define XATTR_LUSTRE_LOV	XATTR_LUSTRE_PREFIX"lov"

/* Please update if XATTR_LUSTRE_LOV".set" groks more flags in the future */
#define allowed_lustre_lov(att) (strcmp((att), XATTR_LUSTRE_LOV".add") == 0 || \
			strcmp((att), XATTR_LUSTRE_LOV".set") == 0 || \
			strcmp((att), XATTR_LUSTRE_LOV".set.flags") == 0 || \
			strcmp((att), XATTR_LUSTRE_LOV".del") == 0)

#define lov_user_ost_data lov_user_ost_data_v1
struct lov_user_ost_data_v1 {     /* per-stripe data structure */
	struct ost_id l_ost_oi;	  /* OST object ID */
	__u32 l_ost_gen;          /* generation of this OST index */
	__u32 l_ost_idx;          /* OST index in LOV */
} __attribute__((packed));

#define lov_user_md lov_user_md_v1
struct lov_user_md_v1 {           /* LOV EA user data (host-endian) */
	__u32 lmm_magic;          /* magic number = LOV_USER_MAGIC_V1 */
	__u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
	struct ost_id lmm_oi;	  /* MDT parent inode id/seq (id/0 for 1.x) */
	__u32 lmm_stripe_size;    /* size of stripe in bytes */
	__u16 lmm_stripe_count;   /* num stripes in use for this object */
	union {
		__u16 lmm_stripe_offset;  /* starting stripe offset in
					   * lmm_objects, use when writing */
		__u16 lmm_layout_gen;     /* layout generation number
					   * used when reading */
	};
	struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed,  __may_alias__));

struct lov_user_md_v3 {           /* LOV EA user data (host-endian) */
	__u32 lmm_magic;          /* magic number = LOV_USER_MAGIC_V3 */
	__u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
	struct ost_id lmm_oi;	  /* MDT parent inode id/seq (id/0 for 1.x) */
	__u32 lmm_stripe_size;    /* size of stripe in bytes */
	__u16 lmm_stripe_count;   /* num stripes in use for this object */
	union {
		__u16 lmm_stripe_offset;  /* starting stripe offset in
					   * lmm_objects, use when writing */
		__u16 lmm_layout_gen;     /* layout generation number
					   * used when reading */
	};
	char  lmm_pool_name[LOV_MAXPOOLNAME + 1]; /* pool name */
	struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed));

struct lu_extent {
	__u64	e_start;
	__u64	e_end;
};

#define DEXT "[%#llx, %#llx)"
#define PEXT(ext) (unsigned long long)(ext)->e_start, (unsigned long long)(ext)->e_end

static inline bool lu_extent_is_overlapped(struct lu_extent *e1,
					   struct lu_extent *e2)
{
	return e1->e_start < e2->e_end && e2->e_start < e1->e_end;
}

static inline bool lu_extent_is_whole(struct lu_extent *e)
{
	return e->e_start == 0 && e->e_end == LUSTRE_EOF;
}

enum lov_comp_md_entry_flags {
	LCME_FL_STALE	= 0x00000001,	/* FLR: stale data */
	LCME_FL_PREF_RD	= 0x00000002,	/* FLR: preferred for reading */
	LCME_FL_PREF_WR	= 0x00000004,	/* FLR: preferred for writing */
	LCME_FL_PREF_RW	= LCME_FL_PREF_RD | LCME_FL_PREF_WR,
	LCME_FL_OFFLINE	= 0x00000008,	/* Not used */
	LCME_FL_INIT	= 0x00000010,	/* instantiated */
	LCME_FL_NOSYNC	= 0x00000020,	/* FLR: no sync for the mirror */
	LCME_FL_NEG	= 0x80000000	/* used to indicate a negative flag,
					   won't be stored on disk */
};

#define LCME_KNOWN_FLAGS	(LCME_FL_NEG | LCME_FL_INIT | LCME_FL_STALE | \
				 LCME_FL_PREF_RW | LCME_FL_NOSYNC)
/* The flags can be set by users at mirror creation time. */
#define LCME_USER_FLAGS		(LCME_FL_PREF_RW)

/* The flags are for mirrors */
#define LCME_MIRROR_FLAGS	(LCME_FL_NOSYNC)

/* These flags have meaning when set in a default layout and will be inherited
 * from the default/template layout set on a directory.
 */
#define LCME_TEMPLATE_FLAGS	(LCME_FL_PREF_RW | LCME_FL_NOSYNC)

/* the highest bit in obdo::o_layout_version is used to mark if the file is
 * being resynced. */
#define LU_LAYOUT_RESYNC	LCME_FL_NEG

/* lcme_id can be specified as certain flags, and the the first
 * bit of lcme_id is used to indicate that the ID is representing
 * certain LCME_FL_* but not a real ID. Which implies we can have
 * at most 31 flags (see LCME_FL_XXX). */
enum lcme_id {
	LCME_ID_INVAL	= 0x0,
	LCME_ID_MAX	= 0x7FFFFFFF,
	LCME_ID_ALL	= 0xFFFFFFFF,
	LCME_ID_NOT_ID	= LCME_FL_NEG
};

#define LCME_ID_MASK	LCME_ID_MAX

struct lov_comp_md_entry_v1 {
	__u32			lcme_id;        /* unique id of component */
	__u32			lcme_flags;     /* LCME_FL_XXX */
	struct lu_extent	lcme_extent;    /* file extent for component */
	__u32			lcme_offset;    /* offset of component blob,
						   start from lov_comp_md_v1 */
	__u32			lcme_size;      /* size of component blob */
	__u32			lcme_layout_gen;
	__u64			lcme_timestamp;	/* snapshot time if applicable*/
	__u32			lcme_padding_1;
} __attribute__((packed));

#define SEQ_ID_MAX		0x0000FFFF
#define SEQ_ID_MASK		SEQ_ID_MAX
/* bit 30:16 of lcme_id is used to store mirror id */
#define MIRROR_ID_MASK		0x7FFF0000
#define MIRROR_ID_NEG		0x8000
#define MIRROR_ID_SHIFT		16

static inline __u32 pflr_id(__u16 mirror_id, __u16 seqid)
{
	return ((mirror_id << MIRROR_ID_SHIFT) & MIRROR_ID_MASK) | seqid;
}

static inline __u16 mirror_id_of(__u32 id)
{
	return (id & MIRROR_ID_MASK) >> MIRROR_ID_SHIFT;
}

/**
 * on-disk data for lcm_flags. Valid if lcm_magic is LOV_MAGIC_COMP_V1.
 */
enum lov_comp_md_flags {
	/* the least 2 bits are used by FLR to record file state */
	LCM_FL_NONE          = 0,
	LCM_FL_RDONLY           = 1,
	LCM_FL_WRITE_PENDING    = 2,
	LCM_FL_SYNC_PENDING     = 3,
	LCM_FL_FLR_MASK         = 0x3,
};

struct lov_comp_md_v1 {
	__u32	lcm_magic;      /* LOV_USER_MAGIC_COMP_V1 */
	__u32	lcm_size;       /* overall size including this struct */
	__u32	lcm_layout_gen;
	__u16	lcm_flags;
	__u16	lcm_entry_count;
	/* lcm_mirror_count stores the number of actual mirrors minus 1,
	 * so that non-flr files will have value 0 meaning 1 mirror. */
	__u16	lcm_mirror_count;
	__u16	lcm_padding1[3];
	__u64	lcm_padding2;
	struct lov_comp_md_entry_v1 lcm_entries[0];
} __attribute__((packed));

static inline __u32 lov_user_md_size(__u16 stripes, __u32 lmm_magic)
{
	if (stripes == (__u16)-1)
		stripes = 0;

	if (lmm_magic == LOV_USER_MAGIC_V1)
		return sizeof(struct lov_user_md_v1) +
			      stripes * sizeof(struct lov_user_ost_data_v1);
	return sizeof(struct lov_user_md_v3) +
				stripes * sizeof(struct lov_user_ost_data_v1);
}

/* Compile with -D_LARGEFILE64_SOURCE or -D_GNU_SOURCE (or #define) to
 * use this.  It is unsafe to #define those values in this header as it
 * is possible the application has already #included <sys/stat.h>. */
#ifdef HAVE_LOV_USER_MDS_DATA
#define lov_user_mds_data lov_user_mds_data_v2
struct lov_user_mds_data_v1 {
	lstat_t lmd_st;                 /* MDS stat struct */
	struct lov_user_md_v1 lmd_lmm;  /* LOV EA V1 user data */
} __attribute__((packed));

struct lov_user_mds_data_v2 {
	struct lu_fid lmd_fid;		/* Lustre FID */
	lstatx_t lmd_stx;		/* MDS statx struct */
	__u64 lmd_flags;		/* MDS stat flags */
	__u32 lmd_lmmsize;		/* LOV EA size */
	__u32 lmd_padding;		/* unused */
	struct lov_user_md_v1 lmd_lmm;	/* LOV EA user data */
} __attribute__((packed));
#endif

struct lmv_user_mds_data {
	struct lu_fid	lum_fid;
	__u32		lum_padding;
	__u32		lum_mds;
};

enum lmv_hash_type {
	LMV_HASH_TYPE_UNKNOWN	= 0,	/* 0 is reserved for testing purpose */
	LMV_HASH_TYPE_ALL_CHARS = 1,
	LMV_HASH_TYPE_FNV_1A_64 = 2,
	LMV_HASH_TYPE_MAX,
};

#define LMV_HASH_NAME_ALL_CHARS	"all_char"
#define LMV_HASH_NAME_FNV_1A_64	"fnv_1a_64"

extern char *mdt_hash_name[LMV_HASH_TYPE_MAX];

/* Got this according to how get LOV_MAX_STRIPE_COUNT, see above,
 * (max buffer size - lmv+rpc header) / sizeof(struct lmv_user_mds_data) */
#define LMV_MAX_STRIPE_COUNT 2000  /* ((12 * 4096 - 256) / 24) */
#define lmv_user_md lmv_user_md_v1
struct lmv_user_md_v1 {
	__u32	lum_magic;	 /* must be the first field */
	__u32	lum_stripe_count;  /* dirstripe count */
	__u32	lum_stripe_offset; /* MDT idx for default dirstripe */
	__u32	lum_hash_type;     /* Dir stripe policy */
	__u32	lum_type;	  /* LMV type: default or normal */
	__u32	lum_padding1;
	__u32	lum_padding2;
	__u32	lum_padding3;
	char	lum_pool_name[LOV_MAXPOOLNAME + 1];
	struct	lmv_user_mds_data  lum_objects[0];
} __attribute__((packed));

static inline int lmv_user_md_size(int stripes, int lmm_magic)
{
	int size = sizeof(struct lmv_user_md);

	if (lmm_magic == LMV_USER_MAGIC_SPECIFIC)
		size += stripes * sizeof(struct lmv_user_mds_data);

	return size;
}

struct ll_recreate_obj {
	__u64 lrc_id;
	__u32 lrc_ost_idx;
};

struct ll_fid {
	__u64 id;         /* holds object id */
	__u32 generation; /* holds object generation */
	__u32 f_type;     /* holds object type or stripe idx when passing it to
			   * OST for saving into EA. */
};

#define UUID_MAX        40
struct obd_uuid {
	char uuid[UUID_MAX];
};

static inline bool obd_uuid_equals(const struct obd_uuid *u1,
				   const struct obd_uuid *u2)
{
	return strcmp((char *)u1->uuid, (char *)u2->uuid) == 0;
}

static inline int obd_uuid_empty(struct obd_uuid *uuid)
{
	return uuid->uuid[0] == '\0';
}

static inline void obd_str2uuid(struct obd_uuid *uuid, const char *tmp)
{
	strncpy((char *)uuid->uuid, tmp, sizeof(*uuid));
	uuid->uuid[sizeof(*uuid) - 1] = '\0';
}

/* For printf's only, make sure uuid is terminated */
static inline char *obd_uuid2str(const struct obd_uuid *uuid)
{
	if (uuid == NULL)
		return NULL;

	if (uuid->uuid[sizeof(*uuid) - 1] != '\0') {
		/* Obviously not safe, but for printfs, no real harm done...
		   we're always null-terminated, even in a race. */
		static char temp[sizeof(*uuid)];
		memcpy(temp, uuid->uuid, sizeof(*uuid) - 1);
		temp[sizeof(*uuid) - 1] = '\0';
		return temp;
	}
	return (char *)(uuid->uuid);
}

#define LUSTRE_MAXFSNAME 8

/* Extract fsname from uuid (or target name) of a target
   e.g. (myfs-OST0007_UUID -> myfs)
   see also deuuidify. */
static inline void obd_uuid2fsname(char *buf, char *uuid, int buflen)
{
	char *p;

	strncpy(buf, uuid, buflen - 1);
	buf[buflen - 1] = '\0';
	p = strrchr(buf, '-');
	if (p != NULL)
		*p = '\0';
}

/* printf display format for Lustre FIDs
 * usage: printf("file FID is "DFID"\n", PFID(fid)); */
#define FID_NOBRACE_LEN 40
#define FID_LEN (FID_NOBRACE_LEN + 2)
#define DFID_NOBRACE "%#llx:0x%x:0x%x"
#define DFID "["DFID_NOBRACE"]"
#define PFID(fid) (unsigned long long)(fid)->f_seq, (fid)->f_oid, (fid)->f_ver

/* scanf input parse format for fids in DFID_NOBRACE format
 * Need to strip '[' from DFID format first or use "["SFID"]" at caller.
 * usage: sscanf(fidstr, SFID, RFID(&fid)); */
#define SFID "0x%llx:0x%x:0x%x"
#define RFID(fid) (unsigned long long *)&((fid)->f_seq), &((fid)->f_oid), &((fid)->f_ver)

/********* Quotas **********/

#define LUSTRE_QUOTABLOCK_BITS 10
#define LUSTRE_QUOTABLOCK_SIZE (1 << LUSTRE_QUOTABLOCK_BITS)

static inline __u64 lustre_stoqb(__kernel_size_t space)
{
	return (space + LUSTRE_QUOTABLOCK_SIZE - 1) >> LUSTRE_QUOTABLOCK_BITS;
}

#define Q_QUOTACHECK	0x800100 /* deprecated as of 2.4 */
#define Q_INITQUOTA	0x800101 /* deprecated as of 2.4  */
#define Q_GETOINFO	0x800102 /* get obd quota info */
#define Q_GETOQUOTA	0x800103 /* get obd quotas */
#define Q_FINVALIDATE	0x800104 /* deprecated as of 2.4 */

/* these must be explicitly translated into linux Q_* in ll_dir_ioctl */
#define LUSTRE_Q_QUOTAON    0x800002     /* deprecated as of 2.4 */
#define LUSTRE_Q_QUOTAOFF   0x800003     /* deprecated as of 2.4 */
#define LUSTRE_Q_GETINFO    0x800005     /* get information about quota files */
#define LUSTRE_Q_SETINFO    0x800006     /* set information about quota files */
#define LUSTRE_Q_GETQUOTA   0x800007     /* get user quota structure */
#define LUSTRE_Q_SETQUOTA   0x800008     /* set user quota structure */
/* lustre-specific control commands */
#define LUSTRE_Q_INVALIDATE  0x80000b     /* deprecated as of 2.4 */
#define LUSTRE_Q_FINVALIDATE 0x80000c     /* deprecated as of 2.4 */
#define LUSTRE_Q_GETDEFAULT  0x80000d     /* get default quota */
#define LUSTRE_Q_SETDEFAULT  0x80000e     /* set default quota */

/* In the current Lustre implementation, the grace time is either the time
 * or the timestamp to be used after some quota ID exceeds the soft limt,
 * 48 bits should be enough, its high 16 bits can be used as quota flags.
 * */
#define LQUOTA_GRACE_BITS	48
#define LQUOTA_GRACE_MASK	((1ULL << LQUOTA_GRACE_BITS) - 1)
#define LQUOTA_GRACE_MAX	LQUOTA_GRACE_MASK
#define LQUOTA_GRACE(t)		(t & LQUOTA_GRACE_MASK)
#define LQUOTA_FLAG(t)		(t >> LQUOTA_GRACE_BITS)
#define LQUOTA_GRACE_FLAG(t, f)	((__u64)t | (__u64)f << LQUOTA_GRACE_BITS)

/* different quota flags */

/* the default quota flag, the corresponding quota ID will use the default
 * quota setting, the hardlimit and softlimit of its quota record in the global
 * quota file will be set to 0, the low 48 bits of the grace will be set to 0
 * and high 16 bits will contain this flag (see above comment).
 * */
#define LQUOTA_FLAG_DEFAULT	0x0001

#define ALLQUOTA 255       /* set all quota */
static inline char *qtype_name(int qtype)
{
	switch (qtype) {
	case USRQUOTA:
		return "usr";
	case GRPQUOTA:
		return "grp";
	case PRJQUOTA:
		return "prj";
	}
	return "unknown";
}

#define IDENTITY_DOWNCALL_MAGIC 0x6d6dd629
#define SEPOL_DOWNCALL_MAGIC 0x8b8bb842

/* permission */
#define N_PERMS_MAX      64

struct perm_downcall_data {
	__u64 pdd_nid;
	__u32 pdd_perm;
	__u32 pdd_padding;
};

struct identity_downcall_data {
	__u32                            idd_magic;
	__u32                            idd_err;
	__u32                            idd_uid;
	__u32                            idd_gid;
	__u32                            idd_nperms;
	__u32                            idd_ngroups;
	struct perm_downcall_data idd_perms[N_PERMS_MAX];
	__u32                            idd_groups[0];
};

struct sepol_downcall_data {
	__u32		sdd_magic;
	__kernel_time_t	sdd_sepol_mtime;
	__u16		sdd_sepol_len;
	char		sdd_sepol[0];
};

#ifdef NEED_QUOTA_DEFS
#ifndef QIF_BLIMITS
#define QIF_BLIMITS     1
#define QIF_SPACE       2
#define QIF_ILIMITS     4
#define QIF_INODES      8
#define QIF_BTIME       16
#define QIF_ITIME       32
#define QIF_LIMITS      (QIF_BLIMITS | QIF_ILIMITS)
#define QIF_USAGE       (QIF_SPACE | QIF_INODES)
#define QIF_TIMES       (QIF_BTIME | QIF_ITIME)
#define QIF_ALL         (QIF_LIMITS | QIF_USAGE | QIF_TIMES)
#endif

#endif /* !__KERNEL__ */

/* lustre volatile file support
 * file name header: ".^L^S^T^R:volatile"
 */
#define LUSTRE_VOLATILE_HDR	".\x0c\x13\x14\x12:VOLATILE"
#define LUSTRE_VOLATILE_HDR_LEN	14

enum lustre_quota_version {
	LUSTRE_QUOTA_V2 = 1
};

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
	__u32 dqb_padding;
};

enum {
	QC_GENERAL      = 0,
	QC_MDTIDX       = 1,
	QC_OSTIDX       = 2,
	QC_UUID         = 3
};

struct if_quotactl {
	__u32                   qc_cmd;
	__u32                   qc_type;
	__u32                   qc_id;
	__u32                   qc_stat;
	__u32                   qc_valid;
	__u32                   qc_idx;
	struct obd_dqinfo       qc_dqinfo;
	struct obd_dqblk        qc_dqblk;
	char                    obd_type[16];
	struct obd_uuid         obd_uuid;
};

/* swap layout flags */
#define SWAP_LAYOUTS_CHECK_DV1		(1 << 0)
#define SWAP_LAYOUTS_CHECK_DV2		(1 << 1)
#define SWAP_LAYOUTS_KEEP_MTIME		(1 << 2)
#define SWAP_LAYOUTS_KEEP_ATIME		(1 << 3)
#define SWAP_LAYOUTS_CLOSE		(1 << 4)

/* Swap XATTR_NAME_HSM as well, only on the MDT so far */
#define SWAP_LAYOUTS_MDS_HSM		(1 << 31)
struct lustre_swap_layouts {
	__u64	sl_flags;
	__u32	sl_fd;
	__u32	sl_gid;
	__u64	sl_dv1;
	__u64	sl_dv2;
};

/** Bit-mask of valid attributes */
/* The LA_* flags are written to disk as part of the ChangeLog records
 * so they are part of the on-disk and network protocol, and cannot be changed.
 * Only the first 12 bits are currently saved.
 */
enum la_valid {
	LA_ATIME	= 1 << 0,	/* 0x00001 */
	LA_MTIME	= 1 << 1,	/* 0x00002 */
	LA_CTIME	= 1 << 2,	/* 0x00004 */
	LA_SIZE		= 1 << 3,	/* 0x00008 */
	LA_MODE		= 1 << 4,	/* 0x00010 */
	LA_UID		= 1 << 5,	/* 0x00020 */
	LA_GID		= 1 << 6,	/* 0x00040 */
	LA_BLOCKS	= 1 << 7,	/* 0x00080 */
	LA_TYPE		= 1 << 8,	/* 0x00100 */
	LA_FLAGS	= 1 << 9,	/* 0x00200 */
	LA_NLINK	= 1 << 10,	/* 0x00400 */
	LA_RDEV		= 1 << 11,	/* 0x00800 */
	LA_BLKSIZE	= 1 << 12,	/* 0x01000 */
	LA_KILL_SUID	= 1 << 13,	/* 0x02000 */
	LA_KILL_SGID	= 1 << 14,	/* 0x04000 */
	LA_PROJID	= 1 << 15,	/* 0x08000 */
	LA_LAYOUT_VERSION = 1 << 16,	/* 0x10000 */
	LA_LSIZE	= 1 << 17,	/* 0x20000 */
	LA_LBLOCKS	= 1 << 18,	/* 0x40000 */
	/**
	 * Attributes must be transmitted to OST objects
	 */
	LA_REMOTE_ATTR_SET = (LA_UID | LA_GID | LA_PROJID | LA_LAYOUT_VERSION)
};

#define MDS_FMODE_READ           00000001
#define MDS_FMODE_WRITE          00000002

#define MDS_FMODE_CLOSED         00000000
#define MDS_FMODE_EXEC           00000004
/*	MDS_FMODE_EPOCH          01000000 obsolete since 2.8.0 */
/*	MDS_FMODE_TRUNC          02000000 obsolete since 2.8.0 */
/*	MDS_FMODE_SOM            04000000 obsolete since 2.8.0 */

#define MDS_OPEN_CREATED         00000010
/*	MDS_OPEN_CROSS           00000020 obsolete in 2.12, internal use only */

#define MDS_OPEN_CREAT           00000100
#define MDS_OPEN_EXCL            00000200
#define MDS_OPEN_TRUNC           00001000
#define MDS_OPEN_APPEND          00002000
#define MDS_OPEN_SYNC            00010000
#define MDS_OPEN_DIRECTORY       00200000

#define MDS_OPEN_BY_FID		040000000 /* open_by_fid for known object */
#define MDS_OPEN_DELAY_CREATE  0100000000 /* delay initial object create */
#define MDS_OPEN_OWNEROVERRIDE 0200000000 /* NFSD rw-reopen ro file for owner */
#define MDS_OPEN_JOIN_FILE     0400000000 /* open for join file.
					   * We do not support JOIN FILE
					   * anymore, reserve this flags
					   * just for preventing such bit
					   * to be reused. */

#define MDS_OPEN_LOCK         04000000000 /* This open requires open lock */
#define MDS_OPEN_HAS_EA      010000000000 /* specify object create pattern */
#define MDS_OPEN_HAS_OBJS    020000000000 /* Just set the EA the obj exist */
#define MDS_OPEN_NORESTORE  0100000000000ULL /* Do not restore file at open */
#define MDS_OPEN_NEWSTRIPE  0200000000000ULL /* New stripe needed (restripe or
					      * hsm restore) */
#define MDS_OPEN_VOLATILE   0400000000000ULL /* File is volatile = created
						unlinked */
#define MDS_OPEN_LEASE	   01000000000000ULL /* Open the file and grant lease
					      * delegation, succeed if it's not
					      * being opened with conflict mode.
					      */
#define MDS_OPEN_RELEASE   02000000000000ULL /* Open the file for HSM release */

#define MDS_OPEN_RESYNC    04000000000000ULL /* FLR: file resync */

/* lustre internal open flags, which should not be set from user space */
#define MDS_OPEN_FL_INTERNAL (MDS_OPEN_HAS_EA | MDS_OPEN_HAS_OBJS |	\
			      MDS_OPEN_OWNEROVERRIDE | MDS_OPEN_LOCK |	\
			      MDS_OPEN_BY_FID | MDS_OPEN_LEASE |	\
			      MDS_OPEN_RELEASE | MDS_OPEN_RESYNC)


/********* Changelogs **********/
/** Changelog record types */
enum changelog_rec_type {
	CL_NONE     = -1,
	CL_MARK     = 0,
	CL_CREATE   = 1,  /* namespace */
	CL_MKDIR    = 2,  /* namespace */
	CL_HARDLINK = 3,  /* namespace */
	CL_SOFTLINK = 4,  /* namespace */
	CL_MKNOD    = 5,  /* namespace */
	CL_UNLINK   = 6,  /* namespace */
	CL_RMDIR    = 7,  /* namespace */
	CL_RENAME   = 8,  /* namespace */
	CL_EXT      = 9,  /* namespace extended record (2nd half of rename) */
	CL_OPEN     = 10, /* not currently used */
	CL_CLOSE    = 11, /* may be written to log only with mtime change */
	CL_LAYOUT   = 12, /* file layout/striping modified */
	CL_TRUNC    = 13,
	CL_SETATTR  = 14,
	CL_SETXATTR = 15,
	CL_XATTR    = CL_SETXATTR, /* Deprecated name */
	CL_HSM      = 16, /* HSM specific events, see flags */
	CL_MTIME    = 17, /* Precedence: setattr > mtime > ctime > atime */
	CL_CTIME    = 18,
	CL_ATIME    = 19,
	CL_MIGRATE  = 20,
	CL_FLRW     = 21, /* FLR: file was firstly written */
	CL_RESYNC   = 22, /* FLR: file was resync-ed */
	CL_GETXATTR = 23,
	CL_DN_OPEN  = 24, /* denied open */
	CL_LAST
};

static inline const char *changelog_type2str(int type) {
	static const char *changelog_str[] = {
		"MARK",  "CREAT", "MKDIR", "HLINK", "SLINK", "MKNOD", "UNLNK",
		"RMDIR", "RENME", "RNMTO", "OPEN",  "CLOSE", "LYOUT", "TRUNC",
		"SATTR", "XATTR", "HSM",   "MTIME", "CTIME", "ATIME", "MIGRT",
		"FLRW",  "RESYNC","GXATR", "NOPEN",
	};

	if (type >= 0 && type < CL_LAST)
		return changelog_str[type];
	return NULL;
}

/* 12 bits of per-record data can be stored in the bottom of the flags */
#define CLF_FLAGSHIFT   12
enum changelog_rec_flags {
	CLF_VERSION	= 0x1000,
	CLF_RENAME	= 0x2000,
	CLF_JOBID	= 0x4000,
	CLF_EXTRA_FLAGS = 0x8000,
	CLF_SUPPORTED	= CLF_VERSION | CLF_RENAME | CLF_JOBID |
			  CLF_EXTRA_FLAGS,
	CLF_FLAGMASK	= (1U << CLF_FLAGSHIFT) - 1,
	CLF_VERMASK	= ~CLF_FLAGMASK,
};


/* Anything under the flagmask may be per-type (if desired) */
/* Flags for unlink */
#define CLF_UNLINK_LAST       0x0001 /* Unlink of last hardlink */
#define CLF_UNLINK_HSM_EXISTS 0x0002 /* File has something in HSM */
				     /* HSM cleaning needed */
/* Flags for rename */
#define CLF_RENAME_LAST		0x0001 /* rename unlink last hardlink
					* of target */
#define CLF_RENAME_LAST_EXISTS	0x0002 /* rename unlink last hardlink of target
					* has an archive in backend */

/* Flags for HSM */
/* 12b used (from high weight to low weight):
 * 2b for flags
 * 3b for event
 * 7b for error code
 */
#define CLF_HSM_ERR_L        0 /* HSM return code, 7 bits */
#define CLF_HSM_ERR_H        6
#define CLF_HSM_EVENT_L      7 /* HSM event, 3 bits, see enum hsm_event */
#define CLF_HSM_EVENT_H      9
#define CLF_HSM_FLAG_L      10 /* HSM flags, 2 bits, 1 used, 1 spare */
#define CLF_HSM_FLAG_H      11
#define CLF_HSM_SPARE_L     12 /* 4 spare bits */
#define CLF_HSM_SPARE_H     15
#define CLF_HSM_LAST        15

/* Remove bits higher than _h, then extract the value
 * between _h and _l by shifting lower weigth to bit 0. */
#define CLF_GET_BITS(_b, _h, _l) (((_b << (CLF_HSM_LAST - _h)) & 0xFFFF) \
				   >> (CLF_HSM_LAST - _h + _l))

#define CLF_HSM_SUCCESS      0x00
#define CLF_HSM_MAXERROR     0x7E
#define CLF_HSM_ERROVERFLOW  0x7F

#define CLF_HSM_DIRTY        1 /* file is dirty after HSM request end */

/* 3 bits field => 8 values allowed */
enum hsm_event {
	HE_ARCHIVE      = 0,
	HE_RESTORE      = 1,
	HE_CANCEL       = 2,
	HE_RELEASE      = 3,
	HE_REMOVE       = 4,
	HE_STATE        = 5,
	HE_SPARE1       = 6,
	HE_SPARE2       = 7,
};

static inline enum hsm_event hsm_get_cl_event(__u16 flags)
{
	return (enum hsm_event)CLF_GET_BITS(flags, CLF_HSM_EVENT_H,
					    CLF_HSM_EVENT_L);
}

static inline void hsm_set_cl_event(enum changelog_rec_flags *clf_flags,
				    enum hsm_event he)
{
	*clf_flags |= (he << CLF_HSM_EVENT_L);
}

static inline __u16 hsm_get_cl_flags(enum changelog_rec_flags clf_flags)
{
	return CLF_GET_BITS(clf_flags, CLF_HSM_FLAG_H, CLF_HSM_FLAG_L);
}

static inline void hsm_set_cl_flags(enum changelog_rec_flags *clf_flags,
				    unsigned int bits)
{
	*clf_flags |= (bits << CLF_HSM_FLAG_L);
}

static inline int hsm_get_cl_error(enum changelog_rec_flags clf_flags)
{
	return CLF_GET_BITS(clf_flags, CLF_HSM_ERR_H, CLF_HSM_ERR_L);
}

static inline void hsm_set_cl_error(enum changelog_rec_flags *clf_flags,
				    unsigned int error)
{
	*clf_flags |= (error << CLF_HSM_ERR_L);
}

enum changelog_rec_extra_flags {
	CLFE_INVALID	= 0,
	CLFE_UIDGID	= 0x0001,
	CLFE_NID	= 0x0002,
	CLFE_OPEN	= 0x0004,
	CLFE_XATTR	= 0x0008,
	CLFE_SUPPORTED	= CLFE_UIDGID | CLFE_NID | CLFE_OPEN | CLFE_XATTR
};

enum changelog_send_flag {
	/* Not yet implemented */
	CHANGELOG_FLAG_FOLLOW      = 0x01,
	/* Blocking IO makes sense in case of slow user parsing of the records,
	 * but it also prevents us from cleaning up if the records are not
	 * consumed. */
	CHANGELOG_FLAG_BLOCK       = 0x02,
	/* Pack jobid into the changelog records if available. */
	CHANGELOG_FLAG_JOBID       = 0x04,
	/* Pack additional flag bits into the changelog record */
	CHANGELOG_FLAG_EXTRA_FLAGS = 0x08,
};

enum changelog_send_extra_flag {
	/* Pack uid/gid into the changelog record */
	CHANGELOG_EXTRA_FLAG_UIDGID = 0x01,
	/* Pack nid into the changelog record */
	CHANGELOG_EXTRA_FLAG_NID    = 0x02,
	/* Pack open mode into the changelog record */
	CHANGELOG_EXTRA_FLAG_OMODE  = 0x04,
	/* Pack xattr name into the changelog record */
	CHANGELOG_EXTRA_FLAG_XATTR  = 0x08,
};

#define CR_MAXSIZE __ALIGN_KERNEL(2 * NAME_MAX + 2 + \
				  changelog_rec_offset(CLF_SUPPORTED, \
						       CLFE_SUPPORTED), 8)

/* 31 usable bytes string + null terminator. */
#define LUSTRE_JOBID_SIZE	32

/* This is the minimal changelog record. It can contain extensions
 * such as rename fields or process jobid. Its exact content is described
 * by the cr_flags and cr_extra_flags.
 *
 * Extensions are packed in the same order as their corresponding flags,
 * then in the same order as their corresponding extra flags.
 */
struct changelog_rec {
	__u16			cr_namelen;
	__u16			cr_flags; /**< \a changelog_rec_flags */
	__u32			cr_type;  /**< \a changelog_rec_type */
	__u64			cr_index; /**< changelog record number */
	__u64			cr_prev;  /**< last index for this target fid */
	__u64			cr_time;
	union {
		struct lu_fid	cr_tfid;        /**< target fid */
		__u32		cr_markerflags; /**< CL_MARK flags */
	};
	struct lu_fid		cr_pfid;        /**< parent fid */
};

/* Changelog extension for RENAME. */
struct changelog_ext_rename {
	struct lu_fid		cr_sfid;     /**< source fid, or zero */
	struct lu_fid		cr_spfid;    /**< source parent fid, or zero */
};

/* Changelog extension to include JOBID. */
struct changelog_ext_jobid {
	char	cr_jobid[LUSTRE_JOBID_SIZE];	/**< zero-terminated string. */
};

/* Changelog extension to include additional flags. */
struct changelog_ext_extra_flags {
	__u64 cr_extra_flags; /* Additional CLFE_* flags */
};

/* Changelog extra extension to include UID/GID. */
struct changelog_ext_uidgid {
	__u64	cr_uid;
	__u64	cr_gid;
};

/* Changelog extra extension to include NID. */
struct changelog_ext_nid {
	/* have __u64 instead of lnet_nid_t type for use by client api */
	__u64 cr_nid;
	/* for use when IPv6 support is added */
	__u64 extra;
	__u32 padding;
};

/* Changelog extra extension to include low 32 bits of MDS_OPEN_* flags. */
struct changelog_ext_openmode {
	__u32 cr_openflags;
};

/* Changelog extra extension to include xattr */
struct changelog_ext_xattr {
	char cr_xattr[XATTR_NAME_MAX + 1]; /**< zero-terminated string. */
};

static inline struct changelog_ext_extra_flags *changelog_rec_extra_flags(
	const struct changelog_rec *rec);

static inline __kernel_size_t changelog_rec_offset(enum changelog_rec_flags crf,
					  enum changelog_rec_extra_flags cref)
{
	__kernel_size_t size = sizeof(struct changelog_rec);

	if (crf & CLF_RENAME)
		size += sizeof(struct changelog_ext_rename);

	if (crf & CLF_JOBID)
		size += sizeof(struct changelog_ext_jobid);

	if (crf & CLF_EXTRA_FLAGS) {
		size += sizeof(struct changelog_ext_extra_flags);
		if (cref & CLFE_UIDGID)
			size += sizeof(struct changelog_ext_uidgid);
		if (cref & CLFE_NID)
			size += sizeof(struct changelog_ext_nid);
		if (cref & CLFE_OPEN)
			size += sizeof(struct changelog_ext_openmode);
		if (cref & CLFE_XATTR)
			size += sizeof(struct changelog_ext_xattr);
	}

	return size;
}

static inline __kernel_size_t changelog_rec_size(const struct changelog_rec *rec)
{
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = changelog_rec_extra_flags(rec)->cr_extra_flags;

	return changelog_rec_offset(rec->cr_flags, cref);
}

static inline __kernel_size_t changelog_rec_varsize(const struct changelog_rec *rec)
{
	return changelog_rec_size(rec) - sizeof(*rec) + rec->cr_namelen;
}

static inline
struct changelog_ext_rename *changelog_rec_rename(const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = rec->cr_flags & CLF_VERSION;

	return (struct changelog_ext_rename *)((char *)rec +
					       changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The jobid follows the rename extension, if present */
static inline
struct changelog_ext_jobid *changelog_rec_jobid(const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = rec->cr_flags &
					(CLF_VERSION | CLF_RENAME);

	return (struct changelog_ext_jobid *)((char *)rec +
					      changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The additional flags follow the rename and jobid extensions, if present */
static inline
struct changelog_ext_extra_flags *changelog_rec_extra_flags(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = rec->cr_flags &
		(CLF_VERSION | CLF_RENAME | CLF_JOBID);

	return (struct changelog_ext_extra_flags *)((char *)rec +
						 changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The uid/gid is the first extra extension */
static inline
struct changelog_ext_uidgid *changelog_rec_uidgid(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = rec->cr_flags &
		(CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS);

	return (struct changelog_ext_uidgid *)((char *)rec +
					       changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The nid is the second extra extension */
static inline
struct changelog_ext_nid *changelog_rec_nid(const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = rec->cr_flags &
		(CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS);
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = changelog_rec_extra_flags(rec)->cr_extra_flags &
		       CLFE_UIDGID;

	return (struct changelog_ext_nid *)((char *)rec +
					    changelog_rec_offset(crf, cref));
}

/* The OPEN mode is the third extra extension */
static inline
struct changelog_ext_openmode *changelog_rec_openmode(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = rec->cr_flags &
		(CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS);
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = changelog_rec_extra_flags(rec)->cr_extra_flags &
		       (CLFE_UIDGID | CLFE_NID);

	return (struct changelog_ext_openmode *)((char *)rec +
					       changelog_rec_offset(crf, cref));
}

/* The xattr name is the fourth extra extension */
static inline
struct changelog_ext_xattr *changelog_rec_xattr(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = rec->cr_flags &
		(CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS);
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = changelog_rec_extra_flags(rec)->cr_extra_flags &
			(CLFE_UIDGID | CLFE_NID | CLFE_OPEN);

	return (struct changelog_ext_xattr *)((char *)rec +
					      changelog_rec_offset(crf, cref));
}

/* The name follows the rename, jobid  and extra flags extns, if present */
static inline char *changelog_rec_name(const struct changelog_rec *rec)
{
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = changelog_rec_extra_flags(rec)->cr_extra_flags;

	return (char *)rec + changelog_rec_offset(rec->cr_flags & CLF_SUPPORTED,
						  cref & CLFE_SUPPORTED);
}

static inline __kernel_size_t changelog_rec_snamelen(const struct changelog_rec *rec)
{
	return rec->cr_namelen - strlen(changelog_rec_name(rec)) - 1;
}

static inline char *changelog_rec_sname(const struct changelog_rec *rec)
{
	char *cr_name = changelog_rec_name(rec);

	return cr_name + strlen(cr_name) + 1;
}

/**
 * Remap a record to the desired format as specified by the crf flags.
 * The record must be big enough to contain the final remapped version.
 * Superfluous extension fields are removed and missing ones are added
 * and zeroed. The flags of the record are updated accordingly.
 *
 * The jobid and rename extensions can be added to a record, to match the
 * format an application expects, typically. In this case, the newly added
 * fields will be zeroed.
 * The Jobid field can be removed, to guarantee compatibility with older
 * clients that don't expect this field in the records they process.
 *
 * The following assumptions are being made:
 *   - CLF_RENAME will not be removed
 *   - CLF_JOBID will not be added without CLF_RENAME being added too
 *   - CLF_EXTRA_FLAGS will not be added without CLF_JOBID being added too
 *
 * @param[in,out]  rec         The record to remap.
 * @param[in]      crf_wanted  Flags describing the desired extensions.
 * @param[in]      cref_want   Flags describing the desired extra extensions.
 */
static inline void changelog_remap_rec(struct changelog_rec *rec,
				       enum changelog_rec_flags crf_wanted,
				       enum changelog_rec_extra_flags cref_want)
{
	char *xattr_mov = NULL;
	char *omd_mov = NULL;
	char *nid_mov = NULL;
	char *uidgid_mov = NULL;
	char *ef_mov;
	char *jid_mov;
	char *rnm_mov;
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	crf_wanted &= CLF_SUPPORTED;
	cref_want &= CLFE_SUPPORTED;

	if ((rec->cr_flags & CLF_SUPPORTED) == crf_wanted) {
		if (!(rec->cr_flags & CLF_EXTRA_FLAGS) ||
		    (rec->cr_flags & CLF_EXTRA_FLAGS &&
		    (changelog_rec_extra_flags(rec)->cr_extra_flags &
							CLFE_SUPPORTED) ==
								     cref_want))
			return;
	}

	/* First move the variable-length name field */
	memmove((char *)rec + changelog_rec_offset(crf_wanted, cref_want),
		changelog_rec_name(rec), rec->cr_namelen);

	/* Locations of extensions in the remapped record */
	if (rec->cr_flags & CLF_EXTRA_FLAGS) {
		xattr_mov = (char *)rec +
			changelog_rec_offset(crf_wanted & CLF_SUPPORTED,
					     cref_want & ~CLFE_XATTR);
		omd_mov = (char *)rec +
			changelog_rec_offset(crf_wanted & CLF_SUPPORTED,
					     cref_want & ~(CLFE_OPEN |
							   CLFE_XATTR));
		nid_mov = (char *)rec +
			changelog_rec_offset(crf_wanted & CLF_SUPPORTED,
					     cref_want & ~(CLFE_NID |
							   CLFE_OPEN |
							   CLFE_XATTR));
		uidgid_mov = (char *)rec +
			changelog_rec_offset(crf_wanted & CLF_SUPPORTED,
					     cref_want & ~(CLFE_UIDGID |
							   CLFE_NID |
							   CLFE_OPEN |
							   CLFE_XATTR));
		cref = changelog_rec_extra_flags(rec)->cr_extra_flags;
	}

	ef_mov  = (char *)rec +
		  changelog_rec_offset(crf_wanted & ~CLF_EXTRA_FLAGS,
				       CLFE_INVALID);
	jid_mov = (char *)rec +
		  changelog_rec_offset(crf_wanted &
				       ~(CLF_EXTRA_FLAGS | CLF_JOBID),
				       CLFE_INVALID);
	rnm_mov = (char *)rec +
		  changelog_rec_offset(crf_wanted &
				       ~(CLF_EXTRA_FLAGS |
					 CLF_JOBID |
					 CLF_RENAME),
				       CLFE_INVALID);

	/* Move the extension fields to the desired positions */
	if ((crf_wanted & CLF_EXTRA_FLAGS) &&
	    (rec->cr_flags & CLF_EXTRA_FLAGS)) {
		if ((cref_want & CLFE_XATTR) && (cref & CLFE_XATTR))
			memmove(xattr_mov, changelog_rec_xattr(rec),
				sizeof(struct changelog_ext_xattr));

		if ((cref_want & CLFE_OPEN) && (cref & CLFE_OPEN))
			memmove(omd_mov, changelog_rec_openmode(rec),
				sizeof(struct changelog_ext_openmode));

		if ((cref_want & CLFE_NID) && (cref & CLFE_NID))
			memmove(nid_mov, changelog_rec_nid(rec),
				sizeof(struct changelog_ext_nid));

		if ((cref_want & CLFE_UIDGID) && (cref & CLFE_UIDGID))
			memmove(uidgid_mov, changelog_rec_uidgid(rec),
				sizeof(struct changelog_ext_uidgid));

		memmove(ef_mov, changelog_rec_extra_flags(rec),
			sizeof(struct changelog_ext_extra_flags));
	}

	if ((crf_wanted & CLF_JOBID) && (rec->cr_flags & CLF_JOBID))
		memmove(jid_mov, changelog_rec_jobid(rec),
			sizeof(struct changelog_ext_jobid));

	if ((crf_wanted & CLF_RENAME) && (rec->cr_flags & CLF_RENAME))
		memmove(rnm_mov, changelog_rec_rename(rec),
			sizeof(struct changelog_ext_rename));

	/* Clear newly added fields */
	if (xattr_mov && (cref_want & CLFE_XATTR) &&
	    !(cref & CLFE_XATTR))
		memset(xattr_mov, 0, sizeof(struct changelog_ext_xattr));

	if (omd_mov && (cref_want & CLFE_OPEN) &&
	    !(cref & CLFE_OPEN))
		memset(omd_mov, 0, sizeof(struct changelog_ext_openmode));

	if (nid_mov && (cref_want & CLFE_NID) &&
	    !(cref & CLFE_NID))
		memset(nid_mov, 0, sizeof(struct changelog_ext_nid));

	if (uidgid_mov && (cref_want & CLFE_UIDGID) &&
	    !(cref & CLFE_UIDGID))
		memset(uidgid_mov, 0, sizeof(struct changelog_ext_uidgid));

	if ((crf_wanted & CLF_EXTRA_FLAGS) &&
	    !(rec->cr_flags & CLF_EXTRA_FLAGS))
		memset(ef_mov, 0, sizeof(struct changelog_ext_extra_flags));

	if ((crf_wanted & CLF_JOBID) && !(rec->cr_flags & CLF_JOBID))
		memset(jid_mov, 0, sizeof(struct changelog_ext_jobid));

	if ((crf_wanted & CLF_RENAME) && !(rec->cr_flags & CLF_RENAME))
		memset(rnm_mov, 0, sizeof(struct changelog_ext_rename));

	/* Update the record's flags accordingly */
	rec->cr_flags = (rec->cr_flags & CLF_FLAGMASK) | crf_wanted;
	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		changelog_rec_extra_flags(rec)->cr_extra_flags =
			changelog_rec_extra_flags(rec)->cr_extra_flags |
			cref_want;
}

enum changelog_message_type {
	CL_RECORD = 10, /* message is a changelog_rec */
	CL_EOF    = 11, /* at end of current changelog */
};

/********* Misc **********/

struct ioc_data_version {
	__u64	idv_version;
	__u32	idv_layout_version; /* FLR: layout version for OST objects */
	__u32	idv_flags;	/* enum ioc_data_version_flags */
};

enum ioc_data_version_flags {
	LL_DV_RD_FLUSH	= (1 << 0), /* Flush dirty pages from clients */
	LL_DV_WR_FLUSH	= (1 << 1), /* Flush all caching pages from clients */
};

#ifndef offsetof
#define offsetof(typ, memb)     ((unsigned long)((char *)&(((typ *)0)->memb)))
#endif

#define dot_lustre_name ".lustre"


/********* HSM **********/

/** HSM per-file state
 * See HSM_FLAGS below.
 */
enum hsm_states {
	HS_NONE		= 0x00000000,
	HS_EXISTS	= 0x00000001,
	HS_DIRTY	= 0x00000002,
	HS_RELEASED	= 0x00000004,
	HS_ARCHIVED	= 0x00000008,
	HS_NORELEASE	= 0x00000010,
	HS_NOARCHIVE	= 0x00000020,
	HS_LOST		= 0x00000040,
};

/* HSM user-setable flags. */
#define HSM_USER_MASK   (HS_NORELEASE | HS_NOARCHIVE | HS_DIRTY)

/* Other HSM flags. */
#define HSM_STATUS_MASK (HS_EXISTS | HS_LOST | HS_RELEASED | HS_ARCHIVED)

/*
 * All HSM-related possible flags that could be applied to a file.
 * This should be kept in sync with hsm_states.
 */
#define HSM_FLAGS_MASK  (HSM_USER_MASK | HSM_STATUS_MASK)

/**
 * HSM request progress state
 */
enum hsm_progress_states {
	HPS_NONE	= 0,
	HPS_WAITING	= 1,
	HPS_RUNNING	= 2,
	HPS_DONE	= 3,
};

static inline const char *hsm_progress_state2name(enum hsm_progress_states s)
{
	switch  (s) {
	case HPS_WAITING:	return "waiting";
	case HPS_RUNNING:	return "running";
	case HPS_DONE:		return "done";
	default:		return "unknown";
	}
}

struct hsm_extent {
	__u64 offset;
	__u64 length;
} __attribute__((packed));

/**
 * Current HSM states of a Lustre file.
 *
 * This structure purpose is to be sent to user-space mainly. It describes the
 * current HSM flags and in-progress action.
 */
struct hsm_user_state {
	/** Current HSM states, from enum hsm_states. */
	__u32			hus_states;
	__u32			hus_archive_id;
	/**  The current undergoing action, if there is one */
	__u32			hus_in_progress_state;
	__u32			hus_in_progress_action;
	struct hsm_extent	hus_in_progress_location;
	char			hus_extended_info[];
};

struct hsm_state_set_ioc {
	struct lu_fid	hssi_fid;
	__u64		hssi_setmask;
	__u64		hssi_clearmask;
};

/*
 * This structure describes the current in-progress action for a file.
 * it is retuned to user space and send over the wire
 */
struct hsm_current_action {
	/**  The current undergoing action, if there is one */
	/* state is one of hsm_progress_states */
	__u32			hca_state;
	/* action is one of hsm_user_action */
	__u32			hca_action;
	struct hsm_extent	hca_location;
};

/***** HSM user requests ******/
/* User-generated (lfs/ioctl) request types */
enum hsm_user_action {
	HUA_NONE    =  1, /* no action (noop) */
	HUA_ARCHIVE = 10, /* copy to hsm */
	HUA_RESTORE = 11, /* prestage */
	HUA_RELEASE = 12, /* drop ost objects */
	HUA_REMOVE  = 13, /* remove from archive */
	HUA_CANCEL  = 14  /* cancel a request */
};

static inline const char *hsm_user_action2name(enum hsm_user_action  a)
{
	switch  (a) {
	case HUA_NONE:    return "NOOP";
	case HUA_ARCHIVE: return "ARCHIVE";
	case HUA_RESTORE: return "RESTORE";
	case HUA_RELEASE: return "RELEASE";
	case HUA_REMOVE:  return "REMOVE";
	case HUA_CANCEL:  return "CANCEL";
	default:          return "UNKNOWN";
	}
}

/*
 * List of hr_flags (bit field)
 */
#define HSM_FORCE_ACTION 0x0001
/* used by CT, cannot be set by user */
#define HSM_GHOST_COPY   0x0002

/**
 * Contains all the fixed part of struct hsm_user_request.
 *
 */
struct hsm_request {
	__u32 hr_action;	/* enum hsm_user_action */
	__u32 hr_archive_id;	/* archive id, used only with HUA_ARCHIVE */
	__u64 hr_flags;		/* request flags */
	__u32 hr_itemcount;	/* item count in hur_user_item vector */
	__u32 hr_data_len;
};

struct hsm_user_item {
       struct lu_fid        hui_fid;
       struct hsm_extent hui_extent;
} __attribute__((packed));

struct hsm_user_request {
	struct hsm_request	hur_request;
	struct hsm_user_item	hur_user_item[0];
	/* extra data blob at end of struct (after all
	 * hur_user_items), only use helpers to access it
	 */
} __attribute__((packed));

/** Return pointer to data field in a hsm user request */
static inline void *hur_data(struct hsm_user_request *hur)
{
	return &(hur->hur_user_item[hur->hur_request.hr_itemcount]);
}

/**
 * Compute the current length of the provided hsm_user_request.  This returns -1
 * instead of an errno because __kernel_ssize_t is defined to be only
 * [ -1, SSIZE_MAX ]
 *
 * return -1 on bounds check error.
 */
static inline __kernel_size_t hur_len(struct hsm_user_request *hur)
{
	__u64	size;

	/* can't overflow a __u64 since hr_itemcount is only __u32 */
	size = offsetof(struct hsm_user_request, hur_user_item[0]) +
		(__u64)hur->hur_request.hr_itemcount *
		sizeof(hur->hur_user_item[0]) + hur->hur_request.hr_data_len;

	if ((__kernel_ssize_t)size < 0)
		return -1;

	return size;
}

/****** HSM RPCs to copytool *****/
/* Message types the copytool may receive */
enum hsm_message_type {
	HMT_ACTION_LIST = 100, /* message is a hsm_action_list */
};

/* Actions the copytool may be instructed to take for a given action_item */
enum hsm_copytool_action {
	HSMA_NONE    = 10, /* no action */
	HSMA_ARCHIVE = 20, /* arbitrary offset */
	HSMA_RESTORE = 21,
	HSMA_REMOVE  = 22,
	HSMA_CANCEL  = 23
};

static inline const char *hsm_copytool_action2name(enum hsm_copytool_action  a)
{
	switch  (a) {
	case HSMA_NONE:    return "NOOP";
	case HSMA_ARCHIVE: return "ARCHIVE";
	case HSMA_RESTORE: return "RESTORE";
	case HSMA_REMOVE:  return "REMOVE";
	case HSMA_CANCEL:  return "CANCEL";
	default:           return "UNKNOWN";
	}
}

/* Copytool item action description */
struct hsm_action_item {
	__u32      hai_len;     /* valid size of this struct */
	__u32      hai_action;  /* hsm_copytool_action, but use known size */
	struct lu_fid hai_fid;     /* Lustre FID to operate on */
	struct lu_fid hai_dfid;    /* fid used for data access */
	struct hsm_extent hai_extent;  /* byte range to operate on */
	__u64      hai_cookie;  /* action cookie from coordinator */
	__u64      hai_gid;     /* grouplock id */
	char       hai_data[0]; /* variable length */
} __attribute__((packed));

/**
 * helper function which print in hexa the first bytes of
 * hai opaque field
 *
 * \param hai [IN]        record to print
 * \param buffer [IN,OUT] buffer to write the hex string to
 * \param len [IN]        max buffer length
 *
 * \retval buffer
 */
static inline char *hai_dump_data_field(const struct hsm_action_item *hai,
					char *buffer, __kernel_size_t len)
{
	int i;
	int data_len;
	char *ptr;

	ptr = buffer;
	data_len = hai->hai_len - sizeof(*hai);
	for (i = 0; (i < data_len) && (len > 2); i++) {
		snprintf(ptr, 3, "%02X", (unsigned char)hai->hai_data[i]);
		ptr += 2;
		len -= 2;
	}

	*ptr = '\0';

	return buffer;
}

/* Copytool action list */
#define HAL_VERSION 1
#define HAL_MAXSIZE LNET_MTU /* bytes, used in userspace only */
struct hsm_action_list {
	__u32 hal_version;
	__u32 hal_count;       /* number of hai's to follow */
	__u64 hal_compound_id; /* returned by coordinator, ignored */
	__u64 hal_flags;
	__u32 hal_archive_id; /* which archive backend */
	__u32 padding1;
	char  hal_fsname[0];   /* null-terminated */
	/* struct hsm_action_item[hal_count] follows, aligned on 8-byte
	   boundaries. See hai_zero */
} __attribute__((packed));

/* Return pointer to first hai in action list */
static inline struct hsm_action_item *hai_first(struct hsm_action_list *hal)
{
	__kernel_size_t offset = __ALIGN_KERNEL(strlen(hal->hal_fsname) + 1, 8);

	return (struct hsm_action_item *)(hal->hal_fsname + offset);
}

/* Return pointer to next hai */
static inline struct hsm_action_item * hai_next(struct hsm_action_item *hai)
{
	__kernel_size_t offset = __ALIGN_KERNEL(hai->hai_len, 8);

	return (struct hsm_action_item *)((char *)hai + offset);
}

/* Return size of an hsm_action_list */
static inline __kernel_size_t hal_size(struct hsm_action_list *hal)
{
	__u32 i;
	__kernel_size_t sz;
	struct hsm_action_item *hai;

	sz = sizeof(*hal) + __ALIGN_KERNEL(strlen(hal->hal_fsname) + 1, 8);
	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count ; i++, hai = hai_next(hai))
		sz += __ALIGN_KERNEL(hai->hai_len, 8);

	return sz;
}

/* HSM file import
 * describe the attributes to be set on imported file
 */
struct hsm_user_import {
	__u64		hui_size;
	__u64		hui_atime;
	__u64		hui_mtime;
	__u32		hui_atime_ns;
	__u32		hui_mtime_ns;
	__u32		hui_uid;
	__u32		hui_gid;
	__u32		hui_mode;
	__u32		hui_archive_id;
};

/* Copytool progress reporting */
#define HP_FLAG_COMPLETED 0x01
#define HP_FLAG_RETRY     0x02

struct hsm_progress {
	struct lu_fid		hp_fid;
	__u64			hp_cookie;
	struct hsm_extent	hp_extent;
	__u16			hp_flags;
	__u16			hp_errval; /* positive val */
	__u32			padding;
};

struct hsm_copy {
	__u64			hc_data_version;
	__u16			hc_flags;
	__u16			hc_errval; /* positive val */
	__u32			padding;
	struct hsm_action_item	hc_hai;
};

/* JSON objects */
enum llapi_json_types {
	LLAPI_JSON_INTEGER = 1,
	LLAPI_JSON_BIGNUM,
	LLAPI_JSON_REAL,
	LLAPI_JSON_STRING
};

struct llapi_json_item {
	char			*lji_key;
	__u32			lji_type;
	union {
		int	lji_integer;
		__u64	lji_u64;
		double	lji_real;
		char	*lji_string;
	};
	struct llapi_json_item	*lji_next;
};

struct llapi_json_item_list {
	int			ljil_item_count;
	struct llapi_json_item	*ljil_items;
};

enum lu_ladvise_type {
	LU_LADVISE_INVALID	= 0,
	LU_LADVISE_WILLREAD	= 1,
	LU_LADVISE_DONTNEED	= 2,
	LU_LADVISE_LOCKNOEXPAND = 3,
	LU_LADVISE_LOCKAHEAD	= 4,
	LU_LADVISE_MAX
};

#define LU_LADVISE_NAMES {						\
	[LU_LADVISE_WILLREAD]		= "willread",			\
	[LU_LADVISE_DONTNEED]		= "dontneed",			\
	[LU_LADVISE_LOCKNOEXPAND]	= "locknoexpand",		\
	[LU_LADVISE_LOCKAHEAD]		= "lockahead",			\
}

/* This is the userspace argument for ladvise.  It is currently the same as
 * what goes on the wire (struct lu_ladvise), but is defined separately as we
 * may need info which is only used locally. */
struct llapi_lu_ladvise {
	__u16 lla_advice;	/* advice type */
	__u16 lla_value1;	/* values for different advice types */
	__u32 lla_value2;
	__u64 lla_start;	/* first byte of extent for advice */
	__u64 lla_end;		/* last byte of extent for advice */
	__u32 lla_value3;
	__u32 lla_value4;
};

enum ladvise_flag {
	LF_ASYNC	= 0x00000001,
	LF_UNSET        = 0x00000002,
};

#define LADVISE_MAGIC 0x1ADF1CE0
/* Masks of valid flags for each advice */
#define LF_LOCKNOEXPAND_MASK LF_UNSET
/* Flags valid for all advices not explicitly specified */
#define LF_DEFAULT_MASK LF_ASYNC
/* All flags */
#define LF_MASK (LF_ASYNC | LF_UNSET)

#define lla_lockahead_mode   lla_value1
#define lla_peradvice_flags    lla_value2
#define lla_lockahead_result lla_value3

/* This is the userspace argument for ladvise, corresponds to ladvise_hdr which
 * is used on the wire.  It is defined separately as we may need info which is
 * only used locally. */
struct llapi_ladvise_hdr {
	__u32			lah_magic;	/* LADVISE_MAGIC */
	__u32			lah_count;	/* number of advices */
	__u64			lah_flags;	/* from enum ladvise_flag */
	__u32			lah_value1;	/* unused */
	__u32			lah_value2;	/* unused */
	__u64			lah_value3;	/* unused */
	struct llapi_lu_ladvise	lah_advise[0];	/* advices in this header */
};

#define LAH_COUNT_MAX	(1024)

/* Shared key */
enum sk_crypt_alg {
	SK_CRYPT_INVALID	= -1,
	SK_CRYPT_EMPTY		= 0,
	SK_CRYPT_AES256_CTR	= 1,
};

enum sk_hmac_alg {
	SK_HMAC_INVALID	= -1,
	SK_HMAC_EMPTY	= 0,
	SK_HMAC_SHA256	= 1,
	SK_HMAC_SHA512	= 2,
};

struct sk_crypt_type {
	const char     *sct_name;
	int		sct_type;
};

struct sk_hmac_type {
	const char     *sht_name;
	int		sht_type;
};

enum lock_mode_user {
	MODE_READ_USER = 1,
	MODE_WRITE_USER,
	MODE_MAX_USER,
};

#define LOCK_MODE_NAMES { \
	[MODE_READ_USER]  = "READ",\
	[MODE_WRITE_USER] = "WRITE"\
}

enum lockahead_results {
	LLA_RESULT_SENT = 0,
	LLA_RESULT_DIFFERENT,
	LLA_RESULT_SAME,
};

struct fid_array {
	__u32 fa_nr;
	/* make header's size equal lu_fid */
	__u32 fa_padding0;
	__u64 fa_padding1;
	struct lu_fid fa_fids[0];
};
#define OBD_MAX_FIDS_IN_ARRAY	4096

#if defined(__cplusplus)
}
#endif

/** @} lustreuser */

#endif /* _LUSTRE_USER_H */
