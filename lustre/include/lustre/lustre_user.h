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
 * lustre/include/lustre/lustre_user.h
 *
 * Lustre public user-space interface definitions.
 */

#ifndef _LUSTRE_USER_H
#define _LUSTRE_USER_H

#include <lustre/ll_fiemap.h>
#if defined(__linux__)
#include <linux/lustre_user.h>
#elif defined(__APPLE__)
#include <darwin/lustre_user.h>
#elif defined(__WINNT__)
#include <winnt/lustre_user.h>
#else
#error Unsupported operating system.
#endif

/* for statfs() */
#define LL_SUPER_MAGIC 0x0BD00BD0

#ifndef EXT3_IOC_GETFLAGS
#define EXT3_IOC_GETFLAGS               _IOR('f', 1, long)
#define EXT3_IOC_SETFLAGS               _IOW('f', 2, long)
#define EXT3_IOC_GETVERSION             _IOR('f', 3, long)
#define EXT3_IOC_SETVERSION             _IOW('f', 4, long)
#define EXT3_IOC_GETVERSION_OLD         _IOR('v', 1, long)
#define EXT3_IOC_SETVERSION_OLD         _IOW('v', 2, long)
#define EXT3_IOC_FIEMAP                 _IOWR('f', 10, struct ll_user_fiemap)
#endif

/* FIEMAP flags supported by Lustre */
#define LUSTRE_FIEMAP_FLAGS_COMPAT (FIEMAP_FLAG_SYNC | FIEMAP_FLAG_DEVICE_ORDER)

struct obd_statfs;

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
#define LL_IOC_GETFLAGS                 _IOR ('f', 151, long)
#define LL_IOC_SETFLAGS                 _IOW ('f', 152, long)
#define LL_IOC_CLRFLAGS                 _IOW ('f', 153, long)
#define LL_IOC_LOV_SETSTRIPE            _IOW ('f', 154, long)
#define LL_IOC_LOV_GETSTRIPE            _IOW ('f', 155, long)
#define LL_IOC_LOV_SETEA                _IOW ('f', 156, long)
#define LL_IOC_RECREATE_OBJ             _IOW ('f', 157, long)
#define LL_IOC_GROUP_LOCK               _IOW ('f', 158, long)
#define LL_IOC_GROUP_UNLOCK             _IOW ('f', 159, long)
#define LL_IOC_QUOTACHECK               _IOW ('f', 160, int)
#define LL_IOC_POLL_QUOTACHECK          _IOR ('f', 161, struct if_quotacheck *)
#define LL_IOC_QUOTACTL                 _IOWR('f', 162, struct if_quotactl *)
#define LL_IOC_JOIN                     _IOW ('f', 163, long)
#define IOC_OBD_STATFS                  _IOWR('f', 164, struct obd_statfs *)
#define IOC_LOV_GETINFO                 _IOWR('f', 165, struct lov_user_mds_data *)

#define LL_IOC_LLOOP_ATTACH             _IOWR('f', 166, OBD_IOC_DATA_TYPE)
#define LL_IOC_LLOOP_DETACH             _IOWR('f', 167, OBD_IOC_DATA_TYPE)
#define LL_IOC_LLOOP_INFO               _IOWR('f', 168, OBD_IOC_DATA_TYPE)
#define LL_IOC_LLOOP_DETACH_BYDEV       _IOWR('f', 169, OBD_IOC_DATA_TYPE)

#define LL_STATFS_MDC           1
#define LL_STATFS_LOV           2

#define IOC_MDC_TYPE            'i'
#define IOC_MDC_LOOKUP          _IOWR(IOC_MDC_TYPE, 20, struct obd_device *)
#define IOC_MDC_GETFILESTRIPE   _IOWR(IOC_MDC_TYPE, 21, struct lov_user_md *)
#define IOC_MDC_GETFILEINFO     _IOWR(IOC_MDC_TYPE, 22, struct lov_user_mds_data *)
#define LL_IOC_MDC_GETINFO      _IOWR(IOC_MDC_TYPE, 23, struct lov_user_mds_data *)

/* Keep these for backward compartability. */
#define LL_IOC_OBD_STATFS       IOC_OBD_STATFS
#define IOC_MDC_GETSTRIPE       IOC_MDC_GETFILESTRIPE

/* Do not define O_CHECK_STALE as 0200000000,
 * which is conflict with MDS_OPEN_OWNEROVERRIDE */
#define O_CHECK_STALE       020000000  /* hopefully this does not conflict */

#define O_LOV_DELAY_CREATE 0100000000  /* hopefully this does not conflict */
#define O_JOIN_FILE        0400000000  /* hopefully this does not conflict */

#define LL_FILE_IGNORE_LOCK             0x00000001
#define LL_FILE_GROUP_LOCKED            0x00000002
#define LL_FILE_READAHEAD               0x00000004

#define LOV_USER_MAGIC_V1 0x0BD10BD0
#define LOV_USER_MAGIC    LOV_USER_MAGIC_V1
#define LOV_USER_MAGIC_JOIN 0x0BD20BD0
#define LOV_USER_MAGIC_V3 0x0BD30BD0

#define LOV_PATTERN_RAID0 0x001
#define LOV_PATTERN_RAID1 0x002
#define LOV_PATTERN_FIRST 0x100

#define MAXPOOLNAME 16

#define lov_user_ost_data lov_user_ost_data_v1
struct lov_user_ost_data_v1 {     /* per-stripe data structure */
        __u64 l_object_id;        /* OST object ID */
        __u64 l_object_gr;        /* OST object group (creating MDS number) */
        __u32 l_ost_gen;          /* generation of this OST index */
        __u32 l_ost_idx;          /* OST index in LOV */
} __attribute__((packed));

#define lov_user_md lov_user_md_v1
struct lov_user_md_v1 {           /* LOV EA user data (host-endian) */
        __u32 lmm_magic;          /* magic number = LOV_USER_MAGIC_V1 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u16 lmm_stripe_count;   /* num stripes in use for this object */
        __u16 lmm_stripe_offset;  /* starting stripe offset in lmm_objects */
        struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed));

struct lov_user_md_v3 {           /* LOV EA user data (host-endian) */
        __u32 lmm_magic;          /* magic number = LOV_USER_MAGIC_V3 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u16 lmm_stripe_count;   /* num stripes in use for this object */
        __u16 lmm_stripe_offset;  /* starting stripe offset in lmm_objects */
        char  lmm_pool_name[MAXPOOLNAME]; /* pool name */
        struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed));

/* Compile with -D_LARGEFILE64_SOURCE or -D_GNU_SOURCE (or #define) to
 * use this.  It is unsafe to #define those values in this header as it
 * is possible the application has already #included <sys/stat.h>. */
#ifdef HAVE_LOV_USER_MDS_DATA
#define lov_user_mds_data lov_user_mds_data_v1
struct lov_user_mds_data_v1 {
        lstat_t lmd_st;                 /* MDS stat struct */
        struct lov_user_md_v1 lmd_lmm;  /* LOV EA V1 user data */
} __attribute__((packed));

struct lov_user_mds_data_v3 {
        lstat_t lmd_st;                 /* MDS stat struct */
        struct lov_user_md_v3 lmd_lmm;  /* LOV EA V3 user data */
} __attribute__((packed));
#endif

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

struct filter_fid {
        struct ll_fid   ff_fid;  /* ff_fid.f_type == file stripe number */
        __u64           ff_objid;
        __u64           ff_group;
};

struct obd_uuid {
        char uuid[40];
};

static inline int obd_uuid_equals(struct obd_uuid *u1, struct obd_uuid *u2)
{
        return strcmp((char *)u1->uuid, (char *)u2->uuid) == 0;
}

static inline int obd_uuid_empty(struct obd_uuid *uuid)
{
        return uuid->uuid[0] == '\0';
}

static inline void obd_str2uuid(struct obd_uuid *uuid, char *tmp)
{
        strncpy((char *)uuid->uuid, tmp, sizeof(*uuid));
        uuid->uuid[sizeof(*uuid) - 1] = '\0';
}

/* For printf's only, make sure uuid is terminated */
static inline char *obd_uuid2str(struct obd_uuid *uuid) 
{
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

/* these must be explicitly translated into linux Q_* in ll_dir_ioctl */
#define LUSTRE_Q_QUOTAON    0x800002     /* turn quotas on */
#define LUSTRE_Q_QUOTAOFF   0x800003     /* turn quotas off */
#define LUSTRE_Q_GETINFO    0x800005     /* get information about quota files */
#define LUSTRE_Q_SETINFO    0x800006     /* set information about quota files */
#define LUSTRE_Q_GETQUOTA   0x800007     /* get user quota structure */
#define LUSTRE_Q_SETQUOTA   0x800008     /* set user quota structure */
/* lustre-specific control commands */
#define LUSTRE_Q_INVALIDATE  0x80000b     /* invalidate quota data */
#define LUSTRE_Q_FINVALIDATE 0x80000c     /* invalidate filter quota data */

#define UGQUOTA 2       /* set both USRQUOTA and GRPQUOTA */

struct if_quotacheck {
        char                    obd_type[16];
        struct obd_uuid         obd_uuid;
};

#define MDS_GRP_DOWNCALL_MAGIC 0x6d6dd620

struct mds_grp_downcall_data {
        __u32           mgd_magic;
        __u32           mgd_err;
        __u32           mgd_uid;
        __u32           mgd_gid;
        __u32           mgd_ngroups;
        __u32           mgd_groups[0];
};

#ifdef NEED_QUOTA_DEFS
#ifndef QUOTABLOCK_BITS
#define QUOTABLOCK_BITS 10
#endif

#ifndef QUOTABLOCK_SIZE
#define QUOTABLOCK_SIZE (1 << QUOTABLOCK_BITS)
#endif

#ifndef toqb
#define toqb(x) (((x) + QUOTABLOCK_SIZE - 1) >> QUOTABLOCK_BITS)
#endif

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

typedef enum lustre_quota_version {
        LUSTRE_QUOTA_V1 = 0,
        LUSTRE_QUOTA_V2 = 1
} lustre_quota_version_t;

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

struct if_quotactl {
        __u32                   qc_cmd;
        __u32                   qc_type;
        __u32                   qc_id;
        __u32                   qc_stat;
        struct obd_dqinfo       qc_dqinfo;
        struct obd_dqblk        qc_dqblk;
        char                    obd_type[16];
        struct obd_uuid         obd_uuid;
};

#ifndef offsetof
# define offsetof(typ,memb)     ((unsigned long)((char *)&(((typ *)0)->memb)))
#endif

#endif /* _LUSTRE_USER_H */
