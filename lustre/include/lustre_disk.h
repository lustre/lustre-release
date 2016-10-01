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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre_disk.h
 *
 * Lustre disk format definitions.
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#ifndef _LUSTRE_DISK_H
#define _LUSTRE_DISK_H

/** \defgroup disk disk
 *
 * @{
 */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <libcfs/libcfs.h>
#ifdef __KERNEL__
#include <linux/list.h>
#else
#include <libcfs/util/list.h>
#endif
#include <lnet/types.h>

/****************** on-disk files *********************/

#define MDT_LOGS_DIR		"LOGS"  /* COMPAT_146 */
#define MOUNT_CONFIGS_DIR	"CONFIGS"
#define CONFIGS_FILE		"mountdata"
/** Persistent mount data are stored on the disk in this file. */
#define MOUNT_DATA_FILE		MOUNT_CONFIGS_DIR"/"CONFIGS_FILE
#define LAST_RCVD		"last_rcvd"
#define REPLY_DATA		"reply_data"
#define LOV_OBJID		"lov_objid"
#define LOV_OBJSEQ		"lov_objseq"
#define HEALTH_CHECK		"health_check"
#define CAPA_KEYS		"capa_keys"
#define CHANGELOG_USERS		"changelog_users"
#define MGS_NIDTBL_DIR		"NIDTBL_VERSIONS"
#define QMT_DIR			"quota_master"
#define QSD_DIR			"quota_slave"
#define HSM_ACTIONS		"hsm_actions"
#define LFSCK_DIR		"LFSCK"
#define LFSCK_BOOKMARK		"lfsck_bookmark"
#define LFSCK_LAYOUT		"lfsck_layout"
#define LFSCK_NAMESPACE		"lfsck_namespace"

/****************** persistent mount data *********************/

#define LDD_F_SV_TYPE_MDT   0x0001
#define LDD_F_SV_TYPE_OST   0x0002
#define LDD_F_SV_TYPE_MGS   0x0004
#define LDD_F_SV_TYPE_MASK (LDD_F_SV_TYPE_MDT  | \
                            LDD_F_SV_TYPE_OST  | \
                            LDD_F_SV_TYPE_MGS)
#define LDD_F_SV_ALL        0x0008
/** need an index assignment */
#define LDD_F_NEED_INDEX    0x0010
/** never registered */
#define LDD_F_VIRGIN        0x0020
/** update the config logs for this server */
#define LDD_F_UPDATE        0x0040
/** rewrite the LDD */
#define LDD_F_REWRITE_LDD   0x0080
/** regenerate config logs for this fs or server */
#define LDD_F_WRITECONF     0x0100
/** COMPAT_14 */
#define LDD_F_UPGRADE14     0x0200
/** process as lctl conf_param */
#define LDD_F_PARAM         0x0400
/** all nodes are specified as service nodes */
#define LDD_F_NO_PRIMNODE   0x1000
/** IR enable flag */
#define LDD_F_IR_CAPABLE    0x2000
/** the MGS refused to register the target. */
#define LDD_F_ERROR         0x4000
/** process at lctl conf_param */
#define LDD_F_PARAM2		0x8000

/* opc for target register */
#define LDD_F_OPC_REG   0x10000000
#define LDD_F_OPC_UNREG 0x20000000
#define LDD_F_OPC_READY 0x40000000
#define LDD_F_OPC_MASK  0xf0000000

#define LDD_F_ONDISK_MASK  (LDD_F_SV_TYPE_MASK)

#define LDD_F_MASK          0xFFFF

enum ldd_mount_type {
	LDD_MT_EXT3 = 0,
	LDD_MT_LDISKFS,
	LDD_MT_SMFS,
	LDD_MT_REISERFS,
	LDD_MT_LDISKFS2,
	LDD_MT_ZFS,
	LDD_MT_LAST
};

static inline char *mt_str(enum ldd_mount_type mt)
{
        static char *mount_type_string[] = {
                "ext3",
                "ldiskfs",
                "smfs",
                "reiserfs",
		"ldiskfs2",
		"zfs",
        };
        return mount_type_string[mt];
}

static inline char *mt_type(enum ldd_mount_type mt)
{
	static char *mount_type_string[] = {
		"osd-ldiskfs",
		"osd-ldiskfs",
		"osd-smfs",
		"osd-reiserfs",
		"osd-ldiskfs",
		"osd-zfs",
	};
	return mount_type_string[mt];
}

#define LDD_INCOMPAT_SUPP 0
#define LDD_ROCOMPAT_SUPP 0

#define LDD_MAGIC 0x1dd00001

/* On-disk configuration file. In host-endian order. */
struct lustre_disk_data {
        __u32      ldd_magic;
        __u32      ldd_feature_compat;  /* compatible feature flags */
        __u32      ldd_feature_rocompat;/* read-only compatible feature flags */
        __u32      ldd_feature_incompat;/* incompatible feature flags */

        __u32      ldd_config_ver;      /* config rewrite count - not used */
        __u32      ldd_flags;           /* LDD_SV_TYPE */
        __u32      ldd_svindex;         /* server index (0001), must match
                                           svname */
        __u32      ldd_mount_type;      /* target fs type LDD_MT_* */
        char       ldd_fsname[64];      /* filesystem this server is part of,
                                           MTI_NAME_MAXLEN */
        char       ldd_svname[64];      /* this server's name (lustre-mdt0001)*/
        __u8       ldd_uuid[40];        /* server UUID (COMPAT_146) */

/*200*/ char       ldd_userdata[1024 - 200]; /* arbitrary user string */
/*1024*/__u8       ldd_padding[4096 - 1024];
/*4096*/char       ldd_mount_opts[4096]; /* target fs mount opts */
/*8192*/char       ldd_params[4096];     /* key=value pairs */
};


#define IS_MDT(data)    ((data)->lsi_flags & LDD_F_SV_TYPE_MDT)
#define IS_OST(data)    ((data)->lsi_flags & LDD_F_SV_TYPE_OST)
#define IS_MGS(data)    ((data)->lsi_flags & LDD_F_SV_TYPE_MGS)
#define IS_SERVER(data) ((data)->lsi_flags & (LDD_F_SV_TYPE_MGS | \
			 LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_OST))
#define MT_STR(data)    mt_str((data)->ldd_mount_type)

/* Make the mdt/ost server obd name based on the filesystem name */
static inline int server_make_name(__u32 flags, __u16 index, char *fs,
                                   char *name)
{
        if (flags & (LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_OST)) {
                if (!(flags & LDD_F_SV_ALL))
			sprintf(name, "%.8s%c%s%04x", fs,
				(flags & LDD_F_VIRGIN) ? ':' :
					((flags & LDD_F_WRITECONF) ? '=' : '-'),
				(flags & LDD_F_SV_TYPE_MDT) ? "MDT" : "OST",
				index);
        } else if (flags & LDD_F_SV_TYPE_MGS) {
                sprintf(name, "MGS");
        } else {
                CERROR("unknown server type %#x\n", flags);
                return 1;
        }
        return 0;
}

/****************** mount command *********************/

/* The lmd is only used internally by Lustre; mount simply passes
   everything as string options */

#define LMD_MAGIC		0xbdacbd03
#define LMD_PARAMS_MAXLEN	4096

/* gleaned from the mount command - no persistent info here */
struct lustre_mount_data {
	__u32	lmd_magic;
	__u32	lmd_flags;	/* lustre mount flags */
	int	lmd_mgs_failnodes; /* mgs failover node count */
	int	lmd_exclude_count;
	int	lmd_recovery_time_soft;
	int	lmd_recovery_time_hard;
	char   *lmd_dev;	/* device name */
	char   *lmd_profile;	/* client only */
	char   *lmd_fileset;	/* mount fileset */
	char   *lmd_mgssec;	/* sptlrpc flavor to mgs */
	char   *lmd_opts;	/* lustre mount options (as opposed to
				 * device_ mount options) */
	char   *lmd_params;	/* lustre params */
	__u32  *lmd_exclude;	/* array of OSTs to ignore */
	char   *lmd_mgs;	/* MGS nid */
	char   *lmd_osd_type;	/* OSD type */
};

#define LMD_FLG_SERVER		0x0001	/* Mounting a server */
#define LMD_FLG_CLIENT		0x0002	/* Mounting a client */
#define LMD_FLG_SKIP_LFSCK	0x0004	/* NOT auto resume LFSCK when mount */
#define LMD_FLG_ABORT_RECOV	0x0008	/* Abort recovery */
#define LMD_FLG_NOSVC		0x0010	/* Only start MGS/MGC for servers,
					   no other services */
#define LMD_FLG_NOMGS		0x0020	/* Only start target for servers, reusing
					   existing MGS services */
#define LMD_FLG_WRITECONF	0x0040	/* Rewrite config log */
#define LMD_FLG_NOIR		0x0080	/* NO imperative recovery */
#define LMD_FLG_NOSCRUB		0x0100	/* Do not trigger scrub automatically */
#define LMD_FLG_MGS		0x0200	/* Also start MGS along with server */
#define LMD_FLG_IAM		0x0400	/* IAM dir */
#define LMD_FLG_NO_PRIMNODE	0x0800	/* all nodes are service nodes */
#define LMD_FLG_VIRGIN		0x1000	/* the service registers first time */
#define LMD_FLG_UPDATE		0x2000	/* update parameters */
#define LMD_FLG_HSM		0x4000	/* Start coordinator */

#define lmd_is_client(x) ((x)->lmd_flags & LMD_FLG_CLIENT)


/****************** last_rcvd file *********************/

/** version recovery epoch */
#define LR_EPOCH_BITS   32
#define lr_epoch(a) ((a) >> LR_EPOCH_BITS)
#define LR_EXPIRE_INTERVALS 16 /**< number of intervals to track transno */
#define ENOENT_VERSION 1 /** 'virtual' version of non-existent object */

#define LR_SERVER_SIZE   512
#define LR_CLIENT_START 8192
#define LR_CLIENT_SIZE   128
#if LR_CLIENT_START < LR_SERVER_SIZE
#error "Can't have LR_CLIENT_START < LR_SERVER_SIZE"
#endif

/*
 * This limit is arbitrary (131072 clients on x86), but it is convenient to use
 * 2^n * PAGE_SIZE * 8 for the number of bits that fit an order-n allocation.
 * If we need more than 131072 clients (order-2 allocation on x86) then this
 * should become an array of single-page pointers that are allocated on demand.
 */
#if (128 * 1024UL) > (PAGE_SIZE * 8)
#define LR_MAX_CLIENTS (128 * 1024UL)
#else
#define LR_MAX_CLIENTS (PAGE_SIZE * 8)
#endif

/** COMPAT_146: this is an OST (temporary) */
#define OBD_COMPAT_OST          0x00000002
/** COMPAT_146: this is an MDT (temporary) */
#define OBD_COMPAT_MDT          0x00000004
/** 2.0 server, interop flag to show server version is changed */
#define OBD_COMPAT_20           0x00000008

/** MDS handles LOV_OBJID file */
#define OBD_ROCOMPAT_LOVOBJID		0x00000001
/** store OST index in the IDIF */
#define OBD_ROCOMPAT_IDX_IN_IDIF	0x00000002

/** OST handles group subdirs */
#define OBD_INCOMPAT_GROUPS     0x00000001
/** this is an OST */
#define OBD_INCOMPAT_OST        0x00000002
/** this is an MDT */
#define OBD_INCOMPAT_MDT        0x00000004
/** common last_rvcd format */
#define OBD_INCOMPAT_COMMON_LR  0x00000008
/** FID is enabled */
#define OBD_INCOMPAT_FID        0x00000010
/** Size-on-MDS is enabled */
#define OBD_INCOMPAT_SOM        0x00000020
/** filesystem using iam format to store directory entries */
#define OBD_INCOMPAT_IAM_DIR    0x00000040
/** LMA attribute contains per-inode incompatible flags */
#define OBD_INCOMPAT_LMA        0x00000080
/** lmm_stripe_count has been shrunk from __u32 to __u16 and the remaining 16
 * bits are now used to store a generation. Once we start changing the layout
 * and bumping the generation, old versions expecting a 32-bit lmm_stripe_count
 * will be confused by interpreting stripe_count | gen << 16 as the actual
 * stripe count */
#define OBD_INCOMPAT_LMM_VER    0x00000100
/** multiple OI files for MDT */
#define OBD_INCOMPAT_MULTI_OI   0x00000200
/** multiple RPCs in flight */
#define OBD_INCOMPAT_MULTI_RPCS	0x00000400

/* Data stored per server at the head of the last_rcvd file.  In le32 order.
   This should be common to filter_internal.h, lustre_mds.h */
struct lr_server_data {
        __u8  lsd_uuid[40];        /* server UUID */
        __u64 lsd_last_transno;    /* last completed transaction ID */
        __u64 lsd_compat14;        /* reserved - compat with old last_rcvd */
        __u64 lsd_mount_count;     /* incarnation number */
        __u32 lsd_feature_compat;  /* compatible feature flags */
        __u32 lsd_feature_rocompat;/* read-only compatible feature flags */
        __u32 lsd_feature_incompat;/* incompatible feature flags */
        __u32 lsd_server_size;     /* size of server data area */
        __u32 lsd_client_start;    /* start of per-client data area */
        __u16 lsd_client_size;     /* size of per-client data area */
        __u16 lsd_subdir_count;    /* number of subdirectories for objects */
        __u64 lsd_catalog_oid;     /* recovery catalog object id */
        __u32 lsd_catalog_ogen;    /* recovery catalog inode generation */
        __u8  lsd_peeruuid[40];    /* UUID of MDS associated with this OST */
	__u32 lsd_osd_index;       /* index number of OST in LOV */
	__u32 lsd_padding1;        /* was lsd_mdt_index, unused in 2.4.0 */
        __u32 lsd_start_epoch;     /* VBR: start epoch from last boot */
        /** transaction values since lsd_trans_table_time */
        __u64 lsd_trans_table[LR_EXPIRE_INTERVALS];
        /** start point of transno table below */
        __u32 lsd_trans_table_time; /* time of first slot in table above */
        __u32 lsd_expire_intervals; /* LR_EXPIRE_INTERVALS */
        __u8  lsd_padding[LR_SERVER_SIZE - 288];
};

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct lsd_client_data {
        __u8  lcd_uuid[40];      /* client UUID */
        __u64 lcd_last_transno; /* last completed transaction ID */
        __u64 lcd_last_xid;     /* xid for the last transaction */
        __u32 lcd_last_result;  /* result from last RPC */
        __u32 lcd_last_data;    /* per-op data (disposition for open &c.) */
        /* for MDS_CLOSE requests */
        __u64 lcd_last_close_transno; /* last completed transaction ID */
        __u64 lcd_last_close_xid;     /* xid for the last transaction */
        __u32 lcd_last_close_result;  /* result from last RPC */
        __u32 lcd_last_close_data;    /* per-op data */
        /* VBR: last versions */
        __u64 lcd_pre_versions[4];
        __u32 lcd_last_epoch;
	/* generation counter of client slot in last_rcvd */
	__u32 lcd_generation;
	__u8  lcd_padding[LR_CLIENT_SIZE - 128];
};


/* Data stored in each slot of the reply_data file.
 *
 * The lrd_client_gen field is assigned with lcd_generation value
 * to allow identify which client the reply data belongs to.
 */
struct lsd_reply_data {
	__u64	lrd_transno;	/* transaction number */
	__u64	lrd_xid;	/* transmission id */
	__u64	lrd_data;	/* per-operation data */
	__u32	lrd_result;	/* request result */
	__u32	lrd_client_gen; /* client generation */
};

/* Header of the reply_data file */
#define LRH_MAGIC 0xbdabda01
struct lsd_reply_header {
	__u32	lrh_magic;
	__u32	lrh_header_size;
	__u32	lrh_reply_size;
	__u8	lrh_pad[sizeof(struct lsd_reply_data) - 12];
};


/* bug20354: the lcd_uuid for export of clients may be wrong */
static inline void check_lcd(char *obd_name, int index,
                             struct lsd_client_data *lcd)
{
	size_t length = sizeof(lcd->lcd_uuid);
        if (strnlen((char*)lcd->lcd_uuid, length) == length) {
                lcd->lcd_uuid[length - 1] = '\0';

                LCONSOLE_ERROR("the client UUID (%s) on %s for exports"
                               "stored in last_rcvd(index = %d) is bad!\n",
                               lcd->lcd_uuid, obd_name, index);
        }
}

/* last_rcvd handling */
static inline void lsd_le_to_cpu(struct lr_server_data *buf,
                                 struct lr_server_data *lsd)
{
	int i;
	memcpy(lsd->lsd_uuid, buf->lsd_uuid, sizeof(lsd->lsd_uuid));
	lsd->lsd_last_transno     = __le64_to_cpu(buf->lsd_last_transno);
	lsd->lsd_compat14         = __le64_to_cpu(buf->lsd_compat14);
	lsd->lsd_mount_count      = __le64_to_cpu(buf->lsd_mount_count);
	lsd->lsd_feature_compat   = __le32_to_cpu(buf->lsd_feature_compat);
	lsd->lsd_feature_rocompat = __le32_to_cpu(buf->lsd_feature_rocompat);
	lsd->lsd_feature_incompat = __le32_to_cpu(buf->lsd_feature_incompat);
	lsd->lsd_server_size      = __le32_to_cpu(buf->lsd_server_size);
	lsd->lsd_client_start     = __le32_to_cpu(buf->lsd_client_start);
	lsd->lsd_client_size      = __le16_to_cpu(buf->lsd_client_size);
	lsd->lsd_subdir_count     = __le16_to_cpu(buf->lsd_subdir_count);
	lsd->lsd_catalog_oid      = __le64_to_cpu(buf->lsd_catalog_oid);
	lsd->lsd_catalog_ogen     = __le32_to_cpu(buf->lsd_catalog_ogen);
	memcpy(lsd->lsd_peeruuid, buf->lsd_peeruuid, sizeof(lsd->lsd_peeruuid));
	lsd->lsd_osd_index        = __le32_to_cpu(buf->lsd_osd_index);
	lsd->lsd_padding1         = __le32_to_cpu(buf->lsd_padding1);
	lsd->lsd_start_epoch      = __le32_to_cpu(buf->lsd_start_epoch);
	for (i = 0; i < LR_EXPIRE_INTERVALS; i++)
		lsd->lsd_trans_table[i] = __le64_to_cpu(buf->lsd_trans_table[i]);
	lsd->lsd_trans_table_time = __le32_to_cpu(buf->lsd_trans_table_time);
	lsd->lsd_expire_intervals = __le32_to_cpu(buf->lsd_expire_intervals);
}

static inline void lsd_cpu_to_le(struct lr_server_data *lsd,
                                 struct lr_server_data *buf)
{
	int i;
	memcpy(buf->lsd_uuid, lsd->lsd_uuid, sizeof(buf->lsd_uuid));
	buf->lsd_last_transno     = __cpu_to_le64(lsd->lsd_last_transno);
	buf->lsd_compat14         = __cpu_to_le64(lsd->lsd_compat14);
	buf->lsd_mount_count      = __cpu_to_le64(lsd->lsd_mount_count);
	buf->lsd_feature_compat   = __cpu_to_le32(lsd->lsd_feature_compat);
	buf->lsd_feature_rocompat = __cpu_to_le32(lsd->lsd_feature_rocompat);
	buf->lsd_feature_incompat = __cpu_to_le32(lsd->lsd_feature_incompat);
	buf->lsd_server_size      = __cpu_to_le32(lsd->lsd_server_size);
	buf->lsd_client_start     = __cpu_to_le32(lsd->lsd_client_start);
	buf->lsd_client_size      = __cpu_to_le16(lsd->lsd_client_size);
	buf->lsd_subdir_count     = __cpu_to_le16(lsd->lsd_subdir_count);
	buf->lsd_catalog_oid      = __cpu_to_le64(lsd->lsd_catalog_oid);
	buf->lsd_catalog_ogen     = __cpu_to_le32(lsd->lsd_catalog_ogen);
	memcpy(buf->lsd_peeruuid, lsd->lsd_peeruuid, sizeof(buf->lsd_peeruuid));
	buf->lsd_osd_index	  = __cpu_to_le32(lsd->lsd_osd_index);
	buf->lsd_padding1	  = __cpu_to_le32(lsd->lsd_padding1);
	buf->lsd_start_epoch      = __cpu_to_le32(lsd->lsd_start_epoch);
	for (i = 0; i < LR_EXPIRE_INTERVALS; i++)
		buf->lsd_trans_table[i] = __cpu_to_le64(lsd->lsd_trans_table[i]);
	buf->lsd_trans_table_time = __cpu_to_le32(lsd->lsd_trans_table_time);
	buf->lsd_expire_intervals = __cpu_to_le32(lsd->lsd_expire_intervals);
}

static inline void lcd_le_to_cpu(struct lsd_client_data *buf,
                                 struct lsd_client_data *lcd)
{
        memcpy(lcd->lcd_uuid, buf->lcd_uuid, sizeof (lcd->lcd_uuid));
	lcd->lcd_last_transno       = __le64_to_cpu(buf->lcd_last_transno);
	lcd->lcd_last_xid           = __le64_to_cpu(buf->lcd_last_xid);
	lcd->lcd_last_result        = __le32_to_cpu(buf->lcd_last_result);
	lcd->lcd_last_data          = __le32_to_cpu(buf->lcd_last_data);
	lcd->lcd_last_close_transno = __le64_to_cpu(buf->lcd_last_close_transno);
	lcd->lcd_last_close_xid     = __le64_to_cpu(buf->lcd_last_close_xid);
	lcd->lcd_last_close_result  = __le32_to_cpu(buf->lcd_last_close_result);
	lcd->lcd_last_close_data    = __le32_to_cpu(buf->lcd_last_close_data);
	lcd->lcd_pre_versions[0]    = __le64_to_cpu(buf->lcd_pre_versions[0]);
	lcd->lcd_pre_versions[1]    = __le64_to_cpu(buf->lcd_pre_versions[1]);
	lcd->lcd_pre_versions[2]    = __le64_to_cpu(buf->lcd_pre_versions[2]);
	lcd->lcd_pre_versions[3]    = __le64_to_cpu(buf->lcd_pre_versions[3]);
	lcd->lcd_last_epoch         = __le32_to_cpu(buf->lcd_last_epoch);
	lcd->lcd_generation	    = __le32_to_cpu(buf->lcd_generation);
}

static inline void lcd_cpu_to_le(struct lsd_client_data *lcd,
                                 struct lsd_client_data *buf)
{
        memcpy(buf->lcd_uuid, lcd->lcd_uuid, sizeof (lcd->lcd_uuid));
	buf->lcd_last_transno       = __cpu_to_le64(lcd->lcd_last_transno);
	buf->lcd_last_xid           = __cpu_to_le64(lcd->lcd_last_xid);
	buf->lcd_last_result        = __cpu_to_le32(lcd->lcd_last_result);
	buf->lcd_last_data          = __cpu_to_le32(lcd->lcd_last_data);
	buf->lcd_last_close_transno = __cpu_to_le64(lcd->lcd_last_close_transno);
	buf->lcd_last_close_xid     = __cpu_to_le64(lcd->lcd_last_close_xid);
	buf->lcd_last_close_result  = __cpu_to_le32(lcd->lcd_last_close_result);
	buf->lcd_last_close_data    = __cpu_to_le32(lcd->lcd_last_close_data);
	buf->lcd_pre_versions[0]    = __cpu_to_le64(lcd->lcd_pre_versions[0]);
	buf->lcd_pre_versions[1]    = __cpu_to_le64(lcd->lcd_pre_versions[1]);
	buf->lcd_pre_versions[2]    = __cpu_to_le64(lcd->lcd_pre_versions[2]);
	buf->lcd_pre_versions[3]    = __cpu_to_le64(lcd->lcd_pre_versions[3]);
	buf->lcd_last_epoch         = __cpu_to_le32(lcd->lcd_last_epoch);
	buf->lcd_generation	    = __cpu_to_le32(lcd->lcd_generation);
}

static inline __u64 lcd_last_transno(struct lsd_client_data *lcd)
{
        return (lcd->lcd_last_transno > lcd->lcd_last_close_transno ?
                lcd->lcd_last_transno : lcd->lcd_last_close_transno);
}

static inline __u64 lcd_last_xid(struct lsd_client_data *lcd)
{
        return (lcd->lcd_last_xid > lcd->lcd_last_close_xid ?
                lcd->lcd_last_xid : lcd->lcd_last_close_xid);
}

/****************** superblock additional info *********************/
#ifdef __KERNEL__

struct ll_sb_info;

struct lustre_sb_info {
	int                       lsi_flags;
	struct obd_device        *lsi_mgc;     /* mgc obd */
	struct lustre_mount_data *lsi_lmd;     /* mount command info */
	struct ll_sb_info        *lsi_llsbi;   /* add'l client sbi info */
	struct dt_device	 *lsi_dt_dev;  /* dt device to access disk fs*/
	atomic_t		  lsi_mounts;  /* references to the srv_mnt */
	char			  lsi_svname[MTI_NAME_MAXLEN];
	char			  lsi_osd_obdname[64];
	char			  lsi_osd_uuid[64];
	struct obd_export	 *lsi_osd_exp;
	char			  lsi_osd_type[16];
	char			  lsi_fstype[16];
	struct backing_dev_info   lsi_bdi;     /* each client mountpoint needs
						  own backing_dev_info */
	struct list_head	  lsi_lwp_list;
	spinlock_t		  lsi_lwp_lock;
	unsigned long		  lsi_lwp_started:1;
};

#define LSI_UMOUNT_FAILOVER              0x00200000
#define LSI_BDI_INITIALIZED              0x00400000

#define     s2lsi(sb)        ((struct lustre_sb_info *)((sb)->s_fs_info))
#define     s2lsi_nocast(sb) ((sb)->s_fs_info)

#define     get_profile_name(sb)   (s2lsi(sb)->lsi_lmd->lmd_profile)
#define	    get_mount_flags(sb)	   (s2lsi(sb)->lsi_lmd->lmd_flags)
#define	    get_mntdev_name(sb)	   (s2lsi(sb)->lsi_lmd->lmd_dev)
#define     get_mount_fileset(sb)  (s2lsi(sb)->lsi_lmd->lmd_fileset)

#endif /* __KERNEL__ */

/****************** mount lookup info *********************/

struct lustre_mount_info {
	char			*lmi_name;
	struct super_block	*lmi_sb;
	struct list_head	 lmi_list_chain;
};

/****************** prototypes *********************/

#ifdef __KERNEL__
/* obd_mount.c */
int server_name2fsname(const char *svname, char *fsname, const char **endptr);
int server_name2svname(const char *label, char *svname, const char **endptr,
		       size_t svsize);
int server_name_is_ost(const char *svname);
int target_name2index(const char *svname, __u32 *idx, const char **endptr);

int lustre_put_lsi(struct super_block *sb);
int lustre_start_simple(char *obdname, char *type, char *uuid,
			char *s1, char *s2, char *s3, char *s4);
int lustre_start_mgc(struct super_block *sb);
void lustre_register_client_fill_super(int (*cfs)(struct super_block *sb,
						  struct vfsmount *mnt));
void lustre_register_kill_super_cb(void (*cfs)(struct super_block *sb));
int lustre_common_put_super(struct super_block *sb);

# ifdef HAVE_SERVER_SUPPORT
/* obd_mount_server.c */
int server_fill_super(struct super_block *sb);
struct lustre_mount_info *server_get_mount(const char *name);
int server_put_mount(const char *name, bool dereg_mnt);
struct mgs_target_info;
int server_mti_print(const char *title, struct mgs_target_info *mti);
void server_calc_timeout(struct lustre_sb_info *lsi, struct obd_device *obd);
# endif

int mgc_fsname2resid(char *fsname, struct ldlm_res_id *res_id, int type);
#endif /* __KERNEL__ */

/** @} disk */

#endif // _LUSTRE_DISK_H
