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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre disk format definitions.
 *
 * Author: Nathan Rutman <nathan.rutman@seagate.com>
 */

#ifndef _UAPI_LUSTRE_DISK_H
#define _UAPI_LUSTRE_DISK_H

/** \defgroup disk disk
 *
 * @{
 */
#include <linux/types.h>

/****************** on-disk files ********************/

#define MDT_LOGS_DIR		"LOGS"	/* COMPAT_146 */
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
#define QSD_DIR_DT		"quota_slave_dt"
#define QSD_DIR_MD		"quota_slave_md"
#define HSM_ACTIONS		"hsm_actions"
#define LFSCK_DIR		"LFSCK"
#define LFSCK_BOOKMARK		"lfsck_bookmark"
#define LFSCK_LAYOUT		"lfsck_layout"
#define LFSCK_NAMESPACE		"lfsck_namespace"
#define REMOTE_PARENT_DIR	"REMOTE_PARENT_DIR"
#define INDEX_BACKUP_DIR	"index_backup"
#define MDT_ORPHAN_DIR		"PENDING"

/****************** persistent mount data *********************/

#define LDD_F_SV_TYPE_MDT	0x0001
#define LDD_F_SV_TYPE_OST	0x0002
#define LDD_F_SV_TYPE_MGS	0x0004
#define LDD_F_SV_TYPE_MASK	(LDD_F_SV_TYPE_MDT  | \
				 LDD_F_SV_TYPE_OST  | \
				 LDD_F_SV_TYPE_MGS)
#define LDD_F_SV_ALL		0x0008
/** need an index assignment */
#define LDD_F_NEED_INDEX	0x0010
/** never registered */
#define LDD_F_VIRGIN		0x0020
/** update the config logs for this server */
#define LDD_F_UPDATE		0x0040
/** rewrite the LDD */
#define LDD_F_REWRITE_LDD	0x0080
/** regenerate config logs for this fs or server */
#define LDD_F_WRITECONF		0x0100
/** COMPAT_14 */
/*#define LDD_F_UPGRADE14		0x0200 deprecated since 1.8 */
/** process as lctl conf_param */
#define LDD_F_PARAM		0x0400
/** all nodes are specified as service nodes */
#define LDD_F_NO_PRIMNODE	0x1000
/** IR enable flag */
#define LDD_F_IR_CAPABLE	0x2000
/** the MGS refused to register the target. */
#define LDD_F_ERROR		0x4000
/** process at lctl conf_param */
#define LDD_F_PARAM2		0x8000
/** the target shouldn't use local logs */
#define LDD_F_NO_LOCAL_LOGS	0x10000

#define LDD_MAGIC 0x1dd00001

#define XATTR_TARGET_RENAME "trusted.rename_tgt"

enum ldd_mount_type {
	LDD_MT_EXT3 = 0,
	LDD_MT_LDISKFS,
	LDD_MT_SMFS,
	LDD_MT_REISERFS,
	LDD_MT_LDISKFS2,
	LDD_MT_ZFS,
	LDD_MT_LAST
};

/****************** last_rcvd file *********************/

#define LR_EXPIRE_INTERVALS 16	/**< number of intervals to track transno */
#define LR_SERVER_SIZE	512
#define LR_CLIENT_START	8192
#define LR_CLIENT_SIZE	128
#if LR_CLIENT_START < LR_SERVER_SIZE
#error "Can't have LR_CLIENT_START < LR_SERVER_SIZE"
#endif

/*
 * Data stored per server at the head of the last_rcvd file. In le32 order.
 */
struct lr_server_data {
	__u8  lsd_uuid[40];	   /* server UUID */
	__u64 lsd_last_transno;    /* last completed transaction ID */
	__u64 lsd_compat14;	   /* reserved - compat with old last_rcvd */
	__u64 lsd_mount_count;	   /* incarnation number */
	__u32 lsd_feature_compat;  /* compatible feature flags */
	__u32 lsd_feature_rocompat;/* read-only compatible feature flags */
	__u32 lsd_feature_incompat;/* incompatible feature flags */
	__u32 lsd_server_size;	   /* size of server data area */
	__u32 lsd_client_start;    /* start of per-client data area */
	__u16 lsd_client_size;	   /* size of per-client data area */
	__u16 lsd_subdir_count;    /* number of subdirectories for objects */
	__u64 lsd_catalog_oid;	   /* recovery catalog object id */
	__u32 lsd_catalog_ogen;    /* recovery catalog inode generation */
	__u8  lsd_peeruuid[40];    /* UUID of MDS associated with this OST */
	__u32 lsd_osd_index;	   /* index number of OST in LOV */
	__u32 lsd_padding1;	   /* was lsd_mdt_index, unused in 2.4.0 */
	__u32 lsd_start_epoch;	   /* VBR: start epoch from last boot */
	/** transaction values since lsd_trans_table_time */
	__u64 lsd_trans_table[LR_EXPIRE_INTERVALS];
	/** start point of transno table below */
	__u32 lsd_trans_table_time; /* time of first slot in table above */
	__u32 lsd_expire_intervals; /* LR_EXPIRE_INTERVALS */
	__u8  lsd_padding[LR_SERVER_SIZE - 288];
};

/* Data stored per client in the last_rcvd file. In le32 order. */
struct lsd_client_data {
	__u8  lcd_uuid[40];		/* client UUID */
	__u64 lcd_last_transno;		/* last completed transaction ID */
	__u64 lcd_last_xid;		/* xid for the last transaction */
	__u32 lcd_last_result;		/* result from last RPC */
	__u32 lcd_last_data;		/* per-op data (disposition for
					 * open &c.)
					 */
	/* for MDS_CLOSE requests */
	__u64 lcd_last_close_transno;	/* last completed transaction ID */
	__u64 lcd_last_close_xid;	/* xid for the last transaction */
	__u32 lcd_last_close_result;	/* result from last RPC */
	__u32 lcd_last_close_data;	/* per-op data */
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
	__u64 lrd_transno;	/* transaction number */
	__u64 lrd_xid;		/* transmission id */
	__u64 lrd_data;		/* per-operation data */
	__u32 lrd_result;	/* request result */
	__u32 lrd_client_gen;	/* client generation */
};

/* Header of the reply_data file */
#define LRH_MAGIC 0xbdabda01
struct lsd_reply_header {
	__u32	lrh_magic;
	__u32	lrh_header_size;
	__u32	lrh_reply_size;
	__u8	lrh_pad[sizeof(struct lsd_reply_data) - 12];
};

/** @} disk */

#endif /* _UAPI_LUSTRE_DISK_H */
