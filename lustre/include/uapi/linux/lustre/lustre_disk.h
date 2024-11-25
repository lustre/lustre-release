/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

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
#include <linux/uuid.h>
#include <linux/lnet/lnet-types.h> /* for lnet_nid_t */
#include <linux/lustre/lustre_param.h>   /* for LDD_PARAM_LEN */

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

/* On-disk configuration file. In host-endian order. */
struct lustre_disk_data {
	__u32 ldd_magic;
	__u32 ldd_feature_compat;	/* compatible feature flags */
	__u32 ldd_feature_rocompat;	/* read-only compatible feature flags */
	__u32 ldd_feature_incompat;	/* incompatible feature flags */

	__u32 ldd_config_ver;		/* config rewrite count - not used */
	__u32 ldd_flags;		/* LDD_SV_TYPE */
	__u32 ldd_svindex;		/* server index (0001), must match
					 * svname
					 */
	__u32 ldd_mount_type;		/* target fs type LDD_MT_* */
	char  ldd_fsname[64];		/* filesystem this server is part of,
					 * MTI_NAME_MAXLEN
					 */
	char  ldd_svname[64];		/* this server's name (lustre-mdt0001)*/
	__u8  ldd_uuid[40];		/* server UUID (COMPAT_146) */

	char  ldd_userdata[1024 - 200];	/* arbitrary user string '200' */
	__u8  ldd_padding[4096 - 1024];	/* 1024 */
	char  ldd_mount_opts[4096];	/* target fs mount opts '4096' */
	char  ldd_params[LDD_PARAM_LEN];/* key=value pairs '8192' */
};

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
	LDD_MT_LDISKFS = 1,
	LDD_MT_REISERFS = 3,
	LDD_MT_LDISKFS2 = 4,
	LDD_MT_ZFS = 5,
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
struct lsd_reply_data_v1 {
	__u64 lrd_transno;	/* transaction number */
	__u64 lrd_xid;		/* transmission id */
	__u64 lrd_data;		/* per-operation data */
	__u32 lrd_result;	/* request result */
	__u32 lrd_client_gen;	/* client generation */
};

struct lsd_reply_data_v2 {
	__u64 lrd_transno;	/* transaction number */
	__u64 lrd_xid;		/* transmission id */
	__u64 lrd_data;		/* per-operation data */
	__u32 lrd_result;	/* request result */
	__u32 lrd_client_gen;	/* client generation */
	__u32 lrd_batch_idx;	/* sub request index in the batched RPC */
	__u32 lrd_padding[7];	/* unused fields, total size is 8X __u64 */
};

#define lsd_reply_data lsd_reply_data_v2

/* Header of the reply_data file */
#define LRH_MAGIC_V1		0xbdabda01
#define LRH_MAGIC_V2		0xbdabda02
#define LRH_MAGIC		LRH_MAGIC_V1

/* Don't change the header size for compatibility. */
struct lsd_reply_header {
	__u32	lrh_magic;
	__u32	lrh_header_size;
	__u32	lrh_reply_size;
	__u8	lrh_pad[sizeof(struct lsd_reply_data_v1) - 12];
};

/****************** nodemap *********************/

enum nodemap_idx_type {
	NODEMAP_EMPTY_IDX = 0,		/* index created with blank record */
	NODEMAP_CLUSTER_IDX = 1,	/* a nodemap cluster of nodes */
	NODEMAP_RANGE_IDX = 2,		/* nid range assigned to a nm cluster */
	NODEMAP_UIDMAP_IDX = 3,		/* uid map assigned to a nm cluster */
	NODEMAP_GIDMAP_IDX = 4,		/* gid map assigned to a nm cluster */
	NODEMAP_PROJIDMAP_IDX = 5,	/* projid map assigned to nm cluster */
	NODEMAP_NID_MASK_IDX = 6,	/* large NID setup for a nm cluster */
	NODEMAP_GLOBAL_IDX = 15,	/* stores nodemap activation status */
};

/* This is needed for struct nodemap_clustre_rec. Please don't move
 * to lustre_idl.h which will break user land builds.
 */
#define LUSTRE_NODEMAP_NAME_LENGTH     16

/* lu_nodemap flags */
enum nm_flag_bits {
	NM_FL_ALLOW_ROOT_ACCESS = 0x1,
	NM_FL_TRUST_CLIENT_IDS = 0x2,
	NM_FL_DENY_UNKNOWN = 0x4,
	NM_FL_MAP_UID = 0x8,
	NM_FL_MAP_GID = 0x10,
	NM_FL_ENABLE_AUDIT = 0x20,
	NM_FL_FORBID_ENCRYPT = 0x40,
	NM_FL_MAP_PROJID = 0x80,
};

enum nm_flag2_bits {
	NM_FL2_READONLY_MOUNT = 0x1,
	NM_FL2_DENY_MOUNT = 0x2,
};

/* Nodemap records, uses 32 byte record length.
 * New nodemap config records can be added into NODEMAP_CLUSTER_IDX
 * with a new nk_cluster_subid value, as long as the records are
 * kept at 32 bytes in size.  New global config records can be added
 * into NODEMAP_GLOBAL_IDX with a new nk_global_subid.  This avoids
 * breaking compatibility.  Do not change the record size.  If a
 * new ID type or range is needed, a new IDX type should be used.
 */
struct nodemap_cluster_rec {
	char			ncr_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	enum nm_flag_bits	ncr_flags:8;
	enum nm_flag2_bits	ncr_flags2:8;
	__u8			ncr_padding1;	/* zeroed since 2.16 */
	__u32			ncr_squash_projid;
	__u32			ncr_squash_uid;
	__u32			ncr_squash_gid;
};

/* lnet_nid_t is 8 bytes */
struct nodemap_range_rec {
	lnet_nid_t	nrr_start_nid;
	lnet_nid_t	nrr_end_nid;
	__u64		nrr_padding1;	/* zeroed since 2.16 */
	__u64		nrr_padding2;	/* zeroed since 2.16 */
};

struct nodemap_range2_rec {
	struct lnet_nid	nrr_nid_prefix;
	__u32		nrr_padding1;	/* padding may be used for nid_prefix */
	__u32		nrr_padding2;	/* if nrr_nid_prefix.nid_size > 12 */
	__u16		nrr_padding3;	/* zeroed since 2.16 */
	__u8		nrr_padding4;	/* zeroed since 2.16 */
	__u8		nrr_netmask;
};

struct nodemap_id_rec {
	__u32	nir_id_fs;
	__u32	nir_padding1;		/* zeroed since 2.16 */
	__u64	nir_padding2;		/* zeroed since 2.16 */
	__u64	nir_padding3;		/* zeroed since 2.16 */
	__u64	nir_padding4;		/* zeroed since 2.16 */
};

struct nodemap_global_rec {
	__u8	ngr_is_active;
	__u8	ngr_padding1;		/* zeroed since 2.16 */
	__u16	ngr_padding2;		/* zeroed since 2.16 */
	__u32	ngr_padding3;		/* zeroed since 2.16 */
	__u64	ngr_padding4;		/* zeroed since 2.16 */
	__u64	ngr_padding5;		/* zeroed since 2.16 */
	__u64	ngr_padding6;		/* zeroed since 2.16 */
};

struct nodemap_cluster_roles_rec {
	__u64 ncrr_roles;		/* enum nodemap_rbac_roles */
	__u64 ncrr_padding1;		/* zeroed since 2.16 (always) */
	__u64 ncrr_padding2;		/* zeroed since 2.16 (always) */
	__u64 ncrr_padding3;		/* zeroed since 2.16 (always) */
};

struct nodemap_offset_rec {
	__u32 nor_start_uid;
	__u32 nor_limit_uid;
	__u32 nor_start_gid;
	__u32 nor_limit_gid;
	__u32 nor_start_projid;
	__u32 nor_limit_projid;
	__u32 nor_padding1;
	__u32 nor_padding2;
};

union nodemap_rec {
	struct nodemap_cluster_rec ncr;
	struct nodemap_range_rec nrr;
	struct nodemap_range2_rec nrr2;
	struct nodemap_id_rec nir;
	struct nodemap_global_rec ngr;
	struct nodemap_cluster_roles_rec ncrr;
	struct nodemap_offset_rec nor;
};

/* sub-keys for records of type NODEMAP_CLUSTER_IDX */
enum nodemap_cluster_rec_subid {
	NODEMAP_CLUSTER_REC = 0,   /* nodemap_cluster_rec */
	NODEMAP_CLUSTER_ROLES = 1, /* nodemap_cluster_roles_rec */
	NODEMAP_CLUSTER_OFFSET = 2, /* UID/GID/PROJID offset for a nm cluster */
};

/* first 4 bits of the nodemap_id is the index type */
struct nodemap_key {
	__u32 nk_nodemap_id;
	union {
		__u32 nk_cluster_subid;
		__u32 nk_range_id;
		__u32 nk_id_client;
		__u32 nk_unused;
	};
};

#define NM_TYPE_MASK 0x0FFFFFFF
#define NM_TYPE_SHIFT 28

/* file structure used for saving OI scrub bookmark state for restart */
#define OSD_OI_FID_OID_BITS_MAX	10
#define OSD_OI_FID_NR_MAX	(1UL << OSD_OI_FID_OID_BITS_MAX)
#define SCRUB_OI_BITMAP_SIZE	(OSD_OI_FID_NR_MAX >> 3)

#define SCRUB_MAGIC_V1			0x4C5FD252
#define SCRUB_MAGIC_V2			0x4C5FE253

enum scrub_flags {
	/* OI files have been recreated, OI mappings should be re-inserted. */
	SF_RECREATED	= 0x0000000000000001ULL,

	/* OI files are invalid, should be rebuild ASAP */
	SF_INCONSISTENT	= 0x0000000000000002ULL,

	/* OI scrub is triggered automatically. */
	SF_AUTO		= 0x0000000000000004ULL,

	/* The device is upgraded from 1.8 format. */
	SF_UPGRADE	= 0x0000000000000008ULL,
};

enum scrub_status {
	/* The scrub file is new created, for new MDT, upgrading from old disk,
	 * or re-creating the scrub file manually.
	 */
	SS_INIT		= 0,

	/* The scrub is checking/repairing the OI files. */
	SS_SCANNING	= 1,

	/* The scrub checked/repaired the OI files successfully. */
	SS_COMPLETED	= 2,

	/* The scrub failed to check/repair the OI files. */
	SS_FAILED	= 3,

	/* The scrub is stopped manually, the OI files may be inconsistent. */
	SS_STOPPED	= 4,

	/* The scrub is paused automatically when umount. */
	SS_PAUSED	= 5,

	/* The scrub crashed during the scanning, should be restarted. */
	SS_CRASHED	= 6,
};

enum scrub_param {
	/* Exit when fail. */
	SP_FAILOUT	= 0x0001,

	/* Check only without repairing. */
	SP_DRYRUN	= 0x0002,
};

#ifdef __KERNEL__
/* v6.2-rc5-72-g5e6a51787fef kernel APIs need type to be guid_t */
#define uuid_le        guid_t
#endif

struct scrub_file {
	uuid_le	sf_uuid;		    /* 128-bit uuid for volume */
	__u64	sf_flags;		    /* see 'enum scrub_flags' */
	__u32	sf_magic;		    /* SCRUB_MAGIC_V1/V2 */
	__u16	sf_status;		    /* see 'enum scrub_status' */
	__u16	sf_param;		    /* see 'enum scrub_param' */
	__s64	sf_time_last_complete;      /* wallclock of last scrub finish */
	__s64	sf_time_latest_start;	    /* wallclock of last scrub run */
	__s64   sf_time_last_checkpoint;    /* wallclock of last checkpoint */
	__u64	sf_pos_latest_start;	    /* OID of last scrub start */
	__u64	sf_pos_last_checkpoint;     /* OID of last scrub checkpoint */
	__u64	sf_pos_first_inconsistent;  /* OID first object to update */
	__u64	sf_items_checked;	    /* number objects checked */
	__u64	sf_items_updated;           /* number objects updated */
	__u64	sf_items_failed;	    /* number objects unrepairable */
	__u64	sf_items_updated_prior;     /* num objects fixed before scan */
	__u64	sf_items_noscrub;	    /* number of objects skipped due to
					     * LDISKFS_STATE_LUSTRE_NOSCRUB
					     */
	__u64   sf_items_igif;		    /* number of IGIF(no FID) objects */
	__u32	sf_run_time;		    /* scrub runtime in seconds */
	__u32	sf_success_count;	    /* number of completed runs */
	__u16	sf_oi_count;		    /* number of OI files */
	__u16	sf_internal_flags;	    /* flags to keep after reset, see
					     * 'enum scrub_internal_flags'
					     */
	__u32	sf_reserved_1;
	__u64	sf_reserved_2[16];
	__u8    sf_oi_bitmap[SCRUB_OI_BITMAP_SIZE]; /* OI files recreated */
};

/** @} disk */

#endif /* _UAPI_LUSTRE_DISK_H */
