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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <linux/backing-dev.h>
#include <linux/list.h>
#include <libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_disk.h>
#include <uapi/linux/lustre/lustre_idl.h>

#define IS_MDT(data)		((data)->lsi_flags & LDD_F_SV_TYPE_MDT)
#define IS_OST(data)		((data)->lsi_flags & LDD_F_SV_TYPE_OST)
#define IS_MGS(data)		((data)->lsi_flags & LDD_F_SV_TYPE_MGS)
#define IS_SERVER(data)		((data)->lsi_flags & (LDD_F_SV_TYPE_MGS | \
						      LDD_F_SV_TYPE_MDT | \
						      LDD_F_SV_TYPE_OST))
#define MT_STR(data)		mt_str((data)->ldd_mount_type)

/****************** mount command *********************/

/* The lmd is only used internally by Lustre; mount simply passes
 * everything as string options
 */
#define LMD_MAGIC		0xbdacbd03
#define LMD_PARAMS_MAXLEN	4096

/* gleaned from the mount command - no persistent info here */
struct lustre_mount_data {
	u32	lmd_magic;
	u32	lmd_flags;	/* lustre mount flags */
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
	u32    *lmd_exclude;	/* array of OSTs to ignore */
	char   *lmd_mgs;	/* MGS nid */
	char   *lmd_osd_type;	/* OSD type */
	char   *lmd_nidnet;     /* network to restrict this client to */
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
#define LMD_FLG_DEV_RDONLY	0x8000	/* discard modification quitely */
#define LMD_FLG_NO_PRECREATE	0x10000	/* do not allow OST object creation */
#define LMD_FLG_LOCAL_RECOV	0x20000 /* force recovery for local clients */
#define LMD_FLG_ABORT_RECOV_MDT	0x40000 /* Abort recovery between MDTs */
#define LMD_FLG_NO_LOCAL_LOGS	0x80000 /* Use config logs from MGS */

#define lmd_is_client(x) ((x)->lmd_flags & LMD_FLG_CLIENT)

/****************** superblock additional info *********************/
struct ll_sb_info;
struct kobject;

struct lustre_sb_info {
	int                       lsi_flags;
	struct obd_device        *lsi_mgc;     /* mgc obd */
	struct lustre_mount_data *lsi_lmd;     /* mount command info */
	struct ll_sb_info        *lsi_llsbi;   /* add'l client sbi info */
	struct dt_device	 *lsi_dt_dev;  /* dt device to access disk fs*/
	atomic_t		  lsi_mounts;  /* references to the srv_mnt */
	struct kobject		 *lsi_kobj;
	char			  lsi_svname[MTI_NAME_MAXLEN];
	/* lsi_osd_obdname format = 'lsi->ls_svname'-osd */
	char			  lsi_osd_obdname[MTI_NAME_MAXLEN + 4];
	/* lsi_osd_uuid format = 'lsi->ls_osd_obdname'_UUID */
	char			  lsi_osd_uuid[MTI_NAME_MAXLEN + 9];
	struct obd_export	 *lsi_osd_exp;
	char			  lsi_osd_type[16];
	char			  lsi_fstype[16];
	struct backing_dev_info   lsi_bdi;     /* each client mountpoint needs
						  own backing_dev_info */
	/* protect lsi_lwp_list */
	struct mutex		  lsi_lwp_mutex;
	struct list_head	  lsi_lwp_list;
	unsigned long		  lsi_lwp_started:1,
				  lsi_server_started:1;
#ifdef CONFIG_LL_ENCRYPTION
	const struct llcrypt_operations	*lsi_cop;
	struct key		 *lsi_master_keys; /* master crypto keys used */
#endif
};

#define LSI_UMOUNT_FAILOVER              0x00200000

#define     s2lsi(sb)        ((struct lustre_sb_info *)((sb)->s_fs_info))
#define     s2lsi_nocast(sb) ((sb)->s_fs_info)

#define     get_profile_name(sb)   (s2lsi(sb)->lsi_lmd->lmd_profile)
#define     get_mount_fileset(sb)  (s2lsi(sb)->lsi_lmd->lmd_fileset)

# ifdef HAVE_SERVER_SUPPORT
/* opc for target register */
#define LDD_F_OPC_REG   0x10000000
#define LDD_F_OPC_UNREG 0x20000000
#define LDD_F_OPC_READY 0x40000000
#define LDD_F_OPC_MASK  0xf0000000

#define LDD_F_MASK	0xFFFF

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
/** lmm_stripe_count has been shrunk from u32 to u16 and the remaining 16
 * bits are now used to store a generation. Once we start changing the layout
 * and bumping the generation, old versions expecting a 32-bit lmm_stripe_count
 * will be confused by interpreting stripe_count | gen << 16 as the actual
 * stripe count */
#define OBD_INCOMPAT_LMM_VER    0x00000100
/** multiple OI files for MDT */
#define OBD_INCOMPAT_MULTI_OI   0x00000200
/** multiple RPCs in flight */
#define OBD_INCOMPAT_MULTI_RPCS	0x00000400

/* last_rcvd handling */
static inline void lsd_le_to_cpu(struct lr_server_data *buf,
                                 struct lr_server_data *lsd)
{
	int i;

	memcpy(lsd->lsd_uuid, buf->lsd_uuid, sizeof(lsd->lsd_uuid));
	lsd->lsd_last_transno = le64_to_cpu(buf->lsd_last_transno);
	lsd->lsd_compat14 = le64_to_cpu(buf->lsd_compat14);
	lsd->lsd_mount_count = le64_to_cpu(buf->lsd_mount_count);
	lsd->lsd_feature_compat = le32_to_cpu(buf->lsd_feature_compat);
	lsd->lsd_feature_rocompat = le32_to_cpu(buf->lsd_feature_rocompat);
	lsd->lsd_feature_incompat = le32_to_cpu(buf->lsd_feature_incompat);
	lsd->lsd_server_size = le32_to_cpu(buf->lsd_server_size);
	lsd->lsd_client_start = le32_to_cpu(buf->lsd_client_start);
	lsd->lsd_client_size = le16_to_cpu(buf->lsd_client_size);
	lsd->lsd_subdir_count = le16_to_cpu(buf->lsd_subdir_count);
	lsd->lsd_catalog_oid = le64_to_cpu(buf->lsd_catalog_oid);
	lsd->lsd_catalog_ogen = le32_to_cpu(buf->lsd_catalog_ogen);
	memcpy(lsd->lsd_peeruuid, buf->lsd_peeruuid, sizeof(lsd->lsd_peeruuid));
	lsd->lsd_osd_index = le32_to_cpu(buf->lsd_osd_index);
	lsd->lsd_padding1 = le32_to_cpu(buf->lsd_padding1);
	lsd->lsd_start_epoch = le32_to_cpu(buf->lsd_start_epoch);
	for (i = 0; i < LR_EXPIRE_INTERVALS; i++)
		lsd->lsd_trans_table[i] = le64_to_cpu(buf->lsd_trans_table[i]);
	lsd->lsd_trans_table_time = le32_to_cpu(buf->lsd_trans_table_time);
	lsd->lsd_expire_intervals = le32_to_cpu(buf->lsd_expire_intervals);
}

static inline void lsd_cpu_to_le(struct lr_server_data *lsd,
                                 struct lr_server_data *buf)
{
	int i;

	memcpy(buf->lsd_uuid, lsd->lsd_uuid, sizeof(buf->lsd_uuid));
	buf->lsd_last_transno = cpu_to_le64(lsd->lsd_last_transno);
	buf->lsd_compat14 = cpu_to_le64(lsd->lsd_compat14);
	buf->lsd_mount_count = cpu_to_le64(lsd->lsd_mount_count);
	buf->lsd_feature_compat = cpu_to_le32(lsd->lsd_feature_compat);
	buf->lsd_feature_rocompat = cpu_to_le32(lsd->lsd_feature_rocompat);
	buf->lsd_feature_incompat = cpu_to_le32(lsd->lsd_feature_incompat);
	buf->lsd_server_size = cpu_to_le32(lsd->lsd_server_size);
	buf->lsd_client_start = cpu_to_le32(lsd->lsd_client_start);
	buf->lsd_client_size = cpu_to_le16(lsd->lsd_client_size);
	buf->lsd_subdir_count = cpu_to_le16(lsd->lsd_subdir_count);
	buf->lsd_catalog_oid = cpu_to_le64(lsd->lsd_catalog_oid);
	buf->lsd_catalog_ogen = cpu_to_le32(lsd->lsd_catalog_ogen);
	memcpy(buf->lsd_peeruuid, lsd->lsd_peeruuid, sizeof(buf->lsd_peeruuid));
	buf->lsd_osd_index = cpu_to_le32(lsd->lsd_osd_index);
	buf->lsd_padding1 = cpu_to_le32(lsd->lsd_padding1);
	buf->lsd_start_epoch = cpu_to_le32(lsd->lsd_start_epoch);
	for (i = 0; i < LR_EXPIRE_INTERVALS; i++)
		buf->lsd_trans_table[i] = cpu_to_le64(lsd->lsd_trans_table[i]);
	buf->lsd_trans_table_time = cpu_to_le32(lsd->lsd_trans_table_time);
	buf->lsd_expire_intervals = cpu_to_le32(lsd->lsd_expire_intervals);
}

static inline void lcd_le_to_cpu(struct lsd_client_data *buf,
                                 struct lsd_client_data *lcd)
{
        memcpy(lcd->lcd_uuid, buf->lcd_uuid, sizeof (lcd->lcd_uuid));
	lcd->lcd_last_transno = le64_to_cpu(buf->lcd_last_transno);
	lcd->lcd_last_xid = le64_to_cpu(buf->lcd_last_xid);
	lcd->lcd_last_result = le32_to_cpu(buf->lcd_last_result);
	lcd->lcd_last_data = le32_to_cpu(buf->lcd_last_data);
	lcd->lcd_last_close_transno = le64_to_cpu(buf->lcd_last_close_transno);
	lcd->lcd_last_close_xid = le64_to_cpu(buf->lcd_last_close_xid);
	lcd->lcd_last_close_result = le32_to_cpu(buf->lcd_last_close_result);
	lcd->lcd_last_close_data = le32_to_cpu(buf->lcd_last_close_data);
	lcd->lcd_pre_versions[0] = le64_to_cpu(buf->lcd_pre_versions[0]);
	lcd->lcd_pre_versions[1] = le64_to_cpu(buf->lcd_pre_versions[1]);
	lcd->lcd_pre_versions[2] = le64_to_cpu(buf->lcd_pre_versions[2]);
	lcd->lcd_pre_versions[3] = le64_to_cpu(buf->lcd_pre_versions[3]);
	lcd->lcd_last_epoch = le32_to_cpu(buf->lcd_last_epoch);
	lcd->lcd_generation = le32_to_cpu(buf->lcd_generation);
}

static inline void lcd_cpu_to_le(struct lsd_client_data *lcd,
                                 struct lsd_client_data *buf)
{
        memcpy(buf->lcd_uuid, lcd->lcd_uuid, sizeof (lcd->lcd_uuid));
	buf->lcd_last_transno = cpu_to_le64(lcd->lcd_last_transno);
	buf->lcd_last_xid = cpu_to_le64(lcd->lcd_last_xid);
	buf->lcd_last_result = cpu_to_le32(lcd->lcd_last_result);
	buf->lcd_last_data = cpu_to_le32(lcd->lcd_last_data);
	buf->lcd_last_close_transno = cpu_to_le64(lcd->lcd_last_close_transno);
	buf->lcd_last_close_xid = cpu_to_le64(lcd->lcd_last_close_xid);
	buf->lcd_last_close_result = cpu_to_le32(lcd->lcd_last_close_result);
	buf->lcd_last_close_data = cpu_to_le32(lcd->lcd_last_close_data);
	buf->lcd_pre_versions[0] = cpu_to_le64(lcd->lcd_pre_versions[0]);
	buf->lcd_pre_versions[1] = cpu_to_le64(lcd->lcd_pre_versions[1]);
	buf->lcd_pre_versions[2] = cpu_to_le64(lcd->lcd_pre_versions[2]);
	buf->lcd_pre_versions[3] = cpu_to_le64(lcd->lcd_pre_versions[3]);
	buf->lcd_last_epoch = cpu_to_le32(lcd->lcd_last_epoch);
	buf->lcd_generation = cpu_to_le32(lcd->lcd_generation);
}

static inline u64 lcd_last_transno(struct lsd_client_data *lcd)
{
        return (lcd->lcd_last_transno > lcd->lcd_last_close_transno ?
                lcd->lcd_last_transno : lcd->lcd_last_close_transno);
}

static inline u64 lcd_last_xid(struct lsd_client_data *lcd)
{
        return (lcd->lcd_last_xid > lcd->lcd_last_close_xid ?
                lcd->lcd_last_xid : lcd->lcd_last_close_xid);
}

/****************** mount lookup info *********************/

struct lustre_mount_info {
	char			*lmi_name;
	struct super_block	*lmi_sb;
	struct list_head	 lmi_list_chain;
};

/****************** prototypes *********************/

/* obd_mount_server.c */
int server_fill_super(struct super_block *sb);
struct lustre_mount_info *server_get_mount(const char *name);
int server_put_mount(const char *name, bool dereg_mnt);
struct mgs_target_info;
int server_mti_print(const char *title, struct mgs_target_info *mti);
void server_calc_timeout(struct lustre_sb_info *lsi, struct obd_device *obd);

/* obd_mount.c */
int server_name2svname(const char *label, char *svname, const char **endptr,
		       size_t svsize);

int server_name_is_ost(const char *svname);
int target_name2index(const char *svname, u32 *idx, const char **endptr);

int lustre_put_lsi(struct super_block *sb);
int lustre_start_simple(char *obdname, char *type, char *uuid,
			char *s1, char *s2, char *s3, char *s4);
#endif /* HAVE_SERVER_SUPPORT */
int server_name2fsname(const char *svname, char *fsname, const char **endptr);
void obdname2fsname(const char *tgt, char *fsname, size_t fslen);

int lustre_start_mgc(struct super_block *sb);
int lustre_common_put_super(struct super_block *sb);

struct lustre_sb_info *lustre_init_lsi(struct super_block *sb);
int lustre_put_lsi(struct super_block *sb);
int lmd_parse(char *options, struct lustre_mount_data *lmd);

/* mgc_request.c */
int mgc_fsname2resid(char *fsname, struct ldlm_res_id *res_id,
		     enum mgs_cfg_type type);
int mgc_logname2resid(char *fsname, struct ldlm_res_id *res_id,
		      enum mgs_cfg_type type);

/** @} disk */

#endif /* _LUSTRE_DISK_H */
