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
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * lustre/include/lustre_scrub.h
 *
 * Shared definitions and declarations for Lustre OI scrub.
 *
 * Author: Fan Yong <fan.yong@intel.com>
 */

#ifndef _LUSTRE_SCRUB_H
# define _LUSTRE_SCRUB_H

#include <linux/uuid.h>
#include <dt_object.h>
#include <lustre_net.h>
#include <uapi/linux/lustre/lustre_disk.h>

#define SCRUB_CHECKPOINT_INTERVAL	60
#define SCRUB_WINDOW_SIZE		1024

enum scrub_next_status {
	/* exit current loop and process next group */
	SCRUB_NEXT_BREAK	= 1,

	/* skip current object and process next bit */
	SCRUB_NEXT_CONTINUE	= 2,

	/* exit all the loops */
	SCRUB_NEXT_EXIT		= 3,

	/* wait for free cache slot */
	SCRUB_NEXT_WAIT		= 4,

	/* simulate system crash during OI scrub */
	SCRUB_NEXT_CRASH	= 5,

	/* simulate failure during OI scrub */
	SCRUB_NEXT_FATAL	= 6,

	/* new created object, no scrub on it */
	SCRUB_NEXT_NOSCRUB	= 7,

	/* the object has no FID-in-LMA */
	SCRUB_NEXT_NOLMA	= 8,

	/* for OST-object */
	SCRUB_NEXT_OSTOBJ	= 9,

	/* old OST-object, no LMA or no FID-on-OST flags in LMA */
	SCRUB_NEXT_OSTOBJ_OLD	= 10,
};

enum scrub_local_file_flags {
	SLFF_SCAN_SUBITEMS	= 0x0001,
	SLFF_HIDE_FID		= 0x0002,
	SLFF_SHOW_NAME		= 0x0004,
	SLFF_NO_OI		= 0x0008,
	SLFF_IDX_IN_FID		= 0x0010,
};

enum scrub_start {
	/* Set failout flag. */
	SS_SET_FAILOUT		= 0x00000001,

	/* Clear failout flag. */
	SS_CLEAR_FAILOUT	= 0x00000002,

	/* Reset scrub start position. */
	SS_RESET		= 0x00000004,

	/* Trigger full scrub automatically. */
	SS_AUTO_FULL		= 0x00000008,

	/* Trigger partial scrub automatically. */
	SS_AUTO_PARTIAL		= 0x00000010,

	/* Set dryrun flag. */
	SS_SET_DRYRUN		= 0x00000020,

	/* Clear dryrun flag. */
	SS_CLEAR_DRYRUN		= 0x00000040,
};

enum osd_lf_flags {
	OLF_SCAN_SUBITEMS	= 0x0001,
	OLF_HIDE_FID		= 0x0002,
	OLF_SHOW_NAME		= 0x0004,
	OLF_NO_OI		= 0x0008,
	OLF_IDX_IN_FID		= 0x0010,
	OLF_NOT_BACKUP		= 0x0020,
};

/* There are some overhead to detect OI inconsistency automatically
 * during normal RPC handling. We do not want to always auto detect
 * OI inconsistency especailly when OI scrub just done recently.
 *
 * The 'auto_scrub' defines the time (united as second) interval to
 * enable auto detect OI inconsistency since last OI scurb done.
 */
enum auto_scrub {
	/* Disable auto scrub. */
	AS_NEVER	= 0,

	/* 1 second is too short interval, it is almost equal to always auto
	 * detect inconsistent OI, usually used for test.
	 */
	AS_ALWAYS	= 1,

	/* Enable auto detect OI inconsistency one month (60 * 60 * 24 * 30)
	 * after last OI scrub.
	 */
	AS_DEFAULT	= 2592000LL,
};

struct lustre_scrub {
	/* Object for the scrub file. */
	struct dt_object       *os_obj;

	struct task_struct     *os_task;
	struct list_head	os_inconsistent_items;
	/* once inconsistent mapping can't be fixed, put into this list */
	struct list_head	os_stale_items;

	/* write lock for scrub prep/update/post/checkpoint,
	 * read lock for scrub dump.
	 */
	struct rw_semaphore	os_rwsem;
	spinlock_t		os_lock;

	/* Scrub file in memory. */
	struct scrub_file       os_file;

	/* Buffer for scrub file load/store. */
	struct scrub_file       os_file_disk;

	const char	       *os_name;

	/* The time for last checkpoint, seconds */
	time64_t		os_time_last_checkpoint;

	/* The time for next checkpoint, seconds */
	time64_t		os_time_next_checkpoint;

	/* How long to wait to start scrubbing */
	time64_t		os_auto_scrub_interval;

	/* How many objects have been checked since last checkpoint. */
	__u64			os_new_checked;
	__u64			os_pos_current;
	__u32			os_start_flags;

	/* FIDs with maxmimum OID in local storage */
	__u32			os_ls_size;
	__u32			os_ls_count;
	struct lu_fid		*os_ls_fids;

	/* Some of these bits can be set by different threads so
	 * all updates must be protected by ->os_lock to avoid
	 * racing read-modify-write cycles causing corruption.
	 */
	/* process inconsistent item found by RPC prior */
	unsigned int		os_in_prior:1,
				os_waiting:1, /* Waiting for scan window. */
				os_full_speed:1, /* run w/o speed limit */
				os_paused:1, /* The scrub is paused. */
				os_convert_igif:1,
				os_partial_scan:1,
				os_in_join:1,
				os_running:1,	/* scrub thread is running */
				os_full_scrub:1,
				os_has_ml_file:1;
};

#define INDEX_BACKUP_MAGIC_V1	0x1E41F208
#define INDEX_BACKUP_BUFSIZE	(4096 * 4)

enum lustre_index_backup_policy {
	/* By default, do not backup the index */
	LIBP_NONE	= 0,

	/* Backup the dirty index objects when umount */
	LIBP_AUTO	= 1,
};

struct lustre_index_backup_header {
	__u32		libh_magic;
	__u32		libh_count;
	__u32		libh_keysize;
	__u32		libh_recsize;
	struct lu_fid	libh_owner;
	__u64		libh_pad[60]; /* keep header 512 bytes aligned */
};

struct lustre_index_backup_unit {
	struct list_head	libu_link;
	struct lu_fid		libu_fid;
	__u32			libu_keysize;
	__u32			libu_recsize;
};

struct lustre_index_restore_unit {
	struct list_head	liru_link;
	struct lu_fid		liru_pfid;
	struct lu_fid		liru_cfid;
	__u64			liru_clid;
	int			liru_len;
	char			liru_name[];
};

void scrub_file_init(struct lustre_scrub *scrub, guid_t uuid);
void scrub_file_reset(struct lustre_scrub *scrub, guid_t uuid, u64 flags);
int scrub_file_load(const struct lu_env *env, struct lustre_scrub *scrub);
int scrub_file_store(const struct lu_env *env, struct lustre_scrub *scrub);
bool scrub_needs_check(struct lustre_scrub *scrub, const struct lu_fid *fid,
		       u64 index);
int scrub_checkpoint(const struct lu_env *env, struct lustre_scrub *scrub);
int scrub_thread_prep(const struct lu_env *env, struct lustre_scrub *scrub,
		      guid_t uuid, u64 start);
int scrub_thread_post(const struct lu_env *env, struct lustre_scrub *scrub,
		      int result);
int scrub_start(int (*threadfn)(void *data), struct lustre_scrub *scrub,
		void *data, __u32 flags);
void scrub_stop(struct lustre_scrub *scrub);
void scrub_dump(struct seq_file *m, struct lustre_scrub *scrub);

int lustre_liru_new(struct list_head *head, const struct lu_fid *pfid,
		    const struct lu_fid *cfid, __u64 child,
		    const char *name, int namelen);

int lustre_index_register(struct dt_device *dev, const char *devname,
			  struct list_head *head, spinlock_t *lock, int *guard,
			  const struct lu_fid *fid,
			  __u32 keysize, __u32 recsize);

void lustre_index_backup(const struct lu_env *env, struct dt_device *dev,
			 const char *devname, struct list_head *head,
			 spinlock_t *lock, int *guard, bool backup);
int lustre_index_restore(const struct lu_env *env, struct dt_device *dev,
			 const struct lu_fid *parent_fid,
			 const struct lu_fid *tgt_fid,
			 const struct lu_fid *bak_fid, const char *name,
			 struct list_head *head, spinlock_t *lock,
			 char *buf, int bufsize);

static inline void lustre_fid2lbx(char *buf, const struct lu_fid *fid, int len)
{
	snprintf(buf, len, DFID_NOBRACE".lbx", PFID(fid));
}

static inline const char *osd_scrub2name(struct lustre_scrub *scrub)
{
	return scrub->os_name;
}
#endif /* _LUSTRE_SCRUB_H */
