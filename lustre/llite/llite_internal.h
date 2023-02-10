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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef LLITE_INTERNAL_H
#define LLITE_INTERNAL_H
#include <obd.h>
#include <lustre_disk.h>  /* for s2sbi */
#include <lustre_linkea.h>

/* for struct cl_lock_descr and struct cl_io */
#include <cl_object.h>
#include <lustre_lmv.h>
#include <lustre_mdc.h>
#include <lustre_intent.h>
#include <linux/compat.h>
#include <linux/aio.h>
#include <linux/parser.h>
#include <lustre_compat.h>
#include <lustre_crypto.h>
#include <range_lock.h>

#include "vvp_internal.h"
#include "pcc.h"
#include "foreign_symlink.h"

#ifndef FMODE_EXEC
#define FMODE_EXEC 0
#endif

#ifndef HAVE_VM_FAULT_RETRY
#define VM_FAULT_RETRY 0
#endif

/* Kernel 3.1 kills LOOKUP_CONTINUE, LOOKUP_PARENT is equivalent to it.
 * seem kernel commit 49084c3bb2055c401f3493c13edae14d49128ca0 */
#ifndef LOOKUP_CONTINUE
#define LOOKUP_CONTINUE LOOKUP_PARENT
#endif

/** Only used on client-side for indicating the tail of dir hash/offset. */
#define LL_DIR_END_OFF          0x7fffffffffffffffULL
#define LL_DIR_END_OFF_32BIT    0x7fffffffUL

/* 4UL * 1024 * 1024 */
#define LL_MAX_BLKSIZE_BITS 22

#define LL_IT2STR(it) ((it) ? ldlm_it2str((it)->it_op) : "0")

#define TIMES_SET_FLAGS (ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET)

struct ll_dentry_data {
	unsigned int			lld_sa_generation;
	unsigned int			lld_invalid:1;
	unsigned int			lld_nfs_dentry:1;
	struct rcu_head			lld_rcu_head;
};

#define ll_d2d(de) ((struct ll_dentry_data*)((de)->d_fsdata))

#define LLI_INODE_MAGIC                 0x111d0de5
#define LLI_INODE_DEAD                  0xdeadd00d

struct ll_getname_data {
#ifdef HAVE_DIR_CONTEXT
	struct dir_context	ctx;
#endif
	char		*lgd_name;	/* points to a buffer with NAME_MAX+1 size */
	struct lu_fid	lgd_fid;	/* target fid we are looking for */
	int		lgd_found;	/* inode matched? */
};

struct ll_grouplock {
	struct lu_env	*lg_env;
	struct cl_io	*lg_io;
	struct cl_lock	*lg_lock;
	unsigned long	 lg_gid;
};

/* See comment on trunc_sem_down_read_nowait */
struct ll_trunc_sem {
	/* when positive, this is a count of readers, when -1, it indicates
	 * the semaphore is held for write, and 0 is unlocked
	 */
	atomic_t	ll_trunc_readers;
	/* this tracks a count of waiting writers */
	atomic_t	ll_trunc_waiters;
};

struct ll_inode_info {
	__u32				lli_inode_magic;
	rwlock_t			lli_lock;

	volatile unsigned long		lli_flags;
	struct posix_acl		*lli_posix_acl;

	/* identifying fields for both metadata and data stacks. */
	struct lu_fid			lli_fid;
	/* master inode fid for stripe directory */
	struct lu_fid			lli_pfid;

	/* We need all three because every inode may be opened in different
	 * modes */
	struct obd_client_handle       *lli_mds_read_och;
	struct obd_client_handle       *lli_mds_write_och;
	struct obd_client_handle       *lli_mds_exec_och;
	__u64				lli_open_fd_read_count;
	__u64				lli_open_fd_write_count;
	__u64				lli_open_fd_exec_count;

	/* Number of times this inode was opened */
	u64				lli_open_fd_count;
	/* When last close was performed on this inode */
	ktime_t				lli_close_fd_time;

	/* Protects access to och pointers and their usage counters */
	struct mutex			lli_och_mutex;

	struct inode			lli_vfs_inode;

	/* the most recent timestamps obtained from mds */
	s64				lli_atime;
	s64				lli_mtime;
	s64				lli_ctime;
	s64				lli_btime;
	spinlock_t			lli_agl_lock;

	/* Try to make the d::member and f::member are aligned. Before using
	 * these members, make clear whether it is directory or not. */
	union {
		/* for directory */
		struct {
			/* metadata statahead */
			/* since parent-child threads can share the same @file
			 * struct, "opendir_key" is the token when dir close for
			 * case of parent exit before child -- it is me should
			 * cleanup the dir readahead. */
			void			       *lli_opendir_key;
			struct ll_statahead_info       *lli_sai;
			/* protect statahead stuff. */
			spinlock_t			lli_sa_lock;
			/* "opendir_pid" is the token when lookup/revalid
			 * -- I am the owner of dir statahead. */
			pid_t				lli_opendir_pid;
			/* directory depth to ROOT */
			unsigned short			lli_dir_depth;
			/* stat will try to access statahead entries or start
			 * statahead if this flag is set, and this flag will be
			 * set upon dir open, and cleared when dir is closed,
			 * statahead hit ratio is too low, or start statahead
			 * thread failed. */
			unsigned short			lli_sa_enabled:1;
			/* generation for statahead */
			unsigned int			lli_sa_generation;
			/* rw lock protects lli_lsm_md */
			struct rw_semaphore		lli_lsm_sem;
			/* directory stripe information */
			struct lmv_stripe_md		*lli_lsm_md;
			/* directory default LMV */
			struct lmv_stripe_md		*lli_default_lsm_md;
		};

		/* for non-directory */
		struct {
			struct mutex		lli_size_mutex;
			char		       *lli_symlink_name;
			struct ll_trunc_sem	lli_trunc_sem;
			struct range_lock_tree	lli_write_tree;
			struct mutex		lli_setattr_mutex;

			struct rw_semaphore	lli_glimpse_sem;
			ktime_t			lli_glimpse_time;
			struct list_head	lli_agl_list;
			__u64			lli_agl_index;

			/* for writepage() only to communicate to fsync */
			int			lli_async_rc;

			/* protect the file heat fields */
			spinlock_t			lli_heat_lock;
			__u32				lli_heat_flags;
			struct obd_heat_instance	lli_heat_instances[OBD_HEAT_COUNT];

			/*
			 * Whenever a process try to read/write the file, the
			 * jobid of the process will be saved here, and it'll
			 * be packed into the write PRC when flush later.
			 *
			 * So the read/write statistics for jobid will not be
			 * accurate if the file is shared by different jobs.
			 */
			char                    lli_jobid[LUSTRE_JOBID_SIZE];

			struct mutex		 lli_pcc_lock;
			enum lu_pcc_state_flags	 lli_pcc_state;
			/*
			 * @lli_pcc_generation saves the gobal PCC generation
			 * when the file was successfully attached into PCC.
			 * The flags of the PCC dataset are saved in
			 * @lli_pcc_dsflags.
			 * The gobal PCC generation will be increased when add
			 * or delete a PCC backend, or change the configuration
			 * parameters for PCC.
			 * If @lli_pcc_generation is same as the gobal PCC
			 * generation, we can use the saved flags of the PCC
			 * dataset to determine whether need to try auto attach
			 * safely.
			 */
			__u64			 lli_pcc_generation;
			enum pcc_dataset_flags	 lli_pcc_dsflags;
			struct pcc_inode	*lli_pcc_inode;

			struct mutex		 lli_group_mutex;
			__u64			 lli_group_users;
			unsigned long		 lli_group_gid;

			__u64			 lli_attr_valid;
			__u64			 lli_lazysize;
			__u64			 lli_lazyblocks;
		};
	};

	/* XXX: For following frequent used members, although they maybe special
	 *      used for non-directory object, it is some time-wasting to check
	 *      whether the object is directory or not before using them. On the
	 *      other hand, currently, sizeof(f) > sizeof(d), it cannot reduce
	 *      the "ll_inode_info" size even if moving those members into u.f.
	 *      So keep them out side.
	 *
	 *      In the future, if more members are added only for directory,
	 *      some of the following members can be moved into u.f.
	 */
	struct cl_object		*lli_clob;

	/* mutex to request for layout lock exclusively. */
	struct mutex			lli_layout_mutex;
	/* Layout version, protected by lli_layout_lock */
	__u32				lli_layout_gen;
	spinlock_t			lli_layout_lock;

	__u32				lli_projid;   /* project id */

	struct rw_semaphore		lli_xattrs_list_rwsem;
	struct mutex			lli_xattrs_enq_lock;
	struct list_head		lli_xattrs; /* ll_xattr_entry->xe_list */
	struct list_head		lli_lccs; /* list of ll_cl_context */
};

#ifndef HAVE_USER_NAMESPACE_ARG
#define inode_permission(ns, inode, mask)	inode_permission(inode, mask)
#define generic_permission(ns, inode, mask)	generic_permission(inode, mask)
#define simple_setattr(ns, de, iattr)		simple_setattr(de, iattr)
#define ll_inode_permission(ns, inode, mask)	ll_inode_permission(inode, mask)
#ifdef HAVE_INODEOPS_ENHANCED_GETATTR
#define ll_getattr(ns, path, stat, mask, fl)	ll_getattr(path, stat, mask, fl)
#endif /* HAVE_INODEOPS_ENHANCED_GETATTR */
#define ll_setattr(ns, de, attr)		ll_setattr(de, attr)
#endif

static inline void ll_trunc_sem_init(struct ll_trunc_sem *sem)
{
	atomic_set(&sem->ll_trunc_readers, 0);
	atomic_set(&sem->ll_trunc_waiters, 0);
}

/* This version of down read ignores waiting writers, meaning if the semaphore
 * is already held for read, this down_read will 'join' that reader and also
 * take the semaphore.
 *
 * This lets us avoid an unusual deadlock.
 *
 * We must take lli_trunc_sem in read mode on entry in to various i/o paths
 * in Lustre, in order to exclude truncates.  Some of these paths then need to
 * take the mmap_lock, while still holding the trunc_sem.  The problem is that
 * page faults hold the mmap_lock when calling in to Lustre, and then must also
 * take the trunc_sem to exclude truncate.
 *
 * This means the locking order for trunc_sem and mmap_lock is sometimes AB,
 * sometimes BA.  This is almost OK because in both cases, we take the trunc
 * sem for read, so it doesn't block.
 *
 * However, if a write mode user (truncate, a setattr op) arrives in the
 * middle of this, the second reader on the truncate_sem will wait behind that
 * writer.
 *
 * So we have, on our truncate sem, in order (where 'reader' and 'writer' refer
 * to the mode in which they take the semaphore):
 * reader (holding mmap_lock, needs truncate_sem)
 * writer
 * reader (holding truncate sem, waiting for mmap_lock)
 *
 * And so the readers deadlock.
 *
 * The solution is this modified semaphore, where this down_read ignores
 * waiting write operations, and all waiters are woken up at once, so readers
 * using down_read_nowait cannot get stuck behind waiting writers, regardless
 * of the order they arrived in.
 *
 * down_read_nowait is only used in the page fault case, where we already hold
 * the mmap_lock.  This is because otherwise repeated read and write operations
 * (which take the truncate sem) could prevent a truncate from ever starting.
 * This could still happen with page faults, but without an even more complex
 * mechanism, this is unavoidable.
 *
 * LU-12460
 */
static inline void trunc_sem_down_read_nowait(struct ll_trunc_sem *sem)
{
	wait_var_event(&sem->ll_trunc_readers,
		       atomic_inc_unless_negative(&sem->ll_trunc_readers));
}

static inline void trunc_sem_down_read(struct ll_trunc_sem *sem)
{
	wait_var_event(&sem->ll_trunc_readers,
		       atomic_read(&sem->ll_trunc_waiters) == 0 &&
		       atomic_inc_unless_negative(&sem->ll_trunc_readers));
}

static inline void trunc_sem_up_read(struct ll_trunc_sem *sem)
{
	if (atomic_dec_return(&sem->ll_trunc_readers) == 0 &&
	    atomic_read(&sem->ll_trunc_waiters))
		wake_up_var(&sem->ll_trunc_readers);
}

static inline void trunc_sem_down_write(struct ll_trunc_sem *sem)
{
	atomic_inc(&sem->ll_trunc_waiters);
	wait_var_event(&sem->ll_trunc_readers,
		       atomic_cmpxchg(&sem->ll_trunc_readers, 0, -1) == 0);
	atomic_dec(&sem->ll_trunc_waiters);
}

static inline void trunc_sem_up_write(struct ll_trunc_sem *sem)
{
	atomic_set(&sem->ll_trunc_readers, 0);
	/* match the smp_mb() in wait_var_event()->prepare_to_wait() */
	smp_mb();
	wake_up_var(&sem->ll_trunc_readers);
}

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
static inline void lli_clear_acl(struct ll_inode_info *lli)
{
	if (lli->lli_posix_acl) {
		posix_acl_release(lli->lli_posix_acl);
		lli->lli_posix_acl = NULL;
	}
}

static inline void lli_replace_acl(struct ll_inode_info *lli,
				   struct lustre_md *md)
{
	write_lock(&lli->lli_lock);
	if (lli->lli_posix_acl)
		posix_acl_release(lli->lli_posix_acl);
	lli->lli_posix_acl = md->posix_acl;
	write_unlock(&lli->lli_lock);
}
#else
static inline void lli_clear_acl(struct ll_inode_info *lli)
{
}

static inline void lli_replace_acl(struct ll_inode_info *lli,
				   struct lustre_md *md)
{
}
#endif

static inline __u32 ll_layout_version_get(struct ll_inode_info *lli)
{
	__u32 gen;

	spin_lock(&lli->lli_layout_lock);
	gen = lli->lli_layout_gen;
	spin_unlock(&lli->lli_layout_lock);

	return gen;
}

static inline void ll_layout_version_set(struct ll_inode_info *lli, __u32 gen)
{
	spin_lock(&lli->lli_layout_lock);
	lli->lli_layout_gen = gen;
	spin_unlock(&lli->lli_layout_lock);
}

enum ll_file_flags {
	/* File data is modified. */
	LLIF_DATA_MODIFIED      = 0,
	/* File is being restored */
	LLIF_FILE_RESTORING	= 1,
	/* Xattr cache is attached to the file */
	LLIF_XATTR_CACHE	= 2,
	/* Project inherit */
	LLIF_PROJECT_INHERIT	= 3,
	/* update atime from MDS even if it's older than local inode atime. */
	LLIF_UPDATE_ATIME	= 4,
	/* foreign file/dir can be unlinked unconditionnaly */
	LLIF_FOREIGN_REMOVABLE	= 5,
	/* Xattr cache is filled */
	LLIF_XATTR_CACHE_FILLED	= 7,

};

int ll_xattr_cache_destroy(struct inode *inode);
int ll_xattr_cache_empty(struct inode *inode);

int ll_xattr_cache_get(struct inode *inode,
		       const char *name,
		       char *buffer,
		       size_t size,
		       __u64 valid);

int ll_xattr_cache_insert(struct inode *inode,
			  const char *name,
			  char *buffer,
			  size_t size);

static inline bool obd_connect_has_secctx(struct obd_connect_data *data)
{
#ifdef CONFIG_SECURITY
	return data->ocd_connect_flags & OBD_CONNECT_FLAGS2 &&
		data->ocd_connect_flags2 & OBD_CONNECT2_FILE_SECCTX;
#else
	return false;
#endif
}

static inline void obd_connect_set_secctx(struct obd_connect_data *data)
{
#ifdef CONFIG_SECURITY
	data->ocd_connect_flags2 |= OBD_CONNECT2_FILE_SECCTX;
#endif
}

/* Only smack and selinux is known to use security contexts */
static inline bool ll_xattr_is_seclabel(const char *name)
{
	return !strcmp(name, XATTR_NAME_SELINUX) ||
		!strcmp(name, XATTR_NAME_SMACK);
}

static inline bool ll_xattr_suffix_is_seclabel(const char *suffix)
{
	return !strcmp(suffix, XATTR_SELINUX_SUFFIX) ||
		!strcmp(suffix, XATTR_SMACK_SUFFIX);
}

int ll_dentry_init_security(struct dentry *dentry, int mode, struct qstr *name,
			    const char **secctx_name, __u32 *secctx_name_size,
			    void **secctx, __u32 *secctx_size);
int ll_inode_init_security(struct dentry *dentry, struct inode *inode,
			   struct inode *dir);

int ll_inode_notifysecctx(struct inode *inode,
			  void *secctx, __u32 secctxlen);

void ll_secctx_name_free(struct ll_sb_info *sbi);

int ll_secctx_name_store(struct inode *in);

__u32 ll_secctx_name_get(struct ll_sb_info *sbi, const char **secctx_name);

int ll_security_secctx_name_filter(struct ll_sb_info *sbi, int xattr_type,
				   const char *suffix);

static inline bool obd_connect_has_enc(struct obd_connect_data *data)
{
#ifdef HAVE_LUSTRE_CRYPTO
	return data->ocd_connect_flags & OBD_CONNECT_FLAGS2 &&
		data->ocd_connect_flags2 & OBD_CONNECT2_ENCRYPT;
#else
	return false;
#endif
}

static inline void obd_connect_set_enc(struct obd_connect_data *data)
{
#ifdef HAVE_LUSTRE_CRYPTO
	data->ocd_connect_flags2 |= OBD_CONNECT2_ENCRYPT;
#endif
}

static inline bool obd_connect_has_name_enc(struct obd_connect_data *data)
{
#ifdef HAVE_LUSTRE_CRYPTO
	return data->ocd_connect_flags & OBD_CONNECT_FLAGS2 &&
		data->ocd_connect_flags2 & OBD_CONNECT2_ENCRYPT_NAME;
#else
	return false;
#endif
}

static inline void obd_connect_set_name_enc(struct obd_connect_data *data)
{
#ifdef HAVE_LUSTRE_CRYPTO
	data->ocd_connect_flags2 |= OBD_CONNECT2_ENCRYPT_NAME;
#endif
}

/*
 * Locking to guarantee consistency of non-atomic updates to long long i_size,
 * consistency between file size and KMS.
 *
 * Implemented by ->lli_size_mutex and ->lsm_lock, nested in that order.
 */

void ll_inode_size_lock(struct inode *inode);
void ll_inode_size_unlock(struct inode *inode);

static inline struct ll_inode_info *ll_i2info(struct inode *inode)
{
	return container_of(inode, struct ll_inode_info, lli_vfs_inode);
}

static inline struct pcc_inode *ll_i2pcci(struct inode *inode)
{
	return ll_i2info(inode)->lli_pcc_inode;
}

/* default to use at least 16M for fast read if possible */
#define RA_REMAIN_WINDOW_MIN			MiB_TO_PAGES(16UL)

/* default read-ahead on a given client mountpoint. */
#define SBI_DEFAULT_READ_AHEAD_MAX		MiB_TO_PAGES(1024UL)

/* default read-ahead for a single file descriptor */
#define SBI_DEFAULT_READ_AHEAD_PER_FILE_MAX	MiB_TO_PAGES(256UL)

/* default read-ahead full files smaller than limit on the second read */
#define SBI_DEFAULT_READ_AHEAD_WHOLE_MAX	MiB_TO_PAGES(2UL)

/* default range pages */
#define SBI_DEFAULT_RA_RANGE_PAGES		MiB_TO_PAGES(1ULL)

/* Min range pages */
#define RA_MIN_MMAP_RANGE_PAGES			16UL

enum ra_stat {
        RA_STAT_HIT = 0,
        RA_STAT_MISS,
        RA_STAT_DISTANT_READPAGE,
        RA_STAT_MISS_IN_WINDOW,
        RA_STAT_FAILED_GRAB_PAGE,
        RA_STAT_FAILED_MATCH,
        RA_STAT_DISCARDED,
        RA_STAT_ZERO_LEN,
        RA_STAT_ZERO_WINDOW,
        RA_STAT_EOF,
        RA_STAT_MAX_IN_FLIGHT,
        RA_STAT_WRONG_GRAB_PAGE,
	RA_STAT_FAILED_REACH_END,
	RA_STAT_ASYNC,
	RA_STAT_FAILED_FAST_READ,
	RA_STAT_MMAP_RANGE_READ,
	_NR_RA_STAT,
};

struct ll_ra_info {
	atomic_t	ra_cur_pages;
	unsigned long	ra_max_pages;
	unsigned long	ra_max_pages_per_file;
	unsigned long	ra_range_pages;
	unsigned long	ra_max_read_ahead_whole_pages;
	struct workqueue_struct  *ll_readahead_wq;
	/*
	 * Max number of active works could be triggered
	 * for async readahead.
	 */
	unsigned int ra_async_max_active;
	/* how many async readahead triggered in flight */
	atomic_t ra_async_inflight;
	/* Threshold to control when to trigger async readahead */
	unsigned long ra_async_pages_per_file_threshold;
};

/* ra_io_arg will be filled in the beginning of ll_readahead with
 * ras_lock, then the following ll_read_ahead_pages will read RA
 * pages according to this arg, all the items in this structure are
 * counted by page index.
 */
struct ra_io_arg {
	pgoff_t		ria_start_idx;	/* start offset of read-ahead*/
	pgoff_t		ria_end_idx;	/* end offset of read-ahead*/
	unsigned long	ria_reserved;	/* reserved pages for read-ahead */
	pgoff_t		ria_end_idx_min;/* minimum end to cover current read */
	bool		ria_eof;	/* reach end of file */
	/* If stride read pattern is detected, ria_stoff is the byte offset
	 * where stride read is started. Note: for normal read-ahead, the
	 * value here is meaningless, and also it will not be accessed*/
	loff_t		ria_stoff;
	/* ria_length and ria_bytes are the length and pages length in the
	 * stride I/O mode. And they will also be used to check whether
	 * it is stride I/O read-ahead in the read-ahead pages*/
	loff_t		ria_length;
	loff_t		ria_bytes;
};

/* LL_HIST_MAX=32 causes an overflow */
#define LL_HIST_MAX 28
#define LL_HIST_START 12 /* buckets start at 2^12 = 4k */
#define LL_PROCESS_HIST_MAX 10
struct per_process_info {
	pid_t pid;
	struct obd_histogram pp_r_hist;
	struct obd_histogram pp_w_hist;
};

/* pp_extents[LL_PROCESS_HIST_MAX] will hold the combined process info */
struct ll_rw_extents_info {
	ktime_t pp_init;
	struct per_process_info pp_extents[LL_PROCESS_HIST_MAX + 1];
};

#define LL_OFFSET_HIST_MAX 100
struct ll_rw_process_info {
        pid_t                     rw_pid;
        int                       rw_op;
        loff_t                    rw_range_start;
        loff_t                    rw_range_end;
        loff_t                    rw_last_file_pos;
        loff_t                    rw_offset;
        size_t                    rw_smallest_extent;
        size_t                    rw_largest_extent;
        struct ll_file_data      *rw_last_file;
};

enum stats_track_type {
        STATS_TRACK_ALL = 0,  /* track all processes */
        STATS_TRACK_PID,      /* track process with this pid */
        STATS_TRACK_PPID,     /* track processes with this ppid */
        STATS_TRACK_GID,      /* track processes with this gid */
        STATS_TRACK_LAST,
};

/* flags for sbi->ll_flags */
enum ll_sbi_flags {
	LL_SBI_NOLCK,			/* DLM locking disabled directio-only */
	LL_SBI_CHECKSUM,		/* checksum each page as it's written */
	LL_SBI_LOCALFLOCK,		/* local flocks instead of fs-wide */
	LL_SBI_FLOCK,			/* flock enabled */
	LL_SBI_USER_XATTR,		/* support user xattr */
	LL_SBI_LRU_RESIZE,		/* lru resize support */
	LL_SBI_LAZYSTATFS,		/* lazystatfs mount option */
	LL_SBI_32BIT_API,		/* generate 32 bit inodes. */
	LL_SBI_USER_FID2PATH,		/* fid2path by unprivileged users */
	LL_SBI_VERBOSE,			/* verbose mount/umount */
	LL_SBI_ALWAYS_PING,		/* ping even if server suppress_pings */
	LL_SBI_TEST_DUMMY_ENCRYPTION,	/* test dummy encryption */
	LL_SBI_ENCRYPT,			/* client side encryption */
	LL_SBI_FOREIGN_SYMLINK,		/* foreign fake-symlink support */
	LL_SBI_FOREIGN_SYMLINK_UPCALL,	/* foreign fake-symlink upcall set */
	LL_SBI_NUM_MOUNT_OPT,

	LL_SBI_ACL,			/* support ACL */
	LL_SBI_AGL_ENABLED,		/* enable agl */
	LL_SBI_64BIT_HASH,		/* support 64-bits dir hash/offset */
	LL_SBI_LAYOUT_LOCK,		/* layout lock support */
	LL_SBI_XATTR_CACHE,		/* support for xattr cache */
	LL_SBI_NOROOTSQUASH,		/* do not apply root squash */
	LL_SBI_FAST_READ,		/* fast read support */
	LL_SBI_FILE_SECCTX,		/* file security context at create */
	LL_SBI_TINY_WRITE,		/* tiny write support */
	LL_SBI_FILE_HEAT,		/* file heat support */
	LL_SBI_PARALLEL_DIO,		/* parallel (async) O_DIRECT RPCs */
	LL_SBI_ENCRYPT_NAME,		/* name encryption */
	LL_SBI_NUM_FLAGS
};

int ll_sbi_flags_seq_show(struct seq_file *m, void *v);

/* This is embedded into llite super-blocks to keep track of connect
 * flags (capabilities) supported by all imports given mount is
 * connected to. */
struct lustre_client_ocd {
	/* This is conjunction of connect_flags across all imports
	 * (LOVs) this mount is connected to. This field is updated by
	 * cl_ocd_update() under ->lco_lock. */
	__u64			 lco_flags;
	struct mutex		 lco_lock;
	struct obd_export	*lco_md_exp;
	struct obd_export	*lco_dt_exp;
};

struct ll_sb_info {
	/* this protects pglist and ra_info.  It isn't safe to
	 * grab from interrupt contexts */
	spinlock_t		 ll_lock;
	spinlock_t		 ll_pp_extent_lock; /* pp_extent entry*/
	spinlock_t		 ll_process_lock; /* ll_rw_process_info */
	struct obd_uuid		 ll_sb_uuid;
	struct obd_export	*ll_md_exp;
	struct obd_export	*ll_dt_exp;
	struct obd_device	*ll_md_obd;
	struct obd_device	*ll_dt_obd;
	struct dentry		*ll_debugfs_entry;
	struct lu_fid		 ll_root_fid; /* root object fid */
	struct mnt_namespace	*ll_mnt_ns;

	DECLARE_BITMAP(ll_flags, LL_SBI_NUM_FLAGS); /* enum ll_sbi_flags */
	unsigned int		 ll_xattr_cache_enabled:1,
				 ll_xattr_cache_set:1, /* already set to 0/1 */
				 ll_client_common_fill_super_succeeded:1,
				 ll_checksum_set:1;

	struct lustre_client_ocd ll_lco;

	struct lprocfs_stats     *ll_stats; /* lprocfs stats counter */

	/* Used to track "unstable" pages on a client, and maintain a
	 * LRU list of clean pages. An "unstable" page is defined as
	 * any page which is sent to a server as part of a bulk request,
	 * but is uncommitted to stable storage. */
	struct cl_client_cache	 *ll_cache;

	struct lprocfs_stats     *ll_ra_stats;

	struct ll_ra_info         ll_ra_info;
	unsigned int              ll_namelen;
	const struct file_operations *ll_fop;

	struct lu_site           *ll_site;
	struct cl_device         *ll_cl;

	/* Statistics */
	struct ll_rw_extents_info *ll_rw_extents_info;
	int			  ll_extent_process_count;
	unsigned int		  ll_offset_process_count;
	struct ll_rw_process_info *ll_rw_process_info;
	struct ll_rw_process_info *ll_rw_offset_info;
	ktime_t			  ll_process_stats_init;
	unsigned int		  ll_rw_offset_entry_count;
	int			  ll_stats_track_id;
	enum stats_track_type	  ll_stats_track_type;
	int			  ll_rw_stats_on;

	/* metadata stat-ahead */
	unsigned int		  ll_sa_running_max;/* max concurrent
						     * statahead instances */
	unsigned int		  ll_sa_max;     /* max statahead RPCs */
	atomic_t		  ll_sa_total;   /* statahead thread started
						  * count */
	atomic_t		  ll_sa_wrong;   /* statahead thread stopped for
						  * low hit ratio */
	atomic_t		  ll_sa_running; /* running statahead thread
						  * count */
	atomic_t		  ll_agl_total;  /* AGL thread started count */

	dev_t			  ll_sdev_orig; /* save s_dev before assign for
						 * clustred nfs */
	/* root squash */
	struct root_squash_info	  ll_squash;
	struct path		  ll_mnt;

	/* st_blksize returned by stat(2), when non-zero */
	unsigned int		  ll_stat_blksize;

	/* maximum relative age of cached statfs results */
	unsigned int		  ll_statfs_max_age;

	struct kset		  ll_kset;	/* sysfs object */
	struct completion	  ll_kobj_unregister;

	/* File heat */
	unsigned int		  ll_heat_decay_weight;
	unsigned int		  ll_heat_period_second;

	/* Opens of the same inode before we start requesting open lock */
	u32			  ll_oc_thrsh_count;

	/* Time in ms between last inode close and next open to be considered
	 * instant back to back and would trigger an open lock request
	 */
	u32			  ll_oc_thrsh_ms;

	/* Time in ms after last file close that we no longer count prior opens*/
	u32			  ll_oc_max_ms;

	/* filesystem fsname */
	char			  ll_fsname[LUSTRE_MAXFSNAME + 1];

	/* Persistent Client Cache */
	struct pcc_super	  ll_pcc_super;

	/* to protect vs updates in all following foreign symlink fields */
	struct rw_semaphore	  ll_foreign_symlink_sem;
	/* foreign symlink path prefix */
	char			 *ll_foreign_symlink_prefix;
	/* full prefix size including leading '\0' */
	size_t			  ll_foreign_symlink_prefix_size;
	/* foreign symlink path upcall */
	char			 *ll_foreign_symlink_upcall;
	/* foreign symlink path upcall infos */
	struct ll_foreign_symlink_upcall_item *ll_foreign_symlink_upcall_items;
	/* foreign symlink path upcall nb infos */
	unsigned int		  ll_foreign_symlink_upcall_nb_items;

	/* cached file security context xattr name. e.g: security.selinux */
	char *ll_secctx_name;
	__u32 ll_secctx_name_size;
};

#define SBI_DEFAULT_HEAT_DECAY_WEIGHT	((80 * 256 + 50) / 100)
#define SBI_DEFAULT_HEAT_PERIOD_SECOND	(60)

#define SBI_DEFAULT_OPENCACHE_THRESHOLD_COUNT	(5)
#define SBI_DEFAULT_OPENCACHE_THRESHOLD_MS	(100) /* 0.1 second */
#define SBI_DEFAULT_OPENCACHE_THRESHOLD_MAX_MS	(60000) /* 1 minute */

/*
 * per file-descriptor read-ahead data.
 */
struct ll_readahead_state {
	spinlock_t	ras_lock;
	/* End byte that read(2) try to read.  */
	loff_t		ras_last_read_end_bytes;
        /*
	 * number of bytes read after last read-ahead window reset. As window
         * is reset on each seek, this is effectively a number of consecutive
         * accesses. Maybe ->ras_accessed_in_window is better name.
         *
         * XXX nikita: window is also reset (by ras_update()) when Lustre
         * believes that memory pressure evicts read-ahead pages. In that
         * case, it probably doesn't make sense to expand window to
         * PTLRPC_MAX_BRW_PAGES on the third access.
         */
	loff_t		ras_consecutive_bytes;
        /*
         * number of read requests after the last read-ahead window reset
         * As window is reset on each seek, this is effectively the number
         * on consecutive read request and is used to trigger read-ahead.
         */
	unsigned long	ras_consecutive_requests;
        /*
         * Parameters of current read-ahead window. Handled by
         * ras_update(). On the initial access to the file or after a seek,
         * window is reset to 0. After 3 consecutive accesses, window is
         * expanded to PTLRPC_MAX_BRW_PAGES. Afterwards, window is enlarged by
         * PTLRPC_MAX_BRW_PAGES chunks up to ->ra_max_pages.
         */
	pgoff_t		ras_window_start_idx;
	pgoff_t		ras_window_pages;

	/* Page index where min range read starts */
	pgoff_t		ras_range_min_start_idx;
	/* Page index where mmap range read ends */
	pgoff_t		ras_range_max_end_idx;
	/* number of mmap pages where last time detected */
	pgoff_t		ras_last_range_pages;
	/* number of mmap range requests */
	pgoff_t		ras_range_requests;

	/*
	 * Optimal RPC size in pages.
	 * It decides how many pages will be sent for each read-ahead.
	 */
	unsigned long	ras_rpc_pages;
        /*
         * Where next read-ahead should start at. This lies within read-ahead
         * window. Read-ahead window is read in pieces rather than at once
         * because: 1. lustre limits total number of pages under read-ahead by
         * ->ra_max_pages (see ll_ra_count_get()), 2. client cannot read pages
         * not covered by DLM lock.
         */
	pgoff_t		ras_next_readahead_idx;
        /*
         * Total number of ll_file_read requests issued, reads originating
         * due to mmap are not counted in this total.  This value is used to
         * trigger full file read-ahead after multiple reads to a small file.
         */
	unsigned long	ras_requests;
        /*
         * The following 3 items are used for detecting the stride I/O
         * mode.
         * In stride I/O mode,
         * ...............|-----data-----|****gap*****|--------|******|....
	 *    offset      |-stride_bytes-|-stride_gap-|
         * ras_stride_offset = offset;
	 * ras_stride_length = stride_bytes + stride_gap;
	 * ras_stride_bytes = stride_bytes;
	 * Note: all these three items are counted by bytes.
	 */
	loff_t		ras_stride_offset;
	loff_t		ras_stride_length;
	loff_t		ras_stride_bytes;
        /*
         * number of consecutive stride request count, and it is similar as
         * ras_consecutive_requests, but used for stride I/O mode.
         * Note: only more than 2 consecutive stride request are detected,
         * stride read-ahead will be enable
         */
	unsigned long	ras_consecutive_stride_requests;
	/* index of the last page that async readahead starts */
	pgoff_t		ras_async_last_readpage_idx;
	/* whether we should increase readahead window */
	bool		ras_need_increase_window;
	/* whether ra miss check should be skipped */
	bool		ras_no_miss_check;
};

struct ll_readahead_work {
	/** File to readahead */
	struct file			*lrw_file;
	pgoff_t				 lrw_start_idx;
	pgoff_t				 lrw_end_idx;
	pid_t				 lrw_user_pid;

	/* async worker to handler read */
	struct work_struct		 lrw_readahead_work;
	char				 lrw_jobid[LUSTRE_JOBID_SIZE];
};

extern struct kmem_cache *ll_file_data_slab;
struct lustre_handle;
struct ll_file_data {
	struct ll_readahead_state fd_ras;
	struct ll_grouplock fd_grouplock;
	__u64 lfd_pos;
	__u32 fd_flags;
	fmode_t fd_omode;
	/* openhandle if lease exists for this file.
	 * Borrow lli->lli_och_mutex to protect assignment */
	struct obd_client_handle *fd_lease_och;
	struct obd_client_handle *fd_och;
	struct file *fd_file;
	/* Indicate whether need to report failure when close.
	 * true: failure is known, not report again.
	 * false: unknown failure, should report. */
	bool fd_write_failed;
	bool ll_lock_no_expand;
	/* Used by mirrored file to lead IOs to a specific mirror, usually
	 * for mirror resync. 0 means default. */
	__u32 fd_designated_mirror;
	/* The layout version when resync starts. Resync I/O should carry this
	 * layout version for verification to OST objects */
	__u32 fd_layout_version;
	struct pcc_file fd_pcc_file;
	/* striped directory may read partially if some stripe inaccessible,
	 * -errno is saved here, and will return to user in close().
	 */
	int fd_partial_readdir_rc;
};

void llite_tunables_unregister(void);
int llite_tunables_register(void);

static inline struct inode *ll_info2i(struct ll_inode_info *lli)
{
        return &lli->lli_vfs_inode;
}

__u32 ll_i2suppgid(struct inode *i);
void ll_i2gids(__u32 *suppgids, struct inode *i1,struct inode *i2);

static inline int ll_need_32bit_api(struct ll_sb_info *sbi)
{
#if BITS_PER_LONG == 32
	return 1;
#elif defined(CONFIG_COMPAT)
	if (unlikely(test_bit(LL_SBI_32BIT_API, sbi->ll_flags)))
		return true;

# ifdef CONFIG_X86_X32
	/* in_compat_syscall() returns true when called from a kthread
	 * and CONFIG_X86_X32 is enabled, which is wrong. So check
	 * whether the caller comes from a syscall (ie. not a kthread)
	 * before calling in_compat_syscall(). */
	if (current->flags & PF_KTHREAD)
		return false;
# endif

	return unlikely(in_compat_syscall());
#else
	return unlikely(test_bit(LL_SBI_32BIT_API, sbi->ll_flags));
#endif
}

static inline bool ll_sbi_has_fast_read(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_FAST_READ, sbi->ll_flags);
}

static inline bool ll_sbi_has_tiny_write(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_TINY_WRITE, sbi->ll_flags);
}

static inline bool ll_sbi_has_file_heat(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_FILE_HEAT, sbi->ll_flags);
}

static inline bool ll_sbi_has_foreign_symlink(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_FOREIGN_SYMLINK, sbi->ll_flags);
}

static inline bool ll_sbi_has_parallel_dio(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_PARALLEL_DIO, sbi->ll_flags);
}

void ll_ras_enter(struct file *f, loff_t pos, size_t count);

/* llite/lcommon_misc.c */
int cl_ocd_update(struct obd_device *host, struct obd_device *watched,
		  enum obd_notify_event ev, void *owner);
int cl_get_grouplock(struct cl_object *obj, unsigned long gid, int nonblock,
		     struct ll_grouplock *lg);
void cl_put_grouplock(struct ll_grouplock *lg);

/* llite/lproc_llite.c */
int ll_debugfs_register_super(struct super_block *sb, const char *name);
void ll_debugfs_unregister_super(struct super_block *sb);
void ll_stats_ops_tally(struct ll_sb_info *sbi, int op, long count);
void ll_free_rw_stats_info(struct ll_sb_info *sbi);

enum {
	LPROC_LL_READ_BYTES,
	LPROC_LL_WRITE_BYTES,
	LPROC_LL_READ,
	LPROC_LL_WRITE,
	LPROC_LL_IOCTL,
	LPROC_LL_OPEN,
	LPROC_LL_RELEASE,
	LPROC_LL_MMAP,
	LPROC_LL_FAULT,
	LPROC_LL_MKWRITE,
	LPROC_LL_LLSEEK,
	LPROC_LL_FSYNC,
	LPROC_LL_READDIR,
	LPROC_LL_SETATTR,
	LPROC_LL_TRUNC,
	LPROC_LL_FLOCK,
	LPROC_LL_GETATTR,
	LPROC_LL_CREATE,
	LPROC_LL_LINK,
	LPROC_LL_UNLINK,
	LPROC_LL_SYMLINK,
	LPROC_LL_MKDIR,
	LPROC_LL_RMDIR,
	LPROC_LL_MKNOD,
	LPROC_LL_RENAME,
	LPROC_LL_STATFS,
	LPROC_LL_SETXATTR,
	LPROC_LL_GETXATTR,
	LPROC_LL_GETXATTR_HITS,
	LPROC_LL_LISTXATTR,
	LPROC_LL_REMOVEXATTR,
	LPROC_LL_INODE_PERM,
	LPROC_LL_FALLOCATE,
	LPROC_LL_INODE_OCOUNT,
	LPROC_LL_INODE_OPCLTM,
	LPROC_LL_FILE_OPCODES
};

/* llite/dir.c */
enum get_default_layout_type {
	GET_DEFAULT_LAYOUT_ROOT = 1,
};

extern const struct file_operations ll_dir_operations;
extern const struct inode_operations ll_dir_inode_operations;
#ifdef HAVE_DIR_CONTEXT
int ll_dir_read(struct inode *inode, __u64 *pos, struct md_op_data *op_data,
		struct dir_context *ctx, int *partial_readdir_rc);
#else
int ll_dir_read(struct inode *inode, __u64 *pos, struct md_op_data *op_data,
		void *cookie, filldir_t filldir, int *partial_readdir_rc);
#endif
int ll_get_mdt_idx(struct inode *inode);
int ll_get_mdt_idx_by_fid(struct ll_sb_info *sbi, const struct lu_fid *fid);
struct page *ll_get_dir_page(struct inode *dir, struct md_op_data *op_data,
			      __u64 offset, int *partial_readdir_rc);
void ll_release_page(struct inode *inode, struct page *page, bool remove);
int quotactl_ioctl(struct super_block *sb, struct if_quotactl *qctl);

/* llite/namei.c */
extern const struct inode_operations ll_special_inode_operations;

struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *lic);
int ll_test_inode_by_fid(struct inode *inode, void *opaque);
int ll_md_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
                       void *data, int flag);
struct dentry *ll_splice_alias(struct inode *inode, struct dentry *de);
int ll_rmdir_entry(struct inode *dir, char *name, int namelen);
void ll_update_times(struct ptlrpc_request *request, struct inode *inode);

/* llite/rw.c */
int ll_writepage(struct page *page, struct writeback_control *wbc);
int ll_writepages(struct address_space *, struct writeback_control *wbc);
int ll_readpage(struct file *file, struct page *page);
int ll_io_read_page(const struct lu_env *env, struct cl_io *io,
			   struct cl_page *page, struct file *file);
void ll_readahead_init(struct inode *inode, struct ll_readahead_state *ras);
int vvp_io_write_commit(const struct lu_env *env, struct cl_io *io);

enum lcc_type;
void ll_cl_add(struct inode *inode, const struct lu_env *env, struct cl_io *io,
	       enum lcc_type type);
void ll_cl_remove(struct inode *inode, const struct lu_env *env);
struct ll_cl_context *ll_cl_find(struct inode *inode);

extern const struct address_space_operations ll_aops;

/* llite/file.c */
extern const struct inode_operations ll_file_inode_operations;
const struct file_operations *ll_select_file_operations(struct ll_sb_info *sbi);
extern int ll_have_md_lock(struct inode *inode, __u64 *bits,
			   enum ldlm_mode l_req_mode);
extern enum ldlm_mode ll_take_md_lock(struct inode *inode, __u64 bits,
				      struct lustre_handle *lockh, __u64 flags,
				      enum ldlm_mode mode);

int ll_file_open(struct inode *inode, struct file *file);
int ll_file_release(struct inode *inode, struct file *file);
int ll_release_openhandle(struct dentry *, struct lookup_intent *);
int ll_md_real_close(struct inode *inode, fmode_t fmode);
void ll_track_file_opens(struct inode *inode);
extern void ll_rw_stats_tally(struct ll_sb_info *sbi, pid_t pid,
                              struct ll_file_data *file, loff_t pos,
                              size_t count, int rw);
#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_INODEOPS_ENHANCED_GETATTR)
int ll_getattr(struct user_namespace *mnt_userns, const struct path *path,
	       struct kstat *stat, u32 request_mask, unsigned int flags);
#else
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat);
#endif /* HAVE_USER_NAMESPACE_ARG */
int ll_getattr_dentry(struct dentry *de, struct kstat *stat, u32 request_mask,
		      unsigned int flags, bool foreign);
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
struct posix_acl *ll_get_acl(struct inode *inode, int type
#ifdef HAVE_GET_ACL_RCU_ARG
			     , bool rcu
#endif /* HAVE_GET_ACL_RCU_ARG */
			     );
int ll_set_acl(struct user_namespace *mnt_userns, struct inode *inode,
	       struct posix_acl *acl, int type);
#else  /* !CONFIG_LUSTRE_FS_POSIX_ACL */
#define ll_get_acl NULL
#define ll_set_acl NULL
#endif /* CONFIG_LUSTRE_FS_POSIX_ACL */

static inline int ll_xflags_to_inode_flags(int xflags)
{
	return ((xflags & FS_XFLAG_SYNC)      ? S_SYNC      : 0) |
	       ((xflags & FS_XFLAG_NOATIME)   ? S_NOATIME   : 0) |
	       ((xflags & FS_XFLAG_APPEND)    ? S_APPEND    : 0) |
	       ((xflags & FS_XFLAG_IMMUTABLE) ? S_IMMUTABLE : 0);
}

static inline int ll_inode_flags_to_xflags(int inode_flags)
{
	return ((inode_flags & S_SYNC)      ? FS_XFLAG_SYNC      : 0) |
	       ((inode_flags & S_NOATIME)   ? FS_XFLAG_NOATIME   : 0) |
	       ((inode_flags & S_APPEND)    ? FS_XFLAG_APPEND    : 0) |
	       ((inode_flags & S_IMMUTABLE) ? FS_XFLAG_IMMUTABLE : 0);
}

int ll_migrate(struct inode *parent, struct file *file,
	       struct lmv_user_md *lum, const char *name, __u32 flags);
int ll_get_fid_by_name(struct inode *parent, const char *name,
		       int namelen, struct lu_fid *fid, struct inode **inode);
int ll_inode_permission(struct user_namespace *mnt_userns, struct inode *inode,
			int mask);
int ll_ioctl_check_project(struct inode *inode, __u32 xflags, __u32 projid);
int ll_ioctl_fsgetxattr(struct inode *inode, unsigned int cmd,
			unsigned long arg);
int ll_ioctl_fssetxattr(struct inode *inode, unsigned int cmd,
			unsigned long arg);
int ll_ioctl_project(struct file *file, unsigned int cmd,
		     unsigned long arg);

int ll_lov_setstripe_ea_info(struct inode *inode, struct dentry *dentry,
			     __u64 flags, struct lov_user_md *lum,
			     int lum_size);
int ll_lov_getstripe_ea_info(struct inode *inode, const char *filename,
                             struct lov_mds_md **lmm, int *lmm_size,
                             struct ptlrpc_request **request);
int ll_dir_setstripe(struct inode *inode, struct lov_user_md *lump,
                     int set_default);
int ll_dir_getstripe_default(struct inode *inode, void **lmmp,
			     int *lmm_size, struct ptlrpc_request **request,
			     struct ptlrpc_request **root_request, u64 valid);
int ll_dir_getstripe(struct inode *inode, void **plmm, int *plmm_size,
		     struct ptlrpc_request **request, u64 valid);
int ll_fsync(struct file *file, loff_t start, loff_t end, int data);
int ll_merge_attr(const struct lu_env *env, struct inode *inode);
int ll_fid2path(struct inode *inode, void __user *arg);
int ll_data_version(struct inode *inode, __u64 *data_version, int flags);
int ll_hsm_release(struct inode *inode);
int ll_hsm_state_set(struct inode *inode, struct hsm_state_set *hss);
void ll_io_set_mirror(struct cl_io *io, const struct file *file);

/* llite/dcache.c */

extern const struct dentry_operations ll_d_ops;
#ifndef HAVE_D_INIT
bool ll_d_setup(struct dentry *de, bool do_put);

static inline bool lld_is_init(struct dentry *dentry)
{
	return ll_d2d(dentry);
}
#else
#define ll_d_setup(de, do_put) (true)
#define lld_is_init(dentry) (true)
#endif

void ll_intent_drop_lock(struct lookup_intent *);
void ll_intent_release(struct lookup_intent *);
void ll_prune_aliases(struct inode *inode);
void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry);
int ll_revalidate_it_finish(struct ptlrpc_request *request,
                            struct lookup_intent *it, struct dentry *de);

/* llite/llite_lib.c */
extern const struct super_operations lustre_super_operations;

void ll_lli_init(struct ll_inode_info *lli);
int ll_fill_super(struct super_block *sb);
void ll_put_super(struct super_block *sb);
void ll_kill_super(struct super_block *sb);
struct inode *ll_inode_from_resource_lock(struct ldlm_lock *lock);
void ll_dir_clear_lsm_md(struct inode *inode);
void ll_clear_inode(struct inode *inode);
int volatile_ref_file(const char *volatile_name, int volatile_len,
		      struct file **ref_file);
int ll_setattr_raw(struct dentry *dentry, struct iattr *attr,
		   enum op_xvalid xvalid, bool hsm_import);
int ll_setattr(struct user_namespace *mnt_userns, struct dentry *de,
	       struct iattr *attr);
int ll_statfs(struct dentry *de, struct kstatfs *sfs);
int ll_statfs_internal(struct ll_sb_info *sbi, struct obd_statfs *osfs,
		       u32 flags);
int ll_update_inode(struct inode *inode, struct lustre_md *md);
void ll_update_inode_flags(struct inode *inode, unsigned int ext_flags);
void ll_update_dir_depth(struct inode *dir, struct inode *inode);
int ll_read_inode2(struct inode *inode, void *opaque);
void ll_truncate_inode_pages_final(struct inode *inode);
void ll_delete_inode(struct inode *inode);
int ll_iocontrol(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg);
int ll_flush_ctx(struct inode *inode);
void ll_umount_begin(struct super_block *sb);
int ll_remount_fs(struct super_block *sb, int *flags, char *data);
int ll_show_options(struct seq_file *seq, struct dentry *dentry);
void ll_dirty_page_discard_warn(struct inode *inode, int ioret);
int ll_prep_inode(struct inode **inode, struct req_capsule *pill,
		  struct super_block *sb, struct lookup_intent *it);
int ll_obd_statfs(struct inode *inode, void __user *arg);
int ll_get_max_mdsize(struct ll_sb_info *sbi, int *max_mdsize);
int ll_get_default_mdsize(struct ll_sb_info *sbi, int *default_mdsize);
int ll_set_default_mdsize(struct ll_sb_info *sbi, int default_mdsize);

void ll_unlock_md_op_lsm(struct md_op_data *op_data);
struct md_op_data *ll_prep_md_op_data(struct md_op_data *op_data,
				      struct inode *i1, struct inode *i2,
				      const char *name, size_t namelen,
				      __u32 mode, enum md_op_code opc,
				      void *data);
void ll_finish_md_op_data(struct md_op_data *op_data);
int ll_get_obd_name(struct inode *inode, unsigned int cmd, unsigned long arg);
void ll_compute_rootsquash_state(struct ll_sb_info *sbi);
ssize_t ll_copy_user_md(const struct lov_user_md __user *md,
			struct lov_user_md **kbuf);
void ll_open_cleanup(struct super_block *sb, struct req_capsule *pill);

void ll_dom_finish_open(struct inode *inode, struct ptlrpc_request *req);

/* Compute expected user md size when passing in a md from user space */
static inline ssize_t ll_lov_user_md_size(const struct lov_user_md *lum)
{
	switch (lum->lmm_magic) {
	case LOV_USER_MAGIC_V1:
		return sizeof(struct lov_user_md_v1);
	case LOV_USER_MAGIC_V3:
		return sizeof(struct lov_user_md_v3);
	case LOV_USER_MAGIC_SPECIFIC:
		if (lum->lmm_stripe_count > LOV_MAX_STRIPE_COUNT)
			return -EINVAL;

		return lov_user_md_size(lum->lmm_stripe_count,
					LOV_USER_MAGIC_SPECIFIC);
	case LOV_USER_MAGIC_COMP_V1:
		return ((struct lov_comp_md_v1 *)lum)->lcm_size;
	case LOV_USER_MAGIC_FOREIGN:
		return foreign_size(lum);
	}

	return -EINVAL;
}

/* llite/llite_nfs.c */
extern const struct export_operations lustre_export_operations;
__u32 get_uuid2int(const char *name, int len);
struct inode *search_inode_for_lustre(struct super_block *sb,
				      const struct lu_fid *fid);
int ll_dir_get_parent_fid(struct inode *dir, struct lu_fid *parent_fid);

/* llite/symlink.c */
extern const struct inode_operations ll_fast_symlink_inode_operations;

/**
 * IO arguments for various VFS I/O interfaces.
 */
struct vvp_io_args {
        /** normal/sendfile/splice */
        union {
                struct {
                        struct kiocb      *via_iocb;
			struct iov_iter   *via_iter;
                } normal;
        } u;
};

enum lcc_type {
	LCC_RW = 1,
	LCC_MMAP
};

struct ll_cl_context {
	struct list_head	 lcc_list;
	void			*lcc_cookie;
	const struct lu_env	*lcc_env;
	struct cl_io		*lcc_io;
	struct cl_page		*lcc_page;
	enum lcc_type		 lcc_type;
};

struct ll_thread_info {
	struct vvp_io_args	lti_args;
	struct ra_io_arg	lti_ria;
	struct ll_cl_context	lti_io_ctx;
};

extern struct lu_context_key ll_thread_key;

static inline struct ll_thread_info *ll_env_info(const struct lu_env *env)
{
	struct ll_thread_info *lti;

	lti = lu_context_key_get(&env->le_ctx, &ll_thread_key);
	LASSERT(lti != NULL);

	return lti;
}

static inline struct vvp_io_args *ll_env_args(const struct lu_env *env)
{
	return &ll_env_info(env)->lti_args;
}

void ll_io_init(struct cl_io *io, struct file *file, enum cl_io_type iot,
		struct vvp_io_args *args);

/* llite/llite_mmap.c */

int ll_file_mmap(struct file * file, struct vm_area_struct * vma);
void policy_from_vma(union ldlm_policy_data *policy, struct vm_area_struct *vma,
		     unsigned long addr, size_t count);
struct vm_area_struct *our_vma(struct mm_struct *mm, unsigned long addr,
                               size_t count);

#define    ll_s2sbi(sb)        (s2lsi(sb)->lsi_llsbi)

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2dtexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_dt_exp;
}

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2mdexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_md_exp;
}

static inline struct client_obd *sbi2mdc(struct ll_sb_info *sbi)
{
        struct obd_device *obd = sbi->ll_md_exp->exp_obd;
        if (obd == NULL)
                LBUG();
        return &obd->u.cli;
}

// FIXME: replace the name of this with LL_SB to conform to kernel stuff
static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return ll_s2sbi(inode->i_sb);
}

static inline struct obd_export *ll_i2dtexp(struct inode *inode)
{
        return ll_s2dtexp(inode->i_sb);
}

static inline struct obd_export *ll_i2mdexp(struct inode *inode)
{
        return ll_s2mdexp(inode->i_sb);
}

static inline struct lu_fid *ll_inode2fid(struct inode *inode)
{
        struct lu_fid *fid;

        LASSERT(inode != NULL);
        fid = &ll_i2info(inode)->lli_fid;

        return fid;
}

static inline bool ll_dir_striped(struct inode *inode)
{
	LASSERT(inode);
	return S_ISDIR(inode->i_mode) &&
	       lmv_dir_striped(ll_i2info(inode)->lli_lsm_md);
}

static inline loff_t ll_file_maxbytes(struct inode *inode)
{
	struct cl_object *obj = ll_i2info(inode)->lli_clob;

	if (obj == NULL)
		return MAX_LFS_FILESIZE;

	return min_t(loff_t, cl_object_maxbytes(obj), MAX_LFS_FILESIZE);
}

/* llite/xattr.c */
extern const struct xattr_handler *ll_xattr_handlers[];

#define XATTR_USER_T		1
#define XATTR_TRUSTED_T		2
#define XATTR_SECURITY_T	3
#define XATTR_ACL_ACCESS_T	4
#define XATTR_ACL_DEFAULT_T	5
#define XATTR_LUSTRE_T		6
#define XATTR_OTHER_T		7
#define XATTR_ENCRYPTION_T	9

ssize_t ll_listxattr(struct dentry *dentry, char *buffer, size_t size);
int ll_xattr_list(struct inode *inode, const char *name, int type,
		  void *buffer, size_t size, u64 valid);
const struct xattr_handler *get_xattr_type(const char *name);

/**
 * Common IO arguments for various VFS I/O interfaces.
 */
int cl_sb_init(struct super_block *sb);
int cl_sb_fini(struct super_block *sb);

enum ras_update_flags {
	LL_RAS_HIT  = 0x1,
	LL_RAS_MMAP = 0x2
};
void ll_ra_count_put(struct ll_sb_info *sbi, unsigned long len);
void ll_ra_stats_inc(struct inode *inode, enum ra_stat which);

/* statahead.c */

#define LL_SA_RPC_MIN           2
#define LL_SA_RPC_DEF           32
#define LL_SA_RPC_MAX           512

/* XXX: If want to support more concurrent statahead instances,
 *	please consider to decentralize the RPC lists attached
 *	on related import, such as imp_{sending,delayed}_list.
 *	LU-11079 */
#define LL_SA_RUNNING_MAX	256
#define LL_SA_RUNNING_DEF	16

#define LL_SA_CACHE_BIT         5
#define LL_SA_CACHE_SIZE        (1 << LL_SA_CACHE_BIT)
#define LL_SA_CACHE_MASK        (LL_SA_CACHE_SIZE - 1)

/* per inode struct, for dir only */
struct ll_statahead_info {
	struct dentry	       *sai_dentry;
	atomic_t		sai_refcount;   /* when access this struct, hold
						 * refcount */
	unsigned int            sai_max;        /* max ahead of lookup */
	__u64                   sai_sent;       /* stat requests sent count */
	__u64                   sai_replied;    /* stat requests which received
						 * reply */
	__u64                   sai_index;      /* index of statahead entry */
	__u64                   sai_index_wait; /* index of entry which is the
						 * caller is waiting for */
	__u64                   sai_hit;        /* hit count */
	__u64                   sai_miss;       /* miss count:
						 * for "ls -al" case, includes
						 * hidden dentry miss;
						 * for "ls -l" case, it does not
						 * include hidden dentry miss.
						 * "sai_miss_hidden" is used for
						 * the later case.
						 */
	unsigned int            sai_consecutive_miss; /* consecutive miss */
	unsigned int            sai_miss_hidden;/* "ls -al", but first dentry
						 * is not a hidden one */
	unsigned int            sai_skip_hidden;/* skipped hidden dentry count
						 */
	unsigned int            sai_ls_all:1,   /* "ls -al", do stat-ahead for
						 * hidden entries */
				sai_in_readpage:1;/* statahead is in readdir()*/
	wait_queue_head_t	sai_waitq;	/* stat-ahead wait queue */
	struct task_struct	*sai_task;	/* stat-ahead thread */
	struct task_struct	*sai_agl_task;	/* AGL thread */
	struct list_head	sai_interim_entries; /* entries which got async
						      * stat reply, but not
						      * instantiated */
	struct list_head	sai_entries;    /* completed entries */
	struct list_head	sai_agls;	/* AGLs to be sent */
	struct list_head	sai_cache[LL_SA_CACHE_SIZE];
	spinlock_t		sai_cache_lock[LL_SA_CACHE_SIZE];
	atomic_t		sai_cache_count; /* entry count in cache */
};

int ll_revalidate_statahead(struct inode *dir, struct dentry **dentry,
			    bool unplug);
int ll_start_statahead(struct inode *dir, struct dentry *dentry, bool agl);
void ll_authorize_statahead(struct inode *dir, void *key);
void ll_deauthorize_statahead(struct inode *dir, void *key);

/* glimpse.c */
blkcnt_t dirty_cnt(struct inode *inode);

int cl_glimpse_size0(struct inode *inode, int agl);
int cl_glimpse_lock(const struct lu_env *env, struct cl_io *io,
		    struct inode *inode, struct cl_object *clob, int agl);

static inline int cl_glimpse_size(struct inode *inode)
{
	return cl_glimpse_size0(inode, 0);
}

/* AGL is 'asychronous glimpse lock', which is a speculative lock taken as
 * part of statahead */
static inline int cl_agl(struct inode *inode)
{
	return cl_glimpse_size0(inode, 1);
}

int ll_file_lock_ahead(struct file *file, struct llapi_lu_ladvise *ladvise);

int cl_io_get(struct inode *inode, struct lu_env **envout,
	      struct cl_io **ioout, __u16 *refcheck);

static inline int ll_glimpse_size(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	int rc;

	down_read(&lli->lli_glimpse_sem);
	rc = cl_glimpse_size(inode);
	lli->lli_glimpse_time = ktime_get();
	up_read(&lli->lli_glimpse_sem);
	return rc;
}

/* dentry may statahead when statahead is enabled and current process has opened
 * parent directory, and this dentry hasn't accessed statahead cache before */
static inline bool
dentry_may_statahead(struct inode *dir, struct dentry *dentry)
{
	struct ll_inode_info  *lli;
	struct ll_dentry_data *ldd;

	if (ll_i2sbi(dir)->ll_sa_max == 0)
		return false;

	lli = ll_i2info(dir);

	/* statahead is not allowed for this dir, there may be three causes:
	 * 1. dir is not opened.
	 * 2. statahead hit ratio is too low.
	 * 3. previous stat started statahead thread failed. */
	if (!lli->lli_sa_enabled)
		return false;

	/* not the same process, don't statahead */
	if (lli->lli_opendir_pid != current->pid)
		return false;

	/*
	 * When stating a dentry, kernel may trigger 'revalidate' or 'lookup'
	 * multiple times, eg. for 'getattr', 'getxattr' and etc.
	 * For patchless client, lookup intent is not accurate, which may
	 * misguide statahead. For example:
	 * The 'revalidate' call for 'getattr' and 'getxattr' of a dentry will
	 * have the same intent -- IT_GETATTR, while one dentry should access
	 * statahead cache once, otherwise statahead windows is messed up.
	 * The solution is as following:
	 * Assign 'lld_sa_generation' with 'lli_sa_generation' when a dentry
	 * IT_GETATTR for the first time, and subsequent IT_GETATTR will
	 * bypass interacting with statahead cache by checking
	 * 'lld_sa_generation == lli->lli_sa_generation'.
	 */
	ldd = ll_d2d(dentry);
	if (ldd != NULL && lli->lli_sa_generation &&
	    ldd->lld_sa_generation == lli->lli_sa_generation)
		return false;

	return true;
}

int cl_sync_file_range(struct inode *inode, loff_t start, loff_t end,
		       enum cl_fsync_mode mode, int ignore_layout);

static inline int ll_file_nolock(const struct file *file)
{
	struct ll_file_data *fd = file->private_data;
	struct inode *inode = file_inode((struct file *)file);

	LASSERT(fd != NULL);
	return ((fd->fd_flags & LL_FILE_IGNORE_LOCK) ||
		test_bit(LL_SBI_NOLCK, ll_i2sbi(inode)->ll_flags));
}

static inline void ll_set_lock_data(struct obd_export *exp, struct inode *inode,
                                    struct lookup_intent *it, __u64 *bits)
{
	if (!it->it_lock_set) {
		struct lustre_handle handle;

		/* If this inode is a remote object, it will get two
		 * separate locks in different namespaces, Master MDT,
		 * where the name entry is, will grant LOOKUP lock,
		 * remote MDT, where the object is, will grant
		 * UPDATE|PERM lock. The inode will be attched to both
		 * LOOKUP and PERM locks, so revoking either locks will
		 * case the dcache being cleared */
		if (it->it_remote_lock_mode) {
			handle.cookie = it->it_remote_lock_handle;
			CDEBUG(D_DLMTRACE, "setting l_data to inode "DFID
			       "(%p) for remote lock %#llx\n",
			       PFID(ll_inode2fid(inode)), inode,
			       handle.cookie);
			md_set_lock_data(exp, &handle, inode, NULL);
		}

		handle.cookie = it->it_lock_handle;

		CDEBUG(D_DLMTRACE, "setting l_data to inode "DFID"(%p)"
		       " for lock %#llx\n",
		       PFID(ll_inode2fid(inode)), inode, handle.cookie);

		md_set_lock_data(exp, &handle, inode, &it->it_lock_bits);
		it->it_lock_set = 1;
	}

	if (bits != NULL)
		*bits = it->it_lock_bits;
}

static inline int d_lustre_invalid(const struct dentry *dentry)
{
	return !ll_d2d(dentry) || ll_d2d(dentry)->lld_invalid;
}

/*
 * Mark dentry INVALID, if dentry refcount is zero (this is normally case for
 * ll_md_blocking_ast), it will be pruned by ll_prune_aliases() and
 * ll_prune_negative_children(); otherwise dput() of the last refcount will
 * unhash this dentry and kill it.
 */
static inline void d_lustre_invalidate(struct dentry *dentry)
{
	CDEBUG(D_DENTRY, "invalidate dentry %pd (%p) parent %p inode %p refc %d\n",
	       dentry, dentry,
	       dentry->d_parent, dentry->d_inode, ll_d_count(dentry));

	spin_lock(&dentry->d_lock);
	if (lld_is_init(dentry))
		ll_d2d(dentry)->lld_invalid = 1;
	spin_unlock(&dentry->d_lock);
}

static inline void d_lustre_revalidate(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	LASSERT(ll_d2d(dentry));
	ll_d2d(dentry)->lld_invalid = 0;
	spin_unlock(&dentry->d_lock);
}

static inline dev_t ll_compat_encode_dev(dev_t dev)
{
	/* The compat_sys_*stat*() syscalls will fail unless the
	 * device majors and minors are both less than 256. Note that
	 * the value returned here will be passed through
	 * old_encode_dev() in cp_compat_stat(). And so we are not
	 * trying to return a valid compat (u16) device number, just
	 * one that will pass the old_valid_dev() check. */

	return MKDEV(MAJOR(dev) & 0xff, MINOR(dev) & 0xff);
}

int ll_layout_conf(struct inode *inode, const struct cl_object_conf *conf);
int ll_layout_refresh(struct inode *inode, __u32 *gen);
int ll_layout_restore(struct inode *inode, loff_t start, __u64 length);
int ll_layout_write_intent(struct inode *inode, enum layout_intent_opc opc,
			   struct lu_extent *ext);

int ll_xattr_init(void);
void ll_xattr_fini(void);

int ll_page_sync_io(const struct lu_env *env, struct cl_io *io,
		    struct cl_page *page, enum cl_req_type crt);

int ll_getparent(struct file *file, struct getparent __user *arg);

/* lcommon_cl.c */
int cl_setattr_ost(struct cl_object *obj, const struct iattr *attr,
		   enum op_xvalid xvalid, unsigned int attr_flags);

extern struct lu_env *cl_inode_fini_env;
extern __u16 cl_inode_fini_refcheck;

int cl_file_inode_init(struct inode *inode, struct lustre_md *md);
void cl_inode_fini(struct inode *inode);

u64 cl_fid_build_ino(const struct lu_fid *fid, int api32);
u32 cl_fid_build_gen(const struct lu_fid *fid);

static inline struct pcc_super *ll_i2pccs(struct inode *inode)
{
	return &ll_i2sbi(inode)->ll_pcc_super;
}

static inline struct pcc_super *ll_info2pccs(struct ll_inode_info *lli)
{
	return ll_i2pccs(ll_info2i(lli));
}

/* crypto.c */
/* The digested form is made of a FID (16 bytes) followed by the second-to-last
 * ciphertext block (16 bytes), so a total length of 32 bytes.
 * That way, llcrypt does not compute a digested form of this digest.
 */
struct ll_digest_filename {
	struct lu_fid ldf_fid;
	char ldf_excerpt[LL_CRYPTO_BLOCK_SIZE];
};

int ll_setup_filename(struct inode *dir, const struct qstr *iname,
		      int lookup, struct llcrypt_name *fname,
		      struct lu_fid *fid);
int ll_fname_disk_to_usr(struct inode *inode,
			 u32 hash, u32 minor_hash,
			 struct llcrypt_str *iname, struct llcrypt_str *oname,
			 struct lu_fid *fid);
int ll_revalidate_d_crypto(struct dentry *dentry, unsigned int flags);
int ll_file_open_encrypt(struct inode *inode, struct file *filp);
static inline char *xattr_for_enc(struct inode *inode)
{
	if (ll_sbi_has_name_encrypt(ll_i2sbi(inode)))
		return LL_XATTR_NAME_ENCRYPTION_CONTEXT;

	return LL_XATTR_NAME_ENCRYPTION_CONTEXT_OLD;
}
#ifdef HAVE_LUSTRE_CRYPTO
extern const struct llcrypt_operations lustre_cryptops;
#endif

/* llite/llite_foreign.c */
int ll_manage_foreign(struct inode *inode, struct lustre_md *lmd);
bool ll_foreign_is_openable(struct dentry *dentry, unsigned int flags);
bool ll_foreign_is_removable(struct dentry *dentry, bool unset);

#endif /* LLITE_INTERNAL_H */
