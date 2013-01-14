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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef LLITE_INTERNAL_H
#define LLITE_INTERNAL_H

#ifdef CONFIG_FS_POSIX_ACL
# include <linux/fs.h>
#ifdef HAVE_XATTR_ACL
# include <linux/xattr_acl.h>
#endif
#ifdef HAVE_LINUX_POSIX_ACL_XATTR_H
# include <linux/posix_acl_xattr.h>
#endif
#endif

#include <lustre_debug.h>
#include <lustre_ver.h>
#include <linux/lustre_version.h>
#include <lustre_disk.h>  /* for s2sbi */

#ifndef HAVE_LE_TYPES
typedef __u16 __le16;
typedef __u32 __le32;
#endif

/*
struct lustre_intent_data {
        __u64 it_lock_handle[2];
        __u32 it_disposition;
        __u32 it_status;
        __u32 it_lock_mode;
        }; */

/* If there is no FMODE_EXEC defined, make it to match nothing */
#ifndef FMODE_EXEC
#define FMODE_EXEC 0
#endif

/** Only used on client-side for indicating the tail of dir hash/offset. */
#define LL_DIR_END_OFF          0x7fffffffffffffffULL
#define LL_DIR_END_OFF_32BIT    0x7fffffffUL

#ifndef DCACHE_LUSTRE_INVALID
#define DCACHE_LUSTRE_INVALID 0x100
#endif

#define LL_IT2STR(it) ((it) ? ldlm_it2str((it)->it_op) : "0")
#define LUSTRE_FPRIVATE(file) ((file)->private_data)

#ifdef HAVE_VFS_INTENT_PATCHES
static inline struct lookup_intent *ll_nd2it(struct nameidata *nd)
{
        return &nd->intent;
}
#endif

/*
 * Directory entries are currently in the same format as ext2/ext3, but will
 * be changed in the future to accomodate FIDs
 */
#define LL_DIR_NAME_LEN (255)
#define LL_DIR_PAD      (4)

struct ll_dir_entry {
        /* number of inode, referenced by this entry */
        __le32  lde_inode;
        /* total record length, multiple of LL_DIR_PAD */
        __le16  lde_rec_len;
        /* length of name */
        __u8    lde_name_len;
        /* file type: regular, directory, device, etc. */
        __u8    lde_file_type;
        /* name. NOT NUL-terminated */
        char    lde_name[LL_DIR_NAME_LEN];
};

struct ll_dentry_data {
        int                      lld_cwd_count;
        int                      lld_mnt_count;
        struct obd_client_handle lld_cwd_och;
        struct obd_client_handle lld_mnt_och;
#ifndef HAVE_VFS_INTENT_PATCHES
        struct lookup_intent    *lld_it;
#endif
        unsigned int             lld_sa_generation;
};

#define ll_d2d(de) ((struct ll_dentry_data*)((de)->d_fsdata))

extern struct file_operations ll_pgcache_seq_fops;

#define LLI_INODE_MAGIC                 0x111d0de5
#define LLI_INODE_DEAD                  0xdeadd00d
#define LLI_F_HAVE_OST_SIZE_LOCK        0
#define LLI_F_HAVE_MDS_SIZE_LOCK        1
#define LLI_F_CONTENDED                 2
#define LLI_F_SRVLOCK                   3

struct ll_inode_info {
        int                     lli_inode_magic;
        struct semaphore        lli_size_sem;           /* protect open and change size */
        void                   *lli_size_sem_owner;
        struct semaphore        lli_write_sem;
        struct lov_stripe_md   *lli_smd;
        char                   *lli_symlink_name;
        __u64                   lli_maxbytes;
        __u64                   lli_io_epoch;
        unsigned long           lli_flags;
        cfs_time_t              lli_contention_time;

        /* this lock protects s_d_w and p_w_ll and mmap_cnt;
         * atomic check-update of lli_smd */
        spinlock_t              lli_lock;
#ifdef HAVE_CLOSE_THREAD
        struct list_head        lli_pending_write_llaps;
        struct list_head        lli_close_item;
        int                     lli_send_done_writing;
#endif
        atomic_t                lli_mmap_cnt;

        /* for writepage() only to communicate to fsync */
        int                     lli_async_rc;

        struct posix_acl       *lli_posix_acl;

        struct list_head        lli_dead_list;

        struct semaphore        lli_och_sem; /* Protects access to och pointers
                                                and their usage counters */
        /* We need all three because every inode may be opened in different
           modes */
        struct obd_client_handle *lli_mds_read_och;
        __u64                   lli_open_fd_read_count;
        struct obd_client_handle *lli_mds_write_och;
        __u64                   lli_open_fd_write_count;
        struct obd_client_handle *lli_mds_exec_och;
        __u64                   lli_open_fd_exec_count;

        /** fid of this object. */
        union {
                struct lu_fid f20;
                struct ll_fid f16;
        } lli_fid;

        /* metadata stat-ahead */
        /*
         * "opendir_pid" is the token when lookup/revalid -- I am the owner of
         * dir statahead.
         */
        pid_t                   lli_opendir_pid;
        /*
         * since parent-child threads can share the same @file struct,
         * "opendir_key" is the token when dir close for case of parent exit
         * before child -- it is me should cleanup the dir readahead. */
        void                   *lli_opendir_key;
        struct ll_statahead_info *lli_sai;
        struct rw_semaphore     lli_truncate_rwsem;
        /* the most recent attributes from mds, it is used for timestamps
         * only so far */
        struct ost_lvb         lli_lvb;
        struct inode            lli_vfs_inode;
};

/*
 * Locking to guarantee consistency of non-atomic updates to long long i_size,
 * consistency between file size and KMS, and consistency within
 * ->lli_smd->lsm_oinfo[]'s.
 *
 * Implemented by ->lli_size_sem and ->lsm_sem, nested in that order.
 */

void ll_inode_size_lock(struct inode *inode, int lock_lsm);
void ll_inode_size_unlock(struct inode *inode, int unlock_lsm);

// FIXME: replace the name of this with LL_I to conform to kernel stuff
// static inline struct ll_inode_info *LL_I(struct inode *inode)
static inline struct ll_inode_info *ll_i2info(struct inode *inode)
{
        return container_of(inode, struct ll_inode_info, lli_vfs_inode);
}

/* default to about 40meg of readahead on a given system.  That much tied
 * up in 512k readahead requests serviced at 40ms each is about 1GB/s. */
#define SBI_DEFAULT_READAHEAD_MAX (40UL << (20 - CFS_PAGE_SHIFT))

/* default to read-ahead full files smaller than 2MB on the second read */
#define SBI_DEFAULT_READAHEAD_WHOLE_MAX (2UL << (20 - CFS_PAGE_SHIFT))

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
        _NR_RA_STAT,
};

#define LL_RA_STAT      _NR_RA_STAT
#define LL_RA_STAT_STRINGS           {                                  \
        [RA_STAT_HIT]               = "hits",                           \
        [RA_STAT_MISS]              = "misses",                         \
        [RA_STAT_DISTANT_READPAGE]  = "readpage not consecutive",       \
        [RA_STAT_MISS_IN_WINDOW]    = "miss inside window",             \
        [RA_STAT_FAILED_GRAB_PAGE]  = "failed grab_cache_page",         \
        [RA_STAT_FAILED_MATCH]      = "failed lock match",              \
        [RA_STAT_DISCARDED]         = "read but discarded",             \
        [RA_STAT_ZERO_LEN]          = "zero length file",               \
        [RA_STAT_ZERO_WINDOW]       = "zero size window",               \
        [RA_STAT_EOF]               = "read-ahead to EOF",              \
        [RA_STAT_MAX_IN_FLIGHT]     = "hit max r-a issue",              \
        [RA_STAT_WRONG_GRAB_PAGE]   = "wrong page from grab_cache_page",\
}

struct ll_ra_info {
        atomic_t                  ra_cur_pages;
        unsigned long             ra_max_pages;
        unsigned long             ra_max_pages_per_file;
        unsigned long             ra_max_read_ahead_whole_pages;
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
        struct file               *rw_last_file;
};


enum stats_track_type {
        STATS_TRACK_ALL = 0,  /* track all processes */
        STATS_TRACK_PID,      /* track process with this pid */
        STATS_TRACK_PPID,     /* track processes with this ppid */
        STATS_TRACK_GID,      /* track processes with this gid */
        STATS_TRACK_LAST,
};

/* flags for sbi->ll_flags */
#define LL_SBI_NOLCK            0x01 /* DLM locking disabled (directio-only) */
#define LL_SBI_DATA_CHECKSUM    0x02 /* checksum each page on the wire */
#define LL_SBI_FLOCK            0x04
#define LL_SBI_USER_XATTR       0x08 /* support user xattr */
#define LL_SBI_ACL              0x10 /* support ACL */
#define LL_SBI_JOIN             0x20 /* support JOIN */
#define LL_SBI_LOCALFLOCK       0x40 /* Local flocks support by kernel */
#define LL_SBI_LRU_RESIZE       0x80 /* support lru resize */
#define LL_SBI_LLITE_CHECKSUM  0x100 /* checksum each page in memory */
#define LL_SBI_LAZYSTATFS      0x200 /* lazystatfs mount option */
#define LL_SBI_32BIT_API       0x400 /* generate 32 bit inodes. */
#define LL_SBI_64BIT_HASH      0x800 /* support 64-bits dir hash/offset */

/* default value for ll_sb_info->contention_time */
#define SBI_DEFAULT_CONTENTION_SECONDS     60
/* default value for lockless_truncate_enable */
#define SBI_DEFAULT_LOCKLESS_TRUNCATE_ENABLE 0 /* see bug 23175 */
/* default value for ll_direct_io_default */
#define SBI_DEFAULT_DIRECT_IO_DEFAULT 0
#define SBI_DEFAULT_LOCKLESS_DIRECT_IO 1

/* percpu data structure for lustre lru page list */
struct ll_pglist_data {
        spinlock_t                llpd_lock; /* lock to protect llpg_list */
        struct list_head          llpd_list; /* all pages (llap_pglist_item) */
        unsigned long             llpd_gen;  /* generation # of this list */
        unsigned long             llpd_count; /* How many pages in this list */
        atomic_t                  llpd_sample_count;
        unsigned long             llpd_reblnc_count;
        /* the pages in this list shouldn't be over this number */
        unsigned long             llpd_budget;
        int                       llpd_cpu;
        /* which page the pglist data is in */
        struct page              *llpd_page;

        /* stats */
        unsigned long             llpd_hit;
        unsigned long             llpd_miss;
        unsigned long             llpd_cross;
};

struct ll_sb_info {
        struct list_head          ll_list;
        /* this protects pglist(only ll_async_page_max) and ra_info.
         * It isn't safe to grab from interrupt contexts. */
        spinlock_t                ll_lock;
        spinlock_t                ll_pp_extent_lock; /* Lock for pp_extent entries */
        spinlock_t                ll_process_lock; /* Lock for ll_rw_process_info */
        struct obd_uuid           ll_sb_uuid;
        struct obd_export        *ll_mdc_exp;
        struct obd_export        *ll_osc_exp;
        struct proc_dir_entry    *ll_proc_root;
        obd_id                    ll_rootino; /* number of root inode */

        int                       ll_flags;
        struct list_head          ll_conn_chain; /* per-conn chain of SBs */
        struct lustre_client_ocd  ll_lco;

        struct list_head          ll_orphan_dentry_list; /*please don't ask -p*/
        struct ll_close_queue    *ll_lcq;

        struct lprocfs_stats     *ll_stats; /* lprocfs stats counter */

        /* reblnc lock protects llpd_budget */
        spinlock_t                ll_async_page_reblnc_lock;
        unsigned long             ll_async_page_reblnc_count;
        unsigned long             ll_async_page_sample_max;
        /* I defined this array here rather than in ll_pglist_data
         * because it is always accessed by only one cpu. -jay */
        unsigned long            *ll_async_page_sample;
        unsigned long             ll_async_page_max;
        unsigned long             ll_async_page_clock_hand;
        lcounter_t                ll_async_page_count;
        struct ll_pglist_data   **ll_pglist;

        struct lprocfs_stats     *ll_ra_stats;

        unsigned                  ll_contention_time; /* seconds */
        unsigned                  ll_lockless_truncate_enable; /* true/false */
        unsigned                  ll_lockless_direct_io; /* true/false */
        unsigned                  ll_direct_io_default; /* true/false */

        struct ll_ra_info         ll_ra_info;
        unsigned int              ll_namelen;
        struct file_operations   *ll_fop;

        /* =0 - hold lock over whole read/write
         * >0 - max. chunk to be read/written w/o lock re-acquiring */
        unsigned long             ll_max_rw_chunk;

        /* Statistics */
        struct ll_rw_extents_info ll_rw_extents_info;
        int                       ll_extent_process_count;
        struct ll_rw_process_info ll_rw_process_info[LL_PROCESS_HIST_MAX];
        unsigned int              ll_offset_process_count;
        struct ll_rw_process_info ll_rw_offset_info[LL_OFFSET_HIST_MAX];
        unsigned int              ll_rw_offset_entry_count;
        enum stats_track_type     ll_stats_track_type;
        int                       ll_stats_track_id;
        int                       ll_rw_stats_on;
        dev_t                     ll_sdev_orig; /* save s_dev before assign for
                                                 * clustred nfs */

        /* metadata stat-ahead */
        unsigned int              ll_sa_max;     /* max statahead RPCs */
        unsigned int              ll_sa_wrong;   /* statahead thread stopped for
                                                  * low hit ratio */
        unsigned int              ll_sa_total;   /* statahead thread started
                                                  * count */
        unsigned long long        ll_sa_blocked; /* ls count waiting for
                                                  * statahead */
        unsigned long long        ll_sa_cached;  /* ls count got in cache */
        unsigned long long        ll_sa_hit;     /* hit count */
        unsigned long long        ll_sa_miss;    /* miss count */
};

#define LL_DEFAULT_MAX_RW_CHUNK      (32 * 1024 * 1024)

#define LL_PGLIST_DATA_CPU(sbi, cpu) ((sbi)->ll_pglist[cpu])
#define LL_PGLIST_DATA(sbi)          LL_PGLIST_DATA_CPU(sbi, smp_processor_id())

static inline struct ll_pglist_data *ll_pglist_cpu_lock(
                struct ll_sb_info *sbi,
                int cpu)
{
        spin_lock(&sbi->ll_pglist[cpu]->llpd_lock);
        return LL_PGLIST_DATA_CPU(sbi, cpu);
}

static inline void ll_pglist_cpu_unlock(struct ll_sb_info *sbi, int cpu)
{
        spin_unlock(&sbi->ll_pglist[cpu]->llpd_lock);
}

static inline struct ll_pglist_data *ll_pglist_double_lock(
                struct ll_sb_info *sbi,
                int cpu, struct ll_pglist_data **pd_cpu)
{
        int current_cpu = cfs_get_cpu();

        if (cpu == current_cpu) {
                ll_pglist_cpu_lock(sbi, cpu);
        } else if (current_cpu < cpu) {
                ll_pglist_cpu_lock(sbi, current_cpu);
                ll_pglist_cpu_lock(sbi, cpu);
        } else {
                ll_pglist_cpu_lock(sbi, cpu);
                ll_pglist_cpu_lock(sbi, current_cpu);
        }

        if (pd_cpu)
                *pd_cpu = LL_PGLIST_DATA_CPU(sbi, cpu);

        return LL_PGLIST_DATA(sbi);
}

static inline void ll_pglist_double_unlock(struct ll_sb_info *sbi, int cpu)
{
        int current_cpu = smp_processor_id();
        if (cpu == current_cpu) {
                ll_pglist_cpu_unlock(sbi, cpu);
        } else {
                ll_pglist_cpu_unlock(sbi, cpu);
                ll_pglist_cpu_unlock(sbi, current_cpu);
        }
        cfs_put_cpu();
}

static inline struct ll_pglist_data *ll_pglist_lock(struct ll_sb_info *sbi)
{
        ll_pglist_cpu_lock(sbi, cfs_get_cpu());
        return LL_PGLIST_DATA(sbi);
}

static inline void ll_pglist_unlock(struct ll_sb_info *sbi)
{
        ll_pglist_cpu_unlock(sbi, smp_processor_id());
        cfs_put_cpu();
}

struct ll_ra_read {
        pgoff_t             lrr_start;
        pgoff_t             lrr_count;
        struct task_struct *lrr_reader;
        struct list_head    lrr_linkage;
};

/*
 * per file-descriptor read-ahead data.
 */
struct ll_readahead_state {
        spinlock_t      ras_lock;
        /*
         * index of the last page that read(2) needed and that wasn't in the
         * cache. Used by ras_update() to detect seeks.
         *
         * XXX nikita: if access seeks into cached region, Lustre doesn't see
         * this.
         */
        unsigned long   ras_last_readpage;
        /*
         * number of pages read after last read-ahead window reset. As window
         * is reset on each seek, this is effectively a number of consecutive
         * accesses. Maybe ->ras_accessed_in_window is better name.
         *
         * XXX nikita: window is also reset (by ras_update()) when Lustre
         * believes that memory pressure evicts read-ahead pages. In that
         * case, it probably doesn't make sense to expand window to
         * PTLRPC_MAX_BRW_PAGES on the third access.
         */
        unsigned long   ras_consecutive_pages;
        /*
         * number of read requests after the last read-ahead window reset
         * As window is reset on each seek, this is effectively the number
         * on consecutive read request and is used to trigger read-ahead.
         */
        unsigned long   ras_consecutive_requests;
        /*
         * Parameters of current read-ahead window. Handled by
         * ras_update(). On the initial access to the file or after a seek,
         * window is reset to 0. After 3 consecutive accesses, window is
         * expanded to PTLRPC_MAX_BRW_PAGES. Afterwards, window is enlarged by
         * PTLRPC_MAX_BRW_PAGES chunks up to ->ra_max_pages.
         */
        unsigned long   ras_window_start, ras_window_len;
        /*
         * Where next read-ahead should start at. This lies within read-ahead
         * window. Read-ahead window is read in pieces rather than at once
         * because: 1. lustre limits total number of pages under read-ahead by
         * ->ra_max_pages (see ll_ra_count_get()), 2. client cannot read pages
         * not covered by DLM lock.
         */
        unsigned long   ras_next_readahead;
        /*
         * Total number of ll_file_read requests issued, reads originating
         * due to mmap are not counted in this total.  This value is used to
         * trigger full file read-ahead after multiple reads to a small file.
         */
        unsigned long   ras_requests;
        /*
         * Page index with respect to the current request, these value
         * will not be accurate when dealing with reads issued via mmap.
         */
        unsigned long   ras_request_index;
        /*
         * list of struct ll_ra_read's one per read(2) call current in
         * progress against this file descriptor. Used by read-ahead code,
         * protected by ->ras_lock.
         */
        struct list_head ras_read_beads;
        /*
         * The following 3 items are used for detecting the stride I/O
         * mode.
         * In stride I/O mode,
         * ...............|-----data-----|****gap*****|--------|******|....
         *    offset      |-stride_pages-|-stride_gap-|
         * ras_stride_offset = offset;
         * ras_stride_length = stride_pages + stride_gap;
         * ras_stride_pages = stride_pages;
         * Note: all these three items are counted by pages.
         */
        unsigned long ras_stride_length;
        unsigned long ras_stride_pages;
        pgoff_t ras_stride_offset;
        /*
         * number of consecutive stride request count, and it is similar as
         * ras_consecutive_requests, but used for stride I/O mode.
         * Note: only more than 2 consecutive stride request are detected,
         * stride read-ahead will be enable
         */
        unsigned long ras_consecutive_stride_requests;
};

struct ll_file_dir {
        __u64 lfd_pos;
        __u64 lfd_next;
};

extern cfs_mem_cache_t *ll_file_data_slab;
extern struct rw_semaphore ll_sb_sem;
struct lustre_handle;
struct ll_file_data {
        struct ll_readahead_state fd_ras;
        int fd_omode;
        struct lustre_handle fd_cwlockh;
        unsigned long fd_gid;
        struct ll_file_dir fd_dir;
        __u32 fd_flags;
	/* Indicate whether need to report failure when close.
	 * true: failure is known, not report again.
	 * false: unknown failure, should report. */
	bool fd_write_failed;
};

struct lov_stripe_md;

extern spinlock_t inode_lock;

extern struct proc_dir_entry *proc_lustre_fs_root;

static inline struct inode *ll_info2i(struct ll_inode_info *lli)
{
        return &lli->lli_vfs_inode;
}

struct it_cb_data {
        struct inode *icbd_parent;
        struct dentry **icbd_childp;
        obd_id hash;
};

void ll_i2gids(__u32 *suppgids, struct inode *i1,struct inode *i2);

#define LLAP_MAGIC 98764321

extern cfs_mem_cache_t *ll_async_page_slab;
extern size_t ll_async_page_slab_size;
struct ll_async_page {
        int              llap_magic;
         /* only trust these if the page lock is providing exclusion */
        unsigned int     llap_write_queued:1,
                         llap_defer_uptodate:1,
                         llap_origin:3,
                         llap_ra_used:1,
                         llap_ignore_quota:1,
                         llap_reserved:7;
        unsigned int     llap_pglist_cpu:16;
        void            *llap_cookie;
        struct page     *llap_page;
        struct list_head llap_pending_write;
        struct list_head llap_pglist_item;
        /* checksum for paranoid I/O debugging */
        __u32 llap_checksum;
        struct lustre_handle llap_lockh_granted;
};

/*
 * enumeration of llap_from_page() call-sites. Used to export statistics in
 * /proc/fs/lustre/llite/fsN/dump_page_cache.
 */
enum {
        LLAP_ORIGIN_UNKNOWN = 0,
        LLAP_ORIGIN_READPAGE,
        LLAP_ORIGIN_READAHEAD,
        LLAP_ORIGIN_COMMIT_WRITE,
        LLAP_ORIGIN_WRITEPAGE,
        LLAP_ORIGIN_REMOVEPAGE,
        LLAP__ORIGIN_MAX,
};
extern char *llap_origins[];

void ll_ra_read_init(struct file *f, struct ll_ra_read *rar,
                     loff_t offset, size_t count);
void ll_ra_read_ex(struct file *f, struct ll_ra_read *rar);
struct ll_ra_read *ll_ra_read_get(struct file *f);

static inline int ll_need_32bit_api(struct ll_sb_info *sbi)
{
#if BITS_PER_LONG == 32
        return 1;
#else
        return unlikely(cfs_curproc_is_32bit() || (sbi->ll_flags & LL_SBI_32BIT_API));
#endif
}

/* llite/lproc_llite.c */
#ifdef LPROCFS
int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block *sb, char *osc, char *mdc);
void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi);
void ll_stats_ops_tally(struct ll_sb_info *sbi, int op, int count);
void lprocfs_llite_init_vars(struct lprocfs_static_vars *lvars);
#else
static inline int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                        struct super_block *sb, char *osc, char *mdc){return 0;}
static inline void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi) {}
static void ll_stats_ops_tally(struct ll_sb_info *sbi, int op, int count) {}
static void lprocfs_llite_init_vars(struct lprocfs_static_vars *lvars)
{
        memset(lvars, 0, sizeof(*lvars));
}
#endif


/* llite/dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

struct page *ll_get_dir_page(struct inode *dir, unsigned long n);

static inline unsigned ll_dir_rec_len(unsigned name_len)
{
        return (name_len + 8 + LL_DIR_PAD - 1) & ~(LL_DIR_PAD - 1);
}

static inline struct ll_dir_entry *ll_entry_at(void *base, unsigned offset)
{
        return (struct ll_dir_entry *)((char *)base + offset);
}

/*
 * p is at least 6 bytes before the end of page
 */
static inline struct ll_dir_entry *ll_dir_next_entry(struct ll_dir_entry *p)
{
        return ll_entry_at(p, le16_to_cpu(p->lde_rec_len));
}

static inline void ll_put_page(struct page *page)
{
        kunmap(page);
        page_cache_release(page);
}

static inline unsigned long dir_pages(struct inode *inode)
{
        return (inode->i_size + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
}

int ll_objects_destroy(struct ptlrpc_request *request, struct inode *dir);
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *lic);
int ll_mdc_cancel_unused(struct lustre_handle *, struct inode *, int flags,
                         void *opaque);
int ll_mdc_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
                        void *data, int flag);
int ll_prepare_mdc_op_data(struct mdc_op_data *,
                           struct inode *i1, struct inode *i2,
                           const char *name, int namelen, int mode, void *data);
#ifndef HAVE_VFS_INTENT_PATCHES
struct lookup_intent *ll_convert_intent(struct open_intent *oit,
                                        int lookup_flags);
#endif
void ll_pin_extent_cb(void *data);
int ll_page_removal_cb(void *data, int discard);
int ll_extent_lock_cancel_cb(struct ldlm_lock *lock, struct ldlm_lock_desc *new,
                             void *data, int flag);
int lookup_it_finish(struct ptlrpc_request *request, int offset,
                     struct lookup_intent *it, void *data);
void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry);

/* llite/rw.c */
int ll_prepare_write(struct file *, struct page *, unsigned from, unsigned to);
int ll_commit_write(struct file *, struct page *, unsigned from, unsigned to);
int ll_writepage(struct page *page);
void ll_inode_fill_obdo(struct inode *inode, int cmd, struct obdo *oa);
int ll_ap_completion(void *data, int cmd, struct obdo *oa, int rc);
int llap_shrink_cache(struct ll_sb_info *sbi, int shrink_fraction);
extern struct cache_definition ll_cache_definition;
void ll_removepage(struct page *page);
int ll_readpage(struct file *file, struct page *page);
struct ll_async_page *llap_cast_private(struct page *page);
void ll_readahead_init(struct inode *inode, struct ll_readahead_state *ras);
void ll_ra_accounting(struct ll_async_page *llap,struct address_space *mapping);
void ll_truncate(struct inode *inode);
int ll_file_punch(struct inode *, loff_t, int);
ssize_t ll_file_lockless_io(struct file *, const struct iovec *,
                            unsigned long, loff_t *, int, ssize_t);
ssize_t ll_direct_IO(int rw, struct file *file,const struct iovec *iov,
                     loff_t file_offset, unsigned long nr_segs, int locked);
void ll_clear_file_contended(struct inode*);
int ll_sync_page_range(struct inode *, struct address_space *, loff_t, size_t);

/* llite/file.c */
extern struct file_operations ll_file_operations;
extern struct file_operations ll_file_operations_flock;
extern struct file_operations ll_file_operations_noflock;
extern struct inode_operations ll_file_inode_operations;
extern int ll_inode_revalidate_it(struct dentry *, struct lookup_intent *);
extern int ll_have_md_lock(struct inode *inode, __u64 bits, ldlm_mode_t l_req_mode);
int ll_region_mapped(unsigned long addr, size_t count);
int ll_extent_lock(struct ll_file_data *, struct inode *,
                   struct lov_stripe_md *, int mode, ldlm_policy_data_t *,
                   struct lustre_handle *, int ast_flags);
int ll_extent_unlock(struct ll_file_data *, struct inode *,
                     struct lov_stripe_md *, int mode, struct lustre_handle *);
int __ll_inode_revalidate_it(struct dentry *, struct lookup_intent *,  __u64 bits);
int ll_revalidate_nd(struct dentry *dentry, struct nameidata *nd);
int ll_file_open(struct inode *inode, struct file *file);
int ll_file_release(struct inode *inode, struct file *file);
int ll_lsm_getattr(struct obd_export *, struct lov_stripe_md *, struct obdo *);
int ll_glimpse_ioctl(struct ll_sb_info *sbi,
                     struct lov_stripe_md *lsm, lstat_t *st);
int ll_glimpse_size(struct inode *inode, int ast_flags);
int ll_local_open(struct file *file,
                  struct lookup_intent *it, struct ll_file_data *fd,
                  struct obd_client_handle *och);
int ll_release_openhandle(struct dentry *, struct lookup_intent *);
int ll_mdc_close(struct obd_export *mdc_exp, struct inode *inode,
                 struct file *file);
int ll_mdc_real_close(struct inode *inode, int flags);
extern void ll_rw_stats_tally(struct ll_sb_info *sbi, pid_t pid, struct file
                               *file, size_t count, int rw);
int ll_getattr_it(struct vfsmount *mnt, struct dentry *de,
               struct lookup_intent *it, struct kstat *stat);
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat);
struct ll_file_data *ll_file_data_get(void);
#ifndef HAVE_INODE_PERMISION_2ARGS
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd);
#else
int ll_inode_permission(struct inode *inode, int mask);
#endif
int ll_lov_setstripe_ea_info(struct inode *inode, struct file *file,
                             int flags, struct lov_user_md *lum,
                             int lum_size);
int ll_lov_getstripe_ea_info(struct inode *inode, const char *filename,
                             struct lov_mds_md **lmm, int *lmm_size,
                             struct ptlrpc_request **request);
int ll_dir_setstripe(struct inode *inode, struct lov_user_md *lump,
                     int set_default);
int ll_dir_getstripe(struct inode *inode, struct lov_mds_md **lmm,
                     int *lmm_size, struct ptlrpc_request **request);
int ll_fsync(struct file *file, struct dentry *dentry, int data);
int ll_do_fiemap(struct inode *inode, struct ll_user_fiemap *fiemap,
              int num_bytes);

/* llite/dcache.c */
/* llite/namei.c */
/**
 * protect race ll_find_aliases vs ll_revalidate_it vs ll_unhash_aliases
 */
extern spinlock_t ll_lookup_lock;
extern struct dentry_operations ll_d_ops;
void ll_intent_drop_lock(struct lookup_intent *);
void ll_intent_release(struct lookup_intent *);
extern void ll_set_dd(struct dentry *de);
int ll_drop_dentry(struct dentry *dentry);
void ll_unhash_aliases(struct inode *);
void ll_frob_intent(struct lookup_intent **itp, struct lookup_intent *deft);
void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry);
int ll_dcompare(struct dentry *parent, struct qstr *d_name, struct qstr *name);
int revalidate_it_finish(struct ptlrpc_request *request, int offset,
                         struct lookup_intent *it, struct dentry *de);

/* llite/llite_lib.c */
extern struct super_operations lustre_super_operations;

char *ll_read_opt(const char *opt, char *data);
void ll_lli_init(struct ll_inode_info *lli);
int ll_fill_super(struct super_block *sb);
void ll_put_super(struct super_block *sb);
void ll_kill_super(struct super_block *sb);
int ll_cache_shrink(SHRINKER_FIRST_ARG int nr_to_scan, gfp_t gfp_mask);
struct inode *ll_inode_from_lock(struct ldlm_lock *lock);
void ll_clear_inode(struct inode *inode);
void ll_delete_inode(struct inode *inode);
int ll_setattr_raw(struct inode *inode, struct iattr *attr);
int ll_setattr(struct dentry *de, struct iattr *attr);
#ifndef HAVE_STATFS_DENTRY_PARAM
int ll_statfs(struct super_block *sb, struct kstatfs *sfs);
#else
int ll_statfs(struct dentry *de, struct kstatfs *sfs);
#endif
int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       __u64 max_age, __u32 flags);
void ll_update_inode(struct inode *inode, struct lustre_md *md);
void ll_read_inode2(struct inode *inode, void *opaque);
int ll_iocontrol(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg);
#ifdef HAVE_UMOUNTBEGIN_VFSMOUNT
void ll_umount_begin(struct vfsmount *vfsmnt, int flags);
#else
void ll_umount_begin(struct super_block *sb);
#endif
int ll_remount_fs(struct super_block *sb, int *flags, char *data);
int ll_show_options(struct seq_file *seq, struct vfsmount *vfs);
int ll_prep_inode(struct obd_export *exp, struct inode **inode,
                  struct ptlrpc_request *req, int offset, struct super_block *);
void lustre_dump_dentry(struct dentry *, int recur);
void lustre_dump_inode(struct inode *);
struct ll_async_page *llite_pglist_next_llap(struct list_head *head,
                                             struct list_head *list);
int ll_obd_statfs(struct inode *inode, void *arg);
int ll_get_max_mdsize(struct ll_sb_info *sbi, int *max_mdsize);
int ll_process_config(struct lustre_cfg *lcfg);

/* llite/llite_nfs.c */
extern struct export_operations lustre_export_operations;
__u32 get_uuid2int(const char *name, int len);

/* llite/special.c */
extern struct inode_operations ll_special_inode_operations;
extern struct file_operations ll_special_chr_inode_fops;
extern struct file_operations ll_special_chr_file_fops;
extern struct file_operations ll_special_blk_inode_fops;
extern struct file_operations ll_special_fifo_inode_fops;
extern struct file_operations ll_special_fifo_file_fops;
extern struct file_operations ll_special_sock_inode_fops;

/* llite/symlink.c */
extern struct inode_operations ll_fast_symlink_inode_operations;

/* llite/llite_close.c */
struct ll_close_queue {
        spinlock_t              lcq_lock;
        struct list_head        lcq_list;
        wait_queue_head_t       lcq_waitq;
        struct completion       lcq_comp;
};

#ifdef HAVE_CLOSE_THREAD
void llap_write_pending(struct inode *inode, struct ll_async_page *llap);
void llap_write_complete(struct inode *inode, struct ll_async_page *llap);
void ll_open_complete(struct inode *inode);
int ll_is_inode_dirty(struct inode *inode);
void ll_try_done_writing(struct inode *inode);
void ll_queue_done_writing(struct inode *inode);
#else
static inline void llap_write_pending(struct inode *inode,
                                      struct ll_async_page *llap) { return; };
static inline void llap_write_complete(struct inode *inode,
                                       struct ll_async_page *llap) { return; };
static inline void ll_open_complete(struct inode *inode) { return; };
static inline int ll_is_inode_dirty(struct inode *inode) { return 0; };
static inline void ll_try_done_writing(struct inode *inode) { return; };
static inline void ll_queue_done_writing(struct inode *inode) { return; };
//static inline void ll_close_thread_shutdown(struct ll_close_queue *lcq) { return; };
//static inline int ll_close_thread_start(struct ll_close_queue **lcq_ret) { return 0; };
#endif
void ll_close_thread_shutdown(struct ll_close_queue *lcq);
int ll_close_thread_start(struct ll_close_queue **lcq_ret);

/* llite/llite_mmap.c */
typedef struct rb_root  rb_root_t;
typedef struct rb_node  rb_node_t;

struct ll_lock_tree_node;
struct ll_lock_tree {
        rb_root_t                       lt_root;
        struct list_head                lt_locked_list;
        struct ll_file_data             *lt_fd;
};

int ll_teardown_mmaps(struct address_space *mapping, __u64 first, __u64 last);
int ll_file_mmap(struct file * file, struct vm_area_struct * vma);
struct ll_lock_tree_node * ll_node_from_inode(struct inode *inode, __u64 start,
                                              __u64 end, ldlm_mode_t mode);
int ll_tree_lock(struct ll_lock_tree *tree,
                 struct ll_lock_tree_node *first_node,
                 const char *buf, size_t count, int ast_flags);
int ll_tree_lock_iov(struct ll_lock_tree *tree,
                     struct ll_lock_tree_node *first_node,
                     const struct iovec *iov, unsigned long nr_segs,
                     int ast_flags);
int ll_tree_unlock(struct ll_lock_tree *tree);

enum ll_lock_style {
        LL_LOCK_STYLE_NOLOCK   = 0,
        LL_LOCK_STYLE_FASTLOCK = 1,
        LL_LOCK_STYLE_TREELOCK = 2
};

struct ll_thread_data {
        int ltd_magic;
        int lock_style;
        struct list_head *tree_list;
        union {
                struct ll_lock_tree tree;
                struct lustre_handle lockh;
        } u;
};
struct ll_thread_data *ll_td_get(void);
void ll_td_set(struct ll_thread_data *ltd);
struct lustre_handle *ltd2lockh(struct ll_thread_data *ltd, __u64 start,
                                __u64 end);

#define    ll_s2sbi(sb)        (s2lsi(sb)->lsi_llsbi)

static inline __u64 ll_ts2u64(struct timespec *time)
{
        __u64 t = time->tv_sec;
        return t;
}

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2obdexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_osc_exp;
}

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2mdcexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_mdc_exp;
}

static inline struct client_obd *sbi2mdc(struct ll_sb_info *sbi)
{
        struct obd_device *obd = sbi->ll_mdc_exp->exp_obd;
        if (obd == NULL)
                LBUG();
        return &obd->u.cli;
}

// FIXME: replace the name of this with LL_SB to conform to kernel stuff
static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return ll_s2sbi(inode->i_sb);
}

static inline struct obd_export *ll_i2obdexp(struct inode *inode)
{
        return ll_s2obdexp(inode->i_sb);
}

static inline struct obd_export *ll_i2mdcexp(struct inode *inode)
{
        return ll_s2mdcexp(inode->i_sb);
}

/** get lu_fid from inode. */
static inline struct lu_fid *ll_inode_lu_fid(struct inode *inode)
{
        return &ll_i2info(inode)->lli_fid.f20;
}

/** get ll_fid from inode. */
static inline struct ll_fid *ll_inode_ll_fid(struct inode *inode)
{
        return &ll_i2info(inode)->lli_fid.f16;
}

static inline void ll_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        *fid = *ll_inode_ll_fid(inode);
}

static inline int ll_mds_max_easize(struct super_block *sb)
{
        return sbi2mdc(ll_s2sbi(sb))->cl_max_mds_easize;
}

static inline __u64 ll_file_maxbytes(struct inode *inode)
{
        return ll_i2info(inode)->lli_maxbytes;
}

/* llite/xattr.c */
int ll_setxattr(struct dentry *dentry, const char *name,
                const void *value, size_t size, int flags);
ssize_t ll_getxattr(struct dentry *dentry, const char *name,
                    void *buffer, size_t size);
ssize_t ll_listxattr(struct dentry *dentry, char *buffer, size_t size);
int ll_removexattr(struct dentry *dentry, const char *name);

/* statahead.c */

#define LL_SA_RPC_MIN   2
#define LL_SA_RPC_DEF   32
#define LL_SA_RPC_MAX   8192

/* per inode struct, for dir only */
struct ll_statahead_info {
        struct inode           *sai_inode;
        unsigned int            sai_generation; /* generation for statahead */
        atomic_t                sai_refcount;   /* when access this struct, hold
                                                 * refcount */
        unsigned int            sai_sent;       /* stat requests sent count */
        unsigned int            sai_replied;    /* stat requests which received
                                                 * reply */
        unsigned int            sai_max;        /* max ahead of lookup */
        unsigned int            sai_index;      /* index of statahead entry */
        unsigned int            sai_index_next; /* index for the next statahead
                                                 * entry to be stated */
        unsigned int            sai_hit;        /* hit count */
        unsigned int            sai_miss;       /* miss count:
                                                 * for "ls -al" case, it includes
                                                 * hidden dentry miss;
                                                 * for "ls -l" case, it does not
                                                 * include hidden dentry miss.
                                                 * "sai_miss_hidden" is used for
                                                 * the later case.
                                                 */
        unsigned int            sai_consecutive_miss; /* consecutive miss */
        unsigned int            sai_miss_hidden;/* "ls -al", but first dentry
                                                 * is not a hidden one */
        unsigned int            sai_skip_hidden;/* skipped hidden dentry count */
        unsigned int            sai_ls_all:1;   /* "ls -al", do stat-ahead for
                                                 * hidden entries */
        cfs_waitq_t             sai_waitq;      /* stat-ahead wait queue */
        struct ptlrpc_thread    sai_thread;     /* stat-ahead thread */
        struct list_head        sai_entries_sent;     /* entries sent out */
        struct list_head        sai_entries_received; /* entries returned */
        struct list_head        sai_entries_stated;   /* entries stated */
};

int do_statahead_enter(struct inode *dir, struct dentry **dentry, int lookup);
void ll_statahead_exit(struct inode *dir, struct dentry *dentry, int result);
void ll_stop_statahead(struct inode *inode, void *key);

static inline
void ll_statahead_mark(struct inode *dir, struct dentry *dentry)
{
        struct ll_inode_info  *lli;
        struct ll_dentry_data *ldd = ll_d2d(dentry);

        /* dentry has been move to other directory, no need mark */
        if (unlikely(dir != dentry->d_parent->d_inode))
                return;

        lli = ll_i2info(dir);
        /* not the same process, don't mark */
        if (lli->lli_opendir_pid != cfs_curproc_pid())
                return;

        spin_lock(&lli->lli_lock);
        if (likely(lli->lli_sai != NULL && ldd != NULL))
                ldd->lld_sa_generation = lli->lli_sai->sai_generation;
        spin_unlock(&lli->lli_lock);
}

static inline
int ll_statahead_enter(struct inode *dir, struct dentry **dentryp, int lookup)
{
        struct ll_inode_info  *lli;
        struct ll_sb_info     *sbi;
        struct ll_dentry_data *ldd = ll_d2d(*dentryp);

        if (unlikely(dir == NULL))
                return -EAGAIN;

        sbi = ll_i2sbi(dir);
        /* temporarily disable dir stat ahead in interoperability mode */
        if (sbi->ll_mdc_exp->exp_connect_flags & OBD_CONNECT_FID)
                return -ENOTSUPP;

        if (sbi->ll_sa_max == 0)
                return -ENOTSUPP;

        lli = ll_i2info(dir);
        /* not the same process, don't statahead */
        if (lli->lli_opendir_pid != cfs_curproc_pid())
                return -EAGAIN;

        /*
         * When "ls" a dentry, the system trigger more than once "revalidate" or
         * "lookup", for "getattr", for "getxattr", and maybe for others.
         * Under patchless client mode, the operation intent is not accurate,
         * it maybe misguide the statahead thread. For example:
         * The "revalidate" call for "getattr" and "getxattr" of a dentry maybe
         * have the same operation intent -- "IT_GETATTR".
         * In fact, one dentry should has only one chance to interact with the
         * statahead thread, otherwise the statahead windows will be confused.
         * The solution is as following:
         * Assign "lld_sa_generation" with "sai_generation" when a dentry
         * "IT_GETATTR" for the first time, and the subsequent "IT_GETATTR"
         * will bypass interacting with statahead thread for checking:
         * "lld_sa_generation == lli_sai->sai_generation"
         */
        if (ldd && lli->lli_sai &&
            ldd->lld_sa_generation == lli->lli_sai->sai_generation)
                return -EAGAIN;

        return do_statahead_enter(dir, dentryp, lookup);
}

static void inline ll_dops_init(struct dentry *de, int block, int init_sa)
{
        struct ll_dentry_data *lld = ll_d2d(de);

        if (lld == NULL && block != 0) {
                ll_set_dd(de);
                lld = ll_d2d(de);
        }

        if (lld != NULL && init_sa != 0)
                lld->lld_sa_generation = 0;

        de->d_op = &ll_d_ops;
}

/* llite ioctl register support rountine */
#ifdef __KERNEL__
enum llioc_iter {
        LLIOC_CONT = 0,
        LLIOC_STOP
};

#define LLIOC_MAX_CMD           256

/*
 * Rules to write a callback function:
 *
 * Parameters:
 *  @magic: Dynamic ioctl call routine will feed this vaule with the pointer
 *      returned to ll_iocontrol_register.  Callback functions should use this
 *      data to check the potential collasion of ioctl cmd. If collasion is
 *      found, callback function should return LLIOC_CONT.
 *  @rcp: The result of ioctl command.
 *
 *  Return values:
 *      If @magic matches the pointer returned by ll_iocontrol_data, the
 *      callback should return LLIOC_STOP; return LLIOC_STOP otherwise.
 */
typedef enum llioc_iter (*llioc_callback_t)(struct inode *inode,
                struct file *file, unsigned int cmd, unsigned long arg,
                void *magic, int *rcp);

enum llioc_iter ll_iocontrol_call(struct inode *inode, struct file *file,
                unsigned int cmd, unsigned long arg, int *rcp);

/* export functions */
/* Register ioctl block dynamatically for a regular file.
 *
 * @cmd: the array of ioctl command set
 * @count: number of commands in the @cmd
 * @cb: callback function, it will be called if an ioctl command is found to
 *      belong to the command list @cmd.
 *
 * Return vaule:
 *      A magic pointer will be returned if success;
 *      otherwise, NULL will be returned.
 * */
void *ll_iocontrol_register(llioc_callback_t cb, int count, unsigned int *cmd);
void ll_iocontrol_unregister(void *magic);

__u64 ll_fid_build_ino(const struct ll_fid *fid, int api32);
__u32 ll_fid_build_gen(struct ll_sb_info *sbi,
                       struct ll_fid *fid);

#endif

#endif /* LLITE_INTERNAL_H */
