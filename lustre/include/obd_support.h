/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _OBD_SUPPORT
#define _OBD_SUPPORT

#include <libcfs/libcfs.h>
#include <lvfs.h>
#include <lprocfs_status.h>

#if defined(__linux__)
#include <linux/obd_support.h>
#elif defined(__APPLE__)
#include <darwin/obd_support.h>
#elif defined(__WINNT__)
#include <winnt/obd_support.h>
#else
#error Unsupported operating system.
#endif

/* global variables */
extern struct lprocfs_stats *obd_memory;
enum {
        OBD_MEMORY_STAT = 0,
        OBD_MEMORY_PAGES_STAT = 1,
        OBD_STATS_NUM,
};

enum {
        OBD_FAIL_LOC_NOSET      = 0,
        OBD_FAIL_LOC_ORSET      = 1,
        OBD_FAIL_LOC_RESET      = 2
};

extern unsigned long obd_fail_loc;
extern unsigned int obd_fail_val;
extern unsigned int obd_debug_peer_on_timeout;
extern unsigned int obd_dump_on_timeout;
extern unsigned int obd_dump_on_eviction;
extern unsigned int obd_timeout;          /* seconds */
#define PING_INTERVAL max(obd_timeout / 4, 1U)
#define RECONNECT_INTERVAL max(obd_timeout / 10, 10U)
extern unsigned int ldlm_timeout;
extern unsigned int obd_health_check_timeout;
extern unsigned int obd_sync_filter;
extern unsigned int obd_max_dirty_pages;
extern atomic_t obd_dirty_pages;
extern cfs_waitq_t obd_race_waitq;
extern int obd_race_state;
extern unsigned int obd_alloc_fail_rate;

int __obd_fail_check_set(__u32 id, __u32 value, int set);

/* lvfs.c */
int obd_alloc_fail(const void *ptr, const char *name, const char *type,
                   size_t size, const char *file, int line);

/* Timeout definitions */
#define LDLM_TIMEOUT_DEFAULT 20
#define OBD_TIMEOUT_DEFAULT 100
#define HEALTH_CHECK_COEF 3 / 2
#define HEALTH_CHECK_TIMEOUT_DEFAULT (OBD_TIMEOUT_DEFAULT * HEALTH_CHECK_COEF)
#define HEALTH_CHECK_TIMEOUT (obd_timeout * HEALTH_CHECK_COEF)

#define OBD_FAIL_MDS                     0x100
#define OBD_FAIL_MDS_HANDLE_UNPACK       0x101
#define OBD_FAIL_MDS_GETATTR_NET         0x102
#define OBD_FAIL_MDS_GETATTR_PACK        0x103
#define OBD_FAIL_MDS_READPAGE_NET        0x104
#define OBD_FAIL_MDS_READPAGE_PACK       0x105
#define OBD_FAIL_MDS_SENDPAGE            0x106
#define OBD_FAIL_MDS_REINT_NET           0x107
#define OBD_FAIL_MDS_REINT_UNPACK        0x108
#define OBD_FAIL_MDS_REINT_SETATTR       0x109
#define OBD_FAIL_MDS_REINT_SETATTR_WRITE 0x10a
#define OBD_FAIL_MDS_REINT_CREATE        0x10b
#define OBD_FAIL_MDS_REINT_CREATE_WRITE  0x10c
#define OBD_FAIL_MDS_REINT_UNLINK        0x10d
#define OBD_FAIL_MDS_REINT_UNLINK_WRITE  0x10e
#define OBD_FAIL_MDS_REINT_LINK          0x10f
#define OBD_FAIL_MDS_REINT_LINK_WRITE    0x110
#define OBD_FAIL_MDS_REINT_RENAME        0x111
#define OBD_FAIL_MDS_REINT_RENAME_WRITE  0x112
#define OBD_FAIL_MDS_OPEN_NET            0x113
#define OBD_FAIL_MDS_OPEN_PACK           0x114
#define OBD_FAIL_MDS_CLOSE_NET           0x115
#define OBD_FAIL_MDS_CLOSE_PACK          0x116
#define OBD_FAIL_MDS_CONNECT_NET         0x117
#define OBD_FAIL_MDS_CONNECT_PACK        0x118
#define OBD_FAIL_MDS_REINT_NET_REP       0x119
#define OBD_FAIL_MDS_DISCONNECT_NET      0x11a
#define OBD_FAIL_MDS_GETSTATUS_NET       0x11b
#define OBD_FAIL_MDS_GETSTATUS_PACK      0x11c
#define OBD_FAIL_MDS_STATFS_PACK         0x11d
#define OBD_FAIL_MDS_STATFS_NET          0x11e
#define OBD_FAIL_MDS_GETATTR_NAME_NET    0x11f
#define OBD_FAIL_MDS_PIN_NET             0x120
#define OBD_FAIL_MDS_UNPIN_NET           0x121
#define OBD_FAIL_MDS_ALL_REPLY_NET       0x122
#define OBD_FAIL_MDS_ALL_REQUEST_NET     0x123
#define OBD_FAIL_MDS_SYNC_NET            0x124
#define OBD_FAIL_MDS_SYNC_PACK           0x125
#define OBD_FAIL_MDS_DONE_WRITING_NET    0x126
#define OBD_FAIL_MDS_DONE_WRITING_PACK   0x127
#define OBD_FAIL_MDS_ALLOC_OBDO          0x128
#define OBD_FAIL_MDS_PAUSE_OPEN          0x129
#define OBD_FAIL_MDS_STATFS_LCW_SLEEP    0x12a
#define OBD_FAIL_MDS_OPEN_CREATE         0x12b
#define OBD_FAIL_MDS_OST_SETATTR         0x12c
#define OBD_FAIL_MDS_QUOTACHECK_NET      0x12d
#define OBD_FAIL_MDS_QUOTACTL_NET        0x12e
#define OBD_FAIL_MDS_CLIENT_ADD          0x12f
#define OBD_FAIL_MDS_GETXATTR_NET        0x130
#define OBD_FAIL_MDS_GETXATTR_PACK       0x131
#define OBD_FAIL_MDS_SETXATTR_NET        0x132
#define OBD_FAIL_MDS_SETXATTR            0x133
#define OBD_FAIL_MDS_SETXATTR_WRITE      0x134
#define OBD_FAIL_MDS_FS_SETUP            0x135
#define OBD_FAIL_MDS_RESEND              0x136
#define OBD_FAIL_MDS_IS_SUBDIR_NET       0x137
#define OBD_FAIL_MDS_IS_SUBDIR_PACK      0x138
#define OBD_FAIL_MDS_SET_INFO_NET        0x139
#define OBD_FAIL_MDS_WRITEPAGE_NET       0x13a
#define OBD_FAIL_MDS_WRITEPAGE_PACK      0x13b
#define OBD_FAIL_MDS_LLOG_CREATE_FAILED  0x13c
#define OBD_FAIL_MDS_OSC_PRECREATE       0x13d
#define OBD_FAIL_MDS_LOV_SYNC_RACE       0x13e
#define OBD_FAIL_MDS_CLOSE_NET_REP       0x13f
#define OBD_FAIL_MDS_LLOG_SYNC_TIMEOUT   0x140

#define OBD_FAIL_OST                     0x200
#define OBD_FAIL_OST_CONNECT_NET         0x201
#define OBD_FAIL_OST_DISCONNECT_NET      0x202
#define OBD_FAIL_OST_GET_INFO_NET        0x203
#define OBD_FAIL_OST_CREATE_NET          0x204
#define OBD_FAIL_OST_DESTROY_NET         0x205
#define OBD_FAIL_OST_GETATTR_NET         0x206
#define OBD_FAIL_OST_SETATTR_NET         0x207
#define OBD_FAIL_OST_OPEN_NET            0x208
#define OBD_FAIL_OST_CLOSE_NET           0x209
#define OBD_FAIL_OST_BRW_NET             0x20a
#define OBD_FAIL_OST_PUNCH_NET           0x20b
#define OBD_FAIL_OST_STATFS_NET          0x20c
#define OBD_FAIL_OST_HANDLE_UNPACK       0x20d
#define OBD_FAIL_OST_BRW_WRITE_BULK      0x20e
#define OBD_FAIL_OST_BRW_READ_BULK       0x20f
#define OBD_FAIL_OST_SYNC_NET            0x210
#define OBD_FAIL_OST_ALL_REPLY_NET       0x211
#define OBD_FAIL_OST_ALL_REQUESTS_NET    0x212
#define OBD_FAIL_OST_LDLM_REPLY_NET      0x213
#define OBD_FAIL_OST_BRW_PAUSE_BULK      0x214
#define OBD_FAIL_OST_ENOSPC              0x215
#define OBD_FAIL_OST_EROFS               0x216
#define OBD_FAIL_OST_ENOENT              0x217
#define OBD_FAIL_OST_QUOTACHECK_NET      0x218
#define OBD_FAIL_OST_QUOTACTL_NET        0x219
#define OBD_FAIL_OST_CHECKSUM_RECEIVE    0x21a
#define OBD_FAIL_OST_CHECKSUM_SEND       0x21b
#define OBD_FAIL_OST_BRW_SIZE            0x21c
#define OBD_FAIL_OST_DROP_REQ            0x21d
#define OBD_FAIL_OST_SETATTR_CREDITS     0x21e
#define OBD_FAIL_OST_HOLD_WRITE_RPC      0x21f
#define OBD_FAIL_OST_BRW_WRITE_BULK2     0x220
#define OBD_FAIL_OST_LLOG_RECOVERY_TIMEOUT 0x221
#define OBD_FAIL_OST_CANCEL_COOKIE_TIMEOUT 0x222
#define OBD_FAIL_OST_CONNECT_NET2        0x225

#define OBD_FAIL_LDLM                    0x300
#define OBD_FAIL_LDLM_NAMESPACE_NEW      0x301
#define OBD_FAIL_LDLM_ENQUEUE            0x302
#define OBD_FAIL_LDLM_CONVERT            0x303
#define OBD_FAIL_LDLM_CANCEL             0x304
#define OBD_FAIL_LDLM_BL_CALLBACK        0x305
#define OBD_FAIL_LDLM_CP_CALLBACK        0x306
#define OBD_FAIL_LDLM_GL_CALLBACK        0x307
#define OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR 0x308
#define OBD_FAIL_LDLM_ENQUEUE_INTENT_ERR 0x309
#define OBD_FAIL_LDLM_CREATE_RESOURCE    0x30a
#define OBD_FAIL_LDLM_ENQUEUE_BLOCKED    0x30b
#define OBD_FAIL_LDLM_REPLY              0x30c
#define OBD_FAIL_LDLM_RECOV_CLIENTS      0x30d
#define OBD_FAIL_LDLM_ENQUEUE_OLD_EXPORT 0x30e
#define OBD_FAIL_LDLM_GLIMPSE            0x30f
#define OBD_FAIL_LDLM_CANCEL_RACE        0x310
#define OBD_FAIL_LDLM_CANCEL_EVICT_RACE  0x311
/* 
#define OBD_FAIL_LDLM_PAUSE_CANCEL       0x312
*/
#define OBD_FAIL_LDLM_CLOSE_THREAD       0x313
#define OBD_FAIL_LDLM_CANCEL_BL_CB_RACE  0x314

#define OBD_FAIL_OSC                     0x400
#define OBD_FAIL_OSC_BRW_READ_BULK       0x401
#define OBD_FAIL_OSC_BRW_WRITE_BULK      0x402
#define OBD_FAIL_OSC_LOCK_BL_AST         0x403
#define OBD_FAIL_OSC_LOCK_CP_AST         0x404
#define OBD_FAIL_OSC_MATCH               0x405
#define OBD_FAIL_OSC_BRW_PREP_REQ        0x406
#define OBD_FAIL_OSC_SHUTDOWN            0x407
#define OBD_FAIL_OSC_CHECKSUM_RECEIVE    0x408
#define OBD_FAIL_OSC_CHECKSUM_SEND       0x409
#define OBD_FAIL_OSC_BRW_PREP_REQ2       0x40a
#define OBD_FAIL_OSC_CONNECT_CKSUM       0x40b
#define OBD_FAIL_OSC_CKSUM_ADLER_ONLY    0x40c
#define OBD_FAIL_OSC_DIO_PAUSE           0x40d

#define OBD_FAIL_PTLRPC                  0x500
#define OBD_FAIL_PTLRPC_ACK              0x501
#define OBD_FAIL_PTLRPC_RQBD             0x502
#define OBD_FAIL_PTLRPC_BULK_GET_NET     0x503
#define OBD_FAIL_PTLRPC_BULK_PUT_NET     0x504
#define OBD_FAIL_PTLRPC_DROP_RPC         0x505
#define OBD_FAIL_PTLRPC_DELAY_SEND       0x506
#define OBD_FAIL_PTLRPC_DELAY_RECOV      0x507

#define OBD_FAIL_OBD_PING_NET            0x600
#define OBD_FAIL_OBD_LOG_CANCEL_NET      0x601
#define OBD_FAIL_OBD_LOGD_NET            0x602
#define OBD_FAIL_OBD_QC_CALLBACK_NET     0x603
#define OBD_FAIL_OBD_DQACQ               0x604

#define OBD_FAIL_TGT_REPLY_NET           0x700
#define OBD_FAIL_TGT_CONN_RACE           0x701
#define OBD_FAIL_TGT_FORCE_RECONNECT     0x702
#define OBD_FAIL_TGT_DELAY_CONNECT       0x703
#define OBD_FAIL_TGT_DELAY_RECONNECT     0x704
#define OBD_FAIL_TGT_DELAY_PRECREATE     0x705
#define OBD_FAIL_TGT_TOOMANY_THREADS     0x706

#define OBD_FAIL_MDC_REVALIDATE_PAUSE    0x800
#define OBD_FAIL_MDC_ENQUEUE_PAUSE       0x801
#define OBD_FAIL_MDC_GETATTR_ENQUEUE     0x803

#define OBD_FAIL_MGS                     0x900
#define OBD_FAIL_MGS_ALL_REQUEST_NET     0x901
#define OBD_FAIL_MGS_ALL_REPLY_NET       0x902
#define OBD_FAIL_MGC_PROCESS_LOG         0x903
#define OBD_FAIL_MGS_SLOW_REQUEST_NET    0x904
#define OBD_FAIL_MGS_SLOW_TARGET_REG     0x905

#define OBD_FAIL_QUOTA_QD_COUNT_32BIT    0xa00

#define OBD_FAIL_LPROC_REMOVE            0xb00

#define OBD_FAIL_GENERAL_ALLOC           0xc00

#define OBD_FAIL_SEQ                     0x1000
#define OBD_FAIL_SEQ_QUERY_NET           0x1001

#define OBD_FAIL_FLD                     0x1100
#define OBD_FAIL_FLD_QUERY_NET           0x1101

#define OBD_FAIL_SEC_CTX                 0x1200
#define OBD_FAIL_SEC_CTX_INIT_NET        0x1201
#define OBD_FAIL_SEC_CTX_INIT_CONT_NET   0x1202
#define OBD_FAIL_SEC_CTX_FINI_NET        0x1203

/* Failure injection control */
#define OBD_FAIL_MASK_SYS    0x0000FF00
#define OBD_FAIL_MASK_LOC   (0x000000FF | OBD_FAIL_MASK_SYS)

#define OBD_FAILED_BIT       30
/* OBD_FAILED is 0x40000000 */
#define OBD_FAILED          (1 << OBD_FAILED_BIT)

#define OBD_FAIL_ONCE_BIT    31
/* OBD_FAIL_ONCE is 0x80000000 */
#define OBD_FAIL_ONCE       (1 << OBD_FAIL_ONCE_BIT)

/* The following flags aren't made to be combined */
#define OBD_FAIL_SKIP        0x20000000 /* skip N times then fail */
#define OBD_FAIL_SOME        0x10000000 /* only fail N times */
#define OBD_FAIL_RAND        0x08000000 /* fail 1/N of the times */
#define OBD_FAIL_USR1        0x04000000 /* user flag */

#define OBD_FAIL_PRECHECK(id) (obd_fail_loc &&                                \
                              (obd_fail_loc & OBD_FAIL_MASK_LOC) ==           \
                              ((id) & OBD_FAIL_MASK_LOC))

static inline int obd_fail_check_set(__u32 id, __u32 value, int set)
{
        int ret = 0;
        if (unlikely(OBD_FAIL_PRECHECK(id) &&
            (ret = __obd_fail_check_set(id, value, set)))) {
                CERROR("*** obd_fail_loc=%x ***\n", id);
        }
        return ret;
}

/* If id hit obd_fail_loc, return 1, otherwise return 0 */
#define OBD_FAIL_CHECK(id) \
        obd_fail_check_set(id, 0, OBD_FAIL_LOC_NOSET)

/* If id hit obd_fail_loc, obd_fail_loc |= value and return 1,
 * otherwise return 0 */
#define OBD_FAIL_CHECK_ORSET(id, value) \
        obd_fail_check_set(id, value, OBD_FAIL_LOC_ORSET)

/* If id hit obd_fail_loc, obd_fail_loc = value and return 1,
 * otherwise return 0 */
#define OBD_FAIL_CHECK_RESET(id, value) \
        obd_fail_check_set(id, value, OBD_FAIL_LOC_RESET)


static inline int obd_fail_timeout_set(__u32 id, __u32 value, int secs, int set)
{
        int ret = 0;
        if (unlikely(OBD_FAIL_PRECHECK(id) &&
            (ret = __obd_fail_check_set(id, value, set)))) {
                CERROR("obd_fail_timeout id %x sleeping for %d secs\n",
                       id, secs);
                set_current_state(TASK_UNINTERRUPTIBLE);
                cfs_schedule_timeout(CFS_TASK_UNINT,  cfs_time_seconds(secs));
                set_current_state(TASK_RUNNING);
                CERROR("obd_fail_timeout id %x awake\n", id);
        }
        return ret;
}

/* If id hit obd_fail_loc, sleep secs */
#define OBD_FAIL_TIMEOUT(id, secs) \
        obd_fail_timeout_set(id, 0, secs, OBD_FAIL_LOC_NOSET)

/* If id hit obd_fail_loc, obd_fail_loc |= value and sleep secs */
#define OBD_FAIL_TIMEOUT_ORSET(id, value, secs) \
        obd_fail_timeout_set(id, value, secs, OBD_FAIL_LOC_ORSET)

#ifdef __KERNEL__
static inline void obd_fail_write(int id, struct super_block *sb)
{
        /* We set FAIL_ONCE because we never "un-fail" a device */
        if (OBD_FAIL_CHECK_ORSET(id & ~OBD_FAIL_ONCE, OBD_FAIL_ONCE)) {
#ifdef LIBCFS_DEBUG
                BDEVNAME_DECLARE_STORAGE(tmp);
                CERROR("obd_fail_loc=%x, fail write operation on %s\n",
                       id, ll_bdevname(sb, tmp));
#endif
                /* TODO-CMD: fix getting jdev */
                __lvfs_set_rdonly(lvfs_sbdev(sb), (lvfs_sbdev_type)0);
        }
}
#define OBD_FAIL_WRITE(id, sb) obd_fail_write(id, sb)

/* The idea here is to synchronise two threads to force a race. The
 * first thread that calls this with a matching fail_loc is put to
 * sleep. The next thread that calls with the same fail_loc wakes up
 * the first and continues. */
static inline void obd_race(__u32 id)
{
        if (OBD_FAIL_PRECHECK(id)) {
                if (unlikely(__obd_fail_check_set(id, 0, OBD_FAIL_LOC_NOSET))) {
                        obd_race_state = 0;
                        CERROR("obd_race id %x sleeping\n", id);
                        OBD_SLEEP_ON(obd_race_waitq, obd_race_state != 0);
                        CERROR("obd_fail_race id %x awake\n", id);
                } else {
                        CERROR("obd_fail_race id %x waking\n", id);
                        obd_race_state = 1;
                        wake_up(&obd_race_waitq);
                }
        }
}
#define OBD_RACE(id) obd_race(id)
#else
/* sigh.  an expedient fix until OBD_RACE is fixed up */
#define OBD_RACE(foo) do {} while(0)
#endif

#define fixme() CDEBUG(D_OTHER, "FIXME\n");

extern atomic_t libcfs_kmemory;

#ifdef LPROCFS
#define obd_memory_add(size)                                                  \
        lprocfs_counter_add(obd_memory, OBD_MEMORY_STAT, (long)(size))
#define obd_memory_sub(size)                                                  \
        lprocfs_counter_sub(obd_memory, OBD_MEMORY_STAT, (long)(size))
#define obd_memory_sum()                                                      \
        lprocfs_stats_collector(obd_memory, OBD_MEMORY_STAT,                  \
                                LPROCFS_FIELDS_FLAGS_SUM)
#define obd_pages_add(order)                                                  \
        lprocfs_counter_add(obd_memory, OBD_MEMORY_PAGES_STAT,                \
                            (long)(1 << (order)))
#define obd_pages_sub(order)                                                  \
        lprocfs_counter_sub(obd_memory, OBD_MEMORY_PAGES_STAT,                \
                            (long)(1 << (order)))
#define obd_pages_sum()                                                       \
        lprocfs_stats_collector(obd_memory, OBD_MEMORY_PAGES_STAT,            \
                                LPROCFS_FIELDS_FLAGS_SUM)

extern void obd_update_maxusage(void);
extern __u64 obd_memory_max(void);
extern __u64 obd_pages_max(void);

#else

extern __u64 obd_alloc;
extern __u64 obd_pages;

extern __u64 obd_max_alloc;
extern __u64 obd_max_pages;

static inline void obd_memory_add(long size)
{
        obd_alloc += size;
        if (obd_alloc > obd_max_alloc)
                obd_max_alloc = obd_alloc;
}

static inline void obd_memory_sub(long size)
{
        obd_alloc -= size;
}

static inline void obd_pages_add(int order)
{
        obd_pages += 1<< order;
        if (obd_pages > obd_max_pages)
                obd_max_pages = obd_pages;
}

static inline void obd_pages_sub(int order)
{
        obd_pages -= 1<< order;
}

#define obd_memory_sum() (obd_alloc)
#define obd_pages_sum()  (obd_pages)

#define obd_memory_max() (obd_max_alloc)
#define obd_pages_max() (obd_max_pages)

#endif

#if defined (CONFIG_DEBUG_MEMORY) && defined(__KERNEL__)

#define OBD_MT_WRONG_SIZE    (1 << 0)
#define OBD_MT_ALREADY_FREED (1 << 1)
#define OBD_MT_LOC_LEN       128

struct obd_mem_track {
        struct hlist_node mt_hash;
        char              mt_loc[OBD_MT_LOC_LEN];
        int               mt_flags;
        void             *mt_ptr;
        int               mt_size;
};

void lvfs_memdbg_show(void);
void lvfs_memdbg_insert(struct obd_mem_track *mt);
void lvfs_memdbg_remove(struct obd_mem_track *mt);
struct obd_mem_track *lvfs_memdbg_find(void *ptr);

int lvfs_memdbg_check_insert(struct obd_mem_track *mt);
struct obd_mem_track *lvfs_memdbg_check_remove(void *ptr);

static inline struct obd_mem_track *
__new_mem_track(void *ptr, int size,
                char *file, int line)
{
        struct obd_mem_track *mt;

        mt = kmalloc(sizeof(*mt), GFP_KERNEL);
        if (unlikely(!mt))
                return NULL;

        snprintf(mt->mt_loc, sizeof(mt->mt_loc) - 1,
                 "%s:%d", file, line);

        mt->mt_size = size;
        mt->mt_ptr = ptr;
        mt->mt_flags = 0;
        return mt;
}

static inline void
__free_mem_track(struct obd_mem_track *mt)
{
        kfree(mt);
}

static inline int
__get_mem_track(void *ptr, int size,
                char *file, int line)
{
        struct obd_mem_track *mt;

        mt = __new_mem_track(ptr, size, file, line);
        if (unlikely(!mt)) {
                CWARN("Can't allocate new memory track\n");
                return 0;
        }

        if (!lvfs_memdbg_check_insert(mt))
                __free_mem_track(mt);

        return 1;
}

static inline int
__put_mem_track(void *ptr, int size,
                char *file, int line)
{
        struct obd_mem_track *mt;

        if (unlikely(!(mt = lvfs_memdbg_check_remove(ptr)))) {
                CWARN("Ptr 0x%p is not allocated. Attempt to free "
                      "not allocated memory at %s:%d\n", ptr,
                      file, line);
                LBUG();
                return 0;
        } else {
                if (unlikely(mt->mt_size != size)) {
                        if (!(mt->mt_flags & OBD_MT_ALREADY_FREED)) {
                                mt->mt_flags |= (OBD_MT_WRONG_SIZE |
                                                 OBD_MT_ALREADY_FREED);

                                CWARN("Freeing memory chunk (at 0x%p) of "
                                      "different size than allocated "
                                      "(%d != %d) at %s:%d, allocated at %s\n",
                                      ptr, mt->mt_size, size, file, line,
                                      mt->mt_loc);
                        }
                } else {
                        __free_mem_track(mt);
                }
                return 1;
        }
}

#define get_mem_track(ptr, size, file, line)                                         \
        __get_mem_track((ptr), (size), (file), (line))

#define put_mem_track(ptr, size, file, line)                                         \
        __put_mem_track((ptr), (size), (file), (line))

#else /* !CONFIG_DEBUG_MEMORY */

#define get_mem_track(ptr, size, file, line)                                         \
        do {} while (0)

#define put_mem_track(ptr, size, file, line)                                         \
        do {} while (0)
#endif /* !CONFIG_DEBUG_MEMORY */

#define OBD_DEBUG_MEMUSAGE (1)

#if OBD_DEBUG_MEMUSAGE
#define OBD_ALLOC_POST(ptr, size, name)                                 \
                obd_memory_add(size);                                   \
                get_mem_track((ptr), (size), __FILE__, __LINE__);       \
                CDEBUG(D_MALLOC, name " '" #ptr "': %d at %p.\n",       \
                       (int)(size), ptr)

#define OBD_FREE_PRE(ptr, size, name)                                   \
        LASSERT(ptr);                                                   \
        put_mem_track((ptr), (size), __FILE__, __LINE__);               \
        obd_memory_sub(size);                                           \
        CDEBUG(D_MALLOC, name " '" #ptr "': %d at %p.\n",               \
               (int)(size), ptr);                                       \
        POISON(ptr, 0x5a, size)

#else /* !OBD_DEBUG_MEMUSAGE */

#define OBD_ALLOC_POST(ptr, size, name) ((void)0)
#define OBD_FREE_PRE(ptr, size, name)   ((void)0)

#endif /* !OBD_DEBUG_MEMUSAGE */

#ifdef RANDOM_FAIL_ALLOC
#define HAS_FAIL_ALLOC_FLAG OBD_FAIL_CHECK(OBD_FAIL_GENERAL_ALLOC)
#else
#define HAS_FAIL_ALLOC_FLAG 0
#endif

#define OBD_ALLOC_FAIL_BITS 24
#define OBD_ALLOC_FAIL_MASK ((1 << OBD_ALLOC_FAIL_BITS) - 1)
#define OBD_ALLOC_FAIL_MULT (OBD_ALLOC_FAIL_MASK / 100)

#if defined(LUSTRE_UTILS) /* this version is for utils only */
#define OBD_ALLOC_GFP(ptr, size, gfp_mask)                                    \
do {                                                                          \
        (ptr) = cfs_alloc(size, (gfp_mask));                                  \
        if (unlikely((ptr) == NULL)) {                                        \
                CERROR("kmalloc of '" #ptr "' (%d bytes) failed at %s:%d\n",  \
                       (int)(size), __FILE__, __LINE__);                      \
        } else {                                                              \
                memset(ptr, 0, size);                                         \
                CDEBUG(D_MALLOC, "kmalloced '" #ptr "': %d at %p\n",          \
                       (int)(size), ptr);                                     \
        }                                                                     \
} while (0)
#else /* this version is for the kernel and liblustre */
#define OBD_FREE_RTN0(ptr)                                                    \
({                                                                            \
        cfs_free(ptr);                                                        \
        (ptr) = NULL;                                                         \
        0;                                                                    \
})
#define OBD_ALLOC_GFP(ptr, size, gfp_mask)                                    \
do {                                                                          \
        (ptr) = cfs_alloc(size, (gfp_mask));                                  \
        if (likely((ptr) != NULL &&                                           \
                   (!HAS_FAIL_ALLOC_FLAG || obd_alloc_fail_rate == 0 ||       \
                    !obd_alloc_fail(ptr, #ptr, "km", size,                    \
                                    __FILE__, __LINE__) ||                    \
                    OBD_FREE_RTN0(ptr)))){                                    \
                memset(ptr, 0, size);                                         \
                OBD_ALLOC_POST(ptr, size, "kmalloced");                       \
        }                                                                     \
} while (0)
#endif

#ifndef OBD_ALLOC_MASK
# define OBD_ALLOC_MASK CFS_ALLOC_IO
#endif

#define OBD_ALLOC(ptr, size) OBD_ALLOC_GFP(ptr, size, OBD_ALLOC_MASK)
#define OBD_ALLOC_WAIT(ptr, size) OBD_ALLOC_GFP(ptr, size, CFS_ALLOC_STD)
#define OBD_ALLOC_PTR(ptr) OBD_ALLOC(ptr, sizeof *(ptr))
#define OBD_ALLOC_PTR_WAIT(ptr) OBD_ALLOC_WAIT(ptr, sizeof *(ptr))

#ifdef __arch_um__
# define OBD_VMALLOC(ptr, size) OBD_ALLOC(ptr, size)
#else
# define OBD_VMALLOC(ptr, size)                                               \
do {                                                                          \
        (ptr) = cfs_alloc_large(size);                                        \
        if (unlikely((ptr) == NULL)) {                                        \
                CERROR("vmalloc of '" #ptr "' (%d bytes) failed\n",           \
                       (int)(size));                                          \
                CERROR(LPU64" total bytes allocated by Lustre, %d by LNET\n", \
                       obd_memory_sum(), atomic_read(&libcfs_kmemory));       \
        } else {                                                              \
                memset(ptr, 0, size);                                         \
                OBD_ALLOC_POST(ptr, size, "vmalloced");                       \
        }                                                                     \
} while(0)
#endif

#ifdef CONFIG_DEBUG_SLAB
#define POISON(ptr, c, s) do {} while (0)
#define POISON_PTR(ptr)  ((void)0)
#else
#define POISON(ptr, c, s) memset(ptr, c, s)
#define POISON_PTR(ptr)  (ptr) = (void *)0xdeadbeef
#endif

#ifdef POISON_BULK
#define POISON_PAGE(page, val) do { memset(kmap(page), val, CFS_PAGE_SIZE);   \
                                    kunmap(page); } while (0)
#else
#define POISON_PAGE(page, val) do { } while (0)
#endif

#ifdef __KERNEL__
#define OBD_FREE(ptr, size)                                                   \
do {                                                                          \
        OBD_FREE_PRE(ptr, size, "kfreed");                                    \
        cfs_free(ptr);                                                        \
        POISON_PTR(ptr);                                                      \
} while(0)


#ifdef HAVE_RCU
# ifdef HAVE_CALL_RCU_PARAM
#  define my_call_rcu(rcu, cb)            call_rcu(rcu, cb, rcu)
# else
#  define my_call_rcu(rcu, cb)            call_rcu(rcu, cb)
# endif
#else
# define my_call_rcu(rcu, cb)             (cb)(rcu)
#endif

#define OBD_FREE_RCU_CB(ptr, size, handle, free_cb)                           \
do {                                                                          \
        struct portals_handle *__h = (handle);                                \
        LASSERT(handle);                                                      \
        __h->h_ptr = (ptr);                                                   \
        __h->h_size = (size);                                                 \
        __h->h_free_cb = (void (*)(void *, size_t))(free_cb);                 \
        my_call_rcu(&__h->h_rcu, class_handle_free_cb);                       \
        POISON_PTR(ptr);                                                      \
} while(0)
#define OBD_FREE_RCU(ptr, size, handle) OBD_FREE_RCU_CB(ptr, size, handle, NULL)

#else
#define OBD_FREE(ptr, size) ((void)(size), free((ptr)))
#define OBD_FREE_RCU(ptr, size, handle) (OBD_FREE(ptr, size))
#define OBD_FREE_RCU_CB(ptr, size, handle, cb)     ((*(cb))(ptr, size))
#endif /* ifdef __KERNEL__ */

#ifdef __arch_um__
# define OBD_VFREE(ptr, size) OBD_FREE(ptr, size)
#else
# define OBD_VFREE(ptr, size)                                                 \
do {                                                                          \
        OBD_FREE_PRE(ptr, size, "vfreed");                                    \
        cfs_free_large(ptr);                                                  \
        POISON_PTR(ptr);                                                      \
} while(0)
#endif

/* we memset() the slab object to 0 when allocation succeeds, so DO NOT
 * HAVE A CTOR THAT DOES ANYTHING.  its work will be cleared here.  we'd
 * love to assert on that, but slab.c keeps kmem_cache_s all to itself. */
#define OBD_SLAB_FREE_RTN0(ptr, slab)                                         \
({                                                                            \
        cfs_mem_cache_free((slab), (ptr));                                    \
        (ptr) = NULL;                                                         \
        0;                                                                    \
})
#define OBD_SLAB_ALLOC(ptr, slab, type, size)                                 \
do {                                                                          \
        LASSERT(!in_interrupt());                                             \
        (ptr) = cfs_mem_cache_alloc(slab, (type));                            \
        if (likely((ptr) != NULL &&                                           \
                   (!HAS_FAIL_ALLOC_FLAG || obd_alloc_fail_rate == 0 ||       \
                    !obd_alloc_fail(ptr, #ptr, "slab-", size,                 \
                                    __FILE__, __LINE__) ||                    \
                    OBD_SLAB_FREE_RTN0(ptr, slab)))) {                        \
                memset(ptr, 0, size);                                         \
                OBD_ALLOC_POST(ptr, size, "slab-alloced");                    \
        }                                                                     \
} while(0)

#define OBD_FREE_PTR(ptr) OBD_FREE(ptr, sizeof *(ptr))

#define OBD_SLAB_FREE(ptr, slab, size)                                        \
do {                                                                          \
        OBD_FREE_PRE(ptr, size, "slab-freed");                                \
        cfs_mem_cache_free(slab, ptr);                                        \
        POISON_PTR(ptr);                                                      \
} while(0)

#define OBD_SLAB_ALLOC_PTR(ptr, slab)                                         \
        OBD_SLAB_ALLOC((ptr), (slab), CFS_ALLOC_STD, sizeof *(ptr))
#define OBD_SLAB_FREE_PTR(ptr, slab)                                          \
        OBD_SLAB_FREE((ptr), (slab), sizeof *(ptr))

#define KEY_IS(str) \
        (keylen >= (sizeof(str)-1) && memcmp(key, str, (sizeof(str)-1)) == 0)

/* Wrapper for contiguous page frame allocation */
#define OBD_PAGES_ALLOC(ptr, order, gfp_mask)                                 \
do {                                                                          \
        (ptr) = cfs_alloc_pages(gfp_mask, order);                             \
        if (unlikely((ptr) == NULL)) {                                        \
                CERROR("alloc_pages of '" #ptr "' %d page(s) / "LPU64" bytes "\
                       "failed\n", (int)(1 << (order)),                       \
                       (__u64)((1 << (order)) << CFS_PAGE_SHIFT));            \
                CERROR(LPU64" total bytes and "LPU64" total pages "           \
                       "("LPU64" bytes) allocated by Lustre, "                \
                       "%d total bytes by LNET\n",                            \
                       obd_memory_sum(),                                      \
                       obd_pages_sum() << CFS_PAGE_SHIFT,                     \
                       obd_pages_sum(),                                       \
                       atomic_read(&libcfs_kmemory));                         \
        } else {                                                              \
                obd_pages_add(order);                                         \
                CDEBUG(D_MALLOC, "alloc_pages '" #ptr "': %d page(s) / "      \
                       LPU64" bytes at %p.\n",                                \
                       (int)(1 << (order)),                                   \
                       (__u64)((1 << (order)) << CFS_PAGE_SHIFT), ptr);       \
        }                                                                     \
} while (0)

#define OBD_PAGE_ALLOC(ptr, gfp_mask)                                         \
        OBD_PAGES_ALLOC(ptr, 0, gfp_mask)

#define OBD_PAGES_FREE(ptr, order)                                            \
do {                                                                          \
        LASSERT(ptr);                                                         \
        obd_pages_sub(order);                                                 \
        CDEBUG(D_MALLOC, "free_pages '" #ptr "': %d page(s) / "LPU64" bytes " \
               "at %p.\n",                                                    \
               (int)(1 << (order)), (__u64)((1 << (order)) << CFS_PAGE_SHIFT),\
               ptr);                                                          \
        __cfs_free_pages(ptr, order);                                         \
        (ptr) = (void *)0xdeadbeef;                                           \
} while (0)

#define OBD_PAGE_FREE(ptr) OBD_PAGES_FREE(ptr, 0)

#endif
