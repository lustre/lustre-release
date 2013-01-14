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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lprocfs_status.h
 *
 * Top level header file for LProc SNMP
 *
 * Author: Hariharan Thantry thantry@users.sourceforge.net
 */
#ifndef _LPROCFS_SNMP_H
#define _LPROCFS_SNMP_H

#if defined(__linux__)
#include <linux/lprocfs_status.h>
#elif defined(__APPLE__)
#include <darwin/lprocfs_status.h>
#elif defined(__WINNT__)
#include <winnt/lprocfs_status.h>
#else
#error Unsupported operating system.
#endif
#include <lustre/lustre_idl.h>

#undef LPROCFS
#if (defined(__KERNEL__) && defined(CONFIG_PROC_FS))
# define LPROCFS
#endif

struct lprocfs_vars {
        const char   *name;
        cfs_read_proc_t *read_fptr;
        cfs_write_proc_t *write_fptr;
        void *data;
        struct file_operations *fops;
        /**
         * /proc file mode.
         */
        mode_t proc_mode;
};

struct lprocfs_static_vars {
        struct lprocfs_vars *module_vars;
        struct lprocfs_vars *obd_vars;
};

/* if we find more consumers this could be generalized */
#define OBD_HIST_MAX 32
struct obd_histogram {
        spinlock_t      oh_lock;
        unsigned long   oh_buckets[OBD_HIST_MAX];
};

enum {
        BRW_R_PAGES = 0,
        BRW_W_PAGES,
        BRW_R_RPC_HIST,
        BRW_W_RPC_HIST,
        BRW_R_IO_TIME,
        BRW_W_IO_TIME,
        BRW_R_DISCONT_PAGES,
        BRW_W_DISCONT_PAGES,
        BRW_R_DISCONT_BLOCKS,
        BRW_W_DISCONT_BLOCKS,
        BRW_R_DISK_IOSIZE,
        BRW_W_DISK_IOSIZE,
        BRW_R_DIO_FRAGS,
        BRW_W_DIO_FRAGS,
        BRW_LAST,
};

struct brw_stats {
        struct obd_histogram hist[BRW_LAST];
};


/* An lprocfs counter can be configured using the enum bit masks below.
 *
 * LPROCFS_CNTR_EXTERNALLOCK indicates that an external lock already
 * protects this counter from concurrent updates. If not specified,
 * lprocfs an internal per-counter lock variable. External locks are
 * not used to protect counter increments, but are used to protect
 * counter readout and resets.
 *
 * LPROCFS_CNTR_AVGMINMAX indicates a multi-valued counter samples,
 * (i.e. counter can be incremented by more than "1"). When specified,
 * the counter maintains min, max and sum in addition to a simple
 * invocation count. This allows averages to be be computed.
 * If not specified, the counter is an increment-by-1 counter.
 * min, max, sum, etc. are not maintained.
 *
 * LPROCFS_CNTR_STDDEV indicates that the counter should track sum of
 * squares (for multi-valued counter samples only). This allows
 * external computation of standard deviation, but involves a 64-bit
 * multiply per counter increment.
 */

enum {
        LPROCFS_CNTR_EXTERNALLOCK = 0x0001,
        LPROCFS_CNTR_AVGMINMAX    = 0x0002,
        LPROCFS_CNTR_STDDEV       = 0x0004,

        /* counter data type */
        LPROCFS_TYPE_REGS         = 0x0100,
        LPROCFS_TYPE_BYTES        = 0x0200,
        LPROCFS_TYPE_PAGES        = 0x0400,
        LPROCFS_TYPE_CYCLE        = 0x0800,
};

struct lprocfs_atomic {
        atomic_t               la_entry;
        atomic_t               la_exit;
};

#define LC_MIN_INIT ((~(__u64)0) >> 1)

struct lprocfs_counter {
        struct lprocfs_atomic  lc_cntl;  /* may need to move to per set */
        unsigned int           lc_config;
        __s64                  lc_count;
        __s64                  lc_sum;
        __s64                  lc_sum_irq;
        __s64                  lc_min;
        __s64                  lc_max;
        __s64                  lc_sumsquare;
        const char            *lc_name;   /* must be static */
        const char            *lc_units;  /* must be static */
};

struct lprocfs_percpu {
#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
        __s64                  pad;
#endif
        struct lprocfs_counter lp_cntr[0];
};

#define LPROCFS_GET_NUM_CPU 0x0001
#define LPROCFS_GET_SMP_ID  0x0002

enum lprocfs_stats_flags {
        LPROCFS_STATS_FLAG_NONE     = 0x0000, /* per cpu counter */
        LPROCFS_STATS_FLAG_NOPERCPU = 0x0001, /* stats have no percpu
                                               * area and need locking */
        LPROCFS_STATS_GET_SMP_ID    = 0x0002, /* just record locking with
                                               * LPROCFS_GET_SMP_ID flag */
};

enum lprocfs_fields_flags {
        LPROCFS_FIELDS_FLAGS_CONFIG = 0x0001,
        LPROCFS_FIELDS_FLAGS_SUM    = 0x0002,
        LPROCFS_FIELDS_FLAGS_MIN    = 0x0003,
        LPROCFS_FIELDS_FLAGS_MAX    = 0x0004,
        LPROCFS_FIELDS_FLAGS_AVG    = 0x0005,
        LPROCFS_FIELDS_FLAGS_SUMSQUARE = 0x0006,
        LPROCFS_FIELDS_FLAGS_COUNT  = 0x0007,
};

struct lprocfs_stats {
        unsigned int           ls_num;     /* # of counters */
        int                    ls_flags; /* See LPROCFS_STATS_FLAG_* */
        spinlock_t             ls_lock;  /* Lock used only when there are
                                          * no percpu stats areas */
        struct lprocfs_percpu *ls_percpu[0];
};

static inline int opcode_offset(__u32 opc) {
        if (opc < OST_LAST_OPC) {
                 /* OST opcode */
                return (opc - OST_FIRST_OPC);
        } else if (opc < MDS_LAST_OPC) {
                /* MDS opcode */
                return (opc - MDS_FIRST_OPC +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < LDLM_LAST_OPC) {
                /* LDLM Opcode */
                return (opc - LDLM_FIRST_OPC +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < MGS_LAST_OPC) {
                /* MGS Opcode */
                return (opc - MGS_FIRST_OPC +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < OBD_LAST_OPC) {
                /* OBD Ping */
                return (opc - OBD_FIRST_OPC +
                        (MGS_LAST_OPC - MGS_FIRST_OPC) +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < LLOG_LAST_OPC) {
                /* LLOG Opcode */
                return (opc - LLOG_FIRST_OPC +
                        (OBD_LAST_OPC - OBD_FIRST_OPC) +
                        (MGS_LAST_OPC - MGS_FIRST_OPC) +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
       } else if (opc < QUOTA_LAST_OPC) {
                /* LQUOTA Opcode */
                return (opc - QUOTA_FIRST_OPC +
                        (LLOG_LAST_OPC - LLOG_FIRST_OPC) +
                        (OBD_LAST_OPC - OBD_FIRST_OPC) +
                        (MGS_LAST_OPC - MGS_FIRST_OPC) +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < SEQ_LAST_OPC) {
                /* SEQ opcode */
                return (opc - SEQ_FIRST_OPC +
                        (QUOTA_LAST_OPC - QUOTA_FIRST_OPC) +
                        (LLOG_LAST_OPC - LLOG_FIRST_OPC) +
                        (OBD_LAST_OPC - OBD_FIRST_OPC) +
                        (MGS_LAST_OPC - MGS_FIRST_OPC) +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else {
                /* Unknown Opcode */
                return -1;
        }
}

#define LUSTRE_MAX_OPCODES ((OST_LAST_OPC - OST_FIRST_OPC)     + \
                            (MDS_LAST_OPC - MDS_FIRST_OPC)     + \
                            (LDLM_LAST_OPC - LDLM_FIRST_OPC)   + \
                            (MGS_LAST_OPC - MGS_FIRST_OPC)     + \
                            (OBD_LAST_OPC - OBD_FIRST_OPC)     + \
                            (LLOG_LAST_OPC - LLOG_FIRST_OPC)   + \
                            (QUOTA_LAST_OPC - QUOTA_FIRST_OPC) + \
                            (SEQ_LAST_OPC - SEQ_FIRST_OPC))

#define EXTRA_MAX_OPCODES ((PTLRPC_LAST_CNTR - PTLRPC_FIRST_CNTR)  + \
                           (EXTRA_LAST_OPC - EXTRA_FIRST_OPC))

enum {
        PTLRPC_REQWAIT_CNTR = 0,
        PTLRPC_REQQDEPTH_CNTR,
        PTLRPC_REQACTIVE_CNTR,
        PTLRPC_TIMEOUT,
        PTLRPC_REQBUF_AVAIL_CNTR,
        PTLRPC_LAST_CNTR
};

#define PTLRPC_FIRST_CNTR PTLRPC_REQWAIT_CNTR

enum {
        LDLM_GLIMPSE_ENQUEUE = 0,
        LDLM_PLAIN_ENQUEUE,
        LDLM_EXTENT_ENQUEUE,
        LDLM_FLOCK_ENQUEUE,
        LDLM_IBITS_ENQUEUE,
        MDS_REINT_SETATTR,
        MDS_REINT_CREATE,
        MDS_REINT_LINK,
        MDS_REINT_UNLINK,
        MDS_REINT_RENAME,
        MDS_REINT_OPEN,
        BRW_READ_BYTES,
        BRW_WRITE_BYTES,
        EXTRA_LAST_OPC
};

#define EXTRA_FIRST_OPC LDLM_GLIMPSE_ENQUEUE
/* class_obd.c */
extern cfs_proc_dir_entry_t *proc_lustre_root;

struct obd_device;
struct file;
struct obd_histogram;

/* Days / hours / mins / seconds format */
struct dhms {
        int d,h,m,s;
};
static inline void s2dhms(struct dhms *ts, time_t secs)
{
        ts->d = secs / 86400;
        secs = secs % 86400;
        ts->h = secs / 3600;
        secs = secs % 3600;
        ts->m = secs / 60;
        ts->s = secs % 60;
}
#define DHMS_FMT "%dd%dh%02dm%02ds"
#define DHMS_VARS(x) (x)->d, (x)->h, (x)->m, (x)->s


#ifdef LPROCFS

static inline int lprocfs_stats_lock(struct lprocfs_stats *stats, int type)
{
        int rc = 0;

        if (stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU) {
                if (type & LPROCFS_GET_NUM_CPU)
                        rc = 1;
                if (type & LPROCFS_GET_SMP_ID)
                        rc = 0;
                spin_lock(&stats->ls_lock);
        } else {
                if (type & LPROCFS_GET_NUM_CPU)
                        rc = num_possible_cpus();
                if (type & LPROCFS_GET_SMP_ID) {
			stats->ls_flags |= LPROCFS_STATS_GET_SMP_ID;
                        rc = cfs_get_cpu();
		}
        }
        return rc;
}

static inline void lprocfs_stats_unlock(struct lprocfs_stats *stats)
{
        if (stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU)
                spin_unlock(&stats->ls_lock);
	else if (stats->ls_flags & LPROCFS_STATS_GET_SMP_ID)
		cfs_put_cpu();
}

/* Two optimized LPROCFS counter increment functions are provided:
 *     lprocfs_counter_incr(cntr, value) - optimized for by-one counters
 *     lprocfs_counter_add(cntr) - use for multi-valued counters
 * Counter data layout allows config flag, counter lock and the
 * count itself to reside within a single cache line.
 */

extern void lprocfs_counter_add(struct lprocfs_stats *stats, int idx,
                                long amount);
extern void lprocfs_counter_sub(struct lprocfs_stats *stats, int idx,
                                long amount);

#define lprocfs_counter_incr(stats, idx) \
        lprocfs_counter_add(stats, idx, 1)
#define lprocfs_counter_decr(stats, idx) \
        lprocfs_counter_sub(stats, idx, 1)

extern __s64 lprocfs_read_helper(struct lprocfs_counter *lc,
                                 enum lprocfs_fields_flags field);

static inline __u64 lprocfs_stats_collector(struct lprocfs_stats *stats,
                                            int idx,
                                            enum lprocfs_fields_flags field)
{
        __u64 ret = 0;
        int i;

        LASSERT(stats != NULL);
        for (i = 0; i < num_possible_cpus(); i++)
                ret += lprocfs_read_helper(&(stats->ls_percpu[i]->lp_cntr[idx]),
                                           field);
        return ret;
}

extern struct lprocfs_stats *lprocfs_alloc_stats(unsigned int num,
                                                 enum lprocfs_stats_flags flags);
extern void lprocfs_clear_stats(struct lprocfs_stats *stats);
extern void lprocfs_free_stats(struct lprocfs_stats **stats);
extern void lprocfs_init_ops_stats(int num_private_stats,
                                   struct lprocfs_stats *stats);
extern void lprocfs_init_ldlm_stats(struct lprocfs_stats *ldlm_stats);
extern int lprocfs_alloc_obd_stats(struct obd_device *obddev,
                                   unsigned int num_private_stats);
extern void lprocfs_counter_init(struct lprocfs_stats *stats, int index,
                                 unsigned conf, const char *name,
                                 const char *units);
extern void lprocfs_free_obd_stats(struct obd_device *obddev);
struct obd_export;
extern int lprocfs_add_clear_entry(struct obd_device * obd,
                                   cfs_proc_dir_entry_t *entry);
extern int lprocfs_exp_setup(struct obd_export *exp,
                             lnet_nid_t *peer_nid, int *newnid);
extern int lprocfs_exp_cleanup(struct obd_export *exp);
extern cfs_proc_dir_entry_t *lprocfs_add_simple(struct proc_dir_entry *root,
                                                char *name,
                                                read_proc_t *read_proc,
                                                write_proc_t *write_proc,
                                                void *data,
                                                struct file_operations *fops);
extern int lprocfs_register_stats(cfs_proc_dir_entry_t *root, const char *name,
                                  struct lprocfs_stats *stats);

/* lprocfs_status.c */
extern int lprocfs_add_vars(cfs_proc_dir_entry_t *root,
                            struct lprocfs_vars *var,
                            void *data);

extern cfs_proc_dir_entry_t *lprocfs_register(const char *name,
                                               cfs_proc_dir_entry_t *parent,
                                               struct lprocfs_vars *list,
                                               void *data);

extern void lprocfs_remove(cfs_proc_dir_entry_t **root);

extern cfs_proc_dir_entry_t *lprocfs_srch(cfs_proc_dir_entry_t *root,
                                           const char *name);

extern int lprocfs_obd_setup(struct obd_device *obd, struct lprocfs_vars *list);
extern int lprocfs_obd_cleanup(struct obd_device *obd);
struct nid_stat;
extern void lprocfs_free_per_client_stats(struct obd_device *obd);
extern int lprocfs_nid_stats_clear_write(struct file *file, const char *buffer,
                                         unsigned long count, void *data);
extern int lprocfs_nid_stats_clear_read(char *page, char **start, off_t off,
                                        int count, int *eof,  void *data);


extern struct file_operations lprocfs_evict_client_fops;

extern int lprocfs_seq_create(cfs_proc_dir_entry_t *parent, char *name,
                              mode_t mode, struct file_operations *seq_fops,
                              void *data);
extern int lprocfs_obd_seq_create(struct obd_device *dev, char *name,
                                  mode_t mode, struct file_operations *seq_fops,
                                  void *data);

/* Generic callbacks */

extern int lprocfs_rd_u64(char *page, char **start, off_t off,
                          int count, int *eof, void *data);
extern int lprocfs_rd_atomic(char *page, char **start, off_t off,
                             int count, int *eof, void *data);
extern int lprocfs_wr_atomic(struct file *file, const char *buffer,
                             unsigned long count, void *data);
extern int lprocfs_rd_uint(char *page, char **start, off_t off,
                           int count, int *eof, void *data);
extern int lprocfs_wr_uint(struct file *file, const char *buffer,
                           unsigned long count, void *data);
extern int lprocfs_rd_uuid(char *page, char **start, off_t off,
                           int count, int *eof, void *data);
extern int lprocfs_rd_name(char *page, char **start, off_t off,
                           int count, int *eof, void *data);
extern int lprocfs_rd_fstype(char *page, char **start, off_t off,
                             int count, int *eof, void *data);
extern int lprocfs_rd_server_uuid(char *page, char **start, off_t off,
                                  int count, int *eof, void *data);
extern int lprocfs_rd_conn_uuid(char *page, char **start, off_t off,
                                int count, int *eof, void *data);
extern int lprocfs_rd_import(char *page, char **start, off_t off, int count,
                             int *eof, void *data);
extern int lprocfs_rd_state(char *page, char **start, off_t off, int count,
                            int *eof, void *data);
extern int lprocfs_rd_connect_flags(char *page, char **start, off_t off,
                                    int count, int *eof, void *data);
extern int lprocfs_rd_num_exports(char *page, char **start, off_t off,
                                  int count, int *eof, void *data);
extern int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                              int count, int *eof, void *data);
struct adaptive_timeout;
extern int lprocfs_at_hist_helper(char *page, int count, int rc,
                                  struct adaptive_timeout *at);
extern int lprocfs_rd_timeouts(char *page, char **start, off_t off,
                               int count, int *eof, void *data);
extern int lprocfs_wr_timeouts(struct file *file, const char *buffer,
                               unsigned long count, void *data);
extern int lprocfs_wr_evict_client(struct file *file, const char *buffer,
                                   unsigned long count, void *data);
extern int lprocfs_wr_ping(struct file *file, const char *buffer,
                           unsigned long count, void *data);

/* Statfs helpers */
extern int lprocfs_rd_blksize(char *page, char **start, off_t off,
                              int count, int *eof, void *data);
extern int lprocfs_rd_kbytestotal(char *page, char **start, off_t off,
                                  int count, int *eof, void *data);
extern int lprocfs_rd_kbytesfree(char *page, char **start, off_t off,
                                 int count, int *eof, void *data);
extern int lprocfs_rd_kbytesavail(char *page, char **start, off_t off,
                                 int count, int *eof, void *data);
extern int lprocfs_rd_filestotal(char *page, char **start, off_t off,
                                 int count, int *eof, void *data);
extern int lprocfs_rd_filesfree(char *page, char **start, off_t off,
                                int count, int *eof, void *data);
extern int lprocfs_rd_filegroups(char *page, char **start, off_t off,
                                 int count, int *eof, void *data);

extern int lprocfs_write_helper(const char *buffer, unsigned long count,
                                int *val);
extern int lprocfs_write_frac_helper(const char *buffer, unsigned long count,
                                     int *val, int mult);
extern int lprocfs_read_frac_helper(char *buffer, unsigned long count,
                                    long val, int mult);
extern int lprocfs_write_u64_helper(const char *buffer, unsigned long count,
                                    __u64 *val);
extern int lprocfs_write_frac_u64_helper(const char *buffer, unsigned long count,
                                         __u64 *val, int mult);
void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value);
void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value);
void lprocfs_oh_clear(struct obd_histogram *oh);
unsigned long lprocfs_oh_sum(struct obd_histogram *oh);

void lprocfs_stats_collect(struct lprocfs_stats *stats, int idx,
                           struct lprocfs_counter *cnt);


/* lprocfs_status.c: recovery status */
int lprocfs_obd_rd_recovery_status(char *page, char **start, off_t off,
                                   int count, int *eof, void *data);

/* lprocfs_statuc.c: hash statistics */
int lprocfs_obd_rd_hash(char *page, char **start, off_t off,
                        int count, int *eof, void *data);

extern int lprocfs_seq_release(struct inode *, struct file *);

/* in lprocfs_stat.c, to protect the private data for proc entries */
extern struct rw_semaphore _lprocfs_lock;

/* to begin from 2.6.23, Linux defines self file_operations (proc_reg_file_ops)
 * in procfs, the proc file_operation defined by Lustre (lprocfs_generic_fops)
 * will be wrapped into the new defined proc_reg_file_ops, which instroduces
 * user count in proc_dir_entrey(pde_users) to protect the proc entry from
 * being deleted. then the protection lock (_lprocfs_lock) defined by Lustre
 * isn't necessary anymore for lprocfs_generic_fops(e.g. lprocfs_fops_read).
 * see bug19706 for detailed information.
 */
#ifndef HAVE_PROCFS_USERS

#define LPROCFS_ENTRY()           do {  \
        down_read(&_lprocfs_lock);      \
} while(0)
#define LPROCFS_EXIT()            do {  \
        up_read(&_lprocfs_lock);        \
} while(0)

#else

#define LPROCFS_ENTRY()
#define LPROCFS_EXIT()
#endif

#ifdef HAVE_PROCFS_DELETED

#ifdef HAVE_PROCFS_USERS
#error proc_dir_entry->deleted is conflicted with proc_dir_entry->pde_users
#endif

#define LPROCFS_ENTRY_AND_CHECK(dp) do {        \
        typecheck(struct proc_dir_entry *, dp); \
        LPROCFS_ENTRY();                        \
        if ((dp)->deleted) {                    \
                LPROCFS_EXIT();                 \
                return -ENODEV;                 \
        }                                       \
} while(0)
#define LPROCFS_CHECK_DELETED(dp) ((dp)->deleted)

#elif defined HAVE_PROCFS_USERS

#define LPROCFS_CHECK_DELETED(dp) ({            \
        int deleted = 0;                        \
        spin_lock(&(dp)->pde_unload_lock);      \
        if (dp->proc_fops == NULL)              \
                deleted = 1;                    \
        spin_unlock(&(dp)->pde_unload_lock);    \
        deleted;                                \
})

#define LPROCFS_ENTRY_AND_CHECK(dp) do {        \
        if (LPROCFS_CHECK_DELETED(dp))          \
                return -ENODEV;                 \
} while(0)

#else

#define LPROCFS_ENTRY_AND_CHECK(dp) \
        LPROCFS_ENTRY();
#define LPROCFS_CHECK_DELETED(dp) (0)
#endif

#define LPROCFS_SRCH_ENTRY()      do {  \
        down_read(&_lprocfs_lock);      \
} while(0)

#define LPROCFS_SRCH_EXIT()       do {  \
        up_read(&_lprocfs_lock);        \
} while(0)

#define LPROCFS_WRITE_ENTRY()     do {  \
        down_write(&_lprocfs_lock);     \
} while(0)
#define LPROCFS_WRITE_EXIT()      do {  \
        up_write(&_lprocfs_lock);       \
} while(0)


/* You must use these macros when you want to refer to
 * the import in a client obd_device for a lprocfs entry */
#define LPROCFS_CLIMP_CHECK(obd) do {           \
        typecheck(struct obd_device *, obd);    \
        down_read(&(obd)->u.cli.cl_sem);        \
        if ((obd)->u.cli.cl_import == NULL) {   \
             up_read(&(obd)->u.cli.cl_sem);     \
             return -ENODEV;                    \
        }                                       \
} while(0)
#define LPROCFS_CLIMP_EXIT(obd)                 \
        up_read(&(obd)->u.cli.cl_sem);


/* write the name##_seq_show function, call LPROC_SEQ_FOPS_RO for read-only
  proc entries; otherwise, you will define name##_seq_write function also for
  a read-write proc entry, and then call LPROC_SEQ_SEQ instead. Finally,
  call lprocfs_obd_seq_create(obd, filename, 0444, &name#_fops, data); */
#define __LPROC_SEQ_FOPS(name, custom_seq_write)                           \
static int name##_seq_open(struct inode *inode, struct file *file) {       \
        struct proc_dir_entry *dp = PDE(inode);                            \
        int rc;                                                            \
        LPROCFS_ENTRY_AND_CHECK(dp);                                       \
        rc = single_open(file, name##_seq_show, dp->data);                 \
        if (rc) {                                                          \
                LPROCFS_EXIT();                                            \
                return rc;                                                 \
        }                                                                  \
        return 0;                                                          \
}                                                                          \
struct file_operations name##_fops = {                                     \
        .owner   = THIS_MODULE,                                            \
        .open    = name##_seq_open,                                        \
        .read    = seq_read,                                               \
        .write   = custom_seq_write,                                       \
        .llseek  = seq_lseek,                                              \
        .release = lprocfs_seq_release,                                    \
}

#define LPROC_SEQ_FOPS_RO(name)         __LPROC_SEQ_FOPS(name, NULL)
#define LPROC_SEQ_FOPS(name)            __LPROC_SEQ_FOPS(name, name##_seq_write)

/* lproc_ptlrpc.c */
struct ptlrpc_request;
extern void target_print_req(void *seq_file, struct ptlrpc_request *req);

int lprocfs_obd_rd_recovery_time_soft(char *page, char **start, off_t off,
                                      int count, int *eof, void *data);
int lprocfs_obd_wr_recovery_time_soft(struct file *file, const char *buffer,
                                      unsigned long count, void *data);
int lprocfs_obd_rd_recovery_time_hard(char *page, char **start, off_t off,
                                      int count, int *eof, void *data);
int lprocfs_obd_wr_recovery_time_hard(struct file *file, const char *buffer,
                                      unsigned long count, void *data);

#ifdef HAVE_DELAYED_RECOVERY
int lprocfs_obd_rd_stale_export_age(char *page, char **start, off_t off,
                                    int count, int *eof, void *data);
int lprocfs_obd_wr_stale_export_age(struct file *file, const char *buffer,
                                    unsigned long count, void *data);
int lprocfs_obd_attach_stale_exports(struct obd_device *dev);
int lprocfs_obd_wr_flush_stale_exports(struct file *file, const char *buffer,
                                       unsigned long count, void *data);
#endif
/* all quota proc functions */
extern int lprocfs_quota_rd_bunit(char *page, char **start, off_t off, int count,
                                  int *eof, void *data);
extern int lprocfs_quota_wr_bunit(struct file *file, const char *buffer,
                                  unsigned long count, void *data);
extern int lprocfs_quota_rd_btune(char *page, char **start, off_t off, int count,
                                  int *eof, void *data);
extern int lprocfs_quota_wr_btune(struct file *file, const char *buffer,
                                  unsigned long count, void *data);
extern int lprocfs_quota_rd_iunit(char *page, char **start, off_t off, int count,
                                  int *eof, void *data);
extern int lprocfs_quota_wr_iunit(struct file *file, const char *buffer,
                                  unsigned long count, void *data);
extern int lprocfs_quota_rd_itune(char *page, char **start, off_t off, int count,
                                  int *eof, void *data);
extern int lprocfs_quota_wr_itune(struct file *file, const char *buffer,
                                  unsigned long count, void *data);
extern int lprocfs_quota_rd_type(char *page, char **start, off_t off, int count,
                                 int *eof, void *data);
extern int lprocfs_quota_wr_type(struct file *file, const char *buffer,
                                 unsigned long count, void *data);
extern int lprocfs_quota_rd_switch_seconds(char *page, char **start, off_t off,
                                           int count, int *eof, void *data);
extern int lprocfs_quota_wr_switch_seconds(struct file *file, const char *buffer,
                                           unsigned long count, void *data);
extern int lprocfs_quota_rd_sync_blk(char *page, char **start, off_t off,
                                     int count, int *eof, void *data);
extern int lprocfs_quota_wr_sync_blk(struct file *file, const char *buffer,
                                     unsigned long count, void *data);
extern int lprocfs_quota_rd_switch_qs(char *page, char **start, off_t off,
                                      int count, int *eof, void *data);
extern int lprocfs_quota_wr_switch_qs(struct file *file, const char *buffer,
                                      unsigned long count, void *data);
extern int lprocfs_quota_rd_boundary_factor(char *page, char **start, off_t off,
                                            int count, int *eof, void *data);
extern int lprocfs_quota_wr_boundary_factor(struct file *file, const char *buffer,
                                            unsigned long count, void *data);
extern int lprocfs_quota_rd_least_bunit(char *page, char **start, off_t off,
                                        int count, int *eof, void *data);
extern int lprocfs_quota_wr_least_bunit(struct file *file, const char *buffer,
                                        unsigned long count, void *data);
extern int lprocfs_quota_rd_least_iunit(char *page, char **start, off_t off,
                                        int count, int *eof, void *data);
extern int lprocfs_quota_wr_least_iunit(struct file *file, const char *buffer,
                                        unsigned long count, void *data);
extern int lprocfs_quota_rd_qs_factor(char *page, char **start, off_t off,
                                      int count, int *eof, void *data);
extern int lprocfs_quota_wr_qs_factor(struct file *file, const char *buffer,
                                      unsigned long count, void *data);

#else
/* LPROCFS is not defined */
static inline void lprocfs_counter_add(struct lprocfs_stats *stats,
                                       int index, long amount) { return; }
static inline void lprocfs_counter_incr(struct lprocfs_stats *stats,
                                        int index) { return; }
static inline void lprocfs_counter_sub(struct lprocfs_stats *stats,
                                       int index, long amount) { return; }
static inline void lprocfs_counter_init(struct lprocfs_stats *stats,
                                        int index, unsigned conf,
                                        const char *name, const char *units)
{ return; }

static inline __u64 lc_read_helper(struct lprocfs_counter *lc,
                                   enum lprocfs_fields_flags field)
{ return 0; }

static inline struct lprocfs_stats* lprocfs_alloc_stats(unsigned int num,
                                                        enum lprocfs_stats_flags flags)
{ return NULL; }
static inline void lprocfs_clear_stats(struct lprocfs_stats *stats)
{ return; }
static inline void lprocfs_free_stats(struct lprocfs_stats **stats)
{ return; }
static inline int lprocfs_register_stats(cfs_proc_dir_entry_t *root,
                                            const char *name,
                                            struct lprocfs_stats *stats)
{ return 0; }
static inline void lprocfs_init_ops_stats(int num_private_stats,
                                          struct lprocfs_stats *stats)
{ return; }
static inline void lprocfs_init_ldlm_stats(struct lprocfs_stats *ldlm_stats)
{ return; }
static inline int lprocfs_alloc_obd_stats(struct obd_device *obddev,
                                          unsigned int num_private_stats)
{ return 0; }
static inline void lprocfs_free_obd_stats(struct obd_device *obddev)
{ return; }

struct obd_export;
static inline int lprocfs_add_clear_entry(struct obd_export *exp)
{ return 0; }
static inline int lprocfs_exp_setup(struct obd_export *exp, lnet_nid_t *peer_nid,
                                    int *newnid)
{ return 0; }
static inline int lprocfs_exp_cleanup(struct obd_export *exp)
{ return 0; }
static inline cfs_proc_dir_entry_t *lprocfs_add_simple(struct proc_dir_entry *root,
                                                char *name,
                                                read_proc_t *read_proc,
                                                write_proc_t *write_proc,
                                                void *data,
                                                struct file_operations *fops)
{return 0; }
struct nid_stat;
static inline void lprocfs_free_per_client_stats(struct obd_device *obd)
{}
static inline
int lprocfs_nid_stats_clear_write(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{return count;}
static inline
int lprocfs_nid_stats_clear_read(char *page, char **start, off_t off,
                                 int count, int *eof,  void *data)
{return count;}


static inline cfs_proc_dir_entry_t *
lprocfs_register(const char *name, cfs_proc_dir_entry_t *parent,
                 struct lprocfs_vars *list, void *data) { return NULL; }
static inline int lprocfs_add_vars(cfs_proc_dir_entry_t *root,
                                   struct lprocfs_vars *var,
                                   void *data) { return 0; }
static inline void lprocfs_remove(cfs_proc_dir_entry_t **root) {};
static inline cfs_proc_dir_entry_t *lprocfs_srch(cfs_proc_dir_entry_t *head,
                                    const char *name) {return 0;}
static inline int lprocfs_obd_setup(struct obd_device *dev,
                                    struct lprocfs_vars *list) { return 0; }
static inline int lprocfs_obd_cleanup(struct obd_device *dev)  { return 0; }
static inline int lprocfs_rd_u64(char *page, char **start, off_t off,
                                 int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_uuid(char *page, char **start, off_t off,
                                  int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_name(char *page, char **start, off_t off,
                                  int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_server_uuid(char *page, char **start, off_t off,
                                         int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_conn_uuid(char *page, char **start, off_t off,
                                       int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_import(char *page, char **start, off_t off,
                                    int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_state(char *page, char **start, off_t off,
                                   int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_connect_flags(char *page, char **start, off_t off,
                                           int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_num_exports(char *page, char **start, off_t off,
                                         int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{ return 0; }
struct adaptive_timeout;
static inline int lprocfs_at_hist_helper(char *page, int count, int rc,
                                         struct adaptive_timeout *at)
{ return 0; }
static inline int lprocfs_rd_timeouts(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_wr_timeouts(struct file *file, const char *buffer,
                                      unsigned long count, void *data)
{ return 0; }
static inline int lprocfs_wr_evict_client(struct file *file, const char *buffer,
                                          unsigned long count, void *data)
{ return 0; }
static inline int lprocfs_wr_ping(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{ return 0; }
#ifdef HAVE_DELAYED_RECOVERY
static inline
int lprocfs_obd_rd_stale_export_age(char *page, char **start, off_t off,
                                    int count, int *eof, void *data)
{ return 0; }
static inline
int lprocfs_obd_wr_stale_export_age(struct file *file, const char *buffer,
                                    unsigned long count, void *data)
{ return 0; }
static inline
int lprocfs_obd_attach_stale_exports(struct obd_device *dev)
{ return 0; }
static inline
int lprocfs_obd_wr_flush_stale_exports(struct file *file, const char *buffer,
                                       unsigned long count, void *data)
{ return 0; }
#endif
/* Statfs helpers */
static inline
int lprocfs_rd_blksize(char *page, char **start, off_t off,
                       int count, int *eof, void *data) { return 0; }
static inline
int lprocfs_rd_kbytestotal(char *page, char **start, off_t off,
                           int count, int *eof, void *data) { return 0; }
static inline
int lprocfs_rd_kbytesfree(char *page, char **start, off_t off,
                          int count, int *eof, void *data) { return 0; }
static inline
int lprocfs_rd_kbytesavail(char *page, char **start, off_t off,
                           int count, int *eof, void *data) { return 0; }
static inline
int lprocfs_rd_filestotal(char *page, char **start, off_t off,
                          int count, int *eof, void *data) { return 0; }
static inline
int lprocfs_rd_filesfree(char *page, char **start, off_t off,
                         int count, int *eof, void *data)  { return 0; }
static inline
int lprocfs_rd_filegroups(char *page, char **start, off_t off,
                          int count, int *eof, void *data) { return 0; }
static inline
void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value) {}
static inline
void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value) {}
static inline
void lprocfs_oh_clear(struct obd_histogram *oh) {}
static inline
unsigned long lprocfs_oh_sum(struct obd_histogram *oh) { return 0; }
static inline
void lprocfs_stats_collect(struct lprocfs_stats *stats, int idx,
                           struct lprocfs_counter *cnt) {}

static inline
__u64 lprocfs_stats_collector(struct lprocfs_stats *stats, int idx,
                               enum lprocfs_fields_flags field)
{ return (__u64)0; }

#define LPROCFS_ENTRY()
#define LPROCFS_EXIT()
#define LPROCFS_ENTRY_AND_CHECK(dp)
#define LPROC_SEQ_FOPS_RO(name)
#define LPROC_SEQ_FOPS(name)

/* lproc_ptlrpc.c */
#define target_print_req NULL

#endif /* LPROCFS */

#endif /* LPROCFS_SNMP_H */
