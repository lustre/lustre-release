/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 *   Top level header file for LProc SNMP
 *   Author: Hariharan Thantry thantry@users.sourceforge.net
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

#undef LPROCFS
#if (defined(__KERNEL__) && defined(CONFIG_PROC_FS))
# define LPROCFS
#endif

struct lprocfs_vars {
        const char   *name;
        cfs_read_proc_t *read_fptr;
        cfs_write_proc_t *write_fptr;
        void *data;
};

struct lprocfs_static_vars {
        struct lprocfs_vars *module_vars;
        struct lprocfs_vars *obd_vars;
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

struct lprocfs_counter {
        struct lprocfs_atomic  lc_cntl;  /* may need to move to per set */
        unsigned int           lc_config;
        __u64                  lc_count;
        __u64                  lc_sum;
        __u64                  lc_min;
        __u64                  lc_max;
        __u64                  lc_sumsquare;
        const char            *lc_name;   /* must be static */
        const char            *lc_units;  /* must be static */
};

struct lprocfs_percpu {
        struct lprocfs_counter lp_cntr[0];
};


struct lprocfs_stats {
        unsigned int           ls_num;     /* # of counters */
        unsigned int           ls_percpu_size;
        struct lprocfs_percpu *ls_percpu[0];
};


/* class_obd.c */
extern cfs_proc_dir_entry_t *proc_lustre_root;

struct obd_device;
struct file;
struct obd_histogram;

#ifdef LPROCFS

/* Two optimized LPROCFS counter increment functions are provided:
 *     lprocfs_counter_incr(cntr, value) - optimized for by-one counters
 *     lprocfs_counter_add(cntr) - use for multi-valued counters
 * Counter data layout allows config flag, counter lock and the
 * count itself to reside within a single cache line.
 */

static inline void lprocfs_counter_add(struct lprocfs_stats *stats, int idx,
                                       long amount)
{
        struct lprocfs_counter *percpu_cntr;

        LASSERT(stats != NULL);
        percpu_cntr = &(stats->ls_percpu[smp_processor_id()]->lp_cntr[idx]);
        atomic_inc(&percpu_cntr->lc_cntl.la_entry);
        percpu_cntr->lc_count++;

        if (percpu_cntr->lc_config & LPROCFS_CNTR_AVGMINMAX) {
                percpu_cntr->lc_sum += amount;
                if (percpu_cntr->lc_config & LPROCFS_CNTR_STDDEV)
                        percpu_cntr->lc_sumsquare += (__u64)amount * amount;
                if (amount < percpu_cntr->lc_min)
                        percpu_cntr->lc_min = amount;
                if (amount > percpu_cntr->lc_max)
                        percpu_cntr->lc_max = amount;
        }
        atomic_inc(&percpu_cntr->lc_cntl.la_exit);
}

static inline void lprocfs_counter_incr(struct lprocfs_stats *stats, int idx)
{
        struct lprocfs_counter *percpu_cntr;

        LASSERT(stats != NULL);
        percpu_cntr = &(stats->ls_percpu[smp_processor_id()]->lp_cntr[idx]);
        atomic_inc(&percpu_cntr->lc_cntl.la_entry);
        percpu_cntr->lc_count++;
        atomic_inc(&percpu_cntr->lc_cntl.la_exit);
}

extern struct lprocfs_stats *lprocfs_alloc_stats(unsigned int num);
extern void lprocfs_free_stats(struct lprocfs_stats *stats);
extern int lprocfs_alloc_obd_stats(struct obd_device *obddev,
                                   unsigned int num_private_stats);
extern void lprocfs_counter_init(struct lprocfs_stats *stats, int index,
                                 unsigned conf, const char *name,
                                 const char *units);
extern void lprocfs_free_obd_stats(struct obd_device *obddev);
extern int lprocfs_register_stats(cfs_proc_dir_entry_t *root, const char *name,
                                  struct lprocfs_stats *stats);

#define LPROCFS_INIT_VARS(name, vclass, vinstance)           \
void lprocfs_##name##_init_vars(struct lprocfs_static_vars *x)  \
{                                                      \
        x->module_vars = vclass;                       \
        x->obd_vars = vinstance;                       \
}                                                      \

#define lprocfs_init_vars(NAME, VAR)     \
do {      \
        extern void lprocfs_##NAME##_init_vars(struct lprocfs_static_vars *);  \
        lprocfs_##NAME##_init_vars(VAR);                                       \
} while (0)
/* lprocfs_status.c */
extern int lprocfs_add_vars(cfs_proc_dir_entry_t *root,
                            struct lprocfs_vars *var,
                            void *data);

extern cfs_proc_dir_entry_t *lprocfs_register(const char *name,
                                               cfs_proc_dir_entry_t *parent,
                                               struct lprocfs_vars *list,
                                               void *data);

extern void lprocfs_remove(cfs_proc_dir_entry_t *root);

extern cfs_proc_dir_entry_t *lprocfs_srch(cfs_proc_dir_entry_t *root,
                                           const char *name);

extern int lprocfs_obd_setup(struct obd_device *obd, struct lprocfs_vars *list);
extern int lprocfs_obd_cleanup(struct obd_device *obd);

/* Generic callbacks */

extern int lprocfs_rd_u64(char *page, char **start, off_t off,
                          int count, int *eof, void *data);
extern int lprocfs_rd_atomic(char *page, char **start, off_t off,
                          int count, int *eof, void *data);
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
extern int lprocfs_rd_connect_flags(char *page, char **start, off_t off,
                                    int count, int *eof, void *data);
extern int lprocfs_rd_num_exports(char *page, char **start, off_t off,
                                  int count, int *eof, void *data);
extern int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                              int count, int *eof, void *data);
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
int lprocfs_obd_seq_create(struct obd_device *dev, char *name, mode_t mode,
                           struct file_operations *seq_fops, void *data);
void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value);
void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value);
void lprocfs_oh_clear(struct obd_histogram *oh);
unsigned long lprocfs_oh_sum(struct obd_histogram *oh);

/* lprocfs_status.c: counter read/write functions */
extern int lprocfs_counter_read(char *page, char **start, off_t off,
                                int count, int *eof, void *data);
extern int lprocfs_counter_write(struct file *file, const char *buffer,
                                 unsigned long count, void *data);

/* lprocfs_status.c: recovery status */
int lprocfs_obd_rd_recovery_status(char *page, char **start, off_t off,
                                   int count, int *eof, void *data);
#else
/* LPROCFS is not defined */
static inline void lprocfs_counter_add(struct lprocfs_stats *stats,
                                       int index, long amount) { return; }
static inline void lprocfs_counter_incr(struct lprocfs_stats *stats,
                                        int index) { return; }
static inline void lprocfs_counter_init(struct lprocfs_stats *stats,
                                        int index, unsigned conf,
                                        const char *name, const char *units)
{ return; }

static inline struct lprocfs_stats* lprocfs_alloc_stats(unsigned int num)
{ return NULL; }
static inline void lprocfs_free_stats(struct lprocfs_stats *stats)
{ return; }

static inline int lprocfs_register_stats(cfs_proc_dir_entry_t *root,
                                            const char *name,
                                            struct lprocfs_stats *stats)
{ return 0; }
static inline int lprocfs_alloc_obd_stats(struct obd_device *obddev,
                                             unsigned int num_private_stats)
{ return 0; }
static inline void lprocfs_free_obd_stats(struct obd_device *obddev)
{ return; }

static inline cfs_proc_dir_entry_t *
lprocfs_register(const char *name, cfs_proc_dir_entry_t *parent,
                 struct lprocfs_vars *list, void *data) { return NULL; }
#define LPROCFS_INIT_VARS(name, vclass, vinstance)
#define lprocfs_init_vars(...) do {} while (0)
static inline int lprocfs_add_vars(cfs_proc_dir_entry_t *root,
                                   struct lprocfs_vars *var,
                                   void *data) { return 0; }
static inline void lprocfs_remove(cfs_proc_dir_entry_t *root) {};
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
static inline int lprocfs_rd_connect_flags(char *page, char **start, off_t off,
                                           int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_num_exports(char *page, char **start, off_t off,
                                         int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{ return 0; }
static inline int lprocfs_wr_evict_client(struct file *file, const char *buffer,
                                          unsigned long count, void *data)
{ return 0; }
static inline int lprocfs_wr_ping(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{ return 0; }


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
int lprocfs_counter_read(char *page, char **start, off_t off,
                         int count, int *eof, void *data) { return 0; }
static inline
int lprocfs_counter_write(struct file *file, const char *buffer,
                          unsigned long count, void *data) { return 0; }
#endif /* LPROCFS */

#endif /* LPROCFS_SNMP_H */
