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

#ifdef __KERNEL__
#include <linux/autoconf.h>
#include <linux/proc_fs.h>
#endif

#ifndef LPROCFS
#ifdef  CONFIG_PROC_FS  /* Ensure that /proc is configured */
#define LPROCFS
#endif
#endif

struct lprocfs_vars {
        const char   *name;
        read_proc_t *read_fptr;
        write_proc_t *write_fptr;
        void *data;
};

struct lprocfs_static_vars {
        struct lprocfs_vars *module_vars;
        struct lprocfs_vars *obd_vars;
};

/* Lprocfs counters are can be configured using the enum bit masks below.
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
        LPROCFS_CNTR_EXTERNALLOCK = 1,
        LPROCFS_CNTR_AVGMINMAX    = 2,
        LPROCFS_CNTR_STDDEV       = 4,
};

struct lprocfs_counter {
        union {
                spinlock_t    internal; /* when there is no external lock */
                spinlock_t   *external; /* external lock, when available */
        } l;
        unsigned int  config;
        __u64         count;
        __u64         sum;
        __u64         min;
        __u64         max;
        __u64         sumsquare;
        const char    *name;   /* must be static */
        const char    *units;  /* must be static */
};


struct lprocfs_counters {
        unsigned int           num;
        unsigned int           padto8byteboundary;
        struct lprocfs_counter cntr[0];
};


/* class_obd.c */
extern struct proc_dir_entry *proc_lustre_root;
struct obd_device;

#ifdef LPROCFS

/* Two optimized LPROCFS counter increment macros are provided:
 *     LPROCFS_COUNTER_INCR(cntr, value) - use for multi-valued counters
 *     LPROCFS_COUNTER_INCBY1(cntr) - optimized for by-one counters
 * Counter data layout allows config flag, counter lock and the
 * count itself to reside within a single cache line.
 */

#define LPROCFS_COUNTER_INCR(cntr, value)                         \
        do {                                                      \
               struct lprocfs_counter *c = (cntr);                \
               LASSERT(c != NULL);                                \
               if (!(c->config & LPROCFS_CNTR_EXTERNALLOCK))      \
                     spin_lock(&c->l.internal);                   \
               c->count++;                                        \
               if (c->config & LPROCFS_CNTR_AVGMINMAX) {          \
                      __u64 val = (__u64) (value);                \
                      c->sum += val;                              \
                      if (c->config & LPROCFS_CNTR_STDDEV)        \
                         c->sumsquare += (val*val);               \
                      if (val < c->min) c->min = val;             \
                      if (val > c->max) c->max = val;             \
               }                                                  \
               if (!(c->config & LPROCFS_CNTR_EXTERNALLOCK))      \
                      spin_unlock(&c->l.internal);                \
      } while (0)

#define LPROCFS_COUNTER_INCBY1(cntr)                              \
        do {                                                      \
               struct lprocfs_counter *c = (cntr);                \
               LASSERT(c != NULL);                                \
               if (!(c->config & LPROCFS_CNTR_EXTERNALLOCK))      \
                     spin_lock(&c->l.internal);                   \
               c->count++;                                        \
               if (!(c->config & LPROCFS_CNTR_EXTERNALLOCK))      \
                      spin_unlock(&c->l.internal);                \
      } while (0)

#define LPROCFS_COUNTER_INIT(cntr, conf, lck, nam, un)                 \
        do {                                                           \
               struct lprocfs_counter *c = (cntr);                     \
               LASSERT(c != NULL);                                     \
               memset(c, 0, sizeof(struct lprocfs_counter));           \
               if (conf & LPROCFS_CNTR_EXTERNALLOCK) c->l.external = (lck); \
               else spin_lock_init(&c->l.internal);                    \
               c->config = conf;                                       \
               c->min = (~(__u64)0);                                   \
               c->name = (nam);                                        \
               c->units = (un);                                        \
        } while (0)

extern struct lprocfs_counters* lprocfs_alloc_counters(unsigned int num);
extern void lprocfs_free_counters(struct lprocfs_counters* cntrs);
extern int lprocfs_alloc_obd_counters(struct obd_device *obddev,
                                      unsigned int num_private_counters);
extern void lprocfs_free_obd_counters(struct obd_device *obddev);
extern int lprocfs_register_counters(struct proc_dir_entry *root,
                                     const char* name,
                                     struct lprocfs_counters *cntrs);

#define LPROCFS_INIT_MULTI_VARS(array, size)                              \
void lprocfs_init_multi_vars(unsigned int idx,                            \
                             struct lprocfs_static_vars *x)               \
{                                                                         \
   struct lprocfs_static_vars *glob = (struct lprocfs_static_vars*)array; \
   LASSERT(glob != 0);                                                    \
   LASSERT(idx < (unsigned int)(size));                                   \
   x->module_vars = glob[idx].module_vars;                                \
   x->obd_vars = glob[idx].obd_vars;                                      \
}                                                                         \

#define LPROCFS_INIT_VARS(vclass, vinstance)           \
void lprocfs_init_vars(struct lprocfs_static_vars *x)  \
{                                                      \
        x->module_vars = vclass;                       \
        x->obd_vars = vinstance;                       \
}                                                      \

extern void lprocfs_init_vars(struct lprocfs_static_vars *var);
extern void lprocfs_init_multi_vars(unsigned int idx,
                                    struct lprocfs_static_vars *var);
/* lprocfs_status.c */
extern int lprocfs_add_vars(struct proc_dir_entry *root,
                            struct lprocfs_vars *var,
                            void *data);

extern struct proc_dir_entry *lprocfs_register(const char *name,
                                               struct proc_dir_entry *parent,
                                               struct lprocfs_vars *list,
                                               void *data);

extern void lprocfs_remove(struct proc_dir_entry *root);

extern int lprocfs_obd_attach(struct obd_device *dev, struct lprocfs_vars *list);
extern int lprocfs_obd_detach(struct obd_device *dev);

/* Generic callbacks */

extern int lprocfs_rd_u64(char *page, char **start, off_t off,
                          int count, int *eof, void *data);
extern int lprocfs_rd_uuid(char *page, char **start, off_t off,
                           int count, int *eof, void *data);
extern int lprocfs_rd_name(char *page, char **start, off_t off,
                           int count, int *eof, void *data);
extern int lprocfs_rd_server_uuid(char *page, char **start, off_t off,
                                  int count, int *eof, void *data);
extern int lprocfs_rd_conn_uuid(char *page, char **start, off_t off,
                                int count, int *eof, void *data);
extern int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                              int count, int *eof, void *data);

/* Statfs helpers */
struct statfs;
extern int lprocfs_rd_blksize(char *page, char **start, off_t off,
                              int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_kbytestotal(char *page, char **start, off_t off,
                                  int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_kbytesfree(char *page, char **start, off_t off,
                                 int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_filestotal(char *page, char **start, off_t off,
                                 int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_filesfree(char *page, char **start, off_t off,
                                int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_filegroups(char *page, char **start, off_t off,
                                 int count, int *eof, struct statfs *sfs);

/* lprocfs_status.c: counter read/write functions */
struct file;
extern int lprocfs_counter_read(char *page, char **start, off_t off,
                                int count, int *eof, void *data);
extern int lprocfs_counter_write(struct file *file, const char *buffer,
                                 unsigned long count, void *data);

#define DEFINE_LPROCFS_STATFS_FCT(fct_name, get_statfs_fct)               \
int fct_name(char *page, char **start, off_t off,                         \
             int count, int *eof, void *data)                             \
{                                                                         \
        struct statfs sfs;                                                \
        int rc = get_statfs_fct((struct obd_device*)data, &sfs);          \
        return (rc == 0 ?                                                 \
                lprocfs_##fct_name (page, start, off, count, eof, &sfs) : \
                rc);                                                      \
}

#else
/* LPROCFS is not defined */
#define LPROCFS_COUNTER_INCR(cntr, value)
#define LPROCFS_COUNTER_INCBY1(cntr)
#define LPROCFS_COUNTER_INIT(cntr, conf, lock, nam, un)

static inline struct lprocfs_counters* lprocfs_alloc_counters(unsigned int num)
{ return NULL; }
static inline void lprocfs_free_counters(struct lprocfs_counters* cntrs)
{ return; }

static inline int lprocfs_register_counters(struct proc_dir_entry *root,
                                            const char* name,
                                            struct lprocfs_counters *cntrs)
{ return 0; }
static inline int lprocfs_alloc_obd_counters(struct obd_device *obddev,
                                             unsigned int num_private_counters)
{ return 0; }
static inline void lprocfs_free_obd_counters(struct obd_device *obddev)
{ return; }

static inline struct proc_dir_entry *
lprocfs_register(const char *name, struct proc_dir_entry *parent,
                 struct lprocfs_vars *list, void *data) { return NULL; }
#define LPROCFS_INIT_MULTI_VARS(array, size)
static inline void lprocfs_init_multi_vars(unsigned int idx,
                                           struct lprocfs_static_vars *x) { return; }
#define LPROCFS_INIT_VARS(vclass, vinstance)
static inline void lprocfs_init_vars(struct lprocfs_static_vars *x) { return; }
static inline int lprocfs_add_vars(struct proc_dir_entry *root,
                                   struct lprocfs_vars *var,
                                   void *data) { return 0; }
static inline void lprocfs_remove(struct proc_dir_entry *root) {};
struct obd_device;
static inline int lprocfs_obd_attach(struct obd_device *dev,
                                     struct lprocfs_vars *list) { return 0; }
static inline int lprocfs_obd_detach(struct obd_device *dev)  { return 0; }
static inline int lprocfs_rd_u64(char *page, char **start, off_t off,
                                 int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_uuid(char *page, char **start, off_t off,
                                  int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_name(char *page, char **start, off_t off,
                                  int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_server_uuid(char *page, char **start, off_t off,
                                         int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_conn_uuid(char *page, char **start, off_t off,
                                       int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                                     int count, int *eof, void *data) { return 0; }

/* Statfs helpers */
struct statfs;
static inline
int lprocfs_rd_blksize(char *page, char **start, off_t off,
                       int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_kbytestotal(char *page, char **start, off_t off,
                           int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_kbytesfree(char *page, char **start, off_t off,
                          int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_filestotal(char *page, char **start, off_t off,
                          int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_filesfree(char *page, char **start, off_t off,
                         int count, int *eof, struct statfs *sfs)  { return 0; }
static inline
int lprocfs_rd_filegroups(char *page, char **start, off_t off,
                          int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_counter_read(char *page, char **start, off_t off,
                         int count, int *eof, void *data) { return 0; }
struct file;
static inline
int lprocfs_counter_write(struct file *file, const char *buffer,
                          unsigned long count, void *data) { return 0; }

#define DEFINE_LPROCFS_STATFS_FCT(fct_name, get_statfs_fct)  \
int fct_name(char *page, char **start, off_t off,            \
             int count, int *eof, void *data) { *eof = 1; return 0; }

#endif /* LPROCFS */

#endif /* LPROCFS_SNMP_H */
