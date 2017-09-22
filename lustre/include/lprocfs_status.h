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
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lprocfs_status.h
 *
 * Top level header file for LProc
 *
 * Author: Hariharan Thantry thantry@users.sourceforge.net
 */
#ifndef _LPROCFS_STATUS_H
#define _LPROCFS_STATUS_H

#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>

#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>

struct lprocfs_vars {
	const char			*name;
	const struct file_operations	*fops;
	void				*data;
	/**
	 * /proc file mode.
	 */
	mode_t				 proc_mode;
};

/* if we find more consumers this could be generalized */
#define OBD_HIST_MAX 32
struct obd_histogram {
	spinlock_t	oh_lock;
	unsigned long	oh_buckets[OBD_HIST_MAX];
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

enum {
        RENAME_SAMEDIR_SIZE = 0,
        RENAME_CROSSDIR_SRC_SIZE,
        RENAME_CROSSDIR_TGT_SIZE,
        RENAME_LAST,
};

struct rename_stats {
        struct obd_histogram hist[RENAME_LAST];
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

#define LC_MIN_INIT ((~(__u64)0) >> 1)

struct lprocfs_counter_header {
	unsigned int		lc_config;
	const char		*lc_name;   /* must be static */
	const char		*lc_units;  /* must be static */
};

struct lprocfs_counter {
	__s64	lc_count;
	__s64	lc_min;
	__s64	lc_max;
	__s64	lc_sumsquare;
	/*
	 * Every counter has lc_array_sum[0], while lc_array_sum[1] is only
	 * for irq context counter, i.e. stats with
	 * LPROCFS_STATS_FLAG_IRQ_SAFE flag, its counter need
	 * lc_array_sum[1]
	 */
	__s64	lc_array_sum[1];
};
#define lc_sum		lc_array_sum[0]
#define lc_sum_irq	lc_array_sum[1]

struct lprocfs_percpu {
	struct lprocfs_counter lp_cntr[0];
};

enum lprocfs_stats_lock_ops {
	LPROCFS_GET_NUM_CPU	= 0x0001, /* number allocated per-CPU stats */
	LPROCFS_GET_SMP_ID	= 0x0002, /* current stat to be updated */
};

enum lprocfs_stats_flags {
	LPROCFS_STATS_FLAG_NONE     = 0x0000, /* per cpu counter */
	LPROCFS_STATS_FLAG_NOPERCPU = 0x0001, /* stats have no percpu
					       * area and need locking */
	LPROCFS_STATS_FLAG_IRQ_SAFE = 0x0002, /* alloc need irq safe */
};

enum lprocfs_fields_flags {
	LPROCFS_FIELDS_FLAGS_CONFIG     = 0x0001,
	LPROCFS_FIELDS_FLAGS_SUM        = 0x0002,
	LPROCFS_FIELDS_FLAGS_MIN        = 0x0003,
	LPROCFS_FIELDS_FLAGS_MAX        = 0x0004,
	LPROCFS_FIELDS_FLAGS_AVG        = 0x0005,
	LPROCFS_FIELDS_FLAGS_SUMSQUARE  = 0x0006,
	LPROCFS_FIELDS_FLAGS_COUNT      = 0x0007,
};

struct lprocfs_stats {
	/* # of counters */
	unsigned short			ls_num;
	/* 1 + the biggest cpu # whose ls_percpu slot has been allocated */
	unsigned short			ls_biggest_alloc_num;
	enum lprocfs_stats_flags	ls_flags;
	/* Lock used when there are no percpu stats areas; For percpu stats,
	 * it is used to protect ls_biggest_alloc_num change */
	spinlock_t			ls_lock;

	/* has ls_num of counter headers */
	struct lprocfs_counter_header	*ls_cnt_header;
	struct lprocfs_percpu		*ls_percpu[0];
};

#define OPC_RANGE(seg) (seg ## _LAST_OPC - seg ## _FIRST_OPC)

/* Pack all opcodes down into a single monotonically increasing index */
static inline int opcode_offset(__u32 opc) {
        if (opc < OST_LAST_OPC) {
                 /* OST opcode */
                return (opc - OST_FIRST_OPC);
        } else if (opc < MDS_LAST_OPC) {
                /* MDS opcode */
                return (opc - MDS_FIRST_OPC +
                        OPC_RANGE(OST));
        } else if (opc < LDLM_LAST_OPC) {
                /* LDLM Opcode */
                return (opc - LDLM_FIRST_OPC +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
        } else if (opc < MGS_LAST_OPC) {
                /* MGS Opcode */
                return (opc - MGS_FIRST_OPC +
                        OPC_RANGE(LDLM) +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
        } else if (opc < OBD_LAST_OPC) {
                /* OBD Ping */
                return (opc - OBD_FIRST_OPC +
                        OPC_RANGE(MGS) +
                        OPC_RANGE(LDLM) +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
        } else if (opc < LLOG_LAST_OPC) {
                /* LLOG Opcode */
                return (opc - LLOG_FIRST_OPC +
                        OPC_RANGE(OBD) +
                        OPC_RANGE(MGS) +
                        OPC_RANGE(LDLM) +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
        } else if (opc < QUOTA_LAST_OPC) {
                /* LQUOTA Opcode */
                return (opc - QUOTA_FIRST_OPC +
                        OPC_RANGE(LLOG) +
                        OPC_RANGE(OBD) +
                        OPC_RANGE(MGS) +
                        OPC_RANGE(LDLM) +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
        } else if (opc < SEQ_LAST_OPC) {
                /* SEQ opcode */
                return (opc - SEQ_FIRST_OPC +
                        OPC_RANGE(QUOTA) +
                        OPC_RANGE(LLOG) +
                        OPC_RANGE(OBD) +
                        OPC_RANGE(MGS) +
                        OPC_RANGE(LDLM) +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
        } else if (opc < SEC_LAST_OPC) {
                /* SEC opcode */
                return (opc - SEC_FIRST_OPC +
                        OPC_RANGE(SEQ) +
                        OPC_RANGE(QUOTA) +
                        OPC_RANGE(LLOG) +
                        OPC_RANGE(OBD) +
                        OPC_RANGE(MGS) +
                        OPC_RANGE(LDLM) +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
        } else if (opc < FLD_LAST_OPC) {
                /* FLD opcode */
                 return (opc - FLD_FIRST_OPC +
                        OPC_RANGE(SEC) +
                        OPC_RANGE(SEQ) +
                        OPC_RANGE(QUOTA) +
                        OPC_RANGE(LLOG) +
                        OPC_RANGE(OBD) +
                        OPC_RANGE(MGS) +
                        OPC_RANGE(LDLM) +
                        OPC_RANGE(MDS) +
                        OPC_RANGE(OST));
	} else if (opc < OUT_UPDATE_LAST_OPC) {
		/* update opcode */
		return (opc - OUT_UPDATE_FIRST_OPC +
			OPC_RANGE(FLD) +
			OPC_RANGE(SEC) +
			OPC_RANGE(SEQ) +
			OPC_RANGE(QUOTA) +
			OPC_RANGE(LLOG) +
			OPC_RANGE(OBD) +
			OPC_RANGE(MGS) +
			OPC_RANGE(LDLM) +
			OPC_RANGE(MDS) +
			OPC_RANGE(OST));
	} else if (opc < LFSCK_LAST_OPC) {
		/* LFSCK opcode */
		return (opc - LFSCK_FIRST_OPC +
			OPC_RANGE(OUT_UPDATE) +
			OPC_RANGE(FLD) +
			OPC_RANGE(SEC) +
			OPC_RANGE(SEQ) +
			OPC_RANGE(QUOTA) +
			OPC_RANGE(LLOG) +
			OPC_RANGE(OBD) +
			OPC_RANGE(MGS) +
			OPC_RANGE(LDLM) +
			OPC_RANGE(MDS) +
			OPC_RANGE(OST));
	} else {
		/* Unknown Opcode */
		return -1;
	}
}


#define LUSTRE_MAX_OPCODES (OPC_RANGE(OST)  + \
                            OPC_RANGE(MDS)  + \
                            OPC_RANGE(LDLM) + \
                            OPC_RANGE(MGS)  + \
                            OPC_RANGE(OBD)  + \
                            OPC_RANGE(LLOG) + \
                            OPC_RANGE(SEC)  + \
                            OPC_RANGE(SEQ)  + \
                            OPC_RANGE(SEC)  + \
			    OPC_RANGE(FLD)  + \
			    OPC_RANGE(OUT_UPDATE) + \
			    OPC_RANGE(LFSCK))

#define EXTRA_MAX_OPCODES ((PTLRPC_LAST_CNTR - PTLRPC_FIRST_CNTR)  + \
                            OPC_RANGE(EXTRA))

enum {
        PTLRPC_REQWAIT_CNTR = 0,
        PTLRPC_REQQDEPTH_CNTR,
        PTLRPC_REQACTIVE_CNTR,
        PTLRPC_TIMEOUT,
        PTLRPC_REQBUF_AVAIL_CNTR,
        PTLRPC_LAST_CNTR
};

#define PTLRPC_FIRST_CNTR PTLRPC_REQWAIT_CNTR

enum lprocfs_extra_opc {
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
        MDS_REINT_SETXATTR,
        BRW_READ_BYTES,
        BRW_WRITE_BYTES,
        EXTRA_LAST_OPC
};

#define EXTRA_FIRST_OPC LDLM_GLIMPSE_ENQUEUE
/* class_obd.c */
extern struct proc_dir_entry *proc_lustre_root;
extern struct dentry *debugfs_lustre_root;
extern struct kobject *lustre_kobj;

struct obd_device;
struct obd_histogram;

#define JOBSTATS_JOBID_VAR_MAX_LEN	20
#define JOBSTATS_DISABLE		"disable"
#define JOBSTATS_PROCNAME_UID		"procname_uid"
#define JOBSTATS_NODELOCAL		"nodelocal"

typedef void (*cntr_init_callback)(struct lprocfs_stats *stats);

struct obd_job_stats {
	struct cfs_hash	       *ojs_hash;	/* hash of jobids */
	struct list_head	ojs_list;	/* list of job_stat structs */
	rwlock_t		ojs_lock;	/* protect ojs_list/js_list */
	unsigned int		ojs_cleanup_interval;/* seconds before expiry */
	time_t			ojs_last_cleanup; /* previous cleanup time */
	cntr_init_callback	ojs_cntr_init_fn;/* lprocfs_stats initializer */
	unsigned short		ojs_cntr_num;	/* number of stats in struct */
	bool			ojs_cleaning;	/* currently expiring stats */
};

#ifdef CONFIG_PROC_FS

int lprocfs_stats_alloc_one(struct lprocfs_stats *stats,
			    unsigned int cpuid);
int lprocfs_stats_lock(struct lprocfs_stats *stats,
		       enum lprocfs_stats_lock_ops opc,
		       unsigned long *flags);
void lprocfs_stats_unlock(struct lprocfs_stats *stats,
			  enum lprocfs_stats_lock_ops opc,
			  unsigned long *flags);

static inline unsigned int
lprocfs_stats_counter_size(struct lprocfs_stats *stats)
{
	unsigned int percpusize;

	percpusize = offsetof(struct lprocfs_percpu, lp_cntr[stats->ls_num]);

	/* irq safe stats need lc_array_sum[1] */
	if ((stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0)
		percpusize += stats->ls_num * sizeof(__s64);

	if ((stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU) == 0)
		percpusize = L1_CACHE_ALIGN(percpusize);

	return percpusize;
}

static inline struct lprocfs_counter *
lprocfs_stats_counter_get(struct lprocfs_stats *stats, unsigned int cpuid,
			  int index)
{
	struct lprocfs_counter *cntr;

	cntr = &stats->ls_percpu[cpuid]->lp_cntr[index];

	if ((stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0)
		cntr = (void *)cntr + index * sizeof(__s64);

	return cntr;
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
				 struct lprocfs_counter_header *header,
				 enum lprocfs_stats_flags flags,
				 enum lprocfs_fields_flags field);
u64 lprocfs_stats_collector(struct lprocfs_stats *stats, int idx,
			    enum lprocfs_fields_flags field);

extern struct lprocfs_stats *
lprocfs_alloc_stats(unsigned int num, enum lprocfs_stats_flags flags);
extern void lprocfs_clear_stats(struct lprocfs_stats *stats);
extern void lprocfs_free_stats(struct lprocfs_stats **stats);
extern void lprocfs_init_ops_stats(int num_private_stats,
                                   struct lprocfs_stats *stats);
extern void lprocfs_init_mps_stats(int num_private_stats,
                                   struct lprocfs_stats *stats);
extern void lprocfs_init_ldlm_stats(struct lprocfs_stats *ldlm_stats);
extern int lprocfs_alloc_obd_stats(struct obd_device *obddev,
                                   unsigned int num_private_stats);
extern int lprocfs_alloc_md_stats(struct obd_device *obddev,
                                  unsigned int num_private_stats);
extern void lprocfs_counter_init(struct lprocfs_stats *stats, int index,
                                 unsigned conf, const char *name,
                                 const char *units);
extern void lprocfs_free_obd_stats(struct obd_device *obddev);
extern void lprocfs_free_md_stats(struct obd_device *obddev);
struct obd_export;
struct nid_stat;
extern int lprocfs_add_clear_entry(struct obd_device * obd,
				   struct proc_dir_entry *entry);
#ifdef HAVE_SERVER_SUPPORT
extern int lprocfs_exp_setup(struct obd_export *exp, lnet_nid_t *peer_nid);
extern int lprocfs_exp_cleanup(struct obd_export *exp);
#else
static inline int lprocfs_exp_cleanup(struct obd_export *exp)
{ return 0; }
#endif
extern struct proc_dir_entry *
lprocfs_add_simple(struct proc_dir_entry *root, char *name,
		   void *data, const struct file_operations *fops);
extern struct proc_dir_entry *
lprocfs_add_symlink(const char *name, struct proc_dir_entry *parent,
                    const char *format, ...);
extern void lprocfs_free_per_client_stats(struct obd_device *obd);
#ifdef HAVE_SERVER_SUPPORT
extern ssize_t
lprocfs_nid_stats_clear_seq_write(struct file *file, const char __user *buffer,
					size_t count, loff_t *off);
extern int lprocfs_nid_stats_clear_seq_show(struct seq_file *file, void *data);
#endif
extern int ldebugfs_register_stats(struct dentry *parent, const char *name,
				   struct lprocfs_stats *stats);
extern int lprocfs_register_stats(struct proc_dir_entry *root, const char *name,
                                  struct lprocfs_stats *stats);

/* lprocfs_status.c */
extern int ldebugfs_add_vars(struct dentry *parent, struct lprocfs_vars *var,
			     void *data);
extern int lprocfs_add_vars(struct proc_dir_entry *root,
			    struct lprocfs_vars *var, void *data);

extern struct dentry *ldebugfs_register(const char *name,
					struct dentry *parent,
					struct lprocfs_vars *list,
					void *data);
extern struct proc_dir_entry *
lprocfs_register(const char *name, struct proc_dir_entry *parent,
		 struct lprocfs_vars *list, void *data);

extern void ldebugfs_remove(struct dentry **entryp);
extern void lprocfs_remove(struct proc_dir_entry **root);
extern void lprocfs_remove_proc_entry(const char *name,
                                      struct proc_dir_entry *parent);
#ifndef HAVE_REMOVE_PROC_SUBTREE
extern int remove_proc_subtree(const char *name,
			       struct proc_dir_entry *parent);
#define PDE_DATA(inode)		(PDE(inode)->data)

static inline int LPROCFS_ENTRY_CHECK(struct inode *inode)
{
	struct proc_dir_entry *dp = PDE(inode);
	int deleted = 0;

	spin_lock(&(dp)->pde_unload_lock);
	if (dp->proc_fops == NULL)
		deleted = 1;
	spin_unlock(&(dp)->pde_unload_lock);
	if (deleted)
		return -ENODEV;
	return 0;
}
#else
static inline int LPROCFS_ENTRY_CHECK(struct inode *inode)
{ return 0; }
#endif
extern int lprocfs_obd_setup(struct obd_device *dev);
extern int lprocfs_obd_cleanup(struct obd_device *obd);
#ifdef HAVE_SERVER_SUPPORT
extern const struct file_operations lprocfs_evict_client_fops;
#endif

extern int ldebugfs_seq_create(struct dentry *parent, const char *name,
			       umode_t mode,
			       const struct file_operations *seq_fops,
			       void *data);
extern int lprocfs_seq_create(struct proc_dir_entry *parent, const char *name,
			      mode_t mode,
			      const struct file_operations *seq_fops,
			      void *data);
extern int lprocfs_obd_seq_create(struct obd_device *dev, const char *name,
				  mode_t mode,
				  const struct file_operations *seq_fops,
				  void *data);

/* Generic callbacks */
extern int lprocfs_u64_seq_show(struct seq_file *m, void *data);
extern int lprocfs_atomic_seq_show(struct seq_file *m, void *data);
extern ssize_t lprocfs_atomic_seq_write(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *off);
extern int lprocfs_uint_seq_show(struct seq_file *m, void *data);
extern ssize_t lprocfs_uint_seq_write(struct file *file,
				      const char __user *buffer,
				      size_t count, loff_t *off);
extern int lprocfs_wr_uint(struct file *file, const char __user *buffer,
			   unsigned long count, void *data);
extern int lprocfs_uuid_seq_show(struct seq_file *m, void *data);
extern int lprocfs_name_seq_show(struct seq_file *m, void *data);
extern int lprocfs_server_uuid_seq_show(struct seq_file *m, void *data);
extern int lprocfs_conn_uuid_seq_show(struct seq_file *m, void *data);
extern int lprocfs_import_seq_show(struct seq_file *m, void *data);
extern int lprocfs_state_seq_show(struct seq_file *m, void *data);
extern int lprocfs_connect_flags_seq_show(struct seq_file *m, void *data);
#ifdef HAVE_SERVER_SUPPORT
extern int lprocfs_num_exports_seq_show(struct seq_file *m, void *data);
#endif
struct adaptive_timeout;
extern int lprocfs_at_hist_helper(struct seq_file *m,
				  struct adaptive_timeout *at);
extern int lprocfs_timeouts_seq_show(struct seq_file *m, void *data);
extern ssize_t
lprocfs_timeouts_seq_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *off);
#ifdef HAVE_SERVER_SUPPORT
extern ssize_t
lprocfs_evict_client_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off);
#endif
extern ssize_t
lprocfs_ping_seq_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *off);
extern ssize_t
lprocfs_import_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off);
extern int lprocfs_pinger_recov_seq_show(struct seq_file *m, void *data);
extern ssize_t
lprocfs_pinger_recov_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off);

/* Statfs helpers */
extern int lprocfs_blksize_seq_show(struct seq_file *m, void *data);
extern int lprocfs_kbytestotal_seq_show(struct seq_file *m, void *data);
extern int lprocfs_kbytesfree_seq_show(struct seq_file *m, void *data);
extern int lprocfs_kbytesavail_seq_show(struct seq_file *m, void *data);
extern int lprocfs_filestotal_seq_show(struct seq_file *m, void *data);
extern int lprocfs_filesfree_seq_show(struct seq_file *m, void *data);

extern int lprocfs_seq_read_frac_helper(struct seq_file *m, long val, int mult);
extern int lprocfs_read_frac_helper(char *buffer, unsigned long count,
                                    long val, int mult);
extern int lprocfs_str_to_s64(const char __user *buffer, unsigned long count,
			      __s64 *val);
extern int lprocfs_str_with_units_to_s64(const char __user *buffer,
					 unsigned long count, __s64 *val,
					 char defunit);

char *lprocfs_strnstr(const char *s1, const char *s2, size_t len);
char *lprocfs_find_named_value(const char *buffer, const char *name,
				size_t *count);
void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value);
void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value);
void lprocfs_oh_clear(struct obd_histogram *oh);
unsigned long lprocfs_oh_sum(struct obd_histogram *oh);

void lprocfs_stats_collect(struct lprocfs_stats *stats, int idx,
                           struct lprocfs_counter *cnt);

#ifdef HAVE_SERVER_SUPPORT
/* lprocfs_status.c: recovery status */
int lprocfs_recovery_status_seq_show(struct seq_file *m, void *data);

/* lprocfs_status.c: hash statistics */
int lprocfs_hash_seq_show(struct seq_file *m, void *data);

/* lprocfs_status.c: IR factor */
int lprocfs_ir_factor_seq_show(struct seq_file *m, void *data);
ssize_t
lprocfs_ir_factor_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off);
#endif

/* lprocfs_status.c: dump pages on cksum error */
int lprocfs_checksum_dump_seq_show(struct seq_file *m, void *data);
ssize_t
lprocfs_checksum_dump_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off);

extern int lprocfs_single_release(struct inode *, struct file *);
extern int lprocfs_seq_release(struct inode *, struct file *);

/* You must use these macros when you want to refer to
 * the import in a client obd_device for a lprocfs entry */
#define LPROCFS_CLIMP_CHECK(obd) do {           \
        typecheck(struct obd_device *, obd);    \
	down_read(&(obd)->u.cli.cl_sem);    \
        if ((obd)->u.cli.cl_import == NULL) {   \
	     up_read(&(obd)->u.cli.cl_sem); \
             return -ENODEV;                    \
        }                                       \
} while(0)
#define LPROCFS_CLIMP_EXIT(obd)                 \
	up_read(&(obd)->u.cli.cl_sem);

/* write the name##_seq_show function, call LPROC_SEQ_FOPS_RO for read-only
  proc entries; otherwise, you will define name##_seq_write function also for
  a read-write proc entry, and then call LPROC_SEQ_SEQ instead. Finally,
  call lprocfs_obd_seq_create(obd, filename, 0444, &name#_fops, data); */
#define __LPROC_SEQ_FOPS(name, custom_seq_write)			\
static int name##_single_open(struct inode *inode, struct file *file)	\
{									\
	int rc;								\
									\
	rc = LPROCFS_ENTRY_CHECK(inode);				\
	if (rc < 0)							\
		return rc;						\
									\
	return single_open(file, name##_seq_show,			\
			   inode->i_private ? : PDE_DATA(inode));	\
}									\
static const struct file_operations name##_fops = {			\
	.owner	 = THIS_MODULE,						\
	.open	 = name##_single_open,					\
	.read	 = seq_read,						\
	.write	 = custom_seq_write,					\
	.llseek	 = seq_lseek,						\
	.release = lprocfs_single_release,				\
}

#define LPROC_SEQ_FOPS_RO(name)		__LPROC_SEQ_FOPS(name, NULL)
#define LPROC_SEQ_FOPS(name)		__LPROC_SEQ_FOPS(name, name##_seq_write)

#define LPROC_SEQ_FOPS_RO_TYPE(name, type)				\
	static int name##_##type##_seq_show(struct seq_file *m, void *v)\
	{								\
		return lprocfs_##type##_seq_show(m, m->private);	\
	}								\
	LPROC_SEQ_FOPS_RO(name##_##type)

#define LPROC_SEQ_FOPS_RW_TYPE(name, type)				\
	static int name##_##type##_seq_show(struct seq_file *m, void *v)\
	{								\
		return lprocfs_##type##_seq_show(m, m->private);	\
	}								\
	static ssize_t name##_##type##_seq_write(struct file *file,	\
			const char __user *buffer, size_t count,	\
			loff_t *off)					\
	{								\
		struct seq_file *seq = file->private_data;		\
		return lprocfs_##type##_seq_write(file, buffer,		\
						count, seq->private);	\
	}								\
	LPROC_SEQ_FOPS(name##_##type);

#define LPROC_SEQ_FOPS_WO_TYPE(name, type)				\
	static ssize_t name##_##type##_write(struct file *file,		\
			const char __user *buffer, size_t count,	\
			loff_t *off)					\
	{								\
		return lprocfs_##type##_seq_write(file, buffer, count, off);\
	}								\
	static int name##_##type##_open(struct inode *inode, struct file *file)\
	{								\
		return single_open(file, NULL,				\
				   inode->i_private ? : PDE_DATA(inode));\
	}								\
	static const struct file_operations name##_##type##_fops = {	\
		.open	 = name##_##type##_open,			\
		.write	 = name##_##type##_write,			\
		.release = lprocfs_single_release,			\
	};

struct lustre_attr {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct attribute *attr,
			char *buf);
	ssize_t (*store)(struct kobject *kobj, struct attribute *attr,
			 const char *buf, size_t len);
};

#define LUSTRE_ATTR(name, mode, show, store) \
static struct lustre_attr lustre_attr_##name = __ATTR(name, mode, show, store)

#define LUSTRE_RO_ATTR(name) LUSTRE_ATTR(name, 0444, name##_show, NULL)
#define LUSTRE_RW_ATTR(name) LUSTRE_ATTR(name, 0644, name##_show, name##_store)

ssize_t lustre_attr_show(struct kobject *kobj, struct attribute *attr,
			 char *buf);
ssize_t lustre_attr_store(struct kobject *kobj, struct attribute *attr,
			  const char *buf, size_t len);

extern const struct sysfs_ops lustre_sysfs_ops;

/* lproc_ptlrpc.c */
struct ptlrpc_request;
extern void target_print_req(void *seq_file, struct ptlrpc_request *req);

#ifdef HAVE_SERVER_SUPPORT
/* lprocfs_jobstats.c */
int lprocfs_job_stats_log(struct obd_device *obd, char *jobid,
			  int event, long amount);
void lprocfs_job_stats_fini(struct obd_device *obd);
int lprocfs_job_stats_init(struct obd_device *obd, int cntr_num,
			   cntr_init_callback fn);
int lprocfs_job_interval_seq_show(struct seq_file *m, void *data);
ssize_t
lprocfs_job_interval_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off);
/* lproc_status.c */
int lprocfs_recovery_time_soft_seq_show(struct seq_file *m, void *data);
ssize_t lprocfs_recovery_time_soft_seq_write(struct file *file,
						const char __user *buffer,
						size_t count, loff_t *off);
int lprocfs_recovery_time_hard_seq_show(struct seq_file *m, void *data);
ssize_t
lprocfs_recovery_time_hard_seq_write(struct file *file,
				     const char __user *buffer,
				     size_t count, loff_t *off);
int lprocfs_target_instance_seq_show(struct seq_file *m, void *data);
#endif
int lprocfs_obd_max_pages_per_rpc_seq_show(struct seq_file *m, void *data);
ssize_t lprocfs_obd_max_pages_per_rpc_seq_write(struct file *file,
						const char __user *buffer,
						size_t count, loff_t *off);

struct root_squash_info;
int lprocfs_wr_root_squash(const char __user *buffer, unsigned long count,
			   struct root_squash_info *squash, char *name);
int lprocfs_wr_nosquash_nids(const char __user *buffer, unsigned long count,
			     struct root_squash_info *squash, char *name);

#else /* !CONFIG_PROC_FS */

#define proc_lustre_root NULL

static inline void lprocfs_counter_add(struct lprocfs_stats *stats,
                                       int index, long amount)
{ return; }
static inline void lprocfs_counter_incr(struct lprocfs_stats *stats,
                                        int index)
{ return; }
static inline void lprocfs_counter_sub(struct lprocfs_stats *stats,
                                       int index, long amount)
{ return; }
static inline void lprocfs_counter_decr(struct lprocfs_stats *stats,
                                        int index)
{ return; }
static inline void lprocfs_counter_init(struct lprocfs_stats *stats,
                                        int index, unsigned conf,
                                        const char *name, const char *units)
{ return; }

static inline __u64 lc_read_helper(struct lprocfs_counter *lc,
                                   enum lprocfs_fields_flags field)
{ return 0; }

/* NB: we return !NULL to satisfy error checker */
static inline struct lprocfs_stats *
lprocfs_alloc_stats(unsigned int num, enum lprocfs_stats_flags flags)
{ return (struct lprocfs_stats *)1; }
static inline void lprocfs_clear_stats(struct lprocfs_stats *stats)
{ return; }
static inline void lprocfs_free_stats(struct lprocfs_stats **stats)
{ return; }
static inline int lprocfs_register_stats(struct proc_dir_entry *root,
                                         const char *name,
                                         struct lprocfs_stats *stats)
{ return 0; }
static inline void lprocfs_init_ops_stats(int num_private_stats,
                                          struct lprocfs_stats *stats)
{ return; }
static inline void lprocfs_init_mps_stats(int num_private_stats,
                                          struct lprocfs_stats *stats)
{ return; }
static inline void lprocfs_init_ldlm_stats(struct lprocfs_stats *ldlm_stats)
{ return; }
static inline int lprocfs_alloc_obd_stats(struct obd_device *obddev,
                                          unsigned int num_private_stats)
{ return 0; }
static inline int lprocfs_alloc_md_stats(struct obd_device *obddev,
                                         unsigned int num_private_stats)
{ return 0; }
static inline void lprocfs_free_obd_stats(struct obd_device *obddev)
{ return; }
static inline void lprocfs_free_md_stats(struct obd_device *obddev)
{ return; }

struct obd_export;
static inline int lprocfs_add_clear_entry(struct obd_export *exp)
{ return 0; }
static inline void lprocfs_free_per_client_stats(struct obd_device *obd)
{ return; }
#ifdef HAVE_SERVER_SUPPORT
static inline
ssize_t lprocfs_nid_stats_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{return 0;}
static inline
int lprocfs_nid_stats_clear_seq_show(struct seq_file *m, void *data)
{return 0;}
static inline int lprocfs_exp_setup(struct obd_export *exp,lnet_nid_t *peer_nid)
{ return 0; }
#endif
static inline int lprocfs_exp_cleanup(struct obd_export *exp)
{ return 0; }
static inline struct proc_dir_entry *
lprocfs_add_simple(struct proc_dir_entry *root, char *name,
		   void *data, const struct file_operations *fops)
{return 0; }
static inline struct proc_dir_entry *
lprocfs_add_symlink(const char *name, struct proc_dir_entry *parent,
                    const char *format, ...)
{return NULL; }
static inline int lprocfs_add_vars(struct proc_dir_entry *root,
				   struct lprocfs_vars *var, void *data)
{ return 0; }
static inline struct proc_dir_entry *
lprocfs_register(const char *name, struct proc_dir_entry *parent,
		 struct lprocfs_vars *list, void *data)
{ return NULL; }
static inline void lprocfs_remove(struct proc_dir_entry **root)
{ return; }
static inline void lprocfs_remove_proc_entry(const char *name,
                                             struct proc_dir_entry *parent)
{ return; }
static inline int lprocfs_obd_setup(struct obd_device *dev)
{ return 0; }
static inline int lprocfs_obd_cleanup(struct obd_device *dev)
{ return 0; }
static inline int lprocfs_uuid_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline int lprocfs_name_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline int lprocfs_server_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline int lprocfs_conn_uuid_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline int lprocfs_import_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline int lprocfs_state_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline int lprocfs_connect_flags_seq_show(struct seq_file *m, void *data)
{ return 0; }
#ifdef HAVE_SERVER_SUPPORT
static inline int lprocfs_num_exports_seq_show(struct seq_file *m, void *data)
{ return 0; }
#endif
struct adaptive_timeout;
static inline int lprocfs_at_hist_helper(struct seq_file *m,
					 struct adaptive_timeout *at)
{ return 0; }
static inline int lprocfs_timeouts_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline ssize_t
lprocfs_timeouts_seq_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *off)
{ return 0; }
#ifdef HAVE_SERVER_SUPPORT
static inline ssize_t
lprocfs_evict_client_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{ return 0; }
#endif
static inline ssize_t
lprocfs_ping_seq_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *off)
{ return 0; }
static inline ssize_t
lprocfs_import_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{ return 0; }
static inline int
lprocfs_pinger_recov_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline ssize_t
lprocfs_pinger_recov_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{ return 0; }

/* Statfs helpers */
static inline
int lprocfs_blksize_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline
int lprocfs_kbytestotal_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline
int lprocfs_kbytesfree_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline
int lprocfs_kbytesavail_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline
int lprocfs_filestotal_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline
int lprocfs_filesfree_seq_show(struct seq_file *m, void *data)
{ return 0; }
static inline
void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value)
{ return; }
static inline
void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value)
{ return; }
static inline
void lprocfs_oh_clear(struct obd_histogram *oh)
{ return; }
static inline
unsigned long lprocfs_oh_sum(struct obd_histogram *oh)
{ return 0; }
static inline
void lprocfs_stats_collect(struct lprocfs_stats *stats, int idx,
                           struct lprocfs_counter *cnt)
{ return; }
static inline
u64 lprocfs_stats_collector(struct lprocfs_stats *stats, int idx,
			    enum lprocfs_fields_flags field)
{ return (__u64)0; }

#define LPROC_SEQ_FOPS_RO(name)
#define LPROC_SEQ_FOPS(name)
#define LPROC_SEQ_FOPS_RO_TYPE(name, type)
#define LPROC_SEQ_FOPS_RW_TYPE(name, type)
#define LPROC_SEQ_FOPS_WO_TYPE(name, type)

/* lprocfs_jobstats.c */
static inline
int lprocfs_job_stats_log(struct obd_device *obd, char *jobid, int event,
			  long amount)
{ return 0; }
static inline
void lprocfs_job_stats_fini(struct obd_device *obd)
{ return; }
static inline
int lprocfs_job_stats_init(struct obd_device *obd, int cntr_num,
			   cntr_init_callback fn)
{ return 0; }


/* lproc_ptlrpc.c */
#define target_print_req NULL

#endif /* CONFIG_PROC_FS */

#endif /* LPROCFS_STATUS_H */
