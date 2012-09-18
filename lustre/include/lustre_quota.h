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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _LUSTRE_QUOTA_H
#define _LUSTRE_QUOTA_H

/** \defgroup quota quota
 *
 * @{
 */

#if defined(__linux__)
#include <linux/lustre_quota.h>
#elif defined(__APPLE__)
#include <darwin/lustre_quota.h>
#elif defined(__WINNT__)
#include <winnt/lustre_quota.h>
#else
#error Unsupported operating system.
#endif

#include <lustre_net.h>
#include <lustre/lustre_idl.h>
#include <lvfs.h>
#include <obd_support.h>

struct obd_device;
struct client_obd;

#ifndef NR_DQHASH
#define NR_DQHASH 45
#endif

#ifndef QUOTABLOCK_BITS
#define QUOTABLOCK_BITS 10
#endif

#ifndef QUOTABLOCK_SIZE
#define QUOTABLOCK_SIZE (1 << QUOTABLOCK_BITS)
#endif

#ifndef toqb
#define toqb(x) (((x) + QUOTABLOCK_SIZE - 1) >> QUOTABLOCK_BITS)
#endif

#ifdef HAVE_QUOTA_SUPPORT

#ifndef MAX_IQ_TIME
#define MAX_IQ_TIME  604800     /* (7*24*60*60) 1 week */
#endif

#ifndef MAX_DQ_TIME
#define MAX_DQ_TIME  604800     /* (7*24*60*60) 1 week */
#endif

#ifdef __KERNEL__

#ifdef LPROCFS
enum {
        LQUOTA_FIRST_STAT = 0,
        /** @{ */
        /**
         * these four are for measuring quota requests, for both of
         * quota master and quota slaves
         */
        LQUOTA_SYNC_ACQ = LQUOTA_FIRST_STAT,
        LQUOTA_SYNC_REL,
        LQUOTA_ASYNC_ACQ,
        LQUOTA_ASYNC_REL,
        /** }@ */
        /** @{ */
        /**
         * these four measure how much time I/O threads spend on dealing
         * with quota before and after writing data or creating files,
         * only for quota slaves(lquota_chkquota and lquota_pending_commit)
         */
        LQUOTA_WAIT_FOR_CHK_BLK,
        LQUOTA_WAIT_FOR_CHK_INO,
        LQUOTA_WAIT_FOR_COMMIT_BLK,
        LQUOTA_WAIT_FOR_COMMIT_INO,
        /** }@ */
        /** @{ */
        /**
         * these two are for measuring time waiting return of quota reqs
         * (qctxt_wait_pending_dqacq), only for quota salves
         */
        LQUOTA_WAIT_PENDING_BLK_QUOTA,
        LQUOTA_WAIT_PENDING_INO_QUOTA,
        /** }@ */
        /** @{ */
        /**
         * these two are for those when they are calling
         * qctxt_wait_pending_dqacq, the quota req has returned already,
         * only for quota salves
         */
        LQUOTA_NOWAIT_PENDING_BLK_QUOTA,
        LQUOTA_NOWAIT_PENDING_INO_QUOTA,
        /** }@ */
        /** @{ */
        /**
         * these are for quota ctl
         */
        LQUOTA_QUOTA_CTL,
        /** }@ */
        /** @{ */
        /**
         * these are for adjust quota qunit, for both of
         * quota master and quota slaves
         */
        LQUOTA_ADJUST_QUNIT,
        LQUOTA_LAST_STAT
        /** }@ */
};
#endif  /* LPROCFS */

/* structures to access admin quotafile */
struct lustre_mem_dqinfo {
        unsigned int dqi_bgrace;
        unsigned int dqi_igrace;
        unsigned long dqi_flags;
        unsigned int dqi_blocks;
        unsigned int dqi_free_blk;
        unsigned int dqi_free_entry;
};

struct lustre_quota_info {
        struct file *qi_files[MAXQUOTAS];
        struct lustre_mem_dqinfo qi_info[MAXQUOTAS];
        lustre_quota_version_t qi_version;
};

struct lustre_mem_dqblk {
        __u64 dqb_bhardlimit;	/**< absolute limit on disk blks alloc */
        __u64 dqb_bsoftlimit;	/**< preferred limit on disk blks */
        __u64 dqb_curspace;	/**< current used space */
        __u64 dqb_ihardlimit;	/**< absolute limit on allocated inodes */
        __u64 dqb_isoftlimit;	/**< preferred inode limit */
        __u64 dqb_curinodes;	/**< current # allocated inodes */
        time_t dqb_btime;	/**< time limit for excessive disk use */
        time_t dqb_itime;	/**< time limit for excessive inode use */
};

struct lustre_dquot {
        /** Hash list in memory, protect by dquot_hash_lock */
        cfs_list_t dq_hash;
        /** Protect the data in lustre_dquot */
        cfs_mutex_t dq_mutex;
        /** Use count */
        cfs_atomic_t dq_refcnt;
        /** Pointer of quota info it belongs to */
        struct lustre_quota_info *dq_info;
        /** Offset of dquot on disk */
        loff_t dq_off;
        /** ID this applies to (uid, gid) */
        unsigned int dq_id;
        /** Type fo quota (USRQUOTA, GRPQUOUTA) */
        int dq_type;
        /** See DQ_ in quota.h */
        unsigned long dq_flags;
        /** Diskquota usage */
        struct lustre_mem_dqblk dq_dqb;
};

struct dquot_id {
        cfs_list_t              di_link;
        __u32                   di_id;
        __u32                   di_flag;
};
/* set inode quota limitation on a quota uid/gid */
#define QI_SET                (1 << 30)
/* set block quota limitation on a quota uid/gid */
#define QB_SET                (1 << 31)

#define QFILE_CHK               1
#define QFILE_RD_INFO           2
#define QFILE_WR_INFO           3
#define QFILE_INIT_INFO         4
#define QFILE_RD_DQUOT          5
#define QFILE_WR_DQUOT          6
#define QFILE_CONVERT           7

/* admin quotafile operations */
int lustre_check_quota_file(struct lustre_quota_info *lqi, int type);
int lustre_read_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_write_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_read_dquot(struct lustre_dquot *dquot);
int lustre_commit_dquot(struct lustre_dquot *dquot);
int lustre_init_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_get_qids(struct file *file, struct inode *inode, int type,
                    cfs_list_t *list);
int lustre_quota_convert(struct lustre_quota_info *lqi, int type);

typedef int (*dqacq_handler_t) (struct obd_device * obd, struct qunit_data * qd,
                                int opc);

/* user quota is turned on on filter */
#define LQC_USRQUOTA_FLAG (1 << 0)
/* group quota is turned on on filter */
#define LQC_GRPQUOTA_FLAG (1 << 1)

#define UGQUOTA2LQC(id) ((Q_TYPEMATCH(id, USRQUOTA) ? LQC_USRQUOTA_FLAG : 0) | \
                         (Q_TYPEMATCH(id, GRPQUOTA) ? LQC_GRPQUOTA_FLAG : 0))

struct lustre_quota_ctxt {
        /** superblock this applies to */
        struct super_block *lqc_sb;
        /** obd_device_target for obt_rwsem */
        struct obd_device_target *lqc_obt;
        /** import used to send dqacq/dqrel RPC */
        struct obd_import *lqc_import;
        /** dqacq/dqrel RPC handler, only for quota master */
        dqacq_handler_t lqc_handler;
        /** quota flags */
        unsigned long lqc_flags;
        /** @{ */
        unsigned long lqc_recovery:1,   /** Doing recovery */
                      lqc_switch_qs:1,  /**
                                         * the function of change qunit size
                                         * 0:Off, 1:On
                                         */
                      lqc_valid:1,      /** this qctxt is valid or not */
                      lqc_setup:1;      /**
                                         * tell whether of not quota_type has
                                         * been processed, so that the master
                                         * knows when it can start processing
                                         * incoming acq/rel quota requests
                                         */
        /** }@ */
        /**
         * original unit size of file quota and
         * upper limitation for adjust file qunit
         */
        unsigned long lqc_iunit_sz;
        /**
         * Trigger dqacq when available file
         * quota less than this value, trigger
         * dqrel when available file quota
         * more than this value + 1 iunit
         */
        unsigned long lqc_itune_sz;
        /**
         * original unit size of block quota and
         * upper limitation for adjust block qunit
         */
        unsigned long lqc_bunit_sz;
        /** See comment of lqc_itune_sz */
        unsigned long lqc_btune_sz;
        /** all lustre_qunit_size structures */
        cfs_hash_t   *lqc_lqs_hash;

        /** @{ */
        /**
         * the values below are relative to how master change its qunit sizes
         */
        /**
         * this affects the boundary of
         * shrinking and enlarging qunit size. default=4
         */
        unsigned long lqc_cqs_boundary_factor;
        /** the least value of block qunit */
        unsigned long lqc_cqs_least_bunit;
        /** the least value of inode qunit */
        unsigned long lqc_cqs_least_iunit;
        /**
         * when enlarging, qunit size will
         * mutilple it; when shrinking,
         * qunit size will divide it
         */
        unsigned long lqc_cqs_qs_factor;
        /**
         * avoid ping-pong effect of
         * adjusting qunit size. How many
         * seconds must be waited between
         * enlarging and shinking qunit
         */
        /** }@ */
        int           lqc_switch_seconds;
        /**
         * when blk qunit reaches this value,
         * later write reqs from client should be sync b=16642
         */
        int           lqc_sync_blk;
        /** guard lqc_imp_valid now */
        cfs_spinlock_t lqc_lock;
        /**
         * when mds isn't connected, threads
         * on osts who send the quota reqs
         * with wait==1 will be put here b=14840
         */
        cfs_waitq_t   lqc_wait_for_qmaster;
        struct proc_dir_entry *lqc_proc_dir;
        /** lquota statistics */
        struct lprocfs_stats  *lqc_stats;
        /** the number of used hashed lqs */
        cfs_atomic_t  lqc_lqs;
        /** no lqs are in use */
        cfs_waitq_t   lqc_lqs_waitq;
};

#define QUOTA_MASTER_READY(qctxt)   (qctxt)->lqc_setup = 1
#define QUOTA_MASTER_UNREADY(qctxt) (qctxt)->lqc_setup = 0

struct lustre_qunit_size {
        cfs_hlist_node_t lqs_hash; /** the hash entry */
        unsigned int lqs_id;        /** id of user/group */
        unsigned long lqs_flags;    /** 31st bit is QB_SET, 30th bit is QI_SET
                                     * other bits are same as LQUOTA_FLAGS_*
                                     */
        unsigned long lqs_iunit_sz; /** Unit size of file quota currently */
        /**
         * Trigger dqacq when available file quota
         * less than this value, trigger dqrel
         * when more than this value + 1 iunit
         */
        unsigned long lqs_itune_sz;
        unsigned long lqs_bunit_sz; /** Unit size of block quota currently */
        unsigned long lqs_btune_sz; /** See comment of lqs itune sz */
        /** the blocks reached ost and don't finish */
        unsigned long lqs_bwrite_pending;
        /** the inodes reached mds and don't finish */
        unsigned long lqs_iwrite_pending;
        /** when inodes are allocated/released, this value will record it */
        long long lqs_ino_rec;
        /** when blocks are allocated/released, this value will record it */
        long long lqs_blk_rec;
        cfs_atomic_t lqs_refcount;
        cfs_time_t lqs_last_bshrink;   /** time of last block shrink */
        cfs_time_t lqs_last_ishrink;   /** time of last inode shrink */
        cfs_spinlock_t lqs_lock;
        unsigned long long lqs_key;    /** hash key */
        struct lustre_quota_ctxt *lqs_ctxt; /** quota ctxt */
};

#define LQS_IS_GRP(lqs)      ((lqs)->lqs_flags & LQUOTA_FLAGS_GRP)
#define LQS_IS_ADJBLK(lqs)   ((lqs)->lqs_flags & LQUOTA_FLAGS_ADJBLK)
#define LQS_IS_ADJINO(lqs)   ((lqs)->lqs_flags & LQUOTA_FLAGS_ADJINO)
#define LQS_IS_RECOVERY(lqs) ((lqs)->lqs_flags & LQUOTA_FLAGS_RECOVERY)
#define LQS_IS_SETQUOTA(lqs) ((lqs)->lqs_flags & LQUOTA_FLAGS_SETQUOTA)

#define LQS_SET_GRP(lqs)       ((lqs)->lqs_flags |= LQUOTA_FLAGS_GRP)
#define LQS_SET_ADJBLK(lqs)    ((lqs)->lqs_flags |= LQUOTA_FLAGS_ADJBLK)
#define LQS_SET_ADJINO(lqs)    ((lqs)->lqs_flags |= LQUOTA_FLAGS_ADJINO)
#define LQS_SET_RECOVERY(lqs)  ((lqs)->lqs_flags |= LQUOTA_FLAGS_RECOVERY)
#define LQS_SET_SETQUOTA(lqs)  ((lqs)->lqs_flags |= LQUOTA_FLAGS_SETQUOTA)

#define LQS_CLEAR_RECOVERY(lqs)  ((lqs)->lqs_flags &= ~LQUOTA_FLAGS_RECOVERY)
#define LQS_CLEAR_SETQUOTA(lqs)  ((lqs)->lqs_flags &= ~LQUOTA_FLAGS_SETQUOTA)

/* In the hash for lustre_qunit_size, the key is decided by
 * grp_or_usr and uid/gid, in here, I combine these two values,
 * which will make comparing easier and more efficient */
#define LQS_KEY(is_grp, id)  ((is_grp ? 1ULL << 32: 0) + id)
#define LQS_KEY_ID(key)      (key & 0xffffffff)
#define LQS_KEY_GRP(key)     (key >> 32)

static inline void lqs_getref(struct lustre_qunit_size *lqs)
{
        int count = cfs_atomic_inc_return(&lqs->lqs_refcount);

        CDEBUG(D_INFO, "lqs=%p refcount %d\n", lqs, count);
}

static inline void lqs_putref(struct lustre_qunit_size *lqs)
{
        int count = cfs_atomic_read(&lqs->lqs_refcount);

        LASSERT(count > 0);
        CDEBUG(D_INFO, "lqs=%p refcount %d\n", lqs, count - 1);

        if (cfs_atomic_dec_and_test(&lqs->lqs_refcount)) {
                if (cfs_atomic_dec_and_test(&lqs->lqs_ctxt->lqc_lqs))
                        cfs_waitq_signal(&lqs->lqs_ctxt->lqc_lqs_waitq);
                OBD_FREE_PTR(lqs);
        }
}

#else

struct lustre_quota_info {
};

struct lustre_quota_ctxt {
};

#define QUOTA_MASTER_READY(qctxt)
#define QUOTA_MASTER_UNREADY(qctxt)

#endif  /* !__KERNEL__ */

#else

#define LL_DQUOT_OFF(sb) do {} while(0)

struct lustre_quota_info {
};

struct lustre_quota_ctxt {
};

#endif /* !HAVE_QUOTA_SUPPORT */

/* If the (quota limit < qunit * slave count), the slave which can't
 * acquire qunit should set it's local limit as MIN_QLIMIT */
#define MIN_QLIMIT      1

struct quotacheck_thread_args {
        struct obd_export   *qta_exp;   /** obd export */
        struct obd_device   *qta_obd;   /** obd device */
        struct obd_quotactl  qta_oqctl; /** obd_quotactl args */
        struct super_block  *qta_sb;    /** obd super block */
        cfs_semaphore_t     *qta_sem;   /** obt_quotachecking */
};

struct obd_trans_info;
typedef int (*quota_acquire)(struct obd_device *obd, const unsigned int id[],
                             struct obd_trans_info *oti, int isblk);

typedef struct {
        int (*quota_init) (void);
        int (*quota_exit) (void);
        int (*quota_setup) (struct obd_device *);
        int (*quota_cleanup) (struct obd_device *);
        /**
         * For quota master, close admin quota files
         */
        int (*quota_fs_cleanup) (struct obd_device *);
        int (*quota_ctl) (struct obd_device *, struct obd_export *,
                          struct obd_quotactl *);
        int (*quota_check) (struct obd_device *, struct obd_export *,
                            struct obd_quotactl *);
        int (*quota_recovery) (struct obd_device *);

        /**
         * For quota master/slave, adjust quota limit after fs operation
         */
        int (*quota_adjust) (struct obd_device *, const unsigned int[],
                             const unsigned int[], int, int);

        /**
         * For quota slave, set import, trigger quota recovery,
         * For quota master, set lqc_setup
         */
        int (*quota_setinfo) (struct obd_device *, void *);

        /**
         * For quota slave, clear import when relative import is invalid
         */
        int (*quota_clearinfo) (struct obd_export *, struct obd_device *);

        /**
         * For quota slave, set proper thread resoure capability
         */
        int (*quota_enforce) (struct obd_device *, unsigned int);

        /**
         * For quota slave, check whether specified uid/gid is over quota
         */
        int (*quota_getflag) (struct obd_device *, struct obdo *);

#ifdef __KERNEL__
        /**
         * For quota slave, acquire/release quota from master if needed
         */
        int (*quota_acquire) (struct obd_device *, const unsigned int [],
                              struct obd_trans_info *, int);

        /**
         * For quota slave, check whether specified uid/gid's remaining quota
         * can finish a block_write or inode_create rpc. It updates the pending
         * record of block and inode, acquires quota if necessary
         */
        int (*quota_chkquota) (struct obd_device *, struct obd_export *,
                               const unsigned int [], int [],
                               int, quota_acquire, struct obd_trans_info *,
                               int, struct inode *, int);

        /**
         * For quota client, the actions after the pending write is committed
         */
        int (*quota_pending_commit) (struct obd_device *, const unsigned int [],
                                     int [], int);
#endif

        /**
         * For quota client, poll if the quota check done
         */
        int (*quota_poll_check) (struct obd_export *, struct if_quotacheck *);

        /**
         * For quota client, check whether specified uid/gid is over quota
         */
        int (*quota_chkdq) (struct client_obd *, const unsigned int []);

        /**
         * For quota client, set over quota flag for specifed uid/gid
         */
        int (*quota_setdq) (struct client_obd *, const unsigned int [],
                            obd_flag, obd_flag);

        /**
         * For adjusting qunit size b=10600
         */
        int (*quota_adjust_qunit) (struct obd_export *exp,
                                   struct quota_adjust_qunit *oqaq,
                                   struct lustre_quota_ctxt *qctxt,
                                   struct ptlrpc_request_set *rqset);

} quota_interface_t;

#define Q_COPY(out, in, member) (out)->member = (in)->member

#define QUOTA_OP(interface, op) interface->quota_ ## op

#define QUOTA_CHECK_OP(interface, op)                           \
do {                                                            \
        if (!interface)                                         \
                RETURN(0);                                      \
        if (!QUOTA_OP(interface, op)) {                         \
                CERROR("no quota operation: " #op "\n");        \
                RETURN(-EOPNOTSUPP);                            \
        }                                                       \
} while(0)

static inline int lquota_init(quota_interface_t *interface)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, init);
        rc = QUOTA_OP(interface, init)();
        RETURN(rc);
}

static inline int lquota_exit(quota_interface_t *interface)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, exit);
        rc = QUOTA_OP(interface, exit)();
        RETURN(rc);
}

static inline int lquota_setup(quota_interface_t *interface,
                               struct obd_device *obd)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, setup);
        rc = QUOTA_OP(interface, setup)(obd);
        RETURN(rc);
}

static inline int lquota_cleanup(quota_interface_t *interface,
                                 struct obd_device *obd)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, cleanup);
        rc = QUOTA_OP(interface, cleanup)(obd);
        RETURN(rc);
}

static inline int lquota_fs_cleanup(quota_interface_t *interface,
                                    struct obd_device *obd)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, fs_cleanup);
        rc = QUOTA_OP(interface, fs_cleanup)(obd);
        RETURN(rc);
}

static inline int lquota_recovery(quota_interface_t *interface,
                                  struct obd_device *obd)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, recovery);
        rc = QUOTA_OP(interface, recovery)(obd);
        RETURN(rc);
}

static inline int lquota_check(quota_interface_t *interface,
                               struct obd_device *obd,
                               struct obd_export *exp,
                               struct obd_quotactl *oqctl)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, check);
        rc = QUOTA_OP(interface, check)(obd, exp, oqctl);
        RETURN(rc);
}

static inline int lquota_ctl(quota_interface_t *interface,
                             struct obd_device *obd,
                             struct obd_quotactl *oqctl)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, ctl);
        rc = QUOTA_OP(interface, ctl)(obd, NULL, oqctl);
        RETURN(rc);
}

static inline int lquota_adjust(quota_interface_t *interface,
                                struct obd_device *obd,
                                const unsigned int qcids[],
                                const unsigned int qpids[],
                                int rc, int opc)
{
        int ret;
        ENTRY;

        QUOTA_CHECK_OP(interface, adjust);
        ret = QUOTA_OP(interface, adjust)(obd, qcids, qpids, rc, opc);
        RETURN(ret);
}

static inline int lquota_setinfo(quota_interface_t *interface,
                                 struct obd_device *obd,
                                 void *data)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, setinfo);
        rc = QUOTA_OP(interface, setinfo)(obd, data);
        RETURN(rc);
}

static inline int lquota_clearinfo(quota_interface_t *interface,
                                   struct obd_export *exp,
                                   struct obd_device *obd)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, clearinfo);
        rc = QUOTA_OP(interface, clearinfo)(exp, obd);
        RETURN(rc);
}

static inline int lquota_enforce(quota_interface_t *interface,
                                 struct obd_device *obd,
                                 unsigned int ignore)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, enforce);
        rc = QUOTA_OP(interface, enforce)(obd, ignore);
        RETURN(rc);
}

static inline int lquota_getflag(quota_interface_t *interface,
                                 struct obd_device *obd, struct obdo *oa)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, getflag);
        rc = QUOTA_OP(interface, getflag)(obd, oa);
        RETURN(rc);
}

#ifdef __KERNEL__
static inline int lquota_chkquota(quota_interface_t *interface,
                                  struct obd_device *obd,
                                  struct obd_export *exp,
                                  const unsigned int id[], int pending[],
                                  int count, struct obd_trans_info *oti,
                                  int isblk, void *data, int frags)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, chkquota);
        QUOTA_CHECK_OP(interface, acquire);
        rc = QUOTA_OP(interface, chkquota)(obd, exp, id, pending, count,
                                           QUOTA_OP(interface, acquire), oti,
                                           isblk, (struct inode *)data, frags);
        RETURN(rc);
}

static inline int lquota_pending_commit(quota_interface_t *interface,
                                        struct obd_device *obd,
                                        const unsigned int id[],
                                        int pending[], int isblk)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, pending_commit);
        rc = QUOTA_OP(interface, pending_commit)(obd, id, pending, isblk);
        RETURN(rc);
}
#endif

#ifndef __KERNEL__
#ifndef MAXQUOTAS
#define MAXQUOTAS 2
#endif

#ifndef USRQUOTA
#define USRQUOTA 0
#endif

#ifndef GRPQUOTA
#define GRPQUOTA 1
#endif

#endif

#define LUSTRE_ADMIN_QUOTAFILES_V2 {\
        "admin_quotafile_v2.usr",       /** user admin quotafile */\
        "admin_quotafile_v2.grp"        /** group admin quotafile */\
}

/*
 * Definitions of structures for vfsv0 quota format
 * Source linux/fs/quota/quotaio_v2.h
 *
 * The following definitions are normally found in private kernel headers.
 * However, some sites build Lustre against kernel development headers rather
 * than than full kernel source, so we provide them here for compatibility.
 */
#ifdef __KERNEL__
# if !defined(HAVE_QUOTAIO_H) && !defined(HAVE_FS_QUOTA_QUOTAIO_H) && \
     !defined(HAVE_FS_QUOTAIO_H)

#include <linux/types.h>
#include <linux/quota.h>

#define V2_INITQMAGICS {\
        0xd9c01f11,     /* USRQUOTA */\
        0xd9c01927      /* GRPQUOTA */\
}

/* Header with type and version specific information */
struct v2_disk_dqinfo {
        __le32 dqi_bgrace;      /* Time before block soft limit becomes hard limit */
        __le32 dqi_igrace;      /* Time before inode soft limit becomes hard limit */
        __le32 dqi_flags;       /* Flags for quotafile (DQF_*) */
        __le32 dqi_blocks;      /* Number of blocks in file */
        __le32 dqi_free_blk;    /* Number of first free block in the list */
        __le32 dqi_free_entry;  /* Number of block with at least one free entry */
};

/* First generic header */
struct v2_disk_dqheader {
        __le32 dqh_magic;       /* Magic number identifying file */
        __le32 dqh_version;     /* File version */
};
#define V2_DQINFOOFF    sizeof(struct v2_disk_dqheader) /* Offset of info header in file */
#define QT_TREEOFF      1                               /* Offset of tree in file in blocks */
#define V2_DQTREEOFF    QT_TREEOFF

# endif /* !defined(HAVE_QUOTAIO_V1_H) ... */
#endif  /* __KERNEL__ */

/** @} quota */

#endif /* _LUSTRE_QUOTA_H */
