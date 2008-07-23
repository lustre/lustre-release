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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _LUSTRE_QUOTA_H
#define _LUSTRE_QUOTA_H

#if defined(__linux__)
#include <linux/lustre_quota.h>
#elif defined(__APPLE__)
#include <darwin/lustre_quota.h>
#elif defined(__WINNT__)
#include <winnt/lustre_quota.h>
#else
#error Unsupported operating system.
#endif

#include <lustre/lustre_idl.h>
#include <lustre_net.h>
#include <lvfs.h>
#include <obd_support.h>

struct obd_device;
struct client_obd;

#ifndef NR_DQHASH
#define NR_DQHASH 45
#endif

#ifdef HAVE_QUOTA_SUPPORT

#ifdef __KERNEL__

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

#define DQ_STATUS_AVAIL         0x0     /* Available dquot */
#define DQ_STATUS_SET           0x01    /* Sombody is setting dquot */
#define DQ_STATUS_RECOVERY      0x02    /* dquot is in recovery */

struct lustre_mem_dqblk {
        __u64 dqb_bhardlimit;	/* absolute limit on disk blks alloc */
        __u64 dqb_bsoftlimit;	/* preferred limit on disk blks */
        __u64 dqb_curspace;	/* current used space */
        __u64 dqb_ihardlimit;	/* absolute limit on allocated inodes */
        __u64 dqb_isoftlimit;	/* preferred inode limit */
        __u64 dqb_curinodes;	/* current # allocated inodes */
        time_t dqb_btime;	/* time limit for excessive disk use */
        time_t dqb_itime;	/* time limit for excessive inode use */
};

struct lustre_dquot {
        /* Hash list in memory, protect by dquot_hash_lock */
        struct list_head dq_hash;
        /* Protect the data in lustre_dquot */
        struct semaphore dq_sem;
        /* Use count */
        int dq_refcnt;
        /* Pointer of quota info it belongs to */
        struct lustre_quota_info *dq_info;

        loff_t dq_off;                  /* Offset of dquot on disk */
        unsigned int dq_id;             /* ID this applies to (uid, gid) */
        int dq_type;                    /* Type fo quota (USRQUOTA, GRPQUOUTA) */
        unsigned short dq_status;       /* See DQ_STATUS_ */
        unsigned long dq_flags;         /* See DQ_ in quota.h */
        struct lustre_mem_dqblk dq_dqb; /* Diskquota usage */
};

struct dquot_id {
        struct list_head        di_link;
        __u32                   di_id;
};

#define QFILE_CHK               1
#define QFILE_RD_INFO           2
#define QFILE_WR_INFO           3
#define QFILE_INIT_INFO         4
#define QFILE_RD_DQUOT          5
#define QFILE_WR_DQUOT          6
#define QFILE_CONVERT           7

/* admin quotafile operations */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
int lustre_check_quota_file(struct lustre_quota_info *lqi, int type);
int lustre_read_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_write_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_read_dquot(struct lustre_dquot *dquot);
int lustre_commit_dquot(struct lustre_dquot *dquot);
int lustre_init_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_get_qids(struct file *file, struct inode *inode, int type,
                    struct list_head *list);
int lustre_quota_convert(struct lustre_quota_info *lqi, int type);
#else

#ifndef DQ_FAKE_B
#define DQ_FAKE_B       6
#endif

static inline int lustre_check_quota_file(struct lustre_quota_info *lqi,
                                          int type)
{
        return 0;
}
static inline int lustre_read_quota_info(struct lustre_quota_info *lqi,
                                         int type)
{
        return 0;
}
static inline int lustre_write_quota_info(struct lustre_quota_info *lqi,
                                          int type)
{
        return 0;
}
static inline int lustre_read_dquot(struct lustre_dquot *dquot)
{
        return 0;
}
static inline int lustre_commit_dquot(struct lustre_dquot *dquot)
{
        return 0;
}
static inline int lustre_init_quota_info(struct lustre_quota_info *lqi,
                                         int type)
{
        return 0;
}
static inline int lustre_quota_convert(struct lustre_quota_info *lqi,
                                       int type)
{
        return 0;
}
#endif  /* KERNEL_VERSION(2,5,0) */

#define LL_DQUOT_OFF(sb)    DQUOT_OFF(sb)

typedef int (*dqacq_handler_t) (struct obd_device * obd, struct qunit_data * qd,
                                int opc);

/* user quota is turned on on filter */
#define LQC_USRQUOTA_FLAG (1 << 0)
/* group quota is turned on on filter */
#define LQC_GRPQUOTA_FLAG (1 << 1)

#define UGQUOTA2LQC(id) ((Q_TYPEMATCH(id, USRQUOTA) ? LQC_USRQUOTA_FLAG : 0) | \
                         (Q_TYPEMATCH(id, GRPQUOTA) ? LQC_GRPQUOTA_FLAG : 0))

struct lustre_quota_ctxt {
        struct super_block *lqc_sb;     /* superblock this applies to */
        struct obd_import *lqc_import;  /* import used to send dqacq/dqrel RPC */
        dqacq_handler_t lqc_handler;    /* dqacq/dqrel RPC handler, only for quota master */
        unsigned long lqc_flags;        /* quota flags */
        unsigned long lqc_recovery:1,   /* Doing recovery */
                      lqc_switch_qs:1;  /* the function of change qunit size
                                         * 0:Off, 1:On */
        unsigned long lqc_iunit_sz;     /* original unit size of file quota and
                                         * upper limitation for adjust file
                                         * qunit */
        unsigned long lqc_itune_sz;     /* Trigger dqacq when available file
                                         * quota less than this value, trigger
                                         * dqrel when available file quota
                                         * more than this value + 1 iunit */
        unsigned long lqc_bunit_sz;     /* original unit size of block quota and
                                         * upper limitation for adjust block
                                         * qunit */
        unsigned long lqc_btune_sz;     /* See comment of lqc_itune_sz */
        struct lustre_class_hash_body *lqc_lqs_hash_body;
                                        /* all lustre_qunit_size structure in
                                         * it */
        /* the values below are relative to how master change its qunit sizes */
        unsigned long lqc_cqs_boundary_factor; /* this affects the boundary of
                                                * shrinking and enlarging qunit
                                                * size. default=4 */
        unsigned long lqc_cqs_least_bunit;  /* the least value of block qunit */
        unsigned long lqc_cqs_least_iunit;  /* the least value of inode qunit */
        unsigned long lqc_cqs_qs_factor;    /* when enlarging, qunit size will
                                             * mutilple it; when shrinking,
                                             * qunit size will divide it */
        int           lqc_switch_seconds;   /* avoid ping-pong effect of
                                             * adjusting qunit size. How many
                                             * seconds must be waited between
                                             * enlarging and shinking qunit */
        spinlock_t    lqc_lock;         /* guard lqc_imp_valid now */
};

#define LQC_HASH_BODY(qctxt) (qctxt->lqc_lqs_hash_body)

struct lustre_qunit_size {
        struct hlist_node lqs_hash; /* the hash entry */
        unsigned int lqs_id;        /* id of user/group */
        unsigned long lqs_flags;    /* is user/group; FULLBUF or LESSBUF */
        unsigned long lqs_iunit_sz; /* Unit size of file quota currently */
        unsigned long lqs_itune_sz; /* Trigger dqacq when available file quota
                                     * less than this value, trigger dqrel
                                     * when more than this value + 1 iunit */
        unsigned long lqs_bunit_sz; /* Unit size of block quota currently */
        unsigned long lqs_btune_sz; /* See comment of lqs itune sz */
        unsigned long lqs_bwrite_pending; /* the blocks reached ost and don't
                                           * finish */
        unsigned long lqs_iwrite_pending; /* the inodes reached mds and don't
                                           * finish */
        long long lqs_ino_rec;  /* when inodes are allocated/released,
                                 * this value will record it */
        long long lqs_blk_rec;  /* when blocks are allocated/released,
                                 * this value will record it */
        atomic_t lqs_refcount;
        cfs_time_t lqs_last_bshrink;   /* time of last block shrink */
        cfs_time_t lqs_last_ishrink;   /* time of last inode shrink */
        spinlock_t lqs_lock;
};

#define LQS_IS_GRP(lqs)    ((lqs)->lqs_flags & LQUOTA_FLAGS_GRP)
#define LQS_IS_ADJBLK(lqs) ((lqs)->lqs_flags & LQUOTA_FLAGS_ADJBLK)
#define LQS_IS_ADJINO(lqs) ((lqs)->lqs_flags & LQUOTA_FLAGS_ADJINO)

#define LQS_SET_GRP(lqs)    ((lqs)->lqs_flags |= LQUOTA_FLAGS_GRP)
#define LQS_SET_ADJBLK(lqs) ((lqs)->lqs_flags |= LQUOTA_FLAGS_ADJBLK)
#define LQS_SET_ADJINO(lqs) ((lqs)->lqs_flags |= LQUOTA_FLAGS_ADJINO)

static inline void lqs_getref(struct lustre_qunit_size *lqs)
{
        atomic_inc(&lqs->lqs_refcount);
}

static inline void lqs_putref(struct lustre_qunit_size *lqs)
{
        if (atomic_dec_and_test(&lqs->lqs_refcount)) {
                spin_lock(&lqs->lqs_lock);
                hlist_del_init(&lqs->lqs_hash);
                spin_unlock(&lqs->lqs_lock);
                OBD_FREE_PTR(lqs);
        }
}

static inline void lqs_initref(struct lustre_qunit_size *lqs)
{
        atomic_set(&lqs->lqs_refcount, 0);
}

#else

struct lustre_quota_info {
};

struct lustre_quota_ctxt {
};

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
        struct obd_export   *qta_exp;   /* obd export */
        struct obd_quotactl  qta_oqctl; /* obd_quotactl args */
        struct super_block  *qta_sb;    /* obd super block */
        atomic_t            *qta_sem;   /* obt_quotachecking */
};

typedef int (*quota_acquire)(struct obd_device *obd,
                             unsigned int uid, unsigned int gid);

typedef struct {
        int (*quota_init) (void);
        int (*quota_exit) (void);
        int (*quota_setup) (struct obd_device *);
        int (*quota_cleanup) (struct obd_device *);
        /* For quota master, close admin quota files */
        int (*quota_fs_cleanup) (struct obd_device *);
        int (*quota_ctl) (struct obd_export *, struct obd_quotactl *);
        int (*quota_check) (struct obd_export *, struct obd_quotactl *);
        int (*quota_recovery) (struct obd_device *);

        /* For quota master/slave, adjust quota limit after fs operation */
        int (*quota_adjust) (struct obd_device *, unsigned int[],
                             unsigned int[], int, int);

        /* For quota slave, set import, trigger quota recovery */
        int (*quota_setinfo) (struct obd_export *, struct obd_device *);

        /* For quota slave, clear import when relative import is invalid */
        int (*quota_clearinfo) (struct obd_export *, struct obd_device *);

        /* For quota slave, set proper thread resoure capability */
        int (*quota_enforce) (struct obd_device *, unsigned int);

        /* For quota slave, check whether specified uid/gid is over quota */
        int (*quota_getflag) (struct obd_device *, struct obdo *);

        /* For quota slave, acquire/release quota from master if needed */
        int (*quota_acquire) (struct obd_device *, unsigned int, unsigned int);

        /* For quota slave, check whether specified uid/gid's remaining quota
         * can finish a block_write or inode_create rpc. It updates the pending
         * record of block and inode, acquires quota if necessary */
        int (*quota_chkquota) (struct obd_device *, unsigned int, unsigned int,
                               int, int *, quota_acquire);

        /* For quota client, poll if the quota check done */
        int (*quota_poll_check) (struct obd_export *, struct if_quotacheck *);

        /* For quota client, check whether specified uid/gid is over quota */
        int (*quota_chkdq) (struct client_obd *, unsigned int, unsigned int);

        /* For quota client, the actions after the pending write is committed */
        int (*quota_pending_commit) (struct obd_device *, unsigned int,
                                     unsigned int, int);

        /* For quota client, set over quota flag for specifed uid/gid */
        int (*quota_setdq) (struct client_obd *, unsigned int, unsigned int,
                            obd_flag, obd_flag);

        /* For adjusting qunit size b=10600 */
        int (*quota_adjust_qunit) (struct obd_export *exp, struct
                                   quota_adjust_qunit *oqaq);

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

static inline int lquota_adjust(quota_interface_t *interface,
                                struct obd_device *obd,
                                unsigned int qcids[],
                                unsigned int qpids[],
                                int rc, int opc)
{
        int ret;
        ENTRY;

        QUOTA_CHECK_OP(interface, adjust);
        ret = QUOTA_OP(interface, adjust)(obd, qcids, qpids, rc, opc);
        RETURN(ret);
}

static inline int lquota_chkdq(quota_interface_t *interface,
                               struct client_obd *cli,
                               unsigned int uid, unsigned int gid)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, chkdq);
        rc = QUOTA_OP(interface, chkdq)(cli, uid, gid);
        RETURN(rc);
}

static inline int lquota_setdq(quota_interface_t *interface,
                               struct client_obd *cli,
                               unsigned int uid, unsigned int gid,
                               obd_flag valid, obd_flag flags)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, setdq);
        rc = QUOTA_OP(interface, setdq)(cli, uid, gid, valid, flags);
        RETURN(rc);
}

static inline int lquota_poll_check(quota_interface_t *interface,
                                    struct obd_export *exp,
                                    struct if_quotacheck *qchk)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, poll_check);
        rc = QUOTA_OP(interface, poll_check)(exp, qchk);
        RETURN(rc);
}

static inline int lquota_setinfo(quota_interface_t *interface,
                                 struct obd_export *exp,
                                 struct obd_device *obd)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, setinfo);
        rc = QUOTA_OP(interface, setinfo)(exp, obd);
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

static inline int lquota_acquire(quota_interface_t *interface,
                                 struct obd_device *obd,
                                 unsigned int uid, unsigned int gid)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, acquire);
        rc = QUOTA_OP(interface, acquire)(obd, uid, gid);
        RETURN(rc);
}

static inline int lquota_chkquota(quota_interface_t *interface,
                                  struct obd_device *obd,
                                  unsigned int uid, unsigned int gid,
                                  int count, int *flag)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, chkquota);
        QUOTA_CHECK_OP(interface, acquire);
        rc = QUOTA_OP(interface, chkquota)(obd, uid, gid, count, flag,
                                           QUOTA_OP(interface, acquire));
        RETURN(rc);
}

static inline int lquota_pending_commit(quota_interface_t *interface,
                                        struct obd_device *obd,
                                        unsigned int uid, unsigned int gid,
                                        int npage)
{
        int rc;
        ENTRY;

        QUOTA_CHECK_OP(interface, pending_commit);
        rc = QUOTA_OP(interface, pending_commit)(obd, uid, gid, npage);
        RETURN(rc);
}

int lprocfs_quota_rd_bunit(char *page, char **start, off_t off, int count,
                           int *eof, void *data);
int lprocfs_quota_wr_bunit(struct file *file, const char *buffer,
                           unsigned long count, void *data);
int lprocfs_quota_rd_btune(char *page, char **start, off_t off, int count,
                           int *eof, void *data);
int lprocfs_quota_wr_btune(struct file *file, const char *buffer,
                           unsigned long count, void *data);
int lprocfs_quota_rd_iunit(char *page, char **start, off_t off, int count,
                           int *eof, void *data);
int lprocfs_quota_wr_iunit(struct file *file, const char *buffer,
                           unsigned long count, void *data);
int lprocfs_quota_rd_itune(char *page, char **start, off_t off, int count,
                           int *eof, void *data);
int lprocfs_quota_wr_itune(struct file *file, const char *buffer,
                           unsigned long count, void *data);
int lprocfs_quota_rd_type(char *page, char **start, off_t off, int count,
                          int *eof, void *data);
int lprocfs_quota_wr_type(struct file *file, const char *buffer,
                          unsigned long count, void *data);
int lprocfs_quota_rd_switch_seconds(char *page, char **start, off_t off,
                                    int count, int *eof, void *data);
int lprocfs_quota_wr_switch_seconds(struct file *file, const char *buffer,
                                    unsigned long count, void *data);

#ifndef __KERNEL__
extern quota_interface_t osc_quota_interface;
extern quota_interface_t mdc_quota_interface;
extern quota_interface_t lov_quota_interface;
#endif

#define LUSTRE_ADMIN_QUOTAFILES_V1 {\
        "admin_quotafile.usr",	/* user admin quotafile */\
        "admin_quotafile.grp"	/* group admin quotafile */\
}

#define LUSTRE_ADMIN_QUOTAFILES_V2 {\
        "admin_quotafile_v2.usr",       /* user admin quotafile */\
        "admin_quotafile_v2.grp"        /* group admin quotafile */\
}

#endif /* _LUSTRE_QUOTA_H */
