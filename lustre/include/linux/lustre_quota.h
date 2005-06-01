/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _LUSTRE_QUOTA_H
#define _LUSTRE_QUOTA_H

#ifdef __KERNEL__
# include <linux/version.h>
#endif
#include <linux/quota.h>
#include <linux/lustre_idl.h>

#define QUSG(count, isblk)      (isblk ? toqb(count) : count)

/* If the (quota limit < qunit * slave count), the slave which can't
 * acquire qunit should set it's local limit as MIN_QLIMIT */
#define MIN_QLIMIT      1

#ifndef NR_DQHASH
#define NR_DQHASH 45
#endif

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
        struct semaphore qi_sem;
        struct file *qi_files[MAXQUOTAS];
        struct lustre_mem_dqinfo qi_info[MAXQUOTAS];
};

#ifdef __KERNEL__
struct lustre_dquot {
        struct list_head dq_hash;
        struct list_head dq_unused;

        /* this semaphore is unused until we implement wb dquot cache */
        struct semaphore dq_sem;
        atomic_t dq_refcnt;

        struct lustre_quota_info *dq_info;
        loff_t dq_off;
        unsigned int dq_id;
        int dq_type;
        unsigned long dq_flags;
        struct mem_dqblk dq_dqb;
};
#endif

#define QFILE_CHK               1
#define QFILE_RD_INFO           2
#define QFILE_WR_INFO           3
#define QFILE_INIT_INFO         4
#define QFILE_RD_DQUOT          5
#define QFILE_WR_DQUOT          6

/* admin quotafile operations */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
int lustre_check_quota_file(struct lustre_quota_info *lqi, int type);
int lustre_read_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_write_quota_info(struct lustre_quota_info *lqi, int type);
#ifdef __KERNEL__
int lustre_read_dquot(struct lustre_dquot *dquot);
int lustre_commit_dquot(struct lustre_dquot *dquot);
#endif
int lustre_init_quota_info(struct lustre_quota_info *lqi, int type);

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
#ifdef __KERNEL__
static inline int lustre_read_dquot(struct lustre_dquot *dquot)
{
        return 0;
}
static inline int lustre_commit_dquot(struct lustre_dquot *dquot)
{
        return 0;
}
#endif
static inline int lustre_init_quota_info(struct lustre_quota_info *lqi,
                                         int type)
{
        return 0;
}
#endif                          /* KERNEL_VERSION(2,5,0) */

/* quota context structures */
struct obd_device;
typedef int (*dqacq_handler_t) (struct obd_device * obd, struct qunit_data * qd,
                                int opc);

struct lustre_quota_ctxt {
        struct super_block *lqc_sb;
        struct obd_import *lqc_import;
        dqacq_handler_t lqc_handler;
        unsigned long lqc_flags;
        unsigned long lqc_iunit_sz;
        unsigned long lqc_itune_sz;
        unsigned long lqc_bunit_sz;
        unsigned long lqc_btune_sz;
};

struct lustre_qunit {
        struct list_head lq_hash;
        atomic_t lq_refcnt;
        struct lustre_quota_ctxt *lq_ctxt;
        struct qunit_data lq_data;
        unsigned int lq_opc;
        struct list_head lq_waiters;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
int qctxt_init(struct lustre_quota_ctxt *qctxt, struct super_block *sb,
               dqacq_handler_t handler);
void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force);
int qctxt_adjust_qunit(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                       uid_t uid, gid_t gid, __u32 isblk);
int qctxt_wait_on_dqacq(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                        uid_t uid, gid_t gid, __u32 isblk);
#else
static inline int qctxt_init(struct lustre_quota_ctxt *qctxt,
                             struct super_block *sb, dqacq_handler_t handler)
{
        return 0;
}
static inline void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force)
{
        return;
}
static inline int qctxt_adjust_qunit(struct obd_device *obd,
                                     struct lustre_quota_ctxt *qctxt,
                                     uid_t uid, gid_t gid, __u32 isblk)
{
        return 0;
}
static inline int qctxt_wait_on_dqacq(struct obd_device *obd,
                                      struct lustre_quota_ctxt *qctxt,
                                      uid_t uid, gid_t gid, __u32 isblk)
{
        return 0;
}
#endif                          /* KERNEL_VERSION(2,5,0) */

/* quota check & quotactl */
#define LUSTRE_ADMIN_QUOTAFILES {\
	"admin_quotafile.usr",	/* user admin quotafile */\
	"admin_quotafile.grp"	/* group admin quotafile */\
}

struct quotacheck_info {
        struct completion qi_starting;
        struct obd_export *qi_exp;
        struct obd_quotactl qi_oqctl;
};

#endif                          /* _LUSTRE_QUOTA_H */
