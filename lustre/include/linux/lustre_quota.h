/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _LUSTRE_QUOTA_H
#define _LUSTRE_QUOTA_H

#ifdef __KERNEL__
# include <linux/version.h>
#endif
#include <linux/lustre_idl.h>

#ifdef HAVE_QUOTA_SUPPORT
#include <linux/lustre_realquota.h>
#else

struct lustre_mem_dqinfo {
};

struct lustre_quota_info {
};

struct lustre_dquot {
};


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

struct obd_device;

typedef int (*dqacq_handler_t) (struct obd_device * obd, struct qunit_data * qd,
                                int opc);

struct lustre_quota_ctxt {
};

struct lustre_qunit {
};

struct super_block;
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

struct quotacheck_info {
};

#define DQUOT_OFF(sb) do {} while(0)

#endif /*!HAVE_QUOTA_SUPPORT */
#endif                          /* _LUSTRE_QUOTA_H */
