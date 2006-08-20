/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/quota/quota_interface.c
 *
 *  Copyright (c) 2001-2005 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   No redistribution or use is permitted outside of Cluster File Systems, Inc.
 *
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/init.h>
# include <linux/fs.h>
# include <linux/jbd.h>
# include <linux/ext3_fs.h>
# include <linux/parser.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/smp_lock.h>
#  include <linux/buffer_head.h>
#  include <linux/workqueue.h>
#  include <linux/mount.h>
# else
#  include <linux/locks.h>
# endif
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_mds.h>
#include <lustre_dlm.h>
#include <lustre_cfg.h>
#include <obd_ost.h>
#include <lustre_fsfilt.h>
#include <lustre_quota.h>
#include "quota_internal.h"


#ifdef __KERNEL__
extern unsigned long default_bunit_sz;
extern unsigned long default_btune_ratio;
extern unsigned long default_iunit_sz;
extern unsigned long default_itune_ratio;

enum {
        Opt_quotaon, Opt_iunit_sz, Opt_bunit_sz,
        Opt_itune_ratio, Opt_btune_ratio, Opt_err,
};

static match_table_t tokens = {
        {Opt_quotaon, "quotaon=%10s"},
        {Opt_iunit_sz, "iunit=%u"},
        {Opt_bunit_sz, "bunit=%u"},
        {Opt_itune_ratio, "itune=%u"},
        {Opt_btune_ratio, "btune=%u"},
        {Opt_err, NULL}
};

static int
quota_parse_config_args(char *options, int *quotaon, int *type,
                        struct lustre_quota_ctxt *qctxt)
{
        char *opt;
        substring_t args[MAX_OPT_ARGS];
        int option;
        int rc = 0;
        unsigned long iunit = 0, bunit = 0, itune = 0, btune = 0;
        ENTRY;

        while ((opt = strsep (&options, ",")) != NULL) {
                int token;
                if (!*opt)
                        continue;

                token = match_token(opt, tokens, args);
                switch(token) {
                case Opt_quotaon: {
                        char *quota_type = match_strdup(&args[0]);
                        if (!quota_type)
                                GOTO(out, rc = -EINVAL);

                        *quotaon = 1;
                        if (strchr(quota_type, 'u') && strchr(quota_type, 'g'))
                                *type = UGQUOTA;
                        else if (strchr(quota_type, 'u'))
                                *type = USRQUOTA;
                        else if (strchr(quota_type, 'g'))
                                *type = GRPQUOTA;
                        else {
                                *quotaon = 0;
                                rc = -EINVAL;
                        }
                        break;
                }
                case Opt_iunit_sz:
                        if (match_int(&args[0], &option))
                                rc = -EINVAL;
                        iunit = option;
                        break;
                case Opt_bunit_sz:
                        if (match_int(&args[0], &option))
                                rc = -EINVAL;
                        bunit = option;
                        break;
                case Opt_itune_ratio:
                        if (match_int(&args[0], &option) ||
                            option <= 0 || option >= 100)
                                rc = -EINVAL;
                        itune = option;
                        break;
                case Opt_btune_ratio:
                        if (match_int(&args[0], &option) ||
                            option <= 0 || option >= 100)
                                rc = -EINVAL;
                        btune = option;
                        break;
                default:
                        rc = -EINVAL;
                }

                if (rc)
                        GOTO(out, rc);
        }

        /* adjust the tunables of qunits based on quota config args */
        if (iunit)
                qctxt->lqc_iunit_sz = iunit;
        if (itune)
                qctxt->lqc_itune_sz = qctxt->lqc_iunit_sz *
                                      itune / 100;
        else
                qctxt->lqc_itune_sz = qctxt->lqc_iunit_sz *
                                      default_itune_ratio / 100;
        if (bunit)
                qctxt->lqc_bunit_sz = bunit << 20;
        if (btune)
                qctxt->lqc_btune_sz = ((qctxt->lqc_bunit_sz >> 20) *
                                        btune / 100) << 20;
        else
                qctxt->lqc_btune_sz = ((qctxt->lqc_bunit_sz >> 20) *
                                        default_btune_ratio / 100) << 20;

        CDEBUG(D_INFO, "iunit=%lu bunit=%lu itune=%lu btune=%lu\n",
               qctxt->lqc_iunit_sz, qctxt->lqc_bunit_sz,
               qctxt->lqc_itune_sz, qctxt->lqc_btune_sz);
        EXIT;

 out:
        if (rc)
                CERROR("quota config args parse error!(rc = %d) usage: "
                "--quota quotaon=u|g|ug,iunit=100,bunit=100,itune=50,btune=50\n",
                 rc);

        return rc;
}

static int auto_quota_on(struct obd_device *obd, int type,
                         struct super_block *sb, int is_master)
{
        struct obd_quotactl *oqctl;
        struct lvfs_run_ctxt saved;
        int rc;
        ENTRY;

        LASSERT(type == USRQUOTA || type == GRPQUOTA || type == UGQUOTA);

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl)
                RETURN(-ENOMEM);

        oqctl->qc_type = type;
        oqctl->qc_cmd = Q_QUOTAON;
        oqctl->qc_id = QFMT_LDISKFS;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if (!is_master)
                goto local_quota;

        /* turn on cluster wide quota */
        rc = mds_admin_quota_on(obd, oqctl);
        if (rc) {
                CERROR("auto enable admin quota error! err = %d\n", rc);
                GOTO(out_pop, rc);
        }
local_quota:
        /* turn on local quota */
        rc = fsfilt_quotactl(obd, sb, oqctl);
        CDEBUG(rc ? D_ERROR : D_INFO, "auto-enable quota. rc=%d\n", rc);
        if (rc && is_master)
                mds_quota_off(obd, oqctl);
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

static int mds_auto_quota_on(struct obd_device *obd, int type)
{
        int rc;
        ENTRY;
        rc = auto_quota_on(obd, type, obd->u.obt.obt_sb, 1);
        RETURN(rc);
}

static int filter_auto_quota_on(struct obd_device *obd, int type)
{
        int rc = 0;
        ENTRY;
        rc = auto_quota_on(obd, type, obd->u.obt.obt_sb, 0);
        RETURN(rc);
}

static int filter_quota_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int rc = 0;
        struct obd_device_target *obt = &obd->u.obt;
        ENTRY;

        atomic_set(&obt->obt_quotachecking, 1);
        rc = qctxt_init(&obt->obt_qctxt, obt->obt_sb, NULL);
        if (rc) {
                CERROR("initialize quota context failed! (rc:%d)\n", rc);
                RETURN(rc);
        }

        /* Based on quota config args, set qunit sizes and enable quota */
        if (LUSTRE_CFG_BUFLEN(lcfg, 5) > 0 && lustre_cfg_buf(lcfg, 5)) {
                char *args = lustre_cfg_string(lcfg, 5);
                int quotaon = 0, type;
                int err = 0;

                err = quota_parse_config_args(args, &quotaon, &type,
                                              &obd->u.obt.obt_qctxt);
                if (!err && quotaon)
                        filter_auto_quota_on(obd, type);
        }

        RETURN(rc);
}

static int filter_quota_cleanup(struct obd_device *obd)
{
        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        return 0;
}

static int filter_quota_setinfo(struct obd_export *exp, struct obd_device *obd)
{
        /* setup the quota context import */
        obd->u.obt.obt_qctxt.lqc_import = exp->exp_imp_reverse;
        /* start quota slave recovery thread. (release high limits) */
        qslave_start_recovery(obd, &obd->u.obt.obt_qctxt);
        return 0;
}
static int filter_quota_enforce(struct obd_device *obd, unsigned int ignore)
{
        ENTRY;

        if (!sb_any_quota_enabled(obd->u.obt.obt_sb))
                RETURN(0);

        if (ignore)
                cap_raise(current->cap_effective, CAP_SYS_RESOURCE);
        else
                cap_lower(current->cap_effective, CAP_SYS_RESOURCE);

        RETURN(0);
}

static int filter_quota_getflag(struct obd_device *obd, struct obdo *oa)
{
        struct obd_device_target *obt = &obd->u.obt;
        int err, cnt, rc = 0;
        struct obd_quotactl *oqctl;
        ENTRY;

        if (!sb_any_quota_enabled(obt->obt_sb))
                RETURN(0);

        oa->o_flags &= ~(OBD_FL_NO_USRQUOTA | OBD_FL_NO_GRPQUOTA);

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl) {
                CERROR("Not enough memory!");
                RETURN(-ENOMEM);
        }

        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                memset(oqctl, 0, sizeof(*oqctl));

                oqctl->qc_cmd = Q_GETQUOTA;
                oqctl->qc_type = cnt;
                oqctl->qc_id = (cnt == USRQUOTA) ? oa->o_uid : oa->o_gid;
                err = fsfilt_quotactl(obd, obt->obt_sb, oqctl);
                if (err) {
                        if (!rc)
                                rc = err;
                        continue;
                }

                /* set over quota flags for a uid/gid */
                oa->o_valid |= (cnt == USRQUOTA) ?
                               OBD_MD_FLUSRQUOTA : OBD_MD_FLGRPQUOTA;
                if (oqctl->qc_dqblk.dqb_bhardlimit &&
                   (toqb(oqctl->qc_dqblk.dqb_curspace) >
                    oqctl->qc_dqblk.dqb_bhardlimit))
                        oa->o_flags |= (cnt == USRQUOTA) ?
                                OBD_FL_NO_USRQUOTA : OBD_FL_NO_GRPQUOTA;
        }
        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

static int filter_quota_acquire(struct obd_device *obd, unsigned int uid,
                                unsigned int gid)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc;
        ENTRY;

        rc = qctxt_adjust_qunit(obd, qctxt, uid, gid, 1, 1);
        RETURN(rc == -EAGAIN);
}

static int mds_quota_init(void)
{
        return lustre_dquot_init();
}

static int mds_quota_exit(void)
{
        lustre_dquot_exit();
        return 0;
}

static int mds_quota_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct mds_obd *mds = &obd->u.mds;
        int rc;
        ENTRY;

        atomic_set(&obt->obt_quotachecking, 1);
        /* initialize quota master and quota context */
        sema_init(&mds->mds_qonoff_sem, 1);
        rc = qctxt_init(&obt->obt_qctxt, obt->obt_sb, dqacq_handler);
        if (rc) {
                CERROR("initialize quota context failed! (rc:%d)\n", rc);
                RETURN(rc);
        }

        /* Based on quota config args, set qunit sizes and enable quota */
        if (LUSTRE_CFG_BUFLEN(lcfg, 5) > 0 && lustre_cfg_buf(lcfg, 5)) {
                char *args = lustre_cfg_string(lcfg, 5);
                int quotaon = 0, type;
                int err;

                err = quota_parse_config_args(args, &quotaon, &type,
                                              &obt->obt_qctxt);
                if (!err && quotaon)
                        mds_auto_quota_on(obd, type);
        }
        RETURN(rc);
}

static int mds_quota_cleanup(struct obd_device *obd)
{
        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        RETURN(0);
}

static int mds_quota_fs_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int i;
        ENTRY;

        /* close admin quota files */
        down(&mds->mds_qonoff_sem);
        for (i = 0; i < MAXQUOTAS; i++) {
                if (mds->mds_quota_info.qi_files[i]) {
                        filp_close(mds->mds_quota_info.qi_files[i], 0);
                        mds->mds_quota_info.qi_files[i] = NULL;
                }
        }
        up(&mds->mds_qonoff_sem);
        RETURN(0);
}
#endif /* __KERNEL__ */

struct osc_quota_info {
        struct list_head        oqi_hash;       /* hash list */
        struct client_obd      *oqi_cli;        /* osc obd */
        unsigned int            oqi_id;         /* uid/gid of a file */
        short                   oqi_type;       /* quota type */
};

spinlock_t qinfo_list_lock = SPIN_LOCK_UNLOCKED;

static struct list_head qinfo_hash[NR_DQHASH];
/* SLAB cache for client quota context */
cfs_mem_cache_t *qinfo_cachep = NULL;

static inline int const hashfn(struct client_obd *cli,
                               unsigned long id,
                               int type)
{
        unsigned long tmp = ((unsigned long)cli>>6) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

/* caller must hold qinfo_list_lock */
static inline void insert_qinfo_hash(struct osc_quota_info *oqi)
{
        struct list_head *head = qinfo_hash +
                hashfn(oqi->oqi_cli, oqi->oqi_id, oqi->oqi_type);

        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        list_add(&oqi->oqi_hash, head);
}

/* caller must hold qinfo_list_lock */
static inline void remove_qinfo_hash(struct osc_quota_info *oqi)
{
        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        list_del_init(&oqi->oqi_hash);
}

/* caller must hold qinfo_list_lock */
static inline struct osc_quota_info *find_qinfo(struct client_obd *cli,
                                                unsigned int id, int type)
{
        unsigned int hashent = hashfn(cli, id, type);
        struct osc_quota_info *oqi;

        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        list_for_each_entry(oqi, &qinfo_hash[hashent], oqi_hash) {
                if (oqi->oqi_cli == cli &&
                    oqi->oqi_id == id && oqi->oqi_type == type)
                        return oqi;
        }
        return NULL;
}

static struct osc_quota_info *alloc_qinfo(struct client_obd *cli,
                                          unsigned int id, int type)
{
        struct osc_quota_info *oqi;
        ENTRY;

        OBD_SLAB_ALLOC(oqi, qinfo_cachep, CFS_ALLOC_STD, sizeof(*oqi));
        if(!oqi)
                RETURN(NULL);

        INIT_LIST_HEAD(&oqi->oqi_hash);
        oqi->oqi_cli = cli;
        oqi->oqi_id = id;
        oqi->oqi_type = type;

        RETURN(oqi);
}

static void free_qinfo(struct osc_quota_info *oqi)
{
        OBD_SLAB_FREE(oqi, qinfo_cachep, sizeof(*oqi));
}

int osc_quota_chkdq(struct client_obd *cli,
                    unsigned int uid, unsigned int gid)
{
        unsigned int id;
        int cnt, rc = QUOTA_OK;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi = NULL;

                id = (cnt == USRQUOTA) ? uid : gid;
                oqi = find_qinfo(cli, id, cnt);
                if (oqi) {
                        rc = NO_QUOTA;
                        break;
                }
        }
        spin_unlock(&qinfo_list_lock);

        RETURN(rc);
}

int osc_quota_setdq(struct client_obd *cli,
                    unsigned int uid, unsigned int gid,
                    obd_flag valid, obd_flag flags)
{
        unsigned int id;
        obd_flag noquota;
        int cnt, rc = 0;
        ENTRY;


        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi, *old;

                if (!(valid & ((cnt == USRQUOTA) ?
                    OBD_MD_FLUSRQUOTA : OBD_MD_FLGRPQUOTA)))
                        continue;

                id = (cnt == USRQUOTA) ? uid : gid;
                noquota = (cnt == USRQUOTA) ?
                    (flags & OBD_FL_NO_USRQUOTA) : (flags & OBD_FL_NO_GRPQUOTA);

                oqi = alloc_qinfo(cli, id, cnt);
                if (oqi) {
                        spin_lock(&qinfo_list_lock);

                        old = find_qinfo(cli, id, cnt);
                        if (old && !noquota)
                                remove_qinfo_hash(old);
                        else if (!old && noquota)
                                insert_qinfo_hash(oqi);

                        spin_unlock(&qinfo_list_lock);

                        if (old || !noquota)
                                free_qinfo(oqi);
                        if (old && !noquota)
                                free_qinfo(old);
                } else {
                        CERROR("not enough mem!\n");
                        rc = -ENOMEM;
                        break;
                }
        }

        RETURN(rc);
}

int osc_quota_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        struct osc_quota_info *oqi, *n;
        int i;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        if (oqi->oqi_cli != cli)
                                continue;
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        spin_unlock(&qinfo_list_lock);

        RETURN(0);
}

int osc_quota_init(void)
{
        int i;
        ENTRY;

        LASSERT(qinfo_cachep == NULL);
        qinfo_cachep = cfs_mem_cache_create("osc_quota_info",
                                         sizeof(struct osc_quota_info),
                                         0, 0);
        if (!qinfo_cachep)
                RETURN(-ENOMEM);

        for (i = 0; i < NR_DQHASH; i++)
                INIT_LIST_HEAD(qinfo_hash + i);

        RETURN(0);
}

int osc_quota_exit(void)
{
        struct osc_quota_info *oqi, *n;
        int i, rc;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        spin_unlock(&qinfo_list_lock);

        rc = cfs_mem_cache_destroy(qinfo_cachep);
        LASSERTF(rc == 0, "couldn't destory qinfo_cachep slab\n");
        qinfo_cachep = NULL;

        RETURN(0);
}

#ifdef __KERNEL__
quota_interface_t mds_quota_interface = {
        .quota_init     = mds_quota_init,
        .quota_exit     = mds_quota_exit,
        .quota_setup    = mds_quota_setup,
        .quota_cleanup  = mds_quota_cleanup,
        .quota_check    = target_quota_check,
        .quota_ctl      = mds_quota_ctl,
        .quota_fs_cleanup       =mds_quota_fs_cleanup,
        .quota_recovery = mds_quota_recovery,
        .quota_adjust   = mds_quota_adjust,
};

quota_interface_t filter_quota_interface = {
        .quota_setup    = filter_quota_setup,
        .quota_cleanup  = filter_quota_cleanup,
        .quota_check    = target_quota_check,
        .quota_ctl      = filter_quota_ctl,
        .quota_setinfo  = filter_quota_setinfo,
        .quota_enforce  = filter_quota_enforce,
        .quota_getflag  = filter_quota_getflag,
        .quota_acquire  = filter_quota_acquire,
        .quota_adjust   = filter_quota_adjust,
};
#endif /* __KERNEL__ */

quota_interface_t mdc_quota_interface = {
        .quota_ctl      = client_quota_ctl,
        .quota_check    = client_quota_check,
        .quota_poll_check = client_quota_poll_check,
};

quota_interface_t osc_quota_interface = {
        .quota_ctl      = client_quota_ctl,
        .quota_check    = client_quota_check,
        .quota_poll_check = client_quota_poll_check,
        .quota_init     = osc_quota_init,
        .quota_exit     = osc_quota_exit,
        .quota_chkdq    = osc_quota_chkdq,
        .quota_setdq    = osc_quota_setdq,
        .quota_cleanup  = osc_quota_cleanup,
};

quota_interface_t lov_quota_interface = {
        .quota_check    = lov_quota_check,
        .quota_ctl      = lov_quota_ctl,
};

#ifdef __KERNEL__
static int __init init_lustre_quota(void)
{
        int rc = qunit_cache_init();
        if (rc)
                return rc;
        PORTAL_SYMBOL_REGISTER(filter_quota_interface);
        PORTAL_SYMBOL_REGISTER(mds_quota_interface);
        PORTAL_SYMBOL_REGISTER(mdc_quota_interface);
        PORTAL_SYMBOL_REGISTER(osc_quota_interface);
        PORTAL_SYMBOL_REGISTER(lov_quota_interface);
        return 0;
}

static void /*__exit*/ exit_lustre_quota(void)
{
        PORTAL_SYMBOL_UNREGISTER(filter_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(mds_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(mdc_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(osc_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(lov_quota_interface);

        qunit_cache_cleanup();
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Quota");
MODULE_LICENSE("GPL");

cfs_module(lquota, "1.0.0", init_lustre_quota, exit_lustre_quota);

EXPORT_SYMBOL(mds_quota_interface);
EXPORT_SYMBOL(filter_quota_interface);
EXPORT_SYMBOL(mdc_quota_interface);
EXPORT_SYMBOL(osc_quota_interface);
EXPORT_SYMBOL(lov_quota_interface);
#endif /* __KERNEL */
