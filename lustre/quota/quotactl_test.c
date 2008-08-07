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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/quota/quotactl_test.c
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/init.h>

#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <lustre_mds.h>
#include <obd_ost.h>

static struct obd_quotactl oqctl;

/* Test quotaon */
static int quotactl_test_1(struct obd_device *obd, struct super_block *sb)
{
        int rc;
        ENTRY;

        oqctl.qc_cmd = Q_QUOTAON;
        oqctl.qc_id = QFMT_LDISKFS;
        oqctl.qc_type = UGQUOTA;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc)
                CERROR("1a: quotactl Q_QUOTAON failed: %d\n", rc);
        RETURN(rc);
}

#if 0 /* set/getinfo not supported, this is for cluster-wide quotas */
/* Test set/getinfo */
static int quotactl_test_2(struct obd_device *obd, struct super_block *sb)
{
        struct obd_quotactl oqctl;
        int rc;
        ENTRY;

        oqctl.qc_cmd = Q_SETINFO;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_dqinfo.dqi_bgrace = 1616;
        oqctl.qc_dqinfo.dqi_igrace = 2828;
        oqctl.qc_dqinfo.dqi_flags = 0;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("2a: quotactl Q_SETINFO failed: %d\n", rc);
                RETURN(rc);
        }

        oqctl.qc_cmd = Q_GETINFO;
        oqctl.qc_type = USRQUOTA;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("2b: quotactl Q_GETINFO failed: %d\n", rc);
                RETURN(rc);
        }
        if (oqctl.qc_dqinfo.dqi_bgrace != 1616 ||
            oqctl.qc_dqinfo.dqi_igrace != 2828 ||
            oqctl.qc_dqinfo.dqi_flags != 0) {
                CERROR("2c: quotactl Q_GETINFO get wrong result: %d, %d, %d\n",
                       oqctl.qc_dqinfo.dqi_bgrace,
                       oqctl.qc_dqinfo.dqi_igrace,
                       oqctl.qc_dqinfo.dqi_flags);
                RETURN(-EINVAL);
        }

        RETURN(0);
}
#endif

/* Test set/getquota */
static int quotactl_test_3(struct obd_device *obd, struct super_block *sb)
{
        int rc;
        ENTRY;

        oqctl.qc_cmd = Q_SETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_id = 500;
        oqctl.qc_dqblk.dqb_bhardlimit = 919;
        oqctl.qc_dqblk.dqb_bsoftlimit = 818;
        oqctl.qc_dqblk.dqb_ihardlimit = 616;
        oqctl.qc_dqblk.dqb_isoftlimit = 515;
        oqctl.qc_dqblk.dqb_valid = QIF_LIMITS;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3a: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }

        oqctl.qc_cmd = Q_GETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_id = 500;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3b: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }
        if (oqctl.qc_dqblk.dqb_bhardlimit != 919 ||
            oqctl.qc_dqblk.dqb_bsoftlimit != 818 ||
            oqctl.qc_dqblk.dqb_ihardlimit != 616 ||
            oqctl.qc_dqblk.dqb_isoftlimit != 515) {
                CERROR("3c: quotactl Q_GETQUOTA get wrong result:"
                       LPU64", "LPU64", "LPU64", "LPU64"\n",
                       oqctl.qc_dqblk.dqb_bhardlimit,
                       oqctl.qc_dqblk.dqb_bsoftlimit,
                       oqctl.qc_dqblk.dqb_ihardlimit,
                       oqctl.qc_dqblk.dqb_isoftlimit);
                RETURN(-EINVAL);
        }

        oqctl.qc_cmd = Q_SETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_id = 500;
        oqctl.qc_dqblk.dqb_curspace = 717;
        oqctl.qc_dqblk.dqb_curinodes = 414;
        oqctl.qc_dqblk.dqb_valid = QIF_USAGE;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3d: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }

        oqctl.qc_cmd = Q_GETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_id = 500;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3e: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }
        if (oqctl.qc_dqblk.dqb_curspace != 717 ||
            oqctl.qc_dqblk.dqb_curinodes != 414) {
                CERROR("3f: quotactl Q_GETQUOTA get wrong result: "
                       LPU64", "LPU64"\n", oqctl.qc_dqblk.dqb_curspace,
                       oqctl.qc_dqblk.dqb_curinodes);
                RETURN(-EINVAL);
        }

        oqctl.qc_cmd = Q_SETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_dqblk.dqb_btime = 313;
        oqctl.qc_dqblk.dqb_itime = 212;
        oqctl.qc_id = 500;
        oqctl.qc_dqblk.dqb_valid = QIF_TIMES;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3g: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }

        oqctl.qc_cmd = Q_GETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_id = 500;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3h: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }
        if (oqctl.qc_dqblk.dqb_btime != 313 ||
            oqctl.qc_dqblk.dqb_itime != 212) {
                CERROR("3i: quotactl Q_GETQUOTA get wrong result: "
                       LPU64", "LPU64"\n", oqctl.qc_dqblk.dqb_btime,
                       oqctl.qc_dqblk.dqb_itime);
                RETURN(-EINVAL);
        }

        oqctl.qc_cmd = Q_SETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_id = 500;
        oqctl.qc_dqblk.dqb_bhardlimit = 919;
        oqctl.qc_dqblk.dqb_bsoftlimit = 818;
        oqctl.qc_dqblk.dqb_curspace = 717;
        oqctl.qc_dqblk.dqb_ihardlimit = 616;
        oqctl.qc_dqblk.dqb_isoftlimit = 515;
        oqctl.qc_dqblk.dqb_curinodes = 414;
        oqctl.qc_dqblk.dqb_btime = 313;
        oqctl.qc_dqblk.dqb_itime = 212;
        oqctl.qc_dqblk.dqb_valid = QIF_ALL;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3j: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }

        oqctl.qc_cmd = Q_GETQUOTA;
        oqctl.qc_type = USRQUOTA;
        oqctl.qc_id = 500;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("3k: quotactl Q_SETQUOTA failed: %d\n", rc);
                RETURN(rc);
        }
        if (oqctl.qc_dqblk.dqb_bhardlimit != 919 ||
            oqctl.qc_dqblk.dqb_bsoftlimit != 818 ||
            oqctl.qc_dqblk.dqb_ihardlimit != 616 ||
            oqctl.qc_dqblk.dqb_isoftlimit != 515 ||
            oqctl.qc_dqblk.dqb_curspace != 717 ||
            oqctl.qc_dqblk.dqb_curinodes != 414 ||
            oqctl.qc_dqblk.dqb_btime != 0 ||
            oqctl.qc_dqblk.dqb_itime != 0) {
                CERROR("3l: quotactl Q_GETQUOTA get wrong result:"
                       LPU64", "LPU64", "LPU64", "LPU64", "LPU64", "LPU64", "
                       LPU64", "LPU64"\n", oqctl.qc_dqblk.dqb_bhardlimit,
                       oqctl.qc_dqblk.dqb_bsoftlimit,
                       oqctl.qc_dqblk.dqb_ihardlimit,
                       oqctl.qc_dqblk.dqb_isoftlimit,
                       oqctl.qc_dqblk.dqb_curspace,
                       oqctl.qc_dqblk.dqb_curinodes,
                       oqctl.qc_dqblk.dqb_btime,
                       oqctl.qc_dqblk.dqb_itime);
                RETURN(-EINVAL);
        }

        RETURN(0);
}

/* Test quotaoff */
static int quotactl_test_4(struct obd_device *obd, struct super_block *sb)
{
        int rc;
        ENTRY;

        oqctl.qc_cmd = Q_QUOTAOFF;
        oqctl.qc_id = 500;
        oqctl.qc_type = UGQUOTA;
        rc = fsfilt_quotactl(obd, sb, &oqctl);
        if (rc) {
                CERROR("4a: quotactl Q_QUOTAOFF failed: %d\n", rc);
                RETURN(rc);
        }

        RETURN(0);
}

/* -------------------------------------------------------------------------
 * Tests above, boring obd functions below
 * ------------------------------------------------------------------------- */
static int quotactl_run_tests(struct obd_device *obd, struct obd_device *tgt)
{
        struct super_block *sb;
        struct lvfs_run_ctxt saved;
        int rc;
        ENTRY;

        if (strcmp(tgt->obd_type->typ_name, LUSTRE_MDS_NAME) &&
            !strcmp(tgt->obd_type->typ_name, "obdfilter")) {
                CERROR("TARGET OBD should be mds or ost\n");
                RETURN(-EINVAL);
        }

        sb = tgt->u.obt.obt_sb;

        push_ctxt(&saved, &tgt->obd_lvfs_ctxt, NULL);

        rc = quotactl_test_1(tgt, sb);
        if (rc)
                GOTO(cleanup, rc);

#if 0
        rc = quotactl_test_2(tgt, sb);
        if (rc)
                GOTO(cleanup, rc);
#endif

        rc = quotactl_test_3(tgt, sb);
        if (rc)
                GOTO(cleanup, rc);

 cleanup:
        quotactl_test_4(tgt, sb);

        pop_ctxt(&saved, &tgt->obd_lvfs_ctxt, NULL);

        return rc;
}

#ifdef LPROCFS
static struct lprocfs_vars lprocfs_quotactl_test_obd_vars[] = { {0} };
static struct lprocfs_vars lprocfs_quotactl_test_module_vars[] = { {0} };

void lprocfs_quotactl_test_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_quotactl_test_module_vars;
    lvars->obd_vars     = lprocfs_quotactl_test_obd_vars;
}
#endif

static int quotactl_test_cleanup(struct obd_device *obd)
{
        lprocfs_obd_cleanup(obd);
        return 0;
}

static int quotactl_test_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lprocfs_static_vars lvars = { 0 };
        struct obd_device *tgt;
        int rc;
        ENTRY;

        if (lcfg->lcfg_bufcount < 1) {
                CERROR("requires a mds OBD name\n");
                RETURN(-EINVAL);
        }

        tgt = class_name2obd(lustre_cfg_string(lcfg, 1));
        if (!tgt || !tgt->obd_attached || !tgt->obd_set_up) {
                CERROR("target device not attached or not set up (%s)\n",
                       lustre_cfg_string(lcfg, 1));
                RETURN(-EINVAL);
        }

        lprocfs_quotactl_test_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        rc = quotactl_run_tests(obd, tgt);

        quotactl_test_cleanup(obd);

        RETURN(rc);
}

static struct obd_ops quotactl_obd_ops = {
        .o_owner       = THIS_MODULE,
        .o_setup       = quotactl_test_setup,
        .o_cleanup     = quotactl_test_cleanup,
};

static int __init quotactl_test_init(void)
{
        struct lprocfs_static_vars lvars = { 0 };

        lprocfs_quotactl_test_init_vars(&lvars);
        return class_register_type(&quotactl_obd_ops, NULL, lvars.module_vars,
                                   "quotactl_test", NULL);
}

static void __exit quotactl_test_exit(void)
{
        class_unregister_type("quotactl_test");
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("quotactl test module");
MODULE_LICENSE("GPL");

module_init(quotactl_test_init);
module_exit(quotactl_test_exit);
