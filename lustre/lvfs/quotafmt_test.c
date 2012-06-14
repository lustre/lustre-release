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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lvfs/quotafmt_test.c
 *
 * No redistribution or use is permitted outside of Sun Microsystems, Inc.
 *
 * Kernel module to test lustre administrative quotafile format APIs
 * from the OBD setup function
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>

#include <lustre_quota.h>
#include <obd_class.h>

#include "lustre_quota_fmt.h"

#ifdef HAVE_QUOTA_SUPPORT

char *test_quotafile[2] = { "usrquota_test", "grpquota_test" };

static int quotfmt_initialize(struct lustre_quota_info *lqi,
                              struct obd_device *tgt,
                              struct lvfs_run_ctxt *saved)
{
        struct lustre_disk_dqheader dqhead;
        static const uint quota_magics[] = LUSTRE_INITQMAGICS;
        static const uint quota_versions[] = LUSTRE_INITQVERSIONS_V2;
        struct file *fp;
        struct inode *parent_inode = tgt->obd_lvfs_ctxt.pwd->d_inode;
        size_t size;
        struct dentry *de;
        int i, rc = 0;
        ENTRY;

        push_ctxt(saved, &tgt->obd_lvfs_ctxt, NULL);

        for (i = 0; i < MAXQUOTAS; i++) {
                loff_t offset = 0;
                char *name = test_quotafile[i];
                int namelen = strlen(name);

                /* remove the stale test quotafile */
                LOCK_INODE_MUTEX_PARENT(parent_inode);
                de = lookup_one_len(name, tgt->obd_lvfs_ctxt.pwd, namelen);
                if (!IS_ERR(de) && de->d_inode)
                        ll_vfs_unlink(parent_inode, de,
                                      tgt->obd_lvfs_ctxt.pwdmnt);
                if (!IS_ERR(de))
                        dput(de);
                UNLOCK_INODE_MUTEX(parent_inode);

                /* create quota file */
                fp = filp_open(name, O_CREAT | O_EXCL, 0644);
                if (IS_ERR(fp)) {
                        rc = PTR_ERR(fp);
                        CERROR("error creating test quotafile %s (rc = %d)\n",
                               name, rc);
                        break;
                }
                lqi->qi_files[i] = fp;

                /* write quotafile header */
                dqhead.dqh_magic = cpu_to_le32(quota_magics[i]);
                dqhead.dqh_version = cpu_to_le32(quota_versions[i]);
                size = fp->f_op->write(fp, (char *)&dqhead,
                                       sizeof(struct lustre_disk_dqheader),
                                       &offset);
                if (size != sizeof(struct lustre_disk_dqheader)) {
                        CERROR("error writing quotafile header %s (rc = %d)\n",
                               name, rc);
                        rc = size;
                        break;
                }
        }

        RETURN(rc);
}

static int quotfmt_finalize(struct lustre_quota_info *lqi,
                            struct obd_device *tgt, struct lvfs_run_ctxt *saved)
{
        struct dentry *de;
        struct inode *parent_inode = tgt->obd_lvfs_ctxt.pwd->d_inode;
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < MAXQUOTAS; i++) {
                char *name = test_quotafile[i];
                int namelen = strlen(name);

                if (lqi->qi_files[i] == NULL)
                        continue;

                /* close quota file */
                filp_close(lqi->qi_files[i], 0);

                /* unlink quota file */
                LOCK_INODE_MUTEX_PARENT(parent_inode);

                de = lookup_one_len(name, tgt->obd_lvfs_ctxt.pwd, namelen);
                if (IS_ERR(de) || de->d_inode == NULL) {
                        rc = IS_ERR(de) ? PTR_ERR(de) : -ENOENT;
                        CERROR("error lookup quotafile %s (rc = %d)\n",
                               name, rc);
                        goto dput;
                }

                rc = ll_vfs_unlink(parent_inode, de, tgt->obd_lvfs_ctxt.pwdmnt);
                if (rc)
                        CERROR("error unlink quotafile %s (rc = %d)\n",
                               name, rc);
              dput:
                if (!IS_ERR(de))
                        dput(de);
                UNLOCK_INODE_MUTEX(parent_inode);
        }

        pop_ctxt(saved, &tgt->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}

static int quotfmt_test_1(struct lustre_quota_info *lqi)
{
        int i;
        ENTRY;

        for (i = 0; i < MAXQUOTAS; i++) {
                if (lustre_check_quota_file(lqi, i))
                        RETURN(-EINVAL);
        }
        RETURN(0);
}

static void print_quota_info(struct lustre_quota_info *lqi)
{
#if 0
        struct lustre_mem_dqinfo *dqinfo;
        int i;

        for (i = 0; i < MAXQUOTAS; i++) {
                dqinfo = &lqi->qi_info[i];
                CDEBUG(D_INFO, "%s quota info:\n", i == USRQUOTA ? "user " : "group");
                CDEBUG(D_INFO, "dqi_bgrace(%u) dqi_igrace(%u) dqi_flags(%lu) dqi_blocks(%u) "
                       "dqi_free_blk(%u) dqi_free_entry(%u)\n",
                       dqinfo->dqi_bgrace, dqinfo->dqi_igrace, dqinfo->dqi_flags,
                       dqinfo->dqi_blocks, dqinfo->dqi_free_blk,
                       dqinfo->dqi_free_entry);
        }
#endif
}

static int quotfmt_test_2(struct lustre_quota_info *lqi)
{
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < MAXQUOTAS; i++) {
                struct lustre_mem_dqinfo dqinfo;

                rc = lustre_init_quota_info(lqi, i);
                if (rc) {
                        CERROR("init quotainfo(%d) failed! (rc:%d)\n", i, rc);
                        break;
                }
                memcpy(&dqinfo, &lqi->qi_info[i], sizeof(dqinfo));

                rc = lustre_read_quota_info(lqi, i);
                if (rc) {
                        CERROR("read quotainfo(%d) failed! (rc:%d)\n", i, rc);
                        break;
                }

                if (memcmp(&dqinfo, &lqi->qi_info[i], sizeof(dqinfo))) {
                        rc = -EINVAL;
                        break;
                }
        }
        RETURN(rc);
}

static struct lustre_dquot *get_rand_dquot(struct lustre_quota_info *lqi)
{
        struct lustre_dquot *dquot;
        unsigned int rand;

        OBD_ALLOC(dquot, sizeof(*dquot));
        if (dquot == NULL)
                return NULL;

        cfs_get_random_bytes(&rand, sizeof(rand));
        if (!rand)
                rand = 1000;

        dquot->dq_info = lqi;
        dquot->dq_id = rand % 1000 + 1;
        dquot->dq_type = rand % MAXQUOTAS;

        dquot->dq_dqb.dqb_bhardlimit = rand;
        dquot->dq_dqb.dqb_bsoftlimit = rand / 2;
        dquot->dq_dqb.dqb_curspace = rand / 3;
        dquot->dq_dqb.dqb_ihardlimit = rand;
        dquot->dq_dqb.dqb_isoftlimit = rand / 2;
        dquot->dq_dqb.dqb_curinodes = rand / 3;
        dquot->dq_dqb.dqb_btime = jiffies;
        dquot->dq_dqb.dqb_itime = jiffies;

        return dquot;
}

static void put_rand_dquot(struct lustre_dquot *dquot)
{
        OBD_FREE(dquot, sizeof(*dquot));
}

static int write_check_dquot(struct lustre_quota_info *lqi)
{
        struct lustre_dquot *dquot;
        struct lustre_mem_dqblk dqblk;
        int rc = 0;
        ENTRY;

        dquot = get_rand_dquot(lqi);
        if (dquot == NULL)
                RETURN(-ENOMEM);

        /* for already exists entry, we set the dq_off by read_dquot */
        rc = lustre_read_dquot(dquot);
        if (rc) {
                CERROR("read dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        cfs_clear_bit(DQ_FAKE_B, &dquot->dq_flags);
        /* for already exists entry, we rewrite it */
        rc = lustre_commit_dquot(dquot);
        if (rc) {
                CERROR("commit dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }
        memcpy(&dqblk, &dquot->dq_dqb, sizeof(dqblk));
        memset(&dquot->dq_dqb, 0, sizeof(dqblk));

        rc = lustre_read_dquot(dquot);
        if (rc) {
                CERROR("read dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        if (memcmp(&dqblk, &dquot->dq_dqb, sizeof(dqblk))) {
                rc = -EINVAL;
                GOTO(out, rc);
        }
      out:
        put_rand_dquot(dquot);
        RETURN(rc);
}

static int quotfmt_test_3(struct lustre_quota_info *lqi)
{
        struct lustre_dquot *dquot;
        int i = 0, rc = 0;
        ENTRY;

        dquot = get_rand_dquot(lqi);
        if (dquot == NULL)
                RETURN(-ENOMEM);
      repeat:
        cfs_clear_bit(DQ_FAKE_B, &dquot->dq_flags);
        /* write a new dquot */
        rc = lustre_commit_dquot(dquot);
        if (rc) {
                CERROR("commit dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }
        dquot->dq_off = 0;
        memset(&dquot->dq_dqb, 0, sizeof(dquot->dq_dqb));

        /* check if this dquot is on disk now */
        rc = lustre_read_dquot(dquot);
        if (rc) {
                CERROR("read dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }
        if (!dquot->dq_off || cfs_test_bit(DQ_FAKE_B, &dquot->dq_flags)) {
                CERROR("the dquot isn't committed\n");
                GOTO(out, rc = -EINVAL);
        }

        /* remove this dquot */
        cfs_set_bit(DQ_FAKE_B, &dquot->dq_flags);
        dquot->dq_dqb.dqb_curspace = 0;
        dquot->dq_dqb.dqb_curinodes = 0;
        rc = lustre_commit_dquot(dquot);
        if (rc) {
                CERROR("remove dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        /* check if the dquot is really removed */
        cfs_clear_bit(DQ_FAKE_B, &dquot->dq_flags);
        dquot->dq_off = 0;
        rc = lustre_read_dquot(dquot);
        if (rc) {
                CERROR("read dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }
        if (!cfs_test_bit(DQ_FAKE_B, &dquot->dq_flags) || dquot->dq_off) {
                CERROR("the dquot isn't removed!\n");
                GOTO(out, rc = -EINVAL);
        }

        /* check if this dquot can be write again */
        if (++i < 2)
                goto repeat;

        print_quota_info(lqi);

      out:
        put_rand_dquot(dquot);
        RETURN(rc);
}

static int quotfmt_test_4(struct lustre_quota_info *lqi)
{
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < 30000; i++) {
                rc = write_check_dquot(lqi);
                if (rc) {
                        CERROR("write/check dquot failed at %d! (rc:%d)\n",
                               i, rc);
                        break;
                }
        }
        print_quota_info(lqi);
        RETURN(rc);
}

static int quotfmt_run_tests(struct obd_device *obd, struct obd_device *tgt)
{
        struct lvfs_run_ctxt saved;
        struct lustre_quota_info *lqi = NULL;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(lqi, sizeof(*lqi));
        if (lqi == NULL) {
                CERROR("not enough memory\n");
                RETURN(-ENOMEM);
        }

        CWARN("=== Initialize quotafile test\n");
        rc = quotfmt_initialize(lqi, tgt, &saved);
        if (rc)
                GOTO(out, rc);

        CWARN("=== test  1: check quota header\n");
        rc = quotfmt_test_1(lqi);
        if (rc) {
                CERROR("check quota header failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        CWARN("=== test  2: write/read quota info\n");
        rc = quotfmt_test_2(lqi);
        if (rc) {
                CERROR("write/read quota info failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        CWARN("=== test  3: write/remove dquot\n");
        rc = quotfmt_test_3(lqi);
        if (rc) {
                CERROR("write/remove dquot failed! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        CWARN("=== test  4: write/read 30000 dquot\n");
        rc = quotfmt_test_4(lqi);
        if (rc) {
                CERROR("write/read 30000 dquot failed\n");
                GOTO(out, rc);
        }

out:
        CWARN("=== Finalize quotafile test\n");
        rc = quotfmt_finalize(lqi, tgt, &saved);
        OBD_FREE(lqi, sizeof(*lqi));
        RETURN(rc);
}

static int quotfmt_test_cleanup(struct obd_device *obd)
{
        ENTRY;
        lprocfs_obd_cleanup(obd);
        RETURN(0);
}

static int quotfmt_test_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lprocfs_static_vars lvars;
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

        rc = quotfmt_run_tests(obd, tgt);
        if (rc)
                quotfmt_test_cleanup(obd);

        lprocfs_quotfmt_test_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        RETURN(rc);
}

static struct obd_ops quotfmt_obd_ops = {
        .o_owner = THIS_MODULE,
        .o_setup = quotfmt_test_setup,
        .o_cleanup = quotfmt_test_cleanup,
};

#ifdef LPROCFS
static struct lprocfs_vars lprocfs_quotfmt_test_obd_vars[] = { {0} };
static struct lprocfs_vars lprocfs_quotfmt_test_module_vars[] = { {0} };

void lprocfs_quotfmt_test_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_quotfmt_test_module_vars;
    lvars->obd_vars     = lprocfs_quotfmt_test_obd_vars;
}
#endif
static int __init quotfmt_test_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_quotfmt_test_init_vars(&lvars);
        return class_register_type(&quotfmt_obd_ops, NULL, lvars.module_vars,
                                   "quotfmt_test", NULL);
}

static void __exit quotfmt_test_exit(void)
{
        class_unregister_type("quotfmt_test");
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("administrative quotafile test module");
MODULE_LICENSE("GPL");

module_init(quotfmt_test_init);
module_exit(quotfmt_test_exit);

#endif /* HAVE_QUOTA_SUPPORT */
