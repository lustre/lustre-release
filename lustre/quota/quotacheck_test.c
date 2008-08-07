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
 * lustre/quota/quotacheck_test.c
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#include <linux/version.h>
#include <linux/bitops.h>

#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <lustre_mds.h>
#include <obd_ost.h>

char *test_quotafile[] = {"aquotacheck.user", "aquotacheck.group"};

static inline struct ext3_group_desc *
get_group_desc(struct super_block *sb, int group)
{
        unsigned long desc_block, desc;
        struct ext3_group_desc *gdp;

        desc_block = group / EXT3_DESC_PER_BLOCK(sb);
        desc = group % EXT3_DESC_PER_BLOCK(sb);
        gdp = (struct ext3_group_desc *)
              EXT3_SB(sb)->s_group_desc[desc_block]->b_data;

        return gdp + desc;
}

static inline struct buffer_head *
read_inode_bitmap(struct super_block *sb, unsigned long group)
{
        struct ext3_group_desc *desc;
        struct buffer_head *bh;

        desc = get_group_desc(sb, group);
        bh = sb_bread(sb, le32_to_cpu(desc->bg_inode_bitmap));

        return bh;
}

static inline struct inode *ext3_iget_inuse(struct super_block *sb,
                                     struct buffer_head *bitmap_bh,
                                     int index, unsigned long ino)
{
        struct inode *inode = NULL;

        if (ext3_test_bit(index, bitmap_bh->b_data)) {
                CERROR("i: %d, ino: %lu\n", index, ino);
                ll_sleep(1);
                inode = iget(sb, ino);
        }

        return inode;
}

static void print_inode(struct inode *inode)
{
        loff_t size = 0;

        if (S_ISDIR(inode->i_mode) ||
            S_ISREG(inode->i_mode) ||
            S_ISLNK(inode->i_mode))
                size = inode_get_bytes(inode);

         CERROR("%lu: uid: %u, size: %llu, blocks: %llu, real size: %llu\n",
               inode->i_ino, inode->i_uid, i_size_read(inode),
               (long long)inode->i_blocks, size);
}

/* Test quotaon */
static int quotacheck_test_1(struct obd_device *obd, struct super_block *sb)
{
        struct ext3_sb_info *sbi = EXT3_SB(sb);
        struct buffer_head *bitmap_bh = NULL;
        struct inode *inode;
        unsigned long ino;
        int i, group;
        ENTRY;

        for (group = 0; group < sbi->s_groups_count; group++) {
                ino = group * sbi->s_inodes_per_group + 1;
                brelse(bitmap_bh);
                bitmap_bh = read_inode_bitmap(sb, group);

                if (group == 0)
                        CERROR("groups_count: %lu, inodes_per_group: %lu, first_ino: %u, inodes_count: %u\n",
                               sbi->s_groups_count, sbi->s_inodes_per_group,
                               sbi->s_first_ino, le32_to_cpu(sbi->s_es->s_inodes_count));

                for (i = 0; i < sbi->s_inodes_per_group; i++, ino++) {
                        if (ino < sbi->s_first_ino)
                                continue;
                        if (ino > le32_to_cpu(sbi->s_es->s_inodes_count)) {
                                CERROR("bad inode number: %lu > s_inodes_count\n", ino);
                                brelse(bitmap_bh);
                                RETURN(-E2BIG);
                        }
                        inode = ext3_iget_inuse(sb, bitmap_bh, i, ino);
                        if (inode)
                                print_inode(inode);
                        iput(inode);
                }
        }
        brelse(bitmap_bh);

        RETURN(0);
}

/* -------------------------------------------------------------------------
 * Tests above, boring obd functions below
 * ------------------------------------------------------------------------- */
static int quotacheck_run_tests(struct obd_device *obd, struct obd_device *tgt)
{
        int rc;
        ENTRY;

        if (strcmp(tgt->obd_type->typ_name, LUSTRE_MDS_NAME) &&
            !strcmp(tgt->obd_type->typ_name, "obdfilter")) {
                CERROR("TARGET OBD should be mds or ost\n");
                RETURN(-EINVAL);
        }

        rc = quotacheck_test_1(tgt, tgt->u.obt.obt_sb);

        return rc;
}

#ifdef LPROCFS
static struct lprocfs_vars lprocfs_quotacheck_test_obd_vars[] = { {0} };
static struct lprocfs_vars lprocfs_quotacheck_test_module_vars[] = { {0} };
#endif

void lprocfs_quotacheck_test_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_quotacheck_test_module_vars;
    lvars->obd_vars     = lprocfs_quotacheck_test_obd_vars;
}

static int quotacheck_test_cleanup(struct obd_device *obd)
{
        lprocfs_obd_cleanup(obd);
        return 0;
}

static int quotacheck_test_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars = { 0 };
        struct lustre_cfg *lcfg = buf;
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

        rc = quotacheck_run_tests(obd, tgt);
        if (rc)
                quotacheck_test_cleanup(obd);

        lprocfs_quotacheck_test_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        RETURN(rc);
}

static struct obd_ops quotacheck_obd_ops = {
        .o_owner       = THIS_MODULE,
        .o_setup       = quotacheck_test_setup,
        .o_cleanup     = quotacheck_test_cleanup,
};

static int __init quotacheck_test_init(void)
{
        struct lprocfs_static_vars lvars = { 0 };

        lprocfs_quotacheck_test_init_vars(&lvars);
        return class_register_type(&quotacheck_obd_ops, lvars.module_vars,
                                   "quotacheck_test");
}

static void __exit quotacheck_test_exit(void)
{
        class_unregister_type("quotacheck_test");
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("quotacheck test module");
MODULE_LICENSE("GPL");

module_init(quotacheck_test_init);
module_exit(quotacheck_test_exit);
