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

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/version.h>
#include <lustre_lite.h>
#include <lustre_ha.h>
#include <lustre_dlm.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/cache_def.h>
#include <lprocfs_status.h>
#include "llite_internal.h"
#include <lustre/lustre_user.h>

extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;


/* exported operations */
struct super_operations lustre_super_operations =
{
        .read_inode2    = ll_read_inode2,
        .clear_inode    = ll_clear_inode,
        .put_super      = ll_put_super,
        .statfs         = ll_statfs,
        .umount_begin   = ll_umount_begin,
        .fh_to_dentry   = ll_fh_to_dentry,
        .dentry_to_fh   = ll_dentry_to_fh,
        .remount_fs     = ll_remount_fs,
};


void lustre_register_client_process_config(int (*cpc)(struct lustre_cfg *lcfg));

static int __init init_lustre_lite(void)
{
        int i, seed[2];
        struct timeval tv;
        lnet_process_id_t lnet_id;

        printk(KERN_INFO "Lustre: Lustre Client File System; "
               "http://www.lustre.org/\n");
        ll_file_data_slab = cfs_mem_cache_create("ll_file_data",
                                                 sizeof(struct ll_file_data), 0,
                                                 SLAB_HWCACHE_ALIGN);
        if (ll_file_data_slab == NULL)
                return -ENOMEM;

        if (proc_lustre_root)
                proc_lustre_fs_root = proc_mkdir("llite", proc_lustre_root);

        ll_register_cache(&ll_cache_definition);

        lustre_register_client_fill_super(ll_fill_super);
        lustre_register_client_process_config(ll_process_config);

        get_random_bytes(seed, sizeof(seed));

        /* Nodes with small feet have little entropy
         * the NID for this node gives the most entropy in the low bits */
        for (i = 0; ; i++) {
                if (LNetGetId(i, &lnet_id) == -ENOENT) {
                        break;
                }
                if (LNET_NETTYP(LNET_NIDNET(lnet_id.nid)) != LOLND) {
                        seed[0] ^= LNET_NIDADDR(lnet_id.nid);
                }
        }

        do_gettimeofday(&tv);
        ll_srand(tv.tv_sec ^ seed[0], tv.tv_usec ^ seed[1]);

        return 0;
}

static void __exit exit_lustre_lite(void)
{
        int rc;

        lustre_register_client_fill_super(NULL);
        lustre_register_client_process_config(NULL);

        ll_unregister_cache(&ll_cache_definition);

        rc = cfs_mem_cache_destroy(ll_file_data_slab);
        LASSERTF(rc == 0, "couldn't destroy ll_file_data slab\n");
        if (ll_async_page_slab) {
                rc = cfs_mem_cache_destroy(ll_async_page_slab);
                LASSERTF(rc == 0, "couldn't destroy ll_async_page slab\n");
        }

        if (proc_lustre_fs_root)
                lprocfs_remove(&proc_lustre_fs_root);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Lite Client File System");
MODULE_LICENSE("GPL");

module_init(init_lustre_lite);
module_exit(exit_lustre_lite);
