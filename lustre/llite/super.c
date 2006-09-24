/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
        .delete_inode   = ll_delete_inode,
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
        int rc, seed[2];

        printk(KERN_INFO "Lustre: Lustre Client File System; "
               "info@clusterfs.com\n");
        ll_file_data_slab = kmem_cache_create("ll_file_data",
                                              sizeof(struct ll_file_data), 0,
                                              SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ll_file_data_slab == NULL)
                return -ENOMEM;

        LASSERT(ll_remote_perm_cachep == NULL);
        ll_remote_perm_cachep = kmem_cache_create("ll_remote_perm",
                                                  sizeof(struct ll_remote_perm),
                                                  0, SLAB_HWCACHE_ALIGN, NULL,
                                                  NULL);
        if (!ll_remote_perm_cachep) {
                kmem_cache_destroy(ll_file_data_slab);
                ll_file_data_slab = NULL;
                return -ENOMEM;
        }

        LASSERT(ll_rmtperm_hash_cachep == NULL);
        ll_rmtperm_hash_cachep = kmem_cache_create("ll_rmtperm_hash",
                                                  REMOTE_PERM_HASHSIZE *
                                                  sizeof(struct list_head),
                                                  0, SLAB_HWCACHE_ALIGN, NULL,
                                                  NULL);
        if (!ll_rmtperm_hash_cachep) {
                kmem_cache_destroy(ll_remote_perm_cachep);
                kmem_cache_destroy(ll_file_data_slab);
                ll_remote_perm_cachep = NULL;
                ll_file_data_slab = NULL;
                return -ENOMEM;
        }

        if (proc_lustre_root)
                proc_lustre_fs_root = proc_mkdir("llite", proc_lustre_root);

        ll_register_cache(&ll_cache_definition);

        lustre_register_client_fill_super(ll_fill_super);
        lustre_register_client_process_config(ll_process_config);

        get_random_bytes(seed, sizeof(seed));
        ll_srand(seed[0], seed[1]);

        return rc;
}

static void __exit exit_lustre_lite(void)
{
        int rc;

        lustre_register_client_fill_super(NULL);
        lustre_register_client_process_config(NULL);

        ll_unregister_cache(&ll_cache_definition);

        rc = kmem_cache_destroy(ll_rmtperm_hash_cachep);
        LASSERTF(rc == 0, "couldn't destroy ll_rmtperm_hash_cachep\n");
        ll_rmtperm_hash_cachep = NULL;

        rc = kmem_cache_destroy(ll_remote_perm_cachep);
        LASSERTF(rc == 0, "couldn't destroy ll_remote_perm_cachep\n");
        ll_remote_perm_cachep = NULL;

        rc = kmem_cache_destroy(ll_file_data_slab);
        LASSERTF(rc == 0, "couldn't destroy ll_file_data slab\n");
        if (ll_async_page_slab) {
                rc = kmem_cache_destroy(ll_async_page_slab);
                LASSERTF(rc == 0, "couldn't destroy ll_async_page slab\n");
        }

        if (proc_lustre_fs_root) {
                lprocfs_remove(proc_lustre_fs_root);
                proc_lustre_fs_root = NULL;
        }
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lite Client File System");
MODULE_LICENSE("GPL");

module_init(init_lustre_lite);
module_exit(exit_lustre_lite);
