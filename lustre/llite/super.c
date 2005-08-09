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
#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/lprocfs_status.h>
#include "llite_internal.h"
#include <lustre/lustre_user.h>

extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
extern struct timer_list ll_capa_timer;

static struct super_block *ll_read_super(struct super_block *sb,
                                         void *data, int silent)
{
        int err;
        ENTRY;
        err = ll_fill_super(sb, data, silent);
        if (err)
                RETURN(NULL);
        RETURN(sb);
}

static struct super_block *lustre_read_super(struct super_block *sb,
                                         void *data, int silent)
{
        int err;
        ENTRY;
        err = lustre_fill_super(sb, data, silent);
        if (err)
                RETURN(NULL);
        RETURN(sb);
}

static void ll_umount_lustre(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        ll_gns_check_mounts(sbi, LL_GNS_UMOUNT);
}

static struct file_system_type lustre_lite_fs_type = {
        .owner          = THIS_MODULE,
        .name           = "lustre_lite",
        .fs_flags       = FS_NFSEXP_FSID,
        .read_super     = ll_read_super,
};

/* exported operations */
struct super_operations lustre_super_operations =
{
        .read_inode2    = ll_read_inode2,
        .clear_inode    = ll_clear_inode,
        .delete_inode   = ll_delete_inode,
        .put_super      = lustre_put_super,
        .statfs         = ll_statfs,
        .umount_begin   = ll_umount_begin,
        .umount_lustre  = ll_umount_lustre,
        .fh_to_dentry   = ll_fh_to_dentry,
        .dentry_to_fh   = ll_dentry_to_fh
};

static struct file_system_type lustre_fs_type = {
        .owner          = THIS_MODULE,
        .name           = "lustre",
        .fs_flags       = FS_NFSEXP_FSID,
        .read_super     = lustre_read_super,
};

static int __init init_lustre_lite(void)
{
        int rc, cleanup = 0;

        printk(KERN_INFO "Lustre: Lustre Lite Client File System; "
               "info@clusterfs.com\n");
        ll_file_data_slab = kmem_cache_create("ll_file_data",
                                              sizeof(struct ll_file_data), 0,
                                              SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ll_file_data_slab == NULL)
                return -ENOMEM;

        ll_intent_slab = kmem_cache_create("lustre_intent_data",
                                              sizeof(struct lustre_intent_data),
                                              0, SLAB_HWCACHE_ALIGN, NULL,
                                              NULL);
        if (ll_intent_slab == NULL) {
                kmem_cache_destroy(ll_file_data_slab);
                return -ENOMEM;
        }

        proc_lustre_fs_root = proc_lustre_root ? proc_mkdir("llite", proc_lustre_root) : NULL;

        rc = register_filesystem(&lustre_lite_fs_type);
        if (rc)
                goto out;
        cleanup = 1;

        rc = register_filesystem(&lustre_fs_type);
        if (rc)
                goto out;
        cleanup = 2;

        rc = ll_gns_start_thread();
        if (rc)
                goto out;

        ll_capa_timer.function = ll_capa_timer_callback;
        ll_capa_timer.data = 0;
        init_timer(&ll_capa_timer);        

        rc = ll_capa_start_thread();
        if (rc)
                goto out;

        return 0;

 out:
        switch (cleanup) {
        case 2:
                unregister_filesystem(&lustre_fs_type);
        case 1:
                unregister_filesystem(&lustre_lite_fs_type);
        case 0:
                kmem_cache_destroy(ll_intent_slab);
                kmem_cache_destroy(ll_file_data_slab);
        }
        return rc;
}

static void __exit exit_lustre_lite(void)
{
        unregister_filesystem(&lustre_lite_fs_type);
        unregister_filesystem(&lustre_fs_type);

        del_timer(&ll_capa_timer);
        ll_capa_stop_thread();
        ll_gns_stop_thread();

        LASSERTF(kmem_cache_destroy(ll_file_data_slab) == 0,
                 "couldn't destroy ll_file_data slab\n");
        LASSERTF(kmem_cache_destroy(ll_intent_slab) == 0,
                 "couldn't destroy ll_intent_slab slab\n");

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
