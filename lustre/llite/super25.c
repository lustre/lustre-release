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
#include <lprocfs_status.h>
#include "llite_internal.h"

static cfs_mem_cache_t *ll_inode_cachep;

static struct inode *ll_alloc_inode(struct super_block *sb)
{
        struct ll_inode_info *lli;
        ll_stats_ops_tally(ll_s2sbi(sb), LPROC_LL_ALLOC_INODE, 1);
        OBD_SLAB_ALLOC_PTR(lli, ll_inode_cachep);
        if (lli == NULL)
                return NULL;

        inode_init_once(&lli->lli_vfs_inode);
        ll_lli_init(lli);

        return &lli->lli_vfs_inode;
}

static void ll_destroy_inode(struct inode *inode)
{
        struct ll_inode_info *ptr = ll_i2info(inode);
        OBD_SLAB_FREE_PTR(ptr, ll_inode_cachep);
}

int ll_init_inodecache(void)
{
        ll_inode_cachep = cfs_mem_cache_create("lustre_inode_cache",
                                               sizeof(struct ll_inode_info),
                                               0, SLAB_HWCACHE_ALIGN);
        if (ll_inode_cachep == NULL)
                return -ENOMEM;
        return 0;
}

void ll_destroy_inodecache(void)
{
        int rc;

        rc = cfs_mem_cache_destroy(ll_inode_cachep);
        LASSERTF(rc == 0, "ll_inode_cache: not all structures were freed\n");
}

/* exported operations */
struct super_operations lustre_super_operations =
{
        .alloc_inode   = ll_alloc_inode,
        .destroy_inode = ll_destroy_inode,
        .clear_inode   = ll_clear_inode,
        .delete_inode  = ll_delete_inode,
        .put_super     = ll_put_super,
        .statfs        = ll_statfs,
        .umount_begin  = ll_umount_begin,
        .remount_fs    = ll_remount_fs,
};


void lustre_register_client_process_config(int (*cpc)(struct lustre_cfg *lcfg));

static int __init init_lustre_lite(void)
{
        int i, rc, seed[2];
        struct timeval tv;
        lnet_process_id_t lnet_id;
 
        rc = ll_init_inodecache();
        if (rc)
                return -ENOMEM;
        ll_file_data_slab = cfs_mem_cache_create("ll_file_data",
                                                 sizeof(struct ll_file_data), 0,
                                                 SLAB_HWCACHE_ALIGN);
        if (ll_file_data_slab == NULL) {
                ll_destroy_inodecache();
                return -ENOMEM;
        }

        ll_remote_perm_cachep = cfs_mem_cache_create("ll_remote_perm_cache",
                                                  sizeof(struct ll_remote_perm),
                                                      0, 0);
        if (ll_remote_perm_cachep == NULL) {
                cfs_mem_cache_destroy(ll_file_data_slab);
                ll_file_data_slab = NULL;
                ll_destroy_inodecache();
                return -ENOMEM;
        }

        ll_rmtperm_hash_cachep = cfs_mem_cache_create("ll_rmtperm_hash_cache",
                                                   REMOTE_PERM_HASHSIZE *
                                                   sizeof(struct list_head),
                                                   0, 0);
        if (ll_rmtperm_hash_cachep == NULL) {
                cfs_mem_cache_destroy(ll_remote_perm_cachep);
                ll_remote_perm_cachep = NULL;
                cfs_mem_cache_destroy(ll_file_data_slab);
                ll_file_data_slab = NULL;
                ll_destroy_inodecache();
                return -ENOMEM;
        }

        proc_lustre_fs_root = proc_lustre_root ?
                              lprocfs_register("llite", proc_lustre_root, NULL, NULL) : NULL;

        ll_register_cache(&ll_cache_definition);

        lustre_register_client_fill_super(ll_fill_super);
        lustre_register_kill_super_cb(ll_kill_super);

        lustre_register_client_process_config(ll_process_config);

        ll_get_random_bytes(seed, sizeof(seed));

        /* Nodes with small feet have little entropy
         * the NID for this node gives the most entropy in the low bits */
        for (i=0; ; i++) {
                if (LNetGetId(i, &lnet_id) == -ENOENT) {
                        break;
                }
                if (LNET_NETTYP(LNET_NIDNET(lnet_id.nid)) != LOLND) {
                        seed[0] ^= LNET_NIDADDR(lnet_id.nid);
                }
        }

        do_gettimeofday(&tv);
        ll_srand(tv.tv_sec ^ seed[0], tv.tv_usec ^ seed[1]);

        init_timer(&ll_capa_timer);
        ll_capa_timer.function = ll_capa_timer_callback;
        rc = ll_capa_thread_start();
        return rc;
}

static void __exit exit_lustre_lite(void)
{
        int rc;
        
        del_timer(&ll_capa_timer);
        ll_capa_thread_stop();
        LASSERTF(capa_count[CAPA_SITE_CLIENT] == 0,
                 "client remaining capa count %d\n",
                 capa_count[CAPA_SITE_CLIENT]);

        lustre_register_client_fill_super(NULL);
        lustre_register_kill_super_cb(NULL);

        lustre_register_client_process_config(NULL);

        ll_unregister_cache(&ll_cache_definition);

        ll_destroy_inodecache();

        rc = cfs_mem_cache_destroy(ll_rmtperm_hash_cachep);
        LASSERTF(rc == 0, "couldn't destroy ll_rmtperm_hash_cachep\n");
        ll_rmtperm_hash_cachep = NULL;

        rc = cfs_mem_cache_destroy(ll_remote_perm_cachep);
        LASSERTF(rc == 0, "couldn't destroy ll_remote_perm_cachep\n");
        ll_remote_perm_cachep = NULL;

        rc = cfs_mem_cache_destroy(ll_file_data_slab);
        LASSERTF(rc == 0, "couldn't destroy ll_file_data slab\n");
        if (ll_async_page_slab) {
                rc = cfs_mem_cache_destroy(ll_async_page_slab);
                LASSERTF(rc == 0, "couldn't destroy ll_async_page slab\n");
        }

        if (proc_lustre_fs_root)
                lprocfs_remove(&proc_lustre_fs_root);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lite Client File System");
MODULE_LICENSE("GPL");

module_init(init_lustre_lite);
module_exit(exit_lustre_lite);
