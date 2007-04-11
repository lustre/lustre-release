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

static kmem_cache_t *ll_inode_cachep;

static struct inode *ll_alloc_inode(struct super_block *sb)
{
        struct ll_inode_info *lli;
        lprocfs_counter_incr((ll_s2sbi(sb))->ll_stats, LPROC_LL_ALLOC_INODE);
        OBD_SLAB_ALLOC(lli, ll_inode_cachep, SLAB_KERNEL, sizeof *lli);
        if (lli == NULL)
                return NULL;

        inode_init_once(&lli->lli_vfs_inode);
        ll_lli_init(lli);

        return &lli->lli_vfs_inode;
}

static void ll_destroy_inode(struct inode *inode)
{
        struct ll_inode_info *ptr = ll_i2info(inode);
        OBD_SLAB_FREE(ptr, ll_inode_cachep, sizeof(*ptr));
}

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
        struct ll_inode_info *lli = foo;

        if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
            SLAB_CTOR_CONSTRUCTOR)
                inode_init_once(&lli->lli_vfs_inode);
}

int ll_init_inodecache(void)
{
        ll_inode_cachep = kmem_cache_create("lustre_inode_cache",
                                            sizeof(struct ll_inode_info),
                                            0, SLAB_HWCACHE_ALIGN,
                                            init_once, NULL);
        if (ll_inode_cachep == NULL)
                return -ENOMEM;
        return 0;
}

void ll_destroy_inodecache(void)
{
#ifdef HAVE_KMEM_CACHE_DESTROY_INT
        int rc;
 
        rc = kmem_cache_destroy(ll_inode_cachep);
        LASSERTF(rc == 0, "ll_inode_cache: not all structures were freed\n");
#else
        kmem_cache_destroy(ll_inode_cachep);
#endif
}

/* exported operations */
struct super_operations lustre_super_operations =
{
        .alloc_inode   = ll_alloc_inode,
        .destroy_inode = ll_destroy_inode,
        .clear_inode   = ll_clear_inode,
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

        printk(KERN_INFO "Lustre: Lustre Client File System; "
               "info@clusterfs.com\n");
        rc = ll_init_inodecache();
        if (rc)
                return -ENOMEM;
        ll_file_data_slab = kmem_cache_create("ll_file_data",
                                              sizeof(struct ll_file_data), 0,
                                              SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ll_file_data_slab == NULL) {
                ll_destroy_inodecache();
                return -ENOMEM;
        }

        proc_lustre_fs_root = proc_lustre_root ?
                              proc_mkdir("llite", proc_lustre_root) : NULL;

        ll_register_cache(&ll_cache_definition);

        lustre_register_client_fill_super(ll_fill_super);
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

        return rc;
}

static void __exit exit_lustre_lite(void)
{
#ifdef HAVE_KMEM_CACHE_DESTROY_INT
        int rc;
#endif

        lustre_register_client_fill_super(NULL);
        lustre_register_client_process_config(NULL);

        ll_unregister_cache(&ll_cache_definition);

        ll_destroy_inodecache();
#ifdef HAVE_KMEM_CACHE_DESTROY_INT
        rc = kmem_cache_destroy(ll_file_data_slab);
        LASSERTF(rc == 0, "couldn't destroy ll_file_data slab\n");
#else
        kmem_cache_destroy(ll_file_data_slab);
#endif
        if (ll_async_page_slab) {
#ifdef HAVE_KMEM_CACHE_DESTROY_INT
                rc = kmem_cache_destroy(ll_async_page_slab);
                LASSERTF(rc == 0, "couldn't destroy ll_async_page slab\n");
#else
                kmem_cache_destroy(ll_async_page_slab);
#endif
        }

        if (proc_lustre_fs_root) 
                lprocfs_remove(&proc_lustre_fs_root);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lite Client File System");
MODULE_LICENSE("GPL");

module_init(init_lustre_lite);
module_exit(exit_lustre_lite);
