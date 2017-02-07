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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
#include <lustre_ha.h>
#include <lustre_dlm.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <lprocfs_status.h>
#include "llite_internal.h"
#include "vvp_internal.h"

static struct kmem_cache *ll_inode_cachep;

static struct inode *ll_alloc_inode(struct super_block *sb)
{
	struct ll_inode_info *lli;
	ll_stats_ops_tally(ll_s2sbi(sb), LPROC_LL_ALLOC_INODE, 1);
	OBD_SLAB_ALLOC_PTR_GFP(lli, ll_inode_cachep, GFP_NOFS);
	if (lli == NULL)
		return NULL;

	inode_init_once(&lli->lli_vfs_inode);
	return &lli->lli_vfs_inode;
}

#ifdef HAVE_INODE_I_RCU
static void ll_inode_destroy_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ll_inode_info *ptr = ll_i2info(inode);
	OBD_SLAB_FREE_PTR(ptr, ll_inode_cachep);
}

static void ll_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, ll_inode_destroy_callback);
}
#else
static void ll_destroy_inode(struct inode *inode)
{
	struct ll_inode_info *ptr = ll_i2info(inode);
	OBD_SLAB_FREE_PTR(ptr, ll_inode_cachep);
}
#endif

/* exported operations */
struct super_operations lustre_super_operations =
{
        .alloc_inode   = ll_alloc_inode,
        .destroy_inode = ll_destroy_inode,
#ifdef HAVE_SBOPS_EVICT_INODE
        .evict_inode   = ll_delete_inode,
#else
        .clear_inode   = ll_clear_inode,
        .delete_inode  = ll_delete_inode,
#endif
        .put_super     = ll_put_super,
        .statfs        = ll_statfs,
        .umount_begin  = ll_umount_begin,
        .remount_fs    = ll_remount_fs,
        .show_options  = ll_show_options,
};


void lustre_register_client_process_config(int (*cpc)(struct lustre_cfg *lcfg));

static int __init lustre_init(void)
{
	struct proc_dir_entry *entry;
	struct lnet_process_id lnet_id;
	struct timespec64 ts;
	int i, rc, seed[2];

	CLASSERT(sizeof(LUSTRE_VOLATILE_HDR) == LUSTRE_VOLATILE_HDR_LEN + 1);

	/* print an address of _any_ initialized kernel symbol from this
	 * module, to allow debugging with gdb that doesn't support data
	 * symbols from modules.*/
	CDEBUG(D_INFO, "Lustre client module (%p).\n",
	       &lustre_super_operations);

	ll_inode_cachep = kmem_cache_create("lustre_inode_cache",
					    sizeof(struct ll_inode_info),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (ll_inode_cachep == NULL)
		GOTO(out_cache, rc = -ENOMEM);

	ll_file_data_slab = kmem_cache_create("ll_file_data",
						 sizeof(struct ll_file_data), 0,
						 SLAB_HWCACHE_ALIGN, NULL);
	if (ll_file_data_slab == NULL)
		GOTO(out_cache, rc = -ENOMEM);

	entry = lprocfs_register("llite", proc_lustre_root, NULL, NULL);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CERROR("cannot register '/proc/fs/lustre/llite': rc = %d\n",
		       rc);
		GOTO(out_cache, rc);
	}

	proc_lustre_fs_root = entry;

	cfs_get_random_bytes(seed, sizeof(seed));

	/* Nodes with small feet have little entropy. The NID for this
	 * node gives the most entropy in the low bits. */
	for (i = 0;; i++) {
		if (LNetGetId(i, &lnet_id) == -ENOENT)
			break;

		if (LNET_NETTYP(LNET_NIDNET(lnet_id.nid)) != LOLND)
			seed[0] ^= LNET_NIDADDR(lnet_id.nid);
	}

	ktime_get_ts64(&ts);
	cfs_srand(ts.tv_sec ^ seed[0], ts.tv_nsec ^ seed[1]);

	rc = vvp_global_init();
	if (rc != 0)
		GOTO(out_proc, rc);

	cl_inode_fini_env = cl_env_alloc(&cl_inode_fini_refcheck,
					 LCT_REMEMBER | LCT_NOREF);
	if (IS_ERR(cl_inode_fini_env))
		GOTO(out_vvp, rc = PTR_ERR(cl_inode_fini_env));

	cl_inode_fini_env->le_ctx.lc_cookie = 0x4;

	rc = ll_xattr_init();
	if (rc != 0)
		GOTO(out_inode_fini_env, rc);

	lustre_register_client_fill_super(ll_fill_super);
	lustre_register_kill_super_cb(ll_kill_super);
	lustre_register_client_process_config(ll_process_config);

	RETURN(0);

out_inode_fini_env:
	cl_env_put(cl_inode_fini_env, &cl_inode_fini_refcheck);
out_vvp:
	vvp_global_fini();
out_proc:
	lprocfs_remove(&proc_lustre_fs_root);
out_cache:
	if (ll_inode_cachep != NULL)
		kmem_cache_destroy(ll_inode_cachep);

	if (ll_file_data_slab != NULL)
		kmem_cache_destroy(ll_file_data_slab);

	return rc;
}

static void __exit lustre_exit(void)
{
	lustre_register_client_fill_super(NULL);
	lustre_register_kill_super_cb(NULL);
	lustre_register_client_process_config(NULL);

	lprocfs_remove(&proc_lustre_fs_root);

	ll_xattr_fini();
	cl_env_put(cl_inode_fini_env, &cl_inode_fini_refcheck);
	vvp_global_fini();

	kmem_cache_destroy(ll_inode_cachep);
	kmem_cache_destroy(ll_file_data_slab);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Client File System");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(lustre_init);
module_exit(lustre_exit);
