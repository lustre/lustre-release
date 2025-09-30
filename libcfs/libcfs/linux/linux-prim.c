// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/mm.h>
#endif
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/netlink.h>

#if defined(CONFIG_KGDB)
#include <asm/kgdb.h>
#endif

#include <lustre_compat.h>
#include <lustre_compat/linux/timer.h>
#include <lustre_compat/linux/linux-misc.h>
#include <lustre_compat/linux/linux-mem.h>
#include <lustre_compat/linux/xarray.h>
#include <lustre_compat/linux/wait_bit.h>
#include <lustre_compat/linux/wait.h>
#include <lustre_compat/linux/shrinker.h>
#include <lustre_crypto.h>

int __init cfs_arch_init(void)
{
	int rc = 0;

#ifndef HAVE_WAIT_VAR_EVENT
	wait_bit_init();
#endif
	rc = lustre_symbols_init();
	if (rc < 0) {
		pr_info("lustre_symbols_init: error %d\n", rc);
		return rc;
	}

	rc = shrinker_debugfs_init();
	if (rc < 0)
		goto failed;

#ifdef CONFIG_LL_ENCRYPTION
	rc = llcrypt_init();
	if (rc < 0)
		goto free_shrinker;
#endif
	return rc;

#ifdef CONFIG_LL_ENCRYPTION
free_shrinker:
	shrinker_debugfs_fini();
#endif
failed:
	return rc;
}

void __exit cfs_arch_exit(void)
{
	shrinker_debugfs_fini();
#ifdef CONFIG_LL_ENCRYPTION
	llcrypt_exit();
#endif
}

static unsigned int libcfs_reserved_cache;
module_param(libcfs_reserved_cache, int, 0644);
MODULE_PARM_DESC(libcfs_reserved_cache, "system page cache reservation in mbytes (for arc cache)");

#ifdef HAVE_TOTALRAM_PAGES_AS_FUNC
  #define _totalram_pages() totalram_pages()
#else
  #define _totalram_pages() totalram_pages
#endif

unsigned long cfs_totalram_pages(void)
{
	if (libcfs_reserved_cache > _totalram_pages()/2)
		libcfs_reserved_cache = _totalram_pages() / 2;

	return _totalram_pages() - libcfs_reserved_cache;
}
EXPORT_SYMBOL(cfs_totalram_pages);
