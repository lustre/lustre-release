/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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
 *
 */

#ifndef _COMPAT25_H
#define _COMPAT25_H

#ifdef __KERNEL__

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) && LINUX_VERSION_CODE < KERNEL_VERSION(2,5,69)
#error sorry, lustre requires at least 2.5.69
#endif

#include <linux/portals_compat25.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)

/*
 * OBD need working random driver, thus all our
 * initialization routines must be called after device
 * driver initialization
 */
#ifndef MODULE
#undef module_init
#define module_init(a)     late_initcall(a)
#endif

/* XXX our code should be using the 2.6 calls, not the other way around */
#define TryLockPage(page)                TestSetPageLocked(page)
#define filemap_fdatasync(mapping)       filemap_fdatawrite(mapping)
#define Page_Uptodate(page)              PageUptodate(page)

#define KDEVT_INIT(val)                 (val)

#define LTIME_S(time)                   (time.tv_sec)
#define ll_path_lookup                  path_lookup
#define ll_permission                   permission

#define ll_pgcache_lock(mapping)          spin_lock(&mapping->page_lock)
#define ll_pgcache_unlock(mapping)        spin_unlock(&mapping->page_lock)

#define ll_vfs_create(a,b,c,d)              vfs_create(a,b,c,d)

#define ll_dev_t                        dev_t
#define kdev_t                          dev_t
#define to_kdev_t(dev)                  (dev)
#define kdev_t_to_nr(dev)               (dev)
#define val_to_kdev(dev)                (dev)
#define ILOOKUP(sb, ino, test, data)    ilookup5(sb, ino, test, data);

#include <linux/writeback.h>

static inline void lustre_daemonize_helper(void)
{
        LASSERT(current->signal != NULL);
        current->session = 1;
        if (current->group_leader)
                current->group_leader->__pgrp = 1;
        else
                CERROR("we aren't group leader\n");
        current->tty = NULL;
}

#define  rb_node_s rb_node
#define  rb_root_s rb_root
typedef struct rb_root_s rb_root_t;
typedef struct rb_node_s rb_node_t;

#define smp_num_cpus    NR_CPUS

#ifndef conditional_schedule
#define conditional_schedule() cond_resched()
#endif

#include <linux/proc_fs.h>

#else /* 2.4.. */

#define ll_vfs_create(a,b,c,d)              vfs_create(a,b,c)
#define ll_permission(a,b,c)                permission(a,b)
#define ILOOKUP(sb, ino, test, data)        ilookup4(sb, ino, test, data);
#define DCACHE_DISCONNECTED                 DCACHE_NFSD_DISCONNECTED
#define ll_dev_t                            int

static inline void clear_page_dirty(struct page *page)
{
        if (PageDirty(page))
                ClearPageDirty(page); 
}

/* 2.5 uses hlists for some things, like the d_hash.  we'll treat them
 * as 2.5 and let macros drop back.. */
#ifndef HLIST_HEAD /* until we get a kernel newer than l28 */
#define hlist_entry                     list_entry
#define hlist_head                      list_head
#define hlist_node                      list_head
#define HLIST_HEAD                      LIST_HEAD
#define INIT_HLIST_HEAD                 INIT_LIST_HEAD
#define hlist_del_init                  list_del_init
#define hlist_add_head                  list_add
#define hlist_for_each_safe             list_for_each_safe
#endif
#define KDEVT_INIT(val)                 (val)
#define ext3_xattr_set_handle           ext3_xattr_set
#define extN_xattr_set_handle           extN_xattr_set
#define try_module_get                  __MOD_INC_USE_COUNT
#define module_put                      __MOD_DEC_USE_COUNT
#define LTIME_S(time)                   (time)
#if !defined(CONFIG_RH_2_4_20) && !defined(cpu_online)
#define cpu_online(cpu)                 (cpu_online_map & (1<<cpu))
#endif

static inline int ll_path_lookup(const char *path, unsigned flags, 
                              struct nameidata *nd)
{
        int error = 0;
        if (path_init(path, flags, nd))
                error = path_walk(path, nd);
        return error;
}
#define ll_permission(a,b,c)  permission(a,b)
typedef long sector_t;

#define ll_pgcache_lock(mapping)        spin_lock(&pagecache_lock)
#define ll_pgcache_unlock(mapping)      spin_unlock(&pagecache_lock)

static inline void __d_drop(struct dentry *dentry)
{
	list_del(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_hash);
}

static inline void lustre_daemonize_helper(void)
{
        current->session = 1;
        current->pgrp = 1;
        current->tty = NULL;
}

#ifndef conditional_schedule
#define conditional_schedule() if (unlikely(need_resched())) schedule()
#endif

/* to find proc_dir_entry from inode. 2.6 has native one -bzzz */
#ifndef HAVE_PDE
#define PDE(ii)         ((ii)->u.generic_ip)
#endif

#endif /* end of 2.4 compat macros */

#endif /* __KERNEL__ */
#endif /* _COMPAT25_H */
