/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define SIGNAL_MASK_LOCK(task, flags)         spin_lock_irqsave(                     \
		&task->sighand->siglock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)       spin_unlock_irqrestore(                \
		&task->sighand->siglock, flags)
#else
# define SIGNAL_MASK_LOCK(task, flags)         spin_lock_irqsave(                     \
		&task->sigmask_lock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)       spin_unlock_irqrestore(                \
		&task->sigmask_lock, flags)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define PGCACHE_WRLOCK(mapping)          write_lock(&mapping->page_lock)
# define PGCACHE_WRUNLOCK(mapping)        write_unlock(&mapping->page_lock)
#else
# define PGCACHE_WRLOCK(mapping)          spin_lock(&pagecache_lock)
# define PGCACHE_WRUNLOCK(mapping)        spin_unlock(&pagecache_lock)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define filemap_fdatasync(mapping)       filemap_fdatawrite(mapping)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define TryLockPage(page)                TestSetPageLocked(page)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define Page_Uptodate(page)              PageUptodate(page)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define USERMODEHELPER(path, argv, envp) call_usermodehelper(path, argv, envp, 0)
#else
# define USERMODEHELPER(path, argv, envp) call_usermodehelper(path, argv, envp)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define LL_CHECK_DIRTY(sb)              do { }while(0)
#else
# define LL_CHECK_DIRTY(sb)              ll_check_dirty(sb)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
# define RECALC_SIGPENDING         recalc_sigpending()
#else
# define RECALC_SIGPENDING         recalc_sigpending(current)
#endif


#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
#define  rb_node_s rb_node
#define  rb_root_s rb_root
typedef struct rb_root_s rb_root_t;
typedef struct rb_node_s rb_node_t;
#endif

#endif /* _COMPAT25_H */
