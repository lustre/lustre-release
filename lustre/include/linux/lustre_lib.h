/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 * Basic Lustre library routines. 
 *
 */

#ifndef _LUSTRE_LIB_H
#define _LUSTRE_LIB_H

#include <asm/types.h>

#ifndef __KERNEL__
# include <string.h>
#endif

#include <linux/portals_lib.h>
#include <asm/semaphore.h>
#include <linux/lustre_idl.h>

#ifdef __KERNEL__
/* l_lock.c */
struct lustre_lock { 
        int l_depth;
        struct task_struct *l_owner;
        struct semaphore l_sem;
        spinlock_t l_spin;
};

void l_lock_init(struct lustre_lock *);
void l_lock(struct lustre_lock *);
void l_unlock(struct lustre_lock *);


/* page.c */
inline void lustre_put_page(struct page *page);
struct page *lustre_get_page_read(struct inode *dir, unsigned long index);
struct page *lustre_get_page_write(struct inode *dir, unsigned long index);
int lustre_commit_page(struct page *page, unsigned from, unsigned to);
void set_page_clean(struct page *page);
void set_page_dirty(struct page *page);

/* simple.c */
struct obd_run_ctxt;
void push_ctxt(struct obd_run_ctxt *save, struct obd_run_ctxt *new);
void pop_ctxt(struct obd_run_ctxt *saved);
#ifdef CTXT_DEBUG
#define OBD_SET_CTXT_MAGIC(ctxt) (ctxt)->magic = OBD_RUN_CTXT_MAGIC
#else
#define OBD_SET_CTXT_MAGIC(magic) do {} while(0)
#endif
struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode);
int lustre_fread(struct file *file, char *str, int len, loff_t *off);
int lustre_fwrite(struct file *file, const char *str, int len, loff_t *off);
int lustre_fsync(struct file *file);

static inline void l_dput(struct dentry *de)
{
        if (!de || IS_ERR(de))
                return;
        shrink_dcache_parent(de);
        dput(de);
}

static inline void ll_sleep(int t)
{
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(t * HZ);
        set_current_state(TASK_RUNNING);
}
#endif

/* FIXME: This needs to validate pointers and cookies */
static inline void *lustre_handle2object(struct lustre_handle *handle)
{
        if (handle) 
                return (void *)(unsigned long)(handle->addr);
        return NULL; 
}

static inline void ldlm_object2handle(void *object, struct lustre_handle *handle)
{
        handle->addr = (__u64)(unsigned long)object;
}

struct obd_statfs;
struct statfs;
void obd_statfs_pack(struct obd_statfs *osfs, struct statfs *sfs);
void obd_statfs_unpack(struct obd_statfs *osfs, struct statfs *sfs);

#include <linux/portals_lib.h>

#endif /* _LUSTRE_LIB_H */
