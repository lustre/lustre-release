/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#include <linux/fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/kmod.h>

#include <linux/lustre_lite.h>
#include "llite_internal.h"

/* After roughly how long should we remove an inactive mount? */
#define GNS_MOUNT_TIMEOUT 120
/* How often should the GNS timer look for mounts to cleanup? */
#define GNS_TICK 30

int ll_finish_gns(struct ll_sb_info *sbi)
{
        down(&sbi->ll_gns_sem);
        if (sbi->ll_gns_state != LL_GNS_STATE_MOUNTING) {
                up(&sbi->ll_gns_sem);
                CERROR("FINISH_GNS called on mount which was not expecting "
                       "completion.\n");
                return -EINVAL;
        }

        sbi->ll_gns_state = LL_GNS_STATE_FINISHED;
        up(&sbi->ll_gns_sem);
        complete(&sbi->ll_gns_completion);

        return 0;
}

/* Pass exactly one (1) page in; when this function returns "page" will point
 * somewhere into the middle of the page. */
int fill_page_with_path(struct dentry *dentry, struct vfsmount *mnt,
                        char **pagep)
{
        char *path = *pagep, *p;

        path[PAGE_SIZE - 1] = '\0';
        p = path + PAGE_SIZE - 1;

        while (1) {
                if (p - path < dentry->d_name.len + 1)
                        return -ENAMETOOLONG;
                if (dentry->d_name.name[0] != '/') {
                        p -= dentry->d_name.len;
                        memcpy(p, dentry->d_name.name, dentry->d_name.len);
                        p--;
                        *p = '/';
                }

                dentry = dentry->d_parent;
                if (dentry->d_parent == dentry) {
                        if (mnt->mnt_parent == mnt)
                                break; /* finished walking up */
                        mnt = mntget(mnt);
                        dget(dentry);
                        while (dentry->d_parent == dentry &&
                               follow_up(&mnt, &dentry))
                                ;
                        mntput(mnt);
                        dput(dentry);
                }
        }
        *pagep = p;
        return 0;
}

int ll_dir_process_mount_object(struct dentry *dentry, struct vfsmount *mnt)
{
        struct ll_sb_info *sbi;
        struct file *mntinfo_fd;
        struct page *datapage, *pathpage;
        struct address_space *mapping;
        struct ll_dentry_data *lld = dentry->d_fsdata;
        struct dentry *dchild, *tmp_dentry;
        struct vfsmount *tmp_mnt;
        char *p, *path, *argv[4];
        int stage = 0, rc = 0;
        ENTRY;

        if (mnt == NULL) {
                CERROR("suid directory found, but no vfsmount available.\n");
                RETURN(-1);
        }

        LASSERT(dentry->d_inode != NULL);
        LASSERT(lld != NULL);
        sbi = ll_i2sbi(dentry->d_inode);
        LASSERT(sbi != NULL);

        down(&sbi->ll_gns_sem);
        if (sbi->ll_gns_state == LL_GNS_STATE_MOUNTING) {
                up(&sbi->ll_gns_sem);
                wait_for_completion(&sbi->ll_gns_completion);
                if (d_mountpoint(dentry))
                        RETURN(0);
                RETURN(-1);
        }
        if (sbi->ll_gns_state == LL_GNS_STATE_FINISHED) {
                /* we lost a race; just return */
                up(&sbi->ll_gns_sem);
                if (d_mountpoint(dentry))
                        RETURN(0);
                RETURN(-1);
        }
        LASSERT(sbi->ll_gns_state == LL_GNS_STATE_IDLE);
        sbi->ll_gns_state = LL_GNS_STATE_MOUNTING;
        up(&sbi->ll_gns_sem);

        /* We need to build an absolute pathname to pass to mount */
        pathpage = alloc_pages(GFP_HIGHUSER, 0);
        if (pathpage == NULL)
                GOTO(cleanup, rc = -ENOMEM);
        path = kmap(pathpage);
        LASSERT(path != NULL);
        stage = 1;
        fill_page_with_path(dentry, mnt, &path);

        dchild = lookup_one_len(".mntinfo", dentry, strlen(".mntinfo"));
        if (dchild == NULL || IS_ERR(dchild)) {
                CERROR("Directory %*s is setuid, but without a mount object.\n",
                       dentry->d_name.len, dentry->d_name.name);
                GOTO(cleanup, rc = -1);
        }

        mntget(mnt);

        mntinfo_fd = dentry_open(dchild, mnt, 0);
        if (IS_ERR(mntinfo_fd)) {
                dput(dchild);
                mntput(mnt);
                GOTO(cleanup, rc = PTR_ERR(mntinfo_fd));
        }
        stage = 2;

        if (mntinfo_fd->f_dentry->d_inode->i_size > PAGE_SIZE) {
                CERROR("Mount object file is too big (%Ld)\n",
                       mntinfo_fd->f_dentry->d_inode->i_size);
                GOTO(cleanup, rc = -1);
        }
        mapping = mntinfo_fd->f_dentry->d_inode->i_mapping;
        datapage = read_cache_page(mapping, 0,
                                   (filler_t *)mapping->a_ops->readpage,
                                   mntinfo_fd);
        if (IS_ERR(datapage))
                GOTO(cleanup, rc = PTR_ERR(datapage));

        p = kmap(datapage);
        LASSERT(p != NULL);
        stage = 3;

        p[PAGE_SIZE - 1] = '\0';

        fput(mntinfo_fd);
        mntinfo_fd = NULL;

        argv[0] = "/usr/local/bin/phikmount.sh";
        argv[1] = p;
        argv[2] = path;
        argv[3] = NULL;
        rc = call_usermodehelper(argv[0], argv, NULL);

        if (rc != 0) {
                CERROR("GNS mount failed: %d\n", rc);
                GOTO(cleanup, rc);
        }

        wait_for_completion(&sbi->ll_gns_completion);
        LASSERT(sbi->ll_gns_state == LL_GNS_STATE_FINISHED);

        if (d_mountpoint(dentry)) {
                /* successful follow_down will mntput and dput */
                tmp_mnt = mntget(mnt);
                tmp_dentry = dget(dentry);
                rc = follow_down(&tmp_mnt, &tmp_dentry);
                if (rc == 1) {
                        struct ll_sb_info *sbi = ll_s2sbi(dentry->d_sb);
                        spin_lock(&dcache_lock);
                        LASSERT(list_empty(&tmp_mnt->mnt_lustre_list));
                        list_add_tail(&tmp_mnt->mnt_lustre_list,
                                      &sbi->ll_mnt_list);
                        spin_unlock(&dcache_lock);

                        tmp_mnt->mnt_last_used = jiffies;

                        mntput(tmp_mnt);
                        dput(tmp_dentry);
                        rc = 0;
                } else {
                        mntput(mnt);
                        dput(dentry);
                }
        } else {
                CERROR("Woke up from GNS mount, but no mountpoint in place.\n");
                rc = -1;
        }

        EXIT;
cleanup:
        switch (stage) {
        case 3:
                kunmap(datapage);
                page_cache_release(datapage);
        case 2:
                if (mntinfo_fd != NULL)
                        fput(mntinfo_fd);
        case 1:
                kunmap(pathpage);
                __free_pages(pathpage, 0);
        case 0:
                down(&sbi->ll_gns_sem);
                sbi->ll_gns_state = LL_GNS_STATE_IDLE;
                up(&sbi->ll_gns_sem);
        }
        return rc;
}

/* If timeout == 1, only remove the mounts which are properly aged.
 *
 * If timeout == 0, we are unmounting -- remove them all. */
int ll_gns_umount_all(struct ll_sb_info *sbi, int timeout)
{
        struct list_head kill_list = LIST_HEAD_INIT(kill_list);
        struct page *page = NULL;
        char *kpage, *path;
        int rc;
        ENTRY;

        if (timeout == 0) {
                page = alloc_pages(GFP_HIGHUSER, 0);
                if (page == NULL)
                        RETURN(-ENOMEM);
                kpage = kmap(page);
                LASSERT(kpage != NULL);
        }

        spin_lock(&dcache_lock);
        list_splice_init(&sbi->ll_mnt_list, &kill_list);

        /* Walk the list in reverse order, and put them on the front of the
         * sbi list each iteration; this avoids list-ordering problems if we
         * race with another gns-mounting thread */
        while (!list_empty(&kill_list)) {
                struct vfsmount *mnt =
                        list_entry(kill_list.prev, struct vfsmount,
                                   mnt_lustre_list);
                mntget(mnt);
                list_del_init(&mnt->mnt_lustre_list);
                list_add(&mnt->mnt_lustre_list, &sbi->ll_mnt_list);

                if (timeout &&
                    jiffies - mnt->mnt_last_used < GNS_MOUNT_TIMEOUT * HZ) {
                        mntput(mnt);
                        continue;
                }
                spin_unlock(&dcache_lock);

                CDEBUG(D_INODE, "unmounting mnt %p from sbi %p\n", mnt, sbi);

                rc = do_umount(mnt, 0);
                if (rc != 0 && page != NULL) {
                        int rc2;
                        path = kpage;
                        rc2 = fill_page_with_path(mnt->mnt_root, mnt, &path);
                        CERROR("GNS umount(%s): %d\n", rc2 == 0 ? path : "",
                               rc);
                }
                mntput(mnt);
                spin_lock(&dcache_lock);
        }
        spin_unlock(&dcache_lock);

        if (page != NULL) {
                kunmap(page);
                __free_pages(page, 0);
        }
        RETURN(0);
}

static struct list_head gns_sbi_list = LIST_HEAD_INIT(gns_sbi_list);
static struct semaphore gns_sem;
static struct ptlrpc_thread gns_thread;

void ll_gns_timer_callback(unsigned long data)
{
        struct ll_sb_info *sbi = (void *)data;
        ENTRY;

        down(&gns_sem);
        if (list_empty(&sbi->ll_gns_sbi_head))
                list_add(&sbi->ll_gns_sbi_head, &gns_sbi_list);
        up(&gns_sem);
        wake_up(&gns_thread.t_ctl_waitq);
        mod_timer(&sbi->ll_gns_timer, jiffies + GNS_TICK * HZ);
}

static int gns_check_event(void)
{
        int rc;
        down(&gns_sem);
        rc = !list_empty(&gns_sbi_list);
        up(&gns_sem);
        return rc;
}

static int ll_gns_thread_main(void *arg)
{
        unsigned long flags;
        ENTRY;

        {
                char name[sizeof(current->comm)];
                snprintf(name, sizeof(name) - 1, "ll_gns");
                kportal_daemonize(name);
        }
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        gns_thread.t_flags = SVC_RUNNING;
        wake_up(&gns_thread.t_ctl_waitq);

        while ((gns_thread.t_flags & SVC_STOPPING) == 0) {
                struct l_wait_info lwi = { 0 };

                l_wait_event(gns_thread.t_ctl_waitq, gns_check_event() ||
                             gns_thread.t_flags & SVC_STOPPING, &lwi);

                down(&gns_sem);
                while (!list_empty(&gns_sbi_list)) {
                        struct ll_sb_info *sbi =
                                list_entry(gns_sbi_list.prev, struct ll_sb_info,
                                           ll_gns_sbi_head);
                        list_del_init(&sbi->ll_gns_sbi_head);
                        ll_gns_umount_all(sbi, 1);
                }
                up(&gns_sem);
        }

        gns_thread.t_flags = SVC_STOPPED;
        wake_up(&gns_thread.t_ctl_waitq);

        RETURN(0);
}

void ll_gns_add_timer(struct ll_sb_info *sbi)
{
        mod_timer(&sbi->ll_gns_timer, jiffies + GNS_TICK * HZ);
}

void ll_gns_del_timer(struct ll_sb_info *sbi)
{
        del_timer(&sbi->ll_gns_timer);
}

int ll_gns_start_thread(void)
{
        struct l_wait_info lwi = { 0 };
        int rc;

        LASSERT(gns_thread.t_flags == 0);
        sema_init(&gns_sem, 1);

        init_waitqueue_head(&gns_thread.t_ctl_waitq);
        rc = kernel_thread(ll_gns_thread_main, NULL, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                return rc;
        }
        l_wait_event(gns_thread.t_ctl_waitq, gns_thread.t_flags & SVC_RUNNING,
                     &lwi);
        return 0;
}

void ll_gns_stop_thread(void)
{
        struct l_wait_info lwi = { 0 };

        down(&gns_sem);
        gns_thread.t_flags = SVC_STOPPING;
        up(&gns_sem);

        wake_up(&gns_thread.t_ctl_waitq);
        l_wait_event(gns_thread.t_ctl_waitq, gns_thread.t_flags & SVC_STOPPED,
                     &lwi);
        gns_thread.t_flags = 0;
}
