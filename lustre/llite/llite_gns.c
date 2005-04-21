/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004, 2005 Cluster File Systems, Inc.
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Oleg Drokin <green@clusterfs.com>
 * Author: Yury Umanets <yury@clusterfs.com>
 * Review: Nikita Danilov <nikita@clusterfs.com>
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

static struct list_head gns_sbi_list = LIST_HEAD_INIT(gns_sbi_list);
static spinlock_t gns_lock = SPIN_LOCK_UNLOCKED;
static struct ptlrpc_thread gns_thread;
static struct ll_gns_ctl gns_ctl;

/*
 * waits until passed dentry gets mountpoint or timeout and attempts are
 * exhausted. Returns 1 if dentry became mountpoint and 0 otherwise.
 */
static int
ll_gns_wait_for_mount(struct dentry *dentry,
                      int timeout, int tries)
{
        struct l_wait_info lwi;
        struct ll_sb_info *sbi;
        ENTRY;

        LASSERT(dentry != NULL);
        LASSERT(!IS_ERR(dentry));
        sbi = ll_s2sbi(dentry->d_sb);
        
        lwi = LWI_TIMEOUT(timeout * HZ, NULL, NULL);
        for (; !d_mountpoint(dentry) && tries > 0; tries--)
                l_wait_event(sbi->ll_gns_waitq, d_mountpoint(dentry), &lwi);

        if (d_mountpoint(dentry)) {
                spin_lock(&sbi->ll_gns_lock);
                sbi->ll_gns_state = LL_GNS_FINISHED;
                spin_unlock(&sbi->ll_gns_lock);
                RETURN(0);
        }
        RETURN(-ETIME);
}

/*
 * tries to mount the mount object under passed @dentry. In the case of success
 * @dentry will become mount point and 0 will be returned. Error code will be
 * returned otherwise.
 */
int
ll_gns_mount_object(struct dentry *dentry, struct vfsmount *mnt)
{
        struct ll_dentry_data *lld = dentry->d_fsdata;
        char *path, *pathpage, *datapage, *argv[4];
        struct file *mntinfo_fd = NULL;
        int cleanup_phase = 0, rc = 0;
        struct ll_sb_info *sbi;
        struct dentry *dchild;
        ENTRY;

        if (mnt == NULL) {
                CERROR("suid directory found, but no "
                       "vfsmount available.\n");
                RETURN(-EINVAL);
        }

        CDEBUG(D_INODE, "mounting dentry %p\n", dentry);

        LASSERT(dentry->d_inode != NULL);
        LASSERT(S_ISDIR(dentry->d_inode->i_mode));
        LASSERT(lld != NULL);
        
        sbi = ll_i2sbi(dentry->d_inode);
        LASSERT(sbi != NULL);

        /* 
         * another thead is in progress or just finished mounting the
         * dentry. Handling that.
         */
        spin_lock(&sbi->ll_gns_lock);
        if (sbi->ll_gns_state == LL_GNS_MOUNTING ||
            sbi->ll_gns_state == LL_GNS_FINISHED) {
                spin_unlock(&sbi->ll_gns_lock);
                CDEBUG(D_INODE, "GNS is in progress now, throwing "
                       "-ERESTARTSYS to restart syscall and let "
                       "it finish.\n");
                RETURN(-ERESTARTSYS);
        }
        LASSERT(sbi->ll_gns_state == LL_GNS_IDLE);

        /* mounting started */
        sbi->ll_gns_state = LL_GNS_MOUNTING;
        spin_unlock(&sbi->ll_gns_lock);

        /* we need to build an absolute pathname to pass to mount */
        pathpage = (char *)__get_free_page(GFP_KERNEL);
        if (!pathpage)
                GOTO(cleanup, rc = -ENOMEM);
        cleanup_phase = 1;

        /* getting @dentry path stored in @pathpage. */
        path = d_path(dentry, mnt, pathpage, PAGE_SIZE);
        if (IS_ERR(path)) {
                CERROR("can't build mount object path, err %d\n",
                       (int)PTR_ERR(dchild));
                GOTO(cleanup, rc = PTR_ERR(dchild));
        }

        /* synchronizing with possible /proc/fs/...write */
        down(&sbi->ll_gns_sem);
        
        /* 
         * mount object name is taken from sbi, where it is set in mount time or
         * via /proc/fs... tunable. It may be ".mntinfo" or so.
         */
        dchild = lookup_one_len(sbi->ll_gns_oname, dentry,
                                strlen(sbi->ll_gns_oname));
        up(&sbi->ll_gns_sem);

        cleanup_phase = 2;
        
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                
                if (rc == -ERESTARTSYS) {
                        CDEBUG(D_INODE, "possible endless loop is detected "
                               "due to mount object is directory marked by "
                               "SUID bit.\n");
                        GOTO(cleanup, rc = -ELOOP);
                }

                CERROR("can't find mount object %*s/%*s err = %d.\n",
                       (int)dentry->d_name.len, dentry->d_name.name,
                       strlen(sbi->ll_gns_oname), sbi->ll_gns_oname,
                       rc);
                GOTO(cleanup, rc);
        }

        /* mount object is not found */
        if (!dchild->d_inode)
                GOTO(cleanup, rc = -ENOENT);

        /* check if found child is regular file */
        if (!S_ISREG(dchild->d_inode->i_mode))
                GOTO(cleanup, rc = -EOPNOTSUPP);

        mntget(mnt);

        /* ok, mount object if found, opening it. */
        mntinfo_fd = dentry_open(dchild, mnt, 0);
        if (IS_ERR(mntinfo_fd)) {
                CERROR("can't open mount object %*s/%*s err = %d.\n",
                       (int)dentry->d_name.len, dentry->d_name.name,
                       strlen(sbi->ll_gns_oname), sbi->ll_gns_oname,
                       (int)PTR_ERR(mntinfo_fd));
                mntput(mnt);
                GOTO(cleanup, rc = PTR_ERR(mntinfo_fd));
        }
        cleanup_phase = 3;

        if (mntinfo_fd->f_dentry->d_inode->i_size > PAGE_SIZE) {
                CERROR("mount object %*s/%*s is too big (%Ld)\n",
                       (int)dentry->d_name.len, dentry->d_name.name,
                       strlen(sbi->ll_gns_oname), sbi->ll_gns_oname,
                       mntinfo_fd->f_dentry->d_inode->i_size);
                GOTO(cleanup, rc = -EFBIG);
        }

        datapage = (char *)__get_free_page(GFP_KERNEL);
        if (!datapage)
                GOTO(cleanup, rc = -ENOMEM);

        cleanup_phase = 4;
        
        /* read data from mount object. */
        rc = kernel_read(mntinfo_fd, 0, datapage, PAGE_SIZE);
        if (rc < 0) {
                CERROR("can't read mount object %*s/%*s data, err %d\n",
                       (int)dentry->d_name.len, dentry->d_name.name,
                       strlen(sbi->ll_gns_oname), sbi->ll_gns_oname,
                       rc);
                GOTO(cleanup, rc);
        }

        datapage[PAGE_SIZE - 1] = '\0';

        fput(mntinfo_fd);
        mntinfo_fd = NULL;
        dchild = NULL;

        /* synchronizing with possible /proc/fs/...write */
        down(&sbi->ll_gns_sem);

        /*
         * upcall is initialized in mount time or via /proc/fs/... tuneable and
         * may be /usr/lib/lustre/gns-upcall.sh
         */
        argv[0] = sbi->ll_gns_upcall;
        argv[1] = datapage;
        argv[2] = path;
        argv[3] = NULL;
        
        up(&sbi->ll_gns_sem);

        rc = USERMODEHELPER(argv[0], argv, NULL);
        if (rc) {
                CERROR("failed to call GNS upcall %s, err = %d\n",
                       sbi->ll_gns_upcall, rc);
                GOTO(cleanup, rc);
        }

        /*
         * wait for mount completion. This is actually not need, because
         * USERMODEHELPER() returns only when usermode process finishes. But we
         * doing this just for case USERMODEHELPER() semantics will be changed
         * or usermode upcall program will start mounting in backgound and
         * return instantly. --umka
         */
        rc = ll_gns_wait_for_mount(dentry, 1, GNS_WAIT_ATTEMPTS);
        complete_all(&sbi->ll_gns_mount_finished);
        if (rc == 0) {
                struct dentry *rdentry;
                struct vfsmount *rmnt;
                
                /* mount is successful */
                LASSERT(sbi->ll_gns_state == LL_GNS_FINISHED);

                rmnt = mntget(mnt);
                rdentry = dget(dentry);
                
                if (follow_down(&rmnt, &rdentry)) {
                        /* 
                         * registering new mount in GNS mounts list and thus
                         * make it accessible from GNS control thread.
                         */
                        spin_lock(&dcache_lock);
                        LASSERT(list_empty(&rmnt->mnt_lustre_list));
                        list_add_tail(&rmnt->mnt_lustre_list,
                                      &sbi->ll_mnt_list);
                        spin_unlock(&dcache_lock);
                        rmnt->mnt_last_used = jiffies;
                        mntput(rmnt);
                        dput(rdentry);
                } else {
                        mntput(mnt);
                        dput(dentry);
                }
        } else {
                CERROR("usermode upcall %s failed to mount %s, err %d\n",
                       sbi->ll_gns_upcall, path, rc);
        }
                
        EXIT;
cleanup:
        switch (cleanup_phase) {
        case 4:
                free_page((unsigned long)datapage);
        case 3:
                if (mntinfo_fd != NULL)
                        fput(mntinfo_fd);
        case 2:
                if (dchild != NULL)
                        dput(dchild);
        case 1:
                free_page((unsigned long)pathpage);
                
                /* 
                 * waking up all waiters after gns state is set to
                 * LL_GNS_MOUNTING
                 */
                complete_all(&sbi->ll_gns_mount_finished);
        case 0:
                spin_lock(&sbi->ll_gns_lock);
                sbi->ll_gns_state = LL_GNS_IDLE;
                spin_unlock(&sbi->ll_gns_lock);
        }
        return rc;
}

/* tries to umount passed @mnt. */
int ll_gns_umount_object(struct vfsmount *mnt)
{
        int rc = 0;
        ENTRY;
        
        CDEBUG(D_INODE, "unmounting mnt %p\n", mnt);
        rc = do_umount(mnt, 0);
        if (rc) {
                CDEBUG(D_INODE, "can't umount 0x%p, err = %d\n",
                       mnt, rc);
        }
        
        RETURN(rc);
}

int ll_gns_check_mounts(struct ll_sb_info *sbi, int flags)
{
        struct list_head check_list = LIST_HEAD_INIT(check_list);
        struct vfsmount *mnt;
        unsigned long pass;
        ENTRY;

        spin_lock(&dcache_lock);
        list_splice_init(&sbi->ll_mnt_list, &check_list);

        /*
         * walk the list in reverse order, and put them on the front of the sbi
         * list each iteration; this avoids list-ordering problems if we race
         * with another gns-mounting thread.
         */
        while (!list_empty(&check_list)) {
                mnt = list_entry(check_list.prev,
                                 struct vfsmount,
                                 mnt_lustre_list);

                mntget(mnt);

                list_del_init(&mnt->mnt_lustre_list);

                list_add(&mnt->mnt_lustre_list,
                         &sbi->ll_mnt_list);

                /* check for timeout if needed */
                pass = jiffies - mnt->mnt_last_used;
                
                if (flags == LL_GNS_CHECK &&
                    pass < sbi->ll_gns_timeout * HZ)
                {
                        mntput(mnt);
                        continue;
                }
                spin_unlock(&dcache_lock);

                /* umounting @mnt */
                ll_gns_umount_object(mnt);

                mntput(mnt);
                spin_lock(&dcache_lock);
        }
        spin_unlock(&dcache_lock);
        RETURN(0);
}

/*
 * GNS timer callback function. It restarts gns timer and wakes up GNS control
 * thread to process mounts list.
 */
void ll_gns_timer_callback(unsigned long data)
{
        struct ll_sb_info *sbi = (void *)data;
        ENTRY;

        spin_lock(&gns_lock);
        if (list_empty(&sbi->ll_gns_sbi_head))
                list_add(&sbi->ll_gns_sbi_head, &gns_sbi_list);
        spin_unlock(&gns_lock);
        
        wake_up(&gns_thread.t_ctl_waitq);
        mod_timer(&sbi->ll_gns_timer,
                  jiffies + sbi->ll_gns_tick * HZ);
}

/* this function checks if something new happened to exist in gns list. */
static int inline ll_gns_check_event(void)
{
        int rc;
        
        spin_lock(&gns_lock);
        rc = !list_empty(&gns_sbi_list);
        spin_unlock(&gns_lock);

        return rc;
}

/* should we stop GNS control thread? */
static int inline ll_gns_check_stop(void)
{
        mb();
        return (gns_thread.t_flags & SVC_STOPPING) ? 1 : 0;
}

/* GNS control thread function. */
static int ll_gns_thread_main(void *arg)
{
        struct ll_gns_ctl *ctl = arg;
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

        /*
         * letting starting function know, that we are ready and control may be
         * returned.
         */
        gns_thread.t_flags = SVC_RUNNING;
        complete(&ctl->gc_starting);

        while (!ll_gns_check_stop()) {
                struct l_wait_info lwi = { 0 };

                l_wait_event(gns_thread.t_ctl_waitq,
                             (ll_gns_check_event() ||
                              ll_gns_check_stop()), &lwi);
                
                spin_lock(&gns_lock);
                while (!list_empty(&gns_sbi_list)) {
                        struct ll_sb_info *sbi;

                        sbi = list_entry(gns_sbi_list.prev,
                                         struct ll_sb_info,
                                         ll_gns_sbi_head);
                        
                        list_del_init(&sbi->ll_gns_sbi_head);
                        spin_unlock(&gns_lock);
                        ll_gns_check_mounts(sbi, LL_GNS_CHECK);
                        spin_lock(&gns_lock);
                }
                spin_unlock(&gns_lock);
        }

        EXIT;
        gns_thread.t_flags = SVC_STOPPED;

        /* this is SMP-safe way to finish thread. */
        complete_and_exit(&ctl->gc_finishing, 0);
}

void ll_gns_add_timer(struct ll_sb_info *sbi)
{
        mod_timer(&sbi->ll_gns_timer,
                  jiffies + sbi->ll_gns_tick * HZ);
}

void ll_gns_del_timer(struct ll_sb_info *sbi)
{
        del_timer(&sbi->ll_gns_timer);
}

/*
 * starts GNS control thread and waits for a signal it is up and work may be
 * continued.
 */
int ll_gns_start_thread(void)
{
        int rc;
        ENTRY;

        LASSERT(gns_thread.t_flags == 0);
        init_completion(&gns_ctl.gc_starting);
        init_completion(&gns_ctl.gc_finishing);
        init_waitqueue_head(&gns_thread.t_ctl_waitq);
        
        rc = kernel_thread(ll_gns_thread_main, &gns_ctl,
                           (CLONE_VM | CLONE_FILES));
        if (rc < 0) {
                CERROR("cannot start GNS control thread, "
                       "err = %d\n", rc);
                RETURN(rc);
        }
        wait_for_completion(&gns_ctl.gc_starting);
        LASSERT(gns_thread.t_flags == SVC_RUNNING);
        RETURN(0);
}

/* stops GNS control thread and waits its actual stop. */
void ll_gns_stop_thread(void)
{
        ENTRY;
        gns_thread.t_flags = SVC_STOPPING;
        wake_up(&gns_thread.t_ctl_waitq);
        wait_for_completion(&gns_ctl.gc_finishing);
        LASSERT(gns_thread.t_flags == SVC_STOPPED);
        gns_thread.t_flags = 0;
        EXIT;
}
