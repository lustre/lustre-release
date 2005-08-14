/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite routines to issue a secondary close after writeback
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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

#include <linux/module.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_gs.h>
#include "llite_internal.h"

/* record that a write is in flight */
void llap_write_pending(struct inode *inode, struct ll_async_page *llap)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct page *page = llap->llap_page;
        spin_lock(&lli->lli_lock);
        CDEBUG(D_INODE, "track page 0x%p/%lu %s\n",
               page, (unsigned long) page->index,
               !list_empty(&llap->llap_pending_write) ? "(already)" : "");
        if (list_empty(&llap->llap_pending_write))
                list_add(&llap->llap_pending_write,
                         &lli->lli_pending_write_llaps);
        spin_unlock(&lli->lli_lock);
}

/* record that a write has completed */
void llap_write_complete(struct inode *inode, struct ll_async_page *llap)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        spin_lock(&lli->lli_lock);
        if (!list_empty(&llap->llap_pending_write))
                list_del_init(&llap->llap_pending_write);
        if (list_empty(&lli->lli_pending_write_llaps))
                wake_up(&lli->lli_dirty_wait);
        spin_unlock(&lli->lli_lock);
}

void ll_open_complete(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        spin_lock(&lli->lli_lock);
        lli->lli_send_done_writing = 0;
        spin_unlock(&lli->lli_lock);
}

/* if we close with writes in flight then we want the completion or cancelation
 * of those writes to send a DONE_WRITING rpc to the MDS */
int ll_is_inode_dirty(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        ENTRY;

        spin_lock(&lli->lli_lock);
        if (!list_empty(&lli->lli_pending_write_llaps))
                rc = 1;
        spin_unlock(&lli->lli_lock);
        RETURN(rc);
}

void ll_try_done_writing(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_close_queue *lcq = ll_i2sbi(inode)->ll_lcq;
        int added = 0;

        spin_lock(&lli->lli_lock);

        if (lli->lli_send_done_writing &&
            list_empty(&lli->lli_pending_write_llaps)) {
                spin_lock(&lcq->lcq_lock);
                if (list_empty(&lli->lli_close_item)) {
                        CDEBUG(D_INODE, "adding inode %lu/%u to close list\n",
                               inode->i_ino, inode->i_generation);
                        list_add_tail(&lli->lli_close_item, &lcq->lcq_list);
                        wake_up(&lcq->lcq_waitq);
                        added = 1;
                }
                spin_unlock(&lcq->lcq_lock);
        }

        spin_unlock(&lli->lli_lock);
       
        /* 
         * we can't grab inode under lli_lock, because:
         * ll_try_done_writing:                 ll_prep_inode:
         *   spin_lock(&lli_lock)                 spin_lock(&inode_lock)
         *     igrab()                              ll_update_inode()
         *       spin_lock(&inode_lock)               spin_lock(&lli_lock)
         */
        if (added)
                LASSERT(igrab(inode) == inode);
}

/* The MDS needs us to get the real file attributes, then send a DONE_WRITING */
void ll_queue_done_writing(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        CDEBUG(D_INODE, "queue closing for %lu/%u\n",
               inode->i_ino, inode->i_generation);
        spin_lock(&lli->lli_lock);
        lli->lli_send_done_writing = 1;
        spin_unlock(&lli->lli_lock);

        ll_try_done_writing(inode);
        EXIT;
}

/* If we know the file size and have the cookies:
 *  - send a DONE_WRITING rpc
 *
 * Otherwise:
 *  - get a whole-file lock
 *  - get the authoritative size and all cookies with GETATTRs
 *  - send a DONE_WRITING rpc
 */
static void ll_try_to_close(struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ll_md_real_close(sbi->ll_md_exp, inode, FMODE_WRITE | FMODE_SYNC);
}

static struct ll_inode_info *ll_close_next_lli(struct ll_close_queue *lcq)
{
        struct ll_inode_info *lli = NULL;

        spin_lock(&lcq->lcq_lock);

        /* first, check for queued request. otherwise, we would
         * leak them upon umount */
        if (!list_empty(&lcq->lcq_list)) {
                lli = list_entry(lcq->lcq_list.next, struct ll_inode_info,
                                 lli_close_item);
                list_del_init(&lli->lli_close_item);
        } else if (lcq->lcq_stop != 0) {
                lli = ERR_PTR(-1);
        }

        spin_unlock(&lcq->lcq_lock);
        return lli;
}

static int ll_close_thread(void *arg)
{
        struct ll_close_queue *lcq = arg;
        ENTRY;

        /* XXX boiler-plate */
        {
                char name[sizeof(current->comm)];
                unsigned long flags;
                snprintf(name, sizeof(name) - 1, "ll_close");
                kportal_daemonize(name);
                SIGNAL_MASK_LOCK(current, flags);
                sigfillset(&current->blocked);
                RECALC_SIGPENDING;
                SIGNAL_MASK_UNLOCK(current, flags);
        }

        complete(&lcq->lcq_comp);

        while (1) {
                struct l_wait_info lwi = { 0 };
                struct ll_inode_info *lli;
                struct inode *inode;

                l_wait_event_exclusive(lcq->lcq_waitq,
                                       (lli = ll_close_next_lli(lcq)) != NULL,
                                       &lwi);
                if (IS_ERR(lli))
                        break;

                inode = ll_info2i(lli);
                ll_try_to_close(inode);
                iput(inode);
        }

        EXIT;

        /* SMF-safe way to finish threads */
        complete_and_exit(&lcq->lcq_comp, 0);
}

int ll_close_thread_start(struct ll_close_queue **lcq_ret)
{
        struct ll_close_queue *lcq;
        pid_t pid;

        OBD_ALLOC(lcq, sizeof(*lcq));
        if (lcq == NULL)
                return -ENOMEM;

        lcq->lcq_stop = 0;
        spin_lock_init(&lcq->lcq_lock);
        INIT_LIST_HEAD(&lcq->lcq_list);
        init_waitqueue_head(&lcq->lcq_waitq);
        init_completion(&lcq->lcq_comp);

        pid = kernel_thread(ll_close_thread, lcq, 0);
        if (pid < 0) {
                OBD_FREE(lcq, sizeof(*lcq));
                return pid;
        }

        wait_for_completion(&lcq->lcq_comp);
        *lcq_ret = lcq;
        return 0;
}

void ll_close_thread_stop(struct ll_close_queue *lcq)
{
        init_completion(&lcq->lcq_comp);
        lcq->lcq_stop = 1;
        wake_up(&lcq->lcq_waitq);
        wait_for_completion(&lcq->lcq_comp);
        OBD_FREE(lcq, sizeof(*lcq));
}
