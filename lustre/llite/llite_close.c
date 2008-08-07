/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/llite_close.c
 *
 * Lustre Lite routines to issue a secondary close after writeback
 */

#include <linux/module.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <lustre_lite.h>
#include "llite_internal.h"

#ifdef HAVE_CLOSE_THREAD
/* record that a write is in flight */
void llap_write_pending(struct inode *inode, struct ll_async_page *llap)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        spin_lock(&lli->lli_lock);
        list_add(&llap->llap_pending_write, &lli->lli_pending_write_llaps);
        spin_unlock(&lli->lli_lock);
}

/* record that a write has completed */
void llap_write_complete(struct inode *inode, struct ll_async_page *llap)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        spin_lock(&lli->lli_lock);
        list_del_init(&llap->llap_pending_write);
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

        spin_lock(&lli->lli_lock);

        if (lli->lli_send_done_writing &&
            list_empty(&lli->lli_pending_write_llaps)) {

                spin_lock(&lcq->lcq_lock);
                if (list_empty(&lli->lli_close_item)) {
                        CDEBUG(D_INODE, "adding inode %lu/%u to close list\n",
                               inode->i_ino, inode->i_generation);
                        igrab(inode);
                        list_add_tail(&lli->lli_close_item, &lcq->lcq_list);
                        wake_up(&lcq->lcq_waitq);
                }
                spin_unlock(&lcq->lcq_lock);
        }

        spin_unlock(&lli->lli_lock);
}

/* The MDS needs us to get the real file attributes, then send a DONE_WRITING */
void ll_queue_done_writing(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

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
static void ll_close_done_writing(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        ldlm_policy_data_t policy = { .l_extent = {0, OBD_OBJECT_EOF } };
        struct lustre_handle lockh = { 0 };
        struct obdo obdo;
        struct mdc_op_data data = { { 0 } };
        obd_flag valid;
        int rc, ast_flags = 0;
        ENTRY;

        memset(&obdo, 0, sizeof(obdo));
        if (test_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags))
                goto rpc;

        rc = ll_extent_lock(NULL, inode, lli->lli_smd, LCK_PW, &policy, &lockh,
                            ast_flags);
        if (rc != 0) {
                CERROR("lock acquisition failed (%d): unable to send "
                       "DONE_WRITING for inode %lu/%u\n", rc, inode->i_ino,
                       inode->i_generation);
                GOTO(out, rc);
        }

        rc = ll_lsm_getattr(ll_i2obdexp(inode), lli->lli_smd, &obdo);
        if (rc) {
                CERROR("inode_getattr failed (%d): unable to send DONE_WRITING "
                       "for inode %lu/%u\n", rc, inode->i_ino,
                       inode->i_generation);
                ll_extent_unlock(NULL, inode, lli->lli_smd, LCK_PW, &lockh);
                GOTO(out, rc);
        }

        obdo_refresh_inode(inode, &obdo, valid);

        CDEBUG(D_INODE, "objid "LPX64" size %Lu, blocks %lu, blksize %lu\n",
               lli->lli_smd->lsm_object_id, i_size_read(inode), inode->i_blocks,
               1<<inode->i_blkbits);

        set_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags);

        rc = ll_extent_unlock(NULL, inode, lli->lli_smd, LCK_PW, &lockh);
        if (rc != ELDLM_OK)
                CERROR("unlock failed (%d)?  proceeding anyways...\n", rc);

 rpc:
        obdo.o_id = inode->i_ino;
        obdo.o_size = i_size_read(inode);
        obdo.o_blocks = inode->i_blocks;
        obdo.o_valid = OBD_MD_FLID | OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

        ll_inode2fid(&data.fid1, inode);
        rc = mdc_done_writing(ll_i2sbi(inode)->ll_mdc_exp, &data, &obdo);
 out:
}


static struct ll_inode_info *ll_close_next_lli(struct ll_close_queue *lcq)
{
        struct ll_inode_info *lli = NULL;

        spin_lock(&lcq->lcq_lock);

        if (lcq->lcq_list.next == NULL)
                lli = ERR_PTR(-1);
        else if (!list_empty(&lcq->lcq_list)) {
                lli = list_entry(lcq->lcq_list.next, struct ll_inode_info,
                                 lli_close_item);
                list_del(&lli->lli_close_item);
        }

        spin_unlock(&lcq->lcq_lock);
        return lli;
}
#else
static struct ll_inode_info *ll_close_next_lli(struct ll_close_queue *lcq)
{
        if (lcq->lcq_list.next == NULL)
                return ERR_PTR(-1);

	return NULL;
}
#endif

static int ll_close_thread(void *arg)
{
        struct ll_close_queue *lcq = arg;
        ENTRY;

        {
                char name[CFS_CURPROC_COMM_MAX];
                snprintf(name, sizeof(name) - 1, "ll_close");
                cfs_daemonize(name);
        }
        
        complete(&lcq->lcq_comp);

        while (1) {
                struct l_wait_info lwi = { 0 };
                struct ll_inode_info *lli;
                //struct inode *inode;

                l_wait_event_exclusive(lcq->lcq_waitq,
                                       (lli = ll_close_next_lli(lcq)) != NULL,
                                       &lwi);
                if (IS_ERR(lli))
                        break;

                //inode = ll_info2i(lli);
                //ll_close_done_writing(inode);
                //iput(inode);
        }

        complete(&lcq->lcq_comp);
        RETURN(0);
}

int ll_close_thread_start(struct ll_close_queue **lcq_ret)
{
        struct ll_close_queue *lcq;
        pid_t pid;

        OBD_FAIL_RETURN(OBD_FAIL_LDLM_CLOSE_THREAD, -EINTR);
        OBD_ALLOC(lcq, sizeof(*lcq));
        if (lcq == NULL)
                return -ENOMEM;

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

void ll_close_thread_shutdown(struct ll_close_queue *lcq)
{
        init_completion(&lcq->lcq_comp);
        lcq->lcq_list.next = NULL;
        wake_up(&lcq->lcq_waitq);
        wait_for_completion(&lcq->lcq_comp);
        OBD_FREE(lcq, sizeof(*lcq));
}
