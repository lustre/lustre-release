/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter_io.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/iobuf.h>

#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include "filter_internal.h"


/* We should only change the file mtime (and not the ctime, like
 * update_inode_times() in generic_file_write()) when we only change data. */
void inode_update_time(struct inode *inode, int ctime_too)
{
        time_t now = CURRENT_TIME;
        if (inode->i_mtime == now && (!ctime_too || inode->i_ctime == now))
                return;
        inode->i_mtime = now;
        if (ctime_too)
                inode->i_ctime = now;
        mark_inode_dirty_sync(inode);
}

int ext3_map_inode_page(struct inode *inode, struct page *page,
                        unsigned long *blocks, int *created, int create);
/* Must be called with i_sem taken; this will drop it */
static int filter_direct_io(int rw, struct inode *inode, struct kiobuf *iobuf,
                            struct obd_device *obd, struct obd_trans_info *oti,
                            void **wait_handle)
{
        struct page *page;
        unsigned long *b = iobuf->blocks;
        int rc, i, create = (rw == OBD_BRW_WRITE), blocks_per_page;
        int *cr, cleanup_phase = 0, *created = NULL;
        ENTRY;

        blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
        if (iobuf->nr_pages * blocks_per_page > KIO_MAX_SECTORS)
                GOTO(cleanup, rc = -EINVAL);

        OBD_ALLOC(created, sizeof(*created) * iobuf->nr_pages*blocks_per_page);
        if (created == NULL)
                GOTO(cleanup, rc = -ENOMEM);
        cleanup_phase = 1;

        rc = lock_kiovec(1, &iobuf, 1);
        if (rc < 0)
                GOTO(cleanup, rc);
        cleanup_phase = 2;

        for (i = 0, cr = created, b = iobuf->blocks; i < iobuf->nr_pages; i++){
                page = iobuf->maplist[i];

                rc = ext3_map_inode_page(inode, page, b, cr, create);
                if (rc)
                        GOTO(cleanup, rc);

                b += blocks_per_page;
                cr += blocks_per_page;
        }
        up(&inode->i_sem);
        cleanup_phase = 3;

        rc = fsfilt_commit_async(obd, inode, oti->oti_handle, wait_handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = brw_kiovec(WRITE, 1, &iobuf, inode->i_dev, iobuf->blocks,
                        1 << inode->i_blkbits);
        CDEBUG(D_INFO, "tried to write %d pages, rc = %d\n",
               iobuf->nr_pages, rc);
        if (rc != (1 << inode->i_blkbits) * iobuf->nr_pages * blocks_per_page)
                CERROR("short write?  expected %d, wrote %d\n",
                       (1 << inode->i_blkbits) * iobuf->nr_pages *
                       blocks_per_page, rc);
        if (rc > 0)
                rc = 0;

        EXIT;
cleanup:
        switch(cleanup_phase) {
        case 3:
        case 2:
                unlock_kiovec(1, &iobuf);
        case 1:
                OBD_FREE(created, sizeof(*created) * 
                         iobuf->nr_pages*blocks_per_page);
        case 0:
                if (cleanup_phase == 3)
                        break;
                up(&inode->i_sem);
                break;
        default:
                CERROR("corrupt cleanup_phase (%d)?\n", cleanup_phase);
                LBUG();
                break;
        }
        return rc;
}

int filter_commitrw_write(struct obd_export *exp, int objcount,
                                 struct obd_ioobj *obj, int niocount,
                                 struct niobuf_local *res,
                                 struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_run_ctxt saved;
        struct niobuf_local *lnb;
        struct fsfilt_objinfo fso;
        struct iattr iattr = { .ia_valid = ATTR_SIZE, .ia_size = 0, };
        struct kiobuf *iobuf;
        struct inode *inode = NULL;
        int rc = 0, i, cleanup_phase = 0, err;
        unsigned long now = jiffies; /* DEBUGGING OST TIMEOUTS */
        void *wait_handle;
        ENTRY;
        LASSERT(oti != NULL);
        LASSERT(objcount == 1);
        LASSERT(current->journal_info == NULL);

        rc = alloc_kiovec(1, &iobuf);
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 1;

#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,4,18))
        iobuf->dovary = 0; /* this prevents corruption, not present in 2.4.20 */
#endif
        rc = expand_kiobuf(iobuf, obj->ioo_bufcnt);
        if (rc)
                GOTO(cleanup, rc);

        iobuf->offset = 0;
        iobuf->length = PAGE_SIZE * obj->ioo_bufcnt;
        iobuf->nr_pages = obj->ioo_bufcnt;

        cleanup_phase = 1;
        fso.fso_dentry = res->dentry;
        fso.fso_bufcnt = obj->ioo_bufcnt;
        inode = res->dentry->d_inode;

        for (i = 0, lnb = res; i < obj->ioo_bufcnt; i++, lnb++) {
                loff_t this_size;
                iobuf->maplist[i] = lnb->page;
                /* We expect these pages to be in offset order, but we'll
                 * be forgiving */
                this_size = lnb->offset + lnb->len;
                if (this_size > iattr.ia_size)
                        iattr.ia_size = this_size;
        }

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        cleanup_phase = 2; 

        down(&inode->i_sem);
        oti->oti_handle = fsfilt_brw_start(obd, objcount, &fso, niocount, oti);
        if (IS_ERR(oti->oti_handle)) {
                rc = PTR_ERR(oti->oti_handle);
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error starting transaction: rc = %d\n", rc);
                oti->oti_handle = NULL;
                GOTO(cleanup, rc);
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow brw_start %lus\n", (jiffies - now) / HZ);

        rc = filter_direct_io(OBD_BRW_WRITE, inode, iobuf, obd,
                                oti, &wait_handle);
        if (rc == 0) {
                lock_kernel();
                inode_update_time(inode, 1);
                if (iattr.ia_size > inode->i_size) {
                        CDEBUG(D_INFO, "setting i_size to "LPU64"\n",
                               iattr.ia_size);
                        fsfilt_setattr(obd, res->dentry, oti->oti_handle,
                                       &iattr, 0);
                }
                unlock_kernel();
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow direct_io %lus\n", (jiffies - now) / HZ);

        rc = filter_finish_transno(exp, oti, rc);
        err = fsfilt_commit_wait(obd, inode, wait_handle);
        if (err)
                rc = err;
        if (obd_sync_filter)
                LASSERT(oti->oti_transno <= obd->obd_last_committed);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow commitrw commit %lus\n", (jiffies - now) / HZ);

cleanup:
        switch (cleanup_phase) {
        case 2:
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);
                LASSERT(current->journal_info == NULL);
        case 1:
                free_kiovec(1, &iobuf);
        case 0:
                for (i = 0, lnb = res; i < obj->ioo_bufcnt; i++, lnb++) {
                        /* flip_.. gets a ref, while free_page only frees
                         * when it decrefs to 0 */
                        if (rc == 0)
                                flip_into_page_cache(inode, lnb->page);
                        __free_page(lnb->page);
                }
                f_dput(res->dentry);
        }

        RETURN(rc);
}

#endif

