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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include "filter_internal.h"

int ext3_map_inode_page(struct inode *inode, struct page *page,
                        unsigned long *blocks, int *created, int create);

static int can_be_merged(struct bio *bio, sector_t sector)
{
	int size;
	
	if (!bio)
		return 0;
	
	size = bio->bi_size >> 9;
	return bio->bi_sector + size == sector ? 1 : 0;
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
        int rc = 0, i, k, cleanup_phase = 0, err;
        unsigned long now = jiffies; /* DEBUGGING OST TIMEOUTS */
	struct bio *bio = NULL, *bio_list = NULL;
	int created[16]; /* 8KB pages man , 512bytes block min */
	unsigned long blocks[16];
	int blocks_per_page;
        ENTRY;
        LASSERT(oti != NULL);
        LASSERT(objcount == 1);
        LASSERT(current->journal_info == NULL);

        blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	LASSERT(blocks_per_page <= 16);

        cleanup_phase = 1;
        fso.fso_dentry = res->dentry;
        fso.fso_bufcnt = obj->ioo_bufcnt;
        inode = res->dentry->d_inode;

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        cleanup_phase = 2; 

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

        for (i = 0, lnb = res; i < obj->ioo_bufcnt; i++, lnb++) {
                loff_t this_size;
		sector_t sector;
		int offs;

		/* get block number for next page */
                rc = ext3_map_inode_page(inode, lnb->page, blocks, created, 1);
                if (rc)
                        GOTO(cleanup, rc);

		for (k = 0; k < blocks_per_page; k++) {
			sector = blocks[k] * (inode->i_sb->s_blocksize >> 9);
			offs = k * inode->i_sb->s_blocksize;

			if (!bio || !can_be_merged(bio, sector) ||
				!bio_add_page(bio, lnb->page, lnb->len, offs)) {
				if (bio) {
					submit_bio(WRITE, bio);
					bio = NULL;
				}
				/* allocate new bio */
				bio = bio_alloc(GFP_NOIO, obj->ioo_bufcnt);
				bio->bi_bdev = inode->i_sb->s_bdev;
				bio->bi_sector = sector;
				bio->bi_end_io = NULL; /* FIXME */

				/* put on the list */
				bio->bi_private = bio_list;
				bio_list = bio;

				if (!bio_add_page(bio, lnb->page, lnb->len, 0))
					LBUG();
			}
		}

                /* We expect these pages to be in offset order, but we'll
                 * be forgiving */
                this_size = lnb->offset + lnb->len;
                if (this_size > iattr.ia_size)
                        iattr.ia_size = this_size;
        }
	if (bio)
		submit_bio(WRITE, bio);

	/* time to wait for I/O completion */

        if (rc == 0) {
                down(&inode->i_sem);
                inode_update_time(inode, 1);
                if (iattr.ia_size > inode->i_size) {
                        CDEBUG(D_INFO, "setting i_size to "LPU64"\n",
                               iattr.ia_size);
                        fsfilt_setattr(obd, res->dentry, oti->oti_handle,
                                       &iattr, 0);
                }
                up(&inode->i_sem);
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow direct_io %lus\n", (jiffies - now) / HZ);

        rc = filter_finish_transno(exp, oti, rc);
        err = fsfilt_commit(obd, inode, oti->oti_handle, obd_sync_filter);
        if (err)
                rc = err;
        if (obd_sync_filter)
                LASSERT(oti->oti_transno <= obd->obd_last_committed);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow commitrw commit %lus\n", (jiffies - now) / HZ);

cleanup:
        switch (cleanup_phase) {
        case 2:
                pop_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
                LASSERT(current->journal_info == NULL);
        case 1:
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

