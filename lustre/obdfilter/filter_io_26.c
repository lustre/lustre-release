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
#include <linux/buffer_head.h>

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include "filter_internal.h"

#warning "implement writeback mode -bzzz"

/* 512byte block min */
#define MAX_BLOCKS_PER_PAGE (PAGE_SIZE / 512)
struct dio_request {
        atomic_t numreqs;       /* number of reqs being processed */
        struct bio *bio_current;/* bio currently being constructed */
        struct bio *bio_list;   /* list of completed bios */
        wait_queue_head_t dr_wait;
        int dr_num_pages;
        int dr_rw;
        int dr_error;
        int dr_created[MAX_BLOCKS_PER_PAGE];
        unsigned long dr_blocks[MAX_BLOCKS_PER_PAGE];
        spinlock_t dr_lock;

};

static int dio_complete_routine(struct bio *bio, unsigned int done, int error)
{
        struct dio_request *dreq = bio->bi_private;
        unsigned long flags;

        spin_lock_irqsave(&dreq->dr_lock, flags);
        bio->bi_private = dreq->bio_list;
        dreq->bio_list = bio;
        spin_unlock_irqrestore(&dreq->dr_lock, flags);
        if (atomic_dec_and_test(&dreq->numreqs))
                wake_up(&dreq->dr_wait);
        if (dreq->dr_error == 0)
                dreq->dr_error = error;
        return 0;
}

static int can_be_merged(struct bio *bio, sector_t sector)
{
        unsigned int size;
        if (!bio)
                return 0;

        size = bio->bi_size >> 9;
        return bio->bi_sector + size == sector ? 1 : 0;
}
int filter_alloc_iobuf(int rw, int num_pages, void **ret)
{
        struct dio_request *dreq;

        LASSERTF(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ, "%x\n", rw);

        OBD_ALLOC(dreq, sizeof(*dreq));
        if (dreq == NULL)
                RETURN(-ENOMEM);

        dreq->bio_list = NULL;
        init_waitqueue_head(&dreq->dr_wait);
        atomic_set(&dreq->numreqs, 0);
        spin_lock_init(&dreq->dr_lock);
        dreq->dr_num_pages = num_pages;
        dreq->dr_rw = rw;

        *ret = dreq;
        RETURN(0);
}

void filter_free_iobuf(void *iobuf)
{
        struct dio_request *dreq = iobuf;

        /* free all bios */
        while (dreq->bio_list) {
                struct bio *bio = dreq->bio_list;
                dreq->bio_list = bio->bi_private;
                bio_put(bio);
        }

        OBD_FREE(dreq, sizeof(*dreq));
}

int filter_iobuf_add_page(struct obd_device *obd, void *iobuf,
                          struct inode *inode, struct page *page)
{
        struct dio_request *dreq = iobuf;
        int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
        unsigned int len = inode->i_sb->s_blocksize, offs;
        struct bio *bio = dreq->bio_current;
        sector_t sector;
        int k, rc;
        ENTRY;

        /* get block number for next page */
        rc = fsfilt_map_inode_pages(obd, inode, &page, 1, dreq->dr_blocks,
                                    dreq->dr_created,
                                    dreq->dr_rw == OBD_BRW_WRITE, NULL);
        if (rc)
                RETURN(rc);

        for (k = 0, offs = 0; k < blocks_per_page; k++, offs += len) {
                if (dreq->dr_created[k] == -1) {
                        memset(kmap(page) + offs, 0, len);
                        kunmap(page);
                        continue;
                }

                sector = dreq->dr_blocks[k] <<(inode->i_sb->s_blocksize_bits-9);

                if (!bio || !can_be_merged(bio, sector) ||
                    !bio_add_page(bio, page, len, offs)) {
                        if (bio) {
                                atomic_inc(&dreq->numreqs);
                                /* FIXME
                                filter_tally_write(&obd->u.filter,dreq->maplist,
                                                   dreq->nr_pages,dreq->blocks,
                                                   blocks_per_page);
                                */
                                fsfilt_send_bio(dreq->dr_rw, obd, inode, bio);
                                dreq->bio_current = bio = NULL;
                        }
                        /* allocate new bio */
                        dreq->bio_current = bio =
                                bio_alloc(GFP_NOIO, dreq->dr_num_pages *
                                                    blocks_per_page);
                        bio->bi_bdev = inode->i_sb->s_bdev;
                        bio->bi_sector = sector;
                        bio->bi_end_io = dio_complete_routine;
                        bio->bi_private = dreq;

                        if (!bio_add_page(bio, page, len, offs))
                                LBUG();
                }
        }
        dreq->dr_num_pages--;

        RETURN(0);
}

static void filter_clear_page_cache(struct inode *inode, struct kiobuf *iobuf)
{
#if 0
        struct page *page;
        int i;

        for (i = 0; i < iobuf->nr_pages ; i++) {
                page = find_lock_page(inode->i_mapping,
                                      iobuf->maplist[i]->index);
                if (page == NULL)
                        continue;
                if (page->mapping != NULL) {
                        block_invalidatepage(page, 0);
                        truncate_complete_page(page);
                }
                unlock_page(page);
                page_cache_release(page);
        }
#endif
}

/* Must be called with i_sem taken for writes; this will drop it */
int filter_direct_io(int rw, struct dentry *dchild, void *iobuf,
                     struct obd_export *exp, struct iattr *attr,
                     struct obd_trans_info *oti, void **wait_handle)
{
        struct dio_request *dreq = iobuf;
        struct inode *inode = dchild->d_inode;
        int rc;
        ENTRY;

        LASSERTF(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ, "%x\n", rw);

        /* This is nearly osync_inode, without the waiting
        rc = generic_osync_inode(inode, inode->i_mapping,
                                 OSYNC_DATA|OSYNC_METADATA); */
        rc = filemap_fdatawrite(inode->i_mapping);
        if (rc == 0)
                rc = sync_mapping_buffers(inode->i_mapping);
        if (rc == 0)
                rc = filemap_fdatawait(inode->i_mapping);
        if (rc < 0)
                GOTO(cleanup, rc);

        if (rw == OBD_BRW_WRITE)
                up(&inode->i_sem);

        /* be careful to call this after fsync_inode_data_buffers has waited
         * for IO to complete before we evict it from the cache */
        filter_clear_page_cache(inode, iobuf);

        if (dreq->bio_current != NULL) {
                atomic_inc(&dreq->numreqs);
                fsfilt_send_bio(rw, exp->exp_obd, inode, dreq->bio_current);
                dreq->bio_current = NULL;
        }

        /* time to wait for I/O completion */
        wait_event(dreq->dr_wait, atomic_read(&dreq->numreqs) == 0);

        rc = dreq->dr_error;
        if (rw == OBD_BRW_WRITE && rc == 0) {
                /* FIXME:
                filter_tally_write(&obd->u.filter, dreq->maplist,
                                   dreq->nr_pages, dreq->blocks,
                                   blocks_per_page);
                */

                if (attr->ia_size > inode->i_size) {
                        CDEBUG(D_INFO, "setting i_size to "LPU64"\n",
                               attr->ia_size);

                        attr->ia_valid |= ATTR_SIZE;
                        down(&inode->i_sem);
                        fsfilt_setattr(exp->exp_obd, dchild, oti->oti_handle,
                                       attr, 0);
                        up(&inode->i_sem);
                }
        }

cleanup:
        RETURN(rc);
}

/* See if there are unallocated parts in given file region */
static int filter_range_is_mapped(struct inode *inode, obd_size offset, int len)
{
        sector_t (*fs_bmap)(struct address_space *, sector_t) =
                inode->i_mapping->a_ops->bmap;
        int j;

        /* We can't know if we are overwriting or not */
        if (fs_bmap == NULL)
                return 0;

        offset >>= inode->i_blkbits;
        len >>= inode->i_blkbits;

        for (j = 0; j <= len; j++)
                if (fs_bmap(inode->i_mapping, offset + j) == 0)
                        return 0;

        return 1;
}

int filter_commitrw_write(struct obd_export *exp, struct obdo *oa,
                          int objcount, struct obd_ioobj *obj, int niocount,
                          struct niobuf_local *res, struct obd_trans_info *oti,
                          int rc)
{
        struct niobuf_local *lnb;
        struct dio_request *dreq = NULL;
        struct lvfs_run_ctxt saved;
        struct fsfilt_objinfo fso;
        struct iattr iattr = { 0 };
        struct inode *inode = NULL;
        unsigned long now = jiffies;
        int i, err, cleanup_phase = 0;
        struct obd_device *obd = exp->exp_obd;

        ENTRY;

        LASSERT(oti != NULL);
        LASSERT(objcount == 1);
        LASSERT(current->journal_info == NULL);

        if (rc != 0)
                GOTO(cleanup, rc);

        inode = res->dentry->d_inode;

        rc = filter_alloc_iobuf(OBD_BRW_WRITE, obj->ioo_bufcnt, (void **)&dreq);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 1;
        fso.fso_dentry = res->dentry;
        fso.fso_bufcnt = obj->ioo_bufcnt;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        cleanup_phase = 2;

        generic_osync_inode(inode, inode->i_mapping, OSYNC_DATA|OSYNC_METADATA);

        oti->oti_handle = fsfilt_brw_start(obd, objcount, &fso, niocount, res,
                                           oti);
        if (IS_ERR(oti->oti_handle)) {
                rc = PTR_ERR(oti->oti_handle);
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error starting transaction: rc = %d\n", rc);
                oti->oti_handle = NULL;
                GOTO(cleanup, rc);
        }

        /* have to call fsfilt_commit() from this point on */

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow brw_start %lus\n", (jiffies - now) / HZ);

        down(&inode->i_sem);
        for (i = 0, lnb = res; i < obj->ioo_bufcnt; i++, lnb++) {
                loff_t this_size;

                /* If overwriting an existing block, we don't need a grant */
                if (!(lnb->flags & OBD_BRW_GRANTED) && lnb->rc == -ENOSPC &&
                    filter_range_is_mapped(inode, lnb->offset, lnb->len))
                        lnb->rc = 0;

                if (lnb->rc) /* ENOSPC, network RPC error, etc. */ 
                        continue;

                err = filter_iobuf_add_page(obd, dreq, inode, lnb->page);
                if (err != 0) {
                        lnb->rc = err;
                        continue;
                }

                /* we expect these pages to be in offset order, but we'll
                 * be forgiving */
                this_size = lnb->offset + lnb->len;
                if (this_size > iattr.ia_size)
                        iattr.ia_size = this_size;
        }

        iattr_from_obdo(&iattr,oa,OBD_MD_FLATIME|OBD_MD_FLMTIME|OBD_MD_FLCTIME);
        rc = filter_direct_io(OBD_BRW_WRITE, res->dentry, dreq, exp, &iattr,
                              oti, NULL);
        rc = filter_finish_transno(exp, oti, rc);

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow direct_io %lus\n", (jiffies - now) / HZ);


        err = fsfilt_commit(obd, obd->u.filter.fo_sb, inode, oti->oti_handle,
                            obd_sync_filter);
        if (err)
                rc = err;

        if (obd_sync_filter)
                LASSERT(oti->oti_transno <= obd->obd_last_committed);

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow commitrw commit %lus\n", (jiffies - now) / HZ);

cleanup:
        filter_grant_commit(exp, niocount, res);

        switch (cleanup_phase) {
        case 2:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                LASSERT(current->journal_info == NULL);
        case 1:
                filter_free_iobuf(dreq);
        case 0:
                filter_free_dio_pages(objcount, obj, niocount, res);
                f_dput(res->dentry);
        }

        RETURN(rc);
}
