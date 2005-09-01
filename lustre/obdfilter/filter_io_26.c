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

/* 512byte block min */
#define MAX_BLOCKS_PER_PAGE (PAGE_SIZE / 512)
struct dio_request {
        atomic_t          dr_numreqs;  /* number of reqs being processed */
        struct bio       *dr_bios;     /* list of completed bios */
        wait_queue_head_t dr_wait;
        int               dr_max_pages;
        int               dr_npages;
        int               dr_error;
        struct page     **dr_pages;
        unsigned long    *dr_blocks;
        spinlock_t        dr_lock;
};

static int dio_complete_routine(struct bio *bio, unsigned int done, int error)
{
        struct dio_request *dreq = bio->bi_private;
        unsigned long flags;

        if (bio->bi_size) {
                CWARN("gets called against non-complete bio 0x%p: %d/%d/%d\n",
                      bio, bio->bi_size, done, error);
                return 1;
        }

        if (dreq == NULL) {
                CERROR("***** bio->bi_private is NULL!  This should never "
                       "happen.  Normally, I would crash here, but instead I "
                       "will dump the bio contents to the console.  Please "
                       "report this to CFS, along with any interesting messages "
                       "leading up to this point (like SCSI errors, perhaps).  "
                       "Because bi_private is NULL, I can't wake up the thread "
                       "that initiated this I/O -- so you will probably have to "
                       "reboot this node.");
                CERROR("bi_next: %p, bi_flags: %lx, bi_rw: %lu, bi_vcnt: %d, "
                       "bi_idx: %d, bi->size: %d, bi_end_io: %p, bi_cnt: %d, "
                       "bi_private: %p\n", bio->bi_next, bio->bi_flags,
                       bio->bi_rw, bio->bi_vcnt, bio->bi_idx, bio->bi_size,
                       bio->bi_end_io, atomic_read(&bio->bi_cnt),
                       bio->bi_private);
                return 0;
        }

        spin_lock_irqsave(&dreq->dr_lock, flags);
        bio->bi_private = dreq->dr_bios;
        dreq->dr_bios = bio;
        if (dreq->dr_error == 0)
                dreq->dr_error = error;
        spin_unlock_irqrestore(&dreq->dr_lock, flags);

        if (atomic_dec_and_test(&dreq->dr_numreqs))
                wake_up(&dreq->dr_wait);

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
                goto failed_0;
        
        OBD_ALLOC(dreq->dr_pages, num_pages * sizeof(*dreq->dr_pages));
        if (dreq->dr_pages == NULL)
                goto failed_1;
        
        OBD_ALLOC(dreq->dr_blocks,
                  MAX_BLOCKS_PER_PAGE * num_pages * sizeof(*dreq->dr_blocks));
        if (dreq->dr_blocks == NULL)
                goto failed_2;

        dreq->dr_bios = NULL;
        init_waitqueue_head(&dreq->dr_wait);
        atomic_set(&dreq->dr_numreqs, 0);
        spin_lock_init(&dreq->dr_lock);
        dreq->dr_max_pages = num_pages;
        dreq->dr_npages = 0;

        *ret = dreq;
        RETURN(0);
        
 failed_2:
        OBD_FREE(dreq->dr_pages,
                 num_pages * sizeof(*dreq->dr_pages));
 failed_1:
        OBD_FREE(dreq, sizeof(*dreq));
 failed_0:
        RETURN(-ENOMEM);
}

void filter_free_iobuf(void *iobuf)
{
        struct dio_request *dreq = iobuf;
        int                 num_pages = dreq->dr_max_pages;

        /* free all bios */
        while (dreq->dr_bios) {
                struct bio *bio = dreq->dr_bios;
                dreq->dr_bios = bio->bi_private;
                bio_put(bio);
        }

        OBD_FREE(dreq->dr_blocks,
                 MAX_BLOCKS_PER_PAGE * num_pages * sizeof(*dreq->dr_blocks));
        OBD_FREE(dreq->dr_pages,
                 num_pages * sizeof(*dreq->dr_pages));
        OBD_FREE(dreq, sizeof(*dreq));
}

int filter_iobuf_add_page(struct obd_device *obd, void *iobuf,
                          struct inode *inode, struct page *page)
{
        struct dio_request *dreq = iobuf;

        LASSERT (dreq->dr_npages < dreq->dr_max_pages);
        dreq->dr_pages[dreq->dr_npages++] = page;

        return 0;
}

int filter_do_bio(struct obd_device *obd, struct inode *inode,
                  struct dio_request *dreq, int rw)
{
        int            blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
        struct page  **pages = dreq->dr_pages;
        int            npages = dreq->dr_npages;
        unsigned long *blocks = dreq->dr_blocks;
        int            total_blocks = npages * blocks_per_page;
        int            sector_bits = inode->i_sb->s_blocksize_bits - 9;
        unsigned int   blocksize = inode->i_sb->s_blocksize;
        struct bio    *bio = NULL;
        struct page   *page;
        unsigned int   page_offset;
        sector_t       sector;
        int            nblocks;
        int            block_idx;
        int            page_idx;
        int            i;
        int            rc = 0;
        ENTRY;

        LASSERT(dreq->dr_npages == npages);
        LASSERT(total_blocks <= OBDFILTER_CREATED_SCRATCHPAD_ENTRIES);

        for (page_idx = 0, block_idx = 0; 
             page_idx < npages; 
             page_idx++, block_idx += blocks_per_page) {
                        
                page = pages[page_idx];
                LASSERT (block_idx + blocks_per_page <= total_blocks);

                for (i = 0, page_offset = 0; 
                     i < blocks_per_page;
                     i += nblocks, page_offset += blocksize * nblocks) {

                        nblocks = 1;

                        if (blocks[block_idx + i] == 0) {  /* hole */
                                LASSERT(rw == OBD_BRW_READ);
                                memset(kmap(page) + page_offset, 0, blocksize);
                                kunmap(page);
                                continue;
                        }

                        sector = blocks[block_idx + i] << sector_bits;

                        /* Additional contiguous file blocks? */
                        while (i + nblocks < blocks_per_page &&
                               (sector + nblocks*(blocksize>>9)) ==
                               (blocks[block_idx + i + nblocks] << sector_bits))
                                nblocks++;

                        if (bio != NULL &&
                            can_be_merged(bio, sector) &&
                            bio_add_page(bio, page, 
                                         blocksize * nblocks, page_offset) != 0)
                                continue;       /* added this frag OK */

                        if (bio != NULL) {
                                request_queue_t *q = bdev_get_queue(bio->bi_bdev);

                                /* Dang! I have to fragment this I/O */
                                CDEBUG(D_INODE, "bio++ sz %d vcnt %d(%d) "
                                       "sectors %d(%d) psg %d(%d) hsg %d(%d)\n",
                                       bio->bi_size, 
                                       bio->bi_vcnt, bio->bi_max_vecs,
                                       bio->bi_size >> 9, q->max_sectors,
                                       bio_phys_segments(q, bio), 
                                       q->max_phys_segments,
                                       bio_hw_segments(q, bio), 
                                       q->max_hw_segments);

                                atomic_inc(&dreq->dr_numreqs);
                                rc = fsfilt_send_bio(rw, obd, inode, bio);
                                if (rc < 0) {
                                        CERROR("Can't send bio: %d\n", rc);
                                        /* OK do dec; we do the waiting */
                                        atomic_dec(&dreq->dr_numreqs);
                                        goto out;
                                }
                                rc = 0;
                                        
                                bio = NULL;
                        }

                        /* allocate new bio */
                        bio = bio_alloc(GFP_NOIO, 
                                        (npages - page_idx) * blocks_per_page);
                        if (bio == NULL) {
                                CERROR ("Can't allocate bio\n");
                                rc = -ENOMEM;
                                goto out;
                        }

                        bio->bi_bdev = inode->i_sb->s_bdev;
                        bio->bi_sector = sector;
                        bio->bi_end_io = dio_complete_routine;
                        bio->bi_private = dreq;

                        rc = bio_add_page(bio, page, 
                                          blocksize * nblocks, page_offset);
                        LASSERT (rc != 0);
                }
        }

        if (bio != NULL) {
                atomic_inc(&dreq->dr_numreqs);
                rc = fsfilt_send_bio(rw, obd, inode, bio);
                if (rc >= 0) {
                        rc = 0;
                } else {
                        CERROR("Can't send bio: %d\n", rc);
                        /* OK do dec; we do the waiting */
                        atomic_dec(&dreq->dr_numreqs);
                }
        }
                        
 out:
        wait_event(dreq->dr_wait, atomic_read(&dreq->dr_numreqs) == 0);

        if (rc == 0)
                rc = dreq->dr_error;
        RETURN(rc);
}
 
/* These are our hacks to keep our directio/bh IO coherent with ext3's
 * page cache use.  Most notably ext3 reads file data into the page
 * cache when it is zeroing the tail of partial-block truncates and
 * leaves it there, sometimes generating io from it at later truncates.
 * This removes the partial page and its buffers from the page cache,
 * so it should only ever cause a wait in rare cases, as otherwise we
 * always do full-page IO to the OST.
 *
 * The call to truncate_complete_page() will call journal_invalidatepage()
 * to free the buffers and drop the page from cache.  The buffers should
 * not be dirty, because we already called fdatasync/fdatawait on them.
 */
static int filter_clear_page_cache(struct inode *inode,
                                   struct dio_request *iobuf)
{
        struct page *page;
        int i, rc, rc2;
  
        /* This is nearly generic_osync_inode, without the waiting on the inode
        rc = generic_osync_inode(inode, inode->i_mapping,
                                  OSYNC_DATA|OSYNC_METADATA);
        */
        rc = filemap_fdatawrite(inode->i_mapping);
        rc2 = sync_mapping_buffers(inode->i_mapping);
        if (rc == 0)
                rc = rc2;
        rc2 = filemap_fdatawait(inode->i_mapping);
        if (rc == 0)
                rc = rc2;
        if (rc != 0)
                RETURN(rc);
 
        /* be careful to call this after fsync_inode_data_buffers has waited
         * for IO to complete before we evict it from the cache */
        for (i = 0; i < iobuf->dr_npages; i++) {
                page = find_lock_page(inode->i_mapping,
                                       iobuf->dr_pages[i]->index);
                if (page == NULL)
                       continue;
                if (page->mapping != NULL) {
                       wait_on_page_writeback(page);
                       ll_truncate_complete_page(page);
                }
  
                unlock_page(page);
                page_cache_release(page);
        }
        return 0;
}
/* Must be called with i_sem taken for writes; this will drop it */
int filter_direct_io(int rw, struct dentry *dchild, void *iobuf,
                     struct obd_export *exp, struct iattr *attr,
                     struct obd_trans_info *oti, void **wait_handle)
{
        struct obd_device *obd = exp->exp_obd;
        struct inode *inode = dchild->d_inode;
        struct dio_request *dreq = iobuf;
        struct semaphore *sem = NULL;
        int rc, rc2, create = 0;
        ENTRY;

        LASSERTF(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ, "%x\n", rw);
        LASSERTF(dreq->dr_npages <= dreq->dr_max_pages, "%d,%d\n",
                 dreq->dr_npages, dreq->dr_max_pages);

        if (dreq->dr_npages == 0)
                RETURN(0);

        if (dreq->dr_npages > OBDFILTER_CREATED_SCRATCHPAD_ENTRIES)
                RETURN(-EINVAL);
        
        if (rw == OBD_BRW_WRITE) {
                create = 1;
                //sem = &obd->u.filter.fo_alloc_lock;
        }

        rc = fsfilt_map_inode_pages(obd, inode,
                                    dreq->dr_pages, dreq->dr_npages,
                                    dreq->dr_blocks,
                                    obdfilter_created_scratchpad,
                                    create, sem);

        if (rw == OBD_BRW_WRITE) {
                if (rc == 0) {
                        int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
                        filter_tally_write(&obd->u.filter,  dreq->dr_pages,
                                           dreq->dr_npages, dreq->dr_blocks,
                                           blocks_per_page);
                        if (attr->ia_size > inode->i_size)
                                attr->ia_valid |= ATTR_SIZE;
                        rc = fsfilt_setattr(obd, dchild, 
                                            oti->oti_handle, attr, 0);
                }
                
                up(&inode->i_sem);

                rc2 = filter_finish_transno(exp, oti, 0);
                if (rc2 != 0)
                        CERROR("can't close transaction: %d\n", rc);
                rc = (rc == 0) ? rc2 : rc;

                rc2 = fsfilt_commit_async(obd,inode,oti->oti_handle,wait_handle);
                rc = (rc == 0) ? rc2 : rc;

                if (rc != 0)
                        RETURN(rc);
        }

        rc = filter_clear_page_cache(inode, dreq);
        if (rc != 0)
                RETURN(rc);

        RETURN(filter_do_bio(obd, inode, dreq, rw));
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
        void *wait_handle = NULL;
        int   total_size = 0;
        loff_t old_size;
        ENTRY;

        LASSERT(oti != NULL);
        LASSERT(objcount == 1);
        LASSERT(current->journal_info == NULL);

        if (rc != 0)
                GOTO(cleanup, rc);
        
        rc = filter_alloc_iobuf(OBD_BRW_WRITE, obj->ioo_bufcnt, (void **)&dreq);
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 1;

        fso.fso_dentry = res->dentry;
        fso.fso_bufcnt = obj->ioo_bufcnt;
        inode = res->dentry->d_inode;

        for (i = 0, lnb = res; i < obj->ioo_bufcnt; i++, lnb++) {
                loff_t this_size;

                /* If overwriting an existing block, we don't need a grant */
                if (!(lnb->flags & OBD_BRW_GRANTED) && lnb->rc == -ENOSPC &&
                    filter_range_is_mapped(inode, lnb->offset, lnb->len))
                        lnb->rc = 0;

                if (lnb->rc) { /* ENOSPC, network RPC error, etc. */
                        CDEBUG(D_INODE, "Skipping [%d] == %d\n", i, lnb->rc);
                        continue;
                }

                err = filter_iobuf_add_page(obd, dreq, inode, lnb->page);
                LASSERT (err == 0);

                total_size += lnb->len;

                /* we expect these pages to be in offset order, but we'll
                 * be forgiving */
                this_size = lnb->offset + lnb->len;
                if (this_size > iattr.ia_size)
                        iattr.ia_size = this_size;
        }
#if 0
        /* I use this when I'm checking our lovely 1M I/Os reach the disk -eeb */
        if (total_size != (1<<20))
                CWARN("total size %d (%d pages)\n", 
                      total_size, total_size/PAGE_SIZE);
#endif
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        cleanup_phase = 2;

        down(&inode->i_sem);
        old_size = inode->i_size;
        oti->oti_handle = fsfilt_brw_start(obd, objcount, &fso, niocount, res,
                                           oti);
        if (IS_ERR(oti->oti_handle)) {
                up(&inode->i_sem);
                rc = PTR_ERR(oti->oti_handle);
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error starting transaction: rc = %d\n", rc);
                oti->oti_handle = NULL;
                GOTO(cleanup, rc);
        }
        /* have to call fsfilt_commit() from this point on */

        fsfilt_check_slow(now, obd_timeout, "brw_start");

        iattr_from_obdo(&iattr,oa,OBD_MD_FLATIME|OBD_MD_FLMTIME|OBD_MD_FLCTIME);
        /* filter_direct_io drops i_sem */
        rc = filter_direct_io(OBD_BRW_WRITE, res->dentry, dreq, exp, &iattr,
                              oti, &wait_handle);

#if 0
        if (inode->i_size != old_size) {
                struct llog_cookie *cookie = obdo_logcookie(oa);
                struct lustre_id *id = obdo_id(oa);
                filter_log_sz_change(obd, id, oa->o_easize, cookie, inode);
        }
#endif

        if (rc == 0)
                obdo_from_inode(oa, inode, FILTER_VALID_FLAGS);

        fsfilt_check_slow(now, obd_timeout, "direct_io");

#if 0   /* disabled to evaluate impact -bzzz */
        err = fsfilt_commit_wait(obd, inode, wait_handle);
        if (rc == 0)
                rc = err;
#endif

        fsfilt_check_slow(now, obd_timeout, "commitrw commit");

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
