/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_io.c
 *
 * body operations
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 *
 */

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/* prerequisite for linux/xattr.h */
#include <linux/types.h>
/* prerequisite for linux/xattr.h */
#include <linux/fs.h>

/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd_support.h>

#include "osd_internal.h"

/* ext_depth() */
#include <ldiskfs/ldiskfs_extents.h>

static int __osd_init_iobuf(struct osd_device *d, struct osd_iobuf *iobuf,
			    int rw, int line, int pages)
{
	int blocks, i;

	LASSERTF(iobuf->dr_elapsed_valid == 0,
		 "iobuf %p, reqs %d, rw %d, line %d\n", iobuf,
		 atomic_read(&iobuf->dr_numreqs), iobuf->dr_rw,
		 iobuf->dr_init_at);
	LASSERT(pages <= PTLRPC_MAX_BRW_PAGES);

	init_waitqueue_head(&iobuf->dr_wait);
	atomic_set(&iobuf->dr_numreqs, 0);
	iobuf->dr_npages = 0;
	iobuf->dr_error = 0;
	iobuf->dr_dev = d;
	iobuf->dr_frags = 0;
	iobuf->dr_elapsed = 0;
	/* must be counted before, so assert */
	iobuf->dr_rw = rw;
	iobuf->dr_init_at = line;

	blocks = pages * (PAGE_SIZE >> osd_sb(d)->s_blocksize_bits);
	if (iobuf->dr_bl_buf.lb_len >= blocks * sizeof(iobuf->dr_blocks[0])) {
		LASSERT(iobuf->dr_pg_buf.lb_len >=
			pages * sizeof(iobuf->dr_pages[0]));
		return 0;
	}

	/* start with 1MB for 4K blocks */
	i = 256;
	while (i <= PTLRPC_MAX_BRW_PAGES && i < pages)
		i <<= 1;

	CDEBUG(D_OTHER, "realloc %u for %u (%u) pages\n",
	       (unsigned)(pages * sizeof(iobuf->dr_pages[0])), i, pages);
	pages = i;
	blocks = pages * (PAGE_SIZE >> osd_sb(d)->s_blocksize_bits);
	iobuf->dr_max_pages = 0;
	CDEBUG(D_OTHER, "realloc %u for %u blocks\n",
	       (unsigned)(blocks * sizeof(iobuf->dr_blocks[0])), blocks);

	lu_buf_realloc(&iobuf->dr_bl_buf, blocks * sizeof(iobuf->dr_blocks[0]));
	iobuf->dr_blocks = iobuf->dr_bl_buf.lb_buf;
	if (unlikely(iobuf->dr_blocks == NULL))
		return -ENOMEM;

	lu_buf_realloc(&iobuf->dr_pg_buf, pages * sizeof(iobuf->dr_pages[0]));
	iobuf->dr_pages = iobuf->dr_pg_buf.lb_buf;
	if (unlikely(iobuf->dr_pages == NULL))
		return -ENOMEM;

	iobuf->dr_max_pages = pages;

	return 0;
}
#define osd_init_iobuf(dev, iobuf, rw, pages) \
	__osd_init_iobuf(dev, iobuf, rw, __LINE__, pages)

static void osd_iobuf_add_page(struct osd_iobuf *iobuf, struct page *page)
{
        LASSERT(iobuf->dr_npages < iobuf->dr_max_pages);
        iobuf->dr_pages[iobuf->dr_npages++] = page;
}

void osd_fini_iobuf(struct osd_device *d, struct osd_iobuf *iobuf)
{
        int rw = iobuf->dr_rw;

        if (iobuf->dr_elapsed_valid) {
                iobuf->dr_elapsed_valid = 0;
                LASSERT(iobuf->dr_dev == d);
                LASSERT(iobuf->dr_frags > 0);
                lprocfs_oh_tally(&d->od_brw_stats.
                                 hist[BRW_R_DIO_FRAGS+rw],
                                 iobuf->dr_frags);
                lprocfs_oh_tally_log2(&d->od_brw_stats.hist[BRW_R_IO_TIME+rw],
                                      iobuf->dr_elapsed);
        }
}

#ifdef HAVE_BIO_ENDIO_USES_ONE_ARG
static void dio_complete_routine(struct bio *bio)
{
	int error = bio->bi_error;
#else
static void dio_complete_routine(struct bio *bio, int error)
{
#endif
	struct osd_iobuf *iobuf = bio->bi_private;
	int iter;
	struct bio_vec *bvl;

        /* CAVEAT EMPTOR: possibly in IRQ context
         * DO NOT record procfs stats here!!! */

	if (unlikely(iobuf == NULL)) {
		CERROR("***** bio->bi_private is NULL!  This should never "
		       "happen.  Normally, I would crash here, but instead I "
		       "will dump the bio contents to the console.  Please "
		       "report this to <https://jira.hpdd.intel.com/> , along "
		       "with any interesting messages leading up to this point "
		       "(like SCSI errors, perhaps).  Because bi_private is "
		       "NULL, I can't wake up the thread that initiated this "
		       "IO - you will probably have to reboot this node.\n");
		CERROR("bi_next: %p, bi_flags: %lx, "
#ifdef HAVE_BI_RW
		       "bi_rw: %lu,"
#else
		       "bi_opf: %u,"
#endif
		       "bi_vcnt: %d, bi_idx: %d, bi->size: %d, bi_end_io: %p,"
		       "bi_cnt: %d, bi_private: %p\n", bio->bi_next,
			(unsigned long)bio->bi_flags,
#ifdef HAVE_BI_RW
			bio->bi_rw,
#else
			bio->bi_opf,
#endif
			bio->bi_vcnt, bio_idx(bio),
			bio_sectors(bio) << 9, bio->bi_end_io,
#ifdef HAVE_BI_CNT
			atomic_read(&bio->bi_cnt),
#else
			atomic_read(&bio->__bi_cnt),
#endif
			bio->bi_private);
		return;
	}

	/* the check is outside of the cycle for performance reason -bzzz */
	if (!bio_data_dir(bio)) {
		bio_for_each_segment_all(bvl, bio, iter) {
			if (likely(error == 0))
				SetPageUptodate(bvl_to_page(bvl));
			LASSERT(PageLocked(bvl_to_page(bvl)));
		}
		atomic_dec(&iobuf->dr_dev->od_r_in_flight);
	} else {
		atomic_dec(&iobuf->dr_dev->od_w_in_flight);
	}

	/* any real error is good enough -bzzz */
	if (error != 0 && iobuf->dr_error == 0)
		iobuf->dr_error = error;

	/*
	 * set dr_elapsed before dr_numreqs turns to 0, otherwise
	 * it's possible that service thread will see dr_numreqs
	 * is zero, but dr_elapsed is not set yet, leading to lost
	 * data in this processing and an assertion in a subsequent
	 * call to OSD.
	 */
	if (atomic_read(&iobuf->dr_numreqs) == 1) {
		iobuf->dr_elapsed = jiffies - iobuf->dr_start_time;
		iobuf->dr_elapsed_valid = 1;
	}
	if (atomic_dec_and_test(&iobuf->dr_numreqs))
		wake_up(&iobuf->dr_wait);

	/* Completed bios used to be chained off iobuf->dr_bios and freed in
	 * filter_clear_dreq().  It was then possible to exhaust the biovec-256
	 * mempool when serious on-disk fragmentation was encountered,
	 * deadlocking the OST.  The bios are now released as soon as complete
	 * so the pool cannot be exhausted while IOs are competing. bug 10076 */
	bio_put(bio);
}

static void record_start_io(struct osd_iobuf *iobuf, int size)
{
	struct osd_device    *osd = iobuf->dr_dev;
	struct obd_histogram *h = osd->od_brw_stats.hist;

	iobuf->dr_frags++;
	atomic_inc(&iobuf->dr_numreqs);

	if (iobuf->dr_rw == 0) {
		atomic_inc(&osd->od_r_in_flight);
		lprocfs_oh_tally(&h[BRW_R_RPC_HIST],
				 atomic_read(&osd->od_r_in_flight));
		lprocfs_oh_tally_log2(&h[BRW_R_DISK_IOSIZE], size);
	} else if (iobuf->dr_rw == 1) {
		atomic_inc(&osd->od_w_in_flight);
		lprocfs_oh_tally(&h[BRW_W_RPC_HIST],
				 atomic_read(&osd->od_w_in_flight));
		lprocfs_oh_tally_log2(&h[BRW_W_DISK_IOSIZE], size);
	} else {
		LBUG();
	}
}

static void osd_submit_bio(int rw, struct bio *bio)
{
        LASSERTF(rw == 0 || rw == 1, "%x\n", rw);
#ifdef HAVE_SUBMIT_BIO_2ARGS
        if (rw == 0)
                submit_bio(READ, bio);
        else
                submit_bio(WRITE, bio);
#else
        bio->bi_opf |= rw;
        submit_bio(bio);
#endif
}

static int can_be_merged(struct bio *bio, sector_t sector)
{
	if (bio == NULL)
		return 0;

	return bio_end_sector(bio) == sector ? 1 : 0;
}

static int osd_do_bio(struct osd_device *osd, struct inode *inode,
                      struct osd_iobuf *iobuf)
{
	int            blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	struct page  **pages = iobuf->dr_pages;
	int            npages = iobuf->dr_npages;
	sector_t      *blocks = iobuf->dr_blocks;
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
	DECLARE_PLUG(plug);
	ENTRY;

        LASSERT(iobuf->dr_npages == npages);

        osd_brw_stats_update(osd, iobuf);
        iobuf->dr_start_time = cfs_time_current();

	blk_start_plug(&plug);
        for (page_idx = 0, block_idx = 0;
             page_idx < npages;
             page_idx++, block_idx += blocks_per_page) {

                page = pages[page_idx];
                LASSERT(block_idx + blocks_per_page <= total_blocks);

                for (i = 0, page_offset = 0;
                     i < blocks_per_page;
                     i += nblocks, page_offset += blocksize * nblocks) {

                        nblocks = 1;

                        if (blocks[block_idx + i] == 0) {  /* hole */
                                LASSERTF(iobuf->dr_rw == 0,
                                         "page_idx %u, block_idx %u, i %u\n",
                                         page_idx, block_idx, i);
                                memset(kmap(page) + page_offset, 0, blocksize);
                                kunmap(page);
                                continue;
                        }

                        sector = (sector_t)blocks[block_idx + i] << sector_bits;

                        /* Additional contiguous file blocks? */
                        while (i + nblocks < blocks_per_page &&
                               (sector + (nblocks << sector_bits)) ==
                               ((sector_t)blocks[block_idx + i + nblocks] <<
                                sector_bits))
                                nblocks++;

                        if (bio != NULL &&
                            can_be_merged(bio, sector) &&
                            bio_add_page(bio, page,
                                         blocksize * nblocks, page_offset) != 0)
                                continue;       /* added this frag OK */

			if (bio != NULL) {
				struct request_queue *q =
					bdev_get_queue(bio->bi_bdev);
				unsigned int bi_size = bio_sectors(bio) << 9;

				/* Dang! I have to fragment this I/O */
				CDEBUG(D_INODE, "bio++ sz %d vcnt %d(%d) "
				       "sectors %d(%d) psg %d(%d) hsg %d(%d)\n",
				       bi_size, bio->bi_vcnt, bio->bi_max_vecs,
				       bio_sectors(bio),
				       queue_max_sectors(q),
                                       bio_phys_segments(q, bio),
                                       queue_max_phys_segments(q),
				       0, queue_max_hw_segments(q));
				record_start_io(iobuf, bi_size);
				osd_submit_bio(iobuf->dr_rw, bio);
			}

			/* allocate new bio */
			bio = bio_alloc(GFP_NOIO, min(BIO_MAX_PAGES,
						      (npages - page_idx) *
						      blocks_per_page));
                        if (bio == NULL) {
                                CERROR("Can't allocate bio %u*%u = %u pages\n",
                                       (npages - page_idx), blocks_per_page,
                                       (npages - page_idx) * blocks_per_page);
                                rc = -ENOMEM;
                                goto out;
                        }

			bio->bi_bdev = inode->i_sb->s_bdev;
			bio_set_sector(bio, sector);
#ifdef HAVE_BI_RW
			bio->bi_rw = (iobuf->dr_rw == 0) ? READ : WRITE;
#else
			bio->bi_opf = (iobuf->dr_rw == 0) ? READ : WRITE;
#endif
			bio->bi_end_io = dio_complete_routine;
			bio->bi_private = iobuf;

			rc = bio_add_page(bio, page,
					  blocksize * nblocks, page_offset);
			LASSERT(rc != 0);
		}
	}

	if (bio != NULL) {
		record_start_io(iobuf, bio_sectors(bio) << 9);
		osd_submit_bio(iobuf->dr_rw, bio);
		rc = 0;
	}

out:
	blk_finish_plug(&plug);

	/* in order to achieve better IO throughput, we don't wait for writes
	 * completion here. instead we proceed with transaction commit in
	 * parallel and wait for IO completion once transaction is stopped
	 * see osd_trans_stop() for more details -bzzz */
	if (iobuf->dr_rw == 0) {
		wait_event(iobuf->dr_wait,
			   atomic_read(&iobuf->dr_numreqs) == 0);
		osd_fini_iobuf(osd, iobuf);
	}

	if (rc == 0)
		rc = iobuf->dr_error;
	RETURN(rc);
}

static int osd_map_remote_to_local(loff_t offset, ssize_t len, int *nrpages,
                                   struct niobuf_local *lnb)
{
        ENTRY;

        *nrpages = 0;

        while (len > 0) {
		int poff = offset & (PAGE_SIZE - 1);
		int plen = PAGE_SIZE - poff;

                if (plen > len)
                        plen = len;
		lnb->lnb_file_offset = offset;
		lnb->lnb_page_offset = poff;
		lnb->lnb_len = plen;
		/* lnb->lnb_flags = rnb->rnb_flags; */
		lnb->lnb_flags = 0;
		lnb->lnb_page = NULL;
		lnb->lnb_rc = 0;

                LASSERTF(plen <= len, "plen %u, len %lld\n", plen,
                         (long long) len);
                offset += plen;
                len -= plen;
                lnb++;
                (*nrpages)++;
        }

        RETURN(0);
}

static struct page *osd_get_page(struct dt_object *dt, loff_t offset,
				 gfp_t gfp_mask)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	struct osd_device *d = osd_obj2dev(osd_dt_obj(dt));
	struct page *page;

        LASSERT(inode);

	page = find_or_create_page(inode->i_mapping, offset >> PAGE_SHIFT,
				   gfp_mask);

        if (unlikely(page == NULL))
                lprocfs_counter_add(d->od_stats, LPROC_OSD_NO_PAGE, 1);

        return page;
}

/*
 * there are following "locks":
 * journal_start
 * i_mutex
 * page lock
 *
 * osd write path:
 *  - lock page(s)
 *  - journal_start
 *  - truncate_sem
 *
 * ext4 vmtruncate:
 *  - lock pages, unlock
 *  - journal_start
 *  - lock partial page
 *  - i_data_sem
 *
 */

/**
 * Unlock and release pages loaded by osd_bufs_get()
 *
 * Unlock \a npages pages from \a lnb and drop the refcount on them.
 *
 * \param env		thread execution environment
 * \param dt		dt object undergoing IO (OSD object + methods)
 * \param lnb		array of pages undergoing IO
 * \param npages	number of pages in \a lnb
 *
 * \retval 0		always
 */
static int osd_bufs_put(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	int i;

	for (i = 0; i < npages; i++) {
		if (lnb[i].lnb_page == NULL)
			continue;
		LASSERT(PageLocked(lnb[i].lnb_page));
		unlock_page(lnb[i].lnb_page);
		put_page(lnb[i].lnb_page);
		dt_object_put(env, dt);
		lnb[i].lnb_page = NULL;
	}

	RETURN(0);
}

/**
 * Load and lock pages undergoing IO
 *
 * Pages as described in the \a lnb array are fetched (from disk or cache)
 * and locked for IO by the caller.
 *
 * DLM locking protects us from write and truncate competing for same region,
 * but partial-page truncate can leave dirty pages in the cache for ldiskfs.
 * It's possible the writeout on a such a page is in progress when we access
 * it. It's also possible that during this writeout we put new (partial) data
 * into the page, but won't be able to proceed in filter_commitrw_write().
 * Therefore, just wait for writeout completion as it should be rare enough.
 *
 * \param env		thread execution environment
 * \param dt		dt object undergoing IO (OSD object + methods)
 * \param pos		byte offset of IO start
 * \param len		number of bytes of IO
 * \param lnb		array of extents undergoing IO
 * \param rw		read or write operation, and other flags
 * \param capa		capabilities
 *
 * \retval pages	(zero or more) loaded successfully
 * \retval -ENOMEM	on memory/page allocation error
 */
static int osd_bufs_get(const struct lu_env *env, struct dt_object *dt,
			loff_t pos, ssize_t len, struct niobuf_local *lnb,
			enum dt_bufs_type rw)
{
	struct osd_object *obj = osd_dt_obj(dt);
	int npages, i, rc = 0;
	gfp_t gfp_mask;

	LASSERT(obj->oo_inode);

	osd_map_remote_to_local(pos, len, &npages, lnb);

	/* this could also try less hard for DT_BUFS_TYPE_READAHEAD pages */
	gfp_mask = rw & DT_BUFS_TYPE_LOCAL ? (GFP_NOFS | __GFP_HIGHMEM) :
					     GFP_HIGHUSER;
	for (i = 0; i < npages; i++, lnb++) {
		lnb->lnb_page = osd_get_page(dt, lnb->lnb_file_offset,
					     gfp_mask);
		if (lnb->lnb_page == NULL)
			GOTO(cleanup, rc = -ENOMEM);

		wait_on_page_writeback(lnb->lnb_page);
		BUG_ON(PageWriteback(lnb->lnb_page));

		lu_object_get(&dt->do_lu);
	}

	RETURN(i);

cleanup:
	if (i > 0)
		osd_bufs_put(env, dt, lnb - i, i);
	return rc;
}

#ifndef HAVE_LDISKFS_MAP_BLOCKS

#ifdef HAVE_EXT_PBLOCK /* Name changed to ext4_ext_pblock for kernel 2.6.35 */
#define ldiskfs_ext_pblock(ex) ext_pblock((ex))
#endif

struct bpointers {
	sector_t *blocks;
	unsigned long start;
	int num;
	int init_num;
	int create;
};

static long ldiskfs_ext_find_goal(struct inode *inode,
				  struct ldiskfs_ext_path *path,
				  unsigned long block, int *aflags)
{
	struct ldiskfs_inode_info *ei = LDISKFS_I(inode);
	unsigned long bg_start;
	unsigned long colour;
	int depth;

	if (path) {
		struct ldiskfs_extent *ex;
		depth = path->p_depth;

		/* try to predict block placement */
		if ((ex = path[depth].p_ext))
			return ldiskfs_ext_pblock(ex) +
				(block - le32_to_cpu(ex->ee_block));

		/* it looks index is empty
		 * try to find starting from index itself */
		if (path[depth].p_bh)
			return path[depth].p_bh->b_blocknr;
	}

	/* OK. use inode's group */
	bg_start = (ei->i_block_group * LDISKFS_BLOCKS_PER_GROUP(inode->i_sb)) +
		le32_to_cpu(LDISKFS_SB(inode->i_sb)->s_es->s_first_data_block);
	colour = (current->pid % 16) *
		(LDISKFS_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	return bg_start + colour + block;
}

static unsigned long new_blocks(handle_t *handle, struct inode *inode,
				struct ldiskfs_ext_path *path,
				unsigned long block, unsigned long *count,
				int *err)
{
	struct ldiskfs_allocation_request ar;
	unsigned long pblock;
	int aflags;

	/* find neighbour allocated blocks */
	ar.lleft = block;
	*err = ldiskfs_ext_search_left(inode, path, &ar.lleft, &ar.pleft);
	if (*err)
		return 0;
	ar.lright = block;
	*err = ldiskfs_ext_search_right(inode, path, &ar.lright, &ar.pright);
	if (*err)
		return 0;

	/* allocate new block */
	ar.goal = ldiskfs_ext_find_goal(inode, path, block, &aflags);
	ar.inode = inode;
	ar.logical = block;
	ar.len = *count;
	ar.flags = LDISKFS_MB_HINT_DATA;
	pblock = ldiskfs_mb_new_blocks(handle, &ar, err);
	*count = ar.len;
	return pblock;
}

static int ldiskfs_ext_new_extent_cb(struct inode *inode,
				     struct ldiskfs_ext_path *path,
				     struct ldiskfs_ext_cache *cex,
#ifdef HAVE_EXT_PREPARE_CB_EXTENT
				     struct ldiskfs_extent *ex,
#endif
				     void *cbdata)
{
	struct bpointers *bp = cbdata;
	struct ldiskfs_extent nex;
	unsigned long pblock = 0;
	unsigned long tgen;
	int err, i;
	unsigned long count;
	handle_t *handle;

#ifdef LDISKFS_EXT_CACHE_EXTENT /* until kernel 2.6.37 */
	if (cex->ec_type == LDISKFS_EXT_CACHE_EXTENT) {
#else
	if ((cex->ec_len != 0) && (cex->ec_start != 0)) {
#endif
		err = EXT_CONTINUE;
		goto map;
	}

	if (bp->create == 0) {
		i = 0;
		if (cex->ec_block < bp->start)
			i = bp->start - cex->ec_block;
		if (i >= cex->ec_len)
			CERROR("nothing to do?! i = %d, e_num = %u\n",
					i, cex->ec_len);
		for (; i < cex->ec_len && bp->num; i++) {
			*(bp->blocks) = 0;
			bp->blocks++;
			bp->num--;
			bp->start++;
		}

		return EXT_CONTINUE;
	}

	tgen = LDISKFS_I(inode)->i_ext_generation;
	count = ldiskfs_ext_calc_credits_for_insert(inode, path);

	handle = osd_journal_start(inode, LDISKFS_HT_MISC,
				   count + LDISKFS_ALLOC_NEEDED + 1);
	if (IS_ERR(handle)) {
		return PTR_ERR(handle);
	}

	if (tgen != LDISKFS_I(inode)->i_ext_generation) {
		/* the tree has changed. so path can be invalid at moment */
		ldiskfs_journal_stop(handle);
		return EXT_REPEAT;
	}

	/* In 2.6.32 kernel, ldiskfs_ext_walk_space()'s callback func is not
	 * protected by i_data_sem as whole. so we patch it to store
	 * generation to path and now verify the tree hasn't changed */
	down_write((&LDISKFS_I(inode)->i_data_sem));

	/* validate extent, make sure the extent tree does not changed */
	if (LDISKFS_I(inode)->i_ext_generation != path[0].p_generation) {
		/* cex is invalid, try again */
		up_write(&LDISKFS_I(inode)->i_data_sem);
		ldiskfs_journal_stop(handle);
		return EXT_REPEAT;
	}

	count = cex->ec_len;
	pblock = new_blocks(handle, inode, path, cex->ec_block, &count, &err);
	if (!pblock)
		goto out;
	BUG_ON(count > cex->ec_len);

	/* insert new extent */
	nex.ee_block = cpu_to_le32(cex->ec_block);
	ldiskfs_ext_store_pblock(&nex, pblock);
	nex.ee_len = cpu_to_le16(count);
	err = ldiskfs_ext_insert_extent(handle, inode, path, &nex, 0);
	if (err) {
		/* free data blocks we just allocated */
		/* not a good idea to call discard here directly,
		 * but otherwise we'd need to call it every free() */
		ldiskfs_discard_preallocations(inode);
#ifdef HAVE_EXT_FREE_BLOCK_WITH_BUFFER_HEAD /* Introduced in 2.6.32-rc7 */
		ldiskfs_free_blocks(handle, inode, NULL,
				    ldiskfs_ext_pblock(&nex),
				    le16_to_cpu(nex.ee_len), 0);
#else
		ldiskfs_free_blocks(handle, inode, ldiskfs_ext_pblock(&nex),
				    le16_to_cpu(nex.ee_len), 0);
#endif
		goto out;
	}

	/*
	 * Putting len of the actual extent we just inserted,
	 * we are asking ldiskfs_ext_walk_space() to continue
	 * scaning after that block
	 */
	cex->ec_len = le16_to_cpu(nex.ee_len);
	cex->ec_start = ldiskfs_ext_pblock(&nex);
	BUG_ON(le16_to_cpu(nex.ee_len) == 0);
	BUG_ON(le32_to_cpu(nex.ee_block) != cex->ec_block);

out:
	up_write((&LDISKFS_I(inode)->i_data_sem));
	ldiskfs_journal_stop(handle);
map:
	if (err >= 0) {
		/* map blocks */
		if (bp->num == 0) {
			CERROR("hmm. why do we find this extent?\n");
			CERROR("initial space: %lu:%u\n",
				bp->start, bp->init_num);
#ifdef LDISKFS_EXT_CACHE_EXTENT /* until kernel 2.6.37 */
			CERROR("current extent: %u/%u/%llu %d\n",
				cex->ec_block, cex->ec_len,
				(unsigned long long)cex->ec_start,
				cex->ec_type);
#else
			CERROR("current extent: %u/%u/%llu\n",
				cex->ec_block, cex->ec_len,
				(unsigned long long)cex->ec_start);
#endif
		}
		i = 0;
		if (cex->ec_block < bp->start)
			i = bp->start - cex->ec_block;
		if (i >= cex->ec_len)
			CERROR("nothing to do?! i = %d, e_num = %u\n",
					i, cex->ec_len);
		for (; i < cex->ec_len && bp->num; i++) {
			*(bp->blocks) = cex->ec_start + i;
			if (pblock != 0) {
				/* unmap any possible underlying metadata from
				 * the block device mapping.  bug 6998. */
#ifndef HAVE_CLEAN_BDEV_ALIASES
				unmap_underlying_metadata(inode->i_sb->s_bdev,
							  *(bp->blocks));
#else
				clean_bdev_aliases(inode->i_sb->s_bdev,
						   *(bp->blocks), 1);
#endif
			}
			bp->blocks++;
			bp->num--;
			bp->start++;
		}
	}
	return err;
}

static int osd_ldiskfs_map_nblocks(struct inode *inode, unsigned long index,
				   int clen, sector_t *blocks, int create)
{
	int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	struct bpointers bp;
	int err;

	if (index + clen >= inode->i_sb->s_maxbytes >> PAGE_SHIFT)
		return -EFBIG;

	bp.blocks = blocks;
	bp.start = index * blocks_per_page;
	bp.init_num = bp.num = clen * blocks_per_page;
	bp.create = create;

	CDEBUG(D_OTHER, "blocks %lu-%lu requested for inode %u\n",
	       bp.start, bp.start + bp.num - 1, (unsigned)inode->i_ino);

	err = ldiskfs_ext_walk_space(inode, bp.start, bp.num,
				     ldiskfs_ext_new_extent_cb, &bp);
	ldiskfs_ext_invalidate_cache(inode);

	return err;
}

static int osd_ldiskfs_map_bm_inode_pages(struct inode *inode,
					  struct page **page, int pages,
					  sector_t *blocks, int create)
{
	int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	pgoff_t bitmap_max_page_index;
	sector_t *b;
	int rc = 0, i;

	bitmap_max_page_index = LDISKFS_SB(inode->i_sb)->s_bitmap_maxbytes >>
				PAGE_SHIFT;
	for (i = 0, b = blocks; i < pages; i++, page++) {
		if ((*page)->index + 1 >= bitmap_max_page_index) {
			rc = -EFBIG;
			break;
		}
		rc = ldiskfs_map_inode_page(inode, *page, b, create);
		if (rc) {
			CERROR("ino %lu, blk %llu create %d: rc %d\n",
			       inode->i_ino,
			       (unsigned long long)*b, create, rc);
			break;
		}
		b += blocks_per_page;
	}
	return rc;
}

static int osd_ldiskfs_map_ext_inode_pages(struct inode *inode,
					   struct page **page,
					   int pages, sector_t *blocks,
					   int create)
{
	int rc = 0, i = 0, clen = 0;
	struct page *fp = NULL;

	CDEBUG(D_OTHER, "inode %lu: map %d pages from %lu\n",
		inode->i_ino, pages, (*page)->index);

	/* pages are sorted already. so, we just have to find
	 * contig. space and process them properly */
	while (i < pages) {
		if (fp == NULL) {
			/* start new extent */
			fp = *page++;
			clen = 1;
			i++;
			continue;
		} else if (fp->index + clen == (*page)->index) {
			/* continue the extent */
			page++;
			clen++;
			i++;
			continue;
		}

		/* process found extent */
		rc = osd_ldiskfs_map_nblocks(inode, fp->index, clen,
					     blocks, create);
		if (rc)
			GOTO(cleanup, rc);

		/* look for next extent */
		fp = NULL;
		blocks += clen * (PAGE_SIZE >> inode->i_blkbits);
	}

	if (fp)
		rc = osd_ldiskfs_map_nblocks(inode, fp->index, clen,
					     blocks, create);

cleanup:
	return rc;
}

static int osd_ldiskfs_map_inode_pages(struct inode *inode, struct page **page,
				       int pages, sector_t *blocks,
				       int create)
{
	int rc;

	if (LDISKFS_I(inode)->i_flags & LDISKFS_EXTENTS_FL) {
		rc = osd_ldiskfs_map_ext_inode_pages(inode, page, pages,
						     blocks, create);
		return rc;
	}
	rc = osd_ldiskfs_map_bm_inode_pages(inode, page, pages, blocks, create);

	return rc;
}
#else
static int osd_ldiskfs_map_inode_pages(struct inode *inode, struct page **page,
				       int pages, sector_t *blocks,
				       int create)
{
	int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	int rc = 0, i = 0;
	struct page *fp = NULL;
	int clen = 0;
	pgoff_t max_page_index;
	handle_t *handle = NULL;

	max_page_index = inode->i_sb->s_maxbytes >> PAGE_SHIFT;

	CDEBUG(D_OTHER, "inode %lu: map %d pages from %lu\n",
		inode->i_ino, pages, (*page)->index);

	if (create) {
		create = LDISKFS_GET_BLOCKS_CREATE;
		handle = ldiskfs_journal_current_handle();
		LASSERT(handle != NULL);
		rc = osd_attach_jinode(inode);
		if (rc)
			return rc;
	}
	/* pages are sorted already. so, we just have to find
	 * contig. space and process them properly */
	while (i < pages) {
		long blen, total = 0;
		struct ldiskfs_map_blocks map = { 0 };

		if (fp == NULL) { /* start new extent */
			fp = *page++;
			clen = 1;
			if (++i != pages)
				continue;
		} else if (fp->index + clen == (*page)->index) {
			/* continue the extent */
			page++;
			clen++;
			if (++i != pages)
				continue;
		}
		if (fp->index + clen >= max_page_index)
			GOTO(cleanup, rc = -EFBIG);
		/* process found extent */
		map.m_lblk = fp->index * blocks_per_page;
		map.m_len = blen = clen * blocks_per_page;
cont_map:
		rc = ldiskfs_map_blocks(handle, inode, &map, create);
		if (rc >= 0) {
			int c = 0;
			for (; total < blen && c < map.m_len; c++, total++) {
				if (rc == 0) {
					*(blocks + total) = 0;
					total++;
					break;
				} else {
					*(blocks + total) = map.m_pblk + c;
					/* unmap any possible underlying
					 * metadata from the block device
					 * mapping.  bug 6998. */
					if ((map.m_flags & LDISKFS_MAP_NEW) &&
					    create)
#ifndef HAVE_CLEAN_BDEV_ALIASES
						unmap_underlying_metadata(
							inode->i_sb->s_bdev,
							map.m_pblk + c);
#else
						clean_bdev_aliases(
							inode->i_sb->s_bdev,
							map.m_pblk + c, 1);
#endif
				}
			}
			rc = 0;
		}
		if (rc == 0 && total < blen) {
			map.m_lblk = fp->index * blocks_per_page + total;
			map.m_len = blen - total;
			goto cont_map;
		}
		if (rc != 0)
			GOTO(cleanup, rc);

		/* look for next extent */
		fp = NULL;
		blocks += blocks_per_page * clen;
	}
cleanup:
	return rc;
}
#endif /* HAVE_LDISKFS_MAP_BLOCKS */

static int osd_write_prep(const struct lu_env *env, struct dt_object *dt,
                          struct niobuf_local *lnb, int npages)
{
        struct osd_thread_info *oti   = osd_oti_get(env);
        struct osd_iobuf       *iobuf = &oti->oti_iobuf;
        struct inode           *inode = osd_dt_obj(dt)->oo_inode;
        struct osd_device      *osd   = osd_obj2dev(osd_dt_obj(dt));
	ktime_t start;
	ktime_t end;
	s64 timediff;
        ssize_t                 isize;
        __s64                   maxidx;
        int                     rc = 0;
        int                     i;
        int                     cache = 0;

        LASSERT(inode);

	rc = osd_init_iobuf(osd, iobuf, 0, npages);
	if (unlikely(rc != 0))
		RETURN(rc);

	isize = i_size_read(inode);
	maxidx = ((isize + PAGE_SIZE - 1) >> PAGE_SHIFT) - 1;

        if (osd->od_writethrough_cache)
                cache = 1;
        if (isize > osd->od_readcache_max_filesize)
                cache = 0;

	start = ktime_get();
	for (i = 0; i < npages; i++) {

		if (cache == 0)
			generic_error_remove_page(inode->i_mapping,
						  lnb[i].lnb_page);

		/*
		 * till commit the content of the page is undefined
		 * we'll set it uptodate once bulk is done. otherwise
		 * subsequent reads can access non-stable data
		 */
		ClearPageUptodate(lnb[i].lnb_page);

		if (lnb[i].lnb_len == PAGE_SIZE)
			continue;

		if (maxidx >= lnb[i].lnb_page->index) {
			osd_iobuf_add_page(iobuf, lnb[i].lnb_page);
		} else {
			long off;
			char *p = kmap(lnb[i].lnb_page);

			off = lnb[i].lnb_page_offset;
			if (off)
				memset(p, 0, off);
			off = (lnb[i].lnb_page_offset + lnb[i].lnb_len) &
			      ~PAGE_MASK;
			if (off)
				memset(p + off, 0, PAGE_SIZE - off);
			kunmap(lnb[i].lnb_page);
		}
	}
	end = ktime_get();
	timediff = ktime_us_delta(end, start);
	lprocfs_counter_add(osd->od_stats, LPROC_OSD_GET_PAGE, timediff);

        if (iobuf->dr_npages) {
		rc = osd_ldiskfs_map_inode_pages(inode, iobuf->dr_pages,
						 iobuf->dr_npages,
						 iobuf->dr_blocks, 0);
                if (likely(rc == 0)) {
                        rc = osd_do_bio(osd, inode, iobuf);
                        /* do IO stats for preparation reads */
                        osd_fini_iobuf(osd, iobuf);
                }
        }
        RETURN(rc);
}

struct osd_fextent {
	sector_t	start;
	sector_t	end;
	unsigned int	mapped:1;
};

static int osd_is_mapped(struct dt_object *dt, __u64 offset,
			 struct osd_fextent *cached_extent)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	sector_t block = offset >> inode->i_blkbits;
	sector_t start;
	struct fiemap_extent_info fei = { 0 };
	struct fiemap_extent fe = { 0 };
	mm_segment_t saved_fs;
	int rc;

	if (block >= cached_extent->start && block < cached_extent->end)
		return cached_extent->mapped;

	if (i_size_read(inode) == 0)
		return 0;

	/* Beyond EOF, must not be mapped */
	if (((i_size_read(inode) - 1) >> inode->i_blkbits) < block)
		return 0;

	fei.fi_extents_max = 1;
	fei.fi_extents_start = &fe;

	saved_fs = get_fs();
	set_fs(get_ds());
	rc = inode->i_op->fiemap(inode, &fei, offset, FIEMAP_MAX_OFFSET-offset);
	set_fs(saved_fs);
	if (rc != 0)
		return 0;

	start = fe.fe_logical >> inode->i_blkbits;

	if (start > block) {
		cached_extent->start = block;
		cached_extent->end = start;
		cached_extent->mapped = 0;
	} else {
		cached_extent->start = start;
		cached_extent->end = (fe.fe_logical + fe.fe_length) >>
				      inode->i_blkbits;
		cached_extent->mapped = 1;
	}

	return cached_extent->mapped;
}

static int osd_declare_write_commit(const struct lu_env *env,
                                    struct dt_object *dt,
                                    struct niobuf_local *lnb, int npages,
                                    struct thandle *handle)
{
	const struct osd_device	*osd = osd_obj2dev(osd_dt_obj(dt));
	struct inode		*inode = osd_dt_obj(dt)->oo_inode;
	struct osd_thandle	*oh;
	int			extents = 1;
	int			depth;
	int			i;
	int			newblocks;
	int			rc = 0;
	int			flags = 0;
	int			credits = 0;
	long long		quota_space = 0;
	struct osd_fextent	extent = { 0 };
	enum osd_qid_declare_flags declare_flags = OSD_QID_BLK;
	ENTRY;

        LASSERT(handle != NULL);
        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle == NULL);

        newblocks = npages;

        /* calculate number of extents (probably better to pass nb) */
	for (i = 0; i < npages; i++) {
		if (i && lnb[i].lnb_file_offset !=
		    lnb[i - 1].lnb_file_offset + lnb[i - 1].lnb_len)
			extents++;

		if (osd_is_mapped(dt, lnb[i].lnb_file_offset, &extent))
			lnb[i].lnb_flags |= OBD_BRW_MAPPED;
		else
			quota_space += PAGE_SIZE;

		/* ignore quota for the whole request if any page is from
		 * client cache or written by root.
		 *
		 * XXX once we drop the 1.8 client support, the checking
		 * for whether page is from cache can be simplified as:
		 * !(lnb[i].flags & OBD_BRW_SYNC)
		 *
		 * XXX we could handle this on per-lnb basis as done by
		 * grant. */
		if ((lnb[i].lnb_flags & OBD_BRW_NOQUOTA) ||
		    (lnb[i].lnb_flags & (OBD_BRW_FROM_GRANT | OBD_BRW_SYNC)) ==
		    OBD_BRW_FROM_GRANT)
			declare_flags |= OSD_QID_FORCE;
	}

        /*
         * each extent can go into new leaf causing a split
         * 5 is max tree depth: inode + 4 index blocks
         * with blockmaps, depth is 3 at most
         */
        if (LDISKFS_I(inode)->i_flags & LDISKFS_EXTENTS_FL) {
                /*
                 * many concurrent threads may grow tree by the time
                 * our transaction starts. so, consider 2 is a min depth
                 */
                depth = ext_depth(inode);
                depth = max(depth, 1) + 1;
                newblocks += depth;
		credits++; /* inode */
		credits += depth * 2 * extents;
	} else {
		depth = 3;
		newblocks += depth;
		credits++; /* inode */
		credits += depth * extents;
	}

	/* quota space for metadata blocks */
	quota_space += depth * extents * LDISKFS_BLOCK_SIZE(osd_sb(osd));

	/* quota space should be reported in 1K blocks */
	quota_space = toqb(quota_space);

        /* each new block can go in different group (bitmap + gd) */

        /* we can't dirty more bitmap blocks than exist */
        if (newblocks > LDISKFS_SB(osd_sb(osd))->s_groups_count)
		credits += LDISKFS_SB(osd_sb(osd))->s_groups_count;
        else
		credits += newblocks;

	/* we can't dirty more gd blocks than exist */
	if (newblocks > LDISKFS_SB(osd_sb(osd))->s_gdb_count)
		credits += LDISKFS_SB(osd_sb(osd))->s_gdb_count;
	else
		credits += newblocks;

	osd_trans_declare_op(env, oh, OSD_OT_WRITE, credits);

	/* make sure the over quota flags were not set */
	lnb[0].lnb_flags &= ~OBD_BRW_OVER_ALLQUOTA;

	rc = osd_declare_inode_qid(env, i_uid_read(inode), i_gid_read(inode),
				   i_projid_read(inode), quota_space, oh,
				   osd_dt_obj(dt), &flags, declare_flags);

	/* we need only to store the overquota flags in the first lnb for
	 * now, once we support multiple objects BRW, this code needs be
	 * revised. */
	if (flags & QUOTA_FL_OVER_USRQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_USRQUOTA;
	if (flags & QUOTA_FL_OVER_GRPQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_GRPQUOTA;
	if (flags & QUOTA_FL_OVER_PRJQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_PRJQUOTA;

	RETURN(rc);
}

/* Check if a block is allocated or not */
static int osd_write_commit(const struct lu_env *env, struct dt_object *dt,
                            struct niobuf_local *lnb, int npages,
                            struct thandle *thandle)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        struct osd_iobuf *iobuf = &oti->oti_iobuf;
        struct inode *inode = osd_dt_obj(dt)->oo_inode;
        struct osd_device  *osd = osd_obj2dev(osd_dt_obj(dt));
        loff_t isize;
        int rc = 0, i;

        LASSERT(inode);

	rc = osd_init_iobuf(osd, iobuf, 1, npages);
	if (unlikely(rc != 0))
		RETURN(rc);

	isize = i_size_read(inode);
	ll_vfs_dq_init(inode);

        for (i = 0; i < npages; i++) {
		if (lnb[i].lnb_rc == -ENOSPC &&
		    (lnb[i].lnb_flags & OBD_BRW_MAPPED)) {
			/* Allow the write to proceed if overwriting an
			 * existing block */
			lnb[i].lnb_rc = 0;
		}

		if (lnb[i].lnb_rc) { /* ENOSPC, network RPC error, etc. */
			CDEBUG(D_INODE, "Skipping [%d] == %d\n", i,
			       lnb[i].lnb_rc);
			LASSERT(lnb[i].lnb_page);
			generic_error_remove_page(inode->i_mapping,
						  lnb[i].lnb_page);
			continue;
		}

		LASSERT(PageLocked(lnb[i].lnb_page));
		LASSERT(!PageWriteback(lnb[i].lnb_page));

		if (lnb[i].lnb_file_offset + lnb[i].lnb_len > isize)
			isize = lnb[i].lnb_file_offset + lnb[i].lnb_len;

		/*
		 * Since write and truncate are serialized by oo_sem, even
		 * partial-page truncate should not leave dirty pages in the
		 * page cache.
		 */
		LASSERT(!PageDirty(lnb[i].lnb_page));

		SetPageUptodate(lnb[i].lnb_page);

		osd_iobuf_add_page(iobuf, lnb[i].lnb_page);
        }

	osd_trans_exec_op(env, thandle, OSD_OT_WRITE);

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_MAPBLK_ENOSPC)) {
                rc = -ENOSPC;
        } else if (iobuf->dr_npages > 0) {
		rc = osd_ldiskfs_map_inode_pages(inode, iobuf->dr_pages,
						 iobuf->dr_npages,
						 iobuf->dr_blocks, 1);
        } else {
                /* no pages to write, no transno is needed */
                thandle->th_local = 1;
        }

	if (likely(rc == 0)) {
		spin_lock(&inode->i_lock);
		if (isize > i_size_read(inode)) {
			i_size_write(inode, isize);
			LDISKFS_I(inode)->i_disksize = isize;
			spin_unlock(&inode->i_lock);
			ll_dirty_inode(inode, I_DIRTY_DATASYNC);
		} else {
			spin_unlock(&inode->i_lock);
		}

		rc = osd_do_bio(osd, inode, iobuf);
		/* we don't do stats here as in read path because
		 * write is async: we'll do this in osd_put_bufs() */
	} else {
		osd_fini_iobuf(osd, iobuf);
	}

	osd_trans_exec_check(env, thandle, OSD_OT_WRITE);

	if (unlikely(rc != 0)) {
		/* if write fails, we should drop pages from the cache */
		for (i = 0; i < npages; i++) {
			if (lnb[i].lnb_page == NULL)
				continue;
			LASSERT(PageLocked(lnb[i].lnb_page));
			generic_error_remove_page(inode->i_mapping,
						  lnb[i].lnb_page);
		}
	}

	RETURN(rc);
}

static int osd_read_prep(const struct lu_env *env, struct dt_object *dt,
                         struct niobuf_local *lnb, int npages)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        struct osd_iobuf *iobuf = &oti->oti_iobuf;
        struct inode *inode = osd_dt_obj(dt)->oo_inode;
        struct osd_device *osd = osd_obj2dev(osd_dt_obj(dt));
	int rc = 0, i, cache = 0, cache_hits = 0, cache_misses = 0;
	ktime_t start, end;
	s64 timediff;
	loff_t isize;

        LASSERT(inode);

	rc = osd_init_iobuf(osd, iobuf, 0, npages);
	if (unlikely(rc != 0))
		RETURN(rc);

	isize = i_size_read(inode);

	if (osd->od_read_cache)
		cache = 1;
	if (isize > osd->od_readcache_max_filesize)
		cache = 0;

	start = ktime_get();
	for (i = 0; i < npages; i++) {

		if (isize <= lnb[i].lnb_file_offset)
			/* If there's no more data, abort early.
			 * lnb->lnb_rc == 0, so it's easy to detect later. */
			break;

		if (isize < lnb[i].lnb_file_offset + lnb[i].lnb_len)
			lnb[i].lnb_rc = isize - lnb[i].lnb_file_offset;
		else
			lnb[i].lnb_rc = lnb[i].lnb_len;

		/* Bypass disk read if fail_loc is set properly */
		if (OBD_FAIL_CHECK(OBD_FAIL_OST_FAKE_RW))
			SetPageUptodate(lnb[i].lnb_page);

		if (PageUptodate(lnb[i].lnb_page)) {
			cache_hits++;
		} else {
			cache_misses++;
			osd_iobuf_add_page(iobuf, lnb[i].lnb_page);
		}

		if (cache == 0)
			generic_error_remove_page(inode->i_mapping,
						  lnb[i].lnb_page);
	}
	end = ktime_get();
	timediff = ktime_us_delta(end, start);
	lprocfs_counter_add(osd->od_stats, LPROC_OSD_GET_PAGE, timediff);

	if (cache_hits != 0)
		lprocfs_counter_add(osd->od_stats, LPROC_OSD_CACHE_HIT,
				    cache_hits);
	if (cache_misses != 0)
		lprocfs_counter_add(osd->od_stats, LPROC_OSD_CACHE_MISS,
				    cache_misses);
	if (cache_hits + cache_misses != 0)
		lprocfs_counter_add(osd->od_stats, LPROC_OSD_CACHE_ACCESS,
				    cache_hits + cache_misses);

        if (iobuf->dr_npages) {
		rc = osd_ldiskfs_map_inode_pages(inode, iobuf->dr_pages,
						 iobuf->dr_npages,
						 iobuf->dr_blocks, 0);
                rc = osd_do_bio(osd, inode, iobuf);

                /* IO stats will be done in osd_bufs_put() */
        }

        RETURN(rc);
}

/*
 * XXX: Another layering violation for now.
 *
 * We don't want to use ->f_op->read methods, because generic file write
 *
 *         - serializes on ->i_sem, and
 *
 *         - does a lot of extra work like balance_dirty_pages(),
 *
 * which doesn't work for globally shared files like /last_rcvd.
 */
static int osd_ldiskfs_readlink(struct inode *inode, char *buffer, int buflen)
{
        struct ldiskfs_inode_info *ei = LDISKFS_I(inode);

        memcpy(buffer, (char *)ei->i_data, buflen);

        return  buflen;
}

int osd_ldiskfs_read(struct inode *inode, void *buf, int size, loff_t *offs)
{
        struct buffer_head *bh;
        unsigned long block;
        int osize;
        int blocksize;
        int csize;
        int boffs;

        /* prevent reading after eof */
	spin_lock(&inode->i_lock);
	if (i_size_read(inode) < *offs + size) {
		loff_t diff = i_size_read(inode) - *offs;
		spin_unlock(&inode->i_lock);
		if (diff < 0) {
			CDEBUG(D_EXT2, "size %llu is too short to read @%llu\n",
			       i_size_read(inode), *offs);
			return -EBADR;
		} else if (diff == 0) {
			return 0;
		} else {
			size = diff;
		}
	} else {
		spin_unlock(&inode->i_lock);
	}

        blocksize = 1 << inode->i_blkbits;
        osize = size;
        while (size > 0) {
                block = *offs >> inode->i_blkbits;
                boffs = *offs & (blocksize - 1);
                csize = min(blocksize - boffs, size);
		bh = __ldiskfs_bread(NULL, inode, block, 0);
		if (IS_ERR(bh)) {
			CERROR("%s: can't read %u@%llu on ino %lu: "
			       "rc = %ld\n", osd_ino2name(inode),
			       csize, *offs, inode->i_ino,
			       PTR_ERR(bh));
			return PTR_ERR(bh);
		}

		if (bh != NULL) {
			memcpy(buf, bh->b_data + boffs, csize);
			brelse(bh);
		} else {
			memset(buf, 0, csize);
		}

                *offs += csize;
                buf += csize;
                size -= csize;
        }
        return osize;
}

static ssize_t osd_read(const struct lu_env *env, struct dt_object *dt,
			struct lu_buf *buf, loff_t *pos)
{
        struct inode *inode = osd_dt_obj(dt)->oo_inode;
        int           rc;

        /* Read small symlink from inode body as we need to maintain correct
         * on-disk symlinks for ldiskfs.
         */
        if (S_ISLNK(dt->do_lu.lo_header->loh_attr) &&
            (buf->lb_len < sizeof(LDISKFS_I(inode)->i_data)))
                rc = osd_ldiskfs_readlink(inode, buf->lb_buf, buf->lb_len);
        else
                rc = osd_ldiskfs_read(inode, buf->lb_buf, buf->lb_len, pos);

        return rc;
}

static inline int osd_extents_enabled(struct super_block *sb,
				      struct inode *inode)
{
	if (inode != NULL) {
		if (LDISKFS_I(inode)->i_flags & LDISKFS_EXTENTS_FL)
			return 1;
	} else if (LDISKFS_HAS_INCOMPAT_FEATURE(sb,
				LDISKFS_FEATURE_INCOMPAT_EXTENTS)) {
		return 1;
	}
	return 0;
}

int osd_calc_bkmap_credits(struct super_block *sb, struct inode *inode,
			   const loff_t size, const loff_t pos,
			   const int blocks)
{
	int credits, bits, bs, i;

	bits = sb->s_blocksize_bits;
	bs = 1 << bits;

	/* legacy blockmap: 3 levels * 3 (bitmap,gd,itself)
	 * we do not expect blockmaps on the large files,
	 * so let's shrink it to 2 levels (4GB files) */

	/* this is default reservation: 2 levels */
	credits = (blocks + 2) * 3;

	/* actual offset is unknown, hard to optimize */
	if (pos == -1)
		return credits;

	/* now check for few specific cases to optimize */
	if (pos + size <= LDISKFS_NDIR_BLOCKS * bs) {
		/* no indirects */
		credits = blocks;
		/* allocate if not allocated */
		if (inode == NULL) {
			credits += blocks * 2;
			return credits;
		}
		for (i = (pos >> bits); i < (pos >> bits) + blocks; i++) {
			LASSERT(i < LDISKFS_NDIR_BLOCKS);
			if (LDISKFS_I(inode)->i_data[i] == 0)
				credits += 2;
		}
	} else if (pos + size <= (LDISKFS_NDIR_BLOCKS + 1024) * bs) {
		/* single indirect */
		credits = blocks * 3;
		if (inode == NULL ||
		    LDISKFS_I(inode)->i_data[LDISKFS_IND_BLOCK] == 0)
			credits += 3;
		else
			/* The indirect block may be modified. */
			credits += 1;
	}

	return credits;
}

static ssize_t osd_declare_write(const struct lu_env *env, struct dt_object *dt,
				 const struct lu_buf *buf, loff_t _pos,
				 struct thandle *handle)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	struct inode	   *inode = obj->oo_inode;
	struct super_block *sb = osd_sb(osd_obj2dev(obj));
	struct osd_thandle *oh;
	int		    rc = 0, est = 0, credits, blocks, allocated = 0;
	int		    bits, bs;
	int		    depth, size;
	loff_t		    pos;
	ENTRY;

	LASSERT(buf != NULL);
        LASSERT(handle != NULL);

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle == NULL);

	size = buf->lb_len;
	bits = sb->s_blocksize_bits;
	bs = 1 << bits;

	if (_pos == -1) {
		/* if this is an append, then we
		 * should expect cross-block record */
		pos = 0;
	} else {
		pos = _pos;
	}

	/* blocks to modify */
	blocks = ((pos + size + bs - 1) >> bits) - (pos >> bits);
	LASSERT(blocks > 0);

	if (inode != NULL && _pos != -1) {
		/* object size in blocks */
		est = (i_size_read(inode) + bs - 1) >> bits;
		allocated = inode->i_blocks >> (bits - 9);
		if (pos + size <= i_size_read(inode) && est <= allocated) {
			/* looks like an overwrite, no need to modify tree */
			credits = blocks;
			/* no need to modify i_size */
			goto out;
		}
	}

	if (osd_extents_enabled(sb, inode)) {
		/*
		 * many concurrent threads may grow tree by the time
		 * our transaction starts. so, consider 2 is a min depth
		 * for every level we may need to allocate a new block
		 * and take some entries from the old one. so, 3 blocks
		 * to allocate (bitmap, gd, itself) + old block - 4 per
		 * level.
		 */
		depth = inode != NULL ? ext_depth(inode) : 0;
		depth = max(depth, 1) + 1;
		credits = depth;
		/* if not append, then split may need to modify
		 * existing blocks moving entries into the new ones */
		if (_pos != -1)
			credits += depth;
		/* blocks to store data: bitmap,gd,itself */
		credits += blocks * 3;
	} else {
		credits = osd_calc_bkmap_credits(sb, inode, size, _pos, blocks);
	}
	/* if inode is created as part of the transaction,
	 * then it's counted already by the creation method */
	if (inode != NULL)
		credits++;

out:

	osd_trans_declare_op(env, oh, OSD_OT_WRITE, credits);

	/* dt_declare_write() is usually called for system objects, such
	 * as llog or last_rcvd files. We needn't enforce quota on those
	 * objects, so always set the lqi_space as 0. */
	if (inode != NULL)
		rc = osd_declare_inode_qid(env, i_uid_read(inode),
					   i_gid_read(inode),
					   i_projid_read(inode), 0,
					   oh, obj, NULL, OSD_QID_BLK);
	RETURN(rc);
}

static int osd_ldiskfs_writelink(struct inode *inode, char *buffer, int buflen)
{
	/* LU-2634: clear the extent format for fast symlink */
	ldiskfs_clear_inode_flag(inode, LDISKFS_INODE_EXTENTS);

	memcpy((char *)&LDISKFS_I(inode)->i_data, (char *)buffer, buflen);
	spin_lock(&inode->i_lock);
	LDISKFS_I(inode)->i_disksize = buflen;
	i_size_write(inode, buflen);
	spin_unlock(&inode->i_lock);
	ll_dirty_inode(inode, I_DIRTY_DATASYNC);

	return 0;
}

int osd_ldiskfs_write_record(struct inode *inode, void *buf, int bufsize,
			     int write_NUL, loff_t *offs, handle_t *handle)
{
        struct buffer_head *bh        = NULL;
        loff_t              offset    = *offs;
        loff_t              new_size  = i_size_read(inode);
        unsigned long       block;
        int                 blocksize = 1 << inode->i_blkbits;
        int                 err = 0;
        int                 size;
        int                 boffs;
        int                 dirty_inode = 0;

	if (write_NUL) {
		/*
		 * long symlink write does not count the NUL terminator in
		 * bufsize, we write it, and the inode's file size does not
		 * count the NUL terminator as well.
		 */
		((char *)buf)[bufsize] = '\0';
		++bufsize;
	}

	while (bufsize > 0) {
		int credits = handle->h_buffer_credits;

		if (bh)
			brelse(bh);

		block = offset >> inode->i_blkbits;
		boffs = offset & (blocksize - 1);
		size = min(blocksize - boffs, bufsize);
		bh = __ldiskfs_bread(handle, inode, block, 1);
		if (IS_ERR_OR_NULL(bh)) {
			if (bh == NULL) {
				err = -EIO;
			} else {
				err = PTR_ERR(bh);
				bh = NULL;
			}

			CERROR("%s: error reading offset %llu (block %lu, "
			       "size %d, offs %llu), credits %d/%d: rc = %d\n",
			       inode->i_sb->s_id, offset, block, bufsize, *offs,
			       credits, handle->h_buffer_credits, err);
                        break;
                }

                err = ldiskfs_journal_get_write_access(handle, bh);
                if (err) {
                        CERROR("journal_get_write_access() returned error %d\n",
                               err);
                        break;
                }
		LASSERTF(boffs + size <= bh->b_size,
			 "boffs %d size %d bh->b_size %lu\n",
			 boffs, size, (unsigned long)bh->b_size);
                memcpy(bh->b_data + boffs, buf, size);
		err = ldiskfs_handle_dirty_metadata(handle, NULL, bh);
                if (err)
                        break;

                if (offset + size > new_size)
                        new_size = offset + size;
                offset += size;
                bufsize -= size;
                buf += size;
        }
        if (bh)
                brelse(bh);

	if (write_NUL)
		--new_size;
	/* correct in-core and on-disk sizes */
	if (new_size > i_size_read(inode)) {
		spin_lock(&inode->i_lock);
		if (new_size > i_size_read(inode))
			i_size_write(inode, new_size);
		if (i_size_read(inode) > LDISKFS_I(inode)->i_disksize) {
			LDISKFS_I(inode)->i_disksize = i_size_read(inode);
			dirty_inode = 1;
		}
		spin_unlock(&inode->i_lock);
		if (dirty_inode)
			ll_dirty_inode(inode, I_DIRTY_DATASYNC);
        }

        if (err == 0)
                *offs = offset;
        return err;
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, loff_t *pos,
			 struct thandle *handle, int ignore_quota)
{
	struct inode		*inode = osd_dt_obj(dt)->oo_inode;
	struct osd_thandle	*oh;
	ssize_t			result;
	int			is_link;

        LASSERT(dt_object_exists(dt));

        LASSERT(handle != NULL);
	LASSERT(inode != NULL);
	ll_vfs_dq_init(inode);

        /* XXX: don't check: one declared chunk can be used many times */
	/* osd_trans_exec_op(env, handle, OSD_OT_WRITE); */

        oh = container_of(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle->h_transaction != NULL);
	osd_trans_exec_op(env, handle, OSD_OT_WRITE);

	/* Write small symlink to inode body as we need to maintain correct
	 * on-disk symlinks for ldiskfs.
	 * Note: the buf->lb_buf contains a NUL terminator while buf->lb_len
	 * does not count it in.
	 */
	is_link = S_ISLNK(dt->do_lu.lo_header->loh_attr);
	if (is_link && (buf->lb_len < sizeof(LDISKFS_I(inode)->i_data)))
		result = osd_ldiskfs_writelink(inode, buf->lb_buf, buf->lb_len);
	else
		result = osd_ldiskfs_write_record(inode, buf->lb_buf,
						  buf->lb_len, is_link, pos,
						  oh->ot_handle);
	if (result == 0)
		result = buf->lb_len;

	osd_trans_exec_check(env, handle, OSD_OT_WRITE);

	return result;
}

static int osd_declare_punch(const struct lu_env *env, struct dt_object *dt,
                             __u64 start, __u64 end, struct thandle *th)
{
        struct osd_thandle *oh;
	struct inode	   *inode;
	int		    rc;
        ENTRY;

        LASSERT(th);
        oh = container_of(th, struct osd_thandle, ot_super);

        /*
         * we don't need to reserve credits for whole truncate
         * it's not possible as truncate may need to free too many
         * blocks and that won't fit a single transaction. instead
         * we reserve credits to change i_size and put inode onto
         * orphan list. if needed truncate will extend or restart
         * transaction
         */
	osd_trans_declare_op(env, oh, OSD_OT_PUNCH,
			     osd_dto_credits_noquota[DTO_ATTR_SET_BASE] + 3);

	inode = osd_dt_obj(dt)->oo_inode;
	LASSERT(inode);

	rc = osd_declare_inode_qid(env, i_uid_read(inode), i_gid_read(inode),
				   i_projid_read(inode), 0, oh, osd_dt_obj(dt),
				   NULL, OSD_QID_BLK);
	RETURN(rc);
}

static int osd_punch(const struct lu_env *env, struct dt_object *dt,
		     __u64 start, __u64 end, struct thandle *th)
{
	struct osd_thandle *oh;
	struct osd_object  *obj = osd_dt_obj(dt);
	struct inode       *inode = obj->oo_inode;
	handle_t           *h;
	tid_t               tid;
	int		   rc = 0, rc2 = 0;
	ENTRY;

	LASSERT(end == OBD_OBJECT_EOF);
	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(inode != NULL);
	ll_vfs_dq_init(inode);

	LASSERT(th);
	oh = container_of(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle->h_transaction != NULL);

	osd_trans_exec_op(env, th, OSD_OT_PUNCH);

	tid = oh->ot_handle->h_transaction->t_tid;

	spin_lock(&inode->i_lock);
	i_size_write(inode, start);
	spin_unlock(&inode->i_lock);
	ll_truncate_pagecache(inode, start);
#ifdef HAVE_INODEOPS_TRUNCATE
	if (inode->i_op->truncate) {
		inode->i_op->truncate(inode);
	} else
#endif
		ldiskfs_truncate(inode);

	/*
	 * For a partial-page truncate, flush the page to disk immediately to
	 * avoid data corruption during direct disk write.  b=17397
	 */
	if ((start & ~PAGE_MASK) != 0)
                rc = filemap_fdatawrite_range(inode->i_mapping, start, start+1);

        h = journal_current_handle();
        LASSERT(h != NULL);
        LASSERT(h == oh->ot_handle);

	/* do not check credits with osd_trans_exec_check() as the truncate
	 * can restart the transaction internally and we restart the
	 * transaction in this case */

        if (tid != h->h_transaction->t_tid) {
                int credits = oh->ot_credits;
                /*
                 * transaction has changed during truncate
                 * we need to restart the handle with our credits
                 */
                if (h->h_buffer_credits < credits) {
                        if (ldiskfs_journal_extend(h, credits))
                                rc2 = ldiskfs_journal_restart(h, credits);
                }
        }

        RETURN(rc == 0 ? rc2 : rc);
}

static int fiemap_check_ranges(struct inode *inode,
			       u64 start, u64 len, u64 *new_len)
{
	loff_t maxbytes;

	*new_len = len;

	if (len == 0)
		return -EINVAL;

	if (ldiskfs_test_inode_flag(inode, LDISKFS_INODE_EXTENTS))
		maxbytes = inode->i_sb->s_maxbytes;
	else
		maxbytes = LDISKFS_SB(inode->i_sb)->s_bitmap_maxbytes;

	if (start > maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (len > maxbytes || (maxbytes - len) < start)
		*new_len = maxbytes - start;

	return 0;
}

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS     (UINT_MAX / sizeof(struct fiemap_extent))

static int osd_fiemap_get(const struct lu_env *env, struct dt_object *dt,
			  struct fiemap *fm)
{
	struct fiemap_extent_info fieinfo = {0, };
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	u64 len;
	int rc;


	LASSERT(inode);
	if (inode->i_op->fiemap == NULL)
		return -EOPNOTSUPP;

	if (fm->fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	rc = fiemap_check_ranges(inode, fm->fm_start, fm->fm_length, &len);
	if (rc)
		return rc;

	fieinfo.fi_flags = fm->fm_flags;
	fieinfo.fi_extents_max = fm->fm_extent_count;
	fieinfo.fi_extents_start = fm->fm_extents;

	if (fieinfo.fi_flags & FIEMAP_FLAG_SYNC)
		filemap_write_and_wait(inode->i_mapping);

	rc = inode->i_op->fiemap(inode, &fieinfo, fm->fm_start, len);
	fm->fm_flags = fieinfo.fi_flags;
	fm->fm_mapped_extents = fieinfo.fi_extents_mapped;

	return rc;
}

static int osd_ladvise(const struct lu_env *env, struct dt_object *dt,
		       __u64 start, __u64 end, enum lu_ladvise_type advice)
{
	int		 rc = 0;
	struct inode	*inode = osd_dt_obj(dt)->oo_inode;
	ENTRY;

	switch (advice) {
	case LU_LADVISE_DONTNEED:
		if (end == 0)
			break;
		invalidate_mapping_pages(inode->i_mapping,
					 start >> PAGE_CACHE_SHIFT,
					 (end - 1) >> PAGE_CACHE_SHIFT);
		break;
	default:
		rc = -ENOTSUPP;
		break;
	}

	RETURN(rc);
}

/*
 * in some cases we may need declare methods for objects being created
 * e.g., when we create symlink
 */
const struct dt_body_operations osd_body_ops_new = {
        .dbo_declare_write = osd_declare_write,
};

const struct dt_body_operations osd_body_ops = {
	.dbo_read			= osd_read,
	.dbo_declare_write		= osd_declare_write,
	.dbo_write			= osd_write,
	.dbo_bufs_get			= osd_bufs_get,
	.dbo_bufs_put			= osd_bufs_put,
	.dbo_write_prep			= osd_write_prep,
	.dbo_declare_write_commit	= osd_declare_write_commit,
	.dbo_write_commit		= osd_write_commit,
	.dbo_read_prep			= osd_read_prep,
	.dbo_declare_punch		= osd_declare_punch,
	.dbo_punch			= osd_punch,
	.dbo_fiemap_get			= osd_fiemap_get,
	.dbo_ladvise			= osd_ladvise,
};
