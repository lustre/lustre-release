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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osd/osd_io.c
 *
 * body operations
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 *
 */

#define DEBUG_SUBSYSTEM	S_OSD

/* prerequisite for linux/xattr.h */
#include <linux/types.h>
/* prerequisite for linux/xattr.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagevec.h>

/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd_support.h>

#include "osd_internal.h"

/* ext_depth() */
#include <ldiskfs/ldiskfs_extents.h>
#include <ldiskfs/ldiskfs.h>

static inline bool osd_use_page_cache(struct osd_device *d)
{
	/* do not use pagecache if write and read caching are disabled */
	if (d->od_writethrough_cache + d->od_read_cache == 0)
		return false;
	/* use pagecache by default */
	return true;
}

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
	iobuf->dr_elapsed = ktime_set(0, 0);
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
	       (unsigned int)(pages * sizeof(iobuf->dr_pages[0])), i, pages);
	pages = i;
	blocks = pages * (PAGE_SIZE >> osd_sb(d)->s_blocksize_bits);
	iobuf->dr_max_pages = 0;
	CDEBUG(D_OTHER, "realloc %u for %u blocks\n",
	       (unsigned int)(blocks * sizeof(iobuf->dr_blocks[0])), blocks);

	lu_buf_realloc(&iobuf->dr_bl_buf, blocks * sizeof(iobuf->dr_blocks[0]));
	iobuf->dr_blocks = iobuf->dr_bl_buf.lb_buf;
	if (unlikely(iobuf->dr_blocks == NULL))
		return -ENOMEM;

	lu_buf_realloc(&iobuf->dr_pg_buf, pages * sizeof(iobuf->dr_pages[0]));
	iobuf->dr_pages = iobuf->dr_pg_buf.lb_buf;
	if (unlikely(iobuf->dr_pages == NULL))
		return -ENOMEM;

	lu_buf_realloc(&iobuf->dr_lnb_buf,
		       pages * sizeof(iobuf->dr_lnbs[0]));
	iobuf->dr_lnbs = iobuf->dr_lnb_buf.lb_buf;
	if (unlikely(iobuf->dr_lnbs == NULL))
		return -ENOMEM;

	iobuf->dr_max_pages = pages;

	return 0;
}
#define osd_init_iobuf(dev, iobuf, rw, pages) \
	__osd_init_iobuf(dev, iobuf, rw, __LINE__, pages)

static void osd_iobuf_add_page(struct osd_iobuf *iobuf,
			       struct niobuf_local *lnb)
{
	LASSERT(iobuf->dr_npages < iobuf->dr_max_pages);
	iobuf->dr_pages[iobuf->dr_npages] = lnb->lnb_page;
	iobuf->dr_lnbs[iobuf->dr_npages] = lnb;
	iobuf->dr_npages++;
}

void osd_fini_iobuf(struct osd_device *d, struct osd_iobuf *iobuf)
{
	int rw = iobuf->dr_rw;

	if (iobuf->dr_elapsed_valid) {
		struct brw_stats *h = &d->od_brw_stats;

		iobuf->dr_elapsed_valid = 0;
		LASSERT(iobuf->dr_dev == d);
		LASSERT(iobuf->dr_frags > 0);
		lprocfs_oh_tally_pcpu(&h->bs_hist[BRW_R_DIO_FRAGS+rw],
				      iobuf->dr_frags);
		lprocfs_oh_tally_log2_pcpu(&h->bs_hist[BRW_R_IO_TIME+rw],
					   ktime_to_ms(iobuf->dr_elapsed));
	}
}

#ifdef HAVE_BIO_ENDIO_USES_ONE_ARG
static void dio_complete_routine(struct bio *bio)
{
	int error = blk_status_to_errno(bio->bi_status);
#else
static void dio_complete_routine(struct bio *bio, int error)
{
#endif
	struct osd_iobuf *iobuf = bio->bi_private;
	struct bio_vec *bvl;

	/* CAVEAT EMPTOR: possibly in IRQ context
	 * DO NOT record procfs stats here!!!
	 */

	if (unlikely(iobuf == NULL)) {
		CERROR("***** bio->bi_private is NULL! Dump the bio contents to the console. Please report this to <https://jira.whamcloud.com/>, and probably have to reboot this node.\n");
		CERROR("bi_next: %p, bi_flags: %lx, " __stringify(bi_opf)
		       ": %x, bi_vcnt: %d, bi_idx: %d, bi->size: %d, bi_end_io: %p, bi_cnt: %d, bi_private: %p\n",
		       bio->bi_next, (unsigned long)bio->bi_flags,
		       (unsigned int)bio->bi_opf, bio->bi_vcnt, bio_idx(bio),
		       bio_sectors(bio) << 9, bio->bi_end_io,
		       atomic_read(&bio->__bi_cnt),
		       bio->bi_private);
		return;
	}

	/* the check is outside of the cycle for performance reason -bzzz */
	if (!bio_data_dir(bio)) {
		DECLARE_BVEC_ITER_ALL(iter_all);

		bio_for_each_segment_all(bvl, bio, iter_all) {
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
		ktime_t now = ktime_get();

		iobuf->dr_elapsed = ktime_sub(now, iobuf->dr_start_time);
		iobuf->dr_elapsed_valid = 1;
	}
	if (atomic_dec_and_test(&iobuf->dr_numreqs))
		wake_up(&iobuf->dr_wait);

	/* Completed bios used to be chained off iobuf->dr_bios and freed in
	 * filter_clear_dreq().  It was then possible to exhaust the biovec-256
	 * mempool when serious on-disk fragmentation was encountered,
	 * deadlocking the OST.  The bios are now released as soon as complete
	 * so the pool cannot be exhausted while IOs are competing. b=10076
	 */
	bio_put(bio);
}

static void record_start_io(struct osd_iobuf *iobuf, int size)
{
	struct osd_device *osd = iobuf->dr_dev;
	struct brw_stats *h = &osd->od_brw_stats;

	iobuf->dr_frags++;
	atomic_inc(&iobuf->dr_numreqs);

	if (iobuf->dr_rw == 0) {
		atomic_inc(&osd->od_r_in_flight);
		lprocfs_oh_tally_pcpu(&h->bs_hist[BRW_R_RPC_HIST],
				 atomic_read(&osd->od_r_in_flight));
		lprocfs_oh_tally_log2_pcpu(&h->bs_hist[BRW_R_DISK_IOSIZE],
					   size);
	} else if (iobuf->dr_rw == 1) {
		atomic_inc(&osd->od_w_in_flight);
		lprocfs_oh_tally_pcpu(&h->bs_hist[BRW_W_RPC_HIST],
				 atomic_read(&osd->od_w_in_flight));
		lprocfs_oh_tally_log2_pcpu(&h->bs_hist[BRW_W_DISK_IOSIZE],
					   size);
	} else {
		LBUG();
	}
}

static void osd_submit_bio(int rw, struct bio *bio)
{
	LASSERTF(rw == 0 || rw == 1, "%x\n", rw);
#ifdef HAVE_SUBMIT_BIO_2ARGS
	submit_bio(rw ? WRITE : READ, bio);
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

#if IS_ENABLED(CONFIG_BLK_DEV_INTEGRITY)
/*
 * This function will change the data written, thus it should only be
 * used when checking data integrity feature
 */
static void bio_integrity_fault_inject(struct bio *bio)
{
	struct bio_vec *bvec;
	DECLARE_BVEC_ITER_ALL(iter_all);
	void *kaddr;
	char *addr;

	bio_for_each_segment_all(bvec, bio, iter_all) {
		struct page *page = bvec->bv_page;

		kaddr = kmap(page);
		addr = kaddr;
		*addr = ~(*addr);
		kunmap(page);
		break;
	}
}

static int bio_dif_compare(__u16 *expected_guard_buf, void *bio_prot_buf,
			   unsigned int sectors, int tuple_size)
{
	__u16 *expected_guard;
	__u16 *bio_guard;
	int i;

	expected_guard = expected_guard_buf;
	for (i = 0; i < sectors; i++) {
		bio_guard = (__u16 *)bio_prot_buf;
		if (*bio_guard != *expected_guard) {
			CERROR(
			       "unexpected guard tags on sector %d expected guard %u, bio guard %u, sectors %u, tuple size %d\n",
			       i, *expected_guard, *bio_guard, sectors,
			       tuple_size);
			return -EIO;
		}
		expected_guard++;
		bio_prot_buf += tuple_size;
	}
	return 0;
}

static int osd_bio_integrity_compare(struct bio *bio, struct block_device *bdev,
				     struct osd_iobuf *iobuf, int index)
{
	struct blk_integrity *bi = bdev_get_integrity(bdev);
	struct bio_integrity_payload *bip = bio->bi_integrity;
	struct niobuf_local *lnb = NULL;
	unsigned short sector_size = blk_integrity_interval(bi);
	void *bio_prot_buf = page_address(bip->bip_vec->bv_page) +
		bip->bip_vec->bv_offset;
	struct bio_vec *bv;
	sector_t sector = bio_start_sector(bio);
	unsigned int i, sectors, total;
	DECLARE_BVEC_ITER_ALL(iter_all);
	__u16 *expected_guard;
	int rc;

	total = 0;
	bio_for_each_segment_all(bv, bio, iter_all) {
		for (i = index; i < iobuf->dr_npages; i++) {
			if (iobuf->dr_pages[i] == bv->bv_page) {
				lnb = iobuf->dr_lnbs[i];
				break;
			}
		}
		if (!lnb)
			continue;
		expected_guard = lnb->lnb_guards;
		sectors = bv->bv_len / sector_size;
		if (lnb->lnb_guard_rpc) {
			rc = bio_dif_compare(expected_guard, bio_prot_buf,
					     sectors, bi->tuple_size);
			if (rc)
				return rc;
		}

		sector += sectors;
		bio_prot_buf += sectors * bi->tuple_size;
		total += sectors * bi->tuple_size;
		LASSERT(total <= bip_size(bio->bi_integrity));
		index++;
		lnb = NULL;
	}
	return 0;
}

static int osd_bio_integrity_handle(struct osd_device *osd, struct bio *bio,
				    struct osd_iobuf *iobuf,
				    int start_page_idx, bool fault_inject,
				    bool integrity_enabled)
{
	struct super_block *sb = osd_sb(osd);
	integrity_gen_fn *generate_fn = NULL;
	integrity_vrfy_fn *verify_fn = NULL;
	int rc;

	ENTRY;

	if (!integrity_enabled)
		RETURN(0);

	rc = osd_get_integrity_profile(osd, &generate_fn, &verify_fn);
	if (rc)
		RETURN(rc);

	rc = bio_integrity_prep_fn(bio, generate_fn, verify_fn);
	if (rc)
		RETURN(rc);

	/* Verify and inject fault only when writing */
	if (iobuf->dr_rw == 1) {
		if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_OST_INTEGRITY_CMP))) {
			rc = osd_bio_integrity_compare(bio, sb->s_bdev, iobuf,
						       start_page_idx);
			if (rc)
				RETURN(rc);
		}

		if (unlikely(fault_inject))
			bio_integrity_fault_inject(bio);
	}

	RETURN(0);
}

#ifdef HAVE_BIO_INTEGRITY_PREP_FN
#  ifdef HAVE_BIO_ENDIO_USES_ONE_ARG
static void dio_integrity_complete_routine(struct bio *bio)
#  else
static void dio_integrity_complete_routine(struct bio *bio, int error)
#  endif
{
	struct osd_bio_private *bio_private = bio->bi_private;

	bio->bi_private = bio_private->obp_iobuf;
	osd_dio_complete_routine(bio, error);

	OBD_FREE_PTR(bio_private);
}
#endif /* HAVE_BIO_INTEGRITY_PREP_FN */
#else  /* !CONFIG_BLK_DEV_INTEGRITY */
#define osd_bio_integrity_handle(osd, bio, iobuf, start_page_idx, \
				 fault_inject, integrity_enabled) 0
#endif /* CONFIG_BLK_DEV_INTEGRITY */

static int osd_bio_init(struct bio *bio, struct osd_iobuf *iobuf,
			bool integrity_enabled, int start_page_idx,
			struct osd_bio_private **pprivate)
{
	ENTRY;

	*pprivate = NULL;

#ifdef HAVE_BIO_INTEGRITY_PREP_FN
	if (integrity_enabled) {
		struct osd_bio_private *bio_private = NULL;

		OBD_ALLOC_GFP(bio_private, sizeof(*bio_private), GFP_NOIO);
		if (bio_private == NULL)
			RETURN(-ENOMEM);
		bio->bi_end_io = dio_integrity_complete_routine;
		bio->bi_private = bio_private;
		bio_private->obp_start_page_idx = start_page_idx;
		bio_private->obp_iobuf = iobuf;
		*pprivate = bio_private;
	} else
#endif
	{
		bio->bi_end_io = dio_complete_routine;
		bio->bi_private = iobuf;
	}

	RETURN(0);
}

static void osd_mark_page_io_done(struct osd_iobuf *iobuf,
				  struct inode *inode,
				  sector_t start_blocks,
				  sector_t count)
{
	struct niobuf_local *lnb;
	int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	pgoff_t pg_start, pg_end;

	pg_start = start_blocks / blocks_per_page;
	if (start_blocks % blocks_per_page)
		pg_start++;
	if (count >= blocks_per_page)
		pg_end = (start_blocks + count -
			  blocks_per_page) / blocks_per_page;
	else
		return; /* nothing to mark */
	for ( ; pg_start <= pg_end; pg_start++) {
		lnb = iobuf->dr_lnbs[pg_start];
		lnb->lnb_flags |= OBD_BRW_DONE;
	}
}

static int osd_do_bio(struct osd_device *osd, struct inode *inode,
		      struct osd_iobuf *iobuf, sector_t start_blocks,
		      sector_t count)
{
	int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	struct page **pages = iobuf->dr_pages;
	int npages = iobuf->dr_npages;
	sector_t *blocks = iobuf->dr_blocks;
	struct super_block *sb = inode->i_sb;
	int sector_bits = sb->s_blocksize_bits - 9;
	unsigned int blocksize = sb->s_blocksize;
	struct block_device *bdev = sb->s_bdev;
	struct osd_bio_private *bio_private = NULL;
	struct bio *bio = NULL;
	int bio_start_page_idx;
	struct page *page;
	unsigned int page_offset;
	sector_t sector;
	int nblocks;
	int block_idx, block_idx_end;
	int page_idx, page_idx_start;
	int i;
	int rc = 0;
	bool fault_inject;
	bool integrity_enabled;
	struct blk_plug plug;
	int blocks_left_page;

	ENTRY;

	fault_inject = OBD_FAIL_CHECK(OBD_FAIL_OST_INTEGRITY_FAULT);
	LASSERT(iobuf->dr_npages == npages);

	integrity_enabled = bdev_integrity_enabled(bdev, iobuf->dr_rw);

	osd_brw_stats_update(osd, iobuf);
	iobuf->dr_start_time = ktime_get();

	if (!count)
		count = npages * blocks_per_page;
	block_idx_end = start_blocks + count;

	blk_start_plug(&plug);

	page_idx_start = start_blocks / blocks_per_page;
	for (page_idx = page_idx_start, block_idx = start_blocks;
	     block_idx < block_idx_end; page_idx++,
	     block_idx += blocks_left_page) {
		/* For cases where the filesystems blocksize is not the
		 * same as PAGE_SIZE (e.g. ARM with PAGE_SIZE=64KB and
		 * blocksize=4KB), there will be multiple blocks to
		 * read/write per page. Also, the start and end block may
		 * not be aligned to the start and end of the page, so the
		 * first page may skip some blocks at the start ("i != 0",
		 * "blocks_left_page" is reduced), and the last page may
		 * skip some blocks at the end (limited by "count").
		 */
		page = pages[page_idx];
		LASSERT(page_idx < iobuf->dr_npages);

		i = block_idx % blocks_per_page;
		blocks_left_page = blocks_per_page - i;
		if (block_idx + blocks_left_page > block_idx_end)
			blocks_left_page = block_idx_end - block_idx;
		page_offset = i * blocksize;
		for (i = 0; i < blocks_left_page;
		     i += nblocks, page_offset += blocksize * nblocks) {
			nblocks = 1;

			if (blocks[block_idx + i] == 0) {  /* hole */
				LASSERTF(iobuf->dr_rw == 0,
					 "page_idx %u, block_idx %u, i %u,"
					 "start_blocks: %llu, count: %llu, npages: %d\n",
					 page_idx, block_idx, i,
					 (unsigned long long)start_blocks,
					 (unsigned long long)count, npages);
				memset(kmap(page) + page_offset, 0, blocksize);
				kunmap(page);
				continue;
			}

			sector = (sector_t)blocks[block_idx + i] << sector_bits;

			/* Additional contiguous file blocks? */
			while (i + nblocks < blocks_left_page &&
			       (sector + (nblocks << sector_bits)) ==
			       ((sector_t)blocks[block_idx + i + nblocks] <<
				 sector_bits))
				nblocks++;

			if (bio && can_be_merged(bio, sector) &&
			    bio_add_page(bio, page, blocksize * nblocks,
					 page_offset) != 0)
				continue;       /* added this frag OK */

			if (bio != NULL) {
				struct request_queue *q = bio_get_queue(bio);
				unsigned int bi_size = bio_sectors(bio) << 9;

				/* Dang! I have to fragment this I/O */
				CDEBUG(D_INODE,
				       "bio++ sz %d vcnt %d(%d) sectors %d(%d) psg %d(%d)\n",
				       bi_size, bio->bi_vcnt, bio->bi_max_vecs,
				       bio_sectors(bio),
				       queue_max_sectors(q),
				       osd_bio_nr_segs(bio),
				       queue_max_segments(q));
				rc = osd_bio_integrity_handle(osd, bio,
					iobuf, bio_start_page_idx,
					fault_inject, integrity_enabled);
				if (rc) {
					bio_put(bio);
					goto out;
				}

				record_start_io(iobuf, bi_size);
				osd_submit_bio(iobuf->dr_rw, bio);
			}

			bio_start_page_idx = page_idx;
			/* allocate new bio */
			bio = bio_alloc(GFP_NOIO, min(BIO_MAX_PAGES,
					(block_idx_end - block_idx +
					 blocks_left_page - 1)));
			if (bio == NULL) {
				CERROR("Can't allocate bio %u pages\n",
				       block_idx_end - block_idx +
				       blocks_left_page - 1);
				rc = -ENOMEM;
				goto out;
			}

			bio_set_dev(bio, bdev);
			bio_set_sector(bio, sector);
			bio->bi_opf = iobuf->dr_rw ? WRITE : READ;
			rc = osd_bio_init(bio, iobuf, integrity_enabled,
					  bio_start_page_idx, &bio_private);
			if (rc) {
				bio_put(bio);
				goto out;
			}

			rc = bio_add_page(bio, page,
					  blocksize * nblocks, page_offset);
			LASSERT(rc != 0);
		}
	}

	if (bio != NULL) {
		rc = osd_bio_integrity_handle(osd, bio, iobuf,
					      bio_start_page_idx,
					      fault_inject,
					      integrity_enabled);
		if (rc) {
			bio_put(bio);
			goto out;
		}

		record_start_io(iobuf, bio_sectors(bio) << 9);
		osd_submit_bio(iobuf->dr_rw, bio);
		rc = 0;
	}

out:
	blk_finish_plug(&plug);

	/* in order to achieve better IO throughput, we don't wait for writes
	 * completion here. instead we proceed with transaction commit in
	 * parallel and wait for IO completion once transaction is stopped
	 * see osd_trans_stop() for more details -bzzz
	 */
	if (iobuf->dr_rw == 0 || fault_inject) {
		wait_event(iobuf->dr_wait,
			   atomic_read(&iobuf->dr_numreqs) == 0);
		osd_fini_iobuf(osd, iobuf);
	}

	if (rc == 0) {
		rc = iobuf->dr_error;
	} else {
		if (bio_private)
			OBD_FREE_PTR(bio_private);
	}

	/* Write only now */
	if (rc == 0 && iobuf->dr_rw)
		osd_mark_page_io_done(iobuf, inode,
				      start_blocks, count);

	RETURN(rc);
}

static int osd_map_remote_to_local(loff_t offset, ssize_t len, int *nrpages,
				   struct niobuf_local *lnb, int maxlnb)
{
	int rc = 0;
	ENTRY;

	*nrpages = 0;

	while (len > 0) {
		int poff = offset & (PAGE_SIZE - 1);
		int plen = PAGE_SIZE - poff;

		if (*nrpages >= maxlnb) {
			rc = -EOVERFLOW;
			break;
		}

		if (plen > len)
			plen = len;
		lnb->lnb_file_offset = offset;
		lnb->lnb_page_offset = poff;
		lnb->lnb_len = plen;
		/* lnb->lnb_flags = rnb->rnb_flags; */
		lnb->lnb_flags = 0;
		lnb->lnb_page = NULL;
		lnb->lnb_rc = 0;
		lnb->lnb_guard_rpc = 0;
		lnb->lnb_guard_disk = 0;
		lnb->lnb_locked = 0;

		LASSERTF(plen <= len, "plen %u, len %lld\n", plen,
			 (long long) len);
		offset += plen;
		len -= plen;
		lnb++;
		(*nrpages)++;
	}

	RETURN(rc);
}

static struct page *osd_get_page(const struct lu_env *env, struct dt_object *dt,
				 loff_t offset, gfp_t gfp_mask, bool cache)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	struct osd_device *d = osd_obj2dev(osd_dt_obj(dt));
	struct page *page;
	int cur;

	LASSERT(inode);

	if (cache) {
		page = find_or_create_page(inode->i_mapping,
					   offset >> PAGE_SHIFT, gfp_mask);

		if (likely(page)) {
			LASSERT(!PagePrivate2(page));
			wait_on_page_writeback(page);
		} else {
			lprocfs_counter_add(d->od_stats, LPROC_OSD_NO_PAGE, 1);
		}

		return page;
	}

	if (inode->i_mapping->nrpages) {
		/* consult with pagecache, but do not create new pages */
		/* this is normally used once */
		page = find_lock_page(inode->i_mapping, offset >> PAGE_SHIFT);
		if (page) {
			wait_on_page_writeback(page);
			return page;
		}
	}

	LASSERT(oti->oti_dio_pages);
	cur = oti->oti_dio_pages_used;
	page = oti->oti_dio_pages[cur];

	if (unlikely(!page)) {
		LASSERT(cur < PTLRPC_MAX_BRW_PAGES);
		page = alloc_page(gfp_mask);
		if (!page)
			return NULL;
		oti->oti_dio_pages[cur] = page;
		SetPagePrivate2(page);
		lock_page(page);
	}

	ClearPageUptodate(page);
	page->index = offset >> PAGE_SHIFT;
	oti->oti_dio_pages_used++;

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
	struct osd_thread_info *oti = osd_oti_get(env);
	struct pagevec pvec;
	int i;

	ll_pagevec_init(&pvec, 0);

	for (i = 0; i < npages; i++) {
		struct page *page = lnb[i].lnb_page;

		if (page == NULL)
			continue;

		/* if the page isn't cached, then reset uptodate
		 * to prevent reuse
		 */
		if (PagePrivate2(page)) {
			oti->oti_dio_pages_used--;
		} else {
			if (lnb[i].lnb_locked)
				unlock_page(page);
			if (pagevec_add(&pvec, page) == 0)
				pagevec_release(&pvec);
		}

		lnb[i].lnb_page = NULL;
	}

	LASSERTF(oti->oti_dio_pages_used == 0, "%d\n", oti->oti_dio_pages_used);

	/* Release any partial pagevec */
	pagevec_release(&pvec);

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
			int maxlnb, enum dt_bufs_type rw)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd   = osd_obj2dev(obj);
	int npages, i, iosize, rc = 0;
	bool cache, write;
	loff_t fsize;
	gfp_t gfp_mask;

	LASSERT(obj->oo_inode);

	rc = osd_map_remote_to_local(pos, len, &npages, lnb, maxlnb);
	if (rc)
		RETURN(rc);

	write = rw & DT_BUFS_TYPE_WRITE;

	fsize = lnb[npages - 1].lnb_file_offset + lnb[npages - 1].lnb_len;
	iosize = fsize - lnb[0].lnb_file_offset;
	fsize = max(fsize, i_size_read(obj->oo_inode));

	cache = rw & DT_BUFS_TYPE_READAHEAD;
	if (cache)
		goto bypass_checks;

	cache = osd_use_page_cache(osd);
	while (cache) {
		if (write) {
			if (!osd->od_writethrough_cache) {
				cache = false;
				break;
			}
			if (iosize > osd->od_writethrough_max_iosize) {
				cache = false;
				break;
			}
		} else {
			if (!osd->od_read_cache) {
				cache = false;
				break;
			}
			if (iosize > osd->od_readcache_max_iosize) {
				cache = false;
				break;
			}
		}
		/* don't use cache on large files */
		if (osd->od_readcache_max_filesize &&
		    fsize > osd->od_readcache_max_filesize)
			cache = false;
		break;
	}

bypass_checks:
	if (!cache && unlikely(!oti->oti_dio_pages)) {
		OBD_ALLOC_PTR_ARRAY_LARGE(oti->oti_dio_pages,
					  PTLRPC_MAX_BRW_PAGES);
		if (!oti->oti_dio_pages)
			return -ENOMEM;
	}

	/* this could also try less hard for DT_BUFS_TYPE_READAHEAD pages */
	gfp_mask = rw & DT_BUFS_TYPE_LOCAL ? (GFP_NOFS | __GFP_HIGHMEM) :
					     GFP_HIGHUSER;
	for (i = 0; i < npages; i++, lnb++) {
		lnb->lnb_page = osd_get_page(env, dt, lnb->lnb_file_offset,
					     gfp_mask, cache);
		if (lnb->lnb_page == NULL)
			GOTO(cleanup, rc = -ENOMEM);

		lnb->lnb_locked = 1;
		if (cache)
			mark_page_accessed(lnb->lnb_page);
	}

#if 0
	/* XXX: this version doesn't invalidate cached pages, but use them */
	if (!cache && write && obj->oo_inode->i_mapping->nrpages) {
		/* do not allow data aliasing, invalidate pagecache */
		/* XXX: can be quite expensive in mixed case */
		invalidate_mapping_pages(obj->oo_inode->i_mapping,
				lnb[0].lnb_file_offset >> PAGE_SHIFT,
				lnb[npages - 1].lnb_file_offset >> PAGE_SHIFT);
	}
#endif

	RETURN(i);

cleanup:
	if (i > 0)
		osd_bufs_put(env, dt, lnb - i, i);
	return rc;
}
/* Borrow @ext4_chunk_trans_blocks */
static int osd_chunk_trans_blocks(struct inode *inode, int nrblocks)
{
	ldiskfs_group_t groups;
	int gdpblocks;
	int idxblocks;
	int depth;
	int ret;

	depth = ext_depth(inode);
	idxblocks = depth * 2;

	/*
	 * Now let's see how many group bitmaps and group descriptors need
	 * to account.
	 */
	groups = idxblocks + 1;
	gdpblocks = groups;
	if (groups > LDISKFS_SB(inode->i_sb)->s_groups_count)
		groups = LDISKFS_SB(inode->i_sb)->s_groups_count;
	if (gdpblocks > LDISKFS_SB(inode->i_sb)->s_gdb_count)
		gdpblocks = LDISKFS_SB(inode->i_sb)->s_gdb_count;

	/* bitmaps and block group descriptor blocks */
	ret = idxblocks + groups + gdpblocks;

	/* Blocks for super block, inode, quota and xattr blocks */
	ret += LDISKFS_META_TRANS_BLOCKS(inode->i_sb);

	return ret;
}

#ifdef HAVE_LDISKFS_JOURNAL_ENSURE_CREDITS
static int osd_extend_restart_trans(handle_t *handle, int needed,
				    struct inode *inode)
{
	int rc;

	rc = ldiskfs_journal_ensure_credits(handle, needed,
		ldiskfs_trans_default_revoke_credits(inode->i_sb));
	/* this means journal has been restarted */
	if (rc > 0)
		rc = 0;

	return rc;
}
#else
static int osd_extend_restart_trans(handle_t *handle, int needed,
				    struct inode *inode)
{
	int rc;

	if (ldiskfs_handle_has_enough_credits(handle, needed))
		return 0;
	rc = ldiskfs_journal_extend(handle,
				needed - handle->h_buffer_credits);
	if (rc <= 0)
		return rc;

	return ldiskfs_journal_restart(handle, needed);
}
#endif /* HAVE_LDISKFS_JOURNAL_ENSURE_CREDITS */

static int osd_ldiskfs_map_write(struct inode *inode, struct osd_iobuf *iobuf,
				 struct osd_device *osd, sector_t start_blocks,
				 sector_t count, loff_t *disk_size,
				 __u64 user_size)
{
	/* if file has grown, take user_size into account */
	if (user_size && *disk_size > user_size)
		*disk_size = user_size;

	spin_lock(&inode->i_lock);
	if (*disk_size > i_size_read(inode)) {
		i_size_write(inode, *disk_size);
		LDISKFS_I(inode)->i_disksize = *disk_size;
		spin_unlock(&inode->i_lock);
		osd_dirty_inode(inode, I_DIRTY_DATASYNC);
	} else {
		spin_unlock(&inode->i_lock);
	}

	/*
	 * We don't do stats here as in read path because
	 * write is async: we'll do this in osd_put_bufs()
	 */
	return osd_do_bio(osd, inode, iobuf, start_blocks, count);
}

static unsigned int osd_extent_bytes(const struct osd_device *o)
{
	unsigned int *extent_bytes_ptr =
			raw_cpu_ptr(o->od_extent_bytes_percpu);

	if (likely(*extent_bytes_ptr))
		return *extent_bytes_ptr;

	/* initialize on first access or CPU hotplug */
	if (!ldiskfs_has_feature_extents(osd_sb(o)))
		*extent_bytes_ptr = 1 << osd_sb(o)->s_blocksize_bits;
	else
		*extent_bytes_ptr = OSD_DEFAULT_EXTENT_BYTES;

	return *extent_bytes_ptr;
}

#define EXTENT_BYTES_DECAY 64
static void osd_decay_extent_bytes(struct osd_device *osd,
				   unsigned int new_bytes)
{
	unsigned int old_bytes;

	if (!ldiskfs_has_feature_extents(osd_sb(osd)))
		return;

	old_bytes = osd_extent_bytes(osd);
	*raw_cpu_ptr(osd->od_extent_bytes_percpu) =
		(old_bytes * (EXTENT_BYTES_DECAY - 1) +
		 min(new_bytes, OSD_DEFAULT_EXTENT_BYTES) +
		 EXTENT_BYTES_DECAY - 1) / EXTENT_BYTES_DECAY;
}

static int osd_ldiskfs_map_inode_pages(struct inode *inode,
				       struct osd_iobuf *iobuf,
				       struct osd_device *osd,
				       int create, __u64 user_size,
				       int check_credits,
				       struct thandle *thandle)
{
	int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	int rc = 0, i = 0, mapped_index = 0;
	struct page *fp = NULL;
	int clen = 0;
	pgoff_t max_page_index;
	handle_t *handle = NULL;
	sector_t start_blocks = 0, count = 0;
	loff_t disk_size = 0;
	struct page **page = iobuf->dr_pages;
	int pages = iobuf->dr_npages;
	sector_t *blocks = iobuf->dr_blocks;
	struct niobuf_local *lnb1, *lnb2;
	loff_t size1, size2;

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
		disk_size = i_size_read(inode);
		/* if disk_size is already bigger than specified user_size,
		 * ignore user_size
		 */
		if (disk_size > user_size)
			user_size = 0;
	}
	/* pages are sorted already. so, we just have to find
	 * contig. space and process them properly
	 */
	while (i < pages) {
		long blen, total = 0, previous_total = 0;
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
		/**
		 * We might restart transaction for block allocations,
		 * in order to make sure data ordered mode, issue IO, disk
		 * size update and block allocations need be within same
		 * transaction to make sure consistency.
		 */
		if (handle && check_credits) {
			struct osd_thandle *oh;

			LASSERT(thandle != NULL);
			oh = container_of(thandle, struct osd_thandle,
					  ot_super);
			/*
			 * only issue IO if restart transaction needed,
			 * as update disk size need hold inode lock, we
			 * want to avoid that as much as possible.
			 */
			if (oh->oh_declared_ext <= 0) {
				rc = osd_ldiskfs_map_write(inode,
					iobuf, osd, start_blocks,
					count, &disk_size, user_size);
				if (rc)
					GOTO(cleanup, rc);
				thandle->th_restart_tran = 1;
				GOTO(cleanup, rc = -EAGAIN);
			}

			if (OBD_FAIL_CHECK(OBD_FAIL_OST_RESTART_IO))
				oh->oh_declared_ext = 0;
			else
				oh->oh_declared_ext--;
		}
		rc = ldiskfs_map_blocks(handle, inode, &map, create);
		if (rc >= 0) {
			int c = 0;

			for (; total < blen && c < map.m_len; c++, total++) {
				if (rc == 0) {
					*(blocks + total) = 0;
					total++;
					break;
				}
				if ((map.m_flags & LDISKFS_MAP_UNWRITTEN) &&
				    !create) {
					/* don't try to read allocated, but
					 * unwritten blocks, instead fill the
					 * patches with zeros in osd_do_bio() */
					*(blocks + total) = 0;
					continue;
				}
				*(blocks + total) = map.m_pblk + c;
				/* unmap any possible underlying
				 * metadata from the block device
				 * mapping.  b=6998.
				 */
				if ((map.m_flags & LDISKFS_MAP_NEW) &&
				    create)
					clean_bdev_aliases(inode->i_sb->s_bdev,
							   map.m_pblk + c, 1);
			}
			rc = 0;
		}

		if (rc == 0 && create) {
			count += (total - previous_total);
			mapped_index = (count + blocks_per_page -
					1) / blocks_per_page - 1;
			lnb1 = iobuf->dr_lnbs[i - clen];
			lnb2 = iobuf->dr_lnbs[mapped_index];
			size1 = lnb1->lnb_file_offset -
				(lnb1->lnb_file_offset % PAGE_SIZE) +
				(total << inode->i_blkbits);
			size2 = lnb2->lnb_file_offset + lnb2->lnb_len;

			if (size1 > size2)
				size1 = size2;
			if (size1 > disk_size)
				disk_size = size1;
		}

		if (rc == 0 && total < blen) {
			/*
			 * decay extent blocks if we could not
			 * allocate extent once.
			 */
			osd_decay_extent_bytes(osd,
				(total - previous_total) << inode->i_blkbits);
			map.m_lblk = fp->index * blocks_per_page + total;
			map.m_len = blen - total;
			previous_total = total;
			goto cont_map;
		}
		if (rc != 0)
			GOTO(cleanup, rc);
		/*
		 * decay extent blocks if we could allocate
		 * good large extent.
		 */
		if (total - previous_total >=
		    osd_extent_bytes(osd) >> inode->i_blkbits)
			osd_decay_extent_bytes(osd,
				(total - previous_total) << inode->i_blkbits);
		/* look for next extent */
		fp = NULL;
		blocks += blocks_per_page * clen;
	}
cleanup:
	if (rc == 0 && create &&
	    start_blocks < pages * blocks_per_page) {
		rc = osd_ldiskfs_map_write(inode, iobuf, osd, start_blocks,
					   count, &disk_size, user_size);
		LASSERT(start_blocks + count == pages * blocks_per_page);
	}
	return rc;
}

static int osd_write_prep(const struct lu_env *env, struct dt_object *dt,
			  struct niobuf_local *lnb, int npages)
{
	struct osd_thread_info *oti   = osd_oti_get(env);
	struct osd_iobuf       *iobuf = &oti->oti_iobuf;
	struct inode           *inode = osd_dt_obj(dt)->oo_inode;
	struct osd_device      *osd   = osd_obj2dev(osd_dt_obj(dt));
	ktime_t start, end;
	s64 timediff;
	ssize_t isize;
	__s64  maxidx;
	int i, rc = 0;

	LASSERT(inode);

	rc = osd_init_iobuf(osd, iobuf, 0, npages);
	if (unlikely(rc != 0))
		RETURN(rc);

	isize = i_size_read(inode);
	maxidx = ((isize + PAGE_SIZE - 1) >> PAGE_SHIFT) - 1;

	start = ktime_get();
	for (i = 0; i < npages; i++) {

		/*
		 * till commit the content of the page is undefined
		 * we'll set it uptodate once bulk is done. otherwise
		 * subsequent reads can access non-stable data
		 */
		ClearPageUptodate(lnb[i].lnb_page);

		if (lnb[i].lnb_len == PAGE_SIZE)
			continue;

		if (maxidx >= lnb[i].lnb_page->index) {
			osd_iobuf_add_page(iobuf, &lnb[i]);
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
		rc = osd_ldiskfs_map_inode_pages(inode, iobuf, osd, 0,
						 0, 0, NULL);
		if (likely(rc == 0)) {
			rc = osd_do_bio(osd, inode, iobuf, 0, 0);
			/* do IO stats for preparation reads */
			osd_fini_iobuf(osd, iobuf);
		}
	}
	RETURN(rc);
}

struct osd_fextent {
	sector_t	start;
	sector_t	end;
	__u32		flags;
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

	rc = inode->i_op->fiemap(inode, &fei, offset, FIEMAP_MAX_OFFSET-offset);
	if (rc != 0)
		return 0;

	start = fe.fe_logical >> inode->i_blkbits;
	cached_extent->flags = fe.fe_flags;
	if (fei.fi_extents_mapped == 0) {
		/* a special case - no extent found at this offset and forward.
		 * we can consider this as a hole to EOF. it's safe to cache
		 * as other threads can not allocate/punch blocks this thread
		 * is working on (LDLM). */
		cached_extent->start = block;
		cached_extent->end = i_size_read(inode) >> inode->i_blkbits;
		cached_extent->mapped = 0;
		return 0;
	}

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

#define MAX_EXTENTS_PER_WRITE 100
static int osd_declare_write_commit(const struct lu_env *env,
				    struct dt_object *dt,
				    struct niobuf_local *lnb, int npages,
				    struct thandle *handle)
{
	const struct osd_device	*osd = osd_obj2dev(osd_dt_obj(dt));
	struct inode		*inode = osd_dt_obj(dt)->oo_inode;
	struct osd_thandle	*oh;
	int			extents = 0, new_meta = 0;
	int			depth, new_blocks = 0;
	int			i;
	int			dirty_groups = 0;
	int			rc = 0;
	int			credits = 0;
	long long		quota_space = 0;
	struct osd_fextent	mapped = { 0 }, extent = { 0 };
	enum osd_quota_local_flags local_flags = 0;
	enum osd_qid_declare_flags declare_flags = OSD_QID_BLK;
	unsigned int		extent_bytes;
	ENTRY;

	LASSERT(handle != NULL);
	oh = container_of(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	/*
	 * We track a decaying average extent blocks per filesystem,
	 * for most of time, it will be 1M, with filesystem becoming
	 * heavily-fragmented, it will be reduced to 4K at the worst.
	 */
	extent_bytes = osd_extent_bytes(osd);
	LASSERT(extent_bytes >= osd_sb(osd)->s_blocksize);

	/* calculate number of extents (probably better to pass nb) */
	for (i = 0; i < npages; i++) {
		/* ignore quota for the whole request if any page is from
		 * client cache or written by root.
		 *
		 * XXX we could handle this on per-lnb basis as done by
		 * grant.
		 */
		if ((lnb[i].lnb_flags & OBD_BRW_NOQUOTA) ||
		    (lnb[i].lnb_flags & OBD_BRW_SYS_RESOURCE) ||
		    !(lnb[i].lnb_flags & OBD_BRW_SYNC))
			declare_flags |= OSD_QID_FORCE;

		/*
		 * Convert unwritten extent might need split extents, could
		 * not skip it.
		 */
		if (osd_is_mapped(dt, lnb[i].lnb_file_offset, &mapped) &&
		    !(mapped.flags & FIEMAP_EXTENT_UNWRITTEN)) {
			lnb[i].lnb_flags |= OBD_BRW_MAPPED;
			continue;
		}

		if (lnb[i].lnb_flags & OBD_BRW_DONE) {
			lnb[i].lnb_flags |= OBD_BRW_MAPPED;
			continue;
		}

		/* count only unmapped changes */
		new_blocks++;
		if (lnb[i].lnb_file_offset != extent.end || extent.end == 0) {
			if (extent.end != 0)
				extents += (extent.end - extent.start +
					    extent_bytes - 1) / extent_bytes;
			extent.start = lnb[i].lnb_file_offset;
			extent.end = lnb[i].lnb_file_offset + lnb[i].lnb_len;
		} else {
			extent.end += lnb[i].lnb_len;
		}

		quota_space += PAGE_SIZE;
	}

	credits++; /* inode */
	/*
	 * overwrite case, no need to modify tree and
	 * allocate blocks.
	 */
	if (!extent.end)
		goto out_declare;

	extents += (extent.end - extent.start +
		    extent_bytes - 1) / extent_bytes;
	/**
	 * with system space usage growing up, mballoc codes won't
	 * try best to scan block group to align best free extent as
	 * we can. So extent bytes per extent could be decayed to a
	 * very small value, this could make us reserve too many credits.
	 * We could be more optimistic in the credit reservations, even
	 * in a case where the filesystem is nearly full, it is extremely
	 * unlikely that the worst case would ever be hit.
	 */
	if (extents > MAX_EXTENTS_PER_WRITE)
		extents = MAX_EXTENTS_PER_WRITE;

	/**
	 * If we add a single extent, then in the worse case, each tree
	 * level index/leaf need to be changed in case of the tree split.
	 * If more extents are inserted, they could cause the whole tree
	 * split more than once, but this is really rare.
	 */
	if (LDISKFS_I(inode)->i_flags & LDISKFS_EXTENTS_FL) {
		/*
		 * many concurrent threads may grow tree by the time
		 * our transaction starts. so, consider 2 is a min depth.
		 */
		depth = ext_depth(inode);
		depth = min(max(depth, 1) + 1, LDISKFS_MAX_EXTENT_DEPTH);
		if (extents <= 1) {
			credits += depth * 2 * extents;
			new_meta = depth;
		} else {
			credits += depth * 3 * extents;
			new_meta = depth * 2 * extents;
		}
	} else {
		/*
		 * With N contiguous data blocks, we need at most
		 * N/EXT4_ADDR_PER_BLOCK(inode->i_sb) + 1 indirect blocks,
		 * 2 dindirect blocks, and 1 tindirect block
		 */
		new_meta = DIV_ROUND_UP(new_blocks,
				LDISKFS_ADDR_PER_BLOCK(inode->i_sb)) + 4;
		credits += new_meta;
	}
	dirty_groups += (extents + new_meta);

	oh->oh_declared_ext = extents;

	/* quota space for metadata blocks */
	quota_space += new_meta * LDISKFS_BLOCK_SIZE(osd_sb(osd));

	/* quota space should be reported in 1K blocks */
	quota_space = toqb(quota_space);

	/* each new block can go in different group (bitmap + gd) */

	/* we can't dirty more bitmap blocks than exist */
	if (dirty_groups > LDISKFS_SB(osd_sb(osd))->s_groups_count)
		credits += LDISKFS_SB(osd_sb(osd))->s_groups_count;
	else
		credits += dirty_groups;

	/* we can't dirty more gd blocks than exist */
	if (dirty_groups > LDISKFS_SB(osd_sb(osd))->s_gdb_count)
		credits += LDISKFS_SB(osd_sb(osd))->s_gdb_count;
	else
		credits += dirty_groups;

	CDEBUG(D_INODE,
	       "%s: inode #%lu extent_bytes %u extents %d credits %d\n",
	       osd_ino2name(inode), inode->i_ino, extent_bytes, extents,
	       credits);

out_declare:
	osd_trans_declare_op(env, oh, OSD_OT_WRITE, credits);

	/* make sure the over quota flags were not set */
	lnb[0].lnb_flags &= ~OBD_BRW_OVER_ALLQUOTA;

	rc = osd_declare_inode_qid(env, i_uid_read(inode), i_gid_read(inode),
				   i_projid_read(inode), quota_space, oh,
				   osd_dt_obj(dt), &local_flags, declare_flags);

	/* we need only to store the overquota flags in the first lnb for
	 * now, once we support multiple objects BRW, this code needs be
	 * revised.
	 */
	if (local_flags & QUOTA_FL_OVER_USRQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_USRQUOTA;
	if (local_flags & QUOTA_FL_OVER_GRPQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_GRPQUOTA;
	if (local_flags & QUOTA_FL_OVER_PRJQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_PRJQUOTA;

	if (rc == 0)
		rc = osd_trunc_lock(osd_dt_obj(dt), oh, true);

	RETURN(rc);
}

/* Check if a block is allocated or not */
static int osd_write_commit(const struct lu_env *env, struct dt_object *dt,
			    struct niobuf_local *lnb, int npages,
			    struct thandle *thandle, __u64 user_size)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_iobuf *iobuf = &oti->oti_iobuf;
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	struct osd_device  *osd = osd_obj2dev(osd_dt_obj(dt));
	int rc = 0, i, check_credits = 0;

	LASSERT(inode);

	rc = osd_init_iobuf(osd, iobuf, 1, npages);
	if (unlikely(rc != 0))
		RETURN(rc);

	dquot_initialize(inode);

	for (i = 0; i < npages; i++) {
		if (lnb[i].lnb_rc == -ENOSPC &&
		    (lnb[i].lnb_flags & OBD_BRW_MAPPED)) {
			/* Allow the write to proceed if overwriting an
			 * existing block
			 */
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

		if (lnb[i].lnb_flags & OBD_BRW_DONE)
			continue;

		if (!(lnb[i].lnb_flags & OBD_BRW_MAPPED))
			check_credits = 1;

		LASSERT(PageLocked(lnb[i].lnb_page));
		LASSERT(!PageWriteback(lnb[i].lnb_page));

		/*
		 * Since write and truncate are serialized by oo_sem, even
		 * partial-page truncate should not leave dirty pages in the
		 * page cache.
		 */
		LASSERT(!PageDirty(lnb[i].lnb_page));

		SetPageUptodate(lnb[i].lnb_page);

		osd_iobuf_add_page(iobuf, &lnb[i]);
	}

	osd_trans_exec_op(env, thandle, OSD_OT_WRITE);

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_MAPBLK_ENOSPC)) {
		rc = -ENOSPC;
	} else if (iobuf->dr_npages > 0) {
		rc = osd_ldiskfs_map_inode_pages(inode, iobuf, osd,
						 1, user_size,
						 check_credits,
						 thandle);
	} else {
		/* no pages to write, no transno is needed */
		thandle->th_local = 1;
	}

	if (rc != 0 && !thandle->th_restart_tran)
		osd_fini_iobuf(osd, iobuf);

	osd_trans_exec_check(env, thandle, OSD_OT_WRITE);

	if (unlikely(rc != 0 && !thandle->th_restart_tran)) {
		/* if write fails, we should drop pages from the cache */
		for (i = 0; i < npages; i++) {
			if (lnb[i].lnb_page == NULL)
				continue;
			if (!PagePrivate2(lnb[i].lnb_page)) {
				LASSERT(PageLocked(lnb[i].lnb_page));
				generic_error_remove_page(inode->i_mapping,
							  lnb[i].lnb_page);
			}
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
	int rc = 0, i, cache_hits = 0, cache_misses = 0;
	ktime_t start, end;
	s64 timediff;
	loff_t isize;

	LASSERT(inode);

	rc = osd_init_iobuf(osd, iobuf, 0, npages);
	if (unlikely(rc != 0))
		RETURN(rc);

	isize = i_size_read(inode);

	start = ktime_get();
	for (i = 0; i < npages; i++) {

		if (isize <= lnb[i].lnb_file_offset)
			/* If there's no more data, abort early.
			 * lnb->lnb_rc == 0, so it's easy to detect later.
			 */
			break;

		/* instead of looking if we go beyong isize, send complete
		 * pages all the time
		 */
		lnb[i].lnb_rc = lnb[i].lnb_len;

		/* Bypass disk read if fail_loc is set properly */
		if (OBD_FAIL_CHECK_QUIET(OBD_FAIL_OST_FAKE_RW))
			SetPageUptodate(lnb[i].lnb_page);

		if (PageUptodate(lnb[i].lnb_page)) {
			cache_hits++;
			unlock_page(lnb[i].lnb_page);
		} else {
			cache_misses++;
			osd_iobuf_add_page(iobuf, &lnb[i]);
		}
		/* no need to unlock in osd_bufs_put(), the sooner page is
		 * unlocked, the earlier another client can access it.
		 * notice real unlock_page() can be called few lines
		 * below after osd_do_bio(). lnb is a per-thread, so it's
		 * fine to have PG_locked and lnb_locked inconsistent here
		 */
		lnb[i].lnb_locked = 0;
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
		rc = osd_ldiskfs_map_inode_pages(inode, iobuf, osd, 0,
						 0, 0, NULL);
		if (!rc)
			rc = osd_do_bio(osd, inode, iobuf, 0, 0);

		/* IO stats will be done in osd_bufs_put() */

		/* early release to let others read data during the bulk */
		for (i = 0; i < iobuf->dr_npages; i++) {
			LASSERT(PageLocked(iobuf->dr_pages[i]));
			if (!PagePrivate2(iobuf->dr_pages[i]))
				unlock_page(iobuf->dr_pages[i]);
		}
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
			CDEBUG(D_OTHER,
			       "size %llu is too short to read @%llu\n",
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
			CERROR("%s: can't read %u@%llu on ino %lu: rc = %ld\n",
			       osd_ino2name(inode), csize, *offs, inode->i_ino,
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
	int rc;

	/* Read small symlink from inode body as we need to maintain correct
	 * on-disk symlinks for ldiskfs.
	 */
	if (S_ISLNK(dt->do_lu.lo_header->loh_attr)) {
		loff_t size = i_size_read(inode);

		if (buf->lb_len < size)
			return -EOVERFLOW;

		if (size < sizeof(LDISKFS_I(inode)->i_data))
			rc = osd_ldiskfs_readlink(inode, buf->lb_buf, size);
		else
			rc = osd_ldiskfs_read(inode, buf->lb_buf, size, pos);
	} else {
		rc = osd_ldiskfs_read(inode, buf->lb_buf, buf->lb_len, pos);
	}

	return rc;
}

static inline int osd_extents_enabled(struct super_block *sb,
				      struct inode *inode)
{
	if (inode != NULL) {
		if (LDISKFS_I(inode)->i_flags & LDISKFS_EXTENTS_FL)
			return 1;
	} else if (ldiskfs_has_feature_extents(sb)) {
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
	 * so let's shrink it to 2 levels (4GB files)
	 */

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

	oh = container_of(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	size = buf->lb_len;
	bits = sb->s_blocksize_bits;
	bs = 1 << bits;

	if (_pos == -1) {
		/* if this is an append, then we
		 * should expect cross-block record
		 */
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
		depth = min(max(depth, 1) + 3, LDISKFS_MAX_EXTENT_DEPTH);
		credits = depth;
		/* if not append, then split may need to modify
		 * existing blocks moving entries into the new ones
		 */
		if (_pos != -1)
			credits += depth;
		/* blocks to store data: bitmap,gd,itself */
		credits += blocks * 3;
	} else {
		credits = osd_calc_bkmap_credits(sb, inode, size, _pos, blocks);
	}
	/* if inode is created as part of the transaction,
	 * then it's counted already by the creation method
	 */
	if (inode != NULL)
		credits++;

out:

	osd_trans_declare_op(env, oh, OSD_OT_WRITE, credits);

	/* dt_declare_write() is usually called for system objects, such
	 * as llog or last_rcvd files. We needn't enforce quota on those
	 * objects, so always set the lqi_space as 0.
	 */
	if (inode != NULL)
		rc = osd_declare_inode_qid(env, i_uid_read(inode),
					   i_gid_read(inode),
					   i_projid_read(inode), 0,
					   oh, obj, NULL, OSD_QID_BLK);

	if (rc == 0)
		rc = osd_trunc_lock(obj, oh, true);

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
	osd_dirty_inode(inode, I_DIRTY_DATASYNC);

	return 0;
}

static int osd_ldiskfs_write_record(struct dt_object *dt, void *buf,
				    int bufsize, int write_NUL, loff_t *offs,
				    handle_t *handle)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	struct buffer_head *bh        = NULL;
	loff_t              offset    = *offs;
	loff_t              new_size  = i_size_read(inode);
	unsigned long       block;
	int                 blocksize = 1 << inode->i_blkbits;
	struct ldiskfs_inode_info *ei = LDISKFS_I(inode);
	int                 err = 0;
	int                 size;
	int                 boffs;
	int                 dirty_inode = 0;
	bool create, sparse, sync = false;

	if (write_NUL) {
		/*
		 * long symlink write does not count the NUL terminator in
		 * bufsize, we write it, and the inode's file size does not
		 * count the NUL terminator as well.
		 */
		((char *)buf)[bufsize] = '\0';
		++bufsize;
	}

	/* only the first flag-set matters */
	dirty_inode = !test_and_set_bit(LDISKFS_INODE_JOURNAL_DATA,
				       &ei->i_flags);

	/* sparse checking is racy, but sparse is very rare case, leave as is */
	sparse = (new_size > 0 && (inode->i_blocks >> (inode->i_blkbits - 9)) <
		  ((new_size - 1) >> inode->i_blkbits) + 1);

	while (bufsize > 0) {
		int credits = handle->h_buffer_credits;
		unsigned long last_block = (new_size == 0) ? 0 :
					   (new_size - 1) >> inode->i_blkbits;

		if (bh)
			brelse(bh);

		block = offset >> inode->i_blkbits;
		boffs = offset & (blocksize - 1);
		size = min(blocksize - boffs, bufsize);
		sync = (block > last_block || new_size == 0 || sparse);

		if (sync)
			down(&ei->i_append_sem);

		bh = __ldiskfs_bread(handle, inode, block, 0);

		if (unlikely(IS_ERR_OR_NULL(bh) && !sync))
			CWARN(
			      "%s: adding bh without locking off %llu (block %lu, size %d, offs %llu)\n",
			      osd_ino2name(inode),
			      offset, block, bufsize, *offs);

		if (IS_ERR_OR_NULL(bh)) {
			struct osd_device *osd = osd_obj2dev(osd_dt_obj(dt));
			int flags = LDISKFS_GET_BLOCKS_CREATE;

			/* while the file system is being mounted, avoid
			 * preallocation otherwise mount can take a long
			 * time as mballoc cache is cold.
			 * XXX: this is a workaround until we have a proper
			 *	fix in mballoc
			 * XXX: works with extent-based files only */
			if (!osd->od_cl_seq)
				flags |= LDISKFS_GET_BLOCKS_NO_NORMALIZE;
			bh = __ldiskfs_bread(handle, inode, block, flags);
			create = true;
		} else {
			if (sync) {
				up(&ei->i_append_sem);
				sync = false;
			}
			create = false;
		}
		if (IS_ERR_OR_NULL(bh)) {
			if (bh == NULL) {
				err = -EIO;
			} else {
				err = PTR_ERR(bh);
				bh = NULL;
			}

			CERROR(
			       "%s: error reading offset %llu (block %lu, size %d, offs %llu), credits %d/%d: rc = %d\n",
			       osd_ino2name(inode), offset, block, bufsize,
			       *offs, credits, handle->h_buffer_credits, err);
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
		if (create) {
			memset(bh->b_data, 0, bh->b_size);
			if (sync) {
				up(&ei->i_append_sem);
				sync = false;
			}
		}
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
	if (sync)
		up(&ei->i_append_sem);

	if (bh)
		brelse(bh);

	if (write_NUL)
		--new_size;
	/* correct in-core and on-disk sizes */
	if (new_size > i_size_read(inode)) {
		spin_lock(&inode->i_lock);
		if (new_size > i_size_read(inode))
			i_size_write(inode, new_size);
		if (i_size_read(inode) > ei->i_disksize) {
			ei->i_disksize = i_size_read(inode);
			dirty_inode = 1;
		}
		spin_unlock(&inode->i_lock);
	}
	if (dirty_inode)
		osd_dirty_inode(inode, I_DIRTY_DATASYNC);

	if (err == 0)
		*offs = offset;
	return err;
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, loff_t *pos,
			 struct thandle *handle)
{
	struct inode		*inode = osd_dt_obj(dt)->oo_inode;
	struct osd_thandle	*oh;
	ssize_t			result;
	int			is_link;

	LASSERT(dt_object_exists(dt));

	LASSERT(handle != NULL);
	LASSERT(inode != NULL);
	dquot_initialize(inode);

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
		result = osd_ldiskfs_write_record(dt, buf->lb_buf, buf->lb_len,
						  is_link, pos, oh->ot_handle);
	if (result == 0)
		result = buf->lb_len;

	osd_trans_exec_check(env, handle, OSD_OT_WRITE);

	return result;
}

static int osd_declare_fallocate(const struct lu_env *env,
				 struct dt_object *dt, __u64 start, __u64 end,
				 int mode, struct thandle *th)
{
	struct osd_thandle *oh = container_of(th, struct osd_thandle, ot_super);
	struct osd_device *osd = osd_obj2dev(osd_dt_obj(dt));
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	long long quota_space = 0;
	/* 5 is max tree depth. (inode + 4 index blocks) */
	int depth = 5;
	int rc;

	ENTRY;

	/*
	 * mode == 0 (which is standard prealloc) and PUNCH is supported
	 * Rest of mode options is not supported yet.
	 */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		RETURN(-EOPNOTSUPP);

	/* disable fallocate completely */
	if (osd_dev(dt->do_lu.lo_dev)->od_fallocate_zero_blocks < 0)
		RETURN(-EOPNOTSUPP);

	LASSERT(th);
	LASSERT(inode);

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		rc = osd_declare_inode_qid(env, i_uid_read(inode),
					   i_gid_read(inode),
					   i_projid_read(inode), 0, oh,
					   osd_dt_obj(dt), NULL, OSD_QID_BLK);
		if (rc == 0)
			rc = osd_trunc_lock(osd_dt_obj(dt), oh, false);
		RETURN(rc);
	}

	/* quota space for metadata blocks
	 * approximate metadata estimate should be good enough.
	 */
	quota_space += PAGE_SIZE;
	quota_space += depth * LDISKFS_BLOCK_SIZE(osd_sb(osd));

	/* quota space should be reported in 1K blocks */
	quota_space = toqb(quota_space) + toqb(end - start) +
		      LDISKFS_META_TRANS_BLOCKS(inode->i_sb);

	/* We don't need to reserve credits for whole fallocate here.
	 * We reserve space only for metadata. Fallocate credits are
	 * extended as required
	 */
	rc = osd_declare_inode_qid(env, i_uid_read(inode), i_gid_read(inode),
				   i_projid_read(inode), quota_space, oh,
				   osd_dt_obj(dt), NULL, OSD_QID_BLK);
	RETURN(rc);
}

static int osd_fallocate_preallocate(const struct lu_env *env,
				     struct dt_object *dt,
				     __u64 start, __u64 end, int mode,
				     struct thandle *th)
{
	struct osd_thandle *oh = container_of(th, struct osd_thandle, ot_super);
	handle_t *handle = ldiskfs_journal_current_handle();
	unsigned int save_credits = oh->ot_credits;
	struct osd_object *obj = osd_dt_obj(dt);
	struct inode *inode = obj->oo_inode;
	struct ldiskfs_map_blocks map;
	unsigned int credits;
	ldiskfs_lblk_t blen;
	ldiskfs_lblk_t boff;
	loff_t new_size = 0;
	int depth = 0;
	int flags;
	int rc = 0;

	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(inode != NULL);

	CDEBUG(D_INODE, "fallocate: inode #%lu: start %llu end %llu mode %d\n",
	       inode->i_ino, start, end, mode);

	dquot_initialize(inode);

	LASSERT(th);

	boff = start >> inode->i_blkbits;
	blen = (ALIGN(end, 1 << inode->i_blkbits) >> inode->i_blkbits) - boff;

	/* Create and mark new extents as either zero or unwritten */
	flags = (osd_dev(dt->do_lu.lo_dev)->od_fallocate_zero_blocks ||
		 !ldiskfs_test_inode_flag(inode, LDISKFS_INODE_EXTENTS)) ?
		LDISKFS_GET_BLOCKS_CREATE_ZERO :
		LDISKFS_GET_BLOCKS_CREATE_UNWRIT_EXT;
#ifndef HAVE_LDISKFS_GET_BLOCKS_KEEP_SIZE
	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= LDISKFS_GET_BLOCKS_KEEP_SIZE;
#endif
	inode_lock(inode);

	if (!(mode & FALLOC_FL_KEEP_SIZE) && (end > i_size_read(inode) ||
	    end > LDISKFS_I(inode)->i_disksize)) {
		new_size = end;
		rc = inode_newsize_ok(inode, new_size);
		if (rc)
			GOTO(out, rc);
	}

	inode_dio_wait(inode);

	map.m_lblk = boff;
	map.m_len = blen;

	/* Don't normalize the request if it can fit in one extent so
	 * that it doesn't get unnecessarily split into multiple extents.
	 */
	if (blen <= EXT_UNWRITTEN_MAX_LEN)
		flags |= LDISKFS_GET_BLOCKS_NO_NORMALIZE;

	/*
	 * credits to insert 1 extent into extent tree.
	 */
	credits = osd_chunk_trans_blocks(inode, blen);
	depth = ext_depth(inode);

	while (rc >= 0 && blen) {
		loff_t epos;

		/*
		 * Recalculate credits when extent tree depth changes.
		 */
		if (depth != ext_depth(inode)) {
			credits = osd_chunk_trans_blocks(inode, blen);
			depth = ext_depth(inode);
		}

		/* TODO: quota check */
		rc = osd_extend_restart_trans(handle, credits, inode);
		if (rc)
			break;

		rc = ldiskfs_map_blocks(handle, inode, &map, flags);
		if (rc <= 0) {
			CDEBUG(D_INODE,
			       "inode #%lu: block %u: len %u: ldiskfs_map_blocks returned %d\n",
			       inode->i_ino, map.m_lblk, map.m_len, rc);
			ldiskfs_mark_inode_dirty(handle, inode);
			break;
		}

		map.m_lblk += rc;
		map.m_len = blen = blen - rc;
		epos = (loff_t)map.m_lblk << inode->i_blkbits;
		inode->i_ctime = current_time(inode);
		if (new_size) {
			if (epos > end)
				epos = end;
			if (ldiskfs_update_inode_size(inode, epos) & 0x1)
				inode->i_mtime = inode->i_ctime;
#ifndef HAVE_LDISKFS_GET_BLOCKS_KEEP_SIZE
		} else {
			if (epos > inode->i_size)
				ldiskfs_set_inode_flag(inode,
						       LDISKFS_INODE_EOFBLOCKS);
#endif
		}

		ldiskfs_mark_inode_dirty(handle, inode);
	}

out:
	/* extand credits if needed for operations such as attribute set */
	if (rc >= 0)
		rc = osd_extend_restart_trans(handle, save_credits, inode);

	inode_unlock(inode);

	RETURN(rc);
}

static int osd_fallocate_punch(const struct lu_env *env, struct dt_object *dt,
			       __u64 start, __u64 end, int mode,
			       struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct inode *inode = obj->oo_inode;
	struct osd_access_lock *al;
	struct osd_thandle *oh;
	int rc = 0, found = 0;

	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(inode != NULL);

	dquot_initialize(inode);

	LASSERT(th);
	oh = container_of(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle->h_transaction != NULL);

	list_for_each_entry(al, &oh->ot_trunc_locks, tl_list) {
		if (obj != al->tl_obj)
			continue;
		LASSERT(al->tl_shared == 0);
		found = 1;
		/* do actual punch in osd_trans_stop() */
		al->tl_start = start;
		al->tl_end = end;
		al->tl_mode = mode;
		al->tl_punch = true;
		break;
	}

	RETURN(rc);
}

static int osd_fallocate(const struct lu_env *env, struct dt_object *dt,
			 __u64 start, __u64 end, int mode, struct thandle *th)
{
	int rc;

	ENTRY;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		/* punch */
		rc = osd_fallocate_punch(env, dt, start, end, mode, th);
	} else {
		/* standard preallocate */
		rc = osd_fallocate_preallocate(env, dt, start, end, mode, th);
	}
	RETURN(rc);
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

	if (rc == 0)
		rc = osd_trunc_lock(osd_dt_obj(dt), oh, false);

	RETURN(rc);
}

static int osd_punch(const struct lu_env *env, struct dt_object *dt,
		     __u64 start, __u64 end, struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	struct inode *inode = obj->oo_inode;
	struct osd_access_lock *al;
	struct osd_thandle *oh;
	int rc = 0, found = 0;
	bool grow = false;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(inode != NULL);
	dquot_initialize(inode);

	LASSERT(th);
	oh = container_of(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle->h_transaction != NULL);

	/* we used to skip truncate to current size to
	 * optimize truncates on OST. with DoM we can
	 * get attr_set to set specific size (MDS_REINT)
	 * and then get truncate RPC which essentially
	 * would be skipped. this is bad.. so, disable
	 * this optimization on MDS till the client stop
	 * to sent MDS_REINT (LU-11033) -bzzz
	 */
	if (osd->od_is_ost && i_size_read(inode) == start)
		RETURN(0);

	osd_trans_exec_op(env, th, OSD_OT_PUNCH);

	spin_lock(&inode->i_lock);
	if (i_size_read(inode) < start)
		grow = true;
	i_size_write(inode, start);
	spin_unlock(&inode->i_lock);
	/* if object holds encrypted content, we need to make sure we truncate
	 * on an encryption unit boundary, or subsequent reads will get
	 * corrupted content
	 */
	if (obj->oo_lma_flags & LUSTRE_ENCRYPT_FL &&
	    start & ~LUSTRE_ENCRYPTION_MASK)
		start = (start & LUSTRE_ENCRYPTION_MASK) +
			LUSTRE_ENCRYPTION_UNIT_SIZE;
	ll_truncate_pagecache(inode, start);

	/* optimize grow case */
	if (grow) {
		osd_execute_truncate(obj);
		GOTO(out, rc);
	}

	inode_lock(inode);
	/* add to orphan list to ensure truncate completion
	 * if this transaction succeed. ldiskfs_truncate()
	 * will take the inode out of the list
	 */
	rc = ldiskfs_orphan_add(oh->ot_handle, inode);
	inode_unlock(inode);
	if (rc != 0)
		GOTO(out, rc);

	list_for_each_entry(al, &oh->ot_trunc_locks, tl_list) {
		if (obj != al->tl_obj)
			continue;
		LASSERT(al->tl_shared == 0);
		found = 1;
		/* do actual truncate in osd_trans_stop() */
		al->tl_truncate = 1;
		break;
	}
	LASSERT(found);

out:
	RETURN(rc);
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
	struct osd_object *obj = osd_dt_obj(dt);
	int rc = 0;
	ENTRY;

	switch (advice) {
	case LU_LADVISE_DONTNEED:
		if (end)
			invalidate_mapping_pages(obj->oo_inode->i_mapping,
						 start >> PAGE_SHIFT,
						 (end - 1) >> PAGE_SHIFT);
		break;
	default:
		rc = -ENOTSUPP;
		break;
	}

	RETURN(rc);
}

static loff_t osd_lseek(const struct lu_env *env, struct dt_object *dt,
			loff_t offset, int whence)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *dev = osd_obj2dev(obj);
	struct inode *inode = obj->oo_inode;
	struct file *file;
	loff_t result;

	ENTRY;
	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(inode);
	LASSERT(offset >= 0);

	file = alloc_file_pseudo(inode, dev->od_mnt, "/", O_NOATIME,
				 inode->i_fop);
	if (IS_ERR(file))
		RETURN(PTR_ERR(file));

	file->f_mode |= FMODE_64BITHASH;
	result = file->f_op->llseek(file, offset, whence);
	ihold(inode);
	fput(file);
	/*
	 * If 'offset' is beyond end of object file then treat it as not error
	 * but valid case for SEEK_HOLE and return 'offset' as result.
	 * LOV will decide if it is beyond real end of file or not.
	 */
	if (whence == SEEK_HOLE && result == -ENXIO)
		result = offset;

	CDEBUG(D_INFO, "seek %s from %lld: %lld\n", whence == SEEK_HOLE ?
		       "hole" : "data", offset, result);
	RETURN(result);
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
	.dbo_declare_fallocate		= osd_declare_fallocate,
	.dbo_fallocate			= osd_fallocate,
	.dbo_lseek			= osd_lseek,
};

/**
 * Get a truncate lock
 *
 * In order to take multi-transaction truncate out of main transaction we let
 * the caller grab a lock on the object passed. the lock can be shared (for
 * writes) and exclusive (for truncate). It's not allowed to mix truncate
 * and write in the same transaction handle (do not confuse with big ldiskfs
 * transaction containing lots of handles).
 * The lock must be taken at declaration.
 *
 * \param obj		object to lock
 * \oh			transaction
 * \shared		shared or exclusive
 *
 * \retval 0		lock is granted
 * \retval -NOMEM	no memory to allocate lock
 */
int osd_trunc_lock(struct osd_object *obj, struct osd_thandle *oh, bool shared)
{
	struct osd_access_lock *al, *tmp;

	LASSERT(obj);
	LASSERT(oh);

	list_for_each_entry(tmp, &oh->ot_trunc_locks, tl_list) {
		if (tmp->tl_obj != obj)
			continue;
		LASSERT(tmp->tl_shared == shared);
		/* found same lock */
		return 0;
	}

	OBD_ALLOC_PTR(al);
	if (unlikely(al == NULL))
		return -ENOMEM;
	al->tl_obj = obj;
	al->tl_truncate = false;
	if (shared)
		down_read(&obj->oo_ext_idx_sem);
	else
		down_write(&obj->oo_ext_idx_sem);
	al->tl_shared = shared;
	lu_object_get(&obj->oo_dt.do_lu);

	list_add(&al->tl_list, &oh->ot_trunc_locks);

	return 0;
}

void osd_trunc_unlock_all(const struct lu_env *env, struct list_head *list)
{
	struct osd_access_lock *al, *tmp;

	list_for_each_entry_safe(al, tmp, list, tl_list) {
		if (al->tl_shared)
			up_read(&al->tl_obj->oo_ext_idx_sem);
		else
			up_write(&al->tl_obj->oo_ext_idx_sem);
		osd_object_put(env, al->tl_obj);
		list_del(&al->tl_list);
		OBD_FREE_PTR(al);
	}
}

/* For a partial-page punch, flush punch range to disk immediately */
static void osd_partial_page_flush_punch(struct osd_device *d,
					 struct inode *inode, loff_t start,
					 loff_t end)
{
	if (osd_use_page_cache(d)) {
		filemap_fdatawrite_range(inode->i_mapping, start, end);
	} else {
		/* Notice we use "wait" version to ensure I/O is complete */
		filemap_write_and_wait_range(inode->i_mapping, start,
					     end);
		invalidate_mapping_pages(inode->i_mapping, start >> PAGE_SHIFT,
					 end >> PAGE_SHIFT);
	}
}

/*
 * For a partial-page truncate, flush the page to disk immediately to
 * avoid data corruption during direct disk write.  b=17397
 */
static void osd_partial_page_flush(struct osd_device *d, struct inode *inode,
				   loff_t offset)
{
	if (!(offset & ~PAGE_MASK))
		return;

	if (osd_use_page_cache(d)) {
		filemap_fdatawrite_range(inode->i_mapping, offset, offset + 1);
	} else {
		/* Notice we use "wait" version to ensure I/O is complete */
		filemap_write_and_wait_range(inode->i_mapping, offset,
					     offset + 1);
		invalidate_mapping_pages(inode->i_mapping, offset >> PAGE_SHIFT,
					 offset >> PAGE_SHIFT);
	}
}

void osd_execute_truncate(struct osd_object *obj)
{
	struct osd_device *d = osd_obj2dev(obj);
	struct inode *inode = obj->oo_inode;
	__u64 size;

	/* simulate crash before (in the middle) of delayed truncate */
	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_FAIL_AT_TRUNCATE)) {
		struct ldiskfs_inode_info *ei = LDISKFS_I(inode);
		struct ldiskfs_sb_info *sbi = LDISKFS_SB(inode->i_sb);

		mutex_lock(&sbi->s_orphan_lock);
		list_del_init(&ei->i_orphan);
		mutex_unlock(&sbi->s_orphan_lock);
		return;
	}

	size = i_size_read(inode);
	inode_lock(inode);
	/* if object holds encrypted content, we need to make sure we truncate
	 * on an encryption unit boundary, or block content will get corrupted
	 */
	if (obj->oo_lma_flags & LUSTRE_ENCRYPT_FL &&
	    size & ~LUSTRE_ENCRYPTION_MASK)
		inode->i_size = (size & LUSTRE_ENCRYPTION_MASK) +
			LUSTRE_ENCRYPTION_UNIT_SIZE;
	ldiskfs_truncate(inode);
	inode_unlock(inode);
	if (inode->i_size != size) {
		spin_lock(&inode->i_lock);
		i_size_write(inode, size);
		LDISKFS_I(inode)->i_disksize = size;
		spin_unlock(&inode->i_lock);
		osd_dirty_inode(inode, I_DIRTY_DATASYNC);
	}
	osd_partial_page_flush(d, inode, size);
}

static int osd_execute_punch(const struct lu_env *env, struct osd_object *obj,
			     loff_t start, loff_t end, int mode)
{
	struct osd_device *d = osd_obj2dev(obj);
	struct inode *inode = obj->oo_inode;
	struct file *file;
	int rc;

	file = alloc_file_pseudo(inode, d->od_mnt, "/", O_NOATIME,
				 inode->i_fop);
	if (IS_ERR(file))
		RETURN(PTR_ERR(file));

	file->f_mode |= FMODE_64BITHASH;
	rc = file->f_op->fallocate(file, mode, start, end - start);
	ihold(inode);
	fput(file);
	if (rc == 0)
		osd_partial_page_flush_punch(d, inode, start, end - 1);
	return rc;
}

int osd_process_truncates(const struct lu_env *env, struct list_head *list)
{
	struct osd_access_lock *al;
	int rc = 0;

	LASSERT(!journal_current_handle());

	list_for_each_entry(al, list, tl_list) {
		if (al->tl_shared)
			continue;
		if (al->tl_truncate)
			osd_execute_truncate(al->tl_obj);
		else if (al->tl_punch)
			rc = osd_execute_punch(env, al->tl_obj, al->tl_start,
					       al->tl_end, al->tl_mode);
	}

	return rc;
}
