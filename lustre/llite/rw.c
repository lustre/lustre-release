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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/llite/rw.c
 *
 * Lustre Lite I/O page cache routines shared by different kernel revs
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/writeback.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
/* current_is_kswapd() */
#include <linux/swap.h>
#include <linux/task_io_accounting_ops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_cksum.h>
#include "llite_internal.h"
#include <lustre_compat.h>

static void ll_ra_stats_inc_sbi(struct ll_sb_info *sbi, enum ra_stat which);

/*
 * Get readahead pages from the filesystem readahead pool of the client for a
 * thread.
 *
 * /param sbi superblock for filesystem readahead state ll_ra_info
 * /param ria per-thread readahead state
 * /param pages number of pages requested for readahead for the thread.
 *
 * WARNING: This algorithm is used to reduce contention on sbi->ll_lock.
 * It should work well if the ra_max_pages is much greater than the single
 * file's read-ahead window, and not too many threads contending for
 * these readahead pages.
 *
 * TODO: There may be a 'global sync problem' if many threads are trying
 * to get an ra budget that is larger than the remaining readahead pages
 * and reach here at exactly the same time. They will compute /a ret to
 * consume the remaining pages, but will fail at atomic_add_return() and
 * get a zero ra window, although there is still ra space remaining. - Jay
 */

static unsigned long ll_ra_count_get(struct ll_sb_info *sbi,
				     struct ra_io_arg *ria,
				     unsigned long pages,
				     unsigned long pages_min)
{
	struct ll_ra_info *ra = &sbi->ll_ra_info;
	long ret;

	ENTRY;

	WARN_ON_ONCE(pages_min > pages);
	/*
	 * Don't try readahead aggresively if we are limited
	 * LRU pages, otherwise, it could cause deadlock.
	 */
	pages = min(sbi->ll_cache->ccc_lru_max >> 2, pages);
	/*
	 * if this happen, we reserve more pages than needed,
	 * this will make us leak @ra_cur_pages, because
	 * ll_ra_count_put() acutally freed @pages.
	 */
	if (unlikely(pages_min > pages))
		pages_min = pages;

	/*
	 * If read-ahead pages left are less than 1M, do not do read-ahead,
	 * otherwise it will form small read RPC(< 1M), which hurt server
	 * performance a lot.
	 */
	ret = min(ra->ra_max_pages - atomic_read(&ra->ra_cur_pages),
		  pages);
	if (ret < 0 || ret < min_t(long, PTLRPC_MAX_BRW_PAGES, pages))
		GOTO(out, ret = 0);

	if (atomic_add_return(ret, &ra->ra_cur_pages) > ra->ra_max_pages) {
		atomic_sub(ret, &ra->ra_cur_pages);
		ret = 0;
	}

out:
	if (ret < pages_min) {
		/* override ra limit for maximum performance */
		atomic_add(pages_min - ret, &ra->ra_cur_pages);
		ret = pages_min;
	}
	RETURN(ret);
}

void ll_ra_count_put(struct ll_sb_info *sbi, unsigned long pages)
{
	struct ll_ra_info *ra = &sbi->ll_ra_info;

	atomic_sub(pages, &ra->ra_cur_pages);
}

static void ll_ra_stats_inc_sbi(struct ll_sb_info *sbi, enum ra_stat which)
{
	LASSERTF(which < _NR_RA_STAT, "which: %u\n", which);
	lprocfs_counter_incr(sbi->ll_ra_stats, which);
}

static inline bool ll_readahead_enabled(struct ll_sb_info *sbi)
{
	return sbi->ll_ra_info.ra_max_pages_per_file > 0 &&
		sbi->ll_ra_info.ra_max_pages > 0;
}

void ll_ra_stats_inc(struct inode *inode, enum ra_stat which)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	ll_ra_stats_inc_sbi(sbi, which);
}

static void ll_ra_stats_add(struct inode *inode, enum ra_stat which, long count)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	LASSERTF(which < _NR_RA_STAT, "which: %u\n", which);
	lprocfs_counter_add(sbi->ll_ra_stats, which, count);
}

#define RAS_CDEBUG(ras) \
	CDEBUG(D_READA,							     \
	       "lre %llu cr %lu cb %llu wsi %lu wp %lu nra %lu rpc %lu "     \
	       "r %lu csr %lu so %llu sb %llu sl %llu lr %lu\n",	     \
	       ras->ras_last_read_end_bytes, ras->ras_consecutive_requests,  \
	       ras->ras_consecutive_bytes, ras->ras_window_start_idx,	     \
	       ras->ras_window_pages, ras->ras_next_readahead_idx,	     \
	       ras->ras_rpc_pages, ras->ras_requests,			     \
	       ras->ras_consecutive_stride_requests, ras->ras_stride_offset, \
	       ras->ras_stride_bytes, ras->ras_stride_length,		     \
	       ras->ras_async_last_readpage_idx)

static bool pos_in_window(loff_t pos, loff_t point,
			  unsigned long before, unsigned long after)
{
	loff_t start = point - before;
	loff_t end = point + after;

	if (start > point)
		start = 0;
	if (end < point)
		end = ~0;

	return start <= pos && pos <= end;
}

enum ll_ra_page_hint {
	MAYNEED = 0, /* this page possibly accessed soon */
	WILLNEED /* this page is gurateed to be needed */
};

/*
 * Initiates read-ahead of a page with given index.
 *
 * \retval +ve: page was already uptodate so it will be skipped
 *              from being added;
 * \retval -ve: page wasn't added to \a queue for error;
 * \retval   0: page was added into \a queue for read ahead.
 */
static int ll_read_ahead_page(const struct lu_env *env, struct cl_io *io,
			      struct cl_page_list *queue, pgoff_t index,
			      enum ll_ra_page_hint hint)
{
	struct cl_object *clob  = io->ci_obj;
	struct inode     *inode = vvp_object_inode(clob);
	struct page      *vmpage = NULL;
	struct cl_page   *cp;
	enum ra_stat      which = _NR_RA_STAT; /* keep gcc happy */
	int               rc    = 0;
	const char       *msg   = NULL;

	ENTRY;

	switch (hint) {
	case MAYNEED:
		/*
		 * We need __GFP_NORETRY here for read-ahead page, otherwise
		 * the process will fail with OOM killed due to memcg limit.
		 * See @readahead_gfp_mask for an example.
		 */
		vmpage = pagecache_get_page(inode->i_mapping, index,
					    FGP_LOCK | FGP_CREAT |
					    FGP_NOFS | FGP_NOWAIT,
					    mapping_gfp_mask(inode->i_mapping) |
					    __GFP_NORETRY | __GFP_NOWARN);
		if (vmpage == NULL) {
			which = RA_STAT_FAILED_GRAB_PAGE;
			msg   = "g_c_p_n failed";
			GOTO(out, rc = -EBUSY);
		}
		break;
	case WILLNEED:
		vmpage = find_or_create_page(inode->i_mapping, index,
					     GFP_NOFS);
		if (vmpage == NULL)
			GOTO(out, rc = -ENOMEM);
		break;
	default:
		/* should not come here */
		GOTO(out, rc = -EINVAL);
	}

	/* Check if vmpage was truncated or reclaimed */
	if (vmpage->mapping != inode->i_mapping) {
		which = RA_STAT_WRONG_GRAB_PAGE;
		msg   = "g_c_p_n returned invalid page";
		GOTO(out, rc = -EBUSY);
	}

	cp = cl_page_find(env, clob, vmpage->index, vmpage, CPT_CACHEABLE);
	if (IS_ERR(cp)) {
		which = RA_STAT_FAILED_GRAB_PAGE;
		msg   = "cl_page_find failed";
		GOTO(out, rc = PTR_ERR(cp));
	}

	cl_page_assume(env, io, cp);

	if (!cp->cp_defer_uptodate && !PageUptodate(vmpage)) {
		if (hint == MAYNEED) {
			cp->cp_defer_uptodate = 1;
			cp->cp_ra_used = 0;
		}

		cl_page_list_add(queue, cp, true);
	} else {
		/* skip completed pages */
		cl_page_unassume(env, io, cp);
		/* This page is already uptodate, returning a positive number
		 * to tell the callers about this
		 */
		rc = 1;
	}

	cl_page_put(env, cp);

out:
	if (vmpage != NULL) {
		if (rc != 0)
			unlock_page(vmpage);
		put_page(vmpage);
	}
	if (msg != NULL && hint == MAYNEED) {
		ll_ra_stats_inc(inode, which);
		CDEBUG(D_READA, "%s\n", msg);

	}

	RETURN(rc);
}

#define RIA_DEBUG(ria)							\
	CDEBUG(D_READA, "rs %lu re %lu ro %llu rl %llu rb %llu\n",	\
	       ria->ria_start_idx, ria->ria_end_idx, ria->ria_stoff,	\
	       ria->ria_length, ria->ria_bytes)

static inline int stride_io_mode(struct ll_readahead_state *ras)
{
	return ras->ras_consecutive_stride_requests > 1;
}

/* The function calculates how many bytes will be read in
 * [off, off + length], in such stride IO area,
 * stride_offset = st_off, stride_lengh = st_len,
 * stride_bytes = st_bytes
 *
 *   |------------------|*****|------------------|*****|------------|*****|....
 * st_off
 *   |--- st_bytes     ---|
 *   |-----     st_len   -----|
 *
 *              How many bytes it should read in such pattern
 *              |-------------------------------------------------------------|
 *              off
 *              |<------                  length                      ------->|
 *
 *          =   |<----->|  +  |-------------------------------------| +   |---|
 *             start_left                 st_bytes * i                 end_left
 */
static loff_t stride_byte_count(loff_t st_off, loff_t st_len, loff_t st_bytes,
				loff_t off, loff_t length)
{
	u64 start = off > st_off ? off - st_off : 0;
	u64 end = off + length > st_off ? off + length - st_off : 0;
	u64 start_left;
	u64 end_left;
	u64 bytes_count;

	if (st_len == 0 || length == 0 || end == 0)
		return length;

	start = div64_u64_rem(start, st_len, &start_left);
	if (start_left < st_bytes)
		start_left = st_bytes - start_left;
	else
		start_left = 0;

	end = div64_u64_rem(end, st_len, &end_left);
	if (end_left > st_bytes)
		end_left = st_bytes;

	CDEBUG(D_READA, "start %llu, end %llu start_left %llu end_left %llu\n",
	       start, end, start_left, end_left);

	if (start == end)
		bytes_count = end_left - (st_bytes - start_left);
	else
		bytes_count = start_left +
			st_bytes * (end - start - 1) + end_left;

	CDEBUG(D_READA,
	       "st_off %llu, st_len %llu st_bytes %llu off %llu length %llu bytescount %llu\n",
	       st_off, st_len, st_bytes, off, length, bytes_count);

	return bytes_count;
}

static unsigned long ria_page_count(struct ra_io_arg *ria)
{
	loff_t length_bytes = ria->ria_end_idx >= ria->ria_start_idx ?
		(loff_t)(ria->ria_end_idx -
			 ria->ria_start_idx + 1) << PAGE_SHIFT : 0;
	loff_t bytes_count;

	if (ria->ria_length > ria->ria_bytes && ria->ria_bytes &&
	    (ria->ria_length & ~PAGE_MASK || ria->ria_bytes & ~PAGE_MASK ||
	     ria->ria_stoff & ~PAGE_MASK)) {
		/* Over-estimate un-aligned page stride read */
		unsigned long pg_count = ((ria->ria_bytes +
					   PAGE_SIZE - 1) >> PAGE_SHIFT) + 1;
		pg_count *= length_bytes / ria->ria_length + 1;

		return pg_count;
	}
	bytes_count = stride_byte_count(ria->ria_stoff, ria->ria_length,
					ria->ria_bytes,
					(loff_t)ria->ria_start_idx<<PAGE_SHIFT,
					length_bytes);
	return (bytes_count + PAGE_SIZE - 1) >> PAGE_SHIFT;
}

static pgoff_t ras_align(struct ll_readahead_state *ras, pgoff_t index)
{
	unsigned int opt_size = min(ras->ras_window_pages, ras->ras_rpc_pages);

	if (opt_size == 0)
		opt_size = 1;
	return index - (index % opt_size);
}

/* Check whether the index is in the defined ra-window */
static bool ras_inside_ra_window(pgoff_t idx, struct ra_io_arg *ria)
{
	loff_t pos = (loff_t)idx << PAGE_SHIFT;

	/* If ria_length == ria_bytes, it means non-stride I/O mode,
	 * idx should always inside read-ahead window in this case
	 * For stride I/O mode, just check whether the idx is inside
	 * the ria_bytes.
	 */
	if (ria->ria_length == 0 || ria->ria_length == ria->ria_bytes)
		return true;

	if (pos >= ria->ria_stoff) {
		u64 offset;

		div64_u64_rem(pos - ria->ria_stoff, ria->ria_length, &offset);

		if (offset < ria->ria_bytes ||
		    (ria->ria_length - offset) < PAGE_SIZE)
			return true;
	} else if (pos + PAGE_SIZE > ria->ria_stoff) {
		return true;
	}

	return false;
}

static unsigned long
ll_read_ahead_pages(const struct lu_env *env, struct cl_io *io,
		    struct cl_page_list *queue, struct ll_readahead_state *ras,
		    struct ra_io_arg *ria, pgoff_t *ra_end, pgoff_t skip_index)
{
	struct cl_read_ahead ra = { 0 };
	/* busy page count is per stride */
	int rc = 0, count = 0, busy_page_count = 0;
	pgoff_t page_idx;

	LASSERT(ria != NULL);
	RIA_DEBUG(ria);

	for (page_idx = ria->ria_start_idx;
	     page_idx <= ria->ria_end_idx && ria->ria_reserved > 0;
	     page_idx++) {
		if (skip_index && page_idx == skip_index)
			continue;
		if (ras_inside_ra_window(page_idx, ria)) {
			if (ra.cra_end_idx == 0 || ra.cra_end_idx < page_idx) {
				pgoff_t end_idx;

				/*
				 * Do not shrink ria_end_idx at any case until
				 * the minimum end of current read is covered.
				 *
				 * Do not extend read lock accross stripe if
				 * lock contention detected.
				 */
				if (ra.cra_contention &&
				    page_idx > ria->ria_end_idx_min) {
					ria->ria_end_idx = *ra_end;
					break;
				}

				cl_read_ahead_release(env, &ra);

				rc = cl_io_read_ahead(env, io, page_idx, &ra);
				if (rc < 0)
					break;

				 /*
				  * Only shrink ria_end_idx if the matched
				  * LDLM lock doesn't cover more.
				  */
				if (page_idx > ra.cra_end_idx) {
					ria->ria_end_idx = ra.cra_end_idx;
					break;
				}

				CDEBUG(D_READA, "idx: %lu, ra: %lu, rpc: %lu\n",
				       page_idx, ra.cra_end_idx,
				       ra.cra_rpc_pages);
				LASSERTF(ra.cra_end_idx >= page_idx,
					 "object: %px, indcies %lu / %lu\n",
					 io->ci_obj, ra.cra_end_idx, page_idx);
				/* update read ahead RPC size.
				 * NB: it's racy but doesn't matter
				 */
				if (ras->ras_rpc_pages != ra.cra_rpc_pages &&
				    ra.cra_rpc_pages > 0)
					ras->ras_rpc_pages = ra.cra_rpc_pages;
				if (!skip_index) {
					/* trim (align with optimal RPC size) */
					end_idx = ras_align(ras,
							ria->ria_end_idx + 1);
					if (end_idx > 0 && !ria->ria_eof)
						ria->ria_end_idx = end_idx - 1;
				}
				if (ria->ria_end_idx < ria->ria_end_idx_min)
					ria->ria_end_idx = ria->ria_end_idx_min;
			}
			if (page_idx > ria->ria_end_idx)
				break;

			/* If the page is inside the read-ahead window */
			rc = ll_read_ahead_page(env, io, queue, page_idx,
						MAYNEED);
			if (rc < 0 && rc != -EBUSY)
				break;
			if (rc == -EBUSY) {
				busy_page_count++;
				CDEBUG(D_READA,
				       "skip busy page: %lu\n", page_idx);
				/* For page unaligned readahead the first
				 * last pages of each region can be read by
				 * another reader on the same node, and so
				 * may be busy. So only stop for > 2 busy
				 * pages.
				 */
				if (busy_page_count > 2)
					break;
			}

			*ra_end = page_idx;
			/* Only subtract from reserve & count the page if we
			 * really did readahead on that page.
			 */
			if (rc == 0) {
				ria->ria_reserved--;
				count++;
			}
		} else if (stride_io_mode(ras)) {
			/* If it is not in the read-ahead window, and it is
			 * read-ahead mode, then check whether it should skip
			 * the stride gap.
			 */
			loff_t pos = (loff_t)page_idx << PAGE_SHIFT;
			u64 offset;

			div64_u64_rem(pos - ria->ria_stoff, ria->ria_length,
				      &offset);
			if (offset >= ria->ria_bytes) {
				pos += (ria->ria_length - offset);
				if ((pos >> PAGE_SHIFT) >= page_idx + 1)
					page_idx = (pos >> PAGE_SHIFT) - 1;
				busy_page_count = 0;
				CDEBUG(D_READA,
				       "Stride: jump %llu pages to %lu\n",
				       ria->ria_length - offset, page_idx);
				continue;
			}
		}
	}

	cl_read_ahead_release(env, &ra);

	if (count)
		ll_ra_stats_add(vvp_object_inode(io->ci_obj),
				RA_STAT_READAHEAD_PAGES, count);

	return count;
}

static void ll_readahead_work_free(struct ll_readahead_work *work)
{
	fput(work->lrw_file);
	OBD_FREE_PTR(work);
}

static void ll_readahead_handle_work(struct work_struct *wq);
static void ll_readahead_work_add(struct inode *inode,
				  struct ll_readahead_work *work)
{
	INIT_WORK(&work->lrw_readahead_work, ll_readahead_handle_work);
	queue_work(ll_i2sbi(inode)->ll_ra_info.ll_readahead_wq,
		   &work->lrw_readahead_work);
}

static int ll_readahead_file_kms(const struct lu_env *env,
				struct cl_io *io, __u64 *kms)
{
	struct cl_object *clob;
	struct inode *inode;
	struct cl_attr *attr = vvp_env_thread_attr(env);
	int ret;

	clob = io->ci_obj;
	inode = vvp_object_inode(clob);

	cl_object_attr_lock(clob);
	ret = cl_object_attr_get(env, clob, attr);
	cl_object_attr_unlock(clob);

	if (ret != 0)
		RETURN(ret);

	*kms = attr->cat_kms;
	return 0;
}

static void ll_readahead_handle_work(struct work_struct *wq)
{
	struct ll_readahead_work *work;
	struct lu_env *env;
	__u16 refcheck;
	struct ra_io_arg *ria;
	struct inode *inode;
	struct ll_file_data *lfd;
	struct ll_readahead_state *ras;
	struct cl_io *io;
	struct cl_2queue *queue;
	pgoff_t ra_end_idx = 0;
	unsigned long pages, pages_min = 0;
	struct file *file;
	__u64 kms;
	int rc;
	pgoff_t eof_index;
	struct ll_sb_info *sbi;
	struct ll_inode_info *lli;

	work = container_of(wq, struct ll_readahead_work,
			    lrw_readahead_work);
	lfd = work->lrw_file->private_data;
	ras = &lfd->fd_ras;
	file = work->lrw_file;
	inode = file_inode(file);
	sbi = ll_i2sbi(inode);
	lli = ll_i2info(inode);

	CDEBUG(D_READA|D_IOTRACE,
	       "%s:"DFID": async ra from %lu to %lu triggered by user pid %d\n",
	       file_dentry(file)->d_name.name, PFID(ll_inode2fid(inode)),
	       work->lrw_start_idx, work->lrw_end_idx, work->lrw_user_pid);

	env = cl_env_alloc(&refcheck, LCT_NOREF);
	if (IS_ERR(env))
		GOTO(out_free_work, rc = PTR_ERR(env));

	io = vvp_env_thread_io(env);
	ll_io_init(io, file, CIT_READ, NULL);

	rc = ll_readahead_file_kms(env, io, &kms);
	if (rc != 0)
		GOTO(out_put_env, rc);

	if (kms == 0) {
		ll_ra_stats_inc(inode, RA_STAT_ZERO_LEN);
		GOTO(out_put_env, rc = 0);
	}

	ria = &ll_env_info(env)->lti_ria;
	memset(ria, 0, sizeof(*ria));

	ria->ria_start_idx = work->lrw_start_idx;
	/* Truncate RA window to end of file */
	eof_index = (pgoff_t)(kms - 1) >> PAGE_SHIFT;
	if (eof_index <= work->lrw_end_idx) {
		work->lrw_end_idx = eof_index;
		ria->ria_eof = true;
	}
	if (work->lrw_end_idx <= work->lrw_start_idx)
		GOTO(out_put_env, rc = 0);

	ria->ria_end_idx = work->lrw_end_idx;
	pages = ria->ria_end_idx - ria->ria_start_idx + 1;
	ria->ria_reserved = ll_ra_count_get(sbi, ria,
					    ria_page_count(ria), pages_min);

	CDEBUG(D_READA,
	       "async reserved pages: %lu/%lu/%lu, ra_cur %d, ra_max %lu\n",
	       ria->ria_reserved, pages, pages_min,
	       atomic_read(&ll_i2sbi(inode)->ll_ra_info.ra_cur_pages),
	       ll_i2sbi(inode)->ll_ra_info.ra_max_pages);

	if (ria->ria_reserved < pages) {
		ll_ra_stats_inc(inode, RA_STAT_MAX_IN_FLIGHT);
		if (PAGES_TO_MiB(ria->ria_reserved) < 1) {
			ll_ra_count_put(ll_i2sbi(inode), ria->ria_reserved);
			GOTO(out_put_env, rc = 0);
		}
	}

	rc = cl_io_rw_init(env, io, CIT_READ, ria->ria_start_idx, pages);
	if (rc)
		GOTO(out_put_env, rc);

	/* overwrite jobid inited in vvp_io_init() */
	write_seqlock(&lli->lli_jobinfo_seqlock);
	memcpy(&lli->lli_jobinfo, &work->lrw_jobinfo, sizeof(lli->lli_jobinfo));
	write_sequnlock(&lli->lli_jobinfo_seqlock);

	vvp_env_io(env)->vui_fd = lfd;
	io->ci_state = CIS_LOCKED;
	io->ci_async_readahead = true;
	rc = cl_io_start(env, io);
	if (rc)
		GOTO(out_io_fini, rc);

	queue = &io->ci_queue;
	cl_2queue_init(queue);

	rc = ll_read_ahead_pages(env, io, &queue->c2_qin, ras, ria,
				 &ra_end_idx, 0);
	if (ria->ria_reserved != 0)
		ll_ra_count_put(ll_i2sbi(inode), ria->ria_reserved);
	if (queue->c2_qin.pl_nr > 0) {
		int count = queue->c2_qin.pl_nr;

		rc = cl_io_submit_rw(env, io, CRT_READ, queue);
		if (rc == 0)
			task_io_account_read(PAGE_SIZE * count);
	}
	if (ria->ria_end_idx == ra_end_idx && ra_end_idx == (kms >> PAGE_SHIFT))
		ll_ra_stats_inc(inode, RA_STAT_EOF);

	if (ra_end_idx != ria->ria_end_idx)
		ll_ra_stats_inc(inode, RA_STAT_FAILED_REACH_END);

	/* TODO: discard all pages until page reinit route is implemented */
	cl_page_list_discard(env, io, &queue->c2_qin);

	/* Unlock unsent read pages in case of error. */
	cl_page_list_disown(env, &queue->c2_qin);

	cl_2queue_fini(env, queue);
out_io_fini:
	cl_io_end(env, io);
	cl_io_fini(env, io);
out_put_env:
	cl_env_put(env, &refcheck);
out_free_work:
	if (ra_end_idx > 0)
		ll_ra_stats_inc_sbi(ll_i2sbi(inode), RA_STAT_ASYNC);
	atomic_dec(&sbi->ll_ra_info.ra_async_inflight);
	ll_readahead_work_free(work);
}

static int ll_readahead(const struct lu_env *env, struct cl_io *io,
			struct cl_page_list *queue,
			struct ll_readahead_state *ras, bool hit,
			struct file *file, pgoff_t skip_index,
			pgoff_t *start_idx)
{
	struct vvp_io *vio = vvp_env_io(env);
	struct ll_thread_info *lti = ll_env_info(env);
	unsigned long pages, pages_min = 0;
	pgoff_t ra_end_idx = 0, end_idx = 0;
	struct inode *inode;
	struct ra_io_arg *ria = &lti->lti_ria;
	struct cl_object *clob;
	int ret = 0;
	__u64 kms;
	struct ll_sb_info *sbi;
	struct ll_ra_info *ra;

	ENTRY;

	clob = io->ci_obj;
	inode = vvp_object_inode(clob);
	sbi = ll_i2sbi(inode);
	ra = &sbi->ll_ra_info;

	/*
	 * In case we have a limited max_cached_mb, readahead
	 * should be stopped if it have run out of all LRU slots.
	 */
	if (atomic_read(&ra->ra_cur_pages) >= sbi->ll_cache->ccc_lru_max) {
		ll_ra_stats_inc(inode, RA_STAT_MAX_IN_FLIGHT);
		RETURN(0);
	}

	memset(ria, 0, sizeof(*ria));
	ret = ll_readahead_file_kms(env, io, &kms);
	if (ret != 0)
		RETURN(ret);

	if (kms == 0) {
		ll_ra_stats_inc(inode, RA_STAT_ZERO_LEN);
		RETURN(0);
	}

	spin_lock(&ras->ras_lock);

	/*
	 * Note: other thread might rollback the ras_next_readahead_idx,
	 * if it can not get the full size of prepared pages, see the
	 * end of this function. For stride read ahead, it needs to
	 * make sure the offset is no less than ras_stride_offset,
	 * so that stride read ahead can work correctly.
	 */
	if (stride_io_mode(ras))
		*start_idx = max_t(pgoff_t, ras->ras_next_readahead_idx,
				  ras->ras_stride_offset >> PAGE_SHIFT);
	else
		*start_idx = ras->ras_next_readahead_idx;

	if (ras->ras_window_pages > 0)
		end_idx = ras->ras_window_start_idx + ras->ras_window_pages - 1;

	if (skip_index)
		end_idx = *start_idx + ras->ras_window_pages - 1;

	/* Enlarge the RA window to encompass the full read */
	if (vio->vui_ra_valid &&
	    end_idx < vio->vui_ra_start_idx + vio->vui_ra_pages - 1)
		end_idx = vio->vui_ra_start_idx + vio->vui_ra_pages - 1;

	if (end_idx != 0) {
		pgoff_t eof_index;

		/* Truncate RA window to end of file */
		eof_index = (pgoff_t)((kms - 1) >> PAGE_SHIFT);
		if (eof_index <= end_idx) {
			end_idx = eof_index;
			ria->ria_eof = true;
		}
	}
	ria->ria_start_idx = *start_idx;
	ria->ria_end_idx = end_idx;
	/* If stride I/O mode is detected, get stride window*/
	if (stride_io_mode(ras)) {
		ria->ria_stoff = ras->ras_stride_offset;
		ria->ria_length = ras->ras_stride_length;
		ria->ria_bytes = ras->ras_stride_bytes;
	}
	spin_unlock(&ras->ras_lock);

	pages = ria_page_count(ria);

	RAS_CDEBUG(ras);
	CDEBUG(D_READA,
	       DFID": ria: %lu/%lu, bead: %lu/%lu, pages %lu, hit: %d\n",
	       PFID(lu_object_fid(&clob->co_lu)),
	       ria->ria_start_idx, ria->ria_end_idx,
	       vio->vui_ra_valid ? vio->vui_ra_start_idx : 0,
	       vio->vui_ra_valid ? vio->vui_ra_pages : 0,
	       pages, hit);

	if (end_idx == 0) {
		ll_ra_stats_inc(inode, RA_STAT_ZERO_WINDOW);
		RETURN(0);
	}
	if (pages == 0) {
		ll_ra_stats_inc(inode, RA_STAT_ZERO_WINDOW);
		RETURN(0);
	}

	/* at least to extend the readahead window to cover current read */
	if (!hit && vio->vui_ra_valid &&
	    vio->vui_ra_start_idx + vio->vui_ra_pages > ria->ria_start_idx) {
		ria->ria_end_idx_min =
			vio->vui_ra_start_idx + vio->vui_ra_pages - 1;
		pages_min = vio->vui_ra_start_idx + vio->vui_ra_pages -
				ria->ria_start_idx;
		 /*
		  * For performance reason, exceeding @ra_max_pages
		  * are allowed, but this should be limited with RPC
		  * size in case a large block size read issued. Trim
		  * to RPC boundary.
		  */
		pages_min = min(pages_min, ras->ras_rpc_pages -
				(ria->ria_start_idx % ras->ras_rpc_pages));
	}

	/* don't over reserved for mmap range read */
	if (skip_index)
		pages_min = 0;
	if (pages_min > pages)
		pages = pages_min;
	ria->ria_reserved = ll_ra_count_get(ll_i2sbi(inode), ria, pages,
					    pages_min);
	if (ria->ria_reserved < pages)
		ll_ra_stats_inc(inode, RA_STAT_MAX_IN_FLIGHT);

	CDEBUG(D_READA, "reserved pages: %lu/%lu/%lu, ra_cur %d, ra_max %lu\n",
	       ria->ria_reserved, pages, pages_min,
	       atomic_read(&ll_i2sbi(inode)->ll_ra_info.ra_cur_pages),
	       ll_i2sbi(inode)->ll_ra_info.ra_max_pages);

	ret = ll_read_ahead_pages(env, io, queue, ras, ria, &ra_end_idx,
				  skip_index);
	if (ria->ria_reserved != 0)
		ll_ra_count_put(ll_i2sbi(inode), ria->ria_reserved);

	if (ra_end_idx == end_idx && ra_end_idx == (kms >> PAGE_SHIFT))
		ll_ra_stats_inc(inode, RA_STAT_EOF);

	CDEBUG(D_READA,
	       "ra_end_idx = %lu end_idx = %lu stride end = %lu pages = %d\n",
	       ra_end_idx, end_idx, ria->ria_end_idx, ret);

	if (ra_end_idx != end_idx)
		ll_ra_stats_inc(inode, RA_STAT_FAILED_REACH_END);
	if (ra_end_idx > 0) {
		/* update the ras so that the next read-ahead tries from
		 * where we left off.
		 */
		spin_lock(&ras->ras_lock);
		ras->ras_next_readahead_idx = ra_end_idx + 1;
		spin_unlock(&ras->ras_lock);
		RAS_CDEBUG(ras);
	}

	RETURN(ret);
}

static int ll_readpages(const struct lu_env *env, struct cl_io *io,
			struct cl_page_list *queue,
			pgoff_t start, pgoff_t end)
{
	int ret = 0;
	__u64 kms;
	pgoff_t page_idx;
	int count = 0;

	ENTRY;

	ret = ll_readahead_file_kms(env, io, &kms);
	if (ret != 0)
		RETURN(ret);

	if (kms == 0)
		RETURN(0);

	if (end != 0) {
		unsigned long end_index;

		end_index = (unsigned long)((kms - 1) >> PAGE_SHIFT);
		if (end_index <= end)
			end = end_index;
	}

	for (page_idx = start; page_idx <= end; page_idx++) {
		ret = ll_read_ahead_page(env, io, queue, page_idx,
					WILLNEED);
		if (ret < 0)
			break;
		else if (ret == 0) /* ret 1 is already uptodate */
			count++;
	}

	RETURN(count > 0 ? count : ret);
}

/* called with the ras_lock held or from places where it doesn't matter */
static void ras_reset(struct ll_readahead_state *ras, pgoff_t index)
{
	ras->ras_consecutive_requests = 0;
	ras->ras_consecutive_bytes = 0;
	ras->ras_window_pages = 0;
	ras->ras_window_start_idx = ras_align(ras, index);
	ras->ras_next_readahead_idx = max(ras->ras_window_start_idx, index + 1);

	RAS_CDEBUG(ras);
}

/* called with the ras_lock held or from places where it doesn't matter */
static void ras_stride_reset(struct ll_readahead_state *ras)
{
	ras->ras_consecutive_stride_requests = 0;
	ras->ras_stride_length = 0;
	ras->ras_stride_bytes = 0;
	RAS_CDEBUG(ras);
}

void ll_readahead_init(struct inode *inode, struct ll_readahead_state *ras)
{
	spin_lock_init(&ras->ras_lock);
	ras->ras_rpc_pages = PTLRPC_MAX_BRW_PAGES;
	ras_reset(ras, 0);
	ras->ras_last_read_end_bytes = 0;
	ras->ras_requests = 0;
	ras->ras_range_min_start_idx = 0;
	ras->ras_range_max_end_idx = 0;
	ras->ras_range_requests = 0;
	ras->ras_last_range_pages = 0;
}

/*
 * Check whether the read request is in the stride window.
 * If it is in the stride window, return true, otherwise return false.
 */
static bool read_in_stride_window(struct ll_readahead_state *ras,
				  loff_t pos, loff_t bytes)
{
	loff_t stride_gap;

	if (ras->ras_stride_length == 0 || ras->ras_stride_bytes == 0 ||
	    ras->ras_stride_bytes == ras->ras_stride_length)
		return false;

	stride_gap = pos - ras->ras_last_read_end_bytes - 1;

	/* If it is contiguous read */
	if (stride_gap == 0)
		return ras->ras_consecutive_bytes + bytes <=
			ras->ras_stride_bytes;

	/* Otherwise check the stride by itself */
	return (ras->ras_stride_length - ras->ras_stride_bytes) == stride_gap &&
		ras->ras_consecutive_bytes == ras->ras_stride_bytes &&
		bytes <= ras->ras_stride_bytes;
}

static void ras_init_stride_detector(struct ll_readahead_state *ras,
				     loff_t pos, loff_t bytes)
{
	loff_t stride_gap = pos - ras->ras_last_read_end_bytes - 1;

	LASSERT(ras->ras_consecutive_stride_requests == 0);

	if (pos <= ras->ras_last_read_end_bytes) {
		/* Reset stride window for forward read */
		ras_stride_reset(ras);
		return;
	}

	ras->ras_stride_bytes = ras->ras_consecutive_bytes;
	ras->ras_stride_length = stride_gap + ras->ras_consecutive_bytes;
	ras->ras_consecutive_stride_requests++;
	ras->ras_stride_offset = pos;

	RAS_CDEBUG(ras);
}

static unsigned long
stride_page_count(struct ll_readahead_state *ras, loff_t len)
{
	loff_t bytes_count =
		stride_byte_count(ras->ras_stride_offset,
				  ras->ras_stride_length, ras->ras_stride_bytes,
				  ras->ras_window_start_idx << PAGE_SHIFT, len);

	return (bytes_count + PAGE_SIZE - 1) >> PAGE_SHIFT;
}

/* Stride Read-ahead window will be increased inc_len according to
 * stride I/O pattern
 */
static void ras_stride_increase_window(struct ll_readahead_state *ras,
				       struct ll_ra_info *ra, loff_t inc_bytes)
{
	loff_t window_bytes, stride_bytes;
	u64 left_bytes;
	u64 step;
	loff_t end;

	/* temporarily store in page units to reduce LASSERT() cost below */
	end = ras->ras_window_start_idx + ras->ras_window_pages;

	LASSERT(ras->ras_stride_length > 0);
	LASSERTF(end >= (ras->ras_stride_offset >> PAGE_SHIFT),
		 "window_start_idx %lu, window_pages %lu stride_offset %llu\n",
		 ras->ras_window_start_idx, ras->ras_window_pages,
		 ras->ras_stride_offset);

	end <<= PAGE_SHIFT;
	if (end <= ras->ras_stride_offset)
		stride_bytes = 0;
	else
		stride_bytes = end - ras->ras_stride_offset;

	div64_u64_rem(stride_bytes, ras->ras_stride_length, &left_bytes);
	window_bytes = (ras->ras_window_pages << PAGE_SHIFT);
	if (left_bytes < ras->ras_stride_bytes) {
		if (ras->ras_stride_bytes - left_bytes >= inc_bytes) {
			window_bytes += inc_bytes;
			goto out;
		} else {
			window_bytes += (ras->ras_stride_bytes - left_bytes);
			inc_bytes -= (ras->ras_stride_bytes - left_bytes);
		}
	} else {
		window_bytes += (ras->ras_stride_length - left_bytes);
	}

	LASSERT(ras->ras_stride_bytes != 0);

	step = div64_u64_rem(inc_bytes, ras->ras_stride_bytes, &left_bytes);

	window_bytes += step * ras->ras_stride_length + left_bytes;
	LASSERT(window_bytes > 0);

out:
	if (stride_page_count(ras, window_bytes) <=
	    ra->ra_max_pages_per_file || ras->ras_window_pages == 0)
		ras->ras_window_pages = (window_bytes >> PAGE_SHIFT);

	LASSERT(ras->ras_window_pages > 0);

	RAS_CDEBUG(ras);
}

static void ras_increase_window(struct inode *inode,
				struct ll_readahead_state *ras,
				struct ll_ra_info *ra)
{
	/* The stretch of ra-window should be aligned with max rpc_size
	 * but current clio architecture does not support retrieve such
	 * information from lower layer. FIXME later
	 */
	if (stride_io_mode(ras)) {
		ras_stride_increase_window(ras, ra,
				      (loff_t)ras->ras_rpc_pages << PAGE_SHIFT);
	} else {
		pgoff_t window_pages;

		window_pages = min(ras->ras_window_pages + ras->ras_rpc_pages,
				   ra->ra_max_pages_per_file);
		if (window_pages < ras->ras_rpc_pages)
			ras->ras_window_pages = window_pages;
		else
			ras->ras_window_pages = ras_align(ras, window_pages);
	}
}

/*
 * Seek within 8 pages are considered as sequential read for now.
 */
static inline bool is_loose_seq_read(struct ll_readahead_state *ras, loff_t pos)
{
	return pos_in_window(pos, ras->ras_last_read_end_bytes,
			     8UL << PAGE_SHIFT, 8UL << PAGE_SHIFT);
}

static inline bool is_loose_mmap_read(struct ll_sb_info *sbi,
				      struct ll_readahead_state *ras,
				      unsigned long pos)
{
	unsigned long range_pages = sbi->ll_ra_info.ra_range_pages;

	return pos_in_window(pos, ras->ras_last_read_end_bytes,
			     range_pages << PAGE_SHIFT,
			     range_pages << PAGE_SHIFT);
}

/*
 * We have observed slow mmap read performances for some
 * applications. The problem is if access pattern is neither
 * sequential nor stride, but could be still adjacent in a
 * small range and then seek a random position.
 *
 * So the pattern could be something like this:
 *
 * [1M data] [hole] [0.5M data] [hole] [0.7M data] [1M data]
 *
 *
 * Every time an application reads mmap data, it may not only
 * read a single 4KB page, but aslo a cluster of nearby pages in
 * a range(e.g. 1MB) of the first page after a cache miss.
 *
 * The readahead engine is modified to track the range size of
 * a cluster of mmap reads, so that after a seek and/or cache miss,
 * the range size is used to efficiently prefetch multiple pages
 * in a single RPC rather than many small RPCs.
 */
static void ras_detect_cluster_range(struct ll_readahead_state *ras,
				     struct ll_sb_info *sbi,
				     unsigned long pos, unsigned long count)
{
	pgoff_t last_pages, pages;
	pgoff_t end_idx = (pos + count - 1) >> PAGE_SHIFT;

	last_pages = ras->ras_range_max_end_idx -
			ras->ras_range_min_start_idx + 1;
	/* First time come here */
	if (!ras->ras_range_max_end_idx)
		goto out;

	/* Random or Stride read */
	if (!is_loose_mmap_read(sbi, ras, pos))
		goto out;

	ras->ras_range_requests++;
	if (ras->ras_range_max_end_idx < end_idx)
		ras->ras_range_max_end_idx = end_idx;

	if (ras->ras_range_min_start_idx > (pos >> PAGE_SHIFT))
		ras->ras_range_min_start_idx = pos >> PAGE_SHIFT;

	/* Out of range, consider it as random or stride */
	pages = ras->ras_range_max_end_idx -
			ras->ras_range_min_start_idx + 1;
	if (pages <= sbi->ll_ra_info.ra_range_pages)
		return;
out:
	ras->ras_last_range_pages = last_pages;
	ras->ras_range_requests = 0;
	ras->ras_range_min_start_idx = pos >> PAGE_SHIFT;
	ras->ras_range_max_end_idx = end_idx;
}

static void ras_detect_read_pattern(struct ll_readahead_state *ras,
				    struct ll_sb_info *sbi,
				    loff_t pos, size_t bytes, bool mmap)
{
	bool stride_detect = false;
	pgoff_t index = pos >> PAGE_SHIFT;

	RAS_CDEBUG(ras);
	/*
	 * Reset the read-ahead window in two cases. First when the app seeks
	 * or reads to some other part of the file. Secondly if we get a
	 * read-ahead miss that we think we've previously issued. This can
	 * be a symptom of there being so many read-ahead pages that the VM
	 * is reclaiming it before we get to it.
	 */
	if (!is_loose_seq_read(ras, pos)) {
		/* Check whether it is in stride I/O mode */
		if (!read_in_stride_window(ras, pos, bytes)) {
			if (ras->ras_consecutive_stride_requests == 0)
				ras_init_stride_detector(ras, pos, bytes);
			else
				ras_stride_reset(ras);
			ras->ras_consecutive_bytes = 0;
			ras_reset(ras, index);
		} else {
			ras->ras_consecutive_bytes = 0;
			ras->ras_consecutive_requests = 0;
			if (++ras->ras_consecutive_stride_requests > 1)
				stride_detect = true;
			RAS_CDEBUG(ras);
		}
		ll_ra_stats_inc_sbi(sbi, RA_STAT_DISTANT_READPAGE);
	} else if (stride_io_mode(ras)) {
		/*
		 * If this is contiguous read but in stride I/O mode
		 * currently, check whether stride step still is valid,
		 * if invalid, it will reset the stride ra window to
		 * be zero.
		 */
		if (!read_in_stride_window(ras, pos, bytes)) {
			ras_stride_reset(ras);
			ras->ras_window_pages = 0;
			ras->ras_next_readahead_idx = index;
		}
	}

	ras->ras_consecutive_bytes += bytes;
	if (mmap) {
		pgoff_t idx = ras->ras_consecutive_bytes >> PAGE_SHIFT;
		unsigned long ra_range_pages =
				max_t(unsigned long, RA_MIN_MMAP_RANGE_PAGES,
				      sbi->ll_ra_info.ra_range_pages);

		if ((idx >= ra_range_pages &&
		     idx % ra_range_pages == 0) || stride_detect)
			ras->ras_need_increase_window = true;
	} else if ((ras->ras_consecutive_requests > 1 || stride_detect)) {
		ras->ras_need_increase_window = true;
	}

	ras->ras_last_read_end_bytes = pos + bytes - 1;
	RAS_CDEBUG(ras);
}

void ll_ras_enter(struct file *f, loff_t pos, size_t bytes)
{
	struct ll_file_data *lfd = f->private_data;
	struct ll_readahead_state *ras = &lfd->fd_ras;
	struct inode *inode = file_inode(f);
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	spin_lock(&ras->ras_lock);
	ras->ras_requests++;
	ras->ras_consecutive_requests++;
	ras->ras_need_increase_window = false;
	ras->ras_whole_file_read = false;
	/*
	 * On the second access to a file smaller than the tunable
	 * ra_max_read_ahead_whole_pages trigger RA on all pages in the
	 * file up to ra_max_pages_per_file.  This is simply a best effort
	 * and only occurs once per open file. Normal RA behavior is reverted
	 * to for subsequent IO.
	 */
	if (ras->ras_requests >= 2) {
		__u64 kms_pages;
		struct ll_ra_info *ra = &sbi->ll_ra_info;

		kms_pages = (i_size_read(inode) + PAGE_SIZE - 1) >>
			    PAGE_SHIFT;

		CDEBUG(D_READA, "kmsp %llu mwp %lu mp %lu\n", kms_pages,
		       ra->ra_max_read_ahead_whole_pages,
		       ra->ra_max_pages_per_file);

		if (kms_pages &&
		    kms_pages <= ra->ra_max_read_ahead_whole_pages) {
			ras->ras_whole_file_read = true;
			ras->ras_window_start_idx = 0;
			ras->ras_next_readahead_idx = 0;
			ras->ras_window_pages = min(ra->ra_max_pages_per_file,
					    ra->ra_max_read_ahead_whole_pages);
			GOTO(out_unlock, 0);
		}
	}
	ras_detect_read_pattern(ras, sbi, pos, bytes, false);
out_unlock:
	spin_unlock(&ras->ras_lock);
}

static bool index_in_stride_window(struct ll_readahead_state *ras,
				   pgoff_t index)
{
	loff_t pos = (loff_t)index << PAGE_SHIFT;

	if (ras->ras_stride_length == 0 || ras->ras_stride_bytes == 0 ||
	    ras->ras_stride_bytes == ras->ras_stride_length)
		return false;

	if (pos >= ras->ras_stride_offset) {
		u64 offset;

		div64_u64_rem(pos - ras->ras_stride_offset,
			      ras->ras_stride_length, &offset);
		if (offset < ras->ras_stride_bytes ||
		    ras->ras_stride_length - offset < PAGE_SIZE)
			return true;
	} else if (ras->ras_stride_offset - pos < PAGE_SIZE) {
		return true;
	}

	return false;
}

/*
 * ll_ras_enter() is used to detect read pattern according to pos and count.
 *
 * ras_update() is used to detect cache miss and
 * reset window or increase window accordingly
 */
static void ras_update(struct ll_sb_info *sbi, struct inode *inode,
		       struct ll_readahead_state *ras, pgoff_t index,
		       enum ras_update_flags flags, struct cl_io *io)
{
	struct ll_ra_info *ra = &sbi->ll_ra_info;
	bool hit = flags & LL_RAS_HIT;

	ENTRY;
	spin_lock(&ras->ras_lock);

	RAS_CDEBUG(ras);

	if (!hit)
		CDEBUG(D_READA|D_IOTRACE, DFID " pages at %lu miss.\n",
		       PFID(ll_inode2fid(inode)), index);
	ll_ra_stats_inc_sbi(sbi, hit ? RA_STAT_HIT : RA_STAT_MISS);

	/*
	 * The readahead window has been expanded to cover whole
	 * file size, we don't care whether ra miss happen or not.
	 * Because we will read whole file to page cache even if
	 * some pages missed.
	 */
	if (ras->ras_whole_file_read)
		GOTO(out_unlock, 0);

	if (io && io->ci_rand_read)
		GOTO(out_unlock, 0);

	if (io && io->ci_seq_read) {
		if (!hit) {
			/* to avoid many small read RPC here */
			ras->ras_window_pages = sbi->ll_ra_info.ra_range_pages;
			ll_ra_stats_inc_sbi(sbi, RA_STAT_MMAP_RANGE_READ);
		}
		goto skip_miss_checking;
	}

	if (flags & LL_RAS_MMAP) {
		unsigned long ra_pages;

		ras_detect_cluster_range(ras, sbi, index << PAGE_SHIFT,
					 PAGE_SIZE);
		ras_detect_read_pattern(ras, sbi, (loff_t)index << PAGE_SHIFT,
					PAGE_SIZE, true);

		/* we did not detect anything but we could prefetch */
		if (!ras->ras_need_increase_window &&
		    ras->ras_window_pages <= sbi->ll_ra_info.ra_range_pages &&
		    ras->ras_range_requests >= 2) {
			if (!hit) {
				ra_pages = max_t(unsigned long,
					RA_MIN_MMAP_RANGE_PAGES,
					ras->ras_last_range_pages);
				if (index < ra_pages / 2)
					index = 0;
				else
					index -= ra_pages / 2;
				ras->ras_window_pages = ra_pages;
				ll_ra_stats_inc_sbi(sbi,
					RA_STAT_MMAP_RANGE_READ);
			} else {
				ras->ras_window_pages = 0;
			}
			goto skip_miss_checking;
		}
	}

	if (!hit && ras->ras_window_pages &&
	    index < ras->ras_next_readahead_idx &&
	    pos_in_window(index, ras->ras_window_start_idx, 0,
			  ras->ras_window_pages)) {
		ll_ra_stats_inc_sbi(sbi, RA_STAT_MISS_IN_WINDOW);
		ras->ras_need_increase_window = false;

		if (index_in_stride_window(ras, index) &&
		    stride_io_mode(ras)) {
			/*
			 * if (index != ras->ras_last_readpage + 1)
			 *	ras->ras_consecutive_pages = 0;
			 */
			ras_reset(ras, index);

			/*
			 * If stride-RA hit cache miss, the stride
			 * detector will not be reset to avoid the
			 * overhead of redetecting read-ahead mode,
			 * but on the condition that the stride window
			 * is still intersect with normal sequential
			 * read-ahead window.
			 */
			if (ras->ras_window_start_idx < ras->ras_stride_offset)
				ras_stride_reset(ras);
			RAS_CDEBUG(ras);
		} else {
			/*
			 * Reset both stride window and normal RA
			 * window.
			 */
			ras_reset(ras, index);
			/* ras->ras_consecutive_pages++; */
			ras->ras_consecutive_bytes = 0;
			ras_stride_reset(ras);
			GOTO(out_unlock, 0);
		}
	}

skip_miss_checking:
	ras->ras_window_start_idx = ras_align(ras, index);

	if (stride_io_mode(ras)) {
		/* Since stride readahead is sentivite to the offset
		 * of read-ahead, so we use original offset here,
		 * instead of ras_window_start_idx, which is RPC aligned.
		 */
		ras->ras_next_readahead_idx = max(index + 1,
						  ras->ras_next_readahead_idx);
		ras->ras_window_start_idx =
				max_t(pgoff_t, ras->ras_window_start_idx,
				      ras->ras_stride_offset >> PAGE_SHIFT);
	} else {
		if (ras->ras_next_readahead_idx < ras->ras_window_start_idx)
			ras->ras_next_readahead_idx = ras->ras_window_start_idx;
		if (!hit)
			ras->ras_next_readahead_idx = index + 1;
	}

	if (ras->ras_need_increase_window) {
		ras_increase_window(inode, ras, ra);
		ras->ras_need_increase_window = false;
	}

	EXIT;
out_unlock:
	RAS_CDEBUG(ras);
	spin_unlock(&ras->ras_lock);
}

int ll_writepage(struct page *vmpage, struct writeback_control *wbc)
{
	struct inode	       *inode = vmpage->mapping->host;
	struct ll_inode_info   *lli   = ll_i2info(inode);
	struct lu_env          *env;
	struct cl_io           *io;
	struct cl_page         *page;
	struct cl_object       *clob;
	bool redirtied = false;
	bool unlocked = false;
	int result;
	__u16 refcheck;

	ENTRY;

	LASSERT(PageLocked(vmpage));
	LASSERT(!PageWriteback(vmpage));

	LASSERT(ll_i2dtexp(inode) != NULL);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		GOTO(out, result = PTR_ERR(env));

	clob  = ll_i2info(inode)->lli_clob;
	LASSERT(clob != NULL);

	io = vvp_env_thread_io(env);
	io->ci_obj = clob;
	io->ci_ignore_layout = 1;
	result = cl_io_init(env, io, CIT_MISC, clob);
	if (result == 0) {
		page = cl_page_find(env, clob, vmpage->index,
				    vmpage, CPT_CACHEABLE);
		if (!IS_ERR(page)) {
			cl_page_assume(env, io, page);
			result = cl_page_flush(env, io, page);
			if (result != 0) {
				/*
				 * Re-dirty page on error so it retries write,
				 * but not in case when IO has actually
				 * occurred and completed with an error.
				 */
				if (!PageError(vmpage)) {
					redirty_page_for_writepage(wbc, vmpage);
					result = 0;
					redirtied = true;
				}
			}
			cl_page_disown(env, io, page);
			unlocked = true;
			cl_page_put(env, page);
		} else {
			result = PTR_ERR(page);
		}
	}
	cl_io_fini(env, io);

	if (redirtied && wbc->sync_mode == WB_SYNC_ALL) {
		loff_t offset = vmpage->index << PAGE_SHIFT;

		/* Flush page failed because the extent is being written out.
		 * Wait for the write of extent to be finished to avoid
		 * breaking kernel which assumes ->writepage should mark
		 * PageWriteback or clean the page.
		 */
		result = cl_sync_file_range(inode, offset,
					    offset + PAGE_SIZE - 1,
					    CL_FSYNC_LOCAL, 1);
		if (result > 0) {
			/* May have written more than one page. decreasing this
			 * page because the caller will count it.
			 */
			wbc->nr_to_write -= result - 1;
			result = 0;
		}
	}

	cl_env_put(env, &refcheck);
	GOTO(out, result);

out:
	if (result < 0) {
		if (!lli->lli_async_rc)
			lli->lli_async_rc = result;
		SetPageError(vmpage);
		if (!unlocked)
			unlock_page(vmpage);
	}
	return result;
}

int ll_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	loff_t start;
	loff_t end;
	enum cl_fsync_mode mode;
	int range_whole = 0;
	int result;

	ENTRY;

	if (wbc->range_cyclic) {
		start = (loff_t)mapping->writeback_index << PAGE_SHIFT;
		end = OBD_OBJECT_EOF;
	} else {
		start = wbc->range_start;
		end = wbc->range_end;
		if (end == LLONG_MAX) {
			end = OBD_OBJECT_EOF;
			range_whole = start == 0;
		}
	}

	mode = CL_FSYNC_NONE;
	if (wbc->sync_mode == WB_SYNC_ALL)
		mode = CL_FSYNC_LOCAL;

	if (wbc->sync_mode == WB_SYNC_NONE) {
#ifdef SB_I_CGROUPWB
		struct bdi_writeback *wb;

		/*
		 * As it may break full stripe writes on the inode,
		 * disable periodic kupdate writeback (@wbc->for_kupdate)?
		 */

		/*
		 * The system is under memory pressure and it is now reclaiming
		 * cache pages.
		 */
		wb = inode_to_wb(inode);
		if (wbc->for_background ||
		    (wb->start_all_reason == WB_REASON_VMSCAN &&
		     test_bit(WB_start_all, &wb->state)))
			mode = CL_FSYNC_RECLAIM;
#else
		/*
		 * We have no idea about writeback reason for memory reclaim
		 * WB_REASON_TRY_TO_FREE_PAGES in the old kernel such as rhel7
		 * (WB_REASON_VMSCAN in the newer kernel) ...
		 * Here set mode with CL_FSYNC_RECLAIM forcely on the old
		 * kernel.
		 */
		if (!wbc->for_kupdate)
			mode = CL_FSYNC_RECLAIM;
#endif
	}

	if (ll_i2info(inode)->lli_clob == NULL || (inode->i_state & I_FREEING))
		RETURN(0);

	/* for directio, it would call writepages() to evict cached pages
	 * inside the IO context of write, which will cause deadlock at
	 * layout_conf since it waits for active IOs to complete.
	 */
	result = cl_sync_file_range(inode, start, end, mode, 1);
	if (result > 0) {
		wbc->nr_to_write -= result;
		result = 0;
	}

	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0)) {
		if (end == OBD_OBJECT_EOF)
			mapping->writeback_index = 0;
		else
			mapping->writeback_index = (end >> PAGE_SHIFT) + 1;
	}
	RETURN(result);
}

struct ll_cl_context *ll_cl_find(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_cl_context *lcc;
	struct ll_cl_context *found = NULL;

	read_lock(&lli->lli_lock);
	list_for_each_entry(lcc, &lli->lli_lccs, lcc_list) {
		if (lcc->lcc_cookie == current) {
			found = lcc;
			break;
		}
	}
	read_unlock(&lli->lli_lock);

	return found;
}

void ll_cl_add(struct inode *inode, const struct lu_env *env, struct cl_io *io,
	       enum lcc_type type)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_cl_context *lcc = &ll_env_info(env)->lti_io_ctx;

	memset(lcc, 0, sizeof(*lcc));
	INIT_LIST_HEAD(&lcc->lcc_list);
	lcc->lcc_cookie = current;
	lcc->lcc_env = env;
	lcc->lcc_io = io;
	lcc->lcc_type = type;

	write_lock(&lli->lli_lock);
	list_add(&lcc->lcc_list, &lli->lli_lccs);
	write_unlock(&lli->lli_lock);
}

void ll_cl_remove(struct inode *inode, const struct lu_env *env)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_cl_context *lcc = &ll_env_info(env)->lti_io_ctx;

	write_lock(&lli->lli_lock);
	list_del_init(&lcc->lcc_list);
	write_unlock(&lli->lli_lock);
}

int ll_io_read_page(const struct lu_env *env, struct cl_io *io,
			   struct cl_page *page, struct file *file)
{
	struct inode              *inode  = vvp_object_inode(page->cp_obj);
	struct ll_sb_info         *sbi    = ll_i2sbi(inode);
	struct ll_file_data       *lfd    = NULL;
	struct ll_readahead_state *ras    = NULL;
	struct cl_2queue          *queue  = &io->ci_queue;
	struct cl_sync_io	  *anchor = NULL;
	int			   rc = 0, rc2 = 0;
	bool			   uptodate;
	struct vvp_io *vio = vvp_env_io(env);
	bool mmap = !vio->vui_ra_valid;
	pgoff_t ra_start_index = 0;
	pgoff_t io_start_index;
	pgoff_t io_end_index;
	bool unlockpage = true;

	ENTRY;

	if (file) {
		lfd = file->private_data;
		ras = &lfd->fd_ras;
	}

	/* PagePrivate2 is set in ll_io_zero_page() to tell us the vmpage
	 * must not be unlocked after processing.
	 */
	if (page->cp_vmpage && PagePrivate2(page->cp_vmpage))
		unlockpage = false;

	uptodate = page->cp_defer_uptodate;

	if (ll_readahead_enabled(sbi) && !page->cp_ra_updated && ras) {
		enum ras_update_flags flags = 0;

		if (uptodate)
			flags |= LL_RAS_HIT;
		if (mmap)
			flags |= LL_RAS_MMAP;
		ras_update(sbi, inode, ras, cl_page_index(page), flags, io);
	}

	cl_2queue_init(queue);
	if (uptodate) {
		page->cp_ra_used = 1;
		SetPageUptodate(page->cp_vmpage);
		cl_page_disown(env, io, page);
	} else {
		anchor = &vvp_env_info(env)->vti_anchor;
		cl_sync_io_init(anchor, 1);
		page->cp_sync_io = anchor;

		cl_page_list_add(&queue->c2_qin, page, true);
	}

	/* mmap does not set the ci_rw fields */
	if (!mmap) {
		io_start_index = io->u.ci_rw.crw_pos >> PAGE_SHIFT;
		io_end_index = (io->u.ci_rw.crw_pos +
				io->u.ci_rw.crw_bytes - 1) >> PAGE_SHIFT;
	} else {
		io_start_index = cl_page_index(page);
		io_end_index = cl_page_index(page);
	}

	if (ll_readahead_enabled(sbi) && ras && !io->ci_rand_read) {
		pgoff_t skip_index = 0;

		if (ras->ras_next_readahead_idx < cl_page_index(page))
			skip_index = cl_page_index(page);
		rc2 = ll_readahead(env, io, &queue->c2_qin, ras,
				   uptodate, file, skip_index,
				   &ra_start_index);
		/* Keep iotrace clean. Print only on actual page read */
		CDEBUG(D_READA | (rc2 ? D_IOTRACE : 0),
		       DFID " %d pages read ahead at %lu, triggered by user read at %lu, stride offset %lld, stride length %lld, stride bytes %lld\n",
		       PFID(ll_inode2fid(inode)), rc2, ra_start_index,
		       cl_page_index(page), ras->ras_stride_offset,
		       ras->ras_stride_length, ras->ras_stride_bytes);

	} else if (cl_page_index(page) == io_start_index &&
		   io_end_index - io_start_index > 0) {
		rc2 = ll_readpages(env, io, &queue->c2_qin, io_start_index + 1,
				   io_end_index);
		CDEBUG(D_READA, DFID " %d pages read at %lu\n",
		       PFID(ll_inode2fid(inode)), rc2, cl_page_index(page));
	}

	if (queue->c2_qin.pl_nr > 0) {
		int count = queue->c2_qin.pl_nr;

		rc = cl_io_submit_rw(env, io, CRT_READ, queue);
		if (rc == 0)
			task_io_account_read(PAGE_SIZE * count);
	}


	if (anchor != NULL && !cl_page_is_owned(page, io)) { /* have sent */
		rc = cl_sync_io_wait(env, anchor, 0);

		cl_page_assume(env, io, page);
		cl_page_list_del(env, &queue->c2_qout, page, true);

		if (!PageUptodate(cl_page_vmpage(page))) {
			/* Failed to read a mirror, discard this page so that
			 * new page can be created with new mirror.
			 *
			 * TODO: this is not needed after page reinit
			 * route is implemented
			 */
			cl_page_discard(env, io, page);
		}
		if (unlockpage)
			cl_page_disown(env, io, page);
	}

	/* TODO: discard all pages until page reinit route is implemented */
	cl_page_list_discard(env, io, &queue->c2_qin);

	/* Unlock unsent read pages in case of error. */
	cl_page_list_disown(env, &queue->c2_qin);

	cl_2queue_fini(env, queue);

	RETURN(rc);
}

/*
 * Possible return value:
 * 0 no async readahead triggered and fast read could not be used.
 * 1 no async readahead, but fast read could be used.
 * 2 async readahead triggered and fast read could be used too.
 * < 0 on error.
 */
static int kickoff_async_readahead(struct file *file, unsigned long pages)
{
	struct ll_readahead_work *lrw;
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ll_file_data *lfd = file->private_data;
	struct ll_readahead_state *ras = &lfd->fd_ras;
	struct ll_ra_info *ra = &sbi->ll_ra_info;
	unsigned long throttle;
	pgoff_t start_idx = ras_align(ras, ras->ras_next_readahead_idx);
	pgoff_t end_idx = start_idx + pages - 1;

	/*
	 * In case we have a limited max_cached_mb, readahead
	 * should be stopped if it have run out of all LRU slots.
	 */
	if (atomic_read(&ra->ra_cur_pages) >= sbi->ll_cache->ccc_lru_max) {
		ll_ra_stats_inc(inode, RA_STAT_MAX_IN_FLIGHT);
		return 0;
	}

	throttle = min(ra->ra_async_pages_per_file_threshold,
		       ra->ra_max_pages_per_file);
	/*
	 * If this is strided i/o or the window is smaller than the
	 * throttle limit, we do not do async readahead. Otherwise,
	 * we do async readahead, allowing the user thread to do fast i/o.
	 */
	if (stride_io_mode(ras) || !throttle ||
	    ras->ras_window_pages < throttle ||
	    atomic_read(&ra->ra_async_inflight) > ra->ra_async_max_active)
		return 0;

	if ((atomic_read(&ra->ra_cur_pages) + pages) > ra->ra_max_pages)
		return 0;

	if (ras->ras_async_last_readpage_idx == start_idx)
		return 1;

	/* ll_readahead_work_free() free it */
	OBD_ALLOC_PTR(lrw);
	if (lrw) {
		atomic_inc(&sbi->ll_ra_info.ra_async_inflight);
		lrw->lrw_file = get_file(file);
		lrw->lrw_start_idx = start_idx;
		lrw->lrw_end_idx = end_idx;
		lrw->lrw_user_pid = current->pid;
		spin_lock(&ras->ras_lock);
		ras->ras_next_readahead_idx = end_idx + 1;
		ras->ras_async_last_readpage_idx = start_idx;
		spin_unlock(&ras->ras_lock);
		lli_jobinfo_cpy(ll_i2info(inode), &lrw->lrw_jobinfo);

		ll_readahead_work_add(inode, lrw);
	} else {
		return -ENOMEM;
	}

	return 2;
}

/*
 * Check if we can issue a readahead RPC, if that is
 * the case, we can't do fast IO because we will need
 * a cl_io to issue the RPC.
 */
static bool ll_use_fast_io(struct file *file,
			   struct ll_readahead_state *ras, pgoff_t index)
{
	unsigned long fast_read_pages =
		max(RA_REMAIN_WINDOW_MIN, ras->ras_rpc_pages);
	loff_t skip_pages;
	loff_t stride_bytes = ras->ras_stride_bytes;

	RAS_CDEBUG(ras);

	if (stride_io_mode(ras) && stride_bytes) {
		skip_pages = (ras->ras_stride_length +
			ras->ras_stride_bytes - 1) / stride_bytes;
		skip_pages *= fast_read_pages;
	} else {
		skip_pages = fast_read_pages;
	}

	RAS_CDEBUG(ras);

	if (ras->ras_whole_file_read ||
	    ras->ras_window_start_idx + ras->ras_window_pages <
	    ras->ras_next_readahead_idx + skip_pages ||
	    kickoff_async_readahead(file, fast_read_pages) > 0) {
		return true;
	}

	return false;
}

int ll_readpage(struct file *file, struct page *vmpage)
{
	struct inode *inode = file_inode(file);
	struct cl_object *clob = ll_i2info(inode)->lli_clob;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct super_block *sb = inode->i_sb;
	const struct lu_env *env = NULL;
	struct cl_read_ahead ra = { 0 };
	struct ll_cl_context *lcc;
	struct cl_io *io = NULL;
	bool ra_assert = false;
	struct cl_page *page;
	struct vvp_io *vio;
	int result;
	int flags;

	ENTRY;

	if (CFS_FAIL_PRECHECK(OBD_FAIL_LLITE_READPAGE_PAUSE)) {
		unlock_page(vmpage);
		CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_READPAGE_PAUSE, cfs_fail_val);
		lock_page(vmpage);
	}

	/*
	 * This is not a Lustre file handle, and should be a file handle of the
	 * PCC copy. It is from PCC mmap readahead I/O path and the PCC copy
	 * was invalidated.
	 * Here return error code directly as it is from readahead I/O path for
	 * the PCC copy.
	 */
	if (inode->i_op != &ll_file_inode_operations) {
		CERROR("%s: readpage() on invalidated PCC inode %lu: rc=%d\n",
		       sb->s_id, inode->i_ino, -EIO);
		unlock_page(vmpage);
		RETURN(-EIO);
	}

	/*
	 * The @vmpage got truncated.
	 * This is a kernel bug introduced since kernel 5.12:
	 * comment: cbd59c48ae2bcadc4a7599c29cf32fd3f9b78251
	 * ("mm/filemap: use head pages in generic_file_buffered_read")
	 *
	 * The page end offset calculation in filemap_get_read_batch() was off
	 * by one.  When a read is submitted with end offset 1048575, then it
	 * calculates the end page for read of 256 where it should be 255. This
	 * results in the readpage() for the page with index 256 is over stripe
	 * boundary and may not covered by a DLM extent lock.
	 *
	 * This happens in a corner race case: filemap_get_read_batch() adds
	 * the page with index 256 for read which is not in the current read
	 * I/O context, and this page is being invalidated and will be removed
	 * from page cache due to the lock protected it being revoken. This
	 * results in this page in the read path not covered by any DLM lock.
	 *
	 * The solution is simple. Check whether the page was truncated in
	 * ->readpage(). If so, just return AOP_TRUNCATED_PAGE to the upper
	 * caller. Then the kernel will retry to batch pages, and it will not
	 * add the truncated page into batches as it was removed from page
	 * cache of the file.
	 */
	if (vmpage->mapping != inode->i_mapping) {
		unlock_page(vmpage);
		RETURN(AOP_TRUNCATED_PAGE);
	}

	lcc = ll_cl_find(inode);
	if (lcc != NULL) {
		env = lcc->lcc_env;
		io  = lcc->lcc_io;
	}

	if (io == NULL) { /* fast read */
		struct inode *inode = file_inode(file);
		struct ll_file_data *lfd = file->private_data;
		struct ll_readahead_state *ras = &lfd->fd_ras;
		struct lu_env  *local_env = NULL;

		CDEBUG(D_VFSTRACE, "fast read pgno: %ld\n", vmpage->index);

		result = -ENODATA;

		/* TODO: need to verify the layout version to make sure
		 * the page is not invalid due to layout change.
		 */
		page = cl_vmpage_page(vmpage, clob);
		if (page == NULL) {
			unlock_page(vmpage);
			CDEBUG(D_READA, "fast read: failed to find page %ld\n",
				vmpage->index);
			ll_ra_stats_inc_sbi(sbi, RA_STAT_FAILED_FAST_READ);
			RETURN(result);
		}

		if (page->cp_defer_uptodate) {
			enum ras_update_flags flags = LL_RAS_HIT;

			if (lcc && lcc->lcc_type == LCC_MMAP)
				flags |= LL_RAS_MMAP;

			/* For fast read, it updates read ahead state only
			 * if the page is hit in cache because non cache page
			 * case will be handled by slow read later.
			 */
			ras_update(sbi, inode, ras, cl_page_index(page), flags, io);
			/* avoid duplicate ras_update() call */
			page->cp_ra_updated = 1;

			if (ll_use_fast_io(file, ras, cl_page_index(page)))
				result = 0;
		}

		if (!env) {
			local_env = cl_env_percpu_get();
			env = local_env;
		}

		/* export the page and skip io stack */
		if (result == 0) {
			page->cp_ra_used = 1;
			SetPageUptodate(vmpage);
		} else {
			ll_ra_stats_inc_sbi(sbi, RA_STAT_FAILED_FAST_READ);
		}

		/* release page refcount before unlocking the page to ensure
		 * the object won't be destroyed in the calling path of
		 * cl_page_put(). Please see comment in ll_releasepage().
		 */
		cl_page_put(env, page);
		unlock_page(vmpage);
		if (local_env)
			cl_env_percpu_put(local_env);

		RETURN(result);
	}

	if (lcc && lcc->lcc_type != LCC_MMAP) {
		/*
		 * This handles a kernel bug introduced in kernel 5.12:
		 * comment: cbd59c48ae2bcadc4a7599c29cf32fd3f9b78251
		 * ("mm/filemap: use head pages in generic_file_buffered_read")
		 *
		 * See above in this function for a full description of the
		 * bug.  Briefly, the kernel will try to read 1 more page than
		 * was actually requested *if that page is already in cache*.
		 *
		 * Because this page is beyond the boundary of the requested
		 * read, Lustre does not lock it as part of the read.  This
		 * means we must check if there is a valid dlmlock on this
		 * this page and reference it before we attempt to read in the
		 * page.  If there is not a valid dlmlock, then we are racing
		 * with dlmlock cancellation and the page is being removed
		 * from the cache.
		 *
		 * That means we should return AOP_TRUNCATED_PAGE, which will
		 * cause the kernel to retry the read, which should allow the
		 * page to be removed from cache as the lock is cancelled.
		 *
		 * This should never occur except in kernels with the bug
		 * mentioned above.
		 */
		if (vmpage->index >= lcc->lcc_end_index) {
			CDEBUG(D_VFSTRACE,
			       "pgno:%ld, beyond read end_index:%ld\n",
			       vmpage->index, lcc->lcc_end_index);

			result = cl_io_read_ahead(env, io, vmpage->index, &ra);
			if (result < 0 || vmpage->index > ra.cra_end_idx) {
				cl_read_ahead_release(env, &ra);
				unlock_page(vmpage);
				RETURN(AOP_TRUNCATED_PAGE);
			}
		}
	}

	/* this is a sequence of checks verifying that kernel readahead is
	 * truly disabled
	 */
	if (lcc && lcc->lcc_type == LCC_MMAP) {
		if (io->u.ci_fault.ft_index != vmpage->index) {
			CERROR("%s: ft_index %lu, vmpage index %lu\n",
			       sbi->ll_fsname, io->u.ci_fault.ft_index,
			       vmpage->index);
			ra_assert = true;
		}
	}

	if (ra_assert || sb->s_bdi->ra_pages != 0 || file->f_ra.ra_pages != 0) {
		CERROR("%s: sbi ra pages %lu, file ra pages %d\n",
		       sbi->ll_fsname, sb->s_bdi->ra_pages,
		       file->f_ra.ra_pages);
		ra_assert = true;
	}


#ifdef HAVE_BDI_IO_PAGES
	if (ra_assert || sb->s_bdi->io_pages != 0) {
		CERROR("%s: bdi io_pages %lu\n",
		       sbi->ll_fsname, sb->s_bdi->io_pages);
		ra_assert = true;
	}
#endif
	if (ra_assert)
		LASSERT(!ra_assert);

	vio = vvp_env_io(env);
	/*
	 * Direct read can fall back to buffered read, but DIO is done
	 * with lockless i/o, and buffered requires LDLM locking, so in
	 * this case we must restart without lockless.
	 */
	flags = iocb_ki_flags_get(file, vio->vui_iocb);
	if (iocb_ki_flags_check(flags, DIRECT) &&
	    lcc && lcc->lcc_type == LCC_RW &&
	    !io->ci_dio_lock) {
		unlock_page(vmpage);
		io->ci_dio_lock = 1;
		io->ci_need_restart = 1;
		GOTO(out, result = -ENOLCK);
	}

	LASSERT(io->ci_state == CIS_IO_GOING);
	page = cl_page_find(env, clob, vmpage->index, vmpage, CPT_CACHEABLE);
	if (!IS_ERR(page)) {
		LASSERT(page->cp_type == CPT_CACHEABLE);
		if (likely(!PageUptodate(vmpage))) {
			cl_page_assume(env, io, page);

			result = ll_io_read_page(env, io, page, file);
		} else {
			/* Page from a non-object file. */
			unlock_page(vmpage);
			result = 0;
		}
		cl_page_put(env, page);
	} else {
		unlock_page(vmpage);
		result = PTR_ERR(page);
		CDEBUG(D_CACHE, "failed to alloc page@%pK index%ld: rc = %d\n",
		       vmpage, vmpage->index, result);
	}

out:
	if (ra.cra_release != NULL)
		cl_read_ahead_release(env, &ra);

	/* this delay gives time for the actual read of the page to finish and
	 * unlock the page in vvp_page_completion_read before we return to our
	 * caller and the caller tries to use the page, allowing us to test
	 * races with the page being unlocked after readpage() but before it's
	 * used by the caller
	 */
	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_READPAGE_PAUSE2, cfs_fail_val);

	RETURN(result);
}

#ifdef HAVE_AOPS_READ_FOLIO
int ll_read_folio(struct file *file, struct folio *folio)
{
	return ll_readpage(file, folio_page(folio, 0));
}
#endif
